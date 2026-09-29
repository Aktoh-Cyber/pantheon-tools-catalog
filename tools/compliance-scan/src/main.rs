//! Synapse v2 tool — `compliance-scan` (Tier 2 FLAGSHIP).
//!
//! Evaluates a policy bundle against the node and returns pass/fail per rule WITH
//! EVIDENCE (the observed value), plus a rollup. Composes the read-only M11
//! providers: `inventory.os-info`, `package.query`, `service.status`, and (0.2.0)
//! `fs.read-file` / `fs.list-dir` for `config` rules that read the REAL host file.
//! Imports only read-only interfaces — it can never mutate host state even if
//! over-granted.
//!
//! Policy bundle (args):
//! {
//!   "policy_id": "cis-baseline-lite",              (optional label)
//!   "rules": [                                     (optional: omitted => built-in baseline)
//!     {"id":"os-debian",  "type":"os",      "kind_in":["linux-debian","linux-rhel"], "min_version":"12"},
//!     {"id":"bash-ok",    "type":"package", "name":"bash",  "installed":true, "min_version":"5.0"},
//!     {"id":"no-telnet",  "type":"package", "name":"telnet","installed":false},
//!     {"id":"ssh-up",     "type":"service", "name":"ssh",   "state":"running"},
//!     {"id":"no-secret",  "type":"file",    "path":"/work/secret.key", "exists":false},
//!     {"id":"ssh-root-login", "type":"config", "path":"/etc/ssh/sshd_config",
//!      "directive":"PermitRootLogin", "allowed":["no"], "default":"prohibit-password",
//!      "missing_file":"pass"}
//!   ]
//! }
//!
//! `config` rules (0.2.0) read an sshd-style keyword file on the HOST through
//! `fs.read-file`: keywords are case-insensitive, the FIRST occurrence wins,
//! `Keyword value` and `Keyword=value` both parse, `Include` (with `*`/`?` globs in
//! the last path component, relative to the main file's directory) is followed in
//! place, and a `Match` line ends the global section. The caller must grant the
//! file's directory in `capabilities.fs_roots` (e.g. `["/etc/ssh"]`); `host_apis`
//! default from this tool's manifest.
//!
//! No `rules` => the built-in baseline ([`default_baseline`]): `ssh-root-login` and
//! `ssh-empty-passwords` against the platform's sshd_config. Before 0.2.0 a bundle
//! without `rules` exited 1, and a `package`/`service` rule without `name` (the
//! only way to try to express an sshd setting) came back `error` with no hint of
//! the expected shape — the librarian's "ssh-root-login ERROR on every node".
//! Every rule error now names the expected shape.
//!
//! Rule outcomes: pass | fail | unknown (host API denied / provider error) | error (bad rule).
//! `unknown` NEVER counts as pass — fail-safe for compliance. Rollup: `pass` only if
//! every rule passed; `unknown_count` surfaces gaps in the lease grant.
//! ExitCode contract: exit 0 for any evaluated bundle (a failing scan is a valid answer);
//! exit 1 only for malformed args.
use std::process::ExitCode;
wit_bindgen::generate!({ path: "wit", world: "compliance-scan", generate_all });
use synapse::host::fs as hostfs;
use synapse::host::inventory::{self, OsKind};
use synapse::host::packages::{self, PackageError};
use synapse::host::service::{self, ServiceError, ServiceStatus};

/// Largest config file a `config` rule reads.
const CONFIG_MAX_BYTES: u64 = 256 * 1024;
/// Include nesting bound (sshd itself caps at 16; loops are the risk).
const INCLUDE_MAX_DEPTH: usize = 8;

const SHAPE_OS: &str = r#"{"id":..,"type":"os","kind_in"?:["linux-debian"|"linux-rhel"|"linux-alpine"|"macos"|"windows"],"min_version"?:".."}"#;
const SHAPE_PACKAGE: &str = r#"{"id":..,"type":"package","name":"<package>","installed"?:true|false,"min_version"?:".."}"#;
const SHAPE_SERVICE: &str = r#"{"id":..,"type":"service","name":"<unit>","state"?:"running"|"stopped"}"#;
const SHAPE_FILE: &str = r#"{"id":..,"type":"file","path":"/work/..","exists"?:true|false} (the tool sandbox, not the host)"#;
const SHAPE_CONFIG: &str = r#"{"id":..,"type":"config","path":"/etc/ssh/sshd_config","directive":"PermitRootLogin","allowed":["no"] | "expected":"no","default"?:"<value when unset>","missing_file"?:"pass"|"fail"|"unknown"} (reads the host file; grant capabilities.fs_roots)"#;

fn shape(ty: &str) -> String {
    match ty {
        "os" => SHAPE_OS.to_string(),
        "package" => SHAPE_PACKAGE.to_string(),
        "service" => SHAPE_SERVICE.to_string(),
        "file" => SHAPE_FILE.to_string(),
        "config" => SHAPE_CONFIG.to_string(),
        _ => format!("one of: {SHAPE_OS} | {SHAPE_PACKAGE} | {SHAPE_SERVICE} | {SHAPE_FILE} | {SHAPE_CONFIG}"),
    }
}

fn err(r: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "compliance-scan", "error": r.into() })
}

fn ver_ge(have: &str, want: &str) -> bool {
    let seg = |s: &str| -> Vec<String> { s.split(|c: char| !c.is_ascii_alphanumeric()).filter(|x| !x.is_empty()).map(String::from).collect() };
    let (h, w) = (seg(have), seg(want));
    for i in 0..w.len().max(h.len()) {
        let (a, b) = (h.get(i).map(String::as_str).unwrap_or("0"), w.get(i).map(String::as_str).unwrap_or("0"));
        let ord = match (a.parse::<u64>(), b.parse::<u64>()) { (Ok(x), Ok(y)) => x.cmp(&y), _ => a.cmp(b) };
        if ord != std::cmp::Ordering::Equal { return ord == std::cmp::Ordering::Greater; }
    }
    true
}

fn os_kind_str(k: &OsKind) -> String {
    match k { OsKind::LinuxDebian => "linux-debian".into(), OsKind::LinuxRhel => "linux-rhel".into(),
        OsKind::LinuxAlpine => "linux-alpine".into(), OsKind::Macos => "macos".into(),
        OsKind::Windows => "windows".into(), OsKind::Other(s) => s.clone() }
}

fn res(id: &str, ty: &str, outcome: &str, evidence: serde_json::Value, reason: &str) -> serde_json::Value {
    serde_json::json!({ "id": id, "type": ty, "outcome": outcome, "evidence": evidence, "reason": reason })
}

/// A rule is malformed: `error`, with the shape the type expects.
fn bad_rule(id: &str, ty: &str, what: &str) -> serde_json::Value {
    res(id, ty, "error", serde_json::Value::Null, &format!("{what}; expected {}", shape(ty)))
}

// ---- host access seams (the node's providers in production, fakes in tests) ----

/// OS facts, `Err(())` when `inventory.os-info` is not granted.
type OsFacts = Result<(String, String, String), ()>;

/// Why a host file read failed.
#[derive(Debug, Clone, PartialEq)]
enum FsErr {
    Denied(String),
    NotFound,
    Other(String),
}

trait Host {
    fn os(&mut self) -> OsFacts;
    fn read(&mut self, path: &str) -> Result<String, FsErr>;
    fn list(&mut self, dir: &str) -> Result<Vec<String>, FsErr>;
}

/// The real node: WIT host imports.
struct Node {
    os: Option<OsFacts>,
}

fn map_fs_err(e: hostfs::FsError) -> FsErr {
    match e {
        hostfs::FsError::Denied(m) => FsErr::Denied(m),
        hostfs::FsError::NotFound(_) => FsErr::NotFound,
        hostfs::FsError::TooLarge(m) => FsErr::Other(format!("file too large: {m}")),
        hostfs::FsError::IoError(m) => FsErr::Other(m),
    }
}

impl Host for Node {
    fn os(&mut self) -> OsFacts {
        self.os
            .get_or_insert_with(|| {
                let h = inventory::os_info();
                let kind = os_kind_str(&h.kind);
                if kind == "denied" { Err(()) } else { Ok((kind, h.version, h.arch)) }
            })
            .clone()
    }
    fn read(&mut self, path: &str) -> Result<String, FsErr> {
        hostfs::read_file(path, CONFIG_MAX_BYTES)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .map_err(map_fs_err)
    }
    fn list(&mut self, dir: &str) -> Result<Vec<String>, FsErr> {
        hostfs::list_dir(dir)
            .map(|entries| entries.into_iter().filter(|e| !e.is_dir).map(|e| e.name).collect())
            .map_err(map_fs_err)
    }
}

// ---- sshd-style keyword files ----

/// Where a directive's effective (global) value came from.
#[derive(Debug, PartialEq)]
enum Lookup {
    /// The main config file does not exist on the host.
    FileMissing,
    /// Not set anywhere in the global section.
    Absent,
    Found { value: String, file: String },
}

/// Split `Keyword value` / `Keyword=value` into (keyword, rest).
fn split_keyword(line: &str) -> (&str, &str) {
    let end = line.find(|c: char| c.is_whitespace() || c == '=').unwrap_or(line.len());
    let rest = line[end..].trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();
    (&line[..end], rest)
}

/// Whitespace-separated arguments; `"..."` quoting keeps spaces.
fn split_args(rest: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut any = false;
    for c in rest.chars() {
        match c {
            '"' => { quoted = !quoted; any = true; }
            c if c.is_whitespace() && !quoted => {
                if any { out.push(std::mem::take(&mut cur)); any = false; }
            }
            c => { cur.push(c); any = true; }
        }
    }
    if any { out.push(cur); }
    out
}

/// `*` / `?` glob over one path component.
fn glob_match(pattern: &str, name: &str) -> bool {
    let (p, n): (Vec<char>, Vec<char>) = (pattern.chars().collect(), name.chars().collect());
    let (mut pi, mut ni, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) { pi += 1; ni += 1; }
        else if pi < p.len() && p[pi] == '*' { star = Some(pi); mark = ni; pi += 1; }
        else if let Some(s) = star { pi = s + 1; mark += 1; ni = mark; }
        else { return false; }
    }
    while pi < p.len() && p[pi] == '*' { pi += 1; }
    pi == p.len()
}

fn separator(path: &str) -> char {
    if path.contains('/') || !path.contains('\\') { '/' } else { '\\' }
}

fn is_absolute(path: &str) -> bool {
    path.starts_with('/') || path.starts_with('\\') || path.as_bytes().get(1) == Some(&b':')
}

fn parent_dir(path: &str) -> String {
    match path.rfind(['/', '\\']) {
        Some(0) => path[..1].to_string(),
        Some(i) => path[..i].to_string(),
        None => ".".to_string(),
    }
}

/// Files an `Include` argument names, in the order sshd loads them (lexical for globs).
fn expand_include(host: &mut dyn Host, base: &str, pattern: &str) -> Result<Vec<String>, FsErr> {
    let sep = separator(base);
    let full = if is_absolute(pattern) { pattern.to_string() } else { format!("{base}{sep}{pattern}") };
    let (dir, last) = match full.rfind(['/', '\\']) {
        Some(i) => (full[..i.max(1)].to_string(), full[i + 1..].to_string()),
        None => (base.to_string(), full.clone()),
    };
    if !last.contains(['*', '?']) {
        return Ok(vec![full]);
    }
    let mut names = match host.list(&dir) {
        Ok(names) => names,
        Err(FsErr::NotFound) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    names.retain(|n| glob_match(&last, n));
    names.sort();
    let sep = separator(&dir);
    Ok(names.into_iter().map(|n| format!("{dir}{sep}{n}")).collect())
}

fn scan(host: &mut dyn Host, text: &str, file: &str, base: &str, want: &str, depth: usize) -> Result<Option<(String, String)>, FsErr> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let (kw, rest) = split_keyword(line);
        let kw = kw.to_ascii_lowercase();
        if kw == "match" {
            return Ok(None); // the global section of this file ends here
        }
        if kw == "include" {
            if depth >= INCLUDE_MAX_DEPTH { continue; }
            for pattern in split_args(rest) {
                for inc in expand_include(host, base, &pattern)? {
                    let text = match host.read(&inc) {
                        Ok(t) => t,
                        Err(FsErr::NotFound) => continue,
                        Err(e) => return Err(e),
                    };
                    if let Some(hit) = scan(host, &text, &inc, base, want, depth + 1)? {
                        return Ok(Some(hit));
                    }
                }
            }
            continue;
        }
        if kw == want {
            let value = split_args(rest).into_iter().next().unwrap_or_default();
            return Ok(Some((value, file.to_string())));
        }
    }
    Ok(None)
}

/// The effective global value of `directive` in the sshd-style file at `path`.
fn sshd_effective(host: &mut dyn Host, path: &str, directive: &str) -> Result<Lookup, FsErr> {
    let text = match host.read(path) {
        Ok(t) => t,
        Err(FsErr::NotFound) => return Ok(Lookup::FileMissing),
        Err(e) => return Err(e),
    };
    let base = parent_dir(path);
    Ok(match scan(host, &text, path, &base, &directive.to_ascii_lowercase(), 0)? {
        Some((value, file)) => Lookup::Found { value, file },
        None => Lookup::Absent,
    })
}

fn eval_config(id: &str, r: &serde_json::Value, host: &mut dyn Host) -> serde_json::Value {
    let ty = "config";
    let Some(path) = r.get("path").and_then(|v| v.as_str()) else { return bad_rule(id, ty, "rule missing 'path'") };
    let Some(directive) = r.get("directive").and_then(|v| v.as_str()) else { return bad_rule(id, ty, "rule missing 'directive'") };
    let allowed: Vec<String> = match (r.get("allowed").and_then(|v| v.as_array()), r.get("expected").and_then(|v| v.as_str())) {
        (Some(a), _) => a.iter().filter_map(|v| v.as_str()).map(|s| s.to_ascii_lowercase()).collect(),
        (None, Some(e)) => vec![e.to_ascii_lowercase()],
        (None, None) => return bad_rule(id, ty, "rule needs 'allowed' (array) or 'expected' (string)"),
    };
    if allowed.is_empty() { return bad_rule(id, ty, "'allowed' is empty"); }
    let default = r.get("default").and_then(|v| v.as_str());
    let missing_file = r.get("missing_file").and_then(|v| v.as_str()).unwrap_or("unknown");
    if !matches!(missing_file, "pass" | "fail" | "unknown") {
        return bad_rule(id, ty, "'missing_file' must be pass|fail|unknown");
    }
    if let Some(f) = r.get("format").and_then(|v| v.as_str()) {
        if f != "sshd" { return bad_rule(id, ty, &format!("unsupported format '{f}' (supported: sshd)")); }
    }
    let judge = |value: &str, source: &str| {
        let ev = serde_json::json!({ "path": path, "directive": directive, "value": value, "source": source, "allowed": allowed });
        if allowed.iter().any(|a| a == &value.to_ascii_lowercase()) { res(id, ty, "pass", ev, "ok") }
        else { res(id, ty, "fail", ev, &format!("{directive} is '{value}' (allowed: {})", allowed.join("|"))) }
    };
    match sshd_effective(host, path, directive) {
        Ok(Lookup::Found { value, file }) => judge(&value, &file),
        Ok(Lookup::Absent) => match default {
            Some(d) => judge(d, "default (not set in the file)"),
            None => res(id, ty, "unknown", serde_json::json!({"path": path, "directive": directive, "value": null}), "directive not set and the rule gives no 'default'"),
        },
        Ok(Lookup::FileMissing) => {
            let ev = serde_json::json!({ "path": path, "exists": false });
            match missing_file {
                "pass" => res(id, ty, "pass", ev, "config file absent on this host (nothing configures it)"),
                "fail" => res(id, ty, "fail", ev, "config file missing"),
                _ => res(id, ty, "unknown", ev, "config file missing; set 'missing_file' to decide"),
            }
        }
        Err(FsErr::Denied(m)) => res(id, ty, "unknown", serde_json::json!({"host_api": "fs.read-file", "path": path}),
            &format!("fs.read-file denied ({m}); grant capabilities.fs_roots covering '{}'", parent_dir(path))),
        Err(FsErr::NotFound) => res(id, ty, "unknown", serde_json::json!({"path": path}), "config file vanished while reading"),
        Err(FsErr::Other(m)) => res(id, ty, "unknown", serde_json::json!({"path": path}), &format!("provider error: {m}")),
    }
}

/// The built-in baseline run when a bundle has no `rules`.
fn default_baseline(os_kind: Option<&str>) -> Vec<serde_json::Value> {
    let sshd = if os_kind == Some("windows") { r"C:\ProgramData\ssh\sshd_config" } else { "/etc/ssh/sshd_config" };
    vec![
        serde_json::json!({ "id": "ssh-root-login", "type": "config", "path": sshd, "directive": "PermitRootLogin",
            "allowed": ["no"], "default": "prohibit-password", "missing_file": "pass", "severity": "high" }),
        serde_json::json!({ "id": "ssh-empty-passwords", "type": "config", "path": sshd, "directive": "PermitEmptyPasswords",
            "allowed": ["no"], "default": "no", "missing_file": "pass", "severity": "critical" }),
    ]
}

fn eval_rule(r: &serde_json::Value, host: &mut dyn Host) -> serde_json::Value {
    let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("?");
    let ty = r.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let mut out = match ty {
        "os" => match host.os() {
            Err(()) => res(id, ty, "unknown", serde_json::json!({"host_api":"inventory.os-info"}), "inventory.os-info not granted"),
            Ok((kind, ver, arch)) => {
                let ev = serde_json::json!({"kind":kind,"version":ver,"arch":arch});
                let kind_ok = r.get("kind_in").and_then(|v| v.as_array()).map(|a| a.iter().any(|k| k.as_str() == Some(kind.as_str()))).unwrap_or(true);
                let ver_ok = r.get("min_version").and_then(|v| v.as_str()).map(|m| ver_ge(&ver, m)).unwrap_or(true);
                if !kind_ok { res(id, ty, "fail", ev, "os kind not in allowed set") }
                else if !ver_ok { res(id, ty, "fail", ev, "os version below minimum") }
                else { res(id, ty, "pass", ev, "ok") }
            }
        },
        "package" => {
            let name = match r.get("name").and_then(|v| v.as_str()) { Some(n) => n, None => return bad_rule(id, ty, "rule missing 'name'") };
            let want_installed = r.get("installed").and_then(|v| v.as_bool()).unwrap_or(true);
            let min = r.get("min_version").and_then(|v| v.as_str());
            match packages::query(name) {
                Ok(info) => {
                    let ev = serde_json::json!({"name":info.name,"installed":info.installed,"version":info.version,"source":info.source});
                    if info.installed != want_installed {
                        res(id, ty, "fail", ev, if want_installed { "not installed" } else { "installed but must be absent" })
                    } else if want_installed && !min.map(|m| ver_ge(&info.version, m)).unwrap_or(true) {
                        res(id, ty, "fail", ev, "version below minimum")
                    } else { res(id, ty, "pass", ev, "ok") }
                }
                Err(PackageError::NotFound) => {
                    let ev = serde_json::json!({"name":name,"installed":false});
                    if want_installed { res(id, ty, "fail", ev, "not installed") } else { res(id, ty, "pass", ev, "absent as required") }
                }
                Err(PackageError::Denied) => res(id, ty, "unknown", serde_json::json!({"host_api":"package.query"}), "package.query not granted"),
                Err(PackageError::BadInput(s)) => res(id, ty, "error", serde_json::Value::Null, &format!("bad input: {s}")),
                Err(PackageError::TransientError(s)) => res(id, ty, "unknown", serde_json::Value::Null, &format!("provider error: {s}")),
            }
        }
        "service" => {
            let name = match r.get("name").and_then(|v| v.as_str()) { Some(n) => n, None => return bad_rule(id, ty, "rule missing 'name'") };
            let want = r.get("state").and_then(|v| v.as_str()).unwrap_or("running");
            match service::status(name) {
                Ok(s) => {
                    let got = match s { ServiceStatus::Running => "running", ServiceStatus::Stopped => "stopped", ServiceStatus::Failed => "failed", ServiceStatus::Unknown => "unknown" };
                    let ev = serde_json::json!({"name":name,"status":got});
                    if got == "unknown" { res(id, ty, "unknown", ev, "service state unknown to back-end") }
                    else if got == want { res(id, ty, "pass", ev, "ok") } else { res(id, ty, "fail", ev, "service state mismatch") }
                }
                Err(ServiceError::NotFound) => {
                    let ev = serde_json::json!({"name":name,"status":"not-found"});
                    if want == "stopped" || want == "absent" { res(id, ty, "pass", ev, "absent") } else { res(id, ty, "fail", ev, "service not found") }
                }
                Err(ServiceError::Denied) => res(id, ty, "unknown", serde_json::json!({"host_api":"service.status"}), "service.status not granted"),
                Err(ServiceError::TransientError(s)) => res(id, ty, "unknown", serde_json::Value::Null, &format!("provider error: {s}")),
            }
        }
        "file" => {
            let path = match r.get("path").and_then(|v| v.as_str()) { Some(p) => p, None => return bad_rule(id, ty, "rule missing 'path'") };
            let want_exists = r.get("exists").and_then(|v| v.as_bool()).unwrap_or(true);
            let exists = std::fs::metadata(path).is_ok();
            // `scope` makes it explicit that this is the tool sandbox, not the host disk.
            let ev = serde_json::json!({"path":path,"exists":exists,"scope":"sandbox"});
            if exists == want_exists { res(id, ty, "pass", ev, "ok") } else { res(id, ty, "fail", ev, if want_exists { "file missing" } else { "file must not exist" }) }
        }
        "config" => eval_config(id, r, host),
        "" => bad_rule(id, ty, "rule missing 'type'"),
        _ => bad_rule(id, ty, &format!("unknown rule type '{ty}'")),
    };
    if let (Some(sev), Some(obj)) = (r.get("severity").and_then(|v| v.as_str()), out.as_object_mut()) {
        obj.insert("severity".into(), sev.into());
    }
    out
}

fn evaluate(a: &serde_json::Value, host: &mut dyn Host) -> Result<serde_json::Value, serde_json::Value> {
    let (rules, rules_source): (Vec<serde_json::Value>, &str) = match a.get("rules") {
        None | Some(serde_json::Value::Null) => {
            let kind = host.os().ok().map(|(k, _, _)| k);
            (default_baseline(kind.as_deref()), "default-baseline")
        }
        Some(serde_json::Value::Array(r)) if r.is_empty() => {
            return Err(err("'rules' is empty (omit it to run the built-in baseline)"))
        }
        Some(serde_json::Value::Array(r)) => (r.clone(), "caller"),
        Some(_) => return Err(err(format!("'rules' must be an array of rules, each {}", shape("?")))),
    };
    let default_id = if rules_source == "caller" { "adhoc" } else { "synapse-baseline" };
    let policy_id = a.get("policy_id").and_then(|v| v.as_str()).unwrap_or(default_id).to_string();

    let results: Vec<serde_json::Value> = rules.iter().map(|r| eval_rule(r, host)).collect();
    let count = |o: &str| results.iter().filter(|r| r.get("outcome").and_then(|v| v.as_str()) == Some(o)).count();
    let (p, f, u, e) = (count("pass"), count("fail"), count("unknown"), count("error"));
    Ok(serde_json::json!({
        "tool": "compliance-scan",
        "policy_id": policy_id,
        "rules_source": rules_source,
        "pass": f == 0 && u == 0 && e == 0,     // unknown never counts as pass — fail-safe
        "summary": { "total": results.len(), "pass": p, "fail": f, "unknown": u, "error": e },
        "results": results,
    }))
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value = serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;
    if !a.is_object() {
        return Err(err("args must be a JSON object: {\"policy_id\"?:..,\"rules\"?:[..]}"));
    }
    evaluate(&a, &mut Node { os: None })
}

fn main() -> ExitCode {
    match run() { Ok(v) => { println!("{v}"); ExitCode::SUCCESS } Err(v) => { println!("{v}"); ExitCode::from(1) } }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// In-memory host: files, OS facts, and paths that answer `denied`.
    #[derive(Default)]
    struct Fake {
        files: BTreeMap<String, String>,
        denied: Vec<String>,
        os: Option<OsFacts>,
    }

    impl Fake {
        fn with(files: &[(&str, &str)]) -> Self {
            Fake { files: files.iter().map(|(p, t)| (p.to_string(), t.to_string())).collect(), ..Default::default() }
        }
    }

    impl Host for Fake {
        fn os(&mut self) -> OsFacts {
            self.os.clone().unwrap_or(Ok(("linux-debian".into(), "12".into(), "x86_64".into())))
        }
        fn read(&mut self, path: &str) -> Result<String, FsErr> {
            if self.denied.iter().any(|d| path.starts_with(d.as_str())) { return Err(FsErr::Denied("outside every granted root".into())); }
            self.files.get(path).cloned().ok_or(FsErr::NotFound)
        }
        fn list(&mut self, dir: &str) -> Result<Vec<String>, FsErr> {
            let prefix = format!("{dir}/");
            let names: Vec<String> = self.files.keys().filter_map(|p| p.strip_prefix(&prefix)).filter(|n| !n.contains('/')).map(String::from).collect();
            if names.is_empty() { Err(FsErr::NotFound) } else { Ok(names) }
        }
    }

    fn root_login_rule() -> serde_json::Value {
        default_baseline(None).remove(0)
    }

    fn outcome(v: &serde_json::Value) -> (&str, &str) {
        (v["outcome"].as_str().unwrap(), v["reason"].as_str().unwrap())
    }

    #[test]
    fn first_occurrence_wins_case_insensitively() {
        let mut h = Fake::with(&[("/etc/ssh/sshd_config", "# comment\npermitrootlogin no\nPermitRootLogin yes\n")]);
        assert_eq!(sshd_effective(&mut h, "/etc/ssh/sshd_config", "PermitRootLogin").unwrap(),
            Lookup::Found { value: "no".into(), file: "/etc/ssh/sshd_config".into() });
    }

    #[test]
    fn equals_syntax_and_quotes_parse() {
        let mut h = Fake::with(&[("/etc/ssh/sshd_config", "PermitRootLogin=\"no\"\n")]);
        assert_eq!(sshd_effective(&mut h, "/etc/ssh/sshd_config", "permitrootlogin").unwrap(),
            Lookup::Found { value: "no".into(), file: "/etc/ssh/sshd_config".into() });
        let mut h = Fake::with(&[("/etc/ssh/sshd_config", "PermitRootLogin = yes\n")]);
        assert!(matches!(sshd_effective(&mut h, "/etc/ssh/sshd_config", "PermitRootLogin").unwrap(), Lookup::Found { value, .. } if value == "yes"));
    }

    /// Debian/Ubuntu/macOS put `Include sshd_config.d/*.conf` at the TOP, so a drop-in
    /// overrides the main file (first wins); drop-ins load in lexical order.
    #[test]
    fn include_glob_is_followed_in_place_in_lexical_order() {
        let mut h = Fake::with(&[
            ("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n"),
            ("/etc/ssh/sshd_config.d/50-cloud.conf", "PermitRootLogin prohibit-password\n"),
            ("/etc/ssh/sshd_config.d/10-first.conf", "PermitRootLogin yes\n"),
            ("/etc/ssh/sshd_config.d/99-ignored.txt", "PermitRootLogin without-password\n"),
        ]);
        assert_eq!(sshd_effective(&mut h, "/etc/ssh/sshd_config", "PermitRootLogin").unwrap(),
            Lookup::Found { value: "yes".into(), file: "/etc/ssh/sshd_config.d/10-first.conf".into() });
    }

    #[test]
    fn relative_include_resolves_against_the_config_dir_and_missing_include_is_skipped() {
        let mut h = Fake::with(&[("/etc/ssh/sshd_config", "Include sshd_config.d/*\nInclude nope.conf\nPermitRootLogin no\n")]);
        assert!(matches!(sshd_effective(&mut h, "/etc/ssh/sshd_config", "PermitRootLogin").unwrap(), Lookup::Found { value, .. } if value == "no"));
    }

    #[test]
    fn match_block_ends_the_global_section() {
        let mut h = Fake::with(&[("/etc/ssh/sshd_config", "Port 22\nMatch User backup\n    PermitRootLogin yes\n")]);
        assert_eq!(sshd_effective(&mut h, "/etc/ssh/sshd_config", "PermitRootLogin").unwrap(), Lookup::Absent);
    }

    #[test]
    fn include_loop_terminates() {
        let mut h = Fake::with(&[("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config\n")]);
        assert_eq!(sshd_effective(&mut h, "/etc/ssh/sshd_config", "PermitRootLogin").unwrap(), Lookup::Absent);
    }

    #[test]
    fn config_rule_pass_fail_and_default() {
        let mut h = Fake::with(&[("/etc/ssh/sshd_config", "PermitRootLogin no\n")]);
        assert_eq!(outcome(&eval_rule(&root_login_rule(), &mut h)).0, "pass");

        let mut h = Fake::with(&[("/etc/ssh/sshd_config", "PermitRootLogin yes\n")]);
        let r = eval_rule(&root_login_rule(), &mut h);
        assert_eq!(outcome(&r), ("fail", "PermitRootLogin is 'yes' (allowed: no)"));
        assert_eq!(r["evidence"]["value"], "yes");
        assert_eq!(r["severity"], "high");

        // Unset: judged on OpenSSH's built-in default, and says so.
        let mut h = Fake::with(&[("/etc/ssh/sshd_config", "#PermitRootLogin prohibit-password\n")]);
        let r = eval_rule(&root_login_rule(), &mut h);
        assert_eq!(r["outcome"], "fail");
        assert_eq!(r["evidence"]["value"], "prohibit-password");
        assert_eq!(r["evidence"]["source"], "default (not set in the file)");
    }

    #[test]
    fn config_rule_missing_file_and_denied() {
        let mut h = Fake::default();
        let r = eval_rule(&root_login_rule(), &mut h);
        assert_eq!(r["outcome"], "pass");
        assert_eq!(r["evidence"]["exists"], false);

        let mut h = Fake { denied: vec!["/etc".into()], ..Default::default() };
        let r = eval_rule(&root_login_rule(), &mut h);
        assert_eq!(r["outcome"], "unknown");
        assert!(r["reason"].as_str().unwrap().contains("grant capabilities.fs_roots covering '/etc/ssh'"));

        let mut rule = root_login_rule();
        rule.as_object_mut().unwrap().remove("missing_file");
        assert_eq!(eval_rule(&rule, &mut Fake::default())["outcome"], "unknown");
    }

    /// The librarian's failure: a rule without the fields its type needs is an
    /// `error` that now names the expected shape, never a bare "missing 'name'".
    #[test]
    fn malformed_rules_name_the_expected_shape() {
        let mut h = Fake::default();
        let r = eval_rule(&serde_json::json!({"id":"ssh-root-login","type":"service","setting":"PermitRootLogin"}), &mut h);
        assert_eq!(r["outcome"], "error");
        assert!(r["reason"].as_str().unwrap().starts_with("rule missing 'name'; expected {\"id\":..,\"type\":\"service\""));

        let r = eval_rule(&serde_json::json!({"id":"x","type":"sshd"}), &mut h);
        assert!(r["reason"].as_str().unwrap().contains("\"type\":\"config\""));

        let r = eval_rule(&serde_json::json!({"id":"x","type":"config","path":"/etc/ssh/sshd_config"}), &mut h);
        assert!(r["reason"].as_str().unwrap().starts_with("rule missing 'directive'"));

        let r = eval_rule(&serde_json::json!({"id":"x","type":"config","path":"/p","directive":"D"}), &mut h);
        assert!(r["reason"].as_str().unwrap().contains("'allowed'"));
    }

    /// No `rules` => the baseline (was: exit 1 "missing 'rules' (array)").
    #[test]
    fn omitted_rules_run_the_baseline() {
        let mut h = Fake::with(&[("/etc/ssh/sshd_config", "PermitRootLogin no\n")]);
        let out = evaluate(&serde_json::json!({}), &mut h).unwrap();
        assert_eq!(out["rules_source"], "default-baseline");
        assert_eq!(out["policy_id"], "synapse-baseline");
        let ids: Vec<&str> = out["results"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert_eq!(ids, vec!["ssh-root-login", "ssh-empty-passwords"]);
        assert_eq!(out["summary"]["pass"], 2);
        assert_eq!(out["pass"], true);

        let out = evaluate(&serde_json::json!({"rules": null, "policy_id": "nightly"}), &mut h).unwrap();
        assert_eq!(out["policy_id"], "nightly");

        assert!(evaluate(&serde_json::json!({"rules": []}), &mut h).is_err());
        assert!(evaluate(&serde_json::json!({"rules": {"id": "x"}}), &mut h).is_err());
    }

    #[test]
    fn windows_baseline_targets_programdata() {
        let mut h = Fake { os: Some(Ok(("windows".into(), "10".into(), "x86_64".into()))), ..Default::default() };
        let out = evaluate(&serde_json::json!({}), &mut h).unwrap();
        assert_eq!(out["results"][0]["evidence"]["path"], r"C:\ProgramData\ssh\sshd_config");
        assert_eq!(out["results"][0]["outcome"], "pass"); // no OpenSSH server installed
    }

    #[test]
    fn glob_and_paths() {
        assert!(glob_match("*.conf", "50-cloud.conf"));
        assert!(!glob_match("*.conf", "50-cloud.conf.bak"));
        assert!(glob_match("1?-x", "10-x"));
        assert!(glob_match("*", "anything"));
        assert_eq!(parent_dir("/etc/ssh/sshd_config"), "/etc/ssh");
        assert_eq!(parent_dir(r"C:\ProgramData\ssh\sshd_config"), r"C:\ProgramData\ssh");
        assert_eq!(split_keyword("Include  a b"), ("Include", "a b"));
        assert_eq!(split_args(r#""a b" c"#), vec!["a b".to_string(), "c".to_string()]);
    }
}
