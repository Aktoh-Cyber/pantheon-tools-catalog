//! Synapse v2 tool — `compliance-scan` (Tier 2 FLAGSHIP).
//!
//! Evaluates a policy bundle against the node and returns pass/fail per rule WITH
//! EVIDENCE (the observed value), plus a rollup. Composes the three read-only M11
//! providers: `inventory.os-info`, `package.query`, `service.status`, and the
//! sandbox filesystem for file rules. Imports only read-only interfaces — it can
//! never mutate host state even if over-granted.
//!
//! Policy bundle (args):
//! {
//!   "policy_id": "cis-baseline-lite",              (optional label)
//!   "rules": [
//!     {"id":"os-debian",  "type":"os",      "kind_in":["linux-debian","linux-rhel"], "min_version":"12"},
//!     {"id":"bash-ok",    "type":"package", "name":"bash",  "installed":true, "min_version":"5.0"},
//!     {"id":"no-telnet",  "type":"package", "name":"telnet","installed":false},
//!     {"id":"ssh-up",     "type":"service", "name":"ssh",   "state":"running"},
//!     {"id":"no-secret",  "type":"file",    "path":"/work/secret.key", "exists":false}
//!   ]
//! }
//! Rule outcomes: pass | fail | unknown (host API denied / provider error) | error (bad rule).
//! `unknown` NEVER counts as pass — fail-safe for compliance. Rollup: `pass` only if
//! every rule passed; `unknown_count` surfaces gaps in the lease grant.
//! Required host_apis: ["inventory.os-info","package.query","service.status"] (grant the
//! subset your rules need; ungranted rules report `unknown` with the api named).
//! ExitCode contract: exit 0 for any evaluated bundle (a failing scan is a valid answer);
//! exit 1 only for malformed args.
use std::process::ExitCode;
wit_bindgen::generate!({ path: "wit", world: "compliance-scan", generate_all });
use synapse::host::inventory::{self, OsKind};
use synapse::host::packages::{self, PackageError};
use synapse::host::service::{self, ServiceError, ServiceStatus};

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

fn eval_rule(r: &serde_json::Value, os_cache: &mut Option<Result<(String, String, String), ()>>) -> serde_json::Value {
    let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("?");
    let ty = r.get("type").and_then(|v| v.as_str()).unwrap_or("");
    match ty {
        "os" => {
            // fetch os-info once per scan
            if os_cache.is_none() {
                let h = inventory::os_info();
                let kind = os_kind_str(&h.kind);
                *os_cache = Some(if kind == "denied" { Err(()) } else { Ok((kind, h.version, h.arch)) });
            }
            match os_cache.as_ref().unwrap() {
                Err(()) => res(id, ty, "unknown", serde_json::json!({"host_api":"inventory.os-info"}), "inventory.os-info not granted"),
                Ok((kind, ver, arch)) => {
                    let ev = serde_json::json!({"kind":kind,"version":ver,"arch":arch});
                    let kind_ok = r.get("kind_in").and_then(|v| v.as_array()).map(|a| a.iter().any(|k| k.as_str() == Some(kind.as_str()))).unwrap_or(true);
                    let ver_ok = r.get("min_version").and_then(|v| v.as_str()).map(|m| ver_ge(ver, m)).unwrap_or(true);
                    if !kind_ok { res(id, ty, "fail", ev, "os kind not in allowed set") }
                    else if !ver_ok { res(id, ty, "fail", ev, "os version below minimum") }
                    else { res(id, ty, "pass", ev, "ok") }
                }
            }
        }
        "package" => {
            let name = match r.get("name").and_then(|v| v.as_str()) { Some(n) => n, None => return res(id, ty, "error", serde_json::Value::Null, "rule missing 'name'") };
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
            let name = match r.get("name").and_then(|v| v.as_str()) { Some(n) => n, None => return res(id, ty, "error", serde_json::Value::Null, "rule missing 'name'") };
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
            let path = match r.get("path").and_then(|v| v.as_str()) { Some(p) => p, None => return res(id, ty, "error", serde_json::Value::Null, "rule missing 'path'") };
            let want_exists = r.get("exists").and_then(|v| v.as_bool()).unwrap_or(true);
            let exists = std::fs::metadata(path).is_ok();
            let ev = serde_json::json!({"path":path,"exists":exists});
            if exists == want_exists { res(id, ty, "pass", ev, "ok") } else { res(id, ty, "fail", ev, if want_exists { "file missing" } else { "file must not exist" }) }
        }
        _ => res(id, ty, "error", serde_json::Value::Null, "unknown rule type (os|package|service|file)"),
    }
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value = serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;
    let policy_id = a.get("policy_id").and_then(|v| v.as_str()).unwrap_or("adhoc").to_string();
    let rules = a.get("rules").and_then(|v| v.as_array()).ok_or_else(|| err("missing 'rules' (array)"))?;
    if rules.is_empty() { return Err(err("'rules' is empty")); }

    let mut os_cache = None;
    let results: Vec<serde_json::Value> = rules.iter().map(|r| eval_rule(r, &mut os_cache)).collect();
    let count = |o: &str| results.iter().filter(|r| r.get("outcome").and_then(|v| v.as_str()) == Some(o)).count();
    let (p, f, u, e) = (count("pass"), count("fail"), count("unknown"), count("error"));
    Ok(serde_json::json!({
        "tool": "compliance-scan",
        "policy_id": policy_id,
        "pass": f == 0 && u == 0 && e == 0,     // unknown never counts as pass — fail-safe
        "summary": { "total": results.len(), "pass": p, "fail": f, "unknown": u, "error": e },
        "results": results,
    }))
}

fn main() -> ExitCode {
    match run() { Ok(v) => { println!("{v}"); ExitCode::SUCCESS } Err(v) => { println!("{v}"); ExitCode::from(1) } }
}
