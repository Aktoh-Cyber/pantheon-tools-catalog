//! Synapse v2 tool — `package-remediate` (Tier 3, WRITE). Drive a package to a
//! desired state through the M11 packages provider. Same contracts as
//! service-remediate, plus two package-specific guards:
//!
//!   * DRY-RUN BY DEFAULT — `"apply": true` required to mutate; else returns the plan.
//!   * IDEMPOTENT — `package.query` first. `present` with an already-installed
//!     version >= min_version ⇒ changed:false, no write. `absent` and not installed
//!     ⇒ changed:false, no write.
//!   * VERIFY-AFTER-WRITE — re-queries; `verified:false` if the state didn't move.
//!   * NEVER_REMOVE DENYLIST — `absent` on a name matching the caller's
//!     `never_remove` list (or the built-in floor below) is refused. The floor
//!     protects the things a remediation must never uninstall out from under
//!     itself: the node agent, the package manager, core libs, ssh.
//!   * DENIAL IS HONEST — provider `denied` ⇒ exit 1 naming the api.
//!
//! Args:
//!   { "name": "<pkg>" (REQUIRED),
//!     "desired": "present" | "absent",
//!     "version": "<exact version to install>" (optional, present only),
//!     "min_version": "<if already installed >= this, no-op>" (optional, present only),
//!     "never_remove": ["<name>", ...] (optional, extends the built-in floor),
//!     "apply": false (default) }
//! host_apis: package.query (always) + package.install (present) / package.uninstall (absent).
//! ExitCode contract: exit 0 for an evaluated request (incl. dry-run/no-op); exit 1 for
//! arg errors, denylist refusal, provider denial/error.
use std::process::ExitCode;
wit_bindgen::generate!({ path: "wit", world: "package-remediate", generate_all });
use synapse::host::packages::{self, PackageError, PackageInfo};

/// Built-in floor: never uninstall these regardless of caller args.
const NEVER_REMOVE_FLOOR: &[&str] = &[
    "synapse-node", "synapse", "apt", "apt-get", "dpkg", "rpm", "dnf", "yum", "apk",
    "libc6", "glibc", "musl", "bash", "sh", "dash", "coreutils", "systemd", "openssh-server",
    "openssh", "sshd", "sudo", "ca-certificates",
];

fn err(r: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "package-remediate", "error": r.into() })
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
/// installed? + version (None if not installed / not found)
fn read(name: &str) -> Result<Option<PackageInfo>, serde_json::Value> {
    match packages::query(name) {
        Ok(i) => Ok(if i.installed { Some(i) } else { None }),
        Err(PackageError::NotFound) => Ok(None),
        Err(PackageError::Denied) => Err(serde_json::json!({ "tool": "package-remediate", "granted": false,
            "error": "package.query not granted in lease host_apis" })),
        Err(PackageError::BadInput(s)) => Err(err(format!("bad input: {s}"))),
        Err(PackageError::TransientError(s)) => Err(err(format!("query provider error: {s}"))),
    }
}
fn map_write(api: &str, r: Result<(), PackageError>) -> Result<(), serde_json::Value> {
    match r {
        Ok(()) => Ok(()),
        Err(PackageError::Denied) => Err(serde_json::json!({ "tool": "package-remediate", "granted": false,
            "error": format!("{api} not granted in lease host_apis") })),
        Err(PackageError::NotFound) => Err(err(format!("{api}: package not found by back-end"))),
        Err(PackageError::BadInput(s)) => Err(err(format!("{api}: bad input: {s}"))),
        Err(PackageError::TransientError(s)) => Err(err(format!("{api} provider error: {s}"))),
    }
}
fn info_json(i: &Option<PackageInfo>) -> serde_json::Value {
    match i { Some(p) => serde_json::json!({"installed":true,"version":p.version,"source":p.source}),
              None => serde_json::json!({"installed":false}) }
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value = serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;
    let name = a.get("name").and_then(|v| v.as_str()).ok_or_else(|| err("missing required arg 'name' (string)"))?;
    let desired = a.get("desired").and_then(|v| v.as_str()).ok_or_else(|| err("missing required arg 'desired' (present|absent)"))?;
    let apply = a.get("apply").and_then(|v| v.as_bool()).unwrap_or(false);
    let version = a.get("version").and_then(|v| v.as_str()).map(String::from);
    let min_version = a.get("min_version").and_then(|v| v.as_str());
    let extra_never: Vec<String> = a.get("never_remove").and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();

    let before = read(name)?;
    let (plan, already, reason_if_already): (Vec<serde_json::Value>, bool, &str) = match desired {
        "present" => {
            let ok = match &before {
                Some(p) => min_version.map(|m| ver_ge(&p.version, m)).unwrap_or(true),
                None => false,
            };
            (if ok { vec![] } else { vec![serde_json::json!({ "api":"package.install", "target": name, "version": version })] },
             ok, "already installed at an acceptable version (idempotent no-op)")
        }
        "absent" => {
            // denylist floor + caller list — refuse BEFORE planning anything
            let n = name.to_ascii_lowercase();
            if NEVER_REMOVE_FLOOR.iter().any(|f| *f == n) || extra_never.iter().any(|f| f.to_ascii_lowercase() == n) {
                return Err(serde_json::json!({ "tool": "package-remediate", "name": name, "desired": "absent",
                    "error": format!("refusing to remove {name}: on the never_remove denylist (built-in floor + caller list)") }));
            }
            let ok = before.is_none();
            (if ok { vec![] } else { vec![serde_json::json!({ "api":"package.uninstall", "target": name })] },
             ok, "already absent (idempotent no-op)")
        }
        other => return Err(err(format!("desired must be present|absent (got {other:?})"))),
    };

    if already {
        return Ok(serde_json::json!({ "tool":"package-remediate","name":name,"desired":desired,
            "before": info_json(&before), "after": info_json(&before), "plan": plan,
            "changed": false, "applied": false, "verified": true, "reason": reason_if_already }));
    }
    if !apply {
        return Ok(serde_json::json!({ "tool":"package-remediate","name":name,"desired":desired,
            "before": info_json(&before), "after": info_json(&before), "plan": plan,
            "changed": false, "applied": false, "verified": false, "dry_run": true,
            "reason": "dry-run: pass \"apply\":true to execute the plan" }));
    }
    match desired {
        "present" => map_write("package.install", packages::install(name, version.as_deref()))?,
        _ => map_write("package.uninstall", packages::uninstall(name))?,
    }
    let after = read(name)?;
    let verified = match desired {
        "present" => match &after { Some(p) => min_version.map(|m| ver_ge(&p.version, m)).unwrap_or(true), None => false },
        _ => after.is_none(),
    };
    Ok(serde_json::json!({ "tool":"package-remediate","name":name,"desired":desired,
        "before": info_json(&before), "after": info_json(&after), "plan": plan,
        "changed": before.as_ref().map(|p| p.version.clone()) != after.as_ref().map(|p| p.version.clone()),
        "applied": true, "verified": verified,
        "reason": if verified { "applied and verified" } else { "applied but post-state does not match desired — investigate" } }))
}

fn main() -> ExitCode {
    match run() { Ok(v) => { println!("{v}"); ExitCode::SUCCESS } Err(v) => { println!("{v}"); ExitCode::from(1) } }
}
