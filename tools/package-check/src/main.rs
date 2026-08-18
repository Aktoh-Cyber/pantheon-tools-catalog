//! Synapse v2 tool — `package-check` (Tier 2). Compliance assertion: is package X
//! installed, optionally at version >= Y? Via M11 `package.query`.
//! Lease must grant `host_apis: ["package.query"]`. Denied → `denied` variant (honest).
//! Args: { "name": "<pkg>" (REQUIRED), "min_version": "<semver-ish>" (optional) }
//! Output: { pass: bool, installed, version, min_version, reason }
//! ExitCode contract: exit 0 whether pass or fail (a failed check is a valid answer);
//! exit 1 only for arg errors / provider denial.
use std::process::ExitCode;
wit_bindgen::generate!({ path: "wit", world: "package-check", generate_all });
use synapse::host::packages::{self, PackageError};

fn err(r: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "package-check", "error": r.into() })
}

/// Lenient version compare: split on non-alphanumerics, compare numeric segments as
/// ints and others lexically. Good enough for "1.2.3 >= 1.2.0" style checks across
/// dpkg/rpm/brew version strings without pulling a semver crate.
fn ver_ge(have: &str, want: &str) -> bool {
    let seg = |s: &str| -> Vec<String> {
        s.split(|c: char| !c.is_ascii_alphanumeric()).filter(|x| !x.is_empty()).map(String::from).collect()
    };
    let (h, w) = (seg(have), seg(want));
    for i in 0..w.len().max(h.len()) {
        let (a, b) = (h.get(i).map(String::as_str).unwrap_or("0"), w.get(i).map(String::as_str).unwrap_or("0"));
        let ord = match (a.parse::<u64>(), b.parse::<u64>()) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            _ => a.cmp(b),
        };
        if ord != std::cmp::Ordering::Equal { return ord == std::cmp::Ordering::Greater; }
    }
    true
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;
    let name = a.get("name").and_then(|v| v.as_str()).ok_or_else(|| err("missing required arg 'name' (string)"))?;
    let min = a.get("min_version").and_then(|v| v.as_str());

    match packages::query(name) {
        Ok(info) => {
            let ver_ok = min.map(|m| ver_ge(&info.version, m)).unwrap_or(true);
            let pass = info.installed && ver_ok;
            let reason = if !info.installed { "not installed" } else if !ver_ok { "version below minimum" } else { "ok" };
            Ok(serde_json::json!({
                "tool": "package-check", "host_api": "package.query", "granted": true,
                "name": info.name, "installed": info.installed, "version": info.version,
                "source": info.source, "min_version": min, "pass": pass, "reason": reason,
            }))
        }
        Err(PackageError::NotFound) => Ok(serde_json::json!({
            "tool": "package-check", "host_api": "package.query", "granted": true,
            "name": name, "installed": false, "min_version": min, "pass": false, "reason": "not found",
        })),
        Err(PackageError::Denied) => Err(serde_json::json!({
            "tool": "package-check", "host_api": "package.query", "granted": false,
            "error": "package.query not granted in lease host_apis",
        })),
        Err(PackageError::BadInput(s)) => Err(err(format!("bad input: {s}"))),
        Err(PackageError::TransientError(s)) => Err(err(format!("transient provider error: {s}"))),
    }
}

fn main() -> ExitCode {
    match run() { Ok(v) => { println!("{v}"); ExitCode::SUCCESS } Err(v) => { println!("{v}"); ExitCode::from(1) } }
}
