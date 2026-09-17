//! Synapse v2 tool — `service-baseline-diff` (Tier 2, pure compute). Compare the
//! observed state of services against an expected baseline and report the
//! mismatches: a service that should be running but isn't, one running that
//! shouldn't be, or one missing entirely. The caller pipes in the observed
//! states (from `service-status` over a list) and the expected baseline. This is
//! how shield turns a hardening standard ("telnet must be disabled, sshd must be
//! running") into a pass/fail per host.
//!
//! Args: { "observed": [{ "name","state" }, ...] (REQUIRED),
//!         "expected": [{ "name","state" }, ...] (REQUIRED) }
//!   state is a free string ("running" | "stopped" | "enabled" | "disabled"...),
//!   compared case-insensitively.
//! Output: { tool, mismatches:[{name,expected,observed}], missing:[...], compliant, checked }
//! ExitCode: 0 for an evaluated request; 1 for arg errors.
use std::collections::HashMap;
use std::process::ExitCode;

fn err(r: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "service-baseline-diff", "error": r.into() })
}

fn to_map(arr: &[serde_json::Value]) -> HashMap<String, String> {
    arr.iter()
        .filter_map(|s| {
            let n = s.get("name").and_then(|v| v.as_str())?;
            if n.is_empty() {
                return None;
            }
            Some((
                n.to_ascii_lowercase(),
                s.get("state").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase(),
            ))
        })
        .collect()
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;

    let observed = a.get("observed").and_then(|v| v.as_array())
        .ok_or_else(|| err("missing required arg 'observed' (array of {name,state})"))?;
    let expected = a.get("expected").and_then(|v| v.as_array())
        .ok_or_else(|| err("missing required arg 'expected' (array of {name,state})"))?;

    let obs = to_map(observed);
    let exp = to_map(expected);

    let mut mismatches = Vec::new();
    let mut missing = Vec::new();
    for (name, want) in &exp {
        match obs.get(name) {
            None => missing.push(serde_json::json!({ "name": name, "expected": want })),
            Some(have) if have != want => mismatches.push(serde_json::json!({
                "name": name, "expected": want, "observed": have
            })),
            Some(_) => {}
        }
    }

    let compliant = mismatches.is_empty() && missing.is_empty();
    Ok(serde_json::json!({
        "tool": "service-baseline-diff",
        "checked": exp.len(),
        "compliant": compliant,
        "mismatches": mismatches,
        "missing": missing,
    }))
}

fn main() -> ExitCode {
    match run() {
        Ok(v) => { println!("{v}"); ExitCode::SUCCESS }
        Err(v) => { println!("{v}"); ExitCode::from(1) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_compare_is_case_insensitive() {
        let obs = to_map(&[serde_json::json!({ "name": "sshd", "state": "Running" })]);
        let exp = to_map(&[serde_json::json!({ "name": "sshd", "state": "running" })]);
        assert_eq!(obs.get("sshd"), exp.get("sshd"));
    }

    #[test]
    fn missing_expected_service_is_flagged() {
        let obs = to_map(&[serde_json::json!({ "name": "sshd", "state": "running" })]);
        let exp = to_map(&[
            serde_json::json!({ "name": "sshd", "state": "running" }),
            serde_json::json!({ "name": "auditd", "state": "running" }),
        ]);
        assert!(!obs.contains_key("auditd") && exp.contains_key("auditd"));
    }
}
