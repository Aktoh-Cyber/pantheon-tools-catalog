//! Synapse v2 tool — `package-drift` (Tier 2, pure compute). Diff an installed-
//! package list against a golden manifest and report what was added, removed, or
//! version-changed. No host access at the WASM level: the caller pipes in the
//! live inventory (from `package-inventory`) and the approved baseline. Drift is
//! shield's and judge's early signal that a host no longer matches its build.
//!
//! Args: { "installed": [{ "name","version" }, ...] (REQUIRED),
//!         "golden":    [{ "name","version" }, ...] (REQUIRED) }
//! Output: { tool, added:[{name,version}], removed:[{name,version}], changed:[{name,from,to}], drift_count }
//! ExitCode: 0 for an evaluated request (no drift is a valid answer); 1 for arg errors.
use std::collections::HashMap;
use std::process::ExitCode;

fn err(r: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "package-drift", "error": r.into() })
}

fn to_map(arr: &[serde_json::Value]) -> HashMap<String, String> {
    arr.iter()
        .filter_map(|p| {
            let n = p.get("name").and_then(|v| v.as_str())?;
            if n.is_empty() {
                return None;
            }
            Some((n.to_string(), p.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string()))
        })
        .collect()
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;

    let installed = a.get("installed").and_then(|v| v.as_array())
        .ok_or_else(|| err("missing required arg 'installed' (array of {name,version})"))?;
    let golden = a.get("golden").and_then(|v| v.as_array())
        .ok_or_else(|| err("missing required arg 'golden' (array of {name,version})"))?;

    let inst = to_map(installed);
    let gold = to_map(golden);

    let mut added = Vec::new();
    let mut changed = Vec::new();
    for (name, ver) in &inst {
        match gold.get(name) {
            None => added.push(serde_json::json!({ "name": name, "version": ver })),
            Some(gv) if gv != ver => {
                changed.push(serde_json::json!({ "name": name, "from": gv, "to": ver }))
            }
            Some(_) => {}
        }
    }
    let mut removed = Vec::new();
    for (name, ver) in &gold {
        if !inst.contains_key(name) {
            removed.push(serde_json::json!({ "name": name, "version": ver }));
        }
    }

    let drift_count = added.len() + removed.len() + changed.len();
    Ok(serde_json::json!({
        "tool": "package-drift",
        "added": added, "removed": removed, "changed": changed,
        "drift_count": drift_count,
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

    fn arr(pairs: &[(&str, &str)]) -> Vec<serde_json::Value> {
        pairs.iter().map(|(n, v)| serde_json::json!({ "name": n, "version": v })).collect()
    }

    #[test]
    fn detects_added_removed_changed() {
        let inst = arr(&[("openssl", "3.0.14"), ("curl", "8.5.0"), ("newpkg", "1.0")]);
        let gold = arr(&[("openssl", "3.0.11"), ("curl", "8.5.0"), ("oldpkg", "2.0")]);
        let i = to_map(&inst);
        let g = to_map(&gold);
        // openssl changed, newpkg added, oldpkg removed, curl unchanged
        assert_eq!(i.get("openssl").unwrap(), "3.0.14");
        assert!(g.contains_key("oldpkg") && !i.contains_key("oldpkg"));
        assert!(i.contains_key("newpkg") && !g.contains_key("newpkg"));
    }

    #[test]
    fn empty_name_is_skipped() {
        let m = to_map(&[serde_json::json!({ "name": "", "version": "1" })]);
        assert!(m.is_empty());
    }
}
