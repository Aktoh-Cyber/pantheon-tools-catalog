//! Synapse v2 tool — `vuln-match` (Tier 0, pure compute). Closes judge's flagship
//! gap: take an installed-package list and an advisory feed and report which
//! packages are exposed. No network at the WASM level — the caller pipes in the
//! inventory (from `package-inventory`) and the advisory set (from pulse's CVE/OSV
//! corpus), and this tool does the version math. A package matches an advisory
//! when its name matches AND its version is below the advisory's `fixed_version`
//! (or appears in an explicit `vulnerable` list).
//!
//! Args: { "packages":   [{ "name":"openssl", "version":"3.0.11" }, ...] (REQUIRED),
//!         "advisories": [{ "id":"CVE-...","package":"openssl","fixed_version":"3.0.14",
//!                          "severity":"high" }, ...] (REQUIRED) }
//! Output: { tool, packages, advisories, match_count, matches:[{ package, version, id, fixed_version, severity }] }
//! ExitCode: 0 for an evaluated request (zero matches is a clean bill); 1 for arg errors.
use std::cmp::Ordering;
use std::process::ExitCode;

fn err(r: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "vuln-match", "error": r.into() })
}

/// Compare dotted versions numerically, component by component. Non-numeric
/// components compare as 0 (so "3.0.11" vs "3.0.14" works; "1.0-rc" degrades
/// gracefully rather than panicking). Shorter version is padded with zeros.
fn ver_cmp(a: &str, b: &str) -> Ordering {
    let split = |s: &str| -> Vec<u64> {
        s.split(|c: char| c == '.' || c == '-' || c == '+' || c == '~')
            .map(|p| p.chars().take_while(|c| c.is_ascii_digit()).collect::<String>())
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let (va, vb) = (split(a), split(b));
    let n = va.len().max(vb.len());
    for i in 0..n {
        let x = va.get(i).copied().unwrap_or(0);
        let y = vb.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;

    let packages = a.get("packages").and_then(|v| v.as_array())
        .ok_or_else(|| err("missing required arg 'packages' (array of {name,version})"))?;
    let advisories = a.get("advisories").and_then(|v| v.as_array())
        .ok_or_else(|| err("missing required arg 'advisories' (array of {id,package,fixed_version|vulnerable,severity})"))?;

    let mut matches: Vec<serde_json::Value> = Vec::new();

    for pkg in packages {
        let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        for adv in advisories {
            let a_pkg = adv.get("package").and_then(|v| v.as_str()).unwrap_or("");
            if !a_pkg.eq_ignore_ascii_case(name) {
                continue;
            }
            let severity = adv.get("severity").and_then(|v| v.as_str()).unwrap_or("unknown");
            let id = adv.get("id").and_then(|v| v.as_str()).unwrap_or("(no id)");

            // Explicit vulnerable-version list takes precedence over a fixed_version range.
            let exact_hit = adv.get("vulnerable").and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|x| x.as_str()).any(|v| v == version))
                .unwrap_or(false);

            let range_hit = adv.get("fixed_version").and_then(|v| v.as_str())
                .map(|fixed| ver_cmp(version, fixed) == Ordering::Less)
                .unwrap_or(false);

            if exact_hit || range_hit {
                let mut m = serde_json::json!({
                    "package": name, "version": version, "id": id, "severity": severity
                });
                if let Some(fixed) = adv.get("fixed_version").and_then(|v| v.as_str()) {
                    m["fixed_version"] = serde_json::json!(fixed);
                }
                matches.push(m);
            }
        }
    }

    Ok(serde_json::json!({
        "tool": "vuln-match",
        "packages": packages.len(),
        "advisories": advisories.len(),
        "match_count": matches.len(),
        "matches": matches,
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
    fn version_compare_numeric() {
        assert_eq!(ver_cmp("3.0.11", "3.0.14"), Ordering::Less);
        assert_eq!(ver_cmp("3.0.14", "3.0.14"), Ordering::Equal);
        assert_eq!(ver_cmp("3.1.0", "3.0.14"), Ordering::Greater);
    }

    #[test]
    fn version_compare_uneven_lengths() {
        assert_eq!(ver_cmp("1.2", "1.2.0"), Ordering::Equal);
        assert_eq!(ver_cmp("1.2", "1.2.1"), Ordering::Less);
    }

    #[test]
    fn version_compare_tolerates_suffixes() {
        // must not panic on non-numeric tails
        assert_eq!(ver_cmp("1.0.0-rc1", "1.0.0"), Ordering::Equal);
        assert_eq!(ver_cmp("2.0.0", "2.0.1-beta"), Ordering::Less);
    }
}
