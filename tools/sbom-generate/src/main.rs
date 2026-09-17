//! Synapse v2 tool — `sbom-generate` (Tier 1, pure compute). Turn an installed-
//! package list into a CycloneDX 1.5 SBOM. No host access at the WASM level: the
//! caller pipes in the inventory (from `package-inventory`), and this tool emits
//! the bill of materials. Gives mason a first-party SBOM and judge a real artifact
//! to score CVEs against, instead of trusting a customer-supplied one.
//!
//! Args: { "packages": [{ "name":"openssl", "version":"3.0.11", "source":"apt" }, ...] (REQUIRED),
//!         "component_type": "application" (default), "subject": "host-42" (optional bom name) }
//! Output: a CycloneDX 1.5 bom object: { bomFormat, specVersion, version, metadata, components:[...] }
//! ExitCode: 0 for an evaluated request; 1 for arg errors.
use std::process::ExitCode;

fn err(r: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "sbom-generate", "error": r.into() })
}

/// A CycloneDX purl for a package. We can't know the ecosystem precisely from a
/// bare inventory, so we map the package `source` to a best-effort purl type and
/// fall back to `generic` — an honest, parseable identifier rather than a guess
/// dressed as certainty.
fn purl(name: &str, version: &str, source: &str) -> String {
    let ptype = match source {
        "apt" | "dpkg" => "deb",
        "rpm" | "dnf" | "yum" => "rpm",
        "apk" => "apk",
        "brew" => "brew",
        "winget" => "winget",
        _ => "generic",
    };
    format!("pkg:{ptype}/{name}@{version}")
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;

    let packages = a.get("packages").and_then(|v| v.as_array())
        .ok_or_else(|| err("missing required arg 'packages' (array of {name,version,source?})"))?;

    let component_type = a.get("component_type").and_then(|v| v.as_str()).unwrap_or("application");
    let subject = a.get("subject").and_then(|v| v.as_str()).unwrap_or("pantheon-target");

    let components: Vec<serde_json::Value> = packages
        .iter()
        .filter_map(|p| {
            let name = p.get("name").and_then(|v| v.as_str())?;
            if name.is_empty() {
                return None;
            }
            let version = p.get("version").and_then(|v| v.as_str()).unwrap_or("");
            let source = p.get("source").and_then(|v| v.as_str()).unwrap_or("generic");
            Some(serde_json::json!({
                "type": "library",
                "name": name,
                "version": version,
                "purl": purl(name, version, source),
            }))
        })
        .collect();

    Ok(serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": { "type": component_type, "name": subject },
            "tools": [{ "name": "sbom-generate", "vendor": "synapse" }]
        },
        "components": components,
        "tool": "sbom-generate",
        "component_count": packages.len(),
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
    fn purl_maps_known_sources() {
        assert_eq!(purl("openssl", "3.0.11", "apt"), "pkg:deb/openssl@3.0.11");
        assert_eq!(purl("httpd", "2.4", "rpm"), "pkg:rpm/httpd@2.4");
    }

    #[test]
    fn purl_falls_back_to_generic() {
        assert_eq!(purl("mystery", "1.0", "unknown-src"), "pkg:generic/mystery@1.0");
    }
}
