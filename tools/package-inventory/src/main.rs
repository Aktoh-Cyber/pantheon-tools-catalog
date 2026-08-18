//! Synapse v2 tool — `package-inventory` (Tier 1). Full installed-package list via
//! the M11 provider `inventory.list-installed` (dpkg/rpm/apk/brew/winget). SBOM seed.
//! Lease must grant `host_apis: ["inventory.list-installed"]`; when denied the
//! provider returns an EMPTY list (read-only ops don't error) — indistinguishable
//! from "no back-end", so we report `granted:"unknown-if-empty"` honestly.
//! Args: { "max": <int, default 2000>, "name_prefix": "<optional filter>" }
//! ExitCode contract: never std::process::exit.
use std::process::ExitCode;
wit_bindgen::generate!({ path: "wit", world: "package-inventory", generate_all });
use synapse::host::inventory;

fn err(r: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "package-inventory", "error": r.into() })
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;
    let max = a.get("max").and_then(|v| v.as_u64()).unwrap_or(2000) as usize;
    let prefix = a.get("name_prefix").and_then(|v| v.as_str()).map(String::from);

    let all = inventory::list_installed();
    let total = all.len();
    let mut pkgs: Vec<serde_json::Value> = all
        .into_iter()
        .filter(|p| prefix.as_ref().map(|pf| p.name.starts_with(pf.as_str())).unwrap_or(true))
        .map(|p| serde_json::json!({ "name": p.name, "version": p.version, "source": p.source }))
        .collect();
    let matched = pkgs.len();
    let truncated = pkgs.len() > max;
    if truncated { pkgs.truncate(max); }

    Ok(serde_json::json!({
        "tool": "package-inventory",
        "host_api": "inventory.list-installed",
        // read-only denial returns [] — a caller can't distinguish denied vs no back-end
        // from the payload alone; the audit trail's host_api_call.decision is authoritative.
        "note": if total == 0 { "empty: either host_apis not granted or no package back-end detected — check audit host_api_call.decision" } else { "" },
        "total_installed": total,
        "matched": matched,
        "truncated": truncated,
        "packages": pkgs,
    }))
}

fn main() -> ExitCode {
    match run() { Ok(v) => { println!("{v}"); ExitCode::SUCCESS } Err(v) => { println!("{v}"); ExitCode::from(1) } }
}
