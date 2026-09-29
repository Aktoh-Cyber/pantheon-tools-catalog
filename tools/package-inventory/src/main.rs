//! Synapse v2 tool — `package-inventory` (Tier 1). Full installed-package list via
//! the M11 provider `inventory.list-installed` (dpkg/rpm/apk/brew/winget/registry).
//! SBOM seed. Lease must grant `host_apis: ["inventory.list-installed"]`.
//!
//! 0.2.0 (synapse #189c, needs synapse-node >= 0.1.17): a denied lease and a host
//! with no package back-end both make `list-installed` return an EMPTY list. When
//! the list is empty the tool now asks `inventory-status` and reports which it
//! was (`status`: `denied` | `no-backend` | `ready:<backend>`), instead of the
//! 0.1.0 "either not granted or no back-end" guess. A non-empty list is proof
//! of both, so `inventory-status` is not called then.
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

    // Empty list: say WHY (denied vs no back-end vs a back-end that listed nothing).
    let (status, note) = if total == 0 {
        match inventory::inventory_status() {
            inventory::BackendStatus::Denied => (
                "denied".to_string(),
                "empty: the lease does not grant inventory.list-installed (not granted)".to_string(),
            ),
            inventory::BackendStatus::NoBackend => (
                "no-backend".to_string(),
                "empty: no package back-end in the node's context (not a clean host: the node cannot see a package manager)".to_string(),
            ),
            inventory::BackendStatus::Ready(b) => (
                format!("ready:{b}"),
                format!("empty: back-end {b} is available but listed no packages"),
            ),
        }
    } else {
        ("ok".to_string(), String::new())
    };

    Ok(serde_json::json!({
        "tool": "package-inventory",
        "version": "0.2.0",
        "host_api": "inventory.list-installed",
        "status": status,
        "note": note,
        "total_installed": total,
        "matched": matched,
        "truncated": truncated,
        "packages": pkgs,
    }))
}

fn main() -> ExitCode {
    match run() { Ok(v) => { println!("{v}"); ExitCode::SUCCESS } Err(v) => { println!("{v}"); ExitCode::from(1) } }
}
