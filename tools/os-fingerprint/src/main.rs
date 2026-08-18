//! Synapse v2 tool — `os-fingerprint` (Tier 1, first host-API tool).
//!
//! A wasi:cli command that imports the M11 first-party host provider
//! `synapse:host/inventory` and reports the node's OS family / version / arch.
//! This is the first catalog tool to exercise the host-provider seam through
//! the REAL executor (`Command::instantiate_async` with `register_in_linker`),
//! not the integration-test harness.
//!
//! Capability contract: the lease MUST grant `host_apis: ["inventory.os-info"]`.
//! When it is not granted the provider does NOT error — it returns a placeholder
//! `HostOs { kind: Other("denied"), version: "", arch }` and records a denied
//! `host_api_call` audit event. We surface that honestly as `granted:false` so
//! a caller can tell "denied by policy" from "unknown OS".
//!
//! Args: {} (none). Follows the node-tool exit contract: return an ExitCode,
//! never std::process::exit (proc_exit traps on the node's Wasmtime).

use std::process::ExitCode;

wit_bindgen::generate!({
    path: "wit",
    world: "os-fingerprint",
    // `inventory` uses `packages.{package-info}` transitively — generate every
    // interface the world reaches so the type resolves.
    generate_all,
});

use synapse::host::inventory::{self, OsKind};

fn err(reason: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "os-fingerprint", "error": reason.into() })
}

fn kind_str(k: &OsKind) -> (String, bool) {
    // (label, is_denied_placeholder)
    match k {
        OsKind::LinuxDebian => ("linux-debian".into(), false),
        OsKind::LinuxRhel => ("linux-rhel".into(), false),
        OsKind::LinuxAlpine => ("linux-alpine".into(), false),
        OsKind::Macos => ("macos".into(), false),
        OsKind::Windows => ("windows".into(), false),
        OsKind::Other(s) if s == "denied" => ("denied".into(), true),
        OsKind::Other(s) => (format!("other:{s}"), false),
    }
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    // Args are optional but must still be valid JSON if present.
    let _a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;

    let host = inventory::os_info();
    let (kind, denied) = kind_str(&host.kind);

    Ok(serde_json::json!({
        "tool": "os-fingerprint",
        "host_api": "inventory.os-info",
        "granted": !denied,
        "os": {
            "kind": kind,
            "version": host.version,
            "arch": host.arch,
        },
    }))
}

fn main() -> ExitCode {
    match run() {
        Ok(v) => {
            println!("{v}");
            ExitCode::SUCCESS
        }
        Err(v) => {
            println!("{v}");
            ExitCode::from(1)
        }
    }
}
