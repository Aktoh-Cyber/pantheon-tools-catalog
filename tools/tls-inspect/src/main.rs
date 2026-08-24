//! tls-inspect — certificate facts for a TLS endpoint, via the host's native
//! handshake (`synapse:host/tls.inspect`, synapse #147). The sandbox needs no
//! network capability at all: the lease grants `host_apis: ["tls.inspect"]`
//! and names the target in `destinations` (host-enforced, fail closed).
//!
//! args (JSON at argv[0]):
//!   { "host": "example.com", "port": 443 }        port defaults to 443
//!
//! Node-tool contract: JSON on stdout, `ExitCode` (never process::exit —
//! proc_exit traps on the node's wasmtime).

use std::process::ExitCode;

wit_bindgen::generate!({ path: "wit", world: "tls-inspect", generate_all });

use synapse::host::tls::{self, TlsError};

fn err(r: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "tls-inspect", "error": r.into() })
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;
    let host = a
        .get("host")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err("missing required arg 'host' (string)"))?;
    let port = match a.get("port") {
        None => 443u16,
        Some(v) => v
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p > 0)
            .ok_or_else(|| err("'port' must be an integer in 1..=65535"))?,
    };

    match tls::inspect(host, port) {
        Ok(i) => Ok(serde_json::json!({
            "tool": "tls-inspect",
            "host": host,
            "port": port,
            "subject": i.subject,
            "issuer": i.issuer,
            "not_before": i.not_before,
            "not_after": i.not_after,
            "days_until_expiry": i.days_until_expiry,
            "expired": i.days_until_expiry < 0,
            "sans": i.sans,
            "chain_len": i.chain_len,
            "protocol": i.protocol,
            "cipher": i.cipher,
            "self_signed": i.self_signed,
        })),
        Err(TlsError::Denied) => Err(serde_json::json!({
            "tool": "tls-inspect", "granted": false,
            "error": "tls.inspect not granted in lease host_apis" })),
        Err(TlsError::DestinationDenied) => Err(serde_json::json!({
            "tool": "tls-inspect", "granted": false,
            "error": format!("destination {host}:{port} not permitted by the lease's destinations allowlist") })),
        Err(TlsError::ConnectError(e)) => Err(err(format!("connect: {e}"))),
        Err(TlsError::HandshakeError(e)) => Err(err(format!("handshake: {e}"))),
    }
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
