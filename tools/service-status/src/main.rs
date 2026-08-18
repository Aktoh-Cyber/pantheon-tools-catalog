//! Synapse v2 tool — `service-status` (Tier 2). Posture check: is service X running?
//! (EDR / firewall / logging agents.) Via M11 `service.status` (systemd/launchd/sc).
//! Lease must grant `host_apis: ["service.status"]`. Denied → honest error.
//! Args: { "name": "<service>" (REQUIRED) } or { "names": [...] } — batch supported;
//! per-service errors stay inline (a bad name doesn't abort the batch).
//! Output: { results: [ { name, status: running|stopped|failed|unknown|not-found } ] }
//! ExitCode contract: never std::process::exit.
use std::process::ExitCode;
wit_bindgen::generate!({ path: "wit", world: "service-status", generate_all });
use synapse::host::service::{self, ServiceError, ServiceStatus};

fn err(r: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "service-status", "error": r.into() })
}

fn status_str(s: ServiceStatus) -> &'static str {
    match s { ServiceStatus::Running => "running", ServiceStatus::Stopped => "stopped",
              ServiceStatus::Failed => "failed", ServiceStatus::Unknown => "unknown" }
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;
    let names: Vec<String> = if let Some(arr) = a.get("names").and_then(|v| v.as_array()) {
        arr.iter().filter_map(|v| v.as_str().map(String::from)).collect()
    } else if let Some(n) = a.get("name").and_then(|v| v.as_str()) { vec![n.to_string()] }
    else { return Err(err("provide 'name' (string) or 'names' (array of strings)")); };
    if names.is_empty() { return Err(err("no service names provided")); }

    let mut denied = false;
    let results: Vec<serde_json::Value> = names.iter().map(|n| match service::status(n) {
        Ok(s) => serde_json::json!({ "name": n, "status": status_str(s), "running": matches!(s, ServiceStatus::Running) }),
        Err(ServiceError::NotFound) => serde_json::json!({ "name": n, "status": "not-found", "running": false }),
        Err(ServiceError::Denied) => { denied = true; serde_json::json!({ "name": n, "status": "denied", "running": false }) }
        Err(ServiceError::TransientError(s)) => serde_json::json!({ "name": n, "status": "error", "error": s, "running": false }),
    }).collect();

    if denied {
        return Err(serde_json::json!({ "tool": "service-status", "host_api": "service.status",
            "granted": false, "error": "service.status not granted in lease host_apis", "results": results }));
    }
    Ok(serde_json::json!({ "tool": "service-status", "host_api": "service.status", "granted": true,
        "count": results.len(), "results": results }))
}

fn main() -> ExitCode {
    match run() { Ok(v) => { println!("{v}"); ExitCode::SUCCESS } Err(v) => { println!("{v}"); ExitCode::from(1) } }
}
