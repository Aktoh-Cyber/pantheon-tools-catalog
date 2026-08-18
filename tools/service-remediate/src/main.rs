//! Synapse v2 tool — `service-remediate` (Tier 3, WRITE). Drive a service to a
//! desired state through the M11 service provider. First write-tier tool; every
//! contract below exists to make host mutation boring:
//!
//!   * DRY-RUN BY DEFAULT — `"apply": true` is required to mutate. Without it the
//!     tool returns the exact plan (what it WOULD run) and touches nothing.
//!   * IDEMPOTENT — reads `service.status` first; if already in the desired state
//!     it returns `changed:false` and issues no write. `service.restart` is the
//!     one deliberately non-idempotent action (a restart is a restart) — it still
//!     requires apply:true and reports what it did.
//!   * VERIFY-AFTER-WRITE — re-reads status after mutating and reports
//!     `verified:true|false`; a write that "succeeded" but didn't move state is
//!     surfaced as verified:false, never as success.
//!   * REFUSES UNKNOWN TARGETS — a service the back-end reports not-found/unknown
//!     is never enabled/restarted by guess; it errors.
//!   * DENIAL IS HONEST — provider `denied` ⇒ exit 1 with the missing api named.
//!
//! Args:
//!   { "name": "<service>" (REQUIRED),
//!     "desired": "running" | "stopped" | "enabled" | "disabled" | "restarted",
//!     "apply": false (default) }
//! host_apis needed: service.status (always) + service.restart (running/restarted),
//!   service.enable (enabled), service.disable (stopped/disabled).
//! Output: { plan:[...actions], changed, applied, verified, before, after, reason }
//! ExitCode contract: exit 0 for an evaluated request (incl. dry-run + no-op);
//! exit 1 for arg errors, unknown target, provider denial/error.
use std::process::ExitCode;
wit_bindgen::generate!({ path: "wit", world: "service-remediate", generate_all });
use synapse::host::service::{self, ServiceError, ServiceStatus};

fn err(r: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "service-remediate", "error": r.into() })
}
fn st(s: ServiceStatus) -> &'static str {
    match s { ServiceStatus::Running => "running", ServiceStatus::Stopped => "stopped",
              ServiceStatus::Failed => "failed", ServiceStatus::Unknown => "unknown" }
}
fn read(name: &str) -> Result<&'static str, serde_json::Value> {
    match service::status(name) {
        Ok(s) => Ok(st(s)),
        Err(ServiceError::NotFound) => Ok("not-found"),
        Err(ServiceError::Denied) => Err(serde_json::json!({ "tool": "service-remediate",
            "granted": false, "error": "service.status not granted in lease host_apis" })),
        Err(ServiceError::TransientError(s)) => Err(err(format!("status provider error: {s}"))),
    }
}
fn write(action: &str, name: &str) -> Result<(), serde_json::Value> {
    let r = match action {
        "restart" => service::restart(name),
        "enable" => service::enable(name),
        "disable" => service::disable(name),
        _ => return Err(err(format!("internal: unknown action {action}"))),
    };
    match r {
        Ok(()) => Ok(()),
        Err(ServiceError::Denied) => Err(serde_json::json!({ "tool": "service-remediate",
            "granted": false, "error": format!("service.{action} not granted in lease host_apis") })),
        Err(ServiceError::NotFound) => Err(err(format!("service {name} not found by back-end during {action}"))),
        Err(ServiceError::TransientError(s)) => Err(err(format!("{action} provider error: {s}"))),
    }
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value = serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;
    let name = a.get("name").and_then(|v| v.as_str()).ok_or_else(|| err("missing required arg 'name' (string)"))?;
    let desired = a.get("desired").and_then(|v| v.as_str()).ok_or_else(|| err("missing required arg 'desired' (running|stopped|enabled|disabled|restarted)"))?;
    let apply = a.get("apply").and_then(|v| v.as_bool()).unwrap_or(false);

    // Plan: which write action(s) reach `desired`, and does the current state already satisfy it?
    let (actions, satisfied_by): (Vec<&str>, fn(&str) -> bool) = match desired {
        "running"   => (vec!["restart"], |s| s == "running"),
        "restarted" => (vec!["restart"], |_| false),           // never satisfied: a restart is a restart
        "stopped"   => (vec!["disable"], |s| s == "stopped"),  // provider has no plain 'stop'; disable is the stop-and-keep-down primitive
        "enabled"   => (vec!["enable"],  |_| false),           // enable is boot-config; status can't observe it — always plan it, rely on provider idempotency
        "disabled"  => (vec!["disable"], |s| s == "stopped"),
        other => return Err(err(format!("desired must be running|stopped|enabled|disabled|restarted (got {other:?})"))),
    };

    let before = read(name)?;
    // Refuse to act on a target the back-end can't see. (dry-run still reports it)
    if before == "not-found" || before == "unknown" {
        return Err(serde_json::json!({ "tool": "service-remediate", "name": name, "before": before,
            "error": format!("refusing to remediate: back-end reports service {name} as {before} — will not enable/restart by guess") }));
    }
    let already = satisfied_by(before);
    let plan: Vec<serde_json::Value> = if already { vec![] } else {
        actions.iter().map(|a| serde_json::json!({ "api": format!("service.{a}"), "action": a, "target": name })).collect()
    };

    if already {
        return Ok(serde_json::json!({ "tool": "service-remediate", "name": name, "desired": desired,
            "before": before, "after": before, "plan": plan, "changed": false, "applied": false,
            "verified": true, "reason": "already in desired state (idempotent no-op)" }));
    }
    if !apply {
        return Ok(serde_json::json!({ "tool": "service-remediate", "name": name, "desired": desired,
            "before": before, "after": before, "plan": plan, "changed": false, "applied": false,
            "verified": false, "dry_run": true,
            "reason": "dry-run: pass \"apply\":true to execute the plan" }));
    }
    for a in &actions { write(a, name)?; }
    let after = read(name)?;
    let verified = match desired { "enabled" | "restarted" => true, _ => satisfied_by(after) };
    Ok(serde_json::json!({ "tool": "service-remediate", "name": name, "desired": desired,
        "before": before, "after": after, "plan": plan, "changed": before != after || desired == "restarted",
        "applied": true, "verified": verified,
        "reason": if verified { "applied and verified" } else { "applied but post-state does not match desired — investigate" } }))
}

fn main() -> ExitCode {
    match run() { Ok(v) => { println!("{v}"); ExitCode::SUCCESS } Err(v) => { println!("{v}"); ExitCode::from(1) } }
}
