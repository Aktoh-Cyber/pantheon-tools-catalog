//! Synapse v2 tool — `port-check` (Tier 4, first NETWORK tool). TCP reachability to
//! one or more host:port targets via std::net over wasi:sockets.
//!
//! The lease must carry `network_mode:"direct"` + a `destinations` allowlist; the node
//! executor checks EVERY connect against that allowlist and records a
//! `network_decision{destination, permitted}` audit event — so a target outside the
//! allowlist fails at connect (reported here as `reachable:false`, `error:...denied/refused`)
//! and is audited, never silently allowed. With `network_mode:"none"` every connect fails.
//!
//! Args: { "targets": ["host:port", ...] (REQUIRED, max 50), "timeout_ms": 3000 (default) }
//! Output: { tool, count, results:[{ target, reachable, latency_ms, error? }] }
//! ExitCode contract: exit 0 for an evaluated request (unreachable is a valid answer);
//! exit 1 for arg errors only.
use std::net::{TcpStream, ToSocketAddrs};
use std::process::ExitCode;
use std::time::{Duration, Instant};

fn err(r: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "port-check", "error": r.into() })
}

fn check(target: &str, timeout: Duration) -> serde_json::Value {
    let t0 = Instant::now();
    // resolve (allow_ip_name_lookup is on under net:direct); take the first addr
    let addr = match target.to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => return serde_json::json!({ "target": target, "reachable": false, "error": "resolved to no addresses" }),
        },
        Err(e) => return serde_json::json!({ "target": target, "reachable": false, "error": format!("resolve: {e}") }),
    };
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_s) => serde_json::json!({ "target": target, "addr": addr.to_string(), "reachable": true,
            "latency_ms": t0.elapsed().as_millis() as u64 }),
        Err(e) => serde_json::json!({ "target": target, "addr": addr.to_string(), "reachable": false,
            "latency_ms": t0.elapsed().as_millis() as u64, "error": e.to_string() }),
    }
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value = serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;
    let targets: Vec<String> = a.get("targets").and_then(|v| v.as_array())
        .ok_or_else(|| err("missing required arg 'targets' (array of \"host:port\")"))?
        .iter().filter_map(|v| v.as_str().map(String::from)).collect();
    if targets.is_empty() { return Err(err("'targets' is empty")); }
    if targets.len() > 50 { return Err(err("too many targets (max 50)")); }
    let timeout = Duration::from_millis(a.get("timeout_ms").and_then(|v| v.as_u64()).unwrap_or(3000));
    let results: Vec<serde_json::Value> = targets.iter().map(|t| check(t, timeout)).collect();
    let reachable = results.iter().filter(|r| r.get("reachable").and_then(|v| v.as_bool()) == Some(true)).count();
    Ok(serde_json::json!({ "tool": "port-check", "count": results.len(), "reachable": reachable, "results": results }))
}

fn main() -> ExitCode {
    match run() { Ok(v) => { println!("{v}"); ExitCode::SUCCESS } Err(v) => { println!("{v}"); ExitCode::from(1) } }
}
