//! Synapse v2 tool — `dns-resolve` (Tier 4). Resolve one or more hostnames to addresses
//! from the NODE's vantage point (its resolver, its split-horizon view). Uses the sandbox
//! name-lookup capability (`allow_ip_name_lookup`, enabled under `network_mode:"direct"`);
//! under `network_mode:"none"` every lookup fails — the honest sandbox default.
//!
//! Why this is useful: DNS answers differ by network position. A node inside a customer
//! VPC sees internal records and split-horizon results an external checker never will —
//! this tool reports what THAT node resolves, which is what its workloads actually use.
//!
//! Args: { "names": ["host", ...] (REQUIRED, max 50) }
//! Output: { tool, count, results:[{ name, addrs:[..] | error }] }
//! ExitCode contract: exit 0 for an evaluated request (NXDOMAIN is an answer); 1 for arg errors.
use std::net::ToSocketAddrs;
use std::process::ExitCode;

fn err(r: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "dns-resolve", "error": r.into() })
}

fn resolve(name: &str) -> serde_json::Value {
    // ToSocketAddrs needs a port; 0 is fine for lookup-only. Dedupe, sort.
    match (name, 0u16).to_socket_addrs() {
        Ok(it) => {
            let mut addrs: Vec<String> = it.map(|a| a.ip().to_string()).collect();
            addrs.sort(); addrs.dedup();
            serde_json::json!({ "name": name, "addrs": addrs, "count": addrs.len() })
        }
        Err(e) => serde_json::json!({ "name": name, "addrs": [], "count": 0, "error": e.to_string() }),
    }
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value = serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;
    let names: Vec<String> = a.get("names").and_then(|v| v.as_array())
        .ok_or_else(|| err("missing required arg 'names' (array of hostnames)"))?
        .iter().filter_map(|v| v.as_str().map(String::from)).collect();
    if names.is_empty() { return Err(err("'names' is empty")); }
    if names.len() > 50 { return Err(err("too many names (max 50)")); }
    let results: Vec<serde_json::Value> = names.iter().map(|n| resolve(n)).collect();
    let resolved = results.iter().filter(|r| r.get("count").and_then(|v| v.as_u64()).unwrap_or(0) > 0).count();
    Ok(serde_json::json!({ "tool": "dns-resolve", "count": results.len(), "resolved": resolved, "results": results }))
}

fn main() -> ExitCode {
    match run() { Ok(v) => { println!("{v}"); ExitCode::SUCCESS } Err(v) => { println!("{v}"); ExitCode::from(1) } }
}
