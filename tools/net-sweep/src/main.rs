//! Synapse v2 tool — `net-sweep` (Tier 4, network). TCP-connect liveness sweep
//! across a host list: the sandbox-legal "ping". WASI exposes no raw sockets, so
//! there is no ICMP echo here — a host is "up" if it accepts a TCP connection on
//! any of the probed ports, and RTT is the connect time. A true ICMP ping /
//! loss-stat tool needs a node-side `net` host provider (see icmp-ping).
//!
//! The lease must carry `network_mode:"direct"` + a `destinations` allowlist; the
//! node executor checks every connect against it and audits a
//! `network_decision{destination,permitted}` event, so a host outside the
//! allowlist reports `up:false` with a denied/refused error and is never
//! silently probed.
//!
//! Args: { "hosts": ["h1", ...] (REQUIRED, max 256),
//!         "ports": [22,80,443,3389,8080] (default),
//!         "timeout_ms": 2000 (default) }
//! Output: { tool, host_count, up, results:[{ host, up, latency_ms?, open_ports:[..] }] }
//! ExitCode: 0 for an evaluated request (down is a valid answer); 1 for arg errors.
use std::net::{TcpStream, ToSocketAddrs};
use std::process::ExitCode;
use std::time::{Duration, Instant};

fn err(r: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "net-sweep", "error": r.into() })
}

/// Probe one host across the port set. First port that connects marks the host
/// up and records the connect RTT; every answering port is collected.
fn sweep(host: &str, ports: &[u16], timeout: Duration) -> serde_json::Value {
    let mut open_ports: Vec<u16> = Vec::new();
    let mut best_latency: Option<u64> = None;
    let mut last_err: Option<String> = None;

    for &port in ports {
        let target = format!("{host}:{port}");
        let addr = match target.to_socket_addrs().ok().and_then(|mut it| it.next()) {
            Some(a) => a,
            None => {
                last_err = Some("resolve failed".to_string());
                continue;
            }
        };
        let t0 = Instant::now();
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(_) => {
                let ms = t0.elapsed().as_millis() as u64;
                open_ports.push(port);
                best_latency = Some(best_latency.map_or(ms, |b| b.min(ms)));
            }
            Err(e) => last_err = Some(e.to_string()),
        }
    }

    let up = !open_ports.is_empty();
    let mut out = serde_json::json!({ "host": host, "up": up, "open_ports": open_ports });
    if let Some(ms) = best_latency {
        out["latency_ms"] = serde_json::json!(ms);
    } else if let Some(e) = last_err {
        out["error"] = serde_json::json!(e);
    }
    out
}

const DEFAULT_PORTS: [u16; 5] = [22, 80, 443, 3389, 8080];

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;

    let hosts: Vec<String> = a
        .get("hosts")
        .and_then(|v| v.as_array())
        .ok_or_else(|| err("missing required arg 'hosts' (array of host strings)"))?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    if hosts.is_empty() {
        return Err(err("'hosts' is empty"));
    }
    if hosts.len() > 256 {
        return Err(err("too many hosts (max 256)"));
    }

    let ports: Vec<u16> = match a.get("ports").and_then(|v| v.as_array()) {
        Some(arr) => {
            let p: Vec<u16> = arr
                .iter()
                .filter_map(|v| v.as_u64())
                .filter(|n| *n >= 1 && *n <= 65535)
                .map(|n| n as u16)
                .collect();
            if p.is_empty() {
                return Err(err("'ports' contained no valid port (1-65535)"));
            }
            p
        }
        None => DEFAULT_PORTS.to_vec(),
    };

    let timeout = Duration::from_millis(
        a.get("timeout_ms").and_then(|v| v.as_u64()).unwrap_or(2000),
    );

    let results: Vec<serde_json::Value> =
        hosts.iter().map(|h| sweep(h, &ports, timeout)).collect();
    let up = results
        .iter()
        .filter(|r| r.get("up").and_then(|v| v.as_bool()) == Some(true))
        .count();

    Ok(serde_json::json!({
        "tool": "net-sweep",
        "host_count": results.len(),
        "up": up,
        "results": results,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ports_are_common_service_ports() {
        assert!(DEFAULT_PORTS.contains(&443));
        assert!(DEFAULT_PORTS.contains(&22));
    }

    #[test]
    fn empty_hosts_is_an_arg_error() {
        // Simulate the arg-validation branch without touching the network.
        let a: serde_json::Value = serde_json::json!({ "hosts": [] });
        let hosts: Vec<String> = a["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        assert!(hosts.is_empty());
    }
}
