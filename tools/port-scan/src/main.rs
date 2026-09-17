//! Synapse v2 tool — `port-scan` (Tier 4, network). Multi-port TCP scan of ONE
//! host. Where `port-check` probes a handful of explicit host:port targets and
//! `net-sweep` probes many hosts on a few ports, `port-scan` probes one host
//! across an explicit list or a bounded range and reports which ports are open.
//!
//! The lease must carry `network_mode:"direct"` + a `destinations` allowlist; the
//! node executor audits every connect and denies anything outside it. Output
//! lists the OPEN ports in full and summarises the closed count, to keep a
//! 1024-port scan's payload small.
//!
//! Args: { "host": "h" (REQUIRED),
//!         "ports": [22,80,...] OR "port_range": "1-1024",
//!         "timeout_ms": 1500 (default), "max_ports": 1024 (hard cap) }
//! Output: { tool, host, scanned, open_count, open:[{ port, latency_ms }], closed_count }
//! ExitCode: 0 for an evaluated scan; 1 for arg errors.
use std::net::{TcpStream, ToSocketAddrs};
use std::process::ExitCode;
use std::time::{Duration, Instant};

fn err(r: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "port-scan", "error": r.into() })
}

/// Parse "1-1024" into an inclusive port list. Rejects reversed / zero / >65535.
fn parse_range(s: &str) -> Result<Vec<u16>, String> {
    let (lo, hi) = s
        .split_once('-')
        .ok_or_else(|| format!("port_range '{s}' must be 'low-high'"))?;
    let lo: u32 = lo.trim().parse().map_err(|_| format!("bad low port in '{s}'"))?;
    let hi: u32 = hi.trim().parse().map_err(|_| format!("bad high port in '{s}'"))?;
    if lo < 1 || hi > 65535 || lo > hi {
        return Err(format!("port_range '{s}' out of bounds (1-65535, low<=high)"));
    }
    Ok((lo..=hi).map(|n| n as u16).collect())
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;

    let host = a
        .get("host")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err("missing required arg 'host'"))?
        .to_string();

    let max_ports = a.get("max_ports").and_then(|v| v.as_u64()).unwrap_or(1024) as usize;

    let ports: Vec<u16> = if let Some(arr) = a.get("ports").and_then(|v| v.as_array()) {
        arr.iter()
            .filter_map(|v| v.as_u64())
            .filter(|n| *n >= 1 && *n <= 65535)
            .map(|n| n as u16)
            .collect()
    } else if let Some(r) = a.get("port_range").and_then(|v| v.as_str()) {
        parse_range(r).map_err(err)?
    } else {
        return Err(err("provide either 'ports' (array) or 'port_range' (\"low-high\")"));
    };

    if ports.is_empty() {
        return Err(err("no valid ports to scan"));
    }
    if ports.len() > max_ports {
        return Err(err(format!(
            "scan of {} ports exceeds max_ports={} (raise it deliberately)",
            ports.len(),
            max_ports
        )));
    }

    let timeout = Duration::from_millis(
        a.get("timeout_ms").and_then(|v| v.as_u64()).unwrap_or(1500),
    );

    let mut open: Vec<serde_json::Value> = Vec::new();
    let mut closed = 0u32;
    for &port in &ports {
        let target = format!("{host}:{port}");
        let addr = match target.to_socket_addrs().ok().and_then(|mut it| it.next()) {
            Some(a) => a,
            None => return Err(err(format!("host '{host}' did not resolve"))),
        };
        let t0 = Instant::now();
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(_) => open.push(serde_json::json!({
                "port": port, "latency_ms": t0.elapsed().as_millis() as u64
            })),
            Err(_) => closed += 1,
        }
    }

    Ok(serde_json::json!({
        "tool": "port-scan",
        "host": host,
        "scanned": ports.len(),
        "open_count": open.len(),
        "open": open,
        "closed_count": closed,
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
    fn parse_range_ok() {
        let p = parse_range("22-25").unwrap();
        assert_eq!(p, vec![22, 23, 24, 25]);
    }

    #[test]
    fn parse_range_rejects_reversed() {
        assert!(parse_range("100-1").is_err());
    }

    #[test]
    fn parse_range_rejects_out_of_bounds() {
        assert!(parse_range("0-10").is_err());
        assert!(parse_range("1-70000").is_err());
    }

    #[test]
    fn parse_range_needs_dash() {
        assert!(parse_range("443").is_err());
    }
}
