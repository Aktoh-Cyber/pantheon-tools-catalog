//! Synapse v2 tool — `banner-grab` (Tier 4, network). Connect to a service, send
//! an optional probe, read the opening bytes, and return the banner for
//! version-fingerprinting (SSH/SMTP/FTP/HTTP server strings, etc.). Reconnaissance
//! stops at the banner — this tool never authenticates and never sends more than
//! the caller's explicit probe.
//!
//! The lease must carry `network_mode:"direct"` + a `destinations` allowlist; the
//! executor audits every connect. Banners are sanitised (control bytes escaped,
//! length-capped) so a hostile service can't inject terminal escapes into an
//! operator's console via the report.
//!
//! Args: { "targets": ["host:port", ...] (REQUIRED, max 50),
//!         "send": "GET / HTTP/1.0\r\n\r\n" (optional probe to write first),
//!         "read_bytes": 512 (default, max 4096), "timeout_ms": 3000 (default) }
//! Output: { tool, count, results:[{ target, reachable, banner?, bytes, error? }] }
//! ExitCode: 0 for an evaluated request; 1 for arg errors.
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::ExitCode;
use std::time::Duration;

fn err(r: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "banner-grab", "error": r.into() })
}

/// Make raw service bytes safe to render: keep printable ASCII + \t\n\r, escape
/// everything else as \xNN, and cap the length. Prevents ANSI-escape injection
/// from a hostile banner into the operator's terminal.
fn sanitize(bytes: &[u8], cap: usize) -> String {
    let mut out = String::new();
    for &b in bytes.iter().take(cap) {
        match b {
            b'\t' | b'\n' | b'\r' => out.push(b as char),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

fn grab(target: &str, send: Option<&str>, read_bytes: usize, timeout: Duration) -> serde_json::Value {
    let addr = match target.to_socket_addrs().ok().and_then(|mut it| it.next()) {
        Some(a) => a,
        None => return serde_json::json!({ "target": target, "reachable": false, "error": "resolve failed" }),
    };
    let mut stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) => return serde_json::json!({ "target": target, "reachable": false, "error": e.to_string() }),
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    if let Some(probe) = send {
        if let Err(e) = stream.write_all(probe.as_bytes()) {
            return serde_json::json!({ "target": target, "reachable": true, "error": format!("write: {e}") });
        }
    }

    let mut buf = vec![0u8; read_bytes];
    match stream.read(&mut buf) {
        Ok(n) => serde_json::json!({
            "target": target, "reachable": true, "bytes": n,
            "banner": sanitize(&buf[..n], read_bytes)
        }),
        Err(e) => serde_json::json!({
            "target": target, "reachable": true, "bytes": 0, "error": format!("read: {e}")
        }),
    }
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;

    let targets: Vec<String> = a
        .get("targets")
        .and_then(|v| v.as_array())
        .ok_or_else(|| err("missing required arg 'targets' (array of \"host:port\")"))?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    if targets.is_empty() {
        return Err(err("'targets' is empty"));
    }
    if targets.len() > 50 {
        return Err(err("too many targets (max 50)"));
    }

    let send = a.get("send").and_then(|v| v.as_str());
    let read_bytes = (a.get("read_bytes").and_then(|v| v.as_u64()).unwrap_or(512) as usize).clamp(1, 4096);
    let timeout = Duration::from_millis(a.get("timeout_ms").and_then(|v| v.as_u64()).unwrap_or(3000));

    let results: Vec<serde_json::Value> =
        targets.iter().map(|t| grab(t, send, read_bytes, timeout)).collect();

    Ok(serde_json::json!({ "tool": "banner-grab", "count": results.len(), "results": results }))
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
    fn sanitize_keeps_printable_and_newlines() {
        assert_eq!(sanitize(b"SSH-2.0-OpenSSH_9.6\r\n", 512), "SSH-2.0-OpenSSH_9.6\r\n");
    }

    #[test]
    fn sanitize_escapes_control_and_high_bytes() {
        assert_eq!(sanitize(&[0x1b, b'[', b'2', b'J'], 512), "\\x1b[2J");
        assert_eq!(sanitize(&[0x00, 0xff], 512), "\\x00\\xff");
    }

    #[test]
    fn sanitize_caps_length() {
        assert_eq!(sanitize(b"aaaaaa", 3), "aaa");
    }
}
