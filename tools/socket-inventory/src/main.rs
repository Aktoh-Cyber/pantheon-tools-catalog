//! Synapse v2 tool — `socket-inventory` (Tier 1, read-only inventory).
//!
//! The host's service map: every listening TCP socket and bound UDP socket, the
//! process that owns it, and the addresses it is bound to. With
//! `include_connections` it also lists established peers, which is what an IOC
//! match needs. It lists sockets; it never opens one (the sandbox stays
//! `net:none`), so it is a local inventory, not a scan.
//!
//! Host API: `process.list-owned-sockets` (synapse-node >= 0.1.17). The lease must
//! grant it in `host_apis`; the catalog manifest declares it, so the control plane
//! fills it in when the caller leaves `capabilities` empty.
//!
//! Args (all optional):
//!   { "include_connections": false,   // also return established peers
//!     "max_connections": 500 }        // cap on returned connections
//!
//! Output: one JSON line. `services` groups sockets by (protocol, port, owner),
//! merging the IPv4 and IPv6 binds of one daemon into one entry. `exposure` is
//! `loopback` (only 127/8 or ::1), `all` (0.0.0.0 or ::) or `specific` (bound
//! to a particular interface address). `ephemeral_port` marks ports >= 32768,
//! where client libraries and dev tooling bind, so a consumer can tell them
//! apart from real services. Exit 0 = evaluated; exit 1 = bad args or the host
//! refused (denied / unsupported), with `error` set. ExitCode contract: never
//! std::process::exit.
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::process::ExitCode;

wit_bindgen::generate!({ path: "wit", world: "socket-inventory", generate_all });
use synapse::host::process::{self, OwnedSocket, ProcError};

const VERSION: &str = "0.1.1";
/// The node captures at most 64 KiB of a tool's stdout; a longer write fails,
/// and a failed `println!` panics into a wasm trap with no output at all
/// (0.1.0 on a busy macOS laptop). Stay well under it.
const OUTPUT_BUDGET: usize = 56 * 1024;
const HOST_API: &str = "process.list-owned-sockets";
const EPHEMERAL_FLOOR: u16 = 32768;

fn err(reason: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "socket-inventory", "version": VERSION, "error": reason.into() })
}

/// Strip an IPv6 zone (`fe80::1%en0`) before parsing.
fn parse_ip(addr: &str) -> Option<IpAddr> {
    addr.split('%').next().unwrap_or(addr).parse().ok()
}

fn is_loopback(addr: &str) -> bool {
    match parse_ip(addr) {
        Some(IpAddr::V4(v4)) => v4.is_loopback(),
        Some(IpAddr::V6(v6)) => {
            v6.is_loopback() || v6.to_ipv4_mapped().map(|v4| v4.is_loopback()).unwrap_or(false)
        }
        None => false,
    }
}

fn is_wildcard(addr: &str) -> bool {
    matches!(addr, "0.0.0.0" | "::" | "*" | "")
}

/// A peer worth matching against public threat intel: not private, loopback,
/// link-local, CGNAT, multicast, documentation or unspecified.
fn is_public(addr: &str) -> bool {
    match parse_ip(addr) {
        Some(IpAddr::V4(v4)) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || (o[0] == 100 && (o[1] & 0xC0) == 64)) // 100.64.0.0/10 CGNAT
        }
        Some(IpAddr::V6(v6)) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(&v4.to_string());
            }
            let seg = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (seg[0] & 0xffc0) == 0xfe80) // fe80::/10 link local
        }
        None => false,
    }
}

fn family(protocol: &str) -> &'static str {
    if protocol.starts_with("udp") {
        "udp"
    } else {
        "tcp"
    }
}

#[derive(Default)]
struct Service {
    pid: Option<u32>,
    binds: BTreeSet<String>,
    ip_versions: BTreeSet<&'static str>,
}

fn services(listeners: &[OwnedSocket]) -> Vec<serde_json::Value> {
    // (family, port, owner) → service. Owner is the process name, or the pid
    // when the platform could not name it, or "" when neither is known.
    let mut map: BTreeMap<(&'static str, u16, String), Service> = BTreeMap::new();
    for s in listeners {
        let owner = if !s.process.is_empty() {
            s.process.clone()
        } else {
            s.pid.map(|p| format!("pid:{p}")).unwrap_or_default()
        };
        let e = map.entry((family(&s.protocol), s.local_port, owner)).or_default();
        e.pid = e.pid.or(s.pid);
        e.binds.insert(s.local_addr.clone());
        e.ip_versions.insert(if s.protocol.ends_with('6') { "6" } else { "4" });
    }
    map.into_iter()
        .map(|((proto, port, owner), svc)| {
            let exposure = if svc.binds.iter().any(|b| is_wildcard(b)) {
                "all"
            } else if svc.binds.iter().all(|b| is_loopback(b)) {
                "loopback"
            } else {
                "specific"
            };
            serde_json::json!({
                "proto": proto,
                "port": port,
                "process": owner,
                "pid": svc.pid,
                "binds": svc.binds.into_iter().collect::<Vec<_>>(),
                "ip_versions": svc.ip_versions.into_iter().collect::<Vec<_>>(),
                "exposure": exposure,
                "ephemeral_port": port >= EPHEMERAL_FLOOR,
            })
        })
        .collect()
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let raw = if raw.trim().is_empty() { "{}".to_string() } else { raw };
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;
    if !a.is_object() {
        return Err(err("args must be a JSON object"));
    }
    let include_connections = match a.get("include_connections") {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(_) => return Err(err("include_connections must be a boolean")),
    };
    let max_connections = match a.get("max_connections") {
        None | Some(serde_json::Value::Null) => 500usize,
        Some(v) => v
            .as_u64()
            .filter(|n| (1..=5000).contains(n))
            .ok_or_else(|| err("max_connections must be an integer 1..=5000"))?
            as usize,
    };

    let sockets = process::list_owned_sockets(!include_connections).map_err(|e| match e {
        ProcError::Denied(m) => {
            let mut v = err(format!("denied: {m}"));
            v["denied"] = serde_json::Value::Bool(true);
            v["host_api"] = serde_json::Value::String(HOST_API.into());
            v
        }
        ProcError::IoError(m) => err(format!("host could not list sockets: {m}")),
    })?;

    let (listeners, others): (Vec<OwnedSocket>, Vec<OwnedSocket>) = sockets
        .into_iter()
        .partition(|s| s.state == "LISTEN" || s.state == "UNCONN");
    let svc = services(&listeners);

    let mut out = serde_json::json!({
        "tool": "socket-inventory",
        "version": VERSION,
        "host_api": HOST_API,
        "listening_sockets": listeners.len(),
        "service_count": svc.len(),
        "services": svc,
        "owner_unknown": listeners.iter().filter(|s| s.pid.is_none() && s.process.is_empty()).count(),
    });

    if include_connections {
        let established: Vec<&OwnedSocket> =
            others.iter().filter(|s| !s.remote_addr.is_empty()).collect();
        let peers: BTreeSet<String> = established
            .iter()
            .filter(|s| is_public(&s.remote_addr))
            .map(|s| s.remote_addr.clone())
            .collect();
        let truncated = established.len() > max_connections;
        let conns: Vec<serde_json::Value> = established
            .iter()
            .take(max_connections)
            .map(|s| {
                serde_json::json!({
                    "proto": s.protocol,
                    "state": s.state,
                    "local_addr": s.local_addr,
                    "local_port": s.local_port,
                    "remote_addr": s.remote_addr,
                    "remote_port": s.remote_port,
                    "process": s.process,
                    "pid": s.pid,
                })
            })
            .collect();
        out["connection_count"] = established.len().into();
        out["connections_truncated"] = truncated.into();
        out["connections"] = conns.into();
        out["remote_peers"] = peers.into_iter().collect::<Vec<_>>().into();
    }
    Ok(out)
}

/// Shrink the result until it fits the node's stdout capture, dropping the
/// least useful detail first and saying so: per-connection rows (the counts and
/// `remote_peers` stay), then peers beyond what fits, then ephemeral-port
/// services, then any remaining services. Never silently.
fn fit_budget(mut v: serde_json::Value) -> serde_json::Value {
    let size = |v: &serde_json::Value| v.to_string().len();
    if size(&v) <= OUTPUT_BUDGET {
        return v;
    }
    if v.get("connections").is_some() {
        v["connections"] = serde_json::json!([]);
        v["connections_omitted"] = true.into();
        v["connections_truncated"] = true.into();
    }
    while size(&v) > OUTPUT_BUDGET {
        let peers = v["remote_peers"].as_array().map(|a| a.len()).unwrap_or(0);
        if peers == 0 {
            break;
        }
        let keep = peers / 2;
        if let Some(a) = v["remote_peers"].as_array_mut() {
            a.truncate(keep);
        }
        v["remote_peers_truncated"] = true.into();
    }
    if size(&v) > OUTPUT_BUDGET {
        if let Some(a) = v["services"].as_array_mut() {
            let before = a.len();
            a.retain(|s| !s["ephemeral_port"].as_bool().unwrap_or(false));
            let dropped = before - a.len();
            v["ephemeral_services_omitted"] = dropped.into();
        }
    }
    while size(&v) > OUTPUT_BUDGET {
        let n = v["services"].as_array().map(|a| a.len()).unwrap_or(0);
        if n == 0 {
            break;
        }
        if let Some(a) = v["services"].as_array_mut() {
            a.truncate(n * 3 / 4);
        }
        v["services_truncated"] = true.into();
    }
    v
}

/// Print one JSON line without panicking if stdout refuses the write.
fn emit(v: &serde_json::Value) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{v}");
    let _ = out.flush();
}

fn main() -> ExitCode {
    match run() {
        Ok(v) => {
            emit(&fit_budget(v));
            ExitCode::SUCCESS
        }
        Err(v) => {
            emit(&v);
            ExitCode::from(1)
        }
    }
}
