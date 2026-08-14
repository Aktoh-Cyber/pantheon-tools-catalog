//! Synapse v2 reference tool #2 — `sysinfo`.
//!
//! Purpose: prove the *full new-tool lifecycle* (author → build → cosign-keyless
//! publish → register → ship → execute) end-to-end on a real node, and give a
//! liveness/identity probe that returns *node-observed* facts rather than
//! caller-supplied ones.
//!
//! Built as `wasm32-wasip2`. The Synapse executor passes the lease's `args` as
//! the single CLI argument (JSON-encoded, at argv[0] — same contract as
//! `fs-list`). It reads that, gathers what the sandbox can genuinely observe,
//! and prints one JSON line to stdout, exit 0.
//!
//! Why this is the honest analog of a "hostname check": the wasip2 sandbox is
//! deliberately isolated from host identity (no `gethostname`, no network, only
//! a preopened `/work`). What the node CAN contribute at execution time is the
//! host wall clock — a value a deterministic guest cannot fabricate. So the
//! `wall_clock_unix_ms` field is proof the code ran *on the node, just now*, and
//! `env_keys` reports the exact env boundary the lease granted (usually empty,
//! which is itself the verifiable fact that the sandbox is locked down).
//!
//! Args contract (all optional):
//!   { "note": "<string echoed back, to correlate an invoke with its output>" }
//!
//! Per `feedback_fail_loud_not_silent`: bad args produce a structured error to
//! stdout (NOT stderr — Synapse captures stdout as the tool result) and exit 1.

use std::time::{SystemTime, UNIX_EPOCH};

fn fail(reason: &str) -> ! {
    let err = serde_json::json!({ "tool": "sysinfo", "error": reason });
    println!("{err}");
    std::process::exit(1);
}

/// djb2 — a tiny, dependency-free hash. We only need to demonstrate that the
/// guest actually executed compute over the input; a cryptographic digest would
/// pull in an extra crate for no security benefit here (the note is not a secret
/// and integrity of the *tool* is covered by cosign at publish time).
fn djb2_hex(s: &str) -> String {
    let mut h: u64 = 5381;
    for b in s.as_bytes() {
        h = h.wrapping_mul(33).wrapping_add(*b as u64);
    }
    format!("{h:016x}")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Mirror fs-list: the executor puts the JSON payload at argv[0].
    let raw = args.first().cloned().unwrap_or_else(|| "{}".to_string());
    let parsed: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => fail(&format!("args is not valid JSON: {e}")),
    };

    let note = parsed.get("note").and_then(|v| v.as_str());

    // Node-generated wall clock — the load-bearing "it really ran here, now"
    // signal. wasip2 exposes the host clock via the clocks interface; a
    // deterministic guest cannot invent this.
    let wall_clock_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // The env boundary the lease actually granted this execution. Reporting the
    // KEYS (not values) proves the sandbox scope without leaking any granted
    // secret material.
    let mut env_keys: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
    env_keys.sort();

    let out = serde_json::json!({
        "tool": "sysinfo",
        "note": note,
        "note_hash_djb2": note.map(djb2_hex),
        "observed": {
            "wall_clock_unix_ms": wall_clock_unix_ms,
            "arg_count": args.len(),
            "env_key_count": env_keys.len(),
            "env_keys": env_keys,
            "wasm_target": "wasm32-wasip2",
        },
    });
    println!("{out}");
}
