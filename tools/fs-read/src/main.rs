//! Synapse v2 tool — `fs-read`: read a file (bounded) and return content + sha256.
//!
//! wasm32-wasip2. The executor passes lease `args` as JSON at argv[0]. Reads
//! only what the sandbox grants (`/work` + declared mounts).
//!
//! NODE-TOOL EXIT CONTRACT (learned live 2026-08-14): a wasip2 tool must NEVER
//! call `std::process::exit()`. On the node's Wasmtime, `proc_exit` surfaces as
//! a trap — the executor's outcome match treats it as `Err(trap)`, drops the
//! captured stdout, and sends no result, so the caller hangs to the deadline
//! and the run records `exit_kind=trap` with no output. fs-read 0.1.0/0.1.1
//! did exactly this (its missing-file path is the only reachable path in an
//! empty sandbox → every invoke trapped). Instead we RETURN an `ExitCode` from
//! `main`: returning normally → exit_kind=success, returning a non-zero code →
//! exit_kind=non_zero — and in BOTH cases stdout (our JSON) is preserved and
//! delivered inline. Fail-loud is expressed by the non-zero code AND the
//! `"error"` key in the payload, not by an abrupt process exit.
//!
//! Args:
//!   { "path": "<abs path>", "max_bytes": <int, default 65536>,
//!     "encoding": "utf8" | "base64" (default "utf8") }

use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::process::ExitCode;

/// Standard base64 (RFC 4648, with padding), dependency-free.
fn b64_encode(input: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { A[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { A[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn err(reason: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "fs-read", "error": reason.into() })
}

/// All logic; returns the success payload or an error payload. `main` prints
/// whichever and maps it to an ExitCode — no `process::exit`.
fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;

    let path = a
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err("missing required arg 'path' (string)"))?;
    let max_bytes = a.get("max_bytes").and_then(|v| v.as_u64()).unwrap_or(65_536) as usize;
    let encoding = a.get("encoding").and_then(|v| v.as_str()).unwrap_or("utf8");
    if encoding != "utf8" && encoding != "base64" {
        return Err(err("encoding must be 'utf8' or 'base64'"));
    }

    let meta = fs::metadata(path).map_err(|e| err(format!("stat({path}) failed: {e}")))?;
    if !meta.is_file() {
        return Err(err(format!("{path} is not a regular file")));
    }
    let size = meta.len();

    let mut f = fs::File::open(path).map_err(|e| err(format!("open({path}) failed: {e}")))?;
    let mut buf = Vec::with_capacity(max_bytes.min(size as usize + 1));
    (&mut f)
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| err(format!("read({path}) failed: {e}")))?;
    let truncated = buf.len() > max_bytes;
    if truncated {
        buf.truncate(max_bytes);
    }

    let sha256 = {
        let mut h = Sha256::new();
        h.update(&buf);
        hex_lower(&h.finalize())
    };

    let content = match encoding {
        "base64" => b64_encode(&buf),
        _ => String::from_utf8(buf.clone())
            .map_err(|_| err("content is not valid UTF-8 — retry with \"encoding\":\"base64\""))?,
    };

    Ok(serde_json::json!({
        "tool": "fs-read",
        "path": path,
        "size_bytes": size,
        "read_bytes": buf.len(),
        "sha256": sha256,
        "truncated": truncated,
        "encoding": encoding,
        "content": content,
    }))
}

fn main() -> ExitCode {
    match run() {
        Ok(v) => {
            println!("{v}");
            ExitCode::SUCCESS
        }
        Err(v) => {
            // stdout, not stderr — Synapse captures stdout as the tool result.
            println!("{v}");
            ExitCode::from(1)
        }
    }
}
