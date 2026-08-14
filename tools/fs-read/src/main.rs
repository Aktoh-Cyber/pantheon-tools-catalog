//! Synapse v2 tool — `fs-read`: read a file (bounded) and return its content + sha256.
//!
//! wasm32-wasip2. The executor passes lease `args` as JSON at argv[0] (same
//! contract as fs-list/sysinfo). Reads only what the sandbox grants (`/work`
//! + declared mounts). Fail-loud: structured error to stdout, exit 1.
//!
//! Args:
//!   { "path": "<abs path under /work or a mount>",
//!     "max_bytes": <int, optional, default 65536>,
//!     "encoding": "utf8" | "base64" (optional, default "utf8") }
//!
//! Output:
//!   { "tool":"fs-read", "path", "size_bytes", "read_bytes", "sha256",
//!     "truncated": bool, "encoding", "content": "<string>" }

use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;

/// Standard base64 (RFC 4648, with padding), implemented inline so the tool
/// carries no extra crate. The `base64` crate traps on the node's wasmtime
/// (proven live 2026-08-14: fs-read at 0.1.0 recorded exit_kind=trap on-node
/// while running clean locally; it was the only Tier-0 tool pulling base64 and
/// the only one that trapped). Dependency-free encoding sidesteps that entirely.
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

fn fail(reason: &str) -> ! {
    println!("{}", serde_json::json!({ "tool": "fs-read", "error": reason }));
    std::process::exit(1);
}

fn main() {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| fail(&format!("args is not valid JSON: {e}")));

    let path = match a.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => fail("missing required arg 'path' (string)"),
    };
    let max_bytes = a.get("max_bytes").and_then(|v| v.as_u64()).unwrap_or(65_536) as usize;
    let encoding = a.get("encoding").and_then(|v| v.as_str()).unwrap_or("utf8");
    if encoding != "utf8" && encoding != "base64" {
        fail("encoding must be 'utf8' or 'base64'");
    }

    let meta = fs::metadata(path).unwrap_or_else(|e| fail(&format!("stat({path}) failed: {e}")));
    if !meta.is_file() {
        fail(&format!("{path} is not a regular file"));
    }
    let size = meta.len();

    let mut f = fs::File::open(path).unwrap_or_else(|e| fail(&format!("open({path}) failed: {e}")));
    let mut buf = Vec::with_capacity(max_bytes.min(size as usize + 1));
    // read at most max_bytes + 1 so we can detect truncation deterministically
    let mut limited = (&mut f).take(max_bytes as u64 + 1);
    limited
        .read_to_end(&mut buf)
        .unwrap_or_else(|e| fail(&format!("read({path}) failed: {e}")));
    let truncated = buf.len() > max_bytes;
    if truncated {
        buf.truncate(max_bytes);
    }

    // sha256 is over the bytes actually returned (so a caller can verify content).
    let sha256 = {
        let mut h = Sha256::new();
        h.update(&buf);
        hex_lower(&h.finalize())
    };

    let content = match encoding {
        "base64" => b64_encode(&buf),
        _ => match String::from_utf8(buf.clone()) {
            Ok(s) => s,
            Err(_) => fail("content is not valid UTF-8 — retry with \"encoding\":\"base64\""),
        },
    };

    println!(
        "{}",
        serde_json::json!({
            "tool": "fs-read",
            "path": path,
            "size_bytes": size,
            "read_bytes": buf.len(),
            "sha256": sha256,
            "truncated": truncated,
            "encoding": encoding,
            "content": content,
        })
    );
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
