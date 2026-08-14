//! Synapse v2 tool — `fs-hash`: checksum one or more files (sha256/sha1/md5).
//!
//! wasm32-wasip2. Lease `args` JSON at argv[0]. Reads only granted paths.
//! Fail-loud on arg errors; per-file errors are reported inline (a bad path
//! doesn't abort the whole batch) so a caller gets a complete integrity map.
//!
//! Args:
//!   { "paths": ["<abs path>", ...] }  OR  { "path": "<abs path>" }
//!   optional: "algo": "sha256" | "sha1" | "md5" (default "sha256")
//!
//! Output:
//!   { "tool":"fs-hash", "algo", "count",
//!     "results": [ { "path", "digest", "size_bytes" } | { "path", "error" } ] }

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::process::ExitCode;

fn err(reason: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "fs-hash", "error": reason.into() })
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn digest_file(path: &str, algo: &str) -> Result<(String, u64), String> {
    let meta = fs::metadata(path).map_err(|e| format!("stat failed: {e}"))?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    let mut f = fs::File::open(path).map_err(|e| format!("open failed: {e}"))?;
    let mut buf = [0u8; 65_536];
    // streaming hash so we never hold the whole file in memory
    macro_rules! stream {
        ($h:expr) => {{
            let mut h = $h;
            loop {
                let n = f.read(&mut buf).map_err(|e| format!("read failed: {e}"))?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            hex_lower(&h.finalize())
        }};
    }
    let digest = match algo {
        "sha256" => stream!(Sha256::new()),
        "sha1" => stream!(Sha1::new()),
        "md5" => stream!(Md5::new()),
        _ => return Err(format!("unknown algo '{algo}'")),
    };
    Ok((digest, meta.len()))
}

/// All logic; per-file errors stay inline in `results` (a bad path never
/// aborts the batch, exit stays 0). Only top-level ARG errors return `Err`.
/// `main` prints the payload and maps it to an ExitCode — no `process::exit`.
fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;

    let algo = a.get("algo").and_then(|v| v.as_str()).unwrap_or("sha256");
    if !matches!(algo, "sha256" | "sha1" | "md5") {
        return Err(err("algo must be one of: sha256, sha1, md5"));
    }

    let paths: Vec<String> = if let Some(arr) = a.get("paths").and_then(|v| v.as_array()) {
        arr.iter().filter_map(|v| v.as_str().map(String::from)).collect()
    } else if let Some(p) = a.get("path").and_then(|v| v.as_str()) {
        vec![p.to_string()]
    } else {
        return Err(err("provide 'paths' (array of strings) or 'path' (string)"));
    };
    if paths.is_empty() {
        return Err(err("no paths provided"));
    }

    let results: Vec<serde_json::Value> = paths
        .iter()
        .map(|p| match digest_file(p, algo) {
            Ok((digest, size)) => {
                serde_json::json!({ "path": p, "digest": digest, "size_bytes": size })
            }
            Err(e) => serde_json::json!({ "path": p, "error": e }),
        })
        .collect();

    Ok(serde_json::json!({
        "tool": "fs-hash",
        "algo": algo,
        "count": results.len(),
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
            // stdout, not stderr — Synapse captures stdout as the tool result.
            println!("{v}");
            ExitCode::from(1)
        }
    }
}
