//! Synapse v2 tool — `fim-snapshot`: file-integrity baseline of a tree.
//!
//! wasm32-wasip2. Lease `args` JSON at argv[0]. Recursively walks a granted
//! root and records sha256 (streaming) + size + mtime for every regular file,
//! then fingerprints the whole tree (sha256 over sorted "path:sha256" lines).
//! Bounded (max_files, max_file_bytes, max_depth); unreadable/oversized files
//! are skipped, never abort the walk. Fail-loud on arg errors only.
//!
//! Args:
//!   { "root": "/work",                 (optional, default "/work")
//!     "name_glob": "*.conf",           (optional, matches basename)
//!     "max_files": <int, default 5000>,
//!     "max_file_bytes": <int, default 10485760>,
//!     "max_depth": <int, default 20> }
//!
//! Output:
//!   { "tool":"fim-snapshot", "root", "count", "truncated": bool,
//!     "files": [ { "path", "sha256", "size_bytes", "modified_unix" } ],
//!     "snapshot_sha256": "<tree fingerprint>" }

use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;
use std::time::UNIX_EPOCH;

fn err(reason: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "fim-snapshot", "error": reason.into() })
}

/// Minimal glob: `*` = any run (incl. empty), `?` = one char. No character
/// classes — that's all a filename filter needs and it stays dependency-free.
fn glob_match(pat: &str, s: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pat.chars().collect(), s.chars().collect());
    let (mut pi, mut ti, mut star, mut mark) = (0usize, 0usize, usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = ti;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn mtime_unix(meta: &fs::Metadata) -> Option<u64> {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
}

/// Streaming sha256 so we never hold a whole file in memory.
fn sha256_file(path: &Path) -> Option<String> {
    let mut f = fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 65_536];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(hex_lower(&h.finalize()))
}

struct Ctx {
    name_glob: Option<String>,
    max_files: usize,
    max_file_bytes: u64,
    max_depth: usize,
}

struct Entry {
    path: String,
    sha256: String,
    size_bytes: u64,
    modified_unix: Option<u64>,
}

fn walk(dir: &Path, depth: usize, ctx: &Ctx, out: &mut Vec<Entry>) {
    if out.len() >= ctx.max_files || depth > ctx.max_depth {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return, // unreadable subtree: skip, don't abort the walk
    };
    for entry in entries.flatten() {
        if out.len() >= ctx.max_files {
            return;
        }
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            walk(&path, depth + 1, ctx, out);
        } else if meta.is_file() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(g) = &ctx.name_glob {
                if !glob_match(g, &name) {
                    continue;
                }
            }
            if meta.len() > ctx.max_file_bytes {
                continue; // oversized: skip rather than blow the time budget
            }
            let sha256 = match sha256_file(&path) {
                Some(d) => d,
                None => continue, // unreadable: skip
            };
            out.push(Entry {
                path: path.to_string_lossy().to_string(),
                sha256,
                size_bytes: meta.len(),
                modified_unix: mtime_unix(&meta),
            });
        }
    }
}

/// All logic; returns the success payload or an error payload. `main` prints
/// whichever and maps it to an ExitCode — no `process::exit`.
fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;

    let root = a.get("root").and_then(|v| v.as_str()).unwrap_or("/work").to_string();
    let max_files = a.get("max_files").and_then(|v| v.as_u64()).unwrap_or(5000) as usize;
    let max_file_bytes = a
        .get("max_file_bytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(10_485_760);
    let max_depth = a.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
    if max_files == 0 {
        return Err(err("max_files must be >= 1"));
    }

    let ctx = Ctx {
        name_glob: a.get("name_glob").and_then(|v| v.as_str()).map(String::from),
        max_files,
        max_file_bytes,
        max_depth,
    };

    let root_path = Path::new(&root);
    if !root_path.is_dir() {
        return Err(err(format!(
            "root {root} is not a directory (is it mounted into this lease?)"
        )));
    }

    let mut out: Vec<Entry> = Vec::new();
    walk(root_path, 0, &ctx, &mut out);
    // walk stops at exactly max_files, so "truncated" = we hit the cap
    let truncated = out.len() >= max_files;
    // sort by path for a deterministic listing + fingerprint
    out.sort_by(|x, y| x.path.cmp(&y.path));

    // tree fingerprint: sha256 over sorted "path:sha256\n" lines
    let mut h = Sha256::new();
    for e in &out {
        h.update(e.path.as_bytes());
        h.update(b":");
        h.update(e.sha256.as_bytes());
        h.update(b"\n");
    }
    let snapshot_sha256 = hex_lower(&h.finalize());

    let files: Vec<serde_json::Value> = out
        .iter()
        .map(|e| {
            serde_json::json!({
                "path": e.path,
                "sha256": e.sha256,
                "size_bytes": e.size_bytes,
                "modified_unix": e.modified_unix,
            })
        })
        .collect();

    Ok(serde_json::json!({
        "tool": "fim-snapshot",
        "root": root,
        "count": files.len(),
        "truncated": truncated,
        "files": files,
        "snapshot_sha256": snapshot_sha256,
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
