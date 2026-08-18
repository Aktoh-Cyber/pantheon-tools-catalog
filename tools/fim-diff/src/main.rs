//! Synapse v2 tool — `fim-diff`: file-integrity drift vs a saved baseline.
//!
//! wasm32-wasip2. Lease `args` JSON at argv[0]. Takes a fresh sha256 snapshot
//! of a granted root (same walk/hash logic as `fim-snapshot`, duplicated on
//! purpose — every tool is a standalone crate) and compares it to a baseline
//! by path: added / removed / modified / unchanged. Bounded (max_files,
//! max_file_bytes, max_depth); unreadable/oversized files are skipped.
//! Fail-loud on arg errors and on a missing/invalid baseline.
//!
//! Args:
//!   { "root": "/work",                          (optional, default "/work")
//!     "baseline": [ {"path","sha256",...}, ... ]   (REQUIRED: the `files` array
//!                                                 from a fim-snapshot output)
//!               | { "path": "/work/baseline.json" } (or read a saved snapshot /
//!                                                 files array from a file)
//!     "name_glob": "*.conf",                    (optional, matches basename)
//!     "max_files": <int, default 5000>,
//!     "max_file_bytes": <int, default 10485760>,
//!     "max_depth": <int, default 20> }
//!
//! Output:
//!   { "tool":"fim-diff", "root", "drift": bool, "truncated": bool,
//!     "summary": { "added", "removed", "modified", "unchanged" },
//!     "added":    [ { "path", "sha256" } ],
//!     "removed":  [ { "path", "sha256" } ],
//!     "modified": [ { "path", "old_sha256", "new_sha256" } ] }

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

fn err(reason: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "fim-diff", "error": reason.into() })
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

/// Fresh snapshot: path -> sha256 (BTreeMap keeps it sorted/deterministic).
fn walk(dir: &Path, depth: usize, ctx: &Ctx, out: &mut BTreeMap<String, String>) {
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
            if let Some(d) = sha256_file(&path) {
                out.insert(path.to_string_lossy().to_string(), d);
            }
        }
    }
}

/// Resolve the `baseline` arg into path -> sha256. Accepts:
///   - an array of {path, sha256} (the `files` array of a fim-snapshot)
///   - a full fim-snapshot object ({"files": [...]})
///   - {"path": "<file>"} whose contents are either of the above (JSON)
fn load_baseline(v: &serde_json::Value) -> Result<BTreeMap<String, String>, serde_json::Value> {
    // 1) {"path": ...} → read + parse the file, then recurse on the parsed doc
    if let Some(p) = v.as_object().and_then(|o| o.get("path")).and_then(|p| p.as_str()) {
        let meta = fs::metadata(p).map_err(|e| err(format!("baseline stat({p}) failed: {e}")))?;
        if !meta.is_file() {
            return Err(err(format!("baseline {p} is not a regular file")));
        }
        if meta.len() > 64 * 1_048_576 {
            return Err(err(format!("baseline {p} exceeds 64MiB")));
        }
        let bytes = fs::read(p).map_err(|e| err(format!("baseline read({p}) failed: {e}")))?;
        let doc: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| err(format!("baseline {p} is not valid JSON: {e}")))?;
        if doc.get("path").is_some() && !doc.is_array() {
            // don't chase {"path":...} indirection more than one level
            return Err(err(format!("baseline {p} must contain a files array or a snapshot object")));
        }
        return load_baseline(&doc);
    }
    // 2) a full snapshot object → use its `files`
    let arr = if let Some(files) = v.as_object().and_then(|o| o.get("files")) {
        files.as_array()
    } else {
        v.as_array()
    };
    let arr = arr.ok_or_else(|| {
        err("baseline must be an array of {path, sha256}, a fim-snapshot object, or {\"path\": <file>}")
    })?;
    let mut map = BTreeMap::new();
    for (i, item) in arr.iter().enumerate() {
        let path = item.get("path").and_then(|p| p.as_str());
        let sha = item.get("sha256").and_then(|s| s.as_str());
        match (path, sha) {
            (Some(p), Some(s)) => {
                map.insert(p.to_string(), s.to_string());
            }
            _ => {
                return Err(err(format!(
                    "baseline entry {i} is missing 'path' or 'sha256'"
                )))
            }
        }
    }
    Ok(map)
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

    let baseline_v = a
        .get("baseline")
        .ok_or_else(|| err("missing required arg 'baseline' (fim-snapshot files array, or {\"path\": <file>})"))?;
    let baseline = load_baseline(baseline_v)?;

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

    let mut current: BTreeMap<String, String> = BTreeMap::new();
    walk(root_path, 0, &ctx, &mut current);
    let truncated = current.len() >= max_files;

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();
    let mut unchanged = 0usize;

    for (path, sha) in &current {
        match baseline.get(path) {
            None => added.push(serde_json::json!({ "path": path, "sha256": sha })),
            Some(old) if old != sha => modified.push(serde_json::json!({
                "path": path, "old_sha256": old, "new_sha256": sha
            })),
            Some(_) => unchanged += 1,
        }
    }
    for (path, sha) in &baseline {
        if !current.contains_key(path) {
            removed.push(serde_json::json!({ "path": path, "sha256": sha }));
        }
    }

    let drift = !added.is_empty() || !removed.is_empty() || !modified.is_empty();

    Ok(serde_json::json!({
        "tool": "fim-diff",
        "root": root,
        "drift": drift,
        "truncated": truncated,
        "summary": {
            "added": added.len(),
            "removed": removed.len(),
            "modified": modified.len(),
            "unchanged": unchanged,
        },
        "added": added,
        "removed": removed,
        "modified": modified,
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
