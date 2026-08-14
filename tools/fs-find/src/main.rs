//! Synapse v2 tool — `fs-find`: locate files by name-glob / size / mtime.
//!
//! wasm32-wasip2. Lease `args` JSON at argv[0]. Recursively walks a granted
//! root (`/work` or a mount). Dependency-free glob (`*` and `?`). Fail-loud on
//! arg errors; a bounded, deterministic walk (max_depth, max_results).
//!
//! Args:
//!   { "root": "/work",                (optional, default "/work")
//!     "name_glob": "*.log",           (optional, matches basename)
//!     "min_size": <int>, "max_size": <int>,        (optional, bytes)
//!     "modified_after_unix": <int>, "modified_before_unix": <int>,  (optional)
//!     "kind": "file" | "dir" | "any", (optional, default "any")
//!     "max_depth": <int, default 20>, "max_results": <int, default 1000> }
//!
//! Output:
//!   { "tool":"fs-find", "root", "count", "truncated": bool,
//!     "results": [ { "path", "kind", "size_bytes", "modified_unix" } ] }

use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::time::UNIX_EPOCH;

fn err(reason: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "fs-find", "error": reason.into() })
}

/// Minimal glob: `*` = any run (incl. empty), `?` = one char. No character
/// classes — that's all a filename filter needs and it stays dependency-free.
fn glob_match(pat: &str, s: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pat.chars().collect(), s.chars().collect());
    // classic two-pointer wildcard match with backtracking on `*`
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

#[derive(Clone)]
struct Filter {
    name_glob: Option<String>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    after: Option<u64>,
    before: Option<u64>,
    kind: String,
}

fn mtime_unix(meta: &fs::Metadata) -> Option<u64> {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
}

#[allow(clippy::too_many_arguments)]
fn walk(
    dir: &Path,
    depth: usize,
    max_depth: usize,
    f: &Filter,
    out: &mut Vec<serde_json::Value>,
    max_results: usize,
) {
    if out.len() >= max_results || depth > max_depth {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return, // unreadable subtree: skip, don't abort the walk
    };
    for entry in entries.flatten() {
        if out.len() >= max_results {
            return;
        }
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let is_dir = meta.is_dir();
        let kind = if is_dir {
            "dir"
        } else if meta.is_file() {
            "file"
        } else {
            "other"
        };
        let name = entry.file_name().to_string_lossy().to_string();
        let size = if meta.is_file() { meta.len() } else { 0 };
        let mtime = mtime_unix(&meta);

        let mut ok = true;
        if let Some(g) = &f.name_glob {
            ok &= glob_match(g, &name);
        }
        if f.kind != "any" {
            ok &= f.kind == kind;
        }
        if let Some(mn) = f.min_size {
            ok &= meta.is_file() && size >= mn;
        }
        if let Some(mx) = f.max_size {
            ok &= meta.is_file() && size <= mx;
        }
        if let Some(af) = f.after {
            ok &= mtime.map(|m| m > af).unwrap_or(false);
        }
        if let Some(bf) = f.before {
            ok &= mtime.map(|m| m < bf).unwrap_or(false);
        }
        if ok {
            out.push(serde_json::json!({
                "path": path.to_string_lossy(),
                "kind": kind,
                "size_bytes": size,
                "modified_unix": mtime,
            }));
        }
        if is_dir {
            walk(&path, depth + 1, max_depth, f, out, max_results);
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
    let kind = a.get("kind").and_then(|v| v.as_str()).unwrap_or("any").to_string();
    if !matches!(kind.as_str(), "any" | "file" | "dir") {
        return Err(err("kind must be 'any', 'file', or 'dir'"));
    }
    let max_depth = a.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
    let max_results = a.get("max_results").and_then(|v| v.as_u64()).unwrap_or(1000) as usize;

    let filter = Filter {
        name_glob: a.get("name_glob").and_then(|v| v.as_str()).map(String::from),
        min_size: a.get("min_size").and_then(|v| v.as_u64()),
        max_size: a.get("max_size").and_then(|v| v.as_u64()),
        after: a.get("modified_after_unix").and_then(|v| v.as_u64()),
        before: a.get("modified_before_unix").and_then(|v| v.as_u64()),
        kind,
    };

    let root_path = Path::new(&root);
    if !root_path.exists() {
        return Err(err(format!("root {root} does not exist (is it mounted into this lease?)")));
    }

    let mut out = Vec::new();
    walk(root_path, 0, max_depth, &filter, &mut out, max_results + 1);
    let truncated = out.len() > max_results;
    if truncated {
        out.truncate(max_results);
    }

    Ok(serde_json::json!({
        "tool": "fs-find",
        "root": root,
        "count": out.len(),
        "truncated": truncated,
        "results": out,
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
