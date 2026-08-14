//! Synapse v2 tool — `fs-grep`: regex content search across files.
//!
//! wasm32-wasip2. Lease `args` JSON at argv[0]. Walks a granted root, reads
//! text files (binary/oversized files skipped), and reports line matches. The
//! workhorse for incident response + threat hunting inside a mounted tree.
//! Fail-loud on a bad regex or arg; bounded (max_matches, max_file_bytes).
//!
//! Args:
//!   { "root": "/work",                 (optional, default "/work")
//!     "pattern": "<regex>",            (REQUIRED)
//!     "name_glob": "*.log",            (optional basename filter)
//!     "ignore_case": bool,             (optional, default false)
//!     "max_matches": <int, default 500>,
//!     "max_file_bytes": <int, default 1048576>,
//!     "max_depth": <int, default 20> }
//!
//! Output:
//!   { "tool":"fs-grep", "pattern", "count", "truncated": bool,
//!     "matches": [ { "path", "line", "text" } ] }

use regex_lite::RegexBuilder;
use std::fs;
use std::path::Path;

fn fail(reason: &str) -> ! {
    println!("{}", serde_json::json!({ "tool": "fs-grep", "error": reason }));
    std::process::exit(1);
}

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

struct Ctx {
    re: regex_lite::Regex,
    name_glob: Option<String>,
    max_matches: usize,
    max_file_bytes: u64,
    max_depth: usize,
}

fn scan_file(path: &Path, ctx: &Ctx, out: &mut Vec<serde_json::Value>) {
    if out.len() >= ctx.max_matches {
        return;
    }
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };
    if meta.len() > ctx.max_file_bytes {
        return; // skip oversized files rather than blow the memory budget
    }
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(_) => return,
    };
    // treat as text only if valid UTF-8 (skip binaries cleanly)
    let text = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(_) => return,
    };
    for (i, line) in text.lines().enumerate() {
        if out.len() >= ctx.max_matches {
            return;
        }
        if ctx.re.is_match(line) {
            // cap line length so a minified/one-line file can't produce a huge record
            let shown: String = line.chars().take(2000).collect();
            out.push(serde_json::json!({
                "path": path.to_string_lossy(),
                "line": i + 1,
                "text": shown,
            }));
        }
    }
}

fn walk(dir: &Path, depth: usize, ctx: &Ctx, out: &mut Vec<serde_json::Value>) {
    if out.len() >= ctx.max_matches || depth > ctx.max_depth {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        if out.len() >= ctx.max_matches {
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
            scan_file(&path, ctx, out);
        }
    }
}

fn main() {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| fail(&format!("args is not valid JSON: {e}")));

    let pattern = match a.get("pattern").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => fail("missing required arg 'pattern' (regex string)"),
    };
    let ignore_case = a.get("ignore_case").and_then(|v| v.as_bool()).unwrap_or(false);
    let re = RegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .build()
        .unwrap_or_else(|e| fail(&format!("invalid regex: {e}")));

    let root = a.get("root").and_then(|v| v.as_str()).unwrap_or("/work").to_string();
    let ctx = Ctx {
        re,
        name_glob: a.get("name_glob").and_then(|v| v.as_str()).map(String::from),
        max_matches: a.get("max_matches").and_then(|v| v.as_u64()).unwrap_or(500) as usize,
        max_file_bytes: a.get("max_file_bytes").and_then(|v| v.as_u64()).unwrap_or(1_048_576),
        max_depth: a.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(20) as usize,
    };

    let root_path = Path::new(&root);
    if !root_path.exists() {
        fail(&format!("root {root} does not exist (is it mounted into this lease?)"));
    }

    let mut out = Vec::new();
    // walk collects up to max_matches+1 so we can flag truncation
    let cap_ctx = Ctx { max_matches: ctx.max_matches + 1, ..ctx };
    walk(root_path, 0, &cap_ctx, &mut out);
    let truncated = out.len() > cap_ctx.max_matches - 1;
    if truncated {
        out.truncate(cap_ctx.max_matches - 1);
    }

    println!(
        "{}",
        serde_json::json!({
            "tool": "fs-grep",
            "pattern": pattern,
            "count": out.len(),
            "truncated": truncated,
            "matches": out,
        })
    );
}
