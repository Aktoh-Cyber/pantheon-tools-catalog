//! Synapse v2 tool — `secret-scan`: find leaked credentials in a tree.
//!
//! wasm32-wasip2. Lease `args` JSON at argv[0]. Recursively walks a granted
//! root, reads UTF-8 text files line-by-line and applies (a) a fixed set of
//! built-in regex rules (AWS / GitHub / Slack tokens, private-key headers,
//! generic `key = "..."` assignments, JWTs) and (b) a Shannon-entropy
//! heuristic over long [A-Za-z0-9+/=_-] runs (> 4.5 bits/byte). Every
//! reported excerpt has the secret span MASKED (first 4 chars + "…"); the
//! full secret is never printed. Bounded (max_matches, max_file_bytes,
//! max_depth); binary/oversized/unreadable files skipped. Fail-loud on arg
//! errors only (the rule set is built-in, so no user regex can be bad).
//!
//! Args:
//!   { "root": "/work",                (optional, default "/work")
//!     "name_glob": "*.env",           (optional, matches basename)
//!     "max_matches": <int, default 200>,
//!     "max_file_bytes": <int, default 1048576>,
//!     "max_depth": <int, default 20>,
//!     "allowlist": ["EXAMPLE", ...] } (optional; a line containing any of
//!                                      these substrings is never reported)
//!
//! Output:
//!   { "tool":"secret-scan", "root", "count", "truncated": bool,
//!     "rules_checked": N,
//!     "matches": [ { "path", "line", "rule", "excerpt" } ] }

use regex_lite::Regex;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

fn err(reason: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "secret-scan", "error": reason.into() })
}

/// Minimal glob: `*` = any run (incl. empty), `?` = one char.
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

/// Built-in rule set: (id, pattern, secret capture group). Group 0 = whole
/// match. The secret group is what gets masked in the excerpt.
const RULES: &[(&str, &str, usize)] = &[
    ("aws-access-key", r"AKIA[0-9A-Z]{16}", 0),
    (
        "aws-secret-key",
        r#"(?i)aws(.{0,20})?(secret|private)?.{0,20}?['"]([0-9a-zA-Z/+]{40})['"]"#,
        3,
    ),
    ("github-token", r"gh[pousr]_[A-Za-z0-9]{36,}", 0),
    ("slack-token", r"xox[baprs]-[0-9A-Za-z-]{10,}", 0),
    (
        "private-key-block",
        r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        0,
    ),
    (
        "generic-api-key",
        r#"(?i)(api[_-]?key|apikey|secret|token|password|passwd)\s*[:=]\s*['"]?([A-Za-z0-9_/+=-]{16,})"#,
        2,
    ),
    (
        "jwt",
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        0,
    ),
];

const ENTROPY_RULE: &str = "high-entropy-string";
const ENTROPY_MIN_LEN: usize = 20;
const ENTROPY_THRESHOLD: f64 = 4.5;
const EXCERPT_MAX_CHARS: usize = 200;

struct Rule {
    id: &'static str,
    re: Regex,
    group: usize,
}

struct Ctx {
    rules: Vec<Rule>,
    name_glob: Option<String>,
    max_matches: usize,
    max_file_bytes: u64,
    max_depth: usize,
    allowlist: Vec<String>,
}

/// A finding on one line: rule id + byte span of the secret to mask.
struct Hit {
    rule: &'static str,
    span: (usize, usize),
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

/// Shannon entropy in bits/byte over a byte slice.
fn shannon(bytes: &[u8]) -> f64 {
    let mut freq = [0u32; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let mut e = 0.0f64;
    for &c in freq.iter() {
        if c > 0 {
            let p = c as f64 / n;
            e -= p * p.log2();
        }
    }
    e
}

/// Regex rules + entropy heuristic over one line. Returns every hit (rule,
/// secret span). Entropy tokens that overlap a regex hit are dropped (the
/// regex rule is the more specific finding).
fn scan_line(line: &str, ctx: &Ctx) -> Vec<Hit> {
    let mut hits: Vec<Hit> = Vec::new();
    for r in &ctx.rules {
        for caps in r.re.captures_iter(line) {
            // fall back to the whole match if the secret group didn't participate
            let m = caps.get(r.group).or_else(|| caps.get(0));
            if let Some(m) = m {
                let mut span = (m.start(), m.end());
                if r.id == "private-key-block" {
                    // key material may follow the header on the same line
                    // (escaped-newline JSON etc.) — mask to end of line.
                    span.1 = line.len();
                }
                hits.push(Hit { rule: r.id, span });
            }
        }
    }
    // entropy heuristic: maximal runs of [A-Za-z0-9+/=_-], len >= 20
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if !is_token_byte(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_token_byte(bytes[i]) {
            i += 1;
        }
        let end = i;
        if end - start < ENTROPY_MIN_LEN {
            continue;
        }
        let overlaps = hits
            .iter()
            .any(|h| h.span.0 < end && start < h.span.1);
        if overlaps {
            continue;
        }
        if shannon(&bytes[start..end]) > ENTROPY_THRESHOLD {
            hits.push(Hit { rule: ENTROPY_RULE, span: (start, end) });
        }
    }
    hits
}

/// Build the masked excerpt: every secret span → first 4 chars + "…"; then
/// window to EXCERPT_MAX_CHARS around the first masked span.
fn masked_excerpt(line: &str, hits: &[Hit]) -> String {
    let mut spans: Vec<(usize, usize)> = hits.iter().map(|h| h.span).collect();
    spans.sort();
    // merge overlapping / adjacent spans
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (s, e) in spans {
        if let Some(last) = merged.last_mut() {
            if s <= last.1 {
                last.1 = last.1.max(e);
                continue;
            }
        }
        merged.push((s, e));
    }
    let mut out = String::new();
    let mut first_mark: Option<usize> = None;
    let mut cursor = 0usize;
    for (s, e) in merged {
        out.push_str(&line[cursor..s]);
        if first_mark.is_none() {
            first_mark = Some(out.chars().count());
        }
        let secret = &line[s..e];
        let keep: String = secret.chars().take(4).collect();
        out.push_str(&keep);
        out.push('…');
        cursor = e;
    }
    out.push_str(&line[cursor..]);

    let total = out.chars().count();
    if total <= EXCERPT_MAX_CHARS {
        return out;
    }
    let mark = first_mark.unwrap_or(0);
    let mut start = mark.saturating_sub(60);
    if start + EXCERPT_MAX_CHARS > total {
        start = total - EXCERPT_MAX_CHARS;
    }
    let window: String = out.chars().skip(start).take(EXCERPT_MAX_CHARS).collect();
    let mut w = String::new();
    if start > 0 {
        w.push('…');
    }
    w.push_str(&window);
    if start + EXCERPT_MAX_CHARS < total {
        w.push('…');
    }
    w
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
        if ctx.allowlist.iter().any(|s| line.contains(s.as_str())) {
            continue;
        }
        let hits = scan_line(line, ctx);
        if hits.is_empty() {
            continue;
        }
        // one masked excerpt per line (ALL secret spans masked), one record
        // per distinct rule that fired on the line
        let excerpt = masked_excerpt(line, &hits);
        let mut seen: Vec<&str> = Vec::new();
        for h in &hits {
            if seen.contains(&h.rule) {
                continue;
            }
            seen.push(h.rule);
            if out.len() >= ctx.max_matches {
                return;
            }
            out.push(serde_json::json!({
                "path": path.to_string_lossy(),
                "line": i + 1,
                "rule": h.rule,
                "excerpt": excerpt,
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
        Err(_) => return, // unreadable subtree: skip, don't abort the walk
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

/// All logic; returns the success payload or an error payload. `main` prints
/// whichever and maps it to an ExitCode — no `process::exit`.
fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;

    let root = a.get("root").and_then(|v| v.as_str()).unwrap_or("/work").to_string();
    let max_matches = a.get("max_matches").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
    let max_file_bytes = a
        .get("max_file_bytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(1_048_576);
    let max_depth = a.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
    if max_matches == 0 {
        return Err(err("max_matches must be >= 1"));
    }
    let allowlist: Vec<String> = match a.get("allowlist") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(arr)) => {
            let mut v = Vec::new();
            for item in arr {
                match item.as_str() {
                    Some(s) if !s.is_empty() => v.push(s.to_string()),
                    _ => return Err(err("allowlist must be an array of non-empty strings")),
                }
            }
            v
        }
        Some(_) => return Err(err("allowlist must be an array of non-empty strings")),
    };

    // Rules are built-in constants; a compile failure here would be a build
    // bug, but we still fail loud (never panic — a panic traps on the node).
    let mut rules = Vec::with_capacity(RULES.len());
    for (id, pat, group) in RULES {
        let re = Regex::new(pat).map_err(|e| err(format!("built-in rule {id} failed to compile: {e}")))?;
        rules.push(Rule { id, re, group: *group });
    }
    let rules_checked = rules.len() + 1; // + entropy heuristic

    let ctx = Ctx {
        rules,
        name_glob: a.get("name_glob").and_then(|v| v.as_str()).map(String::from),
        max_matches,
        max_file_bytes,
        max_depth,
        allowlist,
    };

    let root_path = Path::new(&root);
    if !root_path.is_dir() {
        return Err(err(format!(
            "root {root} is not a directory (is it mounted into this lease?)"
        )));
    }

    let mut out = Vec::new();
    walk(root_path, 0, &ctx, &mut out);
    let truncated = out.len() >= max_matches;

    Ok(serde_json::json!({
        "tool": "secret-scan",
        "root": root,
        "count": out.len(),
        "truncated": truncated,
        "rules_checked": rules_checked,
        "matches": out,
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
