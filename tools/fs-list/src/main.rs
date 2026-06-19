//! Synapse v2 reference tool — list directory contents on a node.
//!
//! Built as `wasm32-wasip2`. The Synapse executor passes the lease's `args` as
//! the single CLI argument (JSON-encoded). This tool reads it, lists the
//! directory at `args.path`, prints `{ "tool": "fs-list", "path": <path>,
//! "entries": [...] }` to stdout, and exits 0.
//!
//! Args contract:
//!   { "path": "<absolute path>", "max_entries": <int, optional, default 100>,
//!     "include_hidden": <bool, optional, default false> }
//!
//! Per `feedback_fail_loud_not_silent`: missing/bad args produce structured
//! error to stdout (NOT stderr — Synapse captures stdout as the tool result)
//! and exit code 1, so the chat surface can render the failure with the
//! actual reason.

use std::fs;
use std::path::Path;

fn fail(reason: &str) -> ! {
    let err = serde_json::json!({
        "tool": "fs-list",
        "error": reason,
    });
    println!("{err}");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let raw = args.first().cloned().unwrap_or_else(|| "{}".to_string());
    let parsed: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => fail(&format!("args is not valid JSON: {e}")),
    };

    let path_s = match parsed.get("path").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => fail("missing required arg 'path' (string)"),
    };
    let max_entries = parsed
        .get("max_entries")
        .and_then(|v| v.as_u64())
        .unwrap_or(100) as usize;
    let include_hidden = parsed
        .get("include_hidden")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let path = Path::new(path_s);
    let read_dir = match fs::read_dir(path) {
        Ok(r) => r,
        Err(e) => fail(&format!("read_dir({path_s}) failed: {e}")),
    };

    let mut entries: Vec<serde_json::Value> = Vec::new();
    for entry in read_dir.take(max_entries) {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                entries.push(serde_json::json!({
                    "error": format!("entry iter failed: {e}"),
                }));
                continue;
            }
        };
        let name = entry.file_name();
        let name_s = name.to_string_lossy().to_string();
        if !include_hidden && name_s.starts_with('.') {
            continue;
        }
        let metadata = entry.metadata().ok();
        let kind = metadata.as_ref().map(|m| {
            if m.is_dir() { "dir" }
            else if m.is_symlink() { "symlink" }
            else { "file" }
        }).unwrap_or("unknown");
        let size = metadata.as_ref().filter(|m| m.is_file()).map(|m| m.len());
        let entry_obj = if let Some(sz) = size {
            serde_json::json!({"name": name_s, "kind": kind, "size": sz})
        } else {
            serde_json::json!({"name": name_s, "kind": kind})
        };
        entries.push(entry_obj);
    }

    let out = serde_json::json!({
        "tool": "fs-list",
        "path": path_s,
        "count": entries.len(),
        "entries": entries,
    });
    println!("{out}");
}
