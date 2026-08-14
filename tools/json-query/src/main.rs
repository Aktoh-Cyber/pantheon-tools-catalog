//! Synapse v2 tool — `json-query`: parse + navigate/reshape JSON (jq-lite).
//!
//! wasm32-wasip2. Lease `args` JSON at argv[0]. Pure compute — no fs, no net.
//! Accepts JSON inline or reads it from a granted path, then extracts a value
//! by a dotted path (with array indices) and/or reports keys/length. Fail-loud
//! on bad JSON or an unresolvable path.
//!
//! Args (provide exactly one source):
//!   { "input": <any JSON value or a JSON string>,   OR
//!     "path_file": "<abs path to a .json file>" }
//!   optional:
//!     "query": "a.b.0.c"   (dotted path; numeric segment = array index)
//!     "keys": bool         (list object keys / array length at the resolved node)
//!
//! Output:
//!   { "tool":"json-query", "matched": bool, "result": <value>,
//!     "keys"?: [..], "length"?: <int> }

fn fail(reason: &str) -> ! {
    println!("{}", serde_json::json!({ "tool": "json-query", "error": reason }));
    std::process::exit(1);
}

/// Navigate `root` by dotted `query`. A numeric segment indexes into an array;
/// any other segment keys into an object. Returns None if a segment doesn't
/// resolve, so the caller gets `matched:false` rather than a fabricated value.
fn navigate<'a>(root: &'a serde_json::Value, query: &str) -> Option<&'a serde_json::Value> {
    let mut cur = root;
    if query.is_empty() {
        return Some(cur);
    }
    for seg in query.split('.') {
        if seg.is_empty() {
            continue;
        }
        cur = match cur {
            serde_json::Value::Array(a) => {
                let idx: usize = seg.parse().ok()?;
                a.get(idx)?
            }
            serde_json::Value::Object(o) => o.get(seg)?,
            _ => return None,
        };
    }
    Some(cur)
}

fn main() {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| fail(&format!("args is not valid JSON: {e}")));

    // Resolve the JSON source: inline `input` (value or embedded string) or a file.
    let root: serde_json::Value = if let Some(v) = a.get("input") {
        match v {
            // if input is a string, try to parse it as JSON; else treat the string as the value
            serde_json::Value::String(s) => {
                serde_json::from_str(s).unwrap_or_else(|_| serde_json::Value::String(s.clone()))
            }
            other => other.clone(),
        }
    } else if let Some(p) = a.get("path_file").and_then(|v| v.as_str()) {
        let bytes = std::fs::read(p).unwrap_or_else(|e| fail(&format!("read({p}) failed: {e}")));
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| fail(&format!("{p} is not valid JSON: {e}")))
    } else {
        fail("provide 'input' (JSON value/string) or 'path_file' (path to a .json)");
    };

    let query = a.get("query").and_then(|v| v.as_str()).unwrap_or("");
    let want_keys = a.get("keys").and_then(|v| v.as_bool()).unwrap_or(false);

    let node = navigate(&root, query);
    let matched = node.is_some();
    let mut out = serde_json::Map::new();
    out.insert("tool".into(), "json-query".into());
    out.insert("matched".into(), matched.into());
    out.insert("query".into(), query.into());

    match node {
        Some(v) => {
            out.insert("result".into(), v.clone());
            if want_keys {
                match v {
                    serde_json::Value::Object(o) => {
                        out.insert(
                            "keys".into(),
                            serde_json::Value::Array(
                                o.keys().map(|k| serde_json::Value::String(k.clone())).collect(),
                            ),
                        );
                        out.insert("length".into(), o.len().into());
                    }
                    serde_json::Value::Array(arr) => {
                        out.insert("length".into(), arr.len().into());
                    }
                    _ => {}
                }
            }
        }
        None => {
            out.insert("result".into(), serde_json::Value::Null);
        }
    }

    println!("{}", serde_json::Value::Object(out));
}
