//! Synapse v2 tool — `text-entropy`: Shannon entropy + text statistics.
//!
//! wasm32-wasip2. Lease `args` JSON at argv[0]. Reads inline text or a granted
//! file and reports byte-level Shannon entropy plus basic stats. High entropy
//! (~>4.5 bits/byte for text, ->8 for binary) flags likely-compressed,
//! -encrypted, or secret material — a cheap first-pass signal for secret-scan
//! and malware triage. Fail-loud on arg/read errors.
//!
//! Args (provide exactly one source):
//!   { "text": "<string>" }  OR  { "path": "<abs path>" }
//!   optional: "max_bytes": <int, default 1048576>  (cap the analyzed prefix)
//!
//! Output:
//!   { "tool":"text-entropy", "bytes", "shannon_entropy", "normalized_entropy",
//!     "printable_ratio", "distinct_bytes", "lines", "words", "high_entropy" }

use std::io::Read;

fn fail(reason: &str) -> ! {
    println!("{}", serde_json::json!({ "tool": "text-entropy", "error": reason }));
    std::process::exit(1);
}

fn main() {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| fail(&format!("args is not valid JSON: {e}")));

    let max_bytes = a.get("max_bytes").and_then(|v| v.as_u64()).unwrap_or(1_048_576) as usize;

    let bytes: Vec<u8> = if let Some(t) = a.get("text").and_then(|v| v.as_str()) {
        let mut b = t.as_bytes().to_vec();
        b.truncate(max_bytes);
        b
    } else if let Some(p) = a.get("path").and_then(|v| v.as_str()) {
        let meta = std::fs::metadata(p).unwrap_or_else(|e| fail(&format!("stat({p}) failed: {e}")));
        if !meta.is_file() {
            fail(&format!("{p} is not a regular file"));
        }
        let f = std::fs::File::open(p).unwrap_or_else(|e| fail(&format!("open({p}) failed: {e}")));
        let mut b = Vec::new();
        f.take(max_bytes as u64)
            .read_to_end(&mut b)
            .unwrap_or_else(|e| fail(&format!("read({p}) failed: {e}")));
        b
    } else {
        fail("provide 'text' (string) or 'path' (string)");
    };

    let n = bytes.len();
    if n == 0 {
        println!(
            "{}",
            serde_json::json!({
                "tool": "text-entropy", "bytes": 0, "shannon_entropy": 0.0,
                "normalized_entropy": 0.0, "printable_ratio": 0.0,
                "distinct_bytes": 0, "lines": 0, "words": 0, "high_entropy": false,
            })
        );
        return;
    }

    // byte-frequency histogram → Shannon entropy in bits/byte
    let mut freq = [0u64; 256];
    let mut printable = 0u64;
    let mut lines = 0u64;
    for &b in &bytes {
        freq[b as usize] += 1;
        // printable = space..~ plus tab/newline/carriage-return
        if (0x20..=0x7e).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r' {
            printable += 1;
        }
        if b == b'\n' {
            lines += 1;
        }
    }
    let nf = n as f64;
    let mut entropy = 0.0f64;
    let mut distinct = 0u32;
    for &c in freq.iter() {
        if c > 0 {
            distinct += 1;
            let p = c as f64 / nf;
            entropy -= p * p.log2();
        }
    }
    // words: whitespace-delimited runs (best-effort over the UTF-8 lossy view)
    let words = String::from_utf8_lossy(&bytes).split_whitespace().count();
    // a file with no trailing newline still has a final line of content
    if n > 0 && bytes[n - 1] != b'\n' {
        lines += 1;
    }

    let printable_ratio = printable as f64 / nf;
    let normalized = entropy / 8.0; // 0..1 (8 bits = max for a byte)
    // Secret/compressed/encrypted signal. We flag on entropy ALONE (>4.8
    // bits/byte) — the threshold detect-secrets/truffleHog use — because the
    // highest-value hits (base64/hex API keys, tokens) are fully *printable*
    // yet high-entropy; gating on non-printability would miss exactly those.
    // English prose sits ~4.0–4.5 and stays below the line.
    let high_entropy = entropy > 4.8;

    println!(
        "{}",
        serde_json::json!({
            "tool": "text-entropy",
            "bytes": n,
            "shannon_entropy": (entropy * 10000.0).round() / 10000.0,
            "normalized_entropy": (normalized * 10000.0).round() / 10000.0,
            "printable_ratio": (printable_ratio * 10000.0).round() / 10000.0,
            "distinct_bytes": distinct,
            "lines": lines,
            "words": words,
            "high_entropy": high_entropy,
        })
    );
}
