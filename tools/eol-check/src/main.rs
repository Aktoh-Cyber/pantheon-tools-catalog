//! Synapse v2 tool — `eol-check` (Tier 1, pure compute). Flag operating systems
//! and packages that have reached (or are near) end-of-life against a caller-
//! supplied EOL table. No host access at the WASM level: the caller pipes in the
//! OS/inventory facts (from os-fingerprint / package-inventory) and the EOL table
//! (from pulse's corpus or a vendored endoflife.date snapshot). Running EOL
//! software is a finding judge and shield both care about — nothing is patching
//! it any more.
//!
//! Comparison is by product + major/minor version cycle. An entry whose
//! `eol_date` is a plain ISO date in the past is EOL; a `days_until` is reported
//! when a `today` is supplied so "approaching EOL" can be surfaced too.
//!
//! Args: { "products": [{ "product":"debian", "version":"10" }, ...] (REQUIRED),
//!         "eol_table": [{ "product":"debian", "cycle":"10", "eol_date":"2024-06-30" }, ...] (REQUIRED),
//!         "today": "2026-09-17" (optional; enables days_until + approaching) }
//! Output: { tool, checked, eol_count, findings:[{ product, version, eol_date, status, days_until? }] }
//! ExitCode: 0 for an evaluated request; 1 for arg errors.
use std::process::ExitCode;

fn err(r: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "eol-check", "error": r.into() })
}

/// Days from `a` to `b` for ISO `YYYY-MM-DD` dates, via a proleptic-Gregorian
/// day count. Returns None if either date is malformed (the finding then omits
/// days_until rather than guessing).
fn iso_to_days(s: &str) -> Option<i64> {
    let mut it = s.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // Howard Hinnant's days-from-civil algorithm.
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe - 719468)
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;

    let products = a.get("products").and_then(|v| v.as_array())
        .ok_or_else(|| err("missing required arg 'products' (array of {product,version})"))?;
    let table = a.get("eol_table").and_then(|v| v.as_array())
        .ok_or_else(|| err("missing required arg 'eol_table' (array of {product,cycle,eol_date})"))?;
    let today = a.get("today").and_then(|v| v.as_str()).and_then(iso_to_days);

    let mut findings: Vec<serde_json::Value> = Vec::new();

    for p in products {
        let product = p.get("product").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
        let version = p.get("version").and_then(|v| v.as_str()).unwrap_or("");
        if product.is_empty() {
            continue;
        }
        // match on product + cycle where the installed version starts with the cycle
        let hit = table.iter().find(|e| {
            e.get("product").and_then(|v| v.as_str()).map(|s| s.eq_ignore_ascii_case(&product)) == Some(true)
                && e.get("cycle").and_then(|v| v.as_str())
                    .map(|c| version == c || version.starts_with(&format!("{c}.")))
                    == Some(true)
        });
        if let Some(e) = hit {
            let eol_date = e.get("eol_date").and_then(|v| v.as_str()).unwrap_or("");
            let eol_days = iso_to_days(eol_date);
            let (status, days_until) = match (today, eol_days) {
                (Some(t), Some(eol)) => {
                    let delta = eol - t;
                    let status = if delta < 0 { "eol" } else if delta <= 180 { "approaching" } else { "supported" };
                    (status, Some(delta))
                }
                _ => ("unknown-date", None),
            };
            if status == "eol" || status == "approaching" {
                let mut f = serde_json::json!({
                    "product": product, "version": version, "eol_date": eol_date, "status": status
                });
                if let Some(d) = days_until {
                    f["days_until"] = serde_json::json!(d);
                }
                findings.push(f);
            }
        }
    }

    Ok(serde_json::json!({
        "tool": "eol-check",
        "checked": products.len(),
        "eol_count": findings.iter().filter(|f| f["status"] == "eol").count(),
        "findings": findings,
    }))
}

fn main() -> ExitCode {
    match run() {
        Ok(v) => { println!("{v}"); ExitCode::SUCCESS }
        Err(v) => { println!("{v}"); ExitCode::from(1) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_day_math_is_consistent() {
        let a = iso_to_days("2024-06-30").unwrap();
        let b = iso_to_days("2024-07-01").unwrap();
        assert_eq!(b - a, 1);
        assert_eq!(iso_to_days("2026-09-17").unwrap() - iso_to_days("2026-09-16").unwrap(), 1);
    }

    #[test]
    fn iso_rejects_malformed() {
        assert!(iso_to_days("not-a-date").is_none());
        assert!(iso_to_days("2024-13-01").is_none());
    }

    #[test]
    fn past_eol_is_negative_delta() {
        let today = iso_to_days("2026-09-17").unwrap();
        let eol = iso_to_days("2024-06-30").unwrap();
        assert!(eol - today < 0);
    }
}
