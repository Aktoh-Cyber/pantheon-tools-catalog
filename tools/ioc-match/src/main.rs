//! Synapse v2 tool — `ioc-match` (Tier 0, pure compute). The glue that closes the
//! intel → hunt loop: take a set of observed indicators (hashes, domains, IPs)
//! and match them against an indicator list (pulse's corpus, a relic extraction,
//! a threat-intel feed). No network, no host APIs, no filesystem — it correlates
//! two JSON sets and reports the overlap.
//!
//! Matching is case-insensitive; domains match on exact label OR parent-domain
//! suffix (so `login.evil.test` matches an IOC of `evil.test`); hashes and IPs
//! match exactly. Defanged IOCs (`evil[.]test`, `1[.]2[.]3[.]4`) are normalised
//! before comparison so a feed's defanged entries still hit.
//!
//! Args: { "observations": { "hashes":[], "domains":[], "ips":[] },
//!         "iocs":         { "hashes":[], "domains":[], "ips":[] } }
//! Output: { tool, checked, match_count, matches:[{ type, observed, ioc }] }
//! ExitCode: 0 for an evaluated request (zero matches is a valid answer); 1 for arg errors.
use std::collections::HashSet;
use std::process::ExitCode;

fn err(r: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "ioc-match", "error": r.into() })
}

/// Undo common defanging and normalise case for comparison.
fn norm(s: &str) -> String {
    s.trim()
        .to_ascii_lowercase()
        .replace("[.]", ".")
        .replace("[:]", ":")
        .replace("hxxp", "http")
}

fn str_list(v: Option<&serde_json::Value>, key: &str) -> Vec<String> {
    v.and_then(|o| o.get(key))
        .and_then(|x| x.as_array())
        .map(|arr| arr.iter().filter_map(|e| e.as_str().map(norm)).collect())
        .unwrap_or_default()
}

/// A domain observation matches an IOC domain if equal, or if the observation is
/// a subdomain of the IOC (suffix on a label boundary).
fn domain_hits(observed: &str, ioc: &str) -> bool {
    observed == ioc || observed.ends_with(&format!(".{ioc}"))
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;

    let obs = a.get("observations");
    let iocs = a.get("iocs");
    if obs.is_none() || iocs.is_none() {
        return Err(err("both 'observations' and 'iocs' objects are required"));
    }

    let o_hashes = str_list(obs, "hashes");
    let o_domains = str_list(obs, "domains");
    let o_ips = str_list(obs, "ips");
    let i_hashes: HashSet<String> = str_list(iocs, "hashes").into_iter().collect();
    let i_domains: Vec<String> = str_list(iocs, "domains");
    let i_ips: HashSet<String> = str_list(iocs, "ips").into_iter().collect();

    let checked = o_hashes.len() + o_domains.len() + o_ips.len();
    let mut matches: Vec<serde_json::Value> = Vec::new();

    for h in &o_hashes {
        if i_hashes.contains(h) {
            matches.push(serde_json::json!({ "type": "hash", "observed": h, "ioc": h }));
        }
    }
    for d in &o_domains {
        if let Some(hit) = i_domains.iter().find(|ioc| domain_hits(d, ioc)) {
            matches.push(serde_json::json!({ "type": "domain", "observed": d, "ioc": hit }));
        }
    }
    for ip in &o_ips {
        if i_ips.contains(ip) {
            matches.push(serde_json::json!({ "type": "ip", "observed": ip, "ioc": ip }));
        }
    }

    Ok(serde_json::json!({
        "tool": "ioc-match",
        "checked": checked,
        "match_count": matches.len(),
        "matches": matches,
    }))
}

fn main() -> ExitCode {
    match run() {
        Ok(v) => {
            println!("{v}");
            ExitCode::SUCCESS
        }
        Err(v) => {
            println!("{v}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn norm_undefangs_and_lowercases() {
        assert_eq!(norm("Evil[.]Test"), "evil.test");
        assert_eq!(norm("HXXP://bad"), "http://bad");
    }

    #[test]
    fn subdomain_matches_parent_ioc() {
        assert!(domain_hits("login.evil.test", "evil.test"));
        assert!(domain_hits("evil.test", "evil.test"));
    }

    #[test]
    fn unrelated_domain_does_not_match() {
        assert!(!domain_hits("notevil.test", "evil.test"));
        assert!(!domain_hits("evil.test.good.test", "evil.test")); // suffix, not subdomain-of
    }
}
