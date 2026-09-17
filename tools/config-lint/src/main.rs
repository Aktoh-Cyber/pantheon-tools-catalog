//! Synapse v2 tool — `config-lint` (Tier 0, pure compute). Parse a security-
//! sensitive config file (sshd_config today; extensible) and flag settings that
//! violate a hardening baseline. No filesystem or host access at the WASM level:
//! the caller passes the file `content` as a string (populated by an fs:read tool
//! or the vault), and this tool applies the ruleset. Findings carry the directive,
//! the observed value, the expected value, and a severity — never a bare rule ID.
//!
//! Args: { "kind": "sshd" (REQUIRED), "content": "<file text>" (REQUIRED) }
//! Output: { tool, kind, evaluated, finding_count, findings:[{ directive, observed, expected, severity, note }] }
//! ExitCode: 0 for an evaluated file (zero findings is a pass); 1 for arg errors.
use std::collections::HashMap;
use std::process::ExitCode;

fn err(r: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": "config-lint", "error": r.into() })
}

/// Parse `key value` lines, last-wins (sshd honours the FIRST occurrence, but for
/// a lint we report on the effective set; we keep the first per sshd semantics).
fn parse_directives(content: &str) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            // sshd_config: first occurrence wins.
            map.entry(k.to_ascii_lowercase()).or_insert_with(|| v.trim().to_string());
        }
    }
    map
}

/// One rule: (directive, expected, severity, note, default_if_absent_is_bad).
/// A finding fires when the observed value != expected, OR the directive is
/// absent AND its compiled-in default is itself non-compliant.
struct Rule {
    directive: &'static str,
    expected: &'static str,
    severity: &'static str,
    note: &'static str,
    absent_is_finding: bool,
}

const SSHD_RULES: &[Rule] = &[
    Rule { directive: "permitrootlogin", expected: "no", severity: "high",
        note: "root should not log in over SSH directly", absent_is_finding: true },
    Rule { directive: "passwordauthentication", expected: "no", severity: "high",
        note: "prefer key-based auth; disable password auth", absent_is_finding: true },
    Rule { directive: "permitemptypasswords", expected: "no", severity: "critical",
        note: "empty passwords must never be accepted", absent_is_finding: false },
    Rule { directive: "x11forwarding", expected: "no", severity: "medium",
        note: "disable X11 forwarding unless required", absent_is_finding: false },
    Rule { directive: "maxauthtries", expected: "4", severity: "low",
        note: "cap auth attempts (<=4 recommended)", absent_is_finding: false },
    Rule { directive: "clientaliveinterval", expected: "300", severity: "low",
        note: "set an idle client timeout", absent_is_finding: false },
];

fn lint_sshd(dirs: &HashMap<String, String>) -> Vec<serde_json::Value> {
    let mut findings = Vec::new();
    for r in SSHD_RULES {
        match dirs.get(r.directive) {
            Some(v) if v.eq_ignore_ascii_case(r.expected) => {} // compliant
            Some(v) => findings.push(serde_json::json!({
                "directive": r.directive, "observed": v, "expected": r.expected,
                "severity": r.severity, "note": r.note
            })),
            None if r.absent_is_finding => findings.push(serde_json::json!({
                "directive": r.directive, "observed": "<absent — insecure default>",
                "expected": r.expected, "severity": r.severity, "note": r.note
            })),
            None => {}
        }
    }
    findings
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;

    let kind = a.get("kind").and_then(|v| v.as_str()).ok_or_else(|| err("missing required arg 'kind'"))?;
    let content = a.get("content").and_then(|v| v.as_str())
        .ok_or_else(|| err("missing required arg 'content' (the config file text)"))?;

    let dirs = parse_directives(content);
    let findings = match kind {
        "sshd" | "sshd_config" => lint_sshd(&dirs),
        other => return Err(err(format!("unsupported kind '{other}' (supported: sshd)"))),
    };

    Ok(serde_json::json!({
        "tool": "config-lint",
        "kind": kind,
        "evaluated": dirs.len(),
        "finding_count": findings.len(),
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
    fn parse_ignores_comments_and_first_wins() {
        let d = parse_directives("# comment\nPermitRootLogin yes\nPermitRootLogin no\n");
        assert_eq!(d.get("permitrootlogin").unwrap(), "yes"); // first-wins per sshd
    }

    #[test]
    fn compliant_sshd_has_no_findings() {
        let d = parse_directives("PermitRootLogin no\nPasswordAuthentication no\n");
        // permitrootlogin + passwordauthentication satisfied; others absent-but-not-required
        let f = lint_sshd(&d);
        assert!(f.iter().all(|x| x["directive"] != "permitrootlogin"));
        assert!(f.iter().all(|x| x["directive"] != "passwordauthentication"));
    }

    #[test]
    fn absent_root_login_is_a_finding() {
        let d = parse_directives("X11Forwarding no\n");
        let f = lint_sshd(&d);
        assert!(f.iter().any(|x| x["directive"] == "permitrootlogin"
            && x["severity"] == "high"));
    }

    #[test]
    fn empty_passwords_yes_is_critical() {
        let d = parse_directives("PermitEmptyPasswords yes\n");
        let f = lint_sshd(&d);
        assert!(f.iter().any(|x| x["directive"] == "permitemptypasswords"
            && x["severity"] == "critical"));
    }
}
