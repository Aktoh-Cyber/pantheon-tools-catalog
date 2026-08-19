//! Synapse v2 tool — `log-triage`: first-pass security triage over a tree
//! of log files.
//!
//! wasm32-wasip2. Lease `args` JSON at argv[0]. Recursively walks a granted
//! root, reads UTF-8 text files whose basename matches `name_glob`
//! (default `*.log`) line-by-line and applies a fixed set of built-in
//! detectors:
//!
//!   auth-failure        (high)   failed logins / access denied / 401 / 403
//!   privilege           (high)   sudo / su / root login / setuid
//!   ioc-suspicious-cmd  (high)   curl|sh, base64 -d, nc -e, /dev/tcp, ...
//!   secret-in-log       (high)   password|secret|api_key|token = <value>;
//!                                the value is MASKED (first 4 chars + "…")
//!   error-burst         (medium) per-file count of error/fatal/panic/
//!                                exception/traceback lines; reported only
//!                                when a file has >= 10 such lines
//!   ioc-ip              (info)   public IPv4 literals, aggregated into
//!                                distinct-IP occurrence counts (top 20)
//!
//! Bounded (max_files, max_file_bytes, max_depth, max_findings); binary /
//! oversized / unreadable files are skipped, never abort. Optional
//! `window_minutes` restricts the scan of each file to lines whose
//! timestamp is within N minutes of the newest timestamp in that file
//! (ISO-8601 `YYYY-MM-DD[T ]HH:MM:SS` or syslog `Mon DD HH:MM:SS`); files
//! with no parseable timestamps are scanned whole. Fail-loud on arg errors
//! only (detectors are built-in). Pure filesystem + compute: no host APIs,
//! no network.
//!
//! Args:
//!   { "root": "/work",               (optional, default "/work")
//!     "name_glob": "*.log",          (optional, default "*.log", basename)
//!     "max_files": <int, default 500>,
//!     "max_file_bytes": <int, default 10485760>,
//!     "max_depth": <int, default 20>,
//!     "max_findings": <int, default 200>,
//!     "window_minutes": <int, default 0 = whole file> }
//!
//! Output (single JSON line):
//!   { "tool":"log-triage", "root", "files_scanned", "files_skipped",
//!     "lines_scanned", "window_minutes", "truncated": bool,
//!     "summary": { "high", "medium", "info", "by_detector": {...} },
//!     "findings": [ { "detector", "severity", "path", "line", "excerpt" } ],
//!     "error_bursts": [ { "path", "count", "first_lines": [n,n,n] } ],
//!     "public_ips": [ { "ip", "count" } ] }
//!
//! `findings` is sorted high → medium → info and capped at max_findings;
//! `summary` counts are totals (pre-cap). `truncated` is true when
//! max_files or max_findings was hit.

use regex_lite::Regex;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;
use std::process::ExitCode;

const TOOL: &str = "log-triage";
const EXCERPT_MAX_CHARS: usize = 200;
const ERROR_BURST_THRESHOLD: usize = 10;
const ERROR_BURST_FIRST_LINES: usize = 3;
const PUBLIC_IPS_TOP: usize = 20;
/// Upper bound on distinct public IPs tracked per run (memory bound on
/// adversarial logs). Beyond this, new IPs are ignored (existing ones still
/// counted).
const MAX_DISTINCT_IPS: usize = 4096;

fn err(reason: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "tool": TOOL, "error": reason.into() })
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

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    High = 0,
    Medium = 1,
    Info = 2,
}

impl Severity {
    fn as_str(self) -> &'static str {
        match self {
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Info => "info",
        }
    }
}

/// Per-line detectors: (id, pattern, severity, group to mask or 0 = none).
const LINE_DETECTORS: &[(&str, &str, Severity, usize)] = &[
    (
        "auth-failure",
        r"(?i)(authentication failure|failed password|invalid user|login failed|access denied|401 unauthorized|403 forbidden)",
        Severity::High,
        0,
    ),
    (
        "privilege",
        r"(?i)(sudo:|su:|root login|privilege|setuid|became root)",
        Severity::High,
        0,
    ),
    (
        "ioc-suspicious-cmd",
        r"(?i)(curl|wget)\s+[^|]*\|\s*(ba)?sh|base64\s+(-d|--decode)|nc\s+-e|/dev/tcp/|powershell\s+-enc|mshta|certutil\s+-urlcache",
        Severity::High,
        0,
    ),
    (
        "secret-in-log",
        r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*(\S{8,})",
        Severity::High,
        2,
    ),
];
const DET_ERROR_BURST: &str = "error-burst";
const DET_IOC_IP: &str = "ioc-ip";
const ERROR_CLASS_RE: &str = r"(?i)\b(error|fatal|panic|exception|traceback)\b";
const IPV4_RE: &str = r"\b(?:\d{1,3}\.){3}\d{1,3}\b";
const ISO_TS_RE: &str = r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})";
const SYSLOG_TS_RE: &str =
    r"^\s*(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})";

struct LineDetector {
    id: &'static str,
    re: Regex,
    severity: Severity,
    mask_group: usize,
}

struct Ctx {
    detectors: Vec<LineDetector>,
    error_re: Regex,
    ip_re: Regex,
    iso_ts_re: Regex,
    syslog_ts_re: Regex,
    name_glob: String,
    max_files: usize,
    max_file_bytes: u64,
    max_depth: usize,
    max_findings: usize,
    window_secs: i64,
}

struct IpStat {
    count: u64,
    first_path: String,
    first_line: usize,
    first_excerpt: String,
}

/// Accumulated results. Findings are bucketed by severity, each bucket
/// capped at max_findings (only that many can ever be emitted), while the
/// counters track totals.
struct Acc {
    high: Vec<serde_json::Value>,
    medium: Vec<serde_json::Value>,
    info: Vec<serde_json::Value>,
    total_findings: usize,
    by_severity: [usize; 3],
    by_detector: BTreeMap<&'static str, usize>,
    error_bursts: Vec<serde_json::Value>,
    ips: HashMap<String, IpStat>,
    files_scanned: usize,
    files_skipped: usize,
    lines_scanned: u64,
    files_truncated: bool,
}

impl Acc {
    fn new() -> Self {
        let mut by_detector = BTreeMap::new();
        for (id, _, _, _) in LINE_DETECTORS {
            by_detector.insert(*id, 0usize);
        }
        by_detector.insert(DET_ERROR_BURST, 0);
        by_detector.insert(DET_IOC_IP, 0);
        Acc {
            high: Vec::new(),
            medium: Vec::new(),
            info: Vec::new(),
            total_findings: 0,
            by_severity: [0; 3],
            by_detector,
            error_bursts: Vec::new(),
            ips: HashMap::new(),
            files_scanned: 0,
            files_skipped: 0,
            lines_scanned: 0,
            files_truncated: false,
        }
    }

    fn push(
        &mut self,
        ctx: &Ctx,
        detector: &'static str,
        severity: Severity,
        path: &str,
        line: usize,
        excerpt: &str,
    ) {
        self.total_findings += 1;
        self.by_severity[severity as usize] += 1;
        *self.by_detector.entry(detector).or_insert(0) += 1;
        let bucket = match severity {
            Severity::High => &mut self.high,
            Severity::Medium => &mut self.medium,
            Severity::Info => &mut self.info,
        };
        if bucket.len() < ctx.max_findings {
            bucket.push(serde_json::json!({
                "detector": detector,
                "severity": severity.as_str(),
                "path": path,
                "line": line,
                "excerpt": excerpt,
            }));
        }
    }
}

/// Build the excerpt: every secret span → first 4 chars + "…"; then window
/// to EXCERPT_MAX_CHARS around the first masked span (or the line start).
fn masked_excerpt(line: &str, spans: &[(usize, usize)]) -> String {
    let mut spans: Vec<(usize, usize)> = spans.to_vec();
    spans.sort();
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
        let keep: String = line[s..e].chars().take(4).collect();
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

/// Public (routable) IPv4: valid octets, not private / loopback / link-local
/// / "this network".
fn is_public_ipv4(s: &str) -> bool {
    let mut o = [0u16; 4];
    let mut n = 0usize;
    for part in s.split('.') {
        if n >= 4 {
            return false;
        }
        match part.parse::<u16>() {
            Ok(v) if v <= 255 => o[n] = v,
            _ => return false,
        }
        n += 1;
    }
    if n != 4 {
        return false;
    }
    !(o[0] == 10
        || o[0] == 127
        || o[0] == 0
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 169 && o[1] == 254))
}

/// Days since 1970-01-01 for a proleptic-Gregorian civil date
/// (Howard Hinnant's days_from_civil).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn month_from_abbrev(s: &str) -> i64 {
    match s {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        _ => 12,
    }
}

fn cap_i64(c: &regex_lite::Captures, i: usize) -> i64 {
    c.get(i)
        .and_then(|m| m.as_str().parse::<i64>().ok())
        .unwrap_or(0)
}

/// Best-effort naive timestamp (seconds) from a line: ISO-8601 anywhere in
/// the line, else syslog `Mon DD HH:MM:SS` at line start (year fixed to
/// 2000 — a leap year — so comparisons within one file stay consistent).
fn parse_ts(line: &str, ctx: &Ctx) -> Option<i64> {
    if let Some(c) = ctx.iso_ts_re.captures(line) {
        let (y, mo, d) = (cap_i64(&c, 1), cap_i64(&c, 2), cap_i64(&c, 3));
        let (h, mi, s) = (cap_i64(&c, 4), cap_i64(&c, 5), cap_i64(&c, 6));
        if (1..=12).contains(&mo) && (1..=31).contains(&d) && h < 24 && mi < 60 && s < 61 {
            return Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s);
        }
    }
    if let Some(c) = ctx.syslog_ts_re.captures(line) {
        let mo = month_from_abbrev(c.get(1).map(|m| m.as_str()).unwrap_or("Dec"));
        let d = cap_i64(&c, 2);
        let (h, mi, s) = (cap_i64(&c, 3), cap_i64(&c, 4), cap_i64(&c, 5));
        if (1..=31).contains(&d) && h < 24 && mi < 60 && s < 61 {
            return Some(days_from_civil(2000, mo, d) * 86_400 + h * 3600 + mi * 60 + s);
        }
    }
    None
}

fn scan_file(path: &Path, ctx: &Ctx, acc: &mut Acc) {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => {
            acc.files_skipped += 1;
            return;
        }
    };
    if meta.len() > ctx.max_file_bytes {
        acc.files_skipped += 1;
        return;
    }
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(_) => {
            acc.files_skipped += 1;
            return;
        }
    };
    // treat as text only if valid UTF-8 (skip binaries cleanly)
    let text = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(_) => {
            acc.files_skipped += 1;
            return;
        }
    };
    acc.files_scanned += 1;
    let path_s = path.to_string_lossy().to_string();

    // Optional time window: newest timestamp in the file minus the window.
    // Files with no parseable timestamps are scanned whole.
    let cutoff: Option<i64> = if ctx.window_secs > 0 {
        text.lines()
            .filter_map(|l| parse_ts(l, ctx))
            .max()
            .map(|newest| newest - ctx.window_secs)
    } else {
        None
    };

    let mut error_count = 0usize;
    let mut error_first: Vec<usize> = Vec::new();

    for (i, raw) in text.lines().enumerate() {
        let lineno = i + 1;
        let line = raw.trim_end();
        if let Some(cut) = cutoff {
            match parse_ts(line, ctx) {
                Some(ts) if ts >= cut => {}
                _ => continue, // older than window, or no timestamp
            }
        }
        acc.lines_scanned += 1;
        if line.is_empty() {
            continue;
        }

        // error-class count for error-burst
        if ctx.error_re.is_match(line) {
            error_count += 1;
            if error_first.len() < ERROR_BURST_FIRST_LINES {
                error_first.push(lineno);
            }
        }

        // per-line detectors; collect secret spans to mask
        let mut fired: Vec<(&'static str, Severity)> = Vec::new();
        let mut mask_spans: Vec<(usize, usize)> = Vec::new();
        for d in &ctx.detectors {
            let mut any = false;
            if d.mask_group == 0 {
                any = d.re.is_match(line);
            } else {
                for caps in d.re.captures_iter(line) {
                    any = true;
                    if let Some(m) = caps.get(d.mask_group) {
                        mask_spans.push((m.start(), m.end()));
                    }
                }
            }
            if any {
                fired.push((d.id, d.severity));
            }
        }

        // public IPv4 aggregation
        let mut ip_hits: Vec<&str> = Vec::new();
        for m in ctx.ip_re.find_iter(line) {
            let ip = m.as_str();
            if is_public_ipv4(ip) {
                ip_hits.push(ip);
            }
        }

        if fired.is_empty() && ip_hits.is_empty() {
            continue;
        }
        let excerpt = masked_excerpt(line, &mask_spans);
        for (id, sev) in fired {
            acc.push(ctx, id, sev, &path_s, lineno, &excerpt);
        }
        for ip in ip_hits {
            if let Some(st) = acc.ips.get_mut(ip) {
                st.count += 1;
            } else if acc.ips.len() < MAX_DISTINCT_IPS {
                acc.ips.insert(
                    ip.to_string(),
                    IpStat {
                        count: 1,
                        first_path: path_s.clone(),
                        first_line: lineno,
                        first_excerpt: excerpt.clone(),
                    },
                );
            }
        }
    }

    if error_count >= ERROR_BURST_THRESHOLD {
        let first_line = error_first.first().copied().unwrap_or(0);
        let excerpt = format!(
            "{error_count} error-class lines in file (first at lines {})",
            error_first
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        acc.push(ctx, DET_ERROR_BURST, Severity::Medium, &path_s, first_line, &excerpt);
        acc.error_bursts.push(serde_json::json!({
            "path": path_s,
            "count": error_count,
            "first_lines": error_first,
        }));
    }
}

fn walk(dir: &Path, depth: usize, ctx: &Ctx, acc: &mut Acc) {
    if acc.files_truncated || depth > ctx.max_depth {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return, // unreadable subtree: skip, don't abort the walk
    };
    for entry in entries.flatten() {
        if acc.files_truncated {
            return;
        }
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            walk(&path, depth + 1, ctx, acc);
        } else if meta.is_file() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !glob_match(&ctx.name_glob, &name) {
                continue;
            }
            if acc.files_scanned >= ctx.max_files {
                acc.files_truncated = true;
                return;
            }
            scan_file(&path, ctx, acc);
        }
    }
}

fn arg_usize(a: &serde_json::Value, key: &str, default: u64) -> Result<usize, serde_json::Value> {
    match a.get(key) {
        None | Some(serde_json::Value::Null) => Ok(default as usize),
        Some(v) => v
            .as_u64()
            .map(|n| n as usize)
            .ok_or_else(|| err(format!("{key} must be a non-negative integer"))),
    }
}

fn compile(pat: &str, what: &str) -> Result<Regex, serde_json::Value> {
    // Patterns are built-in constants; a compile failure would be a build
    // bug, but we still fail loud (never panic — a panic traps on the node).
    Regex::new(pat).map_err(|e| err(format!("built-in pattern {what} failed to compile: {e}")))
}

/// All logic; returns the success payload or an error payload. `main` prints
/// whichever and maps it to an ExitCode — no `process::exit`.
fn run() -> Result<serde_json::Value, serde_json::Value> {
    let raw = std::env::args().next().unwrap_or_else(|| "{}".to_string());
    let a: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("args is not valid JSON: {e}")))?;
    if !a.is_object() {
        return Err(err("args must be a JSON object"));
    }

    let root = a.get("root").and_then(|v| v.as_str()).unwrap_or("/work").to_string();
    let name_glob = match a.get("name_glob") {
        None | Some(serde_json::Value::Null) => "*.log".to_string(),
        Some(v) => match v.as_str() {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => return Err(err("name_glob must be a non-empty string")),
        },
    };
    let max_files = arg_usize(&a, "max_files", 500)?;
    let max_file_bytes = arg_usize(&a, "max_file_bytes", 10_485_760)? as u64;
    let max_depth = arg_usize(&a, "max_depth", 20)?;
    let max_findings = arg_usize(&a, "max_findings", 200)?;
    let window_minutes = arg_usize(&a, "window_minutes", 0)?;
    if max_files == 0 {
        return Err(err("max_files must be >= 1"));
    }
    if max_findings == 0 {
        return Err(err("max_findings must be >= 1"));
    }

    let mut detectors = Vec::with_capacity(LINE_DETECTORS.len());
    for (id, pat, severity, mask_group) in LINE_DETECTORS {
        detectors.push(LineDetector {
            id,
            re: compile(pat, id)?,
            severity: *severity,
            mask_group: *mask_group,
        });
    }
    let ctx = Ctx {
        detectors,
        error_re: compile(ERROR_CLASS_RE, DET_ERROR_BURST)?,
        ip_re: compile(IPV4_RE, DET_IOC_IP)?,
        iso_ts_re: compile(ISO_TS_RE, "iso-timestamp")?,
        syslog_ts_re: compile(SYSLOG_TS_RE, "syslog-timestamp")?,
        name_glob,
        max_files,
        max_file_bytes,
        max_depth,
        max_findings,
        window_secs: (window_minutes as i64).saturating_mul(60),
    };

    let root_path = Path::new(&root);
    if !root_path.is_dir() {
        return Err(err(format!(
            "root {root} is not a directory (is it mounted into this lease?)"
        )));
    }

    let mut acc = Acc::new();
    walk(root_path, 0, &ctx, &mut acc);

    // ioc-ip: one info finding per distinct public IP, most frequent first,
    // plus the top-N aggregate.
    let mut ip_list: Vec<(&String, &IpStat)> = acc.ips.iter().collect();
    ip_list.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(b.0)));
    let ip_findings: Vec<(String, String, usize, String)> = ip_list
        .iter()
        .map(|(ip, st)| {
            (
                (*ip).clone(),
                st.first_path.clone(),
                st.first_line,
                st.first_excerpt.clone(),
            )
        })
        .collect();
    let public_ips: Vec<serde_json::Value> = ip_list
        .iter()
        .take(PUBLIC_IPS_TOP)
        .map(|(ip, st)| serde_json::json!({ "ip": ip, "count": st.count }))
        .collect();
    for (_ip, path, line, excerpt) in &ip_findings {
        acc.push(&ctx, DET_IOC_IP, Severity::Info, path, *line, excerpt);
    }

    // Assemble findings: high → medium → info, capped at max_findings.
    let mut findings: Vec<serde_json::Value> = Vec::with_capacity(ctx.max_findings);
    for bucket in [&mut acc.high, &mut acc.medium, &mut acc.info] {
        let room = ctx.max_findings.saturating_sub(findings.len());
        if room == 0 {
            break;
        }
        let take = room.min(bucket.len());
        findings.extend(bucket.drain(..take));
    }
    let truncated = acc.files_truncated || acc.total_findings > ctx.max_findings;

    let by_detector: serde_json::Map<String, serde_json::Value> = acc
        .by_detector
        .iter()
        .map(|(k, v)| (k.to_string(), serde_json::json!(v)))
        .collect();

    Ok(serde_json::json!({
        "tool": TOOL,
        "root": root,
        "files_scanned": acc.files_scanned,
        "files_skipped": acc.files_skipped,
        "lines_scanned": acc.lines_scanned,
        "window_minutes": window_minutes,
        "truncated": truncated,
        "summary": {
            "high": acc.by_severity[Severity::High as usize],
            "medium": acc.by_severity[Severity::Medium as usize],
            "info": acc.by_severity[Severity::Info as usize],
            "by_detector": by_detector,
        },
        "findings": findings,
        "error_bursts": acc.error_bursts,
        "public_ips": public_ips,
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
