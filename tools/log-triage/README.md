# log-triage

Tier-5 Synapse tool (security composite). First-pass triage over a tree of
log files: walks a granted root, reads UTF-8 text files matching `name_glob`
line-by-line and applies 6 built-in detectors. `wasm32-wasip2`; args JSON at
argv[0]; `network_mode: none`, no `host_apis`; pure filesystem + compute;
ExitCode contract (never `process::exit`). Errors go to stdout as
`{"tool":"log-triage","error":...}` with exit 1 (args only — detectors are
built-in). Binary (non-UTF-8), oversized, and unreadable files are skipped,
never abort.

## Args
```json
{ "root":"/work", "name_glob":"*.log",
  "max_files":500, "max_file_bytes":10485760, "max_depth":20,
  "max_findings":200, "window_minutes":0 }
```
All optional. `window_minutes > 0` restricts each file to lines whose
timestamp is within N minutes of the newest timestamp in that file
(ISO-8601 `YYYY-MM-DD[T ]HH:MM:SS` anywhere in the line, or syslog
`Mon DD HH:MM:SS` at line start); lines without a timestamp are skipped in
that mode, files with no parseable timestamps are scanned whole.

## Detectors
| id | severity | what |
|---|---|---|
| `auth-failure` | high | authentication failure / failed password / invalid user / login failed / access denied / 401 / 403 |
| `privilege` | high | `sudo:` / `su:` / root login / privilege / setuid / became root |
| `ioc-suspicious-cmd` | high | `curl\|wget ... \| sh`, `base64 -d`, `nc -e`, `/dev/tcp/`, `powershell -enc`, `mshta`, `certutil -urlcache` |
| `secret-in-log` | high | `password\|passwd\|secret\|api_key\|token [:=] <value>=8 chars>`; the value is **masked** (first 4 chars + `…`), never printed in full |
| `error-burst` | medium | per-file count of `error\|fatal\|panic\|exception\|traceback` lines; reported only when a file has >= 10 (count + first 3 line numbers) |
| `ioc-ip` | info | public IPv4 literals (valid octets; excludes 10/8, 172.16/12, 192.168/16, 127/8, 0/8, 169.254/16); one finding per distinct IP, most frequent first; top 20 in `public_ips` |

One finding per detector per line. Every excerpt is capped at 200 chars and
has all secret spans masked regardless of which detector fired.

## Output
```json
{ "tool":"log-triage", "root":"/work",
  "files_scanned":N, "files_skipped":N, "lines_scanned":N,
  "window_minutes":0, "truncated":false,
  "summary": { "high":N, "medium":N, "info":N,
               "by_detector": { "auth-failure":N, "privilege":N, "ioc-suspicious-cmd":N,
                                "secret-in-log":N, "error-burst":N, "ioc-ip":N } },
  "findings": [ { "detector", "severity", "path", "line", "excerpt" } ],
  "error_bursts": [ { "path", "count", "first_lines":[n,n,n] } ],
  "public_ips": [ { "ip", "count" } ] }
```
`findings` is sorted high → medium → info and capped at `max_findings`;
`summary` counts are totals before the cap. `truncated` is true when
`max_files` or `max_findings` was hit. Distinct public IPs tracked per run
are bounded at 4096.
