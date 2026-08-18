# secret-scan

Tier-5 Synapse tool (security composite). Scans a granted tree for leaked
credentials: 7 built-in regex rules + a Shannon-entropy heuristic. Every
excerpt is **masked** (secret span → first 4 chars + `…`, capped at 200 chars);
the full secret is never printed. `wasm32-wasip2`; args JSON at argv[0];
`network_mode: none`, no `host_apis`; ExitCode contract (never
`process::exit`). Errors go to stdout as `{"tool":"secret-scan","error":...}`
with exit 1 (args only — the rule set is built-in).

## Args
```json
{ "root":"/work", "name_glob":"*.env",
  "max_matches":200, "max_file_bytes":1048576, "max_depth":20,
  "allowlist":["EXAMPLE","test-fixture"] }
```
All optional. A line containing any `allowlist` substring is never reported.
Binary (non-UTF-8), oversized, and unreadable files are skipped.

## Rules
`aws-access-key`, `aws-secret-key`, `github-token`, `slack-token`,
`private-key-block`, `generic-api-key` (`api_key|apikey|secret|token|password|passwd`
`[:=]` value >= 16 chars), `jwt`, plus `high-entropy-string` (any maximal run of
`[A-Za-z0-9+/=_-]` with length >= 20 and Shannon entropy > 4.5 bits/byte that
does not already overlap a regex hit). One record per rule per line.

## Output
```json
{ "tool":"secret-scan", "root":"/work", "count":N, "truncated":false,
  "rules_checked":8,
  "matches":[{"path","line","rule","excerpt"}] }
```
