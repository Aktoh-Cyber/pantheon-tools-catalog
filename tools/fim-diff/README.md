# fim-diff

Tier-5 Synapse tool (security composite). File-integrity **drift**: takes a
fresh sha256 snapshot of a granted root (same walk/hash logic as
`fim-snapshot`) and compares it to a baseline by path.
`wasm32-wasip2`; args JSON at argv[0]; `network_mode: none`, no `host_apis`;
ExitCode contract (never `process::exit`). Errors go to stdout as
`{"tool":"fim-diff","error":...}` with exit 1. Missing/invalid `baseline` is
an error.

## Args
```json
{ "root":"/work",
  "baseline": [ {"path":"/work/a","sha256":"..."} ],
  "name_glob":"*.conf", "max_files":5000, "max_file_bytes":10485760, "max_depth":20 }
```
`baseline` (REQUIRED) is the `files` array from a `fim-snapshot` output, a whole
fim-snapshot object, or `{"path":"/work/baseline.json"}` to read a saved
snapshot from a granted file. Everything else optional.

## Output
```json
{ "tool":"fim-diff", "root":"/work", "drift":true, "truncated":false,
  "summary":{"added":1,"removed":1,"modified":1,"unchanged":3},
  "added":[{"path","sha256"}],
  "removed":[{"path","sha256"}],
  "modified":[{"path","old_sha256","new_sha256"}] }
```
