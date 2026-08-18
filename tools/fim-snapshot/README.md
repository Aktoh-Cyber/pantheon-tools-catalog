# fim-snapshot

Tier-5 Synapse tool (security composite). File-integrity **baseline**: walks a
granted root and records sha256 (streaming) + size + mtime for every regular
file, plus a single `snapshot_sha256` fingerprint of the whole tree (sha256 over
the sorted `path:sha256` lines). Pair with `fim-diff` to detect drift.
`wasm32-wasip2`; args JSON at argv[0]; `network_mode: none`, no `host_apis`;
ExitCode contract (never `process::exit`). Errors go to stdout as
`{"tool":"fim-snapshot","error":...}` with exit 1.

## Args
```json
{ "root":"/work", "name_glob":"*.conf",
  "max_files":5000, "max_file_bytes":10485760, "max_depth":20 }
```
All optional. Oversized/unreadable files are skipped, never abort the walk.

## Output
```json
{ "tool":"fim-snapshot", "root":"/work", "count":N, "truncated":false,
  "files":[{"path","sha256","size_bytes","modified_unix"}],
  "snapshot_sha256":"<tree fingerprint>" }
```
`files` is sorted by path (deterministic). Feed `files` to `fim-diff` as `baseline`.
