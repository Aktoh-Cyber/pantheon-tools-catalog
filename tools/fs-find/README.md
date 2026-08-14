# fs-find

Tier-0 Synapse tool. Locate files by name-glob / size / mtime under a root.
Dependency-free glob (`*`, `?`). `wasm32-wasip2`; args JSON at argv[0];
`network_mode: none`, no `host_apis`. Bounded walk (`max_depth`, `max_results`).

## Args
```json
{ "root":"/work", "name_glob":"*.log", "min_size":0, "max_size":0,
  "modified_after_unix":0, "kind":"any", "max_depth":20, "max_results":1000 }
```
`kind` = `any` (default) | `file` | `dir`. Output: `{path,kind,size_bytes,modified_unix}` + `truncated`.
