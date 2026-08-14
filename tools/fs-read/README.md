# fs-read

Tier-0 Synapse tool. Read a file (bounded) and return its content + sha256.
`wasm32-wasip2`; lease `args` JSON at argv[0]; reads only granted paths
(`/work` + mounts). `network_mode: none`, no `host_apis`.

## Args
```json
{ "path": "/work/x", "max_bytes": 65536, "encoding": "utf8" }
```
`encoding` = `utf8` (default) or `base64` (for binary). Output includes
`size_bytes`, `read_bytes`, `sha256` (of returned bytes), `truncated`, `content`.
Bad args / non-UTF-8 in utf8 mode → structured error, exit 1.
