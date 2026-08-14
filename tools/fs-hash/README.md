# fs-hash

Tier-0 Synapse tool. Checksum one or more files (streaming) for integrity/FIM.
`wasm32-wasip2`; args JSON at argv[0]; `network_mode: none`, no `host_apis`.

## Args
```json
{ "paths": ["/work/a","/work/b"], "algo": "sha256" }
```
`algo` = `sha256` (default) | `sha1` | `md5`. Single `"path"` also accepted.
Per-file errors are reported inline (a bad path doesn't abort the batch).
