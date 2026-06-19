# fs-list

First WASM reference tool for the Synapse v2 tool pipeline (SYNAPSE-51).

Lists directory contents on a node. Built as `wasm32-wasip2`; the Synapse
executor passes lease `args` as a single JSON-encoded CLI argument.

## Args

```json
{
  "path": "/etc",
  "max_entries": 100,        // optional, default 100
  "include_hidden": false    // optional, default false
}
```

## Output (stdout, single line)

```json
{
  "tool": "fs-list",
  "path": "/etc",
  "count": 42,
  "entries": [
    {"name": "hosts", "kind": "file", "size": 220},
    {"name": "ssl",   "kind": "dir"}
  ]
}
```

Failure mode (`feedback_fail_loud_not_silent`):

```json
{"tool": "fs-list", "error": "read_dir(/no/such) failed: ..."}
```

Exit code: 0 on success, 1 on argument/IO error.

## Build

```bash
./build.sh
# → prints the SHA-256 digest of the WASM artifact;
#   copy is at out/<digest>.wasm
```

## Publish target

Per SYNAPSE-51 bobby cycle-98 decision (OCI strategy Option C):

```
ghcr.io/aktoh-cyber/synapse-tools-shared/fs-list:0.1.0
```

The CI workflow `.github/workflows/wasm-publish.yml` builds + cosign-keyless
signs + pushes on tag.
