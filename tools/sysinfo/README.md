# sysinfo

Second WASM reference tool for the Synapse v2 tool pipeline. Where `fs-list`
proved the *executor*, `sysinfo` proves the *authoring lifecycle*: a
brand-new tool taken from source → `wasm32-wasip2` build → cosign-keyless
publish → `synapse.upload_tool` registration → signed-lease delivery →
on-node execution, with nothing hand-staged.

It is also a liveness/identity probe. A wasip2 sandbox is deliberately
isolated from host identity (no `gethostname`, no network, only a preopened
`/work`), so instead of a spoofable "hostname" it returns facts the sandbox
can genuinely observe — most importantly a **node-generated wall clock**,
which a deterministic guest cannot fabricate and which therefore proves the
code ran on the node at invocation time.

## Args (all optional)

```json
{ "note": "correlate-this-invoke" }
```

The Synapse executor passes lease `args` as a single JSON-encoded CLI
argument at `argv[0]` (same contract as `fs-list`).

## Output (stdout, single line)

```json
{
  "tool": "sysinfo",
  "note": "correlate-this-invoke",
  "note_hash_djb2": "….",
  "observed": {
    "wall_clock_unix_ms": 1786720796695,
    "arg_count": 1,
    "env_key_count": 0,
    "env_keys": [],
    "wasm_target": "wasm32-wasip2"
  }
}
```

`env_keys` reports the exact environment the lease granted this execution
(keys only, never values) — normally empty, which is the verifiable evidence
the sandbox is locked down. Bad args fail loud: a structured `{"error":…}` to
stdout and exit code 1 (per the vault's fail-loud standard).

## Build

```bash
cd tools/sysinfo && ./build.sh   # prints the wasm sha256, writes out/<sha>.wasm
```

## Publish

Tag `sysinfo-v<semver>` (or run the `wasm-publish` workflow manually) to build,
push to `ghcr.io/aktoh-cyber/pantheon-tools-catalog/sysinfo:<semver>`, and
cosign-keyless sign under the catalog's publish identity.
