# os-fingerprint

**Tier-1** Synapse tool — the first catalog tool to call a **host API**. Imports the
M11 first-party provider `synapse:host/inventory@0.1.0` and reports the node's OS
family / version / arch via `inventory.os-info`.

Built as a plain `wasm32-wasip2` command with `wit-bindgen::generate!` (no
`cargo-component`), so it ships through the same `wasm-publish` path as Tier-0.
The host WIT is mirrored into `wit/deps/synapse-host/` from
`synapse/crates/synapse-host/wit/` — keep them in sync.

## Capability contract
The lease must grant `host_apis: ["inventory.os-info"]`. If it does not, the
provider returns a placeholder (`kind: other("denied")`) + a denied audit event; the
tool reports that honestly as `granted:false`.

## Args
`{}` — none.

## Output
```json
{ "tool":"os-fingerprint", "host_api":"inventory.os-info", "granted":true,
  "os": { "kind":"linux-debian", "version":"12", "arch":"aarch64" } }
```
