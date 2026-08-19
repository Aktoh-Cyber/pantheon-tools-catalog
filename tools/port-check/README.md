# port-check

**Tier 4 — NETWORK (first).** TCP reachability to `host:port` targets via `std::net` over
`wasi:sockets`. Requires `network_mode:"direct"` + a `destinations` allowlist in the lease;
the node checks every connect against the allowlist and records a `network_decision`
audit event — a non-allowlisted target fails at connect (reported honestly as
`reachable:false`), never silently allowed. Under `network_mode:"none"` every connect fails
at name resolution (proven locally: wasmtime without `-S tcp` → "Non-recoverable error").

## Args
```json
{ "targets": ["host:port", "..."], "timeout_ms": 3000 }
```
Max 50 targets. Output: `results:[{ target, addr, reachable, latency_ms, error? }]`, exit 0
(unreachable is a valid answer); exit 1 only for arg errors.
