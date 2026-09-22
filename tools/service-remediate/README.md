# service-remediate

**Tier 3 — WRITE.** Drive a service to a desired state (`running | stopped | restarted | enabled | disabled`) through the M11 service provider. The first write-tier tool;
built to make host mutation boring:

- **Dry-run by default** — `"apply": true` is required to mutate; otherwise returns the plan.
- **Idempotent** — reads `service.status` first; already-in-state ⇒ `changed:false`, no write.
- **Verify-after-write** — re-reads status; `verified:false` if the state didn't move.
- **Refuses unknown targets** — never enables/restarts a service the back-end can't see.
- **Honest denial** — missing api ⇒ exit 1 naming it.

## `stopped`
`desired:stopped` stops a running service through the `service.stop` host api (added in
synapse-host #145; requires a node image at or after that build). Note `disable` is
boot-config only and does **not** stop an already-running service — use `stopped` for that.

## Gate
Requires (a) lease `host_apis`: `service.status` + the action's write api (`stopped` ⇒
`service.stop`), and (b) the
principal to be remediation-entitled — the CP grant floor (synapse #137) `forbid`s host
writes otherwise. `synapse remediation grant --tenant … --principal … --granted-by …`.

## Args
```json
{ "name":"cron", "desired":"running", "apply":false }
```
