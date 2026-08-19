# package-remediate

**Tier 3 — WRITE.** Drive a package to `present` (optionally at `version`, idempotent
against `min_version`) or `absent` via the M11 packages provider. Also serves as
**patch-apply**: `desired:present` + `version:<fixed>` + `min_version:<fixed>`.

- **Dry-run by default** — `"apply": true` required; otherwise returns the plan.
- **Idempotent** — `package.query` first; already-good ⇒ `changed:false`, no write.
- **Verify-after-write** — re-queries; `verified:false` if state didn't move.
- **`never_remove` denylist** — built-in floor (node agent, package manager, libc, bash,
  coreutils, systemd, ssh, sudo, ca-certificates) + caller list; `absent` on any of
  these is refused before planning.
- **Honest denial** — missing api ⇒ exit 1 naming it.

## Gate
Lease `host_apis`: `package.query` + `package.install` / `package.uninstall`, AND the
principal must be remediation-entitled (CP grant floor, synapse #137).

## Args
```json
{ "name":"hello", "desired":"present", "version":"2.10-3", "min_version":"2.10", "apply":false }
```
