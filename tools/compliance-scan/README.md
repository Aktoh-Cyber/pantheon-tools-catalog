# compliance-scan

**Tier-2 flagship.** Evaluates a policy bundle against a node and returns pass/fail
**per rule with evidence**, plus a rollup. Composes the three read-only M11 providers
(`inventory.os-info`, `package.query`, `service.status`) + the sandbox filesystem.
Imports only read-only interfaces — cannot mutate host state even if over-granted.

## Rules
`os` (kind_in, min_version) · `package` (name, installed, min_version) · `service`
(name, state) · `file` (path, exists). Outcomes: `pass | fail | unknown | error`.
**`unknown` (host API not granted / provider error) never counts as pass** — the
rollup `pass` is true only when every rule passed. `summary.unknown` surfaces gaps
in the lease grant, so an under-granted scan can't silently pass.

## Args
See `src/main.rs` module doc for a full bundle example. Grant the subset of
`host_apis` your rules need: `inventory.os-info`, `package.query`, `service.status`.
