# compliance-scan

**Tier-2 flagship.** Evaluates a policy bundle against a node and returns pass/fail
**per rule with evidence**, plus a rollup. Composes the read-only M11 providers
(`inventory.os-info`, `package.query`, `service.status`) and, since 0.2.0, the read-only
host `fs` provider (`fs.read-file`, `fs.list-dir`) for `config` rules. Imports only
read-only interfaces, so it cannot mutate host state even if over-granted.

## Rules
Every rule has an `id` and a `type`. The required fields depend on the type:

- **`os`**: optional `kind_in` and `min_version`.
- **`package`**: `name` is required. Optional `installed` and `min_version`.
- **`service`**: `name` is required. Optional `state`.
- **`file`**: `path` and `exists`. This checks the tool's **sandbox** `/work`, not the host disk; evidence carries `scope: "sandbox"`.
- **`config`** (0.2.0): reads an sshd-style keyword file on the **host**. Requires `path`, `directive`, and either `allowed` or `expected`. Optional:
  - `default`: the value to judge when the directive is unset.
  - `missing_file`: `pass`, `fail` or `unknown` (default `unknown`) when the file doesn't exist.

  Keywords are case-insensitive and the first occurrence wins. `Keyword value` and `Keyword=value` both parse. `Include` is followed in place (globs allowed in the last component; relative paths resolve against the main file's directory), and a `Match` line ends the global section.

Outcomes are `pass | fail | unknown | error`. **`unknown` never counts as pass** (host API not granted, or a provider error). The rollup `pass` is true only when every rule passed, and `summary.unknown` surfaces gaps in the lease grant, so an under-granted scan can't silently pass. An `error` (malformed rule) names the shape its type expects.

## Built-in baseline
If `rules` is omitted (or `null`), the tool runs `ssh-root-login` and `ssh-empty-passwords` against the platform's sshd_config: `/etc/ssh/sshd_config`, or `C:\ProgramData\ssh\sshd_config` on Windows.

| Rule | Checks | If the directive is unset | If the file is missing |
|---|---|---|---|
| `ssh-root-login` | `PermitRootLogin no` | judged on OpenSSH's default `prohibit-password`, which fails | pass |
| `ssh-empty-passwords` | `PermitEmptyPasswords no` | default `no` | pass |

`policy_id` defaults to `synapse-baseline`, and `rules_source` reports `default-baseline` or `caller`.

## Invoking
`host_apis` default from the manifest (`declared_capabilities`). `config` rules also need the file's directory in `capabilities.fs_roots`, which is a runtime parameter:

```json
{"tool": "compliance-scan", "args": {}, "capabilities": {"fs_roots": ["/etc/ssh"]}}
```

A granted root that doesn't exist on the host (no SSH server) reads as a missing file on nodes ≥ node-v0.1.16. Older nodes report `unknown` (`fs.read-file denied`).

The manifest's `metadata` (`args_schema`, `rule_shapes`, `invoke_hint`) is returned by `synapse.tool_spec`.
