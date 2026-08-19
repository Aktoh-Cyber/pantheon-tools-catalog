# dns-resolve

**Tier 4 — NETWORK.** Resolve hostnames from the **node's** vantage point (its resolver,
its split-horizon view) — what that node's workloads actually see. Uses the sandbox
name-lookup capability, enabled under `network_mode:"direct"`; under `"none"` every
lookup fails (sandbox default). Args: `{ "names": ["host", ...] }` (max 50). Output:
`results:[{ name, addrs:[..], count } | { name, error }]`, exit 0 (NXDOMAIN is an answer).
