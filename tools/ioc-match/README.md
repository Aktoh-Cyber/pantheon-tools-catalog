# ioc-match

Synapse v2 tool: match observed indicators (hashes/domains/IPs) against an IOC list (Tier 0, pure compute).

Synapse v2 node tool. Args are a single JSON object on argv; output is one JSON line on stdout. Exit 0 for an evaluated request, exit 1 for argument errors (ExitCode contract — never traps).
