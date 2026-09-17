# net-sweep

Synapse v2 tool: TCP-connect liveness sweep across a host list (Tier 4, net:direct). The sandbox-legal ping — no ICMP.

Synapse v2 node tool. Args are a single JSON object on argv; output is one JSON line on stdout. Exit 0 for an evaluated request, exit 1 for argument errors (ExitCode contract — never traps).
