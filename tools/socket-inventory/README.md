# socket-inventory

**Tier 1, read-only inventory.** The host's service map: every listening TCP socket
and bound UDP socket, the process that owns it, and the addresses it is bound to.
With `include_connections: true` it also lists established peers (the input an IOC
match needs). It lists sockets through the node's host provider and never opens
one; the sandbox stays `net:none`. It is a local inventory, not a scan.

Host API: `process.list-owned-sockets` (synapse-node **>= 0.1.17**; Linux reads
`/proc`, macOS `netstat -anvW`, Windows `netstat -ano`). The catalog manifest
declares the grant, so `capabilities` can be left empty on invoke.

## Args
```json
{ "include_connections": false, "max_connections": 500 }
```

## Output
```json
{ "tool": "socket-inventory", "version": "0.1.0",
  "listening_sockets": 12, "service_count": 7, "owner_unknown": 0,
  "services": [
    { "proto": "tcp", "port": 22, "process": "sshd", "pid": 812,
      "binds": ["0.0.0.0", "::"], "ip_versions": ["4", "6"],
      "exposure": "all", "ephemeral_port": false } ],
  "connection_count": 40, "connections_truncated": false,
  "connections": [ { "proto": "tcp", "state": "ESTABLISHED", "local_addr": "10.0.0.5",
      "local_port": 50123, "remote_addr": "52.1.2.3", "remote_port": 443,
      "process": "curl", "pid": 4242 } ],
  "remote_peers": ["52.1.2.3"] }
```

- `exposure`: `loopback` (127/8, ::1 only), `all` (0.0.0.0 or ::), `specific`
  (bound to one interface address).
- `ephemeral_port`: port >= 32768, where client libraries and dev tooling bind.
- `remote_peers`: distinct public peer addresses (private, loopback, link-local,
  CGNAT, multicast and documentation ranges are dropped).
- `owner_unknown`: sockets whose owner the node could not read (for example a
  non-root node looking at another user's process on Linux).

Exit 0 when evaluated. Exit 1 with `error` for bad args, a lease that does not
grant the host API (`denied: true`), or a host that cannot list sockets.

The librarian records this output with `librarian.ingest_inventory`
(`Service` nodes, `Host -[:LISTENS_ON]-> Service`).
