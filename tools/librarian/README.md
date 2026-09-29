# librarian — tool catalog

Hermes-MCP tools the librarian persona exposes to the rest of the
pantheon + PMC's `/graph` UI.

| Tool                       | Module                    | Mutates? | Principals          |
|----------------------------|---------------------------|----------|---------------------|
| `librarian.schema`         | `librarian/schema.py`     | no       | User + AgentService |
| `librarian.query`          | `librarian/query.py`      | no       | User + AgentService |
| `librarian.explain`        | `librarian/explain.py`    | no       | User + AgentService |
| `librarian.upsert_node`    | `librarian/upsert_node.py`| yes      | AgentService only   |
| `librarian.upsert_edge`    | `librarian/upsert_edge.py`| yes      | AgentService only   |
| `librarian.purge_session`  | `librarian/purge_session.py`| yes (destructive) | AgentService only |
| `librarian.apply_pending`  | `librarian/apply_pending.py`| yes (replay) | AgentService only |
| `librarian.collect_inventory` | `librarian/collect_inventory.py` | yes (bulk) | AgentService only |
| `librarian.ingest_inventory` | `librarian/ingest_inventory.py` | yes (bulk) | AgentService only |
| `librarian.enrich_all`     | `librarian/enrich_all.py` | yes (bulk) | AgentService only |
| `librarian.enrich_vulnerabilities` | `librarian/enrich_vulnerabilities.py` | yes (bulk) | AgentService only |
| `librarian.enrich_eol`     | `librarian/enrich_eol.py` | yes (bulk) | AgentService only |
| `librarian.match_iocs`     | `librarian/match_iocs.py` | yes (on match) | AgentService only |

These are a **tenant-local stdio MCP server** (`python -m tools.librarian`)
that the pantheon container runs next to its own graph store. They are
not Synapse tools: Synapse tools execute on customer nodes, which cannot
reach the tenant's loopback-bound graph store.

Write tools are Cedar-gated via the `LibrarianWrite` action permit
(SYNAPSE-32). `purge_session` is gated by the `LibrarianPurge`
action permit (SYNAPSE-33a, aktoh policy v6) — separate from
`LibrarianWrite` so a leaked AgentService key with only Write scope
can't trigger destruction. Read tools rely on the default
`LibrarianQuery` permit. AgentService vs User principal scoping is
enforced by
Cedar, not the tools.

Defense in depth: `librarian.query` also rejects write Cypher at
the tool layer (see `tools/_shared/cypher_safety.py`) so an
operator who happens to also have an AgentService side-channel
can't smuggle writes through the read path.

## Inputs and outputs

Each tool exports two pydantic models and one async `run`:

```python
async def run(input: ToolInput) -> ToolResponse:
    ...
```

`ToolResponse` always has `ok: bool` plus exactly one of `result`
or `error` populated. On failure, `error` is the human-readable
diagnostic and `details` carries machine-readable context.

## Cypher safety

`librarian.query` accepts only the read keywords
`MATCH`, `RETURN`, `WITH`, `WHERE`, `ORDER BY`, `LIMIT`,
`OPTIONAL MATCH`, `UNWIND`. Any `MERGE`/`CREATE`/`DELETE`/`SET`/
`REMOVE`/`DROP` keyword triggers `CypherWriteRejected` → tool
returns `{ok: false, error: ...}` and the operator sees a clear
diagnostic in PMC's tool-call card.

## Provenance

Every write call stamps the resulting node/edge with:
- `commissioned_by`: the calling agent's short handle (read from
  the MCP request envelope's `principal_id`)
- `commissioned_at`: server-side `datetime()` (NOT a string —
  Neo4j's native timestamp)
- `session_id`: the operator's session ID for per-session cleanup
  (`librarian.purge_session` reads this)

The provenance keys are reserved — callers cannot override them
via `props`.

## Write journal (v0.2.3)

When `LIBRARIAN_STATE_DIR` is set (pantheon sets `/opt/data/graph`), the
write tools report on themselves:

- `server.json` is written when the MCP server starts. It shows the agent
  runtime actually connected the server, not just that it is configured.
- `write-status.json` records the last success, the last store error, and the
  current failure streak.
- `pending/<tool>-<sha>.json` holds one entry per commission the **store**
  failed to take. The entry is keyed by the commission, so a retry that
  fails again updates it and one that succeeds clears it.
  `librarian.apply_pending` lists entries (`confirm=false`) or replays them
  (`confirm=true`).

Input validation errors, reserved-key conflicts, and missing edge endpoints
are the caller's to fix. They are returned, never queued. The tenant sidecar
reads these files for PMC's Knowledge -> Graph tab, so "nothing recorded
yet" is never shown when recording is actually failing.

## Sweep ingest and enrichment (v0.3.0)

After a sweep, the librarian records every node's inventory and enriches the
graph from public feeds. `librarian.enrich_all` with `collect: true` does all
of it in one call.

0. `librarian.collect_inventory` pulls each connected node's `os-fingerprint`,
   `package-inventory` and `socket-inventory` output straight from Synapse
   (with the librarian profile's own agent token, read from
   `/opt/data/profiles/librarian/.env`) and records it via
   `ingest_inventory`. No inventory passes through an agent's reply: relayed
   that way, the 09-28 aktoh sweep landed 15 of 91 packages with epochs
   dropped. Only those three read-only tools, with fixed arguments.
1. `librarian.ingest_inventory` with `tool` = `package-inventory` or
   `socket-inventory` and `output` = the Synapse result's `inline_output`,
   unchanged. It writes `Package` + `HAS_PACKAGE`, or `Service` +
   `LISTENS_ON` (and the host's public `remote_peers`), and reconciles: a
   package or service the new snapshot no longer lists is unlinked/removed.
   An empty or truncated snapshot never removes anything.
2. `librarian.enrich_all` runs, in order:
   - `enrich_vulnerabilities`: OSV (`api.osv.dev`), Debian/Ubuntu apt
     packages, binary -> source mapped from the release's `Packages.xz`
     (epochs restored). `Vulnerability` nodes and `AFFECTED_BY
     {fixed_version, fix_available}`. Severity is the distro's triage when it
     has one (Debian urgency, Ubuntu priority), else the CVSS v3 base score;
     both are stored. Homebrew/Windows/RPM/Alpine are `unsupported`, with the
     reason.
   - `enrich_eol`: endoflife.date for OS releases and runtimes; `eol_*`
     properties and `Finding` (tool `eol`) per end-of-life item.
   - `match_iocs`: abuse.ch ThreatFox (48 h export) + Feodo Tracker, key-less.
     Put an abuse.ch Auth-Key in `$LIBRARIAN_STATE_DIR/threatfox-auth-key`
     (0600; `/opt/data/graph/threatfox-auth-key` on a tenant) or the
     `THREATFOX_AUTH_KEY` env to use ThreatFox's API (7 days) instead; `LIBRARIAN_IOC_FEEDS` picks feeds.

Feeds are fetched by the tenant container, never by customer nodes, and cached
under `$LIBRARIAN_STATE_DIR/feeds`. Every node and edge carries the usual
provenance (`commissioned_by`, `commissioned_at`, `session_id`).
