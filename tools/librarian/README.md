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

Write tools are Cedar-gated via the `LibrarianWrite` action permit
(SYNAPSE-32). Read tools rely on the default `LibrarianQuery`
permit. AgentService vs User principal scoping is enforced by
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
