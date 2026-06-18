# pantheon-tools-catalog

Universal Hermes-MCP tools for the Aktoh pantheon. Customer-bespoke
tools live in `pantheon-tools-<customer>` forks; **this repo** holds
the tools every pantheon agent uses regardless of tenant.

Pantheon containers clone this repo at a pinned tag during boot
(`docker/entrypoint.sh`). Each agent persona registers the tools it
needs via its profile config; tool resolution is by import path
inside this tree.

## Status

Bootstrapped 2026-06-18 per **PANTHEON-21**. First five tools target
the librarian persona's knowledge-graph surface.

| Tool                       | Persona   | Purpose                                                                |
|----------------------------|-----------|------------------------------------------------------------------------|
| `librarian.schema`         | librarian | Return Neo4j node-labels / relationship-types / property-keys.         |
| `librarian.query`          | librarian | Run read-only Cypher; reject write Cypher at the tool layer.           |
| `librarian.explain`        | librarian | Natural language → Cypher (optional pass-through execute).             |
| `librarian.upsert_node`    | librarian | AgentService-only `MERGE`-based node upsert.                           |
| `librarian.upsert_edge`    | librarian | AgentService-only `MERGE`-based relationship upsert.                   |

## Layout

```
tools/
  _shared/                  shared helpers (Neo4j client, Cypher safety)
    neo4j_client.py
    cypher_safety.py
  librarian/                librarian persona tools
    schema.py
    query.py
    explain.py
    upsert_node.py
    upsert_edge.py
    README.md               per-persona tool catalogue
tests/                      pytest suite (testcontainers-managed Neo4j)
.github/workflows/
  ci.yml                    pytest + ruff + bandit + mypy
  release.yml               tag-cut on merge to main
pyproject.toml
requirements.txt
README.md
```

## Conventions

- **Tool entrypoint shape:** each tool exports a `run(...)` coroutine
  and a `SCHEMA` pydantic model describing its input/output. MCP
  framework wires these.
- **Connection pooling:** `_shared/neo4j_client.py` lazily creates a
  single Neo4j driver per process and shares it across tools. Driver
  is reused across calls; closed on process exit.
- **Cedar permits:** every write tool's runtime path goes through the
  Cedar `LibrarianWrite` action (SYNAPSE-32). Read tools rely on the
  default `LibrarianQuery` permit. AgentService vs User principal
  scoping is enforced by Cedar, not the tools.
- **Fail loud:** every tool returns `{ok: bool, error?: str, details?: dict}`
  on failure. Never silent no-op. Per memory
  `feedback_fail_loud_not_silent`.

## Dependencies

- Python 3.13+
- `neo4j` (the official driver, not `py2neo`)
- `pydantic` for tool I/O schemas
- `mcp` for MCP entry surfaces

See `requirements.txt` for pinned versions.

## Testing

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest tests/
```

Tests use [testcontainers-python](https://github.com/testcontainers/testcontainers-python)
to spin up an ephemeral Neo4j per session. No host-side Neo4j needed.
