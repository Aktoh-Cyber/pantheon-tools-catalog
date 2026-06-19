"""MCP server entry-point for the librarian tool catalog.

Run as a stdio MCP server:

    python -m tools.librarian

Pantheon's per-profile config.yaml registers this in the
`mcp_servers` block — Hermes spawns the process at boot and routes
`librarian.*` tool calls through it.

Each of the 5 tools (schema, query, explain, upsert_node,
upsert_edge) is registered with its pydantic input schema; the
server validates the input against the schema, calls the tool's
`run()`, and returns the response as a JSON-serializable dict.

Cedar's `LibrarianQuery` / `LibrarianWrite` permits gate the
principal upstream (synapse control-plane). The tool layer here
doesn't enforce the principal — it trusts whatever's already
been authorized.

This module is the seam between the async, structured-error
pydantic-shaped `run()` functions and the MCP wire format. The
tool implementations stay framework-agnostic; the MCP framework
is only imported in this module.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from mcp.server import Server  # type: ignore[import-not-found]
from mcp.server.stdio import stdio_server  # type: ignore[import-not-found]
from mcp.types import TextContent, Tool  # type: ignore[import-not-found]

from tools.librarian import (
    explain,
    purge_session,
    query,
    schema,
    upsert_edge,
    upsert_node,
)


log = logging.getLogger("librarian-mcp")


# --- tool registry ----------------------------------------------------------

# Map MCP tool name → (description, pydantic input model, run callable).
# The MCP server exposes each entry as a tool with its JSON Schema.
_TOOLS = {
    "librarian.schema": (
        "Return the shape of the per-tenant Neo4j: node_labels, "
        "relationship_types, property_keys.",
        schema.SchemaInput,
        schema.run,
    ),
    "librarian.query": (
        "Run read-only Cypher. Returns rows + optional GraphData "
        "projection. Rejects writes at the tool layer (defense in "
        "depth alongside Cedar).",
        query.QueryInput,
        query.run,
    ),
    "librarian.explain": (
        "Translate a natural-language question into Cypher. Optional "
        "`execute=true` runs the candidate through the read-only path.",
        explain.ExplainInput,
        explain.run,
    ),
    "librarian.upsert_node": (
        "Commissioner-driven node MERGE. AgentService-only via Cedar "
        "LibrarianWrite. Stamps commissioned_by/commissioned_at/"
        "session_id provenance server-side.",
        upsert_node.UpsertNodeInput,
        upsert_node.run,
    ),
    "librarian.upsert_edge": (
        "Commissioner-driven relationship MERGE. Endpoints MATCHed "
        "(not auto-created). AgentService-only via Cedar "
        "LibrarianWrite. Stamps provenance.",
        upsert_edge.UpsertEdgeInput,
        upsert_edge.run,
    ),
    "librarian.purge_session": (
        "DETACH DELETE every node carrying session_id == <input>. "
        "AgentService-only via Cedar LibrarianPurge. Requires "
        "explicit confirm=True; wildcard session_ids rejected.",
        purge_session.PurgeSessionInput,
        purge_session.run,
    ),
}


# --- server ----------------------------------------------------------------


def _build_server() -> Server:
    server = Server("pantheon-librarian-tools")

    @server.list_tools()
    async def _list_tools() -> list[Tool]:
        return [
            Tool(
                name=name,
                description=desc,
                inputSchema=model.model_json_schema(),
            )
            for name, (desc, model, _) in _TOOLS.items()
        ]

    @server.call_tool()
    async def _call_tool(
        name: str, arguments: dict[str, Any]
    ) -> list[TextContent]:
        entry = _TOOLS.get(name)
        if entry is None:
            return [
                TextContent(
                    type="text",
                    text=(
                        '{"ok": false, "error": "unknown tool: '
                        f'{name}\", "details": {{"available": '
                        f'{sorted(_TOOLS)}}}}}'
                    ),
                )
            ]
        _desc, input_model, run_callable = entry
        try:
            parsed = input_model.model_validate(arguments)
        except Exception as exc:  # noqa: BLE001
            return [
                TextContent(
                    type="text",
                    text=_error_json(
                        f"input validation failed: {type(exc).__name__}: {exc}",
                        {"tool": name, "stage": "validate"},
                    ),
                )
            ]
        try:
            response = await run_callable(parsed)
        except Exception as exc:  # noqa: BLE001
            return [
                TextContent(
                    type="text",
                    text=_error_json(
                        f"tool raised: {type(exc).__name__}: {exc}",
                        {"tool": name, "stage": "run"},
                    ),
                )
            ]
        return [
            TextContent(
                type="text",
                text=response.model_dump_json(exclude_none=True),
            )
        ]

    return server


def _error_json(error: str, details: dict[str, Any]) -> str:
    import json

    return json.dumps({"ok": False, "error": error, "details": details})


async def _amain() -> None:
    logging.basicConfig(level=logging.INFO)
    server = _build_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main() -> None:
    asyncio.run(_amain())


if __name__ == "__main__":
    main()
