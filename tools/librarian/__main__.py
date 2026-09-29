"""MCP server entry-point for the librarian tool catalog.

Run as a stdio MCP server:

    python -m tools.librarian

Pantheon's per-profile config.yaml registers this in the
`mcp_servers` block — Hermes spawns the process at boot and routes
`librarian.*` tool calls through it.

Each tool (schema, query, explain, upsert_node, upsert_edge,
purge_session, apply_pending, and since v0.3.0 ingest_inventory and the
enrichers) is registered with its pydantic input schema; the
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
from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool
from pydantic import BaseModel

from tools._shared import write_journal
from tools._shared.json_safe import to_json_safe
from tools.librarian import (
    apply_pending,
    enrich_all,
    enrich_eol,
    enrich_vulnerabilities,
    explain,
    ingest_inventory,
    match_iocs,
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
_ToolEntry = tuple[str, type[BaseModel], Callable[..., Awaitable[Any]]]
_TOOLS: dict[str, _ToolEntry] = {
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
    "librarian.apply_pending": (
        "List (confirm=false) or re-apply (confirm=true) commissions the "
        "graph store failed to take. Store-level write failures are kept "
        "as pending instead of being lost; replays are idempotent MERGEs. "
        "Use this when a write failed, and before telling anyone the graph "
        "is up to date.",
        apply_pending.ApplyPendingInput,
        apply_pending.run,
    ),
    "librarian.ingest_inventory": (
        "Record a node tool's inventory for one Host in ONE call: pass the "
        "Synapse tool's result.inline_output unchanged. tool=package-inventory "
        "-> Package nodes + HAS_PACKAGE (packages no longer listed are "
        "unlinked); tool=socket-inventory -> Service nodes + LISTENS_ON "
        "(services no longer listening are removed) and the host's public "
        "remote_peers. The Host (merge key node_id) must exist. Use this "
        "instead of one upsert per package or port.",
        ingest_inventory.IngestInventoryInput,
        ingest_inventory.run,
    ),
    "librarian.enrich_all": (
        "Run after EVERY sweep commission, once the inventories are "
        "recorded: enrich_vulnerabilities (OSV), enrich_eol "
        "(endoflife.date) and match_iocs (abuse.ch), in that order. Reports "
        "each step's counts; ok only when all three succeeded.",
        enrich_all.EnrichAllInput,
        enrich_all.run,
    ),
    "librarian.enrich_vulnerabilities": (
        "Match every Host's packages against OSV (osv.dev). Writes "
        "Vulnerability nodes (id, CVEs, severity, CVSS, summary) and "
        "Package-[:AFFECTED_BY {fixed_version, fix_available}]->Vulnerability; "
        "rolls counts up onto Package and Host. Debian/Ubuntu apt packages "
        "are checked (binary->source mapped); Homebrew and Windows packages "
        "are reported unsupported, never guessed.",
        enrich_vulnerabilities.EnrichVulnerabilitiesInput,
        enrich_vulnerabilities.run,
    ),
    "librarian.enrich_eol": (
        "End-of-life status from endoflife.date for each Host's OS release "
        "and for runtimes among its packages (python, nodejs, openssl, perl, "
        "...). Sets eol_* properties on Host and Package and a Finding "
        "(tool eol) per end-of-life item.",
        enrich_eol.EnrichEolInput,
        enrich_eol.run,
    ),
    "librarian.match_iocs": (
        "Match observed IPs/domains/hashes in the graph (e.g. a Host's "
        "remote_peers) against abuse.ch threat intel (ThreatFox, Feodo). "
        "A match writes an Indicator, MATCHES_IOC, and a high-severity "
        "Finding. Reports feeds that need an API key.",
        match_iocs.MatchIocsInput,
        match_iocs.run,
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

    # mcp's Server.list_tools()/call_tool() return untyped decorators
    # (upstream typing gap); silence the strict untyped-decorator errors.
    @server.list_tools()  # type: ignore[no-untyped-call, misc]
    async def _list_tools() -> list[Tool]:
        return [
            Tool(
                name=name,
                description=desc,
                inputSchema=model.model_json_schema(),
            )
            for name, (desc, model, _) in _TOOLS.items()
        ]

    @server.call_tool()  # type: ignore[misc]
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
        except Exception as exc:
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
        except Exception as exc:
            return [
                TextContent(
                    type="text",
                    text=_error_json(
                        f"tool raised: {type(exc).__name__}: {exc}",
                        {"tool": name, "stage": "run"},
                    ),
                )
            ]
        return [TextContent(type="text", text=_encode_response(response))]

    return server


def _encode_response(response: BaseModel) -> str:
    """JSON-encode a tool response, never failing on a value type.

    2026-09-29: a Neo4j DateTime in a result made encoding raise AFTER a
    write had landed, so the agent saw a failure for a successful write.
    Results are made JSON-safe at the source (tools._shared.json_safe);
    this is the backstop, so a new value type degrades to its string form
    instead of hiding the real outcome."""
    import json

    try:
        return response.model_dump_json(exclude_none=True)
    except Exception:
        data = to_json_safe(response.model_dump(exclude_none=True))
        return json.dumps(data, default=str)


def _error_json(error: str, details: dict[str, Any]) -> str:
    import json

    return json.dumps({"ok": False, "error": error, "details": details})


def _catalog_version() -> str:
    # Pantheon runs the catalog from a git clone on PYTHONPATH (not an
    # installed distribution), so read the version from pyproject.toml.
    import tomllib
    from pathlib import Path

    try:
        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        return str(data["project"]["version"])
    except Exception:
        return "unknown"


async def _amain() -> None:
    logging.basicConfig(level=logging.INFO)
    # Tell the tenant (via the sidecar) that the agent runtime actually
    # started this server, not merely that it is configured.
    write_journal.mark_server_started(_catalog_version())
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
