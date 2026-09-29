"""librarian.collect_inventory: pull each node's inventory from Synapse into the graph.

For every connected node (or the ``node_ids`` given), it runs the read-only
Tier-1 inventory tools through Synapse and records their output with
``librarian.ingest_inventory``. No output ever passes through an agent's reply.
- ``os-fingerprint``: the Host's ``os_kind`` / ``os_version`` / ``arch``,
  which the enrichers need.
- ``package-inventory``: Package + HAS_PACKAGE.
- ``socket-inventory``: Service + LISTENS_ON, plus public ``remote_peers``.
  Needs synapse-node >= 0.1.17.

Relaying the output through a reply is how the 09-28 aktoh sweep landed 15 of
91 packages with epochs dropped.

The Host node (merge key ``node_id``) is created or refreshed from Synapse's
node report: name, connected, last_seen, agent_version. Only those three
fixed, read-only tools are ever invoked, with fixed arguments. Cedar decides
each invoke as it does for the agent. A tool that fails on a node is reported
for that node and does not stop the rest.

Then run ``librarian.enrich_all``.
"""

from __future__ import annotations

import asyncio
from typing import Any

from pydantic import BaseModel, Field

from tools._shared import write_journal
from tools._shared.graph_batch import Commission, flat, prov, write
from tools._shared.synapse_client import SynapseClient, SynapseError, candidate_digests
from tools.librarian import ingest_inventory

TOOL = "librarian.collect_inventory"
INVENTORY_TOOLS = ("os-fingerprint", "package-inventory", "socket-inventory")
_ARGS: dict[str, dict[str, Any]] = {
    "os-fingerprint": {},
    "package-inventory": {},
    "socket-inventory": {"include_connections": True, "max_connections": 200},
}
# A node captures at most 64 KiB of a tool's stdout, and package-inventory
# prints every package it returns. 500 rows stay under that even with long
# Windows display names. A host with more is read page by page with
# name_prefix (see _collect_packages).
PKG_PAGE = 500
_PREFIX_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_MAX_PREFIX_DEPTH = 3


class CollectInventoryInput(Commission):
    node_ids: list[str] | None = Field(
        default=None,
        description="Synapse node ids to collect from (default: every "
        "connected node of the tenant).",
    )
    tools: list[str] = Field(
        default_factory=lambda: list(INVENTORY_TOOLS),
        description="Subset of os-fingerprint, package-inventory, socket-inventory.",
    )


class CollectInventoryResult(BaseModel):
    tenant: str
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    skipped_offline: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class CollectInventoryToolResponse(BaseModel):
    ok: bool
    result: CollectInventoryResult | None = None
    error: str | None = None
    details: dict[str, Any] | None = None


async def run(input: CollectInventoryInput) -> CollectInventoryToolResponse:
    bad = [t for t in input.tools if t not in INVENTORY_TOOLS]
    if bad:
        return CollectInventoryToolResponse(
            ok=False,
            error=f"only {', '.join(INVENTORY_TOOLS)} can be collected, not {bad}",
            details={"tool": TOOL},
        )
    try:
        client = await asyncio.to_thread(SynapseClient.from_environment)
        nodes = await asyncio.to_thread(client.nodes)
        catalog = await asyncio.to_thread(client.tools)
    except SynapseError as exc:
        return CollectInventoryToolResponse(
            ok=False, error=f"Synapse unavailable: {exc}", details={"tool": TOOL}
        )
    res = CollectInventoryResult(tenant=client.tenant)
    by_id = {str(n.get("node_id")): n for n in nodes}
    if input.node_ids:
        targets = []
        for nid in input.node_ids:
            if nid not in by_id:
                res.errors.append(f"{nid}: not an enrolled node of {client.tenant}")
            else:
                targets.append(by_id[nid])
    else:
        targets = [n for n in nodes if n.get("status") != "revoked"]
    c = Commission(commissioned_by=input.commissioned_by, session_id=input.session_id)
    ok_any = False
    for node in targets:
        nid = str(node.get("node_id"))
        name = str(node.get("name") or nid)
        await write(
            "MERGE (h:Host {node_id: $id}) "
            "SET h += $props, h.last_verified_at = datetime(), " + prov("h"),
            {
                "id": nid,
                "props": flat(
                    {
                        "name": name,
                        "connected": bool(node.get("connected")),
                        "last_seen": node.get("last_seen"),
                        "agent_version": node.get("current_version"),
                        "source": "synapse",
                    }
                ),
            },
            c,
        )
        if not node.get("connected"):
            res.skipped_offline.append(f"{name} (last seen {node.get('last_seen')})")
            continue
        summary: dict[str, Any] = {"node_id": nid, "name": name}
        for tool in [t for t in INVENTORY_TOOLS if t in input.tools]:
            if tool == "package-inventory":
                out, err = await _collect_packages(client, catalog, nid)
            else:
                out, err = await _invoke(client, catalog, nid, tool, _ARGS[tool])
            if err or out is None:
                summary[tool] = f"failed: {err}"
                res.errors.append(f"{name} {tool}: {err}")
                continue
            if tool == "os-fingerprint":
                summary[tool] = await _record_os(nid, out, c)
                ok_any = True
                continue
            ing = await ingest_inventory.run(
                ingest_inventory.IngestInventoryInput(
                    host_node_id=nid,
                    tool=tool,  # type: ignore[arg-type]
                    output=out,
                    commissioned_by=input.commissioned_by,
                    session_id=input.session_id,
                )
            )
            if ing.ok and ing.result:
                ok_any = True
                summary[tool] = ing.result.model_dump(exclude_none=True)
            else:
                summary[tool] = f"not recorded: {ing.error}"
                res.errors.append(f"{name} {tool}: {ing.error}")
        res.nodes.append(summary)
    payload = input.model_dump(mode="json")
    if ok_any:
        write_journal.record_success(TOOL, payload)
    return CollectInventoryToolResponse(
        ok=ok_any and not res.errors,
        result=res,
        error=(
            None
            if ok_any and not res.errors
            else ("; ".join(res.errors) or "nothing was collected")
        ),
    )


async def _collect_packages(
    client: SynapseClient, catalog: list[dict[str, Any]], node_id: str
) -> tuple[dict[str, Any] | None, str | None]:
    """The whole package list in pages that fit the node's output capture."""
    tool = "package-inventory"
    first, err = await _invoke(client, catalog, node_id, tool, {"max": PKG_PAGE})
    if first is None or not first.get("truncated"):
        return first, err
    total = int(first.get("total_installed") or 0)
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    incomplete: list[str] = []

    async def walk(prefix: str) -> None:
        out, e = await _invoke(
            client, catalog, node_id, tool, {"max": PKG_PAGE, "name_prefix": prefix}
        )
        if out is None:
            incomplete.append(f"{prefix}*: {e}")
            return
        if out.get("truncated") and len(prefix) < _MAX_PREFIX_DEPTH:
            for ch in _PREFIX_CHARS:
                await walk(prefix + ch)
            return
        if out.get("truncated"):
            incomplete.append(f"{prefix}*: more than {PKG_PAGE} names")
        for p in out.get("packages") or []:
            if isinstance(p, dict) and p.get("name"):
                rows[(str(p["name"]), str(p.get("version") or ""))] = p

    for ch in _PREFIX_CHARS:
        await walk(ch)
    merged = {
        **{k: v for k, v in first.items() if k != "packages"},
        "packages": list(rows.values()),
        "matched": len(rows),
        # Names starting outside [A-Za-z0-9] are not reachable by prefix; a
        # short count keeps the snapshot from reconciling (never unlinks).
        "truncated": bool(incomplete) or len(rows) < total,
        "paged": True,
    }
    if incomplete:
        merged["note"] = "incomplete pages: " + "; ".join(incomplete[:5])
    return merged, None


async def _invoke(
    client: SynapseClient,
    catalog: list[dict[str, Any]],
    node_id: str,
    tool: str,
    args: dict[str, Any],
) -> tuple[dict[str, Any] | None, str | None]:
    digests = candidate_digests(catalog, tool)
    if not digests:
        return None, f"{tool} is not in the tenant's Synapse tool list"
    last = "no attempt"
    for digest in digests:
        try:
            result = await asyncio.to_thread(client.invoke, node_id, digest, args)
        except SynapseError as exc:
            last = str(exc)
            continue
        out = result.get("inline_output")
        if isinstance(out, str):
            try:
                out = ingest_inventory._parse_output(out)
            except ValueError:
                out = None
        if result.get("exit_kind") == "success" and isinstance(out, dict):
            return out, None
        if isinstance(out, dict) and out.get("error"):
            last = f"{digest[:19]}: {out['error']}"
        else:
            kind, code = result.get("exit_kind"), result.get("exit_code")
            last = f"{digest[:19]}: exit {kind} / {code}"
    return None, last


async def _record_os(node_id: str, out: dict[str, Any], c: Commission) -> str:
    os_ = out.get("os") if isinstance(out.get("os"), dict) else {}
    if not out.get("granted", True) or not os_:
        return "os-info not granted"
    kind = str(os_.get("kind") or "")
    props = flat(
        {
            "os_kind": kind,
            "os_version": os_.get("version") or None,
            "arch": os_.get("arch") or None,
            "platform": (
                "linux"
                if kind.startswith("linux")
                else ("macos" if kind == "macos" else kind)
            )
            or None,
        }
    )
    await write(
        f"MATCH (h:Host {{node_id: $id}}) SET h += $props, {prov('h')}",
        {"id": node_id, "props": props},
        c,
    )
    return f"{props.get('os_kind')} {props.get('os_version', '')}".strip()
