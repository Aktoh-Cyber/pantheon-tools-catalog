"""librarian.ingest_inventory: record a node tool's inventory output in one call.

Pass the Synapse tool's output (``result.inline_output``) as-is, for one host:

- ``package-inventory`` -> ``Package {name, version}`` nodes (plus ``manager``)
  and ``(Host)-[:HAS_PACKAGE]->(Package)``. The snapshot is the host's
  current state, so a HAS_PACKAGE edge to a package no longer listed (removed,
  or upgraded to a new version) is removed. Otherwise an upgraded host would
  keep the old version's vulnerabilities.
- ``socket-inventory`` -> ``Service`` nodes, one per (host, protocol, port,
  owning process), and ``(Host)-[:LISTENS_ON {port, proto, process,
  exposure}]->(Service)``. Service nodes are host-owned, so one this host no
  longer shows is deleted. With ``skip_transient`` (default), loopback-only
  listeners on ephemeral ports (dev tooling, IDE and language-server plumbing)
  and UDP on ephemeral ports (client sockets) are counted on the Host, not
  modelled. Established peers, when present, land on the Host as
  ``remote_peers`` (public addresses only) for ``librarian.match_iocs``.

The Host must already exist (``upsert_node`` label Host, merge key node_id),
the same rule ``upsert_edge`` applies to endpoints: a typo in node_id must
not spawn an orphan host. An EMPTY or truncated snapshot never removes
anything; it is reported instead.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, Field

from tools._shared import write_journal
from tools._shared.graph_batch import Commission, flat, prov, read, write, write_rows

TOOL = "librarian.ingest_inventory"
MAX_PEERS = 500


class IngestInventoryInput(Commission):
    host_node_id: str = Field(
        ..., min_length=1, description="The Host's node_id (Synapse node id)."
    )
    tool: Literal["package-inventory", "socket-inventory"]
    output: dict[str, Any] | str = Field(
        ...,
        description="The tool's output exactly as returned "
        "(result.inline_output), as an object or its JSON text.",
    )
    skip_transient: bool = Field(
        default=True,
        description="socket-inventory only: count, don't model, loopback-only "
        "listeners on ephemeral ports and UDP sockets on ephemeral ports.",
    )


class IngestInventoryResult(BaseModel):
    host_node_id: str
    host_name: str | None = None
    tool: str
    recorded: dict[str, int] = Field(default_factory=dict)
    removed: dict[str, int] = Field(default_factory=dict)
    skipped: dict[str, int] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


class IngestInventoryToolResponse(BaseModel):
    ok: bool
    result: IngestInventoryResult | None = None
    error: str | None = None
    details: dict[str, Any] | None = None


def _parse_output(raw: dict[str, Any] | str) -> dict[str, Any]:
    if isinstance(raw, dict):
        data = raw
    else:
        text = raw.strip()
        # Tolerate a result envelope ({"inline_output": "..."}), or trailing
        # log lines after the JSON line the tool prints.
        try:
            data = json.loads(text)
        except ValueError:
            first = next(
                (ln for ln in text.splitlines() if ln.strip().startswith("{")), ""
            )
            data = json.loads(first) if first else {}
    if isinstance(data.get("inline_output"), str):
        return _parse_output(data["inline_output"])
    if not isinstance(data, dict):
        raise ValueError("output is not a JSON object")
    return data


async def run(input: IngestInventoryInput) -> IngestInventoryToolResponse:
    try:
        out = _parse_output(input.output)
    except ValueError as exc:
        return IngestInventoryToolResponse(
            ok=False,
            error=f"output is not the tool's JSON: {exc}",
            details={"tool": TOOL},
        )
    if out.get("error"):
        return IngestInventoryToolResponse(
            ok=False,
            error=(
                f"the {input.tool} run itself failed: {out['error']}. "
                "Nothing recorded."
            ),
            details={"tool": TOOL, "tool_error": out["error"]},
        )
    field = "packages" if input.tool == "package-inventory" else "services"
    if not isinstance(out.get(field), list):
        return IngestInventoryToolResponse(
            ok=False,
            error=(
                f"this is not {input.tool} output: no `{field}` list. Pass the "
                "tool's result.inline_output unchanged."
            ),
            details={"tool": TOOL, "keys": sorted(out)[:20]},
        )
    payload = input.model_dump(mode="json")
    try:
        hosts = await read(
            "MATCH (h:Host {node_id: $id}) RETURN h.name AS name",
            {"id": input.host_node_id},
        )
        if not hosts:
            return IngestInventoryToolResponse(
                ok=False,
                error=(
                    f"no Host with node_id {input.host_node_id!r} in the graph. "
                    "Record the host first (librarian.upsert_node label Host, "
                    "merge_keys [node_id]), then ingest."
                ),
                details={"tool": TOOL, "hint": "host_not_found"},
            )
        host_name = hosts[0].get("name")
        if input.tool == "package-inventory":
            res = await _packages(input, out)
        else:
            res = await _services(input, out)
        res.host_name = host_name
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        details: dict[str, Any] = {"tool": TOOL, "recorded": False}
        pending = write_journal.record_failure(TOOL, error, payload)
        if pending:
            details["pending_id"] = pending
        return IngestInventoryToolResponse(ok=False, error=error, details=details)
    write_journal.record_success(TOOL, payload)
    return IngestInventoryToolResponse(ok=True, result=res)


# --- package-inventory ---------------------------------------------------------


async def _packages(
    inp: IngestInventoryInput, out: dict[str, Any]
) -> IngestInventoryResult:
    c = Commission(commissioned_by=inp.commissioned_by, session_id=inp.session_id)
    res = IngestInventoryResult(host_node_id=inp.host_node_id, tool=inp.tool)
    pkgs_raw = out.get("packages")
    if not isinstance(pkgs_raw, list):
        raise ValueError("package-inventory output has no `packages` list")
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for p in pkgs_raw:
        if not isinstance(p, dict) or not p.get("name"):
            continue
        name, version = str(p["name"]), str(p.get("version") or "")
        rows[(name, version)] = {
            "name": name,
            "version": version,
            "manager": str(p.get("source") or ""),
        }
    status = str(out.get("status") or ("ok" if rows else "empty"))
    host_props = flat(
        {
            "package_inventory_status": status,
            "package_inventory_note": out.get("note") or None,
            "package_count": int(out.get("total_installed") or len(rows)),
        }
    )
    managers = sorted({r["manager"] for r in rows.values() if r["manager"]})
    for m in managers:
        host_props[f"package_count_{m.replace('-', '_')}"] = sum(
            1 for r in rows.values() if r["manager"] == m
        )
    await write(
        f"MATCH (h:Host {{node_id: $id}}) SET h += $props, "
        f"h.packages_recorded_at = datetime(), {prov('h')}",
        {"id": inp.host_node_id, "props": host_props},
        c,
    )
    if not rows:
        res.notes.append(
            f"package-inventory listed no packages (status {status}): "
            f"{out.get('note') or 'no reason given'}. Existing HAS_PACKAGE edges kept."
        )
        return res
    counters = await write_rows(
        "MATCH (h:Host {node_id: $id}) "
        "UNWIND $rows AS row "
        "MERGE (p:Package {name: row.name, version: row.version}) "
        f"SET p.manager = row.manager, {prov('p')} "
        "MERGE (h)-[r:HAS_PACKAGE]->(p) "
        f"SET r.last_seen_at = datetime(), r.source = 'package-inventory', {prov('r')}",
        list(rows.values()),
        c,
        {"id": inp.host_node_id},
    )
    res.recorded = {
        "packages": len(rows),
        "packages_created": counters.get("nodes_created", 0),
        "has_package_created": counters.get("relationships_created", 0),
    }
    if out.get("truncated"):
        res.notes.append(
            "the tool truncated its list (raise `max`); "
            "stale HAS_PACKAGE edges were kept"
        )
        return res
    keys = [f"{n}\u0000{v}" for (n, v) in rows]
    removed = await write(
        "MATCH (h:Host {node_id: $id})-[r:HAS_PACKAGE]->(p:Package) "
        "WHERE NOT (p.name + '\u0000' + p.version) IN $keys DELETE r",
        {"id": inp.host_node_id, "keys": keys},
        c,
    )
    res.removed = {"stale_has_package": removed.get("relationships_deleted", 0)}
    return res


# --- socket-inventory ----------------------------------------------------------

_LOCAL_PREFIXES = ("10.", "192.168.", "127.", "169.254.", "0.")


def _service_rows(
    host_id: str, host_name: str, services: list[dict[str, Any]], skip_transient: bool
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    rows: list[dict[str, Any]] = []
    skipped = {"loopback_ephemeral": 0, "udp_ephemeral": 0}
    for s in services:
        if not isinstance(s, dict) or s.get("port") is None:
            continue
        proto = str(s.get("proto") or "tcp")
        port = int(s["port"])
        exposure = str(s.get("exposure") or "")
        ephemeral = bool(s.get("ephemeral_port"))
        if skip_transient and ephemeral:
            if exposure == "loopback":
                skipped["loopback_ephemeral"] += 1
                continue
            if proto == "udp":
                skipped["udp_ephemeral"] += 1
                continue
        process = str(s.get("process") or "")
        rows.append(
            {
                "key": f"{host_id}|{proto}/{port}|{process}",
                "props": flat(
                    {
                        "name": f"{process or 'unknown'} {proto}/{port}",
                        "host_node_id": host_id,
                        "host_name": host_name,
                        "proto": proto,
                        "port": port,
                        "process": process,
                        "pid": s.get("pid"),
                        "binds": [str(b) for b in (s.get("binds") or [])],
                        "ip_versions": [str(v) for v in (s.get("ip_versions") or [])],
                        "exposure": exposure,
                        "ephemeral_port": ephemeral,
                        "source": "socket-inventory",
                    }
                ),
                "edge": flat(
                    {
                        "port": port,
                        "proto": proto,
                        "process": process,
                        "exposure": exposure,
                    }
                ),
            }
        )
    return rows, skipped


def _public(addr: str) -> bool:
    if ":" in addr:  # the tool already drops private v6 ranges
        return not addr.lower().startswith(("fe80", "fc", "fd", "::1"))
    if addr.startswith(_LOCAL_PREFIXES):
        return False
    parts = addr.split(".")
    if len(parts) == 4 and parts[0] == "172" and parts[1].isdigit():
        return not 16 <= int(parts[1]) <= 31
    if len(parts) == 4 and parts[0] == "100" and parts[1].isdigit():
        return not 64 <= int(parts[1]) <= 127
    return True


async def _services(
    inp: IngestInventoryInput, out: dict[str, Any]
) -> IngestInventoryResult:
    c = Commission(commissioned_by=inp.commissioned_by, session_id=inp.session_id)
    res = IngestInventoryResult(host_node_id=inp.host_node_id, tool=inp.tool)
    services = out.get("services")
    if not isinstance(services, list):
        raise ValueError("socket-inventory output has no `services` list")
    name_rows = await read(
        "MATCH (h:Host {node_id: $id}) RETURN coalesce(h.name, h.node_id) AS n",
        {"id": inp.host_node_id},
    )
    host_name = str(name_rows[0]["n"]) if name_rows else inp.host_node_id
    rows, skipped = _service_rows(
        inp.host_node_id, host_name, services, inp.skip_transient
    )
    res.skipped = {k: v for k, v in skipped.items() if v}
    peers_raw = out.get("remote_peers")
    host_props: dict[str, Any] = flat(
        {
            "service_count": len(rows),
            "listening_sockets": out.get("listening_sockets"),
            "transient_listeners_skipped": sum(skipped.values()),
            "socket_owner_unknown": out.get("owner_unknown"),
        }
    )
    if isinstance(peers_raw, list):
        peers = sorted({str(p) for p in peers_raw if isinstance(p, str) and _public(p)})
        host_props["remote_peers"] = peers[:MAX_PEERS]
        host_props["connection_count"] = int(out.get("connection_count") or 0)
        res.recorded["remote_peers"] = len(host_props["remote_peers"])
    await write(
        "MATCH (h:Host {node_id: $id}) SET h += $props, "
        f"h.services_recorded_at = datetime(), {prov('h')}"
        + (", h.remote_peers_at = datetime()" if "remote_peers" in host_props else ""),
        {"id": inp.host_node_id, "props": host_props},
        c,
    )
    counters = await write_rows(
        "MATCH (h:Host {node_id: $id}) "
        "UNWIND $rows AS row "
        "MERGE (s:Service {key: row.key}) "
        f"SET s += row.props, s.last_seen_at = datetime(), {prov('s')} "
        "MERGE (h)-[r:LISTENS_ON]->(s) "
        f"SET r += row.edge, r.last_seen_at = datetime(), {prov('r')}",
        rows,
        c,
        {"id": inp.host_node_id},
    )
    res.recorded.update(
        {
            "services": len(rows),
            "services_created": counters.get("nodes_created", 0),
            "listens_on_created": counters.get("relationships_created", 0),
        }
    )
    removed = await write(
        "MATCH (s:Service {host_node_id: $id, source: 'socket-inventory'}) "
        "WHERE NOT s.key IN $keys DETACH DELETE s",
        {"id": inp.host_node_id, "keys": [r["key"] for r in rows]},
        c,
    )
    res.removed = {"stale_services": removed.get("nodes_deleted", 0)}
    if not rows and not services:
        res.notes.append("socket-inventory reported no listening sockets on this host")
    return res
