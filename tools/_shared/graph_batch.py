"""Batch read/write helpers for the librarian's bulk tools (v0.3.0).

``upsert_node`` / ``upsert_edge`` write one entity per call, which is right
for a commission of a few facts and wrong for a 91-package inventory or a
few hundred vulnerabilities: the agent would spend hundreds of tool calls and
could stop halfway. The bulk tools (``ingest_inventory``, the enrichers)
write with ``UNWIND`` in a few transactions instead, and stamp the same
provenance (``commissioned_by``, ``commissioned_at = datetime()``,
``session_id``) on every node and relationship they touch.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from tools._shared.json_safe import to_json_safe
from tools._shared.neo4j_client import get_driver

CHUNK = 250


class Commission(BaseModel):
    """The commissioning envelope every write tool requires."""

    commissioned_by: str = Field(..., min_length=1)
    session_id: str = Field(..., min_length=1)


def prov(var: str) -> str:
    """Cypher fragment stamping provenance on ``var``."""
    return (
        f"{var}.commissioned_by = $commissioned_by, "
        f"{var}.commissioned_at = datetime(), "
        f"{var}.session_id = $session_id"
    )


async def read(
    cypher: str, params: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    driver = get_driver()
    async with driver.session() as session:
        result = await session.run(cypher, params or {})
        rows = [r.data() async for r in result]
    return [to_json_safe(r) for r in rows]


async def write(
    cypher: str,
    params: dict[str, Any],
    commission: Commission,
) -> dict[str, int]:
    """Run one write statement; return its counters."""
    driver = get_driver()
    full = {
        **params,
        "commissioned_by": commission.commissioned_by,
        "session_id": commission.session_id,
    }
    async with driver.session() as session:
        result = await session.run(cypher, full)
        summary = await result.consume()
    c = summary.counters
    return {
        "nodes_created": c.nodes_created,
        "nodes_deleted": c.nodes_deleted,
        "relationships_created": c.relationships_created,
        "relationships_deleted": c.relationships_deleted,
        "properties_set": c.properties_set,
    }


async def write_rows(
    cypher: str,
    rows: list[dict[str, Any]],
    commission: Commission,
    extra: dict[str, Any] | None = None,
) -> dict[str, int]:
    """``UNWIND $rows AS row ...`` in chunks; summed counters."""
    total: dict[str, int] = {}
    for start in range(0, len(rows), CHUNK):
        counters = await write(
            cypher, {**(extra or {}), "rows": rows[start : start + CHUNK]}, commission
        )
        for k, v in counters.items():
            total[k] = total.get(k, 0) + v
    return total


def flat(props: dict[str, Any]) -> dict[str, Any]:
    """Drop None and anything the graph cannot store as a property (only
    scalars and homogeneous scalar lists are allowed)."""
    out: dict[str, Any] = {}
    for k, v in props.items():
        if v is None:
            continue
        if isinstance(v, bool | int | float | str):
            out[k] = v
        elif isinstance(v, list | tuple):
            items = [x for x in v if isinstance(x, bool | int | float | str)]
            if items and len({type(x) for x in items}) == 1:
                out[k] = list(items)
            elif not v:
                out[k] = []
    return out
