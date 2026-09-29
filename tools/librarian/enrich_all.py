"""librarian.enrich_all: run every enricher once, in order, after a sweep.

``enrich_vulnerabilities`` (OSV) -> ``enrich_eol`` (endoflife.date) ->
``match_iocs`` (abuse.ch). One failing does not stop the others; each
reports its own ``ok`` and error, and the call is ``ok`` only when all are.
Run it after recording a sweep's inventories (``librarian.collect_inventory``
or ``librarian.ingest_inventory``); ``collect=true`` runs
``collect_inventory`` first, so one call does the whole sweep.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from tools._shared.graph_batch import Commission
from tools.librarian import (
    collect_inventory,
    enrich_eol,
    enrich_vulnerabilities,
    match_iocs,
)


class EnrichAllInput(Commission):
    collect: bool = Field(
        default=False,
        description="Run librarian.collect_inventory (every connected node) first.",
    )
    host_node_id: str | None = Field(
        default=None, description="Limit vulnerability and EOL checks to one Host."
    )


class EnrichAllToolResponse(BaseModel):
    ok: bool
    result: dict[str, Any] | None = None
    error: str | None = None
    details: dict[str, Any] | None = None


async def run(input: EnrichAllInput) -> EnrichAllToolResponse:
    by, sid = input.commissioned_by, input.session_id
    steps: dict[str, Any] = {}
    if input.collect:
        steps["collect"] = await collect_inventory.run(
            collect_inventory.CollectInventoryInput(
                commissioned_by=by,
                session_id=sid,
                node_ids=[input.host_node_id] if input.host_node_id else None,
            )
        )
    vul = await enrich_vulnerabilities.run(
        enrich_vulnerabilities.EnrichVulnerabilitiesInput(
            commissioned_by=by, session_id=sid, host_node_id=input.host_node_id
        )
    )
    eol = await enrich_eol.run(
        enrich_eol.EnrichEolInput(
            commissioned_by=by, session_id=sid, host_node_id=input.host_node_id
        )
    )
    ioc = await match_iocs.run(
        match_iocs.MatchIocsInput(commissioned_by=by, session_id=sid)
    )
    steps.update({"vulnerabilities": vul, "eol": eol, "iocs": ioc})
    failed = [name for name, r in steps.items() if not r.ok]
    return EnrichAllToolResponse(
        ok=not failed,
        result={name: r.model_dump(exclude_none=True) for name, r in steps.items()},
        error=(f"enrichers failed: {', '.join(failed)}" if failed else None),
    )
