"""librarian.enrich_all: run every enricher once, in order, after a sweep.

``enrich_vulnerabilities`` (OSV) -> ``enrich_eol`` (endoflife.date) ->
``match_iocs`` (abuse.ch). One failing does not stop the others; each
reports its own ``ok`` and error, and the call is ``ok`` only when all are.
Run it after recording a sweep's inventories with ``librarian.ingest_inventory``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from tools._shared.graph_batch import Commission
from tools.librarian import enrich_eol, enrich_vulnerabilities, match_iocs


class EnrichAllInput(Commission):
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
    steps: dict[str, Any] = {"vulnerabilities": vul, "eol": eol, "iocs": ioc}
    failed = [name for name, r in steps.items() if not r.ok]
    return EnrichAllToolResponse(
        ok=not failed,
        result={name: r.model_dump(exclude_none=True) for name, r in steps.items()},
        error=(f"enrichers failed: {', '.join(failed)}" if failed else None),
    )
