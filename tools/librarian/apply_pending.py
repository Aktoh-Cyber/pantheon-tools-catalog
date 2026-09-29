"""librarian.apply_pending: re-apply commissions the graph store failed to take.

When a write tool hits a store-level failure (the graph store is down, the
driver errors, a MERGE returns nothing), the commission is journaled under
``$LIBRARIAN_STATE_DIR/pending/`` (see ``tools._shared.write_journal``)
instead of being lost. This tool lists those entries (``confirm=False``)
or replays them through the same write tool (``confirm=True``). Every write
is an idempotent MERGE, so a replay can never duplicate data. A successful
replay removes its entry, and one that fails again stays pending with its
attempt count bumped.

Once pending is empty and the last write succeeded, PMC's Knowledge -> Graph
tab stops reporting "updates waiting to be recorded".
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import BaseModel, Field

from tools._shared import write_journal
from tools.librarian import (
    enrich_eol,
    enrich_vulnerabilities,
    ingest_inventory,
    match_iocs,
    purge_session,
    upsert_edge,
    upsert_node,
)

_Replay = tuple[type[BaseModel], Callable[[Any], Awaitable[Any]]]
_REPLAYERS: dict[str, _Replay] = {
    "librarian.upsert_node": (upsert_node.UpsertNodeInput, upsert_node.run),
    "librarian.upsert_edge": (upsert_edge.UpsertEdgeInput, upsert_edge.run),
    "librarian.purge_session": (purge_session.PurgeSessionInput, purge_session.run),
    "librarian.ingest_inventory": (
        ingest_inventory.IngestInventoryInput,
        ingest_inventory.run,
    ),
    "librarian.enrich_vulnerabilities": (
        enrich_vulnerabilities.EnrichVulnerabilitiesInput,
        enrich_vulnerabilities.run,
    ),
    "librarian.enrich_eol": (enrich_eol.EnrichEolInput, enrich_eol.run),
    "librarian.match_iocs": (match_iocs.MatchIocsInput, match_iocs.run),
}


class ApplyPendingInput(BaseModel):
    confirm: bool = Field(
        False,
        description="False lists what is pending without touching the graph. "
        "True replays each pending commission through its write tool.",
    )
    limit: int = Field(100, ge=1, le=1000)


class PendingItem(BaseModel):
    id: str
    tool: str
    attempts: int
    last_error: str | None = None
    applied: bool | None = None
    error: str | None = None


class ApplyPendingResult(BaseModel):
    pending_before: int
    applied: int
    still_failing: int
    remaining: int
    journaling: bool
    items: list[PendingItem]


class ApplyPendingToolResponse(BaseModel):
    ok: bool
    result: ApplyPendingResult | None = None
    error: str | None = None
    details: dict[str, Any] | None = None


async def run(input: ApplyPendingInput) -> ApplyPendingToolResponse:
    if write_journal.state_dir() is None:
        return ApplyPendingToolResponse(
            ok=True,
            result=ApplyPendingResult(
                pending_before=0,
                applied=0,
                still_failing=0,
                remaining=0,
                journaling=False,
                items=[],
            ),
        )

    entries = write_journal.pending_entries()
    items: list[PendingItem] = []
    applied = failing = 0
    for path in entries[: input.limit]:
        entry = write_journal.load_entry(path)
        tool = str(entry.get("tool") or "")
        item = PendingItem(
            id=path.stem,
            tool=tool or "unknown",
            attempts=int(entry.get("attempts") or 0),
            last_error=entry.get("last_error"),
        )
        if input.confirm:
            replay = _REPLAYERS.get(tool)
            if replay is None:
                item.applied, item.error = False, f"unknown tool {tool!r}"
                failing += 1
            else:
                model, runner = replay
                try:
                    parsed = model.model_validate(entry.get("input") or {})
                    resp = await runner(parsed)
                except Exception as exc:
                    item.applied, item.error = False, f"{type(exc).__name__}: {exc}"
                    failing += 1
                else:
                    if getattr(resp, "ok", False):
                        # record_success inside the write tool already
                        # removed the entry (same commission key).
                        item.applied = True
                        applied += 1
                    else:
                        item.applied = False
                        item.error = getattr(resp, "error", None)
                        failing += 1
        items.append(item)

    remaining = len(write_journal.pending_entries())
    return ApplyPendingToolResponse(
        ok=failing == 0,
        result=ApplyPendingResult(
            pending_before=len(entries),
            applied=applied,
            still_failing=failing,
            remaining=remaining,
            journaling=True,
            items=items,
        ),
        error=None
        if failing == 0
        else f"{failing} pending commission(s) still failed to apply",
    )


__all__ = [
    "ApplyPendingInput",
    "ApplyPendingResult",
    "ApplyPendingToolResponse",
    "run",
]
