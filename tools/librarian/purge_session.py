"""librarian.purge_session — drop every node + relationship for a session.

Symmetric counterpart to `librarian.upsert_node` / `upsert_edge`. The
upsert pair stamps `session_id` on every node they create; this tool
deletes every node carrying a given `session_id` value and (via
DETACH) drops their incident relationships in one statement.

AgentService-only (Cedar `LibrarianPurge` permit from SYNAPSE-33a +
aktoh policy v6). The tool layer does NOT enforce the AgentService
check — Cedar gates the principal upstream. This module's job is
to translate the caller's `{session_id, confirm}` into a deterministic
DETACH DELETE Cypher and return how many nodes were dropped.

Defense-in-depth rules:
  - `session_id` must be non-empty (rejected before Cypher runs).
  - `confirm=True` must be passed explicitly. Default `confirm=False`
    forces the caller to acknowledge the destructive intent. This is
    a deliberate friction step per `feedback_fail_loud_not_silent`:
    a silent default-true would let a stray caller wipe a session's
    graph with no signal.
  - Wildcard `session_id` values (`*`, empty string, whitespace) are
    rejected. The MERGE counterparts validate `session_id` shape on
    the commissioning envelope; we mirror that here.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from tools._shared.neo4j_client import get_driver


class PurgeSessionInput(BaseModel):
    session_id: str = Field(
        ..., min_length=1,
        description="Session identifier to purge. Every node carrying "
        "`session_id == <this value>` is DETACH-DELETEd. Must match "
        "the value used at upsert time.",
    )
    confirm: bool = Field(
        default=False,
        description="Must be set to True to actually delete. Default "
        "False makes the caller acknowledge destructive intent.",
    )
    # Commissioning envelope — symmetric with upsert tools. Helpful
    # for audit logging downstream (e.g. who initiated the purge).
    commissioned_by: str = Field(..., min_length=1)

    @field_validator("session_id")
    @classmethod
    def _no_wildcards(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("session_id must be non-empty after strip")
        if stripped == "*":
            raise ValueError(
                "session_id='*' rejected — purge is single-session "
                "by design; use a specific session_id."
            )
        return v


class PurgeSessionResult(BaseModel):
    session_id: str
    deleted_count: int = Field(
        ...,
        description="Number of nodes deleted. Relationships are "
        "DETACH-dropped silently (Neo4j counts them in "
        "summary.counters.relationships_deleted, surfaced as "
        "relationships_deleted below).",
    )
    relationships_deleted: int


class PurgeSessionToolResponse(BaseModel):
    ok: bool
    result: PurgeSessionResult | None = None
    error: str | None = None
    details: dict[str, Any] | None = None


async def run(input: PurgeSessionInput) -> PurgeSessionToolResponse:
    """DETACH DELETE every node with session_id == input.session_id."""
    if not input.confirm:
        return PurgeSessionToolResponse(
            ok=False,
            error=(
                "confirm=False — purge_session requires explicit "
                "confirm=True to acknowledge destructive intent. "
                "No nodes were touched."
            ),
            details={
                "tool": "librarian.purge_session",
                "session_id": input.session_id,
                "hint": "Re-call with confirm=True if you intended to purge.",
            },
        )

    cypher = (
        "MATCH (n {session_id: $session_id}) "
        "DETACH DELETE n"
    )
    params = {"session_id": input.session_id}

    try:
        driver = get_driver()
        async with driver.session() as session:
            result = await session.run(cypher, params)
            summary = await result.consume()
    except Exception as exc:  # noqa: BLE001
        return PurgeSessionToolResponse(
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
            details={
                "tool": "librarian.purge_session",
                "session_id": input.session_id,
            },
        )

    return PurgeSessionToolResponse(
        ok=True,
        result=PurgeSessionResult(
            session_id=input.session_id,
            deleted_count=summary.counters.nodes_deleted,
            relationships_deleted=summary.counters.relationships_deleted,
        ),
    )


__all__ = [
    "PurgeSessionInput",
    "PurgeSessionResult",
    "PurgeSessionToolResponse",
    "run",
]
