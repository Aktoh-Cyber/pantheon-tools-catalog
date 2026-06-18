"""librarian.upsert_edge — commissioner-driven relationship MERGE.

AgentService-only (Cedar `LibrarianWrite`). Same trust + provenance
shape as `upsert_node`: caller is gated upstream by Cedar, this
module translates the request into idempotent MERGE Cypher and
stamps provenance.

Input names the relationship plus its endpoints. Each endpoint is
identified by a `(label, merge_keys, match)` tuple:
- `label`: Cypher label of the endpoint node
- `merge_keys`: which subset of `match` to MERGE-bind on
- `match`: full property bag to match the endpoint by

The endpoint nodes MUST already exist — `upsert_edge` does NOT
create them. Use `upsert_node` for the endpoints first if needed.
Rationale: writing an edge implies a relationship between two
already-known entities; auto-creating endpoints would let a typo
silently spawn orphan nodes.

Provenance stamping on the relationship: `commissioned_by`,
`commissioned_at = datetime()`, `session_id`. Reserved keys; can't
be overridden via `props`.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from tools._shared.neo4j_client import get_driver
from tools._shared.provenance import (
    ReservedKeyConflict,
    assert_no_reserved_keys,
)


class EdgeEndpoint(BaseModel):
    label: str = Field(..., min_length=1)
    merge_keys: list[str] = Field(..., min_length=1)
    match: dict[str, Any] = Field(default_factory=dict)

    @field_validator("label")
    @classmethod
    def _label_must_be_identifier(cls, v: str) -> str:
        if not v[0].isalpha() or not all(c.isalnum() or c == "_" for c in v):
            raise ValueError(
                "Label must be a Cypher identifier "
                "(letter then [A-Za-z0-9_])."
            )
        return v


class UpsertEdgeInput(BaseModel):
    rel_type: str = Field(..., min_length=1)
    from_: EdgeEndpoint = Field(..., alias="from")
    to: EdgeEndpoint
    props: dict[str, Any] = Field(default_factory=dict)
    commissioned_by: str = Field(..., min_length=1)
    session_id: str = Field(..., min_length=1)

    model_config = {"populate_by_name": True}

    @field_validator("rel_type")
    @classmethod
    def _rel_type_must_be_identifier(cls, v: str) -> str:
        if not v[0].isalpha() or not all(c.isalnum() or c == "_" for c in v):
            raise ValueError(
                "rel_type must be a Cypher identifier "
                "(letter then [A-Za-z0-9_])."
            )
        return v


class UpsertEdgeResult(BaseModel):
    element_id: str
    type: str
    source_element_id: str
    target_element_id: str
    properties: dict[str, Any]
    created: bool


class UpsertEdgeToolResponse(BaseModel):
    ok: bool
    result: UpsertEdgeResult | None = None
    error: str | None = None
    details: dict[str, Any] | None = None


async def run(input: UpsertEdgeInput) -> UpsertEdgeToolResponse:
    """Run the MERGE on the relationship + return the resulting edge."""
    # --- validate merge_keys all present in match for each endpoint.
    missing_from = [k for k in input.from_.merge_keys if k not in input.from_.match]
    missing_to = [k for k in input.to.merge_keys if k not in input.to.match]
    if missing_from or missing_to:
        return UpsertEdgeToolResponse(
            ok=False,
            error=(
                "endpoint merge_keys reference properties not in match: "
                f"from={missing_from}, to={missing_to}"
            ),
            details={
                "tool": "librarian.upsert_edge",
                "missing_from_merge_keys": missing_from,
                "missing_to_merge_keys": missing_to,
            },
        )

    # --- reject reserved provenance keys.
    try:
        assert_no_reserved_keys(input.props)
    except ReservedKeyConflict as exc:
        return UpsertEdgeToolResponse(
            ok=False,
            error=str(exc),
            details={
                "tool": "librarian.upsert_edge",
                "conflicting_key": exc.key,
            },
        )

    cypher, params = _build_cypher(input)
    try:
        driver = get_driver()
        async with driver.session() as session:
            result = await session.run(cypher, params)
            record = await result.single()
            summary = await result.consume()
    except Exception as exc:  # noqa: BLE001
        return UpsertEdgeToolResponse(
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
            details={"tool": "librarian.upsert_edge"},
        )

    if record is None:
        return UpsertEdgeToolResponse(
            ok=False,
            error=(
                "MERGE on edge returned no record. Most likely cause: "
                "one or both endpoint nodes don't exist. Use "
                "librarian.upsert_node to create endpoints first."
            ),
            details={
                "tool": "librarian.upsert_edge",
                "hint": "endpoint_not_found",
            },
        )

    rel = record["r"]
    created = summary.counters.relationships_created > 0
    return UpsertEdgeToolResponse(
        ok=True,
        result=UpsertEdgeResult(
            element_id=str(rel.element_id),
            type=rel.type,
            source_element_id=str(rel.start_node.element_id)
            if rel.start_node else "",
            target_element_id=str(rel.end_node.element_id)
            if rel.end_node else "",
            properties=dict(rel),
            created=created,
        ),
    )


def _build_cypher(input: UpsertEdgeInput) -> tuple[str, dict[str, Any]]:
    """Compose the relationship MERGE.

    Shape:
        MATCH (a:FromLabel {from_match_keys}),
              (b:ToLabel   {to_match_keys})
        MERGE (a)-[r:REL_TYPE {edge_merge_keys}]->(b)
        SET   r += $edge_props,
              r.commissioned_by = $commissioned_by,
              r.commissioned_at = datetime(),
              r.session_id = $session_id
        RETURN r

    Endpoints are matched (not merged) — `upsert_edge` doesn't
    create missing endpoint nodes; caller must MERGE those via
    `upsert_node` first.

    The relationship itself is MERGE'd against the from/to pair
    only (no rel-level merge_keys — at most one edge of a given
    type between any two specific nodes; multi-edges or
    parallel-relationship semantics are out of scope for v0.1).
    """
    from_match = ", ".join(
        f"{k}: $from_{k}" for k in input.from_.merge_keys
    )
    to_match = ", ".join(
        f"{k}: $to_{k}" for k in input.to.merge_keys
    )
    cypher = (
        f"MATCH (a:{input.from_.label} {{{from_match}}}), "
        f"(b:{input.to.label} {{{to_match}}}) "
        f"MERGE (a)-[r:{input.rel_type}]->(b) "
        "SET r += $edge_props, "
        "    r.commissioned_by = $commissioned_by, "
        "    r.commissioned_at = datetime(), "
        "    r.session_id = $session_id "
        "RETURN r"
    )
    params: dict[str, Any] = {}
    for k in input.from_.merge_keys:
        params[f"from_{k}"] = input.from_.match[k]
    for k in input.to.merge_keys:
        params[f"to_{k}"] = input.to.match[k]
    params["edge_props"] = input.props
    params["commissioned_by"] = input.commissioned_by
    params["session_id"] = input.session_id
    return cypher, params


__all__ = [
    "EdgeEndpoint",
    "UpsertEdgeInput",
    "UpsertEdgeResult",
    "UpsertEdgeToolResponse",
    "run",
]
