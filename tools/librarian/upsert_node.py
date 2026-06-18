"""librarian.upsert_node — commissioner-driven node MERGE.

AgentService-only (Cedar `LibrarianWrite` permit from SYNAPSE-32 +
aktoh policy v5). The tool layer does NOT enforce the AgentService
check — Cedar gates the principal upstream. This module's job is
to translate the caller's `{label, props, merge_keys}` into a
deterministic, idempotent MERGE Cypher and stamp the result with
provenance.

Idempotency comes from `merge_keys`: every value in `merge_keys`
must be present in `props`. The MERGE matches on those keys; SET
applies the rest.

Provenance keys are reserved (`commissioned_by`, `commissioned_at`,
`session_id`); they're added server-side and callers cannot
override via `props`. See `tools._shared.provenance`.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from tools._shared.neo4j_client import get_driver
from tools._shared.provenance import (
    RESERVED_PROVENANCE_KEYS,
    ReservedKeyConflict,
    assert_no_reserved_keys,
)


class UpsertNodeInput(BaseModel):
    label: str = Field(..., min_length=1)
    merge_keys: list[str] = Field(
        ..., min_length=1,
        description="Property names used in the MERGE match. Must all "
        "be present in `props`.",
    )
    props: dict[str, Any] = Field(default_factory=dict)
    # Commissioning envelope — supplied by the MCP request layer.
    commissioned_by: str = Field(..., min_length=1)
    session_id: str = Field(..., min_length=1)

    @field_validator("label")
    @classmethod
    def _label_must_be_identifier(cls, v: str) -> str:
        # Reject Cypher metacharacters. Neo4j labels are alphanumeric
        # + underscore, must start with a letter.
        if not v[0].isalpha() or not all(c.isalnum() or c == "_" for c in v):
            raise ValueError(
                "Label must be a Cypher identifier "
                "(letter then [A-Za-z0-9_])."
            )
        return v


class UpsertNodeResult(BaseModel):
    element_id: str
    labels: list[str]
    properties: dict[str, Any]
    created: bool = Field(
        ...,
        description="True if the MERGE created a new node, False if it "
        "matched an existing one.",
    )


class UpsertNodeToolResponse(BaseModel):
    ok: bool
    result: UpsertNodeResult | None = None
    error: str | None = None
    details: dict[str, Any] | None = None


async def run(input: UpsertNodeInput) -> UpsertNodeToolResponse:
    """Run the MERGE + return the resulting node."""
    # --- validate merge_keys all present in props.
    missing = [k for k in input.merge_keys if k not in input.props]
    if missing:
        return UpsertNodeToolResponse(
            ok=False,
            error=(
                "merge_keys reference properties not in props: "
                + ", ".join(missing)
                + ". The MERGE clause can't bind to keys that aren't "
                "in the property bag."
            ),
            details={
                "tool": "librarian.upsert_node",
                "missing_merge_keys": missing,
            },
        )

    # --- reject reserved provenance keys in props.
    try:
        assert_no_reserved_keys(input.props)
    except ReservedKeyConflict as exc:
        return UpsertNodeToolResponse(
            ok=False,
            error=str(exc),
            details={
                "tool": "librarian.upsert_node",
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
        return UpsertNodeToolResponse(
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
            details={"tool": "librarian.upsert_node"},
        )

    if record is None:
        return UpsertNodeToolResponse(
            ok=False,
            error="MERGE returned no record — Neo4j misbehaving?",
            details={"tool": "librarian.upsert_node"},
        )

    node = record["n"]
    created = summary.counters.nodes_created > 0
    return UpsertNodeToolResponse(
        ok=True,
        result=UpsertNodeResult(
            element_id=str(node.element_id),
            labels=sorted(node.labels),
            properties=dict(node),
            created=created,
        ),
    )


def _build_cypher(
    input: UpsertNodeInput,
) -> tuple[str, dict[str, Any]]:
    """Compose the MERGE Cypher with parameterised values.

    Shape:
        MERGE (n:Label {key1: $merge_key1, key2: $merge_key2})
        SET n += $set_props,
            n.commissioned_by = $commissioned_by,
            n.commissioned_at = datetime(),
            n.session_id = $session_id
        RETURN n
    """
    match_clauses = ", ".join(
        f"{k}: $merge_{k}" for k in input.merge_keys
    )
    # Build the params dict: merge_<key> for each merge key, plus the
    # full set_props for the non-match properties (which is `props`
    # itself — Neo4j's `+=` overlays on existing, and the MERGE
    # match path will match against the merge_keys, then SET applies
    # everything else without removing existing fields).
    params: dict[str, Any] = {f"merge_{k}": input.props[k] for k in input.merge_keys}
    params["set_props"] = input.props
    params["commissioned_by"] = input.commissioned_by
    params["session_id"] = input.session_id
    cypher = (
        f"MERGE (n:{input.label} {{{match_clauses}}}) "
        "SET n += $set_props, "
        "    n.commissioned_by = $commissioned_by, "
        "    n.commissioned_at = datetime(), "
        "    n.session_id = $session_id "
        "RETURN n"
    )
    return cypher, params


__all__ = [
    "UpsertNodeInput",
    "UpsertNodeResult",
    "UpsertNodeToolResponse",
    "RESERVED_PROVENANCE_KEYS",
    "run",
]
