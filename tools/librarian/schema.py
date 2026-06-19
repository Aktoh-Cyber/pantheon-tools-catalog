"""librarian.schema — return the shape of the per-tenant Neo4j graph.

Called once per `/graph` session open so PMC's SchemaSidebar
populates with the labels the operator can actually query. Read-
only; doesn't mutate the graph.

Three procedure calls in one session (atomic enough for a
schema-discovery scenario):
    CALL db.labels()           YIELD label              → list[str]
    CALL db.relationshipTypes() YIELD relationshipType   → list[str]
    CALL db.propertyKeys()     YIELD propertyKey        → list[str]

(An earlier single-Cypher form with chained `CALL` + `WITH collect()`
collapsed to zero rows whenever any of the three procedures returned
zero rows — the cross product wipes the prior accumulators. Three
separate queries are simpler + correct.)

Returns `{node_labels, relationship_types, property_keys}` sorted
alphabetically so the UI sidebar has a stable display order.

Returns the structured-error shape on failure (Neo4j unreachable,
permission denied, etc.) per `feedback_fail_loud_not_silent`.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from tools._shared.neo4j_client import get_driver

_LABELS_CYPHER = "CALL db.labels() YIELD label RETURN label"
_REL_TYPES_CYPHER = "CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType"
_PROP_KEYS_CYPHER = "CALL db.propertyKeys() YIELD propertyKey RETURN propertyKey"


class SchemaInput(BaseModel):
    """No inputs — schema is a global property of the per-tenant
    graph. The tool runtime fills in tenant context (Neo4j driver
    URL) from process env, not from caller-supplied args."""

    pass


class SchemaResult(BaseModel):
    node_labels: list[str] = Field(default_factory=list)
    relationship_types: list[str] = Field(default_factory=list)
    property_keys: list[str] = Field(default_factory=list)


class SchemaToolResponse(BaseModel):
    """MCP wrapper around the result + error channel."""

    ok: bool
    result: SchemaResult | None = None
    error: str | None = None
    details: dict[str, Any] | None = None


async def run(_: SchemaInput | None = None) -> SchemaToolResponse:
    """Execute the three schema-discovery Cyphers and return the result."""
    try:
        driver = get_driver()
        async with driver.session() as session:
            labels = [
                r["label"]
                async for r in await session.run(_LABELS_CYPHER)
            ]
            rel_types = [
                r["relationshipType"]
                async for r in await session.run(_REL_TYPES_CYPHER)
            ]
            prop_keys = [
                r["propertyKey"]
                async for r in await session.run(_PROP_KEYS_CYPHER)
            ]
        return SchemaToolResponse(
            ok=True,
            result=SchemaResult(
                node_labels=sorted(labels),
                relationship_types=sorted(rel_types),
                property_keys=sorted(prop_keys),
            ),
        )
    except Exception as exc:  # noqa: BLE001 — fail loud, surface root cause
        return SchemaToolResponse(
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
            details={"tool": "librarian.schema"},
        )
