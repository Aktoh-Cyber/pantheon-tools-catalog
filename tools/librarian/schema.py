"""librarian.schema — return the shape of the per-tenant Neo4j graph.

Called once per `/graph` session open so PMC's SchemaSidebar
populates with the labels the operator can actually query. Read-
only; doesn't mutate the graph.

Cypher source (one round-trip via UNWIND):
    CALL db.labels() YIELD label
    WITH collect(label) AS node_labels
    CALL db.relationshipTypes() YIELD relationshipType
    WITH node_labels, collect(relationshipType) AS rel_types
    CALL db.propertyKeys() YIELD propertyKey
    RETURN node_labels, rel_types, collect(propertyKey) AS prop_keys

Returns `{node_labels, relationship_types, property_keys}` sorted
alphabetically so the UI sidebar has a stable display order.

Returns the structured-error shape on failure (Neo4j unreachable,
permission denied, etc.) per `feedback_fail_loud_not_silent`.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from tools._shared.neo4j_client import get_driver

_SCHEMA_CYPHER = """
CALL db.labels() YIELD label
WITH collect(label) AS node_labels
CALL db.relationshipTypes() YIELD relationshipType
WITH node_labels, collect(relationshipType) AS rel_types
CALL db.propertyKeys() YIELD propertyKey
RETURN node_labels, rel_types, collect(propertyKey) AS prop_keys
"""


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
    """Execute the schema-discovery Cypher and return the result."""
    try:
        driver = get_driver()
        async with driver.session() as session:
            record = await (await session.run(_SCHEMA_CYPHER)).single()
        if record is None:
            return SchemaToolResponse(
                ok=True, result=SchemaResult()
            )
        return SchemaToolResponse(
            ok=True,
            result=SchemaResult(
                node_labels=sorted(record["node_labels"]),
                relationship_types=sorted(record["rel_types"]),
                property_keys=sorted(record["prop_keys"]),
            ),
        )
    except Exception as exc:  # noqa: BLE001 — fail loud, surface root cause
        return SchemaToolResponse(
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
            details={"tool": "librarian.schema"},
        )
