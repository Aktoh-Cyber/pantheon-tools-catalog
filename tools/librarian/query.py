"""librarian.query — run read-only Cypher against the per-tenant Neo4j.

Operator workflow: PMC `/graph` composer sends a Cypher string;
librarian executes it; PMC renders rows as a table and (when the
query yields a path/subgraph) lifts the optional `graph` projection
into `AgentGraph`.

Safety:
- Defense in depth via `tools._shared.cypher_safety.assert_read_only`.
  MERGE/CREATE/DELETE/SET/REMOVE/DROP are rejected at the tool
  layer regardless of Cedar permits.
- Cedar runtime permits the operator's User principal with
  `LibrarianQuery` (default); writes need AgentService +
  `LibrarianWrite` (SYNAPSE-32). The tool layer doesn't enforce
  the AgentService gate — Cedar does. We just make sure no path
  through this tool can mutate the graph.

Graph projection:
- If a row contains a `Node`, `Relationship`, or `Path` value, we
  flatten the whole result set into a `GraphData` shape PMC's
  `AgentGraph` can render. Rows still come back verbatim so the
  table-view UI also works.
"""
from __future__ import annotations

from typing import Any, Optional

from neo4j.graph import Node, Path, Relationship
from pydantic import BaseModel, Field

from tools._shared.cypher_safety import (
    CypherWriteRejected,
    assert_read_only,
)
from tools._shared.neo4j_client import get_driver


class QueryInput(BaseModel):
    cypher: str = Field(..., min_length=1, description="Read-only Cypher")
    params: dict[str, Any] = Field(
        default_factory=dict,
        description="Bind parameters (use these instead of string-"
        "interpolating user input into the Cypher).",
    )


class GraphNode(BaseModel):
    id: str
    labels: list[str]
    properties: dict[str, Any]


class GraphEdge(BaseModel):
    id: str
    type: str
    source: str
    target: str
    properties: dict[str, Any]


class GraphData(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class QueryResult(BaseModel):
    rows: list[dict[str, Any]] = Field(default_factory=list)
    graph: Optional[GraphData] = None


class QueryToolResponse(BaseModel):
    ok: bool
    result: QueryResult | None = None
    error: str | None = None
    details: dict[str, Any] | None = None


async def run(input: QueryInput) -> QueryToolResponse:
    """Execute `input.cypher` after read-only validation."""
    try:
        assert_read_only(input.cypher)
    except CypherWriteRejected as exc:
        return QueryToolResponse(
            ok=False,
            error=str(exc),
            details={
                "tool": "librarian.query",
                "rejected_keyword": exc.keyword,
                "cypher": input.cypher,
            },
        )

    try:
        driver = get_driver()
        async with driver.session() as session:
            result = await session.run(input.cypher, input.params)
            rows = [dict(record) async for record in result]
    except Exception as exc:  # noqa: BLE001 — fail loud
        return QueryToolResponse(
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
            details={"tool": "librarian.query"},
        )

    graph = _project_graph(rows) if _rows_contain_graph(rows) else None
    return QueryToolResponse(
        ok=True,
        result=QueryResult(rows=_serialize_rows(rows), graph=graph),
    )


# --- graph projection --------------------------------------------------------


def _rows_contain_graph(rows: list[dict[str, Any]]) -> bool:
    for row in rows:
        for value in row.values():
            if isinstance(value, (Node, Relationship, Path)):
                return True
            if isinstance(value, list) and any(
                isinstance(v, (Node, Relationship, Path)) for v in value
            ):
                return True
    return False


def _project_graph(rows: list[dict[str, Any]]) -> GraphData:
    nodes: dict[str, GraphNode] = {}
    edges: dict[str, GraphEdge] = {}
    for row in rows:
        for value in row.values():
            _ingest_graph_value(value, nodes, edges)
    return GraphData(nodes=list(nodes.values()), edges=list(edges.values()))


def _ingest_graph_value(
    value: Any,
    nodes: dict[str, GraphNode],
    edges: dict[str, GraphEdge],
) -> None:
    if isinstance(value, Node):
        node_id = str(value.element_id)
        if node_id not in nodes:
            nodes[node_id] = GraphNode(
                id=node_id,
                labels=sorted(value.labels),
                properties=dict(value),
            )
    elif isinstance(value, Relationship):
        edge_id = str(value.element_id)
        if edge_id not in edges:
            edges[edge_id] = GraphEdge(
                id=edge_id,
                type=value.type,
                source=str(value.start_node.element_id) if value.start_node else "",
                target=str(value.end_node.element_id) if value.end_node else "",
                properties=dict(value),
            )
        if value.start_node is not None:
            _ingest_graph_value(value.start_node, nodes, edges)
        if value.end_node is not None:
            _ingest_graph_value(value.end_node, nodes, edges)
    elif isinstance(value, Path):
        for node in value.nodes:
            _ingest_graph_value(node, nodes, edges)
        for rel in value.relationships:
            _ingest_graph_value(rel, nodes, edges)
    elif isinstance(value, list):
        for item in value:
            _ingest_graph_value(item, nodes, edges)


# --- row serialization -------------------------------------------------------


def _serialize_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Replace Neo4j Node/Relationship/Path objects with JSON-safe
    dicts so the row table can render them. Primitive values pass
    through unchanged."""
    return [{k: _serialize_value(v) for k, v in row.items()} for row in rows]


def _serialize_value(value: Any) -> Any:
    if isinstance(value, Node):
        return {
            "_type": "Node",
            "id": str(value.element_id),
            "labels": sorted(value.labels),
            "properties": dict(value),
        }
    if isinstance(value, Relationship):
        return {
            "_type": "Relationship",
            "id": str(value.element_id),
            "type": value.type,
            "source": str(value.start_node.element_id) if value.start_node else "",
            "target": str(value.end_node.element_id) if value.end_node else "",
            "properties": dict(value),
        }
    if isinstance(value, Path):
        return {
            "_type": "Path",
            "nodes": [_serialize_value(n) for n in value.nodes],
            "relationships": [_serialize_value(r) for r in value.relationships],
        }
    if isinstance(value, list):
        return [_serialize_value(item) for item in value]
    if isinstance(value, dict):
        return {k: _serialize_value(v) for k, v in value.items()}
    return value
