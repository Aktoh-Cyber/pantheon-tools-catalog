"""Integration tests for librarian.{schema,query,upsert_node,upsert_edge}.

One Neo4j testcontainer per session via `neo4j_container` /
`neo4j_clean` in conftest.py. Each test gets a fresh, empty
database (cleanup before + after).

Skipped when Docker is unavailable (auto-skip in conftest).

Run locally:
    pytest -m integration tests/test_librarian_integration.py
"""
from __future__ import annotations

import pytest

from tools.librarian.query import QueryInput, run as run_query
from tools.librarian.schema import SchemaInput, run as run_schema
from tools.librarian.upsert_edge import (
    EdgeEndpoint,
    UpsertEdgeInput,
    run as run_upsert_edge,
)
from tools.librarian.upsert_node import (
    UpsertNodeInput,
    run as run_upsert_node,
)

pytestmark = pytest.mark.integration


# --- schema ----------------------------------------------------------------


async def test_schema_on_empty_db(neo4j_clean) -> None:
    """A fresh DB has no labels / types / properties."""
    resp = await run_schema(SchemaInput())
    assert resp.ok is True
    assert resp.result is not None
    assert resp.result.node_labels == []
    assert resp.result.relationship_types == []
    assert resp.result.property_keys == []


async def test_schema_reflects_writes(neo4j_clean) -> None:
    """After a couple of upserts, the schema reflects them.

    Neo4j's `db.labels()` / `db.propertyKeys()` are
    eventually-consistent procedures. We poll briefly to let the
    label registry catch up before asserting — this is how
    operators using PMC's /graph view would see it too (the
    Schema sidebar refreshes on each session open, not on every
    write)."""
    import asyncio

    await run_upsert_node(
        UpsertNodeInput(
            label="Host",
            merge_keys=["ip"],
            props={"ip": "10.0.0.42", "name": "h-42"},
            commissioned_by="infosec",
            session_id="inv-1",
        )
    )
    await run_upsert_node(
        UpsertNodeInput(
            label="Service",
            merge_keys=["port"],
            props={"port": 443, "name": "https"},
            commissioned_by="infosec",
            session_id="inv-1",
        )
    )

    # Poll the schema until both labels show up (or give up after
    # ~5s — Neo4j's metadata refresh is typically <1s but can lag
    # under load).
    for _ in range(25):
        resp = await run_schema(SchemaInput())
        assert resp.ok is True
        assert resp.result is not None
        if "Host" in resp.result.node_labels and "Service" in resp.result.node_labels:
            break
        await asyncio.sleep(0.2)
    else:  # pragma: no cover — only fires when the registry never updates
        pytest.fail(
            "schema didn't reflect writes within 5s; node_labels="
            + str(resp.result.node_labels)
        )

    assert "Host" in resp.result.node_labels
    assert "Service" in resp.result.node_labels
    # The upserts stamp provenance, so property_keys includes those.
    assert "ip" in resp.result.property_keys
    assert "port" in resp.result.property_keys
    assert "commissioned_by" in resp.result.property_keys


# --- upsert_node -----------------------------------------------------------


async def test_upsert_node_creates_then_idempotent(neo4j_clean) -> None:
    inp = UpsertNodeInput(
        label="Host",
        merge_keys=["ip"],
        props={"ip": "10.0.0.42", "name": "h-42"},
        commissioned_by="infosec",
        session_id="inv-1",
    )
    first = await run_upsert_node(inp)
    assert first.ok is True
    assert first.result is not None
    assert first.result.created is True
    assert "Host" in first.result.labels
    assert first.result.properties["ip"] == "10.0.0.42"
    assert first.result.properties["commissioned_by"] == "infosec"
    assert first.result.properties["session_id"] == "inv-1"
    assert "commissioned_at" in first.result.properties

    second = await run_upsert_node(inp)
    assert second.ok is True
    assert second.result is not None
    assert second.result.created is False
    # Same element_id — matched the existing node, no duplicate.
    assert second.result.element_id == first.result.element_id


async def test_upsert_node_provenance_overlay_on_re_run(neo4j_clean) -> None:
    """Re-running with different commissioned_by overlays — the
    second commission overwrites provenance on the existing node."""
    a = await run_upsert_node(
        UpsertNodeInput(
            label="Host",
            merge_keys=["ip"],
            props={"ip": "10.0.0.42"},
            commissioned_by="infosec",
            session_id="inv-1",
        )
    )
    b = await run_upsert_node(
        UpsertNodeInput(
            label="Host",
            merge_keys=["ip"],
            props={"ip": "10.0.0.42"},
            commissioned_by="scout",
            session_id="sweep-2",
        )
    )
    assert a.result.element_id == b.result.element_id
    assert b.result.properties["commissioned_by"] == "scout"
    assert b.result.properties["session_id"] == "sweep-2"


# --- upsert_edge -----------------------------------------------------------


async def test_upsert_edge_happy_path(neo4j_clean) -> None:
    # Create endpoints first.
    host = await run_upsert_node(
        UpsertNodeInput(
            label="Host",
            merge_keys=["ip"],
            props={"ip": "10.0.0.42"},
            commissioned_by="infosec",
            session_id="inv-1",
        )
    )
    service = await run_upsert_node(
        UpsertNodeInput(
            label="Service",
            merge_keys=["port"],
            props={"port": 443},
            commissioned_by="infosec",
            session_id="inv-1",
        )
    )
    assert host.ok and service.ok

    edge = await run_upsert_edge(
        UpsertEdgeInput(
            rel_type="RUNS",
            **{
                "from": EdgeEndpoint(
                    label="Host",
                    merge_keys=["ip"],
                    match={"ip": "10.0.0.42"},
                ),
            },
            to=EdgeEndpoint(
                label="Service",
                merge_keys=["port"],
                match={"port": 443},
            ),
            props={"since": "2026-06-01"},
            commissioned_by="infosec",
            session_id="inv-1",
        )
    )
    assert edge.ok is True
    assert edge.result is not None
    assert edge.result.created is True
    assert edge.result.type == "RUNS"
    assert edge.result.properties["since"] == "2026-06-01"
    assert edge.result.properties["commissioned_by"] == "infosec"


async def test_upsert_edge_idempotent(neo4j_clean) -> None:
    await run_upsert_node(
        UpsertNodeInput(
            label="Host", merge_keys=["ip"],
            props={"ip": "10.0.0.42"},
            commissioned_by="infosec", session_id="inv-1",
        )
    )
    await run_upsert_node(
        UpsertNodeInput(
            label="Service", merge_keys=["port"],
            props={"port": 443},
            commissioned_by="infosec", session_id="inv-1",
        )
    )

    def _edge_inp():
        return UpsertEdgeInput(
            rel_type="RUNS",
            **{
                "from": EdgeEndpoint(
                    label="Host", merge_keys=["ip"],
                    match={"ip": "10.0.0.42"},
                ),
            },
            to=EdgeEndpoint(
                label="Service", merge_keys=["port"],
                match={"port": 443},
            ),
            props={},
            commissioned_by="infosec", session_id="inv-1",
        )

    first = await run_upsert_edge(_edge_inp())
    second = await run_upsert_edge(_edge_inp())
    assert first.result.created is True
    assert second.result.created is False
    assert first.result.element_id == second.result.element_id

    # Cypher COUNT to assert truly one edge.
    count = await run_query(
        QueryInput(
            cypher="MATCH (:Host)-[r:RUNS]->(:Service) RETURN count(r) AS c",
        )
    )
    assert count.ok is True
    assert count.result.rows[0]["c"] == 1


async def test_upsert_edge_rejects_when_endpoint_missing(
    neo4j_clean,
) -> None:
    """Endpoint nodes don't exist → MERGE on the relationship matches
    nothing and the tool surfaces the endpoint_not_found hint."""
    resp = await run_upsert_edge(
        UpsertEdgeInput(
            rel_type="RUNS",
            **{
                "from": EdgeEndpoint(
                    label="Host", merge_keys=["ip"],
                    match={"ip": "10.0.0.42"},
                ),
            },
            to=EdgeEndpoint(
                label="Service", merge_keys=["port"],
                match={"port": 443},
            ),
            props={},
            commissioned_by="infosec", session_id="inv-1",
        )
    )
    assert resp.ok is False
    assert resp.error is not None
    assert "endpoint" in resp.error.lower()
    assert resp.details is not None
    assert resp.details["hint"] == "endpoint_not_found"


# --- query -----------------------------------------------------------------


async def test_query_returns_rows(neo4j_clean) -> None:
    await run_upsert_node(
        UpsertNodeInput(
            label="Host", merge_keys=["ip"],
            props={"ip": "10.0.0.42", "name": "h-42"},
            commissioned_by="infosec", session_id="inv-1",
        )
    )
    resp = await run_query(
        QueryInput(cypher="MATCH (h:Host) RETURN h.ip AS ip, h.name AS name")
    )
    assert resp.ok is True
    assert resp.result is not None
    assert resp.result.rows == [{"ip": "10.0.0.42", "name": "h-42"}]
    # No graph types in the result → no GraphData projection.
    assert resp.result.graph is None


async def test_query_projects_graph_when_path_returned(neo4j_clean) -> None:
    """When the result contains Node / Relationship / Path values,
    the tool flattens them into a GraphData projection PMC's
    AgentGraph can render."""
    await run_upsert_node(
        UpsertNodeInput(
            label="Host", merge_keys=["ip"],
            props={"ip": "10.0.0.42"},
            commissioned_by="infosec", session_id="inv-1",
        )
    )
    await run_upsert_node(
        UpsertNodeInput(
            label="Service", merge_keys=["port"],
            props={"port": 443},
            commissioned_by="infosec", session_id="inv-1",
        )
    )
    await run_upsert_edge(
        UpsertEdgeInput(
            rel_type="RUNS",
            **{
                "from": EdgeEndpoint(
                    label="Host", merge_keys=["ip"],
                    match={"ip": "10.0.0.42"},
                ),
            },
            to=EdgeEndpoint(
                label="Service", merge_keys=["port"],
                match={"port": 443},
            ),
            props={},
            commissioned_by="infosec", session_id="inv-1",
        )
    )

    resp = await run_query(
        QueryInput(
            cypher="MATCH (h:Host)-[r:RUNS]->(s:Service) RETURN h, r, s"
        )
    )
    assert resp.ok is True
    assert resp.result is not None
    # GraphData populated.
    assert resp.result.graph is not None
    node_labels = sorted(
        l for n in resp.result.graph.nodes for l in n.labels
    )
    assert "Host" in node_labels
    assert "Service" in node_labels
    assert len(resp.result.graph.edges) == 1
    assert resp.result.graph.edges[0].type == "RUNS"


async def test_query_write_rejected_at_tool_layer(neo4j_clean) -> None:
    """Even with a working Neo4j connection, write Cypher is rejected
    at the safety layer before reaching the database."""
    resp = await run_query(
        QueryInput(cypher="MERGE (n:Smuggled) RETURN n")
    )
    assert resp.ok is False
    assert resp.error is not None
    assert "MERGE" in resp.error or "merge" in resp.error.lower()

    # Confirm nothing was written.
    check = await run_query(
        QueryInput(cypher="MATCH (n:Smuggled) RETURN count(n) AS c")
    )
    assert check.ok is True
    assert check.result.rows[0]["c"] == 0
