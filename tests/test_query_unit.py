"""Unit tests for `tools.librarian.query.run`.

Pure unit-level: write rejection + row serialization + graph
projection helpers. Integration tests (real Cypher round-trip
through testcontainers) live in `test_query_integration.py` and
are skipped unless Docker is available.
"""
from __future__ import annotations

from typing import Any

import pytest

from tools.librarian.query import (
    QueryInput,
    _ingest_graph_value,
    _project_graph,
    _rows_contain_graph,
    _serialize_value,
    run,
)


# --- write rejection ---------------------------------------------------------


@pytest.mark.parametrize(
    "cypher,expected_keyword",
    [
        ("MERGE (n:X) RETURN n", "MERGE"),
        ("CREATE (n:Test) RETURN n", "CREATE"),
        ("MATCH (n) DELETE n", "DELETE"),
        ("MATCH (n) SET n.x = 1", "SET"),
    ],
)
async def test_run_rejects_write_cypher(
    cypher: str, expected_keyword: str
) -> None:
    """The tool must reject writes BEFORE touching Neo4j."""
    resp = await run(QueryInput(cypher=cypher))
    assert resp.ok is False
    assert resp.error is not None
    assert "rejected" in resp.error.lower()
    assert resp.details is not None
    assert resp.details["rejected_keyword"].upper() == expected_keyword
    assert resp.details["tool"] == "librarian.query"
    assert resp.details["cypher"] == cypher


async def test_run_rejects_lowercase_write() -> None:
    """Case-insensitive rejection — `merge` is the same as `MERGE`."""
    resp = await run(QueryInput(cypher="merge (n:X) return n"))
    assert resp.ok is False
    assert resp.details is not None
    assert resp.details["rejected_keyword"].upper() == "MERGE"


# --- serialization helpers ---------------------------------------------------


def test_serialize_primitive_passes_through() -> None:
    assert _serialize_value(42) == 42
    assert _serialize_value("hello") == "hello"
    assert _serialize_value(None) is None


def test_serialize_dict_recurses() -> None:
    assert _serialize_value({"a": 1, "b": "x"}) == {"a": 1, "b": "x"}
    # Nested
    assert _serialize_value({"a": {"b": 2}}) == {"a": {"b": 2}}


def test_serialize_list_recurses() -> None:
    assert _serialize_value([1, "x", None]) == [1, "x", None]


# --- graph projection on fake Node/Relationship objects ---------------------


class _FakeNode:
    """Stand-in for neo4j.graph.Node — same duck-typed surface the
    tool reads (labels, element_id, mapping-like). Lets us test the
    projection logic without spinning up Neo4j."""

    def __init__(
        self, element_id: str, labels: list[str], props: dict[str, Any]
    ) -> None:
        self.element_id = element_id
        self.labels = set(labels)
        self._props = props

    def __iter__(self):
        return iter(self._props)

    def __getitem__(self, key: str) -> Any:
        return self._props[key]

    def keys(self):
        return self._props.keys()

    def values(self):
        return self._props.values()

    def items(self):
        return self._props.items()


class _FakeRel:
    def __init__(
        self,
        element_id: str,
        rel_type: str,
        start: _FakeNode,
        end: _FakeNode,
        props: dict[str, Any],
    ) -> None:
        self.element_id = element_id
        self.type = rel_type
        self.start_node = start
        self.end_node = end
        self._props = props

    def __iter__(self):
        return iter(self._props)

    def __getitem__(self, key: str) -> Any:
        return self._props[key]

    def keys(self):
        return self._props.keys()

    def values(self):
        return self._props.values()

    def items(self):
        return self._props.items()


def _isinstance_patch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make _FakeNode register as a Node and _FakeRel as a
    Relationship for the duration of the test. We patch the
    isinstance check by replacing the neo4j.graph types the tool
    imports with our fakes."""
    import tools.librarian.query as q

    monkeypatch.setattr(q, "Node", _FakeNode)
    monkeypatch.setattr(q, "Relationship", _FakeRel)
    # Path stays the real one — we don't construct Paths in these tests.


def test_rows_contain_graph_detects_node(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isinstance_patch(monkeypatch)
    rows: list[dict[str, Any]] = [
        {"n": _FakeNode("1", ["Host"], {"ip": "10.0.0.42"})},
    ]
    assert _rows_contain_graph(rows) is True


def test_rows_contain_graph_detects_in_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isinstance_patch(monkeypatch)
    rows: list[dict[str, Any]] = [
        {"items": [_FakeNode("1", ["Host"], {"ip": "10.0.0.42"})]},
    ]
    assert _rows_contain_graph(rows) is True


def test_rows_contain_graph_pure_scalars_returns_false() -> None:
    rows: list[dict[str, Any]] = [
        {"count": 42, "name": "aktoh"},
        {"count": 7, "name": "acmeinc"},
    ]
    assert _rows_contain_graph(rows) is False


def test_project_graph_dedupes_nodes_and_edges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isinstance_patch(monkeypatch)
    n1 = _FakeNode("n1", ["Host"], {"ip": "10.0.0.42"})
    n2 = _FakeNode("n2", ["Service"], {"port": 443})
    r = _FakeRel("r1", "RUNS", n1, n2, {"since": "2026-06-01"})
    # Same node appears in multiple rows.
    rows: list[dict[str, Any]] = [
        {"h": n1, "r": r, "s": n2},
        {"h": n1},  # duplicate
    ]
    graph = _project_graph(rows)
    assert len(graph.nodes) == 2  # deduped
    assert len(graph.edges) == 1
    node_ids = sorted(n.id for n in graph.nodes)
    assert node_ids == ["n1", "n2"]
    assert graph.edges[0].type == "RUNS"
    assert graph.edges[0].source == "n1"
    assert graph.edges[0].target == "n2"


def test_ingest_graph_value_handles_nested_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isinstance_patch(monkeypatch)
    n = _FakeNode("n1", ["Host"], {})
    nodes: dict[str, Any] = {}
    edges: dict[str, Any] = {}
    _ingest_graph_value([n, [n, n]], nodes, edges)
    assert "n1" in nodes
    assert len(nodes) == 1
