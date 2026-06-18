"""Unit tests for the two librarian upsert tools.

Cover the Cypher composition + input validation + reserved-key
rejection. Real Neo4j round-trip happens in `test_upsert_integration.py`
(testcontainers).
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from tools._shared.provenance import (
    RESERVED_PROVENANCE_KEYS,
    ReservedKeyConflict,
    assert_no_reserved_keys,
)
from tools.librarian.upsert_edge import (
    EdgeEndpoint,
    UpsertEdgeInput,
    _build_cypher as _build_edge_cypher,
)
from tools.librarian.upsert_edge import run as run_edge
from tools.librarian.upsert_node import (
    UpsertNodeInput,
    _build_cypher as _build_node_cypher,
)
from tools.librarian.upsert_node import run as run_node


# ---------------------------------------------------------------------------
# Shared provenance helper
# ---------------------------------------------------------------------------


def test_reserved_provenance_keys_set():
    assert RESERVED_PROVENANCE_KEYS == {
        "commissioned_by",
        "commissioned_at",
        "session_id",
    }


def test_assert_no_reserved_keys_passes_on_clean_props():
    assert_no_reserved_keys({"ip": "10.0.0.42", "name": "h-42"})


@pytest.mark.parametrize(
    "key", sorted(RESERVED_PROVENANCE_KEYS)
)
def test_assert_no_reserved_keys_rejects(key: str):
    with pytest.raises(ReservedKeyConflict) as exc:
        assert_no_reserved_keys({key: "anything"})
    assert exc.value.key == key
    assert key in str(exc.value)


# ---------------------------------------------------------------------------
# upsert_node — Cypher composition
# ---------------------------------------------------------------------------


def _node_input(**overrides):
    base = dict(
        label="Host",
        merge_keys=["ip"],
        props={"ip": "10.0.0.42", "name": "h-42"},
        commissioned_by="infosec",
        session_id="inv-1",
    )
    base.update(overrides)
    return UpsertNodeInput(**base)


def test_node_cypher_uses_label_inline():
    cypher, _ = _build_node_cypher(_node_input(label="Host"))
    assert "MERGE (n:Host {" in cypher
    assert "RETURN n" in cypher


def test_node_cypher_binds_merge_key():
    cypher, params = _build_node_cypher(
        _node_input(merge_keys=["ip"], props={"ip": "10.0.0.42"})
    )
    assert "ip: $merge_ip" in cypher
    assert params["merge_ip"] == "10.0.0.42"


def test_node_cypher_multiple_merge_keys():
    cypher, params = _build_node_cypher(
        _node_input(
            merge_keys=["ip", "tenant_id"],
            props={"ip": "10.0.0.42", "tenant_id": "aktoh", "extra": "x"},
        )
    )
    assert "ip: $merge_ip" in cypher
    assert "tenant_id: $merge_tenant_id" in cypher
    assert params["merge_ip"] == "10.0.0.42"
    assert params["merge_tenant_id"] == "aktoh"
    # set_props carries the full bag — Neo4j's `+=` overlays.
    assert params["set_props"] == {
        "ip": "10.0.0.42",
        "tenant_id": "aktoh",
        "extra": "x",
    }


def test_node_cypher_provenance_stamps():
    cypher, params = _build_node_cypher(
        _node_input(commissioned_by="infosec", session_id="inv-123")
    )
    assert "n.commissioned_by = $commissioned_by" in cypher
    assert "n.commissioned_at = datetime()" in cypher
    assert "n.session_id = $session_id" in cypher
    assert params["commissioned_by"] == "infosec"
    assert params["session_id"] == "inv-123"


# ---------------------------------------------------------------------------
# upsert_node — input validation
# ---------------------------------------------------------------------------


def test_node_rejects_non_identifier_label():
    with pytest.raises(ValidationError):
        UpsertNodeInput(
            label="Host-Bad",
            merge_keys=["ip"],
            props={"ip": "x"},
            commissioned_by="infosec",
            session_id="inv-1",
        )


def test_node_rejects_label_starting_with_digit():
    with pytest.raises(ValidationError):
        UpsertNodeInput(
            label="9Bad",
            merge_keys=["ip"],
            props={"ip": "x"},
            commissioned_by="infosec",
            session_id="inv-1",
        )


def test_node_requires_non_empty_merge_keys():
    with pytest.raises(ValidationError):
        UpsertNodeInput(
            label="Host",
            merge_keys=[],
            props={"ip": "x"},
            commissioned_by="infosec",
            session_id="inv-1",
        )


def test_node_underscore_label_ok():
    inp = UpsertNodeInput(
        label="Host_Old",
        merge_keys=["ip"],
        props={"ip": "x"},
        commissioned_by="infosec",
        session_id="inv-1",
    )
    assert inp.label == "Host_Old"


# ---------------------------------------------------------------------------
# upsert_node — run() error paths (no Neo4j needed)
# ---------------------------------------------------------------------------


async def test_node_run_rejects_missing_merge_key():
    inp = _node_input(
        merge_keys=["ip", "tenant_id"],
        props={"ip": "10.0.0.42"},  # tenant_id missing
    )
    resp = await run_node(inp)
    assert resp.ok is False
    assert resp.error is not None
    assert "tenant_id" in resp.error
    assert resp.details is not None
    assert resp.details["missing_merge_keys"] == ["tenant_id"]


async def test_node_run_rejects_reserved_provenance_in_props():
    inp = _node_input(
        props={
            "ip": "10.0.0.42",
            "commissioned_by": "smuggled-value",
        }
    )
    resp = await run_node(inp)
    assert resp.ok is False
    assert resp.error is not None
    assert "commissioned_by" in resp.error
    assert resp.details is not None
    assert resp.details["conflicting_key"] == "commissioned_by"


# ---------------------------------------------------------------------------
# upsert_edge — Cypher composition
# ---------------------------------------------------------------------------


def _edge_input(**overrides):
    base = dict(
        rel_type="RUNS",
        props={"since": "2026-06-01"},
        commissioned_by="infosec",
        session_id="inv-1",
    )
    base.setdefault(
        "from",
        EdgeEndpoint(
            label="Host", merge_keys=["ip"], match={"ip": "10.0.0.42"}
        ),
    )
    base.setdefault(
        "to",
        EdgeEndpoint(
            label="Service", merge_keys=["port"], match={"port": 443}
        ),
    )
    base.update(overrides)
    return UpsertEdgeInput(**base)


def test_edge_cypher_matches_endpoints_then_merges_rel():
    cypher, _ = _build_edge_cypher(_edge_input())
    # Both endpoints come from MATCH (not MERGE) — edge tool doesn't
    # create endpoint nodes.
    assert "MATCH (a:Host {" in cypher
    assert "(b:Service {" in cypher
    assert "MERGE (a)-[r:RUNS]->(b)" in cypher
    assert "RETURN r" in cypher


def test_edge_cypher_namespaces_endpoint_params():
    cypher, params = _build_edge_cypher(
        _edge_input(
            **{
                "from": EdgeEndpoint(
                    label="Host", merge_keys=["ip"],
                    match={"ip": "10.0.0.42"},
                ),
                "to": EdgeEndpoint(
                    label="Service", merge_keys=["port"],
                    match={"port": 443},
                ),
            }
        )
    )
    # Endpoint params are prefixed so a property named the same on
    # both sides doesn't collide.
    assert "ip: $from_ip" in cypher
    assert "port: $to_port" in cypher
    assert params["from_ip"] == "10.0.0.42"
    assert params["to_port"] == 443


def test_edge_cypher_provenance_stamps_relationship():
    cypher, params = _build_edge_cypher(
        _edge_input(commissioned_by="scout", session_id="sweep-7")
    )
    assert "r.commissioned_by = $commissioned_by" in cypher
    assert "r.commissioned_at = datetime()" in cypher
    assert "r.session_id = $session_id" in cypher
    assert params["commissioned_by"] == "scout"
    assert params["session_id"] == "sweep-7"


# ---------------------------------------------------------------------------
# upsert_edge — input validation
# ---------------------------------------------------------------------------


def test_edge_rejects_non_identifier_rel_type():
    with pytest.raises(ValidationError):
        UpsertEdgeInput(
            rel_type="RUNS-LIKE",
            **{
                "from": EdgeEndpoint(
                    label="Host", merge_keys=["ip"], match={"ip": "x"},
                ),
            },
            to=EdgeEndpoint(
                label="Service", merge_keys=["port"], match={"port": 1}
            ),
            props={},
            commissioned_by="infosec",
            session_id="inv-1",
        )


def test_edge_rejects_non_identifier_endpoint_label():
    with pytest.raises(ValidationError):
        EdgeEndpoint(label="Host Bad", merge_keys=["ip"], match={})


# ---------------------------------------------------------------------------
# upsert_edge — run() error paths
# ---------------------------------------------------------------------------


async def test_edge_run_rejects_missing_from_merge_key():
    inp = _edge_input(
        **{
            "from": EdgeEndpoint(
                label="Host",
                merge_keys=["ip", "tenant_id"],
                match={"ip": "10.0.0.42"},  # tenant_id missing
            ),
        }
    )
    resp = await run_edge(inp)
    assert resp.ok is False
    assert resp.error is not None
    assert "tenant_id" in resp.error
    assert resp.details is not None
    assert resp.details["missing_from_merge_keys"] == ["tenant_id"]
    assert resp.details["missing_to_merge_keys"] == []


async def test_edge_run_rejects_missing_to_merge_key():
    inp = _edge_input(
        to=EdgeEndpoint(
            label="Service",
            merge_keys=["port", "host"],
            match={"port": 443},  # host missing
        )
    )
    resp = await run_edge(inp)
    assert resp.ok is False
    assert resp.error is not None
    assert "host" in resp.error
    assert resp.details is not None
    assert resp.details["missing_to_merge_keys"] == ["host"]


async def test_edge_run_rejects_reserved_provenance_in_props():
    inp = _edge_input(props={"session_id": "rogue-session"})
    resp = await run_edge(inp)
    assert resp.ok is False
    assert resp.error is not None
    assert "session_id" in resp.error
    assert resp.details is not None
    assert resp.details["conflicting_key"] == "session_id"
