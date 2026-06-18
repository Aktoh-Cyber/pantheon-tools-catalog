"""Tests for `tools._shared.cypher_safety.assert_read_only`.

Pure-Python tests; no Neo4j needed.
"""
from __future__ import annotations

import pytest

from tools._shared.cypher_safety import (
    CypherWriteRejected,
    assert_read_only,
)


# --- Read queries pass --------------------------------------------------------

READ_OK = [
    "MATCH (n) RETURN n LIMIT 10",
    "MATCH (h:Host)-[:RUNS]->(s:Service) RETURN h.name, s.port",
    "OPTIONAL MATCH (a)-[r]->(b) RETURN a, r, b",
    "MATCH (n) WHERE n.last_verified_at > 0 RETURN count(n)",
    "MATCH (n) WITH n ORDER BY n.last_verified_at DESC LIMIT 1 RETURN n",
    "UNWIND [1,2,3] AS x RETURN x",
    # String-literal containing "create" must NOT trigger rejection.
    'MATCH (n) WHERE n.notes = "this CREATE is fake" RETURN n',
    # Double-quoted string with embedded keyword.
    'RETURN "DELETE FROM dual" AS literal',
]


@pytest.mark.parametrize("cypher", READ_OK)
def test_read_only_passes(cypher: str) -> None:
    assert_read_only(cypher)  # should not raise


# --- Write queries rejected --------------------------------------------------

WRITE_REJECT = [
    ("MERGE (n:X) RETURN n", "MERGE"),
    ("CREATE (n:Test) RETURN n", "CREATE"),
    ("MATCH (n) DELETE n", "DELETE"),
    ("MATCH (n) DETACH DELETE n", "DELETE"),
    ("MATCH (n) SET n.x = 1 RETURN n", "SET"),
    ("MATCH (n) REMOVE n.x RETURN n", "REMOVE"),
    ("DROP INDEX FOR (n:Test) ON (n.x)", "DROP"),
    # Lowercase is rejected.
    ("merge (n:Test) return n", "merge"),
    # Embedded write in a multi-statement chain.
    ("MATCH (n:A) WITH n CREATE (m:B {x: n.x}) RETURN m", "CREATE"),
]


@pytest.mark.parametrize("cypher,keyword", WRITE_REJECT)
def test_write_rejected(cypher: str, keyword: str) -> None:
    with pytest.raises(CypherWriteRejected) as exc:
        assert_read_only(cypher)
    # The detected keyword matches (case-insensitive).
    assert exc.value.keyword.upper() == keyword.upper()
    # The error message points at the AgentService path.
    assert "LibrarianWrite" in str(exc.value)
    assert "SYNAPSE-32" in str(exc.value)


# --- Edge cases --------------------------------------------------------------


def test_empty_cypher_passes() -> None:
    # An empty Cypher will fail in Neo4j parsing; that's fine. The
    # safety layer doesn't care.
    assert_read_only("")


def test_backtick_identifier_still_rejects_writes() -> None:
    # Defense in depth: backtick-quoted identifiers ARE part of
    # legitimate Cypher, but a backtick-quoted "CREATE" used as a
    # property name is rare enough to live with the false positive
    # rather than risk a metaprogramming bypass. If a property
    # really must be named `CREATE`, the operator can use
    # `librarian.upsert_*` instead (with proper Cedar gating).
    with pytest.raises(CypherWriteRejected):
        assert_read_only("MATCH (n) RETURN n.`CREATE` AS literal")
