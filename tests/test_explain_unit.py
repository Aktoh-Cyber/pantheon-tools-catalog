"""Unit tests for `tools.librarian.explain.run`.

The tool fans out to (1) schema fetch via Neo4j and (2) an LLM call.
We mock both: the schema fetch via monkeypatching `_fetch_schema`,
the LLM via the `set_llm_factory` seam.

Integration tests (real Cypher round-trip + a fake-Anthropic
endpoint) go in `test_explain_integration.py` later.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

import tools.librarian.explain as explain_mod
from tools.librarian.explain import (
    ExplainInput,
    reset_llm_factory_for_testing,
    run,
    set_llm_factory,
    _parse_json_or_raise,
)


# --- fixtures ---------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_llm_factory():
    yield
    reset_llm_factory_for_testing()


@pytest.fixture
def stub_schema(monkeypatch: pytest.MonkeyPatch):
    """Replace _fetch_schema with a fake that returns a small fixed
    schema. Tests don't touch Neo4j."""

    async def _fake_fetch():
        return {
            "node_labels": ["Host", "Service"],
            "relationship_types": ["RUNS"],
            "property_keys": ["ip", "name", "port"],
        }

    monkeypatch.setattr(explain_mod, "_fetch_schema", _fake_fetch)


# --- LLM stubs --------------------------------------------------------------


def _stub_llm_returning(payload: dict[str, Any]):
    async def _call(system: str, user: str, output_schema: dict[str, Any]):
        return payload

    def factory():
        return _call

    return factory


# --- happy path -------------------------------------------------------------


async def test_returns_candidate_without_executing(stub_schema):
    """`execute=false` returns the Cypher candidate; doesn't touch Neo4j."""
    set_llm_factory(
        _stub_llm_returning(
            {
                "cypher": "MATCH (h:Host)-[:RUNS]->(s:Service) RETURN h, s",
                "confidence": 0.85,
                "explanation": "joined Host to Service via the RUNS edge",
            }
        )
    )
    resp = await run(ExplainInput(question="what services run on each host?"))
    assert resp.ok is True
    assert resp.result is not None
    assert resp.result.executed is False
    assert resp.result.rows is None
    assert "RUNS" in resp.result.candidate.cypher
    assert resp.result.candidate.confidence == 0.85


async def test_passes_schema_into_user_prompt(stub_schema, monkeypatch):
    """Operator's schema should be reflected in the user prompt so the
    LLM grounds its answer in real labels."""
    captured: dict[str, str] = {}

    async def _capture(system: str, user: str, output_schema: dict[str, Any]):
        captured["system"] = system
        captured["user"] = user
        return {
            "cypher": "MATCH (n) RETURN n LIMIT 1",
            "confidence": 0.5,
            "explanation": "any",
        }

    set_llm_factory(lambda: _capture)

    await run(ExplainInput(question="list everything"))
    assert "Host, Service" in captured["user"]
    assert "RUNS" in captured["user"]
    assert "ip, name, port" in captured["user"]
    assert "JSON only" in captured["user"]
    # System prompt has the hard constraints.
    assert "read-only" in captured["system"].lower()
    assert "MERGE" in captured["system"]


# --- write rejection from LLM output ---------------------------------------


async def test_rejects_write_cypher_from_llm(stub_schema):
    """If the LLM produces a write Cypher despite the system prompt,
    the tool catches it before executing."""
    set_llm_factory(
        _stub_llm_returning(
            {
                "cypher": "MERGE (n:Host {ip: '10.0.0.42'}) RETURN n",
                "confidence": 0.95,
                "explanation": "rogue write candidate",
            }
        )
    )
    resp = await run(
        ExplainInput(question="record 10.0.0.42 as a host", execute=True)
    )
    assert resp.ok is False
    assert resp.error is not None
    assert "MERGE" in resp.error.upper()
    assert resp.details is not None
    assert resp.details["stage"] == "safety"
    assert resp.details["rejected_keyword"].upper() == "MERGE"
    # Candidate is surfaced so PMC can show what the LLM tried.
    assert "MERGE" in resp.details["candidate_cypher"]


# --- LLM failures bubble cleanly -------------------------------------------


async def test_llm_failure_returns_structured_error(stub_schema):
    """Network / API failure becomes `ok: false` with details."""

    async def _explode(system: str, user: str, output_schema: dict[str, Any]):
        raise RuntimeError("anthropic API 500")

    set_llm_factory(lambda: _explode)

    resp = await run(ExplainInput(question="anything"))
    assert resp.ok is False
    assert resp.error is not None
    assert "RuntimeError" in resp.error
    assert "anthropic API 500" in resp.error
    assert resp.details is not None
    assert resp.details["stage"] == "llm"


# --- schema fetch failures bubble cleanly ----------------------------------


async def test_schema_fetch_failure_returns_structured_error(monkeypatch):
    """If Neo4j is unreachable, we fail at the schema stage with a
    clear error — don't even attempt the LLM call."""

    async def _broken_fetch():
        raise ConnectionError("Neo4j down")

    monkeypatch.setattr(explain_mod, "_fetch_schema", _broken_fetch)

    resp = await run(ExplainInput(question="any"))
    assert resp.ok is False
    assert resp.error is not None
    assert "Neo4j down" in resp.error
    assert resp.details is not None
    assert resp.details["stage"] == "schema"


# --- low-confidence pass-through -------------------------------------------


async def test_low_confidence_still_returns_candidate(stub_schema):
    """A confidence=0.0 candidate is still a legitimate response (the
    LLM is signalling 'I can't answer with this schema')."""
    set_llm_factory(
        _stub_llm_returning(
            {
                "cypher": "MATCH (n) RETURN 0 LIMIT 0",
                "confidence": 0.0,
                "explanation": "schema doesn't include vendor info",
            }
        )
    )
    resp = await run(
        ExplainInput(question="which vendor owns 10.0.0.42?")
    )
    assert resp.ok is True
    assert resp.result is not None
    assert resp.result.candidate.confidence == 0.0


# --- JSON parsing helpers --------------------------------------------------


def test_parse_json_bare_object():
    assert _parse_json_or_raise('{"a": 1}') == {"a": 1}


def test_parse_json_stripped_whitespace():
    assert _parse_json_or_raise('   {"a": 1}\n  ') == {"a": 1}


def test_parse_json_with_fenced_block():
    text = '```json\n{"a": 1, "b": [2, 3]}\n```'
    assert _parse_json_or_raise(text) == {"a": 1, "b": [2, 3]}


def test_parse_json_with_unlabeled_fence():
    text = '```\n{"a": 1}\n```'
    assert _parse_json_or_raise(text) == {"a": 1}


def test_parse_json_raises_on_garbage():
    with pytest.raises(json.JSONDecodeError):
        _parse_json_or_raise("not json")
