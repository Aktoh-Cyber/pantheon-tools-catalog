"""Unit tests for `librarian.purge_session`.

Covers input validation (session_id rejection rules + confirm gating)
and the response shape on the confirm=False path. Real Neo4j round-
trip (deleted_count + relationships_deleted) is exercised in
`test_librarian_integration.py` against the shared testcontainer.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from tools.librarian.purge_session import (
    PurgeSessionInput,
    PurgeSessionToolResponse,
    run,
)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_input_rejects_empty_session_id():
    with pytest.raises(ValidationError):
        PurgeSessionInput(
            session_id="",
            commissioned_by="@infosec-aktoh",
        )


def test_input_rejects_whitespace_only_session_id():
    with pytest.raises(ValidationError) as exc:
        PurgeSessionInput(
            session_id="   ",
            commissioned_by="@infosec-aktoh",
        )
    # The string-length validator fires before our strip validator
    # for a fully-whitespace string. We accept either gate; only the
    # field-validator path strips, so check that gate too explicitly.
    assert "session_id" in str(exc.value)


def test_input_rejects_wildcard_session_id():
    with pytest.raises(ValidationError) as exc:
        PurgeSessionInput(
            session_id="*",
            commissioned_by="@infosec-aktoh",
        )
    assert "wildcard" in str(exc.value).lower() or "*" in str(exc.value)


def test_input_rejects_missing_commissioned_by():
    with pytest.raises(ValidationError):
        PurgeSessionInput(session_id="sess-abc")  # type: ignore[call-arg]


def test_input_defaults_confirm_to_false():
    inp = PurgeSessionInput(
        session_id="sess-abc",
        commissioned_by="@infosec-aktoh",
    )
    assert inp.confirm is False


def test_input_accepts_normal_session_id():
    inp = PurgeSessionInput(
        session_id="sess-0123",
        commissioned_by="@infosec-aktoh",
        confirm=True,
    )
    assert inp.session_id == "sess-0123"
    assert inp.confirm is True


# ---------------------------------------------------------------------------
# Confirm gating — confirm=False must NOT touch Neo4j
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_rejects_confirm_false_without_neo4j_call(monkeypatch):
    """confirm=False must short-circuit BEFORE driver is touched.

    We monkeypatch get_driver to a sentinel that would explode if
    called, then call run with confirm=False. The response must be
    ok=False with a hint, and our sentinel must remain unfired.
    """
    called = {"driver": False}

    def boom():
        called["driver"] = True
        raise RuntimeError("driver should NOT have been touched on confirm=False")

    monkeypatch.setattr("tools.librarian.purge_session.get_driver", boom)

    inp = PurgeSessionInput(
        session_id="sess-abc",
        commissioned_by="@infosec-aktoh",
        confirm=False,
    )
    resp = await run(inp)

    assert isinstance(resp, PurgeSessionToolResponse)
    assert resp.ok is False
    assert resp.result is None
    assert resp.error is not None
    assert "confirm" in resp.error.lower()
    assert resp.details is not None
    assert resp.details.get("session_id") == "sess-abc"
    assert "hint" in resp.details
    # Sentinel must remain unfired.
    assert called["driver"] is False
