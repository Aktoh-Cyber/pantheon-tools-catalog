"""Unit tests for the librarian write journal + librarian.apply_pending.

Regression (2026-09-28, tenant aktoh): the librarian's write tools were not
connected, the librarian told the operator a sweep was "staged in a pending
file" that never existed, and PMC's graph tab said "Nothing is wrong". The
journal is how the write path now reports on itself: store failures are kept
(never lost to a chat transcript) and surfaced as pending / failing.

The graph store is faked at the driver seam (`get_driver`), so these run
without Docker.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools._shared import write_journal
from tools.librarian import apply_pending, purge_session, upsert_edge, upsert_node

# --------------------------------------------------------------------------
# Fake driver
# --------------------------------------------------------------------------


class _Counters:
    nodes_created = 1
    relationships_created = 1
    nodes_deleted = 2
    relationships_deleted = 3


class _Summary:
    counters = _Counters()


class _Node(dict[str, Any]):
    element_id = "4:x:1"
    labels = frozenset({"Host"})


class _Rel(dict[str, Any]):
    element_id = "5:x:1"
    type = "RUNS"
    start_node = _Node()
    end_node = _Node()


class _Result:
    def __init__(self, record: dict[str, Any] | None) -> None:
        self._record = record

    async def single(self) -> dict[str, Any] | None:
        return self._record

    async def consume(self) -> _Summary:
        return _Summary()


class _Session:
    def __init__(self, store: _Store) -> None:
        self._store = store

    async def __aenter__(self) -> _Session:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def run(self, cypher: str, params: dict[str, Any]) -> _Result:
        self._store.calls.append(cypher)
        if self._store.down:
            raise ConnectionError("graph store unreachable")
        if cypher.startswith("MERGE (n:"):
            return _Result({"n": _Node(name="h")})
        if "MERGE (a)-[r:" in cypher:
            return _Result(None if self._store.no_endpoints else {"r": _Rel()})
        return _Result(None)


class _Store:
    def __init__(self) -> None:
        self.down = False
        self.no_endpoints = False
        self.calls: list[str] = []

    def session(self) -> _Session:
        return _Session(self)


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> _Store:
    s = _Store()
    for mod in (upsert_node, upsert_edge, purge_session):
        monkeypatch.setattr(mod, "get_driver", lambda: s)
    return s


@pytest.fixture
def state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv(write_journal.STATE_DIR_ENV, str(tmp_path))
    return tmp_path


def _node(**over: Any) -> upsert_node.UpsertNodeInput:
    base: dict[str, Any] = {
        "label": "Host",
        "merge_keys": ["node_id"],
        "props": {"node_id": "n-1", "name": "tek.local"},
        "commissioned_by": "infosec",
        "session_id": "sweep_2026-09-28T2114Z",
    }
    base.update(over)
    return upsert_node.UpsertNodeInput(**base)


def _edge() -> upsert_edge.UpsertEdgeInput:
    return upsert_edge.UpsertEdgeInput.model_validate(
        {
            "rel_type": "HAS_FINDING",
            "from": {
                "label": "Host",
                "merge_keys": ["node_id"],
                "match": {"node_id": "n-1"},
            },
            "to": {
                "label": "Finding",
                "merge_keys": ["key"],
                "match": {"key": "f-1"},
            },
            "commissioned_by": "infosec",
            "session_id": "sweep_2026-09-28T2114Z",
        }
    )


def _status(state: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((state / write_journal.STATUS_FILE).read_text())
    return data


# --------------------------------------------------------------------------
# Journal off: behaviour unchanged
# --------------------------------------------------------------------------


async def test_no_state_dir_means_no_files(
    store: _Store, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(write_journal.STATE_DIR_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    store.down = True
    resp = await upsert_node.run(_node())
    assert resp.ok is False
    assert resp.details is not None and "pending_id" not in resp.details
    assert list(tmp_path.iterdir()) == []


# --------------------------------------------------------------------------
# Store failure is kept, success clears it
# --------------------------------------------------------------------------


async def test_store_failure_is_journaled_and_reported_not_recorded(
    store: _Store, state: Path
) -> None:
    store.down = True
    resp = await upsert_node.run(_node())
    assert resp.ok is False
    assert resp.details is not None
    assert resp.details["recorded"] is False
    pid = resp.details["pending_id"]
    entry = json.loads((state / "pending" / f"{pid}.json").read_text())
    assert entry["tool"] == "librarian.upsert_node"
    assert entry["input"]["props"]["name"] == "tek.local"
    assert entry["attempts"] == 1
    st = _status(state)
    assert st["consecutive_failures"] == 1
    assert "unreachable" in st["last_error"]


async def test_repeat_failure_updates_same_entry(store: _Store, state: Path) -> None:
    store.down = True
    await upsert_node.run(_node())
    await upsert_node.run(_node())
    files = list((state / "pending").glob("*.json"))
    assert len(files) == 1
    assert json.loads(files[0].read_text())["attempts"] == 2
    assert _status(state)["consecutive_failures"] == 2


async def test_success_clears_matching_pending_and_resets_streak(
    store: _Store, state: Path
) -> None:
    store.down = True
    await upsert_node.run(_node())
    store.down = False
    resp = await upsert_node.run(_node())
    assert resp.ok is True
    assert list((state / "pending").glob("*.json")) == []
    st = _status(state)
    assert st["consecutive_failures"] == 0
    assert st["last_ok_tool"] == "librarian.upsert_node"


async def test_missing_endpoint_is_callers_problem_not_pending(
    store: _Store, state: Path
) -> None:
    store.no_endpoints = True
    resp = await upsert_edge.run(_edge())
    assert resp.ok is False
    assert resp.details is not None
    assert resp.details["hint"] == "endpoint_not_found"
    assert not (state / "pending").exists()
    assert not (state / write_journal.STATUS_FILE).exists()


async def test_validation_errors_are_not_journaled(store: _Store, state: Path) -> None:
    resp = await upsert_node.run(_node(merge_keys=["missing"]))
    assert resp.ok is False
    assert not (state / "pending").exists()
    assert store.calls == []


async def test_edge_and_purge_store_failures_are_journaled(
    store: _Store, state: Path
) -> None:
    store.down = True
    e = await upsert_edge.run(_edge())
    p = await purge_session.run(
        purge_session.PurgeSessionInput(
            session_id="sweep_2026-09-28T2114Z", commissioned_by="infosec", confirm=True
        )
    )
    assert e.ok is False and p.ok is False
    tools = sorted(
        json.loads(f.read_text())["tool"] for f in (state / "pending").glob("*.json")
    )
    assert tools == ["librarian.purge_session", "librarian.upsert_edge"]
    # Edge payload keeps the wire alias so a replay validates.
    edge_entry = next(
        json.loads(f.read_text())
        for f in (state / "pending").glob("upsert_edge-*.json")
    )
    assert "from" in edge_entry["input"]


# --------------------------------------------------------------------------
# apply_pending
# --------------------------------------------------------------------------


async def test_apply_pending_lists_without_touching_graph(
    store: _Store, state: Path
) -> None:
    store.down = True
    await upsert_node.run(_node())
    calls_before = len(store.calls)
    resp = await apply_pending.run(apply_pending.ApplyPendingInput(confirm=False))
    assert resp.ok is True and resp.result is not None
    assert resp.result.pending_before == 1
    assert resp.result.remaining == 1
    assert resp.result.items[0].tool == "librarian.upsert_node"
    assert resp.result.items[0].applied is None
    assert len(store.calls) == calls_before


async def test_apply_pending_replays_and_clears(store: _Store, state: Path) -> None:
    store.down = True
    await upsert_node.run(_node())
    await upsert_edge.run(_edge())
    store.down = False
    resp = await apply_pending.run(apply_pending.ApplyPendingInput(confirm=True))
    assert resp.ok is True and resp.result is not None
    assert resp.result.applied == 2
    assert resp.result.remaining == 0
    assert _status(state)["consecutive_failures"] == 0


async def test_apply_pending_keeps_what_still_fails(store: _Store, state: Path) -> None:
    store.down = True
    await upsert_node.run(_node())
    resp = await apply_pending.run(apply_pending.ApplyPendingInput(confirm=True))
    assert resp.ok is False and resp.result is not None
    assert resp.result.still_failing == 1
    assert resp.result.remaining == 1
    entry = next((state / "pending").glob("*.json"))
    assert json.loads(entry.read_text())["attempts"] == 2


async def test_apply_pending_with_journaling_off(
    store: _Store, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(write_journal.STATE_DIR_ENV, raising=False)
    resp = await apply_pending.run(apply_pending.ApplyPendingInput(confirm=True))
    assert resp.ok is True and resp.result is not None
    assert resp.result.journaling is False


def test_server_start_marker(state: Path) -> None:
    write_journal.mark_server_started("0.2.3")
    data = json.loads((state / write_journal.SERVER_FILE).read_text())
    assert data["version"] == "0.2.3"
    assert isinstance(data["pid"], int)


def test_apply_pending_is_registered_on_the_mcp_server() -> None:
    from tools.librarian.__main__ import _TOOLS

    assert "librarian.apply_pending" in _TOOLS
    assert {
        "librarian.upsert_node",
        "librarian.upsert_edge",
        "librarian.purge_session",
    } <= set(_TOOLS)
