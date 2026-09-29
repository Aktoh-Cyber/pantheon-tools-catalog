"""Write-outcome journal for the librarian's graph write tools.

Why this exists (2026-09-28, tenant aktoh): PMC's Knowledge -> Graph tab
said "Your knowledge graph is empty ... Nothing is wrong" while the
librarian could not write at all. Its write tools were never connected in
the running agent. The librarian told the operator it had "staged the
commission in a pending file" that was never actually written; the data
survived only inside a chat transcript. Nothing in the write path reported
on itself, so the UI could not tell "nothing recorded yet" apart from
"recording is broken".

Every write tool now records its outcome here. A STORE-level failure also
keeps the commission, so it can be re-applied later
(``librarian.apply_pending``) instead of being lost:

    $LIBRARIAN_STATE_DIR/server.json           written when the MCP server starts
    $LIBRARIAN_STATE_DIR/write-status.json     last ok / last error / failure streak
    $LIBRARIAN_STATE_DIR/pending/<tool>-<sha>.json   one failed commission each

The tenant sidecar reads these files (read-only) and reports them to PMC.
If ``LIBRARIAN_STATE_DIR`` is unset, journaling is off (tests, local runs)
and the tools behave exactly as before.

Only store failures are journaled: driver/connection errors, or a MERGE that
returns nothing. Input validation, reserved-key conflicts, and edge endpoints
that don't exist go back to the caller to fix. They are never queued and do
not count as the store failing.

The journal is best-effort. A journal I/O error is logged to stderr and never
replaces the tool's own result: the caller must always see the real outcome.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger("librarian-journal")

STATE_DIR_ENV = "LIBRARIAN_STATE_DIR"
STATUS_FILE = "write-status.json"
SERVER_FILE = "server.json"
PENDING_DIR = "pending"
SCHEMA_VERSION = 1
_MAX_ERROR_CHARS = 500

_lock = threading.Lock()


def state_dir() -> Path | None:
    raw = os.environ.get(STATE_DIR_ENV, "").strip()
    return Path(raw) if raw else None


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, sort_keys=True, default=str)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def commission_key(tool: str, payload: dict[str, Any]) -> str:
    """Stable identity of one commission: the same tool + the same input
    always maps to the same pending file, so a retry that fails again
    updates the entry instead of piling up duplicates, and a retry that
    succeeds clears it."""
    canonical = json.dumps(
        {"tool": tool, "input": payload}, sort_keys=True, default=str
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    safe_tool = tool.replace("librarian.", "").replace(".", "_")
    return f"{safe_tool}-{digest}"


def _update_status(sd: Path, *, ok: bool, tool: str, error: str | None) -> None:
    path = sd / STATUS_FILE
    st = _read_json(path)
    now = _now()
    st["schema"] = SCHEMA_VERSION
    st["updated_at"] = now
    if ok:
        st["last_ok_at"] = now
        st["last_ok_tool"] = tool
        st["consecutive_failures"] = 0
        st["ok_total"] = int(st.get("ok_total") or 0) + 1
    else:
        st["last_error_at"] = now
        st["last_error_tool"] = tool
        st["last_error"] = (error or "")[:_MAX_ERROR_CHARS]
        st["consecutive_failures"] = int(st.get("consecutive_failures") or 0) + 1
        st["failed_total"] = int(st.get("failed_total") or 0) + 1
    _atomic_write_json(path, st)


def record_success(tool: str, payload: dict[str, Any]) -> None:
    """The store accepted a write. Resets the failure streak and clears
    any pending entry for this exact commission."""
    sd = state_dir()
    if sd is None:
        return
    try:
        with _lock:
            _update_status(sd, ok=True, tool=tool, error=None)
            pending = sd / PENDING_DIR / f"{commission_key(tool, payload)}.json"
            if pending.exists():
                pending.unlink()
    except OSError as exc:
        log.warning("write journal: could not record success for %s: %s", tool, exc)


def record_failure(tool: str, error: str, payload: dict[str, Any]) -> str | None:
    """The store rejected or could not take a write. Returns the pending
    entry's name (the commission is kept for librarian.apply_pending),
    or None when journaling is off or the entry could not be saved."""
    sd = state_dir()
    if sd is None:
        return None
    key = commission_key(tool, payload)
    try:
        with _lock:
            _update_status(sd, ok=False, tool=tool, error=error)
            path = sd / PENDING_DIR / f"{key}.json"
            prior = _read_json(path)
            _atomic_write_json(
                path,
                {
                    "schema": SCHEMA_VERSION,
                    "tool": tool,
                    "input": payload,
                    "first_failed_at": prior.get("first_failed_at") or _now(),
                    "last_failed_at": _now(),
                    "attempts": int(prior.get("attempts") or 0) + 1,
                    "last_error": error[:_MAX_ERROR_CHARS],
                },
            )
        return key
    except OSError as exc:
        log.warning("write journal: could not record failure for %s: %s", tool, exc)
        return None


def pending_entries() -> list[Path]:
    sd = state_dir()
    if sd is None:
        return []
    pdir = sd / PENDING_DIR
    try:
        return sorted(p for p in pdir.glob("*.json") if p.is_file())
    except OSError:
        return []


def load_entry(path: Path) -> dict[str, Any]:
    return _read_json(path)


def mark_server_started(version: str) -> None:
    """Written once when the MCP server process starts, i.e. when the
    agent runtime actually connected it. The sidecar checks the pid is
    alive to tell "connected" apart from "configured but never started"."""
    sd = state_dir()
    if sd is None:
        return
    try:
        _atomic_write_json(
            sd / SERVER_FILE,
            {
                "schema": SCHEMA_VERSION,
                "pid": os.getpid(),
                "started_at": _now(),
                "version": version,
            },
        )
    except OSError as exc:
        log.warning("write journal: could not record server start: %s", exc)


__all__ = [
    "PENDING_DIR",
    "SERVER_FILE",
    "STATE_DIR_ENV",
    "STATUS_FILE",
    "commission_key",
    "load_entry",
    "mark_server_started",
    "pending_entries",
    "record_failure",
    "record_success",
    "state_dir",
]
