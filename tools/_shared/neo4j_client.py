"""Lazy, process-wide Neo4j driver.

Every librarian tool shares one driver per process. The driver
itself is thread-safe and pools sessions internally — we just need
to make sure we don't bring up N drivers for N tool invocations.

Connection params come from env so the same code paths work locally
(tests with testcontainers point `NEO4J_BOLT_URL` at the
testcontainer port) and in production (the per-tenant Neo4j runs
inside the pantheon container, bound to `bolt://localhost:7687`
with auth disabled — the container itself is the trust boundary;
see `PMC-Conversational-Graph-Architecture.md` §15.2).
"""
from __future__ import annotations

import os
import threading
from typing import Optional

from neo4j import AsyncDriver, AsyncGraphDatabase

_DEFAULT_BOLT_URL = "bolt://localhost:7687"

_driver: Optional[AsyncDriver] = None
_lock = threading.Lock()


def _build_driver() -> AsyncDriver:
    url = os.environ.get("NEO4J_BOLT_URL", _DEFAULT_BOLT_URL)
    user = os.environ.get("NEO4J_USER", "")
    password = os.environ.get("NEO4J_PASSWORD", "")
    if user and password:
        auth = (user, password)
    else:
        auth = None
    # max_connection_lifetime defaults to 1h which is fine for
    # localhost; max_connection_pool_size defaults to 100 which
    # is generous for a single sidecar.
    return AsyncGraphDatabase.driver(url, auth=auth)


def get_driver() -> AsyncDriver:
    """Return the shared driver, creating it on first call."""
    global _driver
    if _driver is not None:
        return _driver
    with _lock:
        if _driver is None:
            _driver = _build_driver()
    return _driver


async def close_driver() -> None:
    """Close the shared driver (e.g. at process shutdown)."""
    global _driver
    if _driver is None:
        return
    drv = _driver
    _driver = None
    await drv.close()


def reset_driver_for_testing() -> None:
    """Drop the cached driver. Tests call this between fixtures so
    a new `NEO4J_BOLT_URL` (set per testcontainer) takes effect."""
    global _driver
    _driver = None
