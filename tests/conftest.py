"""pytest fixtures.

Integration tests live in `tests/test_*_integration.py` and are
gated behind the `integration` marker. They spin a Neo4j
testcontainer once per session, point the catalog's driver at it,
and clean per-test state with a tag/cleanup pattern.

To run integration tests locally:

    pytest -m integration

Unit tests run by default; integration tests are skipped unless
Docker is available + the marker is requested.
"""
from __future__ import annotations

import os
import socket
from collections.abc import AsyncIterator, Iterator
from contextlib import suppress

import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "integration: integration test (requires Docker + testcontainers)",
    )


def _docker_available() -> bool:
    """Cheap probe: try to connect to the Docker daemon socket.
    On CI runners with Docker, this is fast and reliable. On dev
    laptops without Docker, we skip integration tests instead of
    hanging."""
    with suppress(Exception):
        sock_path = os.environ.get("DOCKER_HOST", "")
        if sock_path.startswith("unix://"):
            sock_path = sock_path[len("unix://") :]
        if not sock_path:
            sock_path = "/var/run/docker.sock"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        sock.connect(sock_path)
        sock.close()
        return True
    return False


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Auto-skip integration tests when Docker isn't available so the
    fast unit lane stays green on dev laptops."""
    if _docker_available():
        return
    skip_no_docker = pytest.mark.skip(
        reason="integration test requires Docker (not detected)"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_no_docker)


@pytest.fixture(scope="session")
def neo4j_container() -> Iterator[object]:
    """Session-scoped Neo4j 5.x container. All integration tests
    share it. Per-test cleanup happens in the `neo4j_clean` fixture
    below.

    Lazy import of testcontainers so unit-only runs don't need it
    installed."""
    from testcontainers.neo4j import Neo4jContainer  # type: ignore

    container = Neo4jContainer("neo4j:5.26")
    with container as c:
        yield c


@pytest.fixture()
async def neo4j_clean(neo4j_container, monkeypatch) -> AsyncIterator[None]:
    """Point the catalog's driver at the container, drop the cached
    driver, and run the test against an empty database. After the
    test, wipe everything we wrote."""
    bolt_url = neo4j_container.get_connection_url()

    monkeypatch.setenv("NEO4J_BOLT_URL", bolt_url)
    monkeypatch.setenv("NEO4J_USER", neo4j_container.username)
    monkeypatch.setenv("NEO4J_PASSWORD", neo4j_container.password)

    from tools._shared import neo4j_client

    neo4j_client.reset_driver_for_testing()

    # Wipe before the test (in case a previous test died mid-run).
    driver = neo4j_client.get_driver()
    async with driver.session() as session:
        await session.run("MATCH (n) DETACH DELETE n")

    yield

    # Wipe after the test.
    async with driver.session() as session:
        await session.run("MATCH (n) DETACH DELETE n")

    await neo4j_client.close_driver()
    neo4j_client.reset_driver_for_testing()
