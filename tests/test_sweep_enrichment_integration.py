# ruff: noqa: E501  (inline Cypher assertions read best on one line)
"""Integration: ingest_inventory + the enrichers against a real Neo4j.

Feeds are canned (``tools._shared.feeds._open`` is replaced), so this runs
offline; the graph side (UNWIND batches, provenance, reconciliation,
roll-ups) is real. Skipped without Docker.
"""

from __future__ import annotations

import datetime as dt
import json
import lzma
from typing import Any

import pytest

from tools._shared import feeds
from tools._shared.graph_batch import read
from tools.librarian.enrich_all import EnrichAllInput
from tools.librarian.enrich_all import run as run_enrich_all
from tools.librarian.ingest_inventory import IngestInventoryInput
from tools.librarian.ingest_inventory import run as run_ingest
from tools.librarian.upsert_node import UpsertNodeInput
from tools.librarian.upsert_node import run as run_upsert_node

pytestmark = pytest.mark.integration

ENV = {"commissioned_by": "infosec", "session_id": "sweep-test"}
TODAY = dt.datetime.now(dt.UTC).date()


def _d(days: int) -> str:
    return (TODAY + dt.timedelta(days=days)).isoformat()


OSV_RECORD = {
    "id": "DEBIAN-CVE-2026-0001",
    "upstream": ["CVE-2026-0001"],
    "details": "NULL dereference in CMP client.",
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"}
    ],
    "affected": [
        {
            "package": {"name": "openssl", "ecosystem": "Debian:12"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "3.0.22-1~deb12u1"}],
                }
            ],
            "ecosystem_specific": {"urgency": "not yet assigned"},
        }
    ],
}
OSV_UNFIXED = {
    "id": "DEBIAN-CVE-2010-4756",
    "upstream": ["CVE-2010-4756"],
    "details": "glob DoS.",
    "affected": [
        {
            "package": {"name": "glibc", "ecosystem": "Debian:12"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            "ecosystem_specific": {"urgency": "unimportant"},
        }
    ],
}
EOL = {
    "debian": [
        {"cycle": "12", "codename": "Bookworm", "support": _d(-60), "eol": _d(600)}
    ],
    "macos": [{"cycle": "26", "eol": False, "support": True}],
    "openssl": [{"cycle": "3.0", "eol": _d(-20), "extendedSupport": True}],
}
PACKAGES_XZ = lzma.compress(
    b"Package: libssl3\nSource: openssl\n\nPackage: libc6\nSource: glibc\n\n"
)
FEODO = [
    {"ip_address": "198.51.100.77", "malware": "Emotet"},
    {"ip_address": "8.8.4.4", "malware": "Test"},
]


def fake_open(url: str, data: bytes | None = None, **_: Any) -> bytes:
    if url.endswith("/querybatch"):
        queries = json.loads(data or b"{}")["queries"]
        results = []
        for q in queries:
            name = q["package"]["name"]
            ids = {
                "openssl": ["DEBIAN-CVE-2026-0001"],
                "glibc": ["DEBIAN-CVE-2010-4756"],
            }.get(name, [])
            results.append({"vulns": [{"id": i} for i in ids]})
        return json.dumps({"results": results}).encode()
    if "/vulns/" in url:
        rec = OSV_RECORD if url.endswith("0001") else OSV_UNFIXED
        return json.dumps(rec).encode()
    if url.startswith("https://endoflife.date/api/"):
        product = url.rsplit("/", 1)[1].removesuffix(".json")
        return json.dumps(EOL.get(product, [])).encode()
    if url.endswith("Packages.xz"):
        return PACKAGES_XZ
    if "threatfox" in url:
        return json.dumps(
            {"9": [{"ioc_value": "evil.example.org", "ioc_type": "domain"}]}
        ).encode()
    if "feodotracker" in url:
        return json.dumps(FEODO).encode()
    raise AssertionError(f"unexpected URL {url}")


@pytest.fixture()
def canned_feeds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LIBRARIAN_STATE_DIR", raising=False)
    monkeypatch.delenv("THREATFOX_AUTH_KEY", raising=False)
    monkeypatch.delenv("LIBRARIAN_IOC_FEEDS", raising=False)
    feeds.clear_memory_cache()
    monkeypatch.setattr(feeds, "_open", fake_open)


async def _host(node_id: str, name: str, **props: Any) -> None:
    resp = await run_upsert_node(
        UpsertNodeInput(
            label="Host",
            merge_keys=["node_id"],
            props={"node_id": node_id, "name": name, **props},
            **ENV,
        )
    )
    assert resp.ok, resp.error


async def _count(cypher: str, **params: Any) -> int:
    rows = await read(cypher, params)
    return int(rows[0]["c"]) if rows else 0


async def test_ingest_then_enrich_all(neo4j_clean, canned_feeds) -> None:
    await _host(
        "deb", "720eb9d52505", os_kind="linux-debian", os_version="12", arch="aarch64"
    )
    await _host(
        "mac", "tek.local", os_kind="macos", os_version="26.6.2", arch="aarch64"
    )

    pkgs = {
        "tool": "package-inventory",
        "total_installed": 3,
        "packages": [
            {"name": "libssl3", "version": "3.0.20-1~deb12u2", "source": "apt"},
            {"name": "libc6", "version": "2.36-9+deb12u14", "source": "apt"},
            {"name": "bash", "version": "5.2.15-2+b13", "source": "apt"},
        ],
    }
    r = await run_ingest(
        IngestInventoryInput(
            host_node_id="deb", tool="package-inventory", output=json.dumps(pkgs), **ENV
        )
    )
    assert r.ok, r.error
    assert r.result and r.result.recorded["packages"] == 3

    brew = {
        "tool": "package-inventory",
        "status": "ok",
        "packages": [{"name": "python@3.12", "version": "3.12.7", "source": "brew"}],
    }
    assert (
        await run_ingest(
            IngestInventoryInput(
                host_node_id="mac", tool="package-inventory", output=brew, **ENV
            )
        )
    ).ok

    socks = {
        "tool": "socket-inventory",
        "services": [
            {
                "proto": "tcp",
                "port": 22,
                "process": "sshd",
                "binds": ["0.0.0.0"],
                "exposure": "all",
                "ephemeral_port": False,
            },
            {
                "proto": "tcp",
                "port": 63000,
                "process": "pulumi",
                "binds": ["127.0.0.1"],
                "exposure": "loopback",
                "ephemeral_port": True,
            },
        ],
        "remote_peers": ["8.8.4.4", "10.0.0.9"],
        "connection_count": 2,
    }
    s = await run_ingest(
        IngestInventoryInput(
            host_node_id="mac", tool="socket-inventory", output=socks, **ENV
        )
    )
    assert s.ok, s.error
    assert s.result and s.result.recorded["services"] == 1
    assert s.result.skipped == {"loopback_ephemeral": 1}

    out = await run_enrich_all(EnrichAllInput(**ENV))
    assert out.ok, out.error
    vul = out.result["vulnerabilities"]["result"]  # type: ignore[index]
    assert vul["vulnerabilities"] == 2
    assert vul["affected_by_edges"] == 2
    assert vul["unsupported"] == {"Homebrew has no OSV ecosystem": 1}
    assert vul["fixable"] == 1
    assert vul["by_severity"] == {"medium": 1, "negligible": 1}

    assert (
        await _count(
            "MATCH (p:Package {name:'libssl3'})-[r:AFFECTED_BY {fix_available:true}]->"
            "(v:Vulnerability {id:'DEBIAN-CVE-2026-0001'}) "
            "WHERE r.source_package='openssl' AND v.cvss_score=5.9 AND v.commissioned_by='infosec' "
            "RETURN count(*) AS c"
        )
        == 1
    )
    host = (
        await read(
            "MATCH (h:Host {node_id:'deb'}) RETURN h.vuln_count AS n, h.vuln_fixable AS f, h.eol_status AS e"
        )
    )[0]
    assert host == {"n": 2, "f": 1, "e": "security-only"}

    eol = out.result["eol"]["result"]  # type: ignore[index]
    keys = {f["key"] for f in eol["findings"]}
    assert keys == {
        "720eb9d52505|eol|openssl-3.0"
    }, "Debian 12 in LTS is not a finding; openssl 3.0 is"
    assert (
        await _count(
            "MATCH (:Host {node_id:'deb'})-[:HAS_FINDING]->(f:Finding {tool:'eol', severity:'low'}) RETURN count(f) AS c"
        )
        == 1
    )

    ioc = out.result["iocs"]["result"]  # type: ignore[index]
    assert [m["observed"] for m in ioc["matches"]] == ["8.8.4.4"]
    assert (
        await _count(
            "MATCH (:Host {node_id:'mac'})-[:MATCHES_IOC]->(i:Indicator {value:'8.8.4.4'}) RETURN count(i) AS c"
        )
        == 1
    )
    assert (
        await _count(
            "MATCH (h:Host {node_id:'mac'}) WHERE h.ioc_match_count = 1 RETURN count(h) AS c"
        )
        == 1
    )


async def test_reconciliation_on_a_new_snapshot(neo4j_clean, canned_feeds) -> None:
    await _host("deb", "d1", os_kind="linux-debian", os_version="12", arch="x86_64")
    first = {
        "packages": [
            {"name": "libssl3", "version": "3.0.20-1~deb12u2", "source": "apt"}
        ],
        "total_installed": 1,
    }
    assert (
        await run_ingest(
            IngestInventoryInput(
                host_node_id="deb", tool="package-inventory", output=first, **ENV
            )
        )
    ).ok
    upgraded = {
        "packages": [
            {"name": "libssl3", "version": "3.0.22-1~deb12u1", "source": "apt"}
        ],
        "total_installed": 1,
    }
    r = await run_ingest(
        IngestInventoryInput(
            host_node_id="deb", tool="package-inventory", output=upgraded, **ENV
        )
    )
    assert r.ok and r.result and r.result.removed == {"stale_has_package": 1}
    assert (
        await _count(
            "MATCH (:Host {node_id:'deb'})-[:HAS_PACKAGE]->(p) RETURN count(p) AS c"
        )
        == 1
    )

    svc1 = {
        "services": [
            {"proto": "tcp", "port": 22, "process": "sshd", "exposure": "all"},
            {"proto": "tcp", "port": 80, "process": "nginx", "exposure": "all"},
        ]
    }
    assert (
        await run_ingest(
            IngestInventoryInput(
                host_node_id="deb", tool="socket-inventory", output=svc1, **ENV
            )
        )
    ).ok
    svc2 = {
        "services": [{"proto": "tcp", "port": 22, "process": "sshd", "exposure": "all"}]
    }
    r2 = await run_ingest(
        IngestInventoryInput(
            host_node_id="deb", tool="socket-inventory", output=svc2, **ENV
        )
    )
    assert r2.ok and r2.result and r2.result.removed == {"stale_services": 1}
    assert (
        await _count(
            "MATCH (:Host {node_id:'deb'})-[:LISTENS_ON]->(s:Service) RETURN count(s) AS c"
        )
        == 1
    )

    empty = {
        "packages": [],
        "total_installed": 0,
        "status": "no-backend",
        "note": "empty: no package back-end",
    }
    r3 = await run_ingest(
        IngestInventoryInput(
            host_node_id="deb", tool="package-inventory", output=empty, **ENV
        )
    )
    assert r3.ok and r3.result and r3.result.notes, "an empty snapshot is reported"
    assert (
        await _count(
            "MATCH (:Host {node_id:'deb'})-[:HAS_PACKAGE]->(p) RETURN count(p) AS c"
        )
        == 1
    ), "and never unlinks"


async def test_ingest_refuses_unknown_host_and_foreign_output(neo4j_clean) -> None:
    r = await run_ingest(
        IngestInventoryInput(
            host_node_id="nope",
            tool="package-inventory",
            output={"packages": []},
            **ENV,
        )
    )
    assert not r.ok and r.details and r.details["hint"] == "host_not_found"
    r2 = await run_ingest(
        IngestInventoryInput(
            host_node_id="nope", tool="socket-inventory", output={"packages": []}, **ENV
        )
    )
    assert not r2.ok and "no `services` list" in (r2.error or "")
    r3 = await run_ingest(
        IngestInventoryInput(
            host_node_id="nope",
            tool="socket-inventory",
            output={"error": "denied: x"},
            **ENV,
        )
    )
    assert not r3.ok and "run itself failed" in (r3.error or "")


class FakeSynapse:
    tenant = "aktoh"

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def nodes(self) -> list[dict[str, Any]]:
        return [
            {
                "node_id": "deb",
                "name": "720eb9d52505",
                "connected": True,
                "status": "online",
                "current_version": "node-v0.1.17",
            },
            {
                "node_id": "win",
                "name": "Aktoh",
                "connected": False,
                "status": "offline",
                "last_seen": "2026-09-28T22:59:18Z",
            },
        ]

    def tools(self) -> list[dict[str, Any]]:
        return [
            {"tool_name": t, "tool_digest": f"sha256:{t}", "source": "catalog"}
            for t in ("os-fingerprint", "package-inventory", "socket-inventory")
        ] + [
            {
                "tool_name": "package-inventory",
                "tool_digest": "sha256:old",
                "source": "tenant",
            }
        ]

    def invoke(
        self, node_id: str, digest: str, args: dict[str, Any], deadline: int = 120
    ) -> dict[str, Any]:
        self.calls.append((node_id, digest))
        if digest == "sha256:os-fingerprint":
            out: dict[str, Any] = {
                "granted": True,
                "os": {"kind": "linux-debian", "version": "12", "arch": "aarch64"},
            }
        elif digest == "sha256:package-inventory":
            return {"exit_kind": "trap", "exit_code": -1, "inline_output": None}
        elif digest == "sha256:old":
            out = {
                "total_installed": 1,
                "packages": [
                    {"name": "libssl3", "version": "3.0.20-1~deb12u2", "source": "apt"}
                ],
            }
        else:
            out = {
                "services": [
                    {"proto": "tcp", "port": 22, "process": "sshd", "exposure": "all"}
                ],
                "remote_peers": ["1.1.1.1"],
            }
        return {"exit_kind": "success", "exit_code": 0, "inline_output": out}


async def test_collect_then_enrich_in_one_call(
    neo4j_clean, canned_feeds, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tools.librarian import collect_inventory

    fake = FakeSynapse()
    monkeypatch.setattr(
        collect_inventory.SynapseClient,
        "from_environment",
        classmethod(lambda cls: fake),
    )
    out = await run_enrich_all(EnrichAllInput(collect=True, **ENV))
    col = out.result["collect"]  # type: ignore[index]
    assert col["ok"] is True, col
    assert col["result"]["skipped_offline"] == [
        "Aktoh (last seen 2026-09-28T22:59:18Z)"
    ]
    node = col["result"]["nodes"][0]
    assert node["os-fingerprint"] == "linux-debian 12"
    assert (
        node["package-inventory"]["recorded"]["packages"] == 1
    ), "fell back to the older digest"
    assert ("deb", "sha256:old") in fake.calls
    assert (
        await _count(
            "MATCH (h:Host {node_id:'deb', os_kind:'linux-debian', agent_version:'node-v0.1.17'})-[:LISTENS_ON]->(:Service) RETURN count(h) AS c"
        )
        == 1
    )
    assert (
        await _count(
            "MATCH (h:Host {node_id:'win', connected:false}) RETURN count(h) AS c"
        )
        == 1
    )
    assert out.result["vulnerabilities"]["ok"] is True  # type: ignore[index]
