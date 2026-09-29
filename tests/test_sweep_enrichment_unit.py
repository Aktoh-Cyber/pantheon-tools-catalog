"""Unit tests for the v0.3.0 inventory/enrichment helpers (no Neo4j, no network)."""

from __future__ import annotations

import datetime as dt
import json
import lzma

import pytest

from tools._shared import feeds
from tools._shared.cvss import cvss3_base_score, max_level, severity_of
from tools._shared.graph_batch import flat
from tools.librarian import enrich_eol, enrich_vulnerabilities, ingest_inventory
from tools.librarian import match_iocs as iocs

# --- CVSS --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss3_base_scores_match_the_spec(vector: str, score: float) -> None:
    assert cvss3_base_score(vector) == score


def test_cvss_non_v3_is_not_scored() -> None:
    assert cvss3_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N") is None
    assert cvss3_base_score("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None


def test_severity_prefers_vendor_triage_and_keeps_cvss() -> None:
    crit = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    rec = {"severity": [{"type": "CVSS_V3", "score": crit}]}
    s = severity_of(rec, "unimportant")
    assert s["level"] == "negligible" and s["level_source"] == "vendor"
    assert s["cvss_score"] == 9.8 and s["cvss_level"] == "critical"
    s2 = severity_of(rec, "not yet assigned")
    assert s2["level"] == "critical" and s2["level_source"] == "cvss"
    assert severity_of({"database_specific": {"severity": "HIGH"}})["level"] == "high"
    assert severity_of({}, "unimportant")["level"] == "negligible"
    assert severity_of({}, "not yet assigned")["level"] == "unknown"
    assert max_level(["low", "high", "unknown"]) == "high"
    assert max_level([]) == "unknown"


# --- OSV mapping ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "ver", "mgr", "eco"),
    [
        ("linux-debian", "12", "apt", "Debian:12"),
        ("linux-debian", "12", "", "Debian:12"),
        ("linux-debian", "22.04", "apt", "Ubuntu:22.04:LTS"),
        ("linux-debian", "24.10", "apt", "Ubuntu:24.10"),
        ("macos", "26.6.2", "brew", None),
        ("windows", "", "windows-registry", None),
        ("linux-rhel", "9.4", "dnf", None),
        ("linux-debian", "", "apt", None),
    ],
)
def test_ecosystem_for(kind: str, ver: str, mgr: str, eco: str | None) -> None:
    got, _distro, _release, reason = enrich_vulnerabilities.ecosystem_for(
        kind, ver, mgr
    )
    assert got == eco
    if eco is None:
        assert reason, "an unsupported package always says why"


def test_brew_is_reported_unsupported_not_guessed() -> None:
    _, _, _, reason = enrich_vulnerabilities.ecosystem_for("macos", "26", "brew")
    assert "Homebrew" in reason


def test_query_version_drops_binnmu_only() -> None:
    assert enrich_vulnerabilities.query_version("5.2.15-2+b13") == "5.2.15-2"
    assert (
        enrich_vulnerabilities.query_version("3.0.20-1~deb12u2") == "3.0.20-1~deb12u2"
    )


def test_fixed_version_picks_the_matching_ecosystem() -> None:
    rec = {
        "affected": [
            {
                "package": {"name": "openssl", "ecosystem": "Debian:11"},
                "ranges": [
                    {"events": [{"introduced": "0"}, {"fixed": "1.1.1w-0+deb11u9"}]}
                ],
            },
            {
                "package": {"name": "openssl", "ecosystem": "Debian:12"},
                "ranges": [
                    {"events": [{"introduced": "0"}, {"fixed": "3.0.22-1~deb12u1"}]}
                ],
                "ecosystem_specific": {"urgency": "not yet assigned"},
            },
        ]
    }
    assert enrich_vulnerabilities.fixed_version(rec, "openssl", "Debian:12") == (
        "3.0.22-1~deb12u1",
        "not yet assigned",
    )
    assert enrich_vulnerabilities.fixed_version(rec, "glibc", "Debian:12") == ("", None)


def test_vuln_props_uses_upstream_cves_and_details_summary() -> None:
    rec = {
        "id": "DEBIAN-CVE-2026-1",
        "upstream": ["CVE-2026-1"],
        "details": "First line.\nMore.",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"}
        ],
    }
    p = enrich_vulnerabilities.vuln_props(rec, None)
    assert p["cves"] == ["CVE-2026-1"]
    assert p["summary"] == "First line."
    assert p["severity"] == "medium" and p["cvss_score"] == 5.9
    assert p["url"].endswith("DEBIAN-CVE-2026-1")


def test_parse_packages_index_maps_binaries_to_sources_and_epochs() -> None:
    text = (
        b"Package: libssl3\nSource: openssl\nVersion: 3.0.20-1~deb12u2\n\n"
        b"Package: bash\nSource: bash (5.2.15-2)\nVersion: 5.2.15-2+b13\n\n"
        b"Package: zlib1g\nSource: zlib\nVersion: 1:1.2.13.dfsg-1\n\n"
        b"Package: util-linux\nVersion: 2.38.1-5\n\n"
    )
    sources, epochs = feeds.parse_packages_index(text)
    assert sources == {"libssl3": "openssl", "zlib1g": "zlib"}, "same-name omitted"
    assert epochs == {"zlib1g": "1"}


# --- feeds seam -----------------------------------------------------------------


def test_open_refuses_non_allow_listed_hosts() -> None:
    with pytest.raises(feeds.FeedError):
        feeds._open("https://evil.example.com/x")
    with pytest.raises(feeds.FeedError):
        feeds._open("http://api.osv.dev/v1/querybatch")


def test_source_package_map_parses_xz_and_caches(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("LIBRARIAN_STATE_DIR", str(tmp_path))
    feeds.clear_memory_cache()
    calls: list[str] = []
    body = lzma.compress(b"Package: libc6\nSource: glibc\n\n")

    def fake_open(url: str, **_: object) -> bytes:
        calls.append(url)
        return body

    monkeypatch.setattr(feeds, "_open", fake_open)
    want = ({"libc6": "glibc"}, {})
    assert feeds.package_index("debian", "bookworm", "arm64") == want
    feeds.clear_memory_cache()
    assert feeds.package_index("debian", "bookworm", "arm64") == want
    assert len(calls) == 1, "second call is served from the disk cache"
    assert calls[0].endswith("/bookworm/main/binary-arm64/Packages.xz")


def test_osv_querybatch_follows_page_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_open(url: str, data: bytes | None = None, **_: object) -> bytes:
        req = json.loads(data or b"{}")
        if url.endswith("/querybatch"):
            return json.dumps(
                {"results": [{"vulns": [{"id": "A"}], "next_page_token": "t1"}, {}]}
            ).encode()
        assert req.get("page_token") == "t1"
        return json.dumps({"vulns": [{"id": "B"}]}).encode()

    monkeypatch.setattr(feeds, "_open", fake_open)
    q = {"package": {"name": "x", "ecosystem": "Debian:12"}, "version": "1"}
    assert feeds.osv_querybatch([q, q]) == [["A", "B"], []]


def test_threatfox_export_normalises(monkeypatch: pytest.MonkeyPatch) -> None:
    feeds.clear_memory_cache()
    monkeypatch.delenv("LIBRARIAN_STATE_DIR", raising=False)
    export = {
        "1": [
            {
                "ioc_value": "1.2.3.4:443",
                "ioc_type": "ip:port",
                "threat_type": "botnet_cc",
                "malware_printable": "X",
            }
        ],
        "2": [
            {
                "ioc_value": "https://Evil.Example.net/p",
                "ioc_type": "url",
                "threat_type": "payload",
            }
        ],
        "3": [{"ioc_value": "ABCDEF", "ioc_type": "sha256_hash"}],
    }
    monkeypatch.setattr(feeds, "_open", lambda url, **_: json.dumps(export).encode())
    got = {(i["type"], i["value"]) for i in feeds.load_ioc_feed("threatfox-recent")}
    assert got == {
        ("ip", "1.2.3.4"),
        ("domain", "evil.example.net"),
        ("sha256", "abcdef"),
    }


def test_threatfox_api_requires_a_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("THREATFOX_AUTH_KEY", raising=False)
    monkeypatch.delenv("LIBRARIAN_STATE_DIR", raising=False)
    with pytest.raises(feeds.FeedError, match="Auth-Key"):
        feeds.load_ioc_feed("threatfox-api")


def test_configured_feeds_switch_to_api_with_a_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("LIBRARIAN_IOC_FEEDS", raising=False)
    monkeypatch.delenv("THREATFOX_AUTH_KEY", raising=False)
    assert feeds.configured_ioc_feeds() == ["threatfox-recent", "feodo"]
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "k")
    assert feeds.configured_ioc_feeds() == ["threatfox-api", "feodo"]


def test_threatfox_key_from_state_dir_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.delenv("THREATFOX_AUTH_KEY", raising=False)
    monkeypatch.setenv("LIBRARIAN_STATE_DIR", str(tmp_path))
    assert feeds.threatfox_key() == ""
    (tmp_path / "threatfox-auth-key").write_text("abc123\n")
    assert feeds.threatfox_key() == "abc123"


# --- EOL -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "ver", "want"),
    [
        ("linux-debian", "12", ("debian", "12")),
        ("linux-debian", "24.04", ("ubuntu", "24.04")),
        ("linux-alpine", "3.20.0", ("alpine-linux", "3.20")),
        ("macos", "26.6.2", ("macos", "26")),
        ("macos", "10.15.7", ("macos", "10.15")),
    ],
)
def test_os_product(kind: str, ver: str, want: tuple[str, str]) -> None:
    assert enrich_eol.os_product(kind, ver) == want


def test_os_product_explains_what_it_cannot_map() -> None:
    assert isinstance(enrich_eol.os_product("windows", ""), str)
    assert isinstance(enrich_eol.os_product("linux-rhel", "9.4"), str)


@pytest.mark.parametrize(
    ("name", "version", "want"),
    [
        ("libssl3", "3.0.20-1~deb12u2", ("openssl", ["3.0", "3"])),
        ("openssl@3", "3.5.2", ("openssl", ["3.5", "3"])),
        ("perl-base", "5.36.0-7+deb12u3", ("perl", ["5.36", "5"])),
        ("python3.11", "3.11.2-6", ("python", ["3.11"])),
        ("python@3.12", "3.12.7", ("python", ["3.12"])),
        ("redis-server", "5:7.0.15-1~deb12u1", ("redis", ["7.0", "7"])),
        ("nodejs", "18.19.0+dfsg-6~deb12u2", ("nodejs", ["18.19", "18"])),
        ("node@20", "20.18.0", ("nodejs", ["20"])),
        ("bash", "5.2.15-2+b13", None),
    ],
)
def test_package_product(name: str, version: str, want: object) -> None:
    assert enrich_eol.package_product(name, version) == want


def test_cycle_status() -> None:
    today = dt.date(2026, 9, 29)
    debian12 = {
        "cycle": "12",
        "support": "2026-07-11",
        "eol": "2028-06-30",
        "extendedSupport": "2033-06-30",
    }
    openssl30 = {"cycle": "3.0", "eol": "2026-09-07", "extendedSupport": True}
    perl536 = {"cycle": "5.36", "eol": "2025-05-27", "support": "2024-06-09"}
    soon = {"cycle": "x", "eol": "2026-11-01"}
    fine = {"cycle": "y", "eol": False, "support": True}
    assert enrich_eol.cycle_status(debian12, today) == "security-only"
    assert enrich_eol.cycle_status(openssl30, today) == "extended-support-only"
    assert enrich_eol.cycle_status(perl536, today) == "eol"
    assert enrich_eol.cycle_status(soon, today) == "eol-soon"
    assert enrich_eol.cycle_status(fine, today) == "supported"


def test_eol_finding_severity_respects_distro_maintenance() -> None:
    assert enrich_eol.finding_severity("os", "eol", False, None) == "high"
    assert enrich_eol.finding_severity("package", "eol", True, "security-only") == "low"
    assert enrich_eol.finding_severity("package", "eol", False, "supported") == "medium"
    assert enrich_eol.finding_severity("package", "eol", True, "eol") == "medium"


# --- IOC -----------------------------------------------------------------------


def test_normalize_ip_keeps_only_public() -> None:
    assert iocs.normalize_ip("8.8.8.8") == "8.8.8.8"
    assert iocs.normalize_ip("::ffff:8.8.4.4") == "8.8.4.4"
    for private in (
        "10.0.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "100.64.0.1",
        "fe80::1%en0",
        "::",
    ):
        assert iocs.normalize_ip(private) is None


def test_observables_of_host_and_service() -> None:
    host = {"name": "web01.example.com", "remote_peers": ["8.8.8.8", "10.0.0.2"]}
    got = iocs.observables_of(host, ["Host"])
    assert ("ip", "8.8.8.8", "remote_peers") in got
    assert ("domain", "web01.example.com", "name") in got
    assert all(v != "10.0.0.2" for _, v, _ in got)
    assert iocs.observables_of({"name": "tek.local"}, ["Host"]) == []
    svc = iocs.observables_of(
        {"binds": ["0.0.0.0", "203.0.113.9", "1.1.1.1"]}, ["Service"]
    )
    assert svc == [("ip", "1.1.1.1", "binds")], "wildcard and documentation ranges drop"


def test_domain_candidates_match_parent_domains() -> None:
    assert iocs.domain_candidates("a.b.evil.com") == [
        "a.b.evil.com",
        "b.evil.com",
        "evil.com",
    ]


# --- ingest --------------------------------------------------------------------


def test_parse_output_accepts_text_envelope_and_log_lines() -> None:
    inner = {"tool": "socket-inventory", "services": []}
    assert ingest_inventory._parse_output(json.dumps(inner)) == inner
    assert ingest_inventory._parse_output({"inline_output": json.dumps(inner)}) == inner
    assert ingest_inventory._parse_output("warn: x\n" + json.dumps(inner)) == inner


def test_service_rows_skip_transient_and_key_by_owner() -> None:
    services = [
        {
            "proto": "tcp",
            "port": 22,
            "process": "sshd",
            "binds": ["0.0.0.0", "::"],
            "exposure": "all",
            "ephemeral_port": False,
        },
        {
            "proto": "tcp",
            "port": 63625,
            "process": "pulumi",
            "binds": ["127.0.0.1"],
            "exposure": "loopback",
            "ephemeral_port": True,
        },
        {
            "proto": "udp",
            "port": 51000,
            "process": "Chrome",
            "binds": ["0.0.0.0"],
            "exposure": "all",
            "ephemeral_port": True,
        },
        {
            "proto": "tcp",
            "port": 52441,
            "process": "Transmission",
            "binds": ["0.0.0.0"],
            "exposure": "all",
            "ephemeral_port": True,
        },
    ]
    rows, skipped = ingest_inventory._service_rows("n1", "tek.local", services, True)
    assert [r["key"] for r in rows] == ["n1|tcp/22|sshd", "n1|tcp/52441|Transmission"]
    assert skipped == {"loopback_ephemeral": 1, "udp_ephemeral": 1, "unbound_port": 0}
    assert rows[0]["props"]["name"] == "sshd tcp/22"
    assert rows[0]["edge"] == {
        "port": 22,
        "proto": "tcp",
        "process": "sshd",
        "exposure": "all",
    }
    rows_all, _ = ingest_inventory._service_rows("n1", "tek.local", services, False)
    assert len(rows_all) == 4


def test_public_filter_for_peers() -> None:
    assert ingest_inventory._public("8.8.8.8")
    assert not ingest_inventory._public("172.20.1.1")
    assert ingest_inventory._public("172.32.1.1")
    assert not ingest_inventory._public("100.101.11.56")


def test_flat_drops_unstorable_values() -> None:
    assert flat(
        {"a": None, "b": 1, "c": [1, "x"], "d": {"x": 1}, "e": ["a"], "f": []}
    ) == {
        "b": 1,
        "e": ["a"],
        "f": [],
    }


# --- Synapse client (collect_inventory) -------------------------------------


def _jwt(claims: dict[str, object]) -> str:
    import base64

    def b64(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    return f"{b64(b'{}')}.{b64(json.dumps(claims).encode())}.sig"


def test_client_reads_the_librarian_token_and_tenant(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    from tools._shared.synapse_client import SynapseClient

    env = tmp_path / ".env"
    env.write_text(f"FOO='x'\nSYNAPSE_AGENT_JWT='{_jwt({'tenant_id': 'aktoh'})}'\n")
    monkeypatch.delenv("SYNAPSE_AGENT_JWT", raising=False)
    monkeypatch.delenv("SYNAPSE_GATEWAY_URL", raising=False)
    monkeypatch.delenv("LIBRARIAN_SYNAPSE_URL", raising=False)
    monkeypatch.setenv("LIBRARIAN_SYNAPSE_ENV", str(env))
    c = SynapseClient.from_environment()
    assert c.tenant == "aktoh"
    assert c.url == "https://synapse.aktohcyber.com"


def test_client_refuses_missing_token_and_plain_http(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    from tools._shared.synapse_client import SynapseClient, SynapseError

    monkeypatch.delenv("SYNAPSE_AGENT_JWT", raising=False)
    monkeypatch.setenv("LIBRARIAN_SYNAPSE_ENV", str(tmp_path / "missing.env"))
    with pytest.raises(SynapseError, match="no Synapse agent token"):
        SynapseClient.from_environment()
    with pytest.raises(SynapseError, match="non-https"):
        SynapseClient("http://synapse.example", "t", "aktoh")


def test_candidate_digests_prefer_newest_catalog_release() -> None:
    from tools._shared.synapse_client import candidate_digests

    tools = [
        {
            "tool_name": "package-inventory",
            "tool_digest": "sha256:old",
            "source": "tenant",
            "uploaded_at": "2026-09-21",
        },
        {
            "tool_name": "package-inventory",
            "tool_digest": "sha256:new",
            "source": "catalog",
            "uploaded_at": "2026-09-29",
        },
        {
            "tool_name": "socket-inventory",
            "tool_digest": "sha256:s",
            "source": "catalog",
        },
    ]
    assert candidate_digests(tools, "package-inventory") == ["sha256:new", "sha256:old"]
    assert candidate_digests(tools, "nope") == []


async def test_collect_pages_packages_by_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tools.librarian import collect_inventory as ci

    names = ["apt", "bash", "libc6", "libssl3", "lz4", "zlib1g"]
    monkeypatch.setattr(ci, "PKG_PAGE", 2)
    calls: list[str] = []

    async def fake_invoke(client, catalog, node_id, tool, args):  # type: ignore[no-untyped-def]
        prefix = args.get("name_prefix", "")
        calls.append(prefix)
        hit = [n for n in names if n.startswith(prefix)]
        page = [
            {"name": n, "version": "1", "source": "apt"} for n in hit[: args["max"]]
        ]
        return {
            "total_installed": len(names),
            "matched": len(hit),
            "truncated": len(hit) > args["max"],
            "packages": page,
        }, None

    monkeypatch.setattr(ci, "_invoke", fake_invoke)
    out, err = await ci._collect_packages(None, [], "n1")  # type: ignore[arg-type]
    assert err is None and out is not None
    assert sorted(p["name"] for p in out["packages"]) == names
    assert out["truncated"] is False and out["paged"] is True
    assert "l" in calls and "li" in calls, "an overfull prefix is split"


async def test_collect_paging_reports_an_unsplittable_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tools.librarian import collect_inventory as ci

    names = ["libaa1", "libaa2", "libaa3"]
    monkeypatch.setattr(ci, "PKG_PAGE", 2)

    async def fake_invoke(client, catalog, node_id, tool, args):  # type: ignore[no-untyped-def]
        hit = [n for n in names if n.startswith(args.get("name_prefix", ""))]
        page = [{"name": n, "version": "1"} for n in hit[: args["max"]]]
        return {
            "total_installed": 3,
            "truncated": len(hit) > args["max"],
            "packages": page,
        }, None

    monkeypatch.setattr(ci, "_invoke", fake_invoke)
    out, _ = await ci._collect_packages(None, [], "n1")  # type: ignore[arg-type]
    assert (
        out is not None and out["truncated"] is True
    ), "short snapshot never reconciles"
    assert "lib*" in out["note"]


def test_service_rows_skip_unbound_port_zero() -> None:
    services = [{"proto": "udp", "port": 0, "process": "airportd", "exposure": "all"}]
    rows, skipped = ingest_inventory._service_rows("n1", "tek.local", services, False)
    assert rows == [] and skipped["unbound_port"] == 1
