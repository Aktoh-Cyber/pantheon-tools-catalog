"""librarian.enrich_vulnerabilities: match the graph's packages against OSV.

Reads every ``(Host)-[:HAS_PACKAGE]->(Package)`` in the graph, asks OSV
(https://osv.dev, free, no key) which advisories affect each package version,
and writes:

- ``Vulnerability {id}`` nodes: OSV id, CVE aliases, summary, severity level,
  CVSS v3 score and vector when the record has one, published/modified, url.
- ``(Package)-[:AFFECTED_BY]->(Vulnerability)`` with the fixed version for
  that release (``fix_available``), the source package queried, the
  ecosystem and the distro's urgency. Edges OSV no longer reports are removed.
- On each Package: ``vuln_status`` (``checked`` | ``unsupported`` |
  ``error``), ``vuln_count``, ``vuln_max_severity``, ``vuln_fixable``,
  ``vuln_checked_at``, and ``vuln_note`` when it could not be checked.
- On each Host: ``vuln_count``, ``vuln_critical`` / ``_high`` / ``_medium`` /
  ``_low``, ``vuln_fixable``, ``vuln_checked_at``.

Ecosystems: Debian and Ubuntu (apt). OSV keys their advisories by SOURCE
package (``openssl``, ``glibc``) while the node lists binaries (``libssl3``,
``libc6``), so each release's ``Packages.xz`` index maps one to the other; a
binNMU suffix (``+b13``) is dropped from the version. Homebrew, Windows and
RPM/Alpine packages are reported as ``unsupported`` with the reason. Nothing
is guessed.

The feed runs in the tenant container: customer nodes make no third-party
calls, and the enricher needs no node release.
"""

from __future__ import annotations

import asyncio
import re
from collections import defaultdict
from typing import Any

from pydantic import BaseModel, Field

from tools._shared import feeds, write_journal
from tools._shared.cvss import LEVEL_RANK, max_level, severity_of
from tools._shared.graph_batch import Commission, flat, prov, read, write, write_rows

TOOL = "librarian.enrich_vulnerabilities"

# Used only when a release's Packages index cannot be fetched.
_FALLBACK_SOURCES = {
    "libc6": "glibc",
    "libc-bin": "glibc",
    "libssl3": "openssl",
    "libssl3t64": "openssl",
    "libssl1.1": "openssl",
    "libsystemd0": "systemd",
    "libudev1": "systemd",
    "libpam0g": "pam",
    "libpam-modules": "pam",
    "libpam-modules-bin": "pam",
    "libpam-runtime": "pam",
    "libgnutls30": "gnutls28",
    "libgnutls30t64": "gnutls28",
    "perl-base": "perl",
    "perl-modules-5.36": "perl",
    "libperl5.36": "perl",
    "zlib1g": "zlib",
    "libseccomp2": "libseccomp",
    "libcurl4": "curl",
    "libexpat1": "expat",
    "liblzma5": "xz-utils",
    "libzstd1": "libzstd",
    "libbz2-1.0": "bzip2",
    "libtinfo6": "ncurses",
    "libncursesw6": "ncurses",
    "ncurses-base": "ncurses",
    "ncurses-bin": "ncurses",
    "libmount1": "util-linux",
    "libblkid1": "util-linux",
    "libuuid1": "util-linux",
    "libsmartcols1": "util-linux",
    "mount": "util-linux",
    "libkrb5-3": "krb5",
    "libgssapi-krb5-2": "krb5",
    "libk5crypto3": "krb5",
    "libkrb5support0": "krb5",
    "libsqlite3-0": "sqlite3",
    "libxml2": "libxml2",
    "libpcre2-8-0": "pcre2",
    "libselinux1": "libselinux",
    "libcap2": "libcap2",
    "libgcrypt20": "libgcrypt20",
    "libgpg-error0": "libgpg-error",
    "libapt-pkg6.0": "apt",
    "libext2fs2": "e2fsprogs",
    "libcom-err2": "e2fsprogs",
    "libss2": "e2fsprogs",
    "logsave": "e2fsprogs",
    "libstdc++6": "gcc-12",
    "libgcc-s1": "gcc-12",
    "gcc-12-base": "gcc-12",
}


class EnrichVulnerabilitiesInput(Commission):
    host_node_id: str | None = Field(
        default=None, description="Only this Host's packages (default: every host)."
    )
    max_vulnerabilities: int = Field(
        default=3000, ge=1, le=20000, description="Safety cap on records fetched."
    )


class EnrichVulnerabilitiesResult(BaseModel):
    feed: str = "osv.dev"
    packages_considered: int = 0
    packages_checked: int = 0
    unsupported: dict[str, int] = Field(default_factory=dict)
    source_maps: dict[str, str] = Field(default_factory=dict)
    vulnerabilities: int = 0
    affected_by_edges: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    fixable: int = 0
    stale_edges_removed: int = 0
    hosts: list[dict[str, Any]] = Field(default_factory=list)
    top: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class EnrichVulnerabilitiesToolResponse(BaseModel):
    ok: bool
    result: EnrichVulnerabilitiesResult | None = None
    error: str | None = None
    details: dict[str, Any] | None = None


# --- pure helpers (unit-tested) ----------------------------------------------


def ecosystem_for(
    os_kind: str | None, os_version: str | None, manager: str | None
) -> tuple[str | None, str | None, str | None, str]:
    """-> (osv_ecosystem, distro, release, reason). ``osv_ecosystem`` None
    means unsupported, and ``reason`` says why."""
    m = (manager or "").lower()
    kind = (os_kind or "").lower()
    ver = (os_version or "").strip()
    if m == "brew":
        return None, None, None, "Homebrew has no OSV ecosystem"
    if m in ("winget", "windows-registry"):
        return None, None, None, "Windows packages have no OSV ecosystem"
    if m in ("dnf", "yum", "rpm") or kind == "linux-rhel":
        return None, None, None, "RPM distributions are not mapped to OSV yet"
    if m == "apk" or kind == "linux-alpine":
        return None, None, None, "Alpine is not mapped to OSV yet"
    if m in ("apt", "") and kind == "linux-debian":
        ubuntu = re.fullmatch(r"(\d{2})\.(\d{2})", ver)
        if ubuntu:
            lts = ubuntu.group(2) == "04" and int(ubuntu.group(1)) % 2 == 0
            return (f"Ubuntu:{ver}:LTS" if lts else f"Ubuntu:{ver}"), "ubuntu", ver, ""
        debian = re.fullmatch(r"(\d{1,2})(?:\.\d+)*", ver)
        if debian:
            major = debian.group(1)
            return f"Debian:{major}", "debian", major, ""
        return (
            None,
            None,
            None,
            f"cannot tell the Debian-family release from os_version {ver!r}",
        )
    return (
        None,
        None,
        None,
        f"no OSV mapping for os_kind {kind or '?'!r} / manager {m or '?'!r}",
    )


def query_version(version: str) -> str:
    """Drop a Debian binNMU suffix: OSV ranges are in source versions."""
    return re.sub(r"\+b\d+$", "", version)


def fixed_version(
    record: dict[str, Any], package: str, ecosystem: str
) -> tuple[str, str | None]:
    """-> (fixed version or "", urgency) for one package in one ecosystem."""
    for aff in record.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("name") != package or pkg.get("ecosystem") != ecosystem:
            continue
        urgency = (aff.get("ecosystem_specific") or {}).get("urgency")
        fixed = [
            ev["fixed"]
            for rng in aff.get("ranges") or []
            for ev in rng.get("events") or []
            if isinstance(ev, dict) and ev.get("fixed")
        ]
        return (fixed[-1] if fixed else ""), (str(urgency) if urgency else None)
    return "", None


def vuln_props(record: dict[str, Any], urgency: str | None) -> dict[str, Any]:
    sev = severity_of(record, urgency)
    aliases = sorted(
        {str(a) for a in (record.get("aliases") or []) + (record.get("upstream") or [])}
    )
    summary = record.get("summary") or ""
    if not summary:
        details = str(record.get("details") or "").strip()
        summary = details.split("\n", 1)[0]
    if len(summary) > 280:
        summary = summary[:277] + "..."
    vid = str(record.get("id"))
    return flat(
        {
            "id": vid,
            "summary": summary or None,
            "aliases": aliases,
            "cves": [a for a in aliases if a.startswith("CVE-")],
            "severity": sev["level"],
            "severity_source": sev.get("level_source"),
            "cvss_score": sev.get("cvss_score"),
            "cvss_severity": sev.get("cvss_level"),
            "cvss_vector": sev.get("cvss_vector"),
            "published": record.get("published"),
            "modified": record.get("modified"),
            "url": f"https://osv.dev/vulnerability/{vid}",
            "source": "osv.dev",
        }
    )


# --- run -----------------------------------------------------------------------


async def run(input: EnrichVulnerabilitiesInput) -> EnrichVulnerabilitiesToolResponse:
    payload = input.model_dump(mode="json")
    try:
        res = await _run(input)
    except feeds.FeedError as exc:
        return EnrichVulnerabilitiesToolResponse(
            ok=False,
            error=f"vulnerability feed unavailable: {exc}. Nothing was written.",
            details={"tool": TOOL, "stage": "feed"},
        )
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        details: dict[str, Any] = {"tool": TOOL, "recorded": False}
        pending = write_journal.record_failure(TOOL, error, payload)
        if pending:
            details["pending_id"] = pending
        return EnrichVulnerabilitiesToolResponse(ok=False, error=error, details=details)
    write_journal.record_success(TOOL, payload)
    return EnrichVulnerabilitiesToolResponse(ok=True, result=res)


async def _run(inp: EnrichVulnerabilitiesInput) -> EnrichVulnerabilitiesResult:
    c = Commission(commissioned_by=inp.commissioned_by, session_id=inp.session_id)
    res = EnrichVulnerabilitiesResult()
    rows = await read(
        "MATCH (h:Host)-[:HAS_PACKAGE]->(p:Package) "
        "WHERE $host IS NULL OR h.node_id = $host "
        "RETURN h.node_id AS host, h.os_kind AS os_kind, h.os_version AS os_version, "
        "h.arch AS arch, p.name AS name, p.version AS version, "
        "coalesce(p.manager, '') AS manager",
        {"host": inp.host_node_id},
    )
    # package key -> (ecosystem, source, query version); or -> unsupported reason
    targets: dict[tuple[str, str], tuple[str, str, str]] = {}
    unsupported: dict[tuple[str, str], str] = {}
    srcmaps: dict[tuple[str, str, str], tuple[dict[str, str], dict[str, str]]] = {}
    for r in rows:
        key = (str(r["name"]), str(r["version"] or ""))
        if key in targets:
            continue
        eco, distro, release, reason = ecosystem_for(
            r["os_kind"], r["os_version"], r["manager"]
        )
        if eco is None or distro is None or release is None:
            unsupported.setdefault(key, reason)
            continue
        arch = feeds.dpkg_arch(r["arch"])
        mkey = (distro, release, arch)
        if mkey not in srcmaps:
            srcmaps[mkey] = await _source_map(distro, release, arch, res)
        sources, epochs = srcmaps[mkey]
        source = sources.get(key[0]) or _FALLBACK_SOURCES.get(key[0], key[0])
        qver = query_version(key[1])
        if ":" not in qver and key[0] in epochs:
            # Recorded without its epoch (a hand-transcribed commission);
            # restore it from the release index before comparing.
            qver = f"{epochs[key[0]]}:{qver}"
        targets[key] = (eco, source, qver)
        unsupported.pop(key, None)
    res.packages_considered = len(
        {(str(r["name"]), str(r["version"] or "")) for r in rows}
    )
    for reason in unsupported.values():
        res.unsupported[reason] = res.unsupported.get(reason, 0) + 1

    # One OSV query per distinct (ecosystem, source, version).
    queries: dict[tuple[str, str, str], list[tuple[str, str]]] = defaultdict(list)
    for key, q in targets.items():
        queries[q].append(key)
    qlist = list(queries)
    ids_per_query = await asyncio.to_thread(
        feeds.osv_querybatch,
        [{"package": {"name": s, "ecosystem": e}, "version": v} for (e, s, v) in qlist],
    )
    all_ids = sorted({i for ids in ids_per_query for i in ids})
    if len(all_ids) > inp.max_vulnerabilities:
        res.errors.append(
            f"{len(all_ids)} advisories exceed max_vulnerabilities="
            f"{inp.max_vulnerabilities}; only the first were recorded"
        )
        all_ids = all_ids[: inp.max_vulnerabilities]
    records = await asyncio.to_thread(feeds.osv_vulns, all_ids)
    good = {k: v for k, v in records.items() if isinstance(v, dict)}
    for vid, err in records.items():
        if not isinstance(err, dict):
            res.errors.append(f"{vid}: {err}")

    vuln_rows: dict[str, dict[str, Any]] = {}
    edge_rows: list[dict[str, Any]] = []
    pkg_rows: list[dict[str, Any]] = []
    for (eco, source, qver), ids in zip(qlist, ids_per_query, strict=True):
        keys = queries[(eco, source, qver)]
        levels: list[str] = []
        fixable = 0
        kept: list[str] = []
        for vid in ids:
            rec = good.get(vid)
            if rec is None:
                continue
            fixed, urgency = fixed_version(rec, source, eco)
            props = vuln_props(rec, urgency)
            prior = vuln_rows.get(vid)
            if (
                prior is None
                or LEVEL_RANK[props["severity"]] < LEVEL_RANK[prior["severity"]]
            ):
                vuln_rows[vid] = props
            levels.append(props["severity"])
            fixable += 1 if fixed else 0
            kept.append(vid)
            for name, version in keys:
                edge_rows.append(
                    {
                        "name": name,
                        "version": version,
                        "id": vid,
                        "props": flat(
                            {
                                "fixed_version": fixed,
                                "fix_available": bool(fixed),
                                "ecosystem": eco,
                                "source_package": source,
                                "urgency": urgency,
                                "severity": props["severity"],
                                "source": "osv.dev",
                            }
                        ),
                    }
                )
        for name, version in keys:
            pkg_rows.append(
                {
                    "name": name,
                    "version": version,
                    "ids": kept,
                    "props": flat(
                        {
                            "vuln_status": "checked",
                            "vuln_ecosystem": eco,
                            "source_package": source,
                            "vuln_count": len(kept),
                            "vuln_max_severity": max_level(levels) if kept else "none",
                            "vuln_fixable": fixable,
                            "vuln_note": "",
                        }
                    ),
                }
            )
    for (name, version), reason in unsupported.items():
        pkg_rows.append(
            {
                "name": name,
                "version": version,
                "ids": None,
                "props": {"vuln_status": "unsupported", "vuln_note": reason},
            }
        )

    await write_rows(
        "UNWIND $rows AS row MERGE (v:Vulnerability {id: row.id}) "
        f"SET v += row, v.checked_at = datetime(), {prov('v')}",
        list(vuln_rows.values()),
        c,
    )
    await write_rows(
        "UNWIND $rows AS row "
        "MATCH (p:Package {name: row.name, version: row.version}), "
        "(v:Vulnerability {id: row.id}) "
        "MERGE (p)-[r:AFFECTED_BY]->(v) "
        f"SET r += row.props, r.last_seen_at = datetime(), {prov('r')}",
        edge_rows,
        c,
    )
    await write_rows(
        "UNWIND $rows AS row MATCH (p:Package {name: row.name, version: row.version}) "
        f"SET p += row.props, p.vuln_checked_at = datetime(), {prov('p')}",
        pkg_rows,
        c,
    )
    stale = await write_rows(
        "UNWIND $rows AS row "
        "MATCH (p:Package {name: row.name, version: row.version})"
        "-[r:AFFECTED_BY]->(v:Vulnerability) "
        "WHERE row.ids IS NULL OR NOT v.id IN row.ids DELETE r",
        [
            {"name": p["name"], "version": p["version"], "ids": p["ids"]}
            for p in pkg_rows
        ],
        c,
    )
    await write(
        "MATCH (h:Host)-[:HAS_PACKAGE]->(:Package) "
        "WHERE $host IS NULL OR h.node_id = $host "
        "WITH DISTINCT h "
        "OPTIONAL MATCH (h)-[:HAS_PACKAGE]->(:Package)"
        "-[r:AFFECTED_BY]->(v:Vulnerability) "
        "WITH h, collect(DISTINCT v) AS vs, "
        "collect(DISTINCT CASE WHEN r.fix_available THEN v.id END) AS fx "
        "SET h.vuln_count = size(vs), "
        "h.vuln_critical = size([x IN vs WHERE x.severity = 'critical']), "
        "h.vuln_high = size([x IN vs WHERE x.severity = 'high']), "
        "h.vuln_medium = size([x IN vs WHERE x.severity = 'medium']), "
        "h.vuln_low = size([x IN vs WHERE x.severity IN ['low', 'negligible']]), "
        "h.vuln_fixable = size(fx), h.vuln_checked_at = datetime(), " + prov("h"),
        {"host": inp.host_node_id},
        c,
    )

    res.packages_checked = len(targets)
    res.vulnerabilities = len(vuln_rows)
    res.affected_by_edges = len(edge_rows)
    res.stale_edges_removed = stale.get("relationships_deleted", 0)
    for v in vuln_rows.values():
        res.by_severity[v["severity"]] = res.by_severity.get(v["severity"], 0) + 1
    res.fixable = len({e["id"] for e in edge_rows if e["props"].get("fix_available")})
    res.hosts = await read(
        "MATCH (h:Host) WHERE h.vuln_checked_at IS NOT NULL "
        "AND ($host IS NULL OR h.node_id = $host) "
        "RETURN h.name AS host, h.vuln_count AS vulns, h.vuln_critical AS critical, "
        "h.vuln_high AS high, h.vuln_fixable AS fixable ORDER BY h.name",
        {"host": inp.host_node_id},
    )
    ranked = sorted(
        (e for e in edge_rows),
        key=lambda e: (
            LEVEL_RANK[vuln_rows[e["id"]]["severity"]],
            -float(vuln_rows[e["id"]].get("cvss_score") or 0),
        ),
    )
    seen: set[str] = set()
    for e in ranked:
        if e["id"] in seen:
            continue
        seen.add(e["id"])
        v = vuln_rows[e["id"]]
        res.top.append(
            flat(
                {
                    "id": e["id"],
                    "cves": v.get("cves"),
                    "severity": v["severity"],
                    "cvss": v.get("cvss_score"),
                    "package": f"{e['name']} {e['version']}",
                    "fixed_version": e["props"].get("fixed_version") or "unfixed",
                }
            )
        )
        if len(res.top) >= 10:
            break
    return res


async def _source_map(
    distro: str, release: str, arch: str, res: EnrichVulnerabilitiesResult
) -> tuple[dict[str, str], dict[str, str]]:
    label = f"{distro}:{release}:{arch}"
    try:
        codename = await asyncio.to_thread(feeds.distro_codename, distro, release)
        if not codename:
            raise feeds.FeedError(f"unknown {distro} release {release}")
        m, epochs = await asyncio.to_thread(feeds.package_index, distro, codename, arch)
        res.source_maps[label] = f"{codename} Packages index ({len(m)} binaries)"
        return m, epochs
    except feeds.FeedError as exc:
        res.source_maps[label] = f"built-in fallback table ({exc})"
        res.errors.append(f"binary->source map for {label}: {exc}")
        return {}, {}
