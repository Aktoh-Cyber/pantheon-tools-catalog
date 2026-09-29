"""librarian.enrich_eol: end-of-life status for hosts' OS releases and runtimes.

Looks up https://endoflife.date (free, no key) for:

- each Host's OS release, from its ``os_kind`` / ``os_version`` (Debian,
  Ubuntu, Alpine, macOS; RHEL-family and Windows hosts do not carry enough to
  name a release cycle and are reported as skipped);
- runtimes and libraries among its packages whose upstream publishes a
  lifecycle: python, nodejs, openssl, perl, php, ruby, go, postgresql,
  mysql, mariadb, redis, nginx, apache.

Writes EOL status properties on the Host (its OS) and on each mapped Package:
``eol_product``, ``eol_cycle``, ``eol_status``, ``eol_date``,
``eol_support_end``, ``eol_extended``, ``eol_latest``, ``eol_checked_at``.

``eol_status`` is one of:
- ``supported``: in active support;
- ``security-only``: active support ended, security fixes continue (e.g. a
  Debian release in LTS);
- ``eol-soon``: security support ends within 90 days;
- ``extended-support-only``: security support ended; only paid extended
  support remains;
- ``eol``: no support at all.

Each ``eol``, ``extended-support-only`` and ``eol-soon`` item also becomes a
``Finding`` (key ``<host>|eol|<product>-<cycle>``, tool ``eol``) linked
``(Host)-[:HAS_FINDING]->``. A package the host's distro maintains (apt) is
marked lower severity: the distro backports security fixes while the release
is supported. A finding that no longer applies is kept with result
``RESOLVED``.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import re
from typing import Any

from pydantic import BaseModel, Field

from tools._shared import feeds, write_journal
from tools._shared.graph_batch import Commission, flat, prov, read, write, write_rows

TOOL = "librarian.enrich_eol"
SOON_DAYS = 90

# (name regex, product, where the cycle comes from: "name" = group 1,
# "version" = the package version)
_PACKAGE_PRODUCTS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(p), prod, src)
    for p, prod, src in [
        (r"^python(3\.\d+)(?:-minimal)?$", "python", "name"),
        (r"^libpython(3\.\d+)(?:-minimal|-stdlib)?$", "python", "name"),
        (r"^python@(3\.\d+)$", "python", "name"),
        (r"^python3$", "python", "version"),
        (r"^nodejs$", "nodejs", "version"),
        (r"^node$", "nodejs", "version"),
        (r"^node@(\d+)$", "nodejs", "name"),
        (r"^openssl$", "openssl", "version"),
        (r"^libssl(?:3|3t64|1\.1)$", "openssl", "version"),
        (r"^openssl@(?:3|1\.1)$", "openssl", "version"),
        (r"^perl$", "perl", "version"),
        (r"^perl-base$", "perl", "version"),
        (r"^php(\d\.\d)(?:-cli|-fpm|-common)?$", "php", "name"),
        (r"^php@(\d\.\d)$", "php", "name"),
        (r"^php$", "php", "version"),
        (r"^ruby(\d\.\d)$", "ruby", "name"),
        (r"^ruby@(\d\.\d)$", "ruby", "name"),
        (r"^ruby$", "ruby", "version"),
        (r"^golang-(1\.\d+)(?:-go)?$", "go", "name"),
        (r"^go@(1\.\d+)$", "go", "name"),
        (r"^go$", "go", "version"),
        (r"^postgresql-(\d+)$", "postgresql", "name"),
        (r"^postgresql@(\d+)$", "postgresql", "name"),
        (r"^mariadb-server(?:-core)?$", "mariadb", "version"),
        (r"^mysql-server(?:-core)?(?:-\d\.\d)?$", "mysql", "version"),
        (r"^mysql$", "mysql", "version"),
        (r"^redis(?:-server)?$", "redis", "version"),
        (r"^nginx(?:-core|-light|-full)?$", "nginx", "version"),
        (r"^apache2$", "apache-http-server", "version"),
        (r"^httpd$", "apache-http-server", "version"),
    ]
]


class EnrichEolInput(Commission):
    host_node_id: str | None = Field(
        default=None, description="Only this Host (default: every host)."
    )


class EnrichEolResult(BaseModel):
    feed: str = "endoflife.date"
    hosts_checked: int = 0
    packages_checked: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    resolved_findings: int = 0
    skipped: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class EnrichEolToolResponse(BaseModel):
    ok: bool
    result: EnrichEolResult | None = None
    error: str | None = None
    details: dict[str, Any] | None = None


# --- pure helpers (unit-tested) ----------------------------------------------


def os_product(os_kind: str | None, os_version: str | None) -> tuple[str, str] | str:
    """-> (product, cycle), or a reason string when it cannot be named."""
    kind = (os_kind or "").lower()
    ver = (os_version or "").strip()
    if kind == "linux-debian":
        if re.fullmatch(r"\d{2}\.\d{2}", ver):
            return "ubuntu", ver
        m = re.fullmatch(r"(\d{1,2})(?:\.\d+)*", ver)
        if m:
            return "debian", m.group(1)
        return f"os_version {ver!r} does not name a Debian-family release"
    if kind == "linux-alpine":
        m = re.match(r"(\d+\.\d+)", ver)
        return ("alpine-linux", m.group(1)) if m else f"alpine version {ver!r} unparsed"
    if kind == "macos":
        m = re.match(r"(\d+)(?:\.(\d+))?", ver)
        if not m:
            return f"macOS version {ver!r} unparsed"
        major = int(m.group(1))
        return (
            ("macos", m.group(1)) if major >= 11 else ("macos", f"10.{m.group(2) or 0}")
        )
    if kind == "linux-rhel":
        return "RHEL-family host: os_kind does not say which distribution"
    if kind == "windows" or kind == "":
        return f"no release cycle derivable for os_kind {kind or '?'!r}"
    return f"no endoflife.date mapping for os_kind {kind!r}"


def upstream_version(version: str) -> str:
    """Debian/brew version -> upstream: drop epoch, revision, +dfsg, ~suffix."""
    v = re.sub(r"^\d+:", "", version.strip())
    if "-" in v:
        v = v.rsplit("-", 1)[0]
    return re.split(r"[+~]", v, maxsplit=1)[0]


def package_product(name: str, version: str) -> tuple[str, list[str]] | None:
    """-> (product, candidate cycles, most specific first) or None."""
    for rx, product, src in _PACKAGE_PRODUCTS:
        m = rx.match(name)
        if not m:
            continue
        if src == "name" and m.groups():
            return product, [m.group(1)]
        up = upstream_version(version)
        vm = re.match(r"(\d+)(?:\.(\d+))?", up)
        if not vm:
            return None
        cands = [f"{vm.group(1)}.{vm.group(2)}"] if vm.group(2) is not None else []
        return product, [*cands, vm.group(1)]
    return None


def _date(value: Any) -> dt.date | None:
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value[:10])
        except ValueError:
            return None
    return None


def cycle_status(cycle: dict[str, Any], today: dt.date) -> str:
    eol, sup, ext = cycle.get("eol"), cycle.get("support"), cycle.get("extendedSupport")
    eol_d, sup_d, ext_d = _date(eol), _date(sup), _date(ext)
    eol_reached = eol is True or (eol_d is not None and eol_d <= today)
    if eol_reached:
        ext_active = ext is True or (ext_d is not None and ext_d > today)
        return "extended-support-only" if ext_active else "eol"
    if eol_d is not None and (eol_d - today).days <= SOON_DAYS:
        return "eol-soon"
    if sup_d is not None and sup_d <= today:
        return "security-only"
    return "supported"


def find_cycle(
    cycles: list[dict[str, Any]], candidates: list[str]
) -> dict[str, Any] | None:
    by = {str(c.get("cycle")): c for c in cycles}
    for cand in candidates:
        if cand in by:
            return by[cand]
    return None


def eol_props(product: str, cycle: dict[str, Any], status: str) -> dict[str, Any]:
    def as_text(v: Any) -> str | None:
        if isinstance(v, bool):
            return "yes" if v else "no"
        return str(v) if v is not None else None

    return flat(
        {
            "eol_product": product,
            "eol_cycle": str(cycle.get("cycle")),
            "eol_status": status,
            "eol_date": as_text(cycle.get("eol")),
            "eol_support_end": as_text(cycle.get("support")),
            "eol_extended": as_text(cycle.get("extendedSupport")),
            "eol_latest": as_text(cycle.get("latest")),
            "eol_source": "endoflife.date",
        }
    )


_FINDING_STATUSES = {
    "eol": "EOL",
    "extended-support-only": "EXTENDED_SUPPORT_ONLY",
    "eol-soon": "EOL_SOON",
}


def finding_severity(
    kind: str, status: str, distro_maintained: bool, os_status: str | None
) -> str:
    if kind == "os":
        return {"eol": "high", "extended-support-only": "high", "eol-soon": "medium"}[
            status
        ]
    if distro_maintained and os_status in ("supported", "security-only", "eol-soon"):
        return "low"
    return {"eol": "medium", "extended-support-only": "medium", "eol-soon": "low"}[
        status
    ]


# --- run -----------------------------------------------------------------------


async def run(input: EnrichEolInput) -> EnrichEolToolResponse:
    payload = input.model_dump(mode="json")
    try:
        res = await _run(input)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        details: dict[str, Any] = {"tool": TOOL, "recorded": False}
        pending = write_journal.record_failure(TOOL, error, payload)
        if pending:
            details["pending_id"] = pending
        return EnrichEolToolResponse(ok=False, error=error, details=details)
    write_journal.record_success(TOOL, payload)
    return EnrichEolToolResponse(ok=True, result=res)


async def _cycles(
    product: str, cache: dict[str, list[dict[str, Any]] | str]
) -> list[dict[str, Any]] | str:
    if product not in cache:
        try:
            cache[product] = await asyncio.to_thread(feeds.eol_cycles, product)
        except feeds.FeedError as exc:
            cache[product] = str(exc)
    return cache[product]


async def _run(inp: EnrichEolInput) -> EnrichEolResult:
    c = Commission(commissioned_by=inp.commissioned_by, session_id=inp.session_id)
    res = EnrichEolResult()
    today = dt.datetime.now(dt.UTC).date()
    cache: dict[str, list[dict[str, Any]] | str] = {}
    hosts = await read(
        "MATCH (h:Host) WHERE $host IS NULL OR h.node_id = $host "
        "RETURN h.node_id AS id, coalesce(h.name, h.node_id) AS name, "
        "h.os_kind AS os_kind, h.os_version AS os_version",
        {"host": inp.host_node_id},
    )
    host_rows: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    os_status: dict[str, str] = {}
    for h in hosts:
        mapped = os_product(h["os_kind"], h["os_version"])
        if isinstance(mapped, str):
            res.skipped.append(f"{h['name']}: {mapped}")
            continue
        product, cyc = mapped
        cycles = await _cycles(product, cache)
        if isinstance(cycles, str):
            res.errors.append(f"{product}: {cycles}")
            continue
        cycle = find_cycle(cycles, [cyc])
        if cycle is None:
            res.skipped.append(
                f"{h['name']}: {product} {cyc} is not a cycle endoflife.date lists"
            )
            continue
        status = cycle_status(cycle, today)
        os_status[h["id"]] = status
        res.hosts_checked += 1
        res.by_status[status] = res.by_status.get(status, 0) + 1
        host_rows.append({"id": h["id"], "props": eol_props(product, cycle, status)})
        if status in _FINDING_STATUSES:
            findings.append(_finding(h, "os", product, cycle, status, False, None))

    pkgs = await read(
        "MATCH (h:Host)-[:HAS_PACKAGE]->(p:Package) "
        "WHERE $host IS NULL OR h.node_id = $host "
        "RETURN h.node_id AS id, coalesce(h.name, h.node_id) AS host, "
        "p.name AS name, p.version AS version, coalesce(p.manager, '') AS manager",
        {"host": inp.host_node_id},
    )
    pkg_rows: dict[tuple[str, str], dict[str, Any]] = {}
    seen_findings: set[str] = set()
    for p in pkgs:
        mapped_pkg = package_product(str(p["name"]), str(p["version"] or ""))
        if mapped_pkg is None:
            continue
        product, cands = mapped_pkg
        cycles = await _cycles(product, cache)
        if isinstance(cycles, str):
            res.errors.append(f"{product}: {cycles}")
            continue
        cycle = find_cycle(cycles, cands)
        if cycle is None:
            continue
        status = cycle_status(cycle, today)
        key = (str(p["name"]), str(p["version"] or ""))
        if key not in pkg_rows:
            pkg_rows[key] = {
                "name": key[0],
                "version": key[1],
                "props": eol_props(product, cycle, status),
            }
            res.by_status[status] = res.by_status.get(status, 0) + 1
        if status in _FINDING_STATUSES:
            f = _finding(
                {"id": p["id"], "name": p["host"]},
                "package",
                product,
                cycle,
                status,
                p["manager"] in ("apt", ""),
                os_status.get(p["id"]),
                package=f"{key[0]} {key[1]}",
            )
            if f["key"] not in seen_findings:
                seen_findings.add(f["key"])
                findings.append(f)
    res.packages_checked = len(pkg_rows)

    await write_rows(
        "UNWIND $rows AS row MATCH (h:Host {node_id: row.id}) "
        f"SET h += row.props, h.eol_checked_at = datetime(), {prov('h')}",
        host_rows,
        c,
    )
    await write_rows(
        "UNWIND $rows AS row MATCH (p:Package {name: row.name, version: row.version}) "
        f"SET p += row.props, p.eol_checked_at = datetime(), {prov('p')}",
        list(pkg_rows.values()),
        c,
    )
    await write_rows(
        "UNWIND $rows AS row MATCH (h:Host {node_id: row.host_id}) "
        "MERGE (f:Finding {key: row.key}) "
        f"SET f += row.props, f.last_seen_at = datetime(), {prov('f')} "
        "REMOVE f.resolved_at "
        "MERGE (h)-[r:HAS_FINDING]->(f) "
        f"SET {prov('r')}",
        [
            {"host_id": f["host_id"], "key": f["key"], "props": f["props"]}
            for f in findings
        ],
        c,
    )
    checked_hosts = sorted({h["id"] for h in hosts})
    resolved = await write(
        "MATCH (h:Host)-[:HAS_FINDING]->(f:Finding {tool: 'eol'}) "
        "WHERE h.node_id IN $hosts AND NOT f.key IN $keys AND f.result <> 'RESOLVED' "
        "SET f.result = 'RESOLVED', f.resolved_at = datetime(), " + prov("f"),
        {"hosts": checked_hosts, "keys": [f["key"] for f in findings]},
        c,
    )
    res.resolved_findings = resolved.get("properties_set", 0) // 5
    res.findings = [
        {
            "key": f["key"],
            "severity": f["props"]["severity"],
            "detail": f["props"]["detail"],
        }
        for f in findings
    ]
    return res


def _finding(
    host: dict[str, Any],
    kind: str,
    product: str,
    cycle: dict[str, Any],
    status: str,
    distro_maintained: bool,
    os_status: str | None,
    package: str | None = None,
) -> dict[str, Any]:
    cyc = str(cycle.get("cycle"))
    check = f"{product}-{cyc}"
    eol = cycle.get("eol")
    when = eol if isinstance(eol, str) else "an unpublished date"
    what = f"{product} {cyc}" + (f" (package {package})" if package else "")
    if status == "eol-soon":
        detail = f"{what} reaches end of security support on {when}"
    elif status == "extended-support-only":
        detail = (
            f"{what} reached end of security support on {when}; "
            "only paid extended support remains"
        )
    else:
        detail = f"{what} reached end of life on {when}"
    if kind == "package" and distro_maintained:
        detail += (
            "; the host's distribution still ships security fixes for its "
            "packaged build while the release is supported"
        )
    sev = finding_severity(kind, status, distro_maintained, os_status)
    return {
        "host_id": host["id"],
        "key": f"{host['name']}|eol|{check}",
        "props": flat(
            {
                "tool": "eol",
                "check": check,
                "result": _FINDING_STATUSES[status],
                "severity": sev,
                "detail": detail,
                "category": "end-of-life",
                "subject": "os" if kind == "os" else "package",
                "eol_date": eol if isinstance(eol, str) else None,
                "latest": cycle.get("latest")
                if isinstance(cycle.get("latest"), str)
                else None,
                "source": "endoflife.date",
            }
        ),
    }
