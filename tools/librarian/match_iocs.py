"""librarian.match_iocs: match what the graph has observed against threat intel.

Feeds are pluggable (``feeds`` input, else ``LIBRARIAN_IOC_FEEDS``, default
``threatfox-recent,feodo``), all from abuse.ch:

- ``threatfox-recent``: ThreatFox's key-less export of the last 48 hours
  (IPs, domains, URLs -> their host, file hashes).
- ``feodo``: Feodo Tracker's botnet C2 IP blocklist (key-less).
- ``threatfox-api``: ThreatFox's API, 7 days. It needs an abuse.ch Auth-Key
  (``$LIBRARIAN_STATE_DIR/threatfox-auth-key`` or ``THREATFOX_AUTH_KEY``);
  when one is set it replaces ``threatfox-recent``.

Observables are read from any environment node (not Vulnerability,
Indicator, Finding, ToolGap or Package) property with one of these names:
``ip``, ``ip_address``, ``ips``, ``ip_addresses``, ``addresses``,
``remote_peers`` (Host, from socket-inventory connections), ``binds``
(Service), ``domain``, ``domains``, ``hostname``, ``fqdn``, ``url``, ``urls``,
``md5``, ``sha1``, ``sha256``. Host ``name`` counts as a domain when it looks
like a public FQDN.

A match writes ``Indicator {value, type}`` (feed, threat type, malware,
confidence, first seen, reference), ``(node)-[:MATCHES_IOC {property}]->
(Indicator)``, and a high-severity ``Finding`` (key ``<host>|ioc|<value>``,
tool ``ioc``) on the owning Host. Every checked Host gets
``ioc_checked_at``, ``ioc_feeds`` and ``ioc_match_count``. No match, no
Indicator nodes: the graph is not filled with the whole feed.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Any

from pydantic import BaseModel, Field

from tools._shared import feeds, write_journal
from tools._shared.graph_batch import Commission, flat, prov, read, write, write_rows

TOOL = "librarian.match_iocs"

_IP_KEYS = (
    "ip",
    "ip_address",
    "ips",
    "ip_addresses",
    "addresses",
    "remote_peers",
    "binds",
)
_DOMAIN_KEYS = ("domain", "domains", "hostname", "fqdn")
_URL_KEYS = ("url", "urls")
_HASH_KEYS = ("md5", "sha1", "sha256")
_ALL_KEYS = [*_IP_KEYS, *_DOMAIN_KEYS, *_URL_KEYS, *_HASH_KEYS]
_FQDN = re.compile(r"^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
_LOCAL_SUFFIXES = (".local", ".lan", ".home", ".internal", ".localdomain", ".corp")
# Nodes that describe intel or findings, not the customer's environment: their
# reference URLs (osv.dev, abuse.ch) are not observations.
_SKIP_LABELS = ["Vulnerability", "Indicator", "Finding", "ToolGap", "Package"]


class MatchIocsInput(Commission):
    feeds: list[str] | None = Field(
        default=None,
        description="Feed ids to use (threatfox-recent, feodo, threatfox-api). "
        "Default: LIBRARIAN_IOC_FEEDS, else threatfox-recent + feodo.",
    )


class MatchIocsResult(BaseModel):
    feeds: dict[str, str] = Field(default_factory=dict)
    indicators_loaded: int = 0
    observables: dict[str, int] = Field(default_factory=dict)
    hosts_checked: int = 0
    matches: list[dict[str, Any]] = Field(default_factory=list)
    needs_key: list[str] = Field(default_factory=list)


class MatchIocsToolResponse(BaseModel):
    ok: bool
    result: MatchIocsResult | None = None
    error: str | None = None
    details: dict[str, Any] | None = None


# --- pure helpers (unit-tested) ----------------------------------------------


def _as_list(v: Any) -> list[str]:
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [x for x in v if isinstance(x, str)]
    return []


def normalize_ip(value: str) -> str | None:
    """Public address in canonical form, or None (private, loopback, ...)."""
    v = value.strip().strip("[]").split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if not ip.is_global:
        return None
    return str(ip)


def observables_of(
    props: dict[str, Any], labels: list[str]
) -> list[tuple[str, str, str]]:
    """-> [(type, value, property)] for one node's properties."""
    out: list[tuple[str, str, str]] = []
    for k in _IP_KEYS:
        for v in _as_list(props.get(k)):
            ip = normalize_ip(v)
            if ip:
                out.append(("ip", ip, k))
    for k in _DOMAIN_KEYS:
        for v in _as_list(props.get(k)):
            d = v.strip().lower().rstrip(".")
            if _FQDN.match(d) and not d.endswith(_LOCAL_SUFFIXES):
                out.append(("domain", d, k))
    for k in _URL_KEYS:
        for v in _as_list(props.get(k)):
            m = re.match(r"^[a-z]+://([^/:?#]+)", v.strip().lower())
            if m:
                host = m.group(1)
                ip = normalize_ip(host)
                out.append(("ip", ip, k) if ip else ("domain", host, k))
    for k in _HASH_KEYS:
        for v in _as_list(props.get(k)):
            out.append((k, v.strip().lower(), k))
    if "Host" in labels:
        name = str(props.get("name") or "").strip().lower().rstrip(".")
        if _FQDN.match(name) and not name.endswith(_LOCAL_SUFFIXES):
            out.append(("domain", name, "name"))
    return out


def index_indicators(
    indicators: list[dict[str, Any]],
) -> dict[tuple[str, str], dict[str, Any]]:
    idx: dict[tuple[str, str], dict[str, Any]] = {}
    for i in indicators:
        t, v = str(i.get("type")), str(i.get("value") or "").lower()
        if t == "ip":
            v = normalize_ip(v) or v
        if v and (t, v) not in idx:
            idx[(t, v)] = i
    return idx


def domain_candidates(domain: str) -> list[str]:
    """``a.b.evil.com`` -> itself and its parents down to ``evil.com``."""
    parts = domain.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


# --- run -----------------------------------------------------------------------


async def run(input: MatchIocsInput) -> MatchIocsToolResponse:
    payload = input.model_dump(mode="json")
    try:
        res = await _run(input)
    except feeds.FeedError as exc:
        return MatchIocsToolResponse(
            ok=False, error=f"no IOC feed could be read: {exc}", details={"tool": TOOL}
        )
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        details: dict[str, Any] = {"tool": TOOL, "recorded": False}
        pending = write_journal.record_failure(TOOL, error, payload)
        if pending:
            details["pending_id"] = pending
        return MatchIocsToolResponse(ok=False, error=error, details=details)
    write_journal.record_success(TOOL, payload)
    return MatchIocsToolResponse(ok=True, result=res)


async def _run(inp: MatchIocsInput) -> MatchIocsResult:
    c = Commission(commissioned_by=inp.commissioned_by, session_id=inp.session_id)
    res = MatchIocsResult()
    wanted = inp.feeds or feeds.configured_ioc_feeds()
    indicators: list[dict[str, Any]] = []
    for f in wanted:
        try:
            got = await asyncio.to_thread(feeds.load_ioc_feed, f)
        except feeds.FeedError as exc:
            res.feeds[f] = f"unavailable: {exc}"
            if "Auth-Key" in str(exc):
                res.needs_key.append(f)
            continue
        res.feeds[f] = f"ok ({len(got)} indicators)"
        indicators += got
    if not indicators and all(v.startswith("unavailable") for v in res.feeds.values()):
        raise feeds.FeedError("; ".join(f"{k}: {v}" for k, v in res.feeds.items()))
    idx = index_indicators(indicators)
    res.indicators_loaded = len(idx)

    nodes = await read(
        "MATCH (n) WHERE (any(k IN keys(n) WHERE k IN $keys) OR n:Host) "
        "AND NOT any(l IN labels(n) WHERE l IN $skip) "
        "OPTIONAL MATCH (h:Host)-[*1..1]->(n) "
        "RETURN elementId(n) AS eid, labels(n) AS labels, properties(n) AS props, "
        "CASE WHEN n:Host THEN n.node_id ELSE h.node_id END AS host_id, "
        "CASE WHEN n:Host THEN coalesce(n.name, n.node_id) "
        "ELSE coalesce(h.name, h.node_id) END AS host_name",
        {"keys": _ALL_KEYS, "skip": _SKIP_LABELS},
    )
    matches: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    host_ids: set[str] = set()
    for n in nodes:
        if n.get("host_id"):
            host_ids.add(str(n["host_id"]))
        for otype, value, prop in observables_of(
            n.get("props") or {}, n.get("labels") or []
        ):
            res.observables[otype] = res.observables.get(otype, 0) + 1
            candidates = domain_candidates(value) if otype == "domain" else [value]
            hit = next(
                (idx[(otype, cand)] for cand in candidates if (otype, cand) in idx),
                None,
            )
            if hit is None or (n["eid"], otype, value) in seen:
                continue
            seen.add((n["eid"], otype, value))
            matches.append(
                {
                    "eid": n["eid"],
                    "host_id": n.get("host_id"),
                    "host_name": n.get("host_name"),
                    "observed": value,
                    "property": prop,
                    "type": otype,
                    "indicator": flat(
                        {
                            "value": str(hit["value"]),
                            "type": otype,
                            "feed": hit.get("feed"),
                            "threat_type": hit.get("threat_type"),
                            "malware": hit.get("malware"),
                            "confidence": hit.get("confidence"),
                            "first_seen": hit.get("first_seen"),
                            "reference": hit.get("reference"),
                            "source": "abuse.ch",
                        }
                    ),
                }
            )
    res.hosts_checked = len(host_ids)

    if matches:
        await write_rows(
            "UNWIND $rows AS row "
            "MERGE (i:Indicator "
            "{value: row.indicator.value, type: row.indicator.type}) "
            f"SET i += row.indicator, i.last_matched_at = datetime(), {prov('i')} "
            "WITH i, row MATCH (n) WHERE elementId(n) = row.eid "
            "MERGE (n)-[r:MATCHES_IOC]->(i) "
            f"SET r.property = row.property, r.observed = row.observed, "
            f"r.last_seen_at = datetime(), {prov('r')}",
            matches,
            c,
        )
        await write_rows(
            "UNWIND $rows AS row MATCH (h:Host {node_id: row.host_id}) "
            "MERGE (f:Finding {key: row.key}) "
            f"SET f += row.props, f.last_seen_at = datetime(), {prov('f')} "
            "MERGE (h)-[r:HAS_FINDING]->(f) "
            f"SET {prov('r')}",
            [
                {
                    "host_id": m["host_id"],
                    "key": f"{m['host_name']}|ioc|{m['observed']}",
                    "props": flat(
                        {
                            "tool": "ioc",
                            "check": f"{m['type']}:{m['observed']}",
                            "result": "MATCH",
                            "severity": "high",
                            "category": "threat-intel",
                            "detail": (
                                f"{m['observed']} (seen in {m['property']}) "
                                "is listed by "
                                f"{m['indicator'].get('feed')} as "
                                f"{m['indicator'].get('threat_type') or 'malicious'}"
                                + (
                                    f" ({m['indicator']['malware']})"
                                    if m["indicator"].get("malware")
                                    else ""
                                )
                            ),
                            "source": "abuse.ch",
                        }
                    ),
                }
                for m in matches
                if m.get("host_id")
            ],
            c,
        )
    per_host: dict[str, int] = {}
    for m in matches:
        if m.get("host_id"):
            per_host[str(m["host_id"])] = per_host.get(str(m["host_id"]), 0) + 1
    await write(
        "MATCH (h:Host) WHERE h.node_id IN $hosts "
        "SET h.ioc_checked_at = datetime(), h.ioc_feeds = $feeds, "
        "h.ioc_match_count = coalesce($counts[h.node_id], 0), " + prov("h"),
        {
            "hosts": sorted(host_ids),
            "feeds": [f for f, s in res.feeds.items() if s.startswith("ok")],
            "counts": per_host,
        },
        c,
    )
    res.matches = [
        {
            "host": m.get("host_name"),
            "observed": m["observed"],
            "property": m["property"],
            "feed": m["indicator"].get("feed"),
            "threat_type": m["indicator"].get("threat_type"),
            "malware": m["indicator"].get("malware"),
        }
        for m in matches
    ]
    return res
