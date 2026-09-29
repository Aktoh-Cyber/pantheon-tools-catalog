"""Public-feed clients for the librarian's enrichers (v0.3.0).

The enrichers run in the tenant container, next to the graph store, which has
internet egress. Customer nodes never call these feeds: the node reports what
it has (package-inventory, socket-inventory), and the tenant looks it up. So a
node needs no third-party egress and no node release to change a feed.

Feeds, all free and key-less by default:

- OSV (https://api.osv.dev): vulnerabilities by (ecosystem, package, version).
- endoflife.date (https://endoflife.date/api/<product>.json): release cycles.
- Debian / Ubuntu ``Packages.xz`` indexes: binary package -> source package.
  OSV's Debian and Ubuntu records are keyed by SOURCE package (``openssl``,
  ``glibc``), while a node lists BINARY packages (``libssl3``, ``libc6``);
  without this map most packages would silently match nothing.
- abuse.ch ThreatFox ``export/json/recent`` (last 48 h) and Feodo Tracker's
  C2 IP blocklist. ThreatFox's API (a wider window) needs an abuse.ch
  Auth-Key: put it in ``$LIBRARIAN_STATE_DIR/threatfox-auth-key`` (0600; on a
  pantheon tenant ``/opt/data/graph/threatfox-auth-key``) or the
  ``THREATFOX_AUTH_KEY`` env of the librarian-tools server, and the API
  replaces the export. The file keeps the key out of agent-readable config.

Responses are cached under ``$LIBRARIAN_STATE_DIR/feeds`` (in-process only when
that is unset), so a re-run inside the TTL makes no network calls.

Every call is HTTPS to a fixed host; ``_open`` is the single network seam and
tests replace it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import lzma
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

log = logging.getLogger("librarian-feeds")

USER_AGENT = "pantheon-librarian-tools/0.3 (+https://aktohcyber.com)"
OSV_API = "https://api.osv.dev/v1"
EOL_API = "https://endoflife.date/api"
THREATFOX_EXPORT = "https://threatfox.abuse.ch/export/json/recent/"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
FEODO_JSON = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

_ALLOWED_HOSTS = frozenset(
    {
        "api.osv.dev",
        "endoflife.date",
        "deb.debian.org",
        "archive.ubuntu.com",
        "ports.ubuntu.com",
        "threatfox.abuse.ch",
        "threatfox-api.abuse.ch",
        "feodotracker.abuse.ch",
    }
)

_mem_cache: dict[str, tuple[float, bytes]] = {}
_mem_lock = threading.Lock()


class FeedError(RuntimeError):
    """A feed could not be read. The message names the feed and the reason."""


# --- network seam ------------------------------------------------------------


def _open(
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> bytes:
    """HTTPS GET/POST to an allow-listed feed host. Replaced in tests."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_HOSTS:
        raise FeedError(f"refusing non-allow-listed feed URL: {url}")
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json, */*"}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdrs)
    try:
        # Scheme and host are checked against the allow-list above.
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            body: bytes = resp.read()
            return body
    except urllib.error.HTTPError as exc:
        raise FeedError(f"{parsed.hostname}: HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FeedError(f"{parsed.hostname}: {exc}") from exc


# --- cache -------------------------------------------------------------------


def _cache_dir() -> Path | None:
    raw = os.environ.get("LIBRARIAN_STATE_DIR", "").strip()
    return Path(raw) / "feeds" if raw else None


def cached_fetch(
    key: str,
    ttl_seconds: float,
    fetch: Callable[[], bytes],
) -> bytes:
    """Return a cached body for ``key`` younger than ``ttl_seconds``, else
    call ``fetch`` and cache its result. A failed fetch falls back to a stale
    cached copy (logged), because a stale feed beats none; with no copy the
    error propagates."""
    digest = hashlib.sha256(key.encode()).hexdigest()[:32]
    now = time.time()
    with _mem_lock:
        hit = _mem_cache.get(digest)
    if hit and now - hit[0] < ttl_seconds:
        return hit[1]
    cdir = _cache_dir()
    path = cdir / f"{digest}.bin" if cdir else None
    if path is not None and path.is_file():
        age = now - path.stat().st_mtime
        if age < ttl_seconds:
            body = path.read_bytes()
            with _mem_lock:
                _mem_cache[digest] = (now - age, body)
            return body
    try:
        body = fetch()
    except FeedError:
        if path is not None and path.is_file():
            log.warning("feed fetch failed for %s; using the stale cached copy", key)
            return path.read_bytes()
        if hit:
            return hit[1]
        raise
    with _mem_lock:
        _mem_cache[digest] = (now, body)
    if path is not None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(body)
            os.replace(tmp, path)
        except OSError as exc:
            log.warning("feed cache write failed for %s: %s", key, exc)
    return body


def clear_memory_cache() -> None:
    with _mem_lock:
        _mem_cache.clear()


def _json(body: bytes, feed: str) -> Any:
    try:
        return json.loads(body)
    except ValueError as exc:
        raise FeedError(f"{feed}: response is not JSON ({exc})") from exc


# --- OSV ---------------------------------------------------------------------

OSV_BATCH = 500


def osv_querybatch(queries: list[dict[str, Any]]) -> list[list[str]]:
    """Vulnerability ids per query, in order. Follows per-query page tokens.

    ``queries`` items: ``{"package": {"name", "ecosystem"}, "version"}``."""
    out: list[list[str]] = []
    for start in range(0, len(queries), OSV_BATCH):
        chunk = queries[start : start + OSV_BATCH]
        body = _open(
            f"{OSV_API}/querybatch",
            data=json.dumps({"queries": chunk}).encode(),
            timeout=60,
        )
        results = _json(body, "osv querybatch").get("results") or []
        if len(results) != len(chunk):
            raise FeedError(
                f"osv querybatch: {len(results)} results for {len(chunk)} queries"
            )
        for q, r in zip(chunk, results, strict=True):
            ids = [v["id"] for v in (r.get("vulns") or []) if v.get("id")]
            token = r.get("next_page_token")
            pages = 0
            while token and pages < 20:
                pages += 1
                more = _json(
                    _open(
                        f"{OSV_API}/query",
                        data=json.dumps({**q, "page_token": token}).encode(),
                        timeout=60,
                    ),
                    "osv query",
                )
                ids += [v["id"] for v in (more.get("vulns") or []) if v.get("id")]
                token = more.get("next_page_token")
            out.append(sorted(set(ids)))
    return out


def osv_vuln(vuln_id: str) -> dict[str, Any]:
    """Full OSV record, cached for a day."""
    safe = urllib.parse.quote(vuln_id, safe="")

    def fetch() -> bytes:
        return _open(f"{OSV_API}/vulns/{safe}", timeout=30)

    data = _json(cached_fetch(f"osv:{vuln_id}", 86400, fetch), f"osv {vuln_id}")
    if not isinstance(data, dict):
        raise FeedError(f"osv {vuln_id}: unexpected record shape")
    return data


def osv_vulns(ids: Iterable[str], workers: int = 16) -> dict[str, dict[str, Any] | str]:
    """Fetch many records concurrently. Values are the record, or an error
    string for an id that could not be read (never silently dropped)."""
    uniq = sorted(set(ids))
    out: dict[str, dict[str, Any] | str] = {}

    def one(vid: str) -> tuple[str, dict[str, Any] | str]:
        try:
            return vid, osv_vuln(vid)
        except FeedError as exc:
            return vid, str(exc)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for vid, rec in pool.map(one, uniq):
            out[vid] = rec
    return out


# --- endoflife.date ----------------------------------------------------------


def eol_cycles(product: str) -> list[dict[str, Any]]:
    """All release cycles of a product, cached for a day."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", product):
        raise FeedError(f"endoflife.date: bad product name {product!r}")

    def fetch() -> bytes:
        return _open(f"{EOL_API}/{product}.json", timeout=30)

    data = _json(cached_fetch(f"eol:{product}", 86400, fetch), f"endoflife {product}")
    if not isinstance(data, list):
        raise FeedError(f"endoflife.date {product}: unexpected shape")
    return [c for c in data if isinstance(c, dict)]


# --- Debian / Ubuntu binary -> source package map ----------------------------

# Static fallbacks used only when the endoflife.date lookup cannot name a
# release's codename.
_DEBIAN_CODENAMES = {
    "10": "buster",
    "11": "bullseye",
    "12": "bookworm",
    "13": "trixie",
    "14": "forky",
}
_UBUNTU_CODENAMES = {
    "20.04": "focal",
    "22.04": "jammy",
    "24.04": "noble",
    "24.10": "oracular",
    "25.04": "plucky",
    "25.10": "questing",
}
_DPKG_ARCH = {
    "aarch64": "arm64",
    "arm64": "arm64",
    "x86_64": "amd64",
    "amd64": "amd64",
    "armv7l": "armhf",
    "armv7": "armhf",
    "i686": "i386",
    "i386": "i386",
}


def dpkg_arch(arch: str | None) -> str:
    return _DPKG_ARCH.get((arch or "").lower(), "amd64")


def distro_codename(distro: str, version: str) -> str | None:
    """``debian``/``12`` -> ``bookworm``; ``ubuntu``/``24.04`` -> ``noble``."""
    static = _DEBIAN_CODENAMES if distro == "debian" else _UBUNTU_CODENAMES
    try:
        for c in eol_cycles(distro):
            if str(c.get("cycle")) == version and c.get("codename"):
                return str(c["codename"]).split()[0].lower()
    except FeedError as exc:
        log.warning("codename lookup via endoflife.date failed: %s", exc)
    return static.get(version)


def _packages_urls(distro: str, codename: str, arch: str) -> list[str]:
    if distro == "debian":
        return [
            f"https://deb.debian.org/debian/dists/{codename}/main/binary-{arch}/Packages.xz"
        ]
    base = (
        "https://archive.ubuntu.com/ubuntu"
        if arch in ("amd64", "i386")
        else "https://ports.ubuntu.com/ubuntu-ports"
    )
    return [
        f"{base}/dists/{codename}/{comp}/binary-{arch}/Packages.xz"
        for comp in ("main", "universe")
    ]


def parse_packages_index(text: bytes) -> tuple[dict[str, str], dict[str, str]]:
    """``Package:``/``Source:``/``Version:`` stanzas -> ({binary: source},
    {binary: epoch}). A stanza without ``Source:`` builds from a source of the
    same name and is omitted; ``Source: name (version)`` keeps the name only.
    Epochs (``Version: 1:1.2.13.dfsg-1``) are kept so a version recorded
    without its epoch can be compared correctly: ``1.2.13`` sorts BELOW
    ``1:1.2.8`` in Debian order, which would report long-fixed advisories."""
    sources: dict[str, str] = {}
    epochs: dict[str, str] = {}
    pkg: str | None = None
    for line in text.split(b"\n"):
        if line.startswith(b"Package: "):
            pkg = line[9:].decode("utf-8", "replace").strip()
        elif line.startswith(b"Source: ") and pkg:
            src = line[8:].decode("utf-8", "replace").strip().split(" ", 1)[0]
            if src and src != pkg:
                sources[pkg] = src
        elif line.startswith(b"Version: ") and pkg:
            ver = line[9:].decode("utf-8", "replace").strip()
            epoch, sep, _ = ver.partition(":")
            if sep and epoch.isdigit() and epoch != "0":
                epochs[pkg] = epoch
        elif not line.strip():
            pkg = None
    return sources, epochs


def package_index(
    distro: str, codename: str, arch: str
) -> tuple[dict[str, str], dict[str, str]]:
    """({binary: source}, {binary: epoch}) for one release + architecture,
    cached for a week as compact JSON (not the 50 MB index)."""
    key = f"pkgindex:v2:{distro}:{codename}:{arch}"

    def fetch() -> bytes:
        sources: dict[str, str] = {}
        epochs: dict[str, str] = {}
        for url in _packages_urls(distro, codename, arch):
            raw = _open(url, timeout=120)
            try:
                s, e = parse_packages_index(lzma.decompress(raw))
            except lzma.LZMAError as exc:
                raise FeedError(f"{url}: not an xz Packages index ({exc})") from exc
            sources.update(s)
            epochs.update(e)
        return json.dumps({"s": sources, "e": epochs}, separators=(",", ":")).encode()

    data = _json(cached_fetch(key, 7 * 86400, fetch), key)
    if not isinstance(data, dict):
        return {}, {}
    s, e = data.get("s") or {}, data.get("e") or {}
    return (
        {str(k): str(v) for k, v in s.items()},
        {str(k): str(v) for k, v in e.items()},
    )


# --- IOC feeds ---------------------------------------------------------------

DEFAULT_IOC_FEEDS = ("threatfox-recent", "feodo")


def threatfox_key() -> str:
    """The abuse.ch Auth-Key: env ``THREATFOX_AUTH_KEY``, else the
    ``threatfox-auth-key`` file in the state dir; "" when neither is set."""
    key = os.environ.get("THREATFOX_AUTH_KEY", "").strip()
    if key:
        return key
    raw = os.environ.get("LIBRARIAN_STATE_DIR", "").strip()
    if raw:
        try:
            return (Path(raw) / "threatfox-auth-key").read_text().strip()
        except OSError:
            return ""
    return ""


def configured_ioc_feeds() -> list[str]:
    raw = os.environ.get("LIBRARIAN_IOC_FEEDS", "").strip()
    feeds = (
        [f.strip() for f in raw.split(",") if f.strip()]
        if raw
        else list(DEFAULT_IOC_FEEDS)
    )
    # A ThreatFox key widens the window from the 48 h export to 7 days of API.
    if threatfox_key():
        feeds = ["threatfox-api" if f == "threatfox-recent" else f for f in feeds]
    return feeds


def _ioc(value: str, ioc_type: str, feed: str, **extra: Any) -> dict[str, Any]:
    return {"value": value, "type": ioc_type, "feed": feed, **extra}


def _normalize_threatfox(
    entries: Iterable[dict[str, Any]], feed: str
) -> list[dict[str, Any]]:
    out = []
    for e in entries:
        value = str(e.get("ioc_value") or e.get("ioc") or "").strip()
        ioc_type = str(e.get("ioc_type") or "").strip()
        if not value or not ioc_type:
            continue
        if ioc_type == "ip:port":
            value, ioc_type = value.rsplit(":", 1)[0].strip("[]"), "ip"
        elif ioc_type == "url":
            host = urllib.parse.urlparse(value).hostname
            if host:
                out.append(
                    _ioc(
                        host.lower(),
                        "domain",
                        feed,
                        threat_type=e.get("threat_type"),
                        malware=e.get("malware_printable") or e.get("malware"),
                        confidence=e.get("confidence_level"),
                        first_seen=e.get("first_seen_utc") or e.get("first_seen"),
                        reference=e.get("reference"),
                        via="url",
                    )
                )
            continue
        elif ioc_type in ("md5_hash", "sha256_hash", "sha1_hash"):
            ioc_type = ioc_type.replace("_hash", "")
        out.append(
            _ioc(
                value.lower(),
                ioc_type,
                feed,
                threat_type=e.get("threat_type"),
                malware=e.get("malware_printable") or e.get("malware"),
                confidence=e.get("confidence_level"),
                first_seen=e.get("first_seen_utc") or e.get("first_seen"),
                reference=e.get("reference"),
            )
        )
    return out


def load_ioc_feed(feed: str) -> list[dict[str, Any]]:
    """Normalised indicators: ``{value, type (ip|domain|md5|sha1|sha256),
    feed, threat_type?, malware?, confidence?, first_seen?, reference?}``."""
    if feed == "threatfox-recent":
        body = cached_fetch(feed, 3600, lambda: _open(THREATFOX_EXPORT, timeout=120))
        data = _json(body, feed)
        if not isinstance(data, dict):
            raise FeedError(f"{feed}: unexpected shape")
        entries = [
            e for group in data.values() if isinstance(group, list) for e in group
        ]
        return _normalize_threatfox(entries, feed)
    if feed == "threatfox-api":
        key = threatfox_key()
        if not key:
            raise FeedError(
                "threatfox-api needs an abuse.ch Auth-Key (THREATFOX_AUTH_KEY, "
                "or the threatfox-auth-key file in LIBRARIAN_STATE_DIR)"
            )
        body = cached_fetch(
            feed,
            3600,
            lambda: _open(
                THREATFOX_API,
                data=json.dumps({"query": "get_iocs", "days": 7}).encode(),
                headers={"Auth-Key": key},
                timeout=120,
            ),
        )
        data = _json(body, feed)
        if data.get("query_status") != "ok":
            raise FeedError(f"{feed}: query_status={data.get('query_status')}")
        return _normalize_threatfox(data.get("data") or [], feed)
    if feed == "feodo":
        data = _json(
            cached_fetch(feed, 3600, lambda: _open(FEODO_JSON, timeout=60)), feed
        )
        if not isinstance(data, list):
            raise FeedError(f"{feed}: unexpected shape")
        return [
            _ioc(
                str(e["ip_address"]),
                "ip",
                feed,
                threat_type="botnet_cc",
                malware=e.get("malware"),
                first_seen=e.get("first_seen"),
                reference="https://feodotracker.abuse.ch/",
            )
            for e in data
            if isinstance(e, dict) and e.get("ip_address")
        ]
    raise FeedError(
        f"unknown IOC feed {feed!r} (known: threatfox-recent, threatfox-api, feodo)"
    )
