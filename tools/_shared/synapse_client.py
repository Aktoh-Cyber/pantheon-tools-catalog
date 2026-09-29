"""Minimal Synapse v2 client for ``librarian.collect_inventory``.

Why the librarian calls Synapse itself: a sweep's inventory is large (91 apt
packages on one node, 254 Homebrew packages on another, dozens of sockets).
Relayed through an agent's reply, it gets truncated and altered. The 09-28
aktoh sweep landed 15 of 91 packages, with Debian epochs dropped. The tool
reads the node's output from Synapse and writes it to the graph with no LLM in
between.

Identity: the LIBRARIAN profile's own Synapse agent token, the one its
``synapse`` MCP server already presents (``/opt/data/profiles/librarian/.env``
-> ``SYNAPSE_AGENT_JWT``). It is read at call time, never logged, and never
returned. Cedar governs every invoke exactly as it does for the agent. Only
the fixed, read-only inventory tools are called (see ``collect_inventory``).

Overrides: ``LIBRARIAN_SYNAPSE_URL`` (default: the ``SYNAPSE_GATEWAY_URL``
env, else ``https://synapse.aktohcyber.com``) and ``LIBRARIAN_SYNAPSE_ENV``
(the .env file holding the token).
"""

from __future__ import annotations

import base64
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

DEFAULT_URL = "https://synapse.aktohcyber.com"
DEFAULT_ENV_FILE = "/opt/data/profiles/librarian/.env"


class SynapseError(RuntimeError):
    """A Synapse call failed. The message never contains the token."""


def _token_from_env_file(path: Path) -> str | None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    m = re.search(r"^SYNAPSE_AGENT_JWT=['\"]?([A-Za-z0-9_\-\.]+)", text, re.M)
    return m.group(1) if m else None


def _claims(token: str) -> dict[str, Any]:
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        data = json.loads(base64.urlsafe_b64decode(part))
    except (IndexError, ValueError) as exc:
        raise SynapseError("the Synapse agent token is not a JWT") from exc
    return data if isinstance(data, dict) else {}


class SynapseClient:
    def __init__(self, url: str, token: str, tenant: str) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise SynapseError(f"refusing non-https Synapse URL {url!r}")
        self.url = url.rstrip("/")
        self._token = token
        self.tenant = tenant

    @classmethod
    def from_environment(cls) -> SynapseClient:
        url = (
            os.environ.get("LIBRARIAN_SYNAPSE_URL")
            or os.environ.get("SYNAPSE_GATEWAY_URL")
            or DEFAULT_URL
        ).strip()
        token = os.environ.get("SYNAPSE_AGENT_JWT", "").strip() or _token_from_env_file(
            Path(os.environ.get("LIBRARIAN_SYNAPSE_ENV", DEFAULT_ENV_FILE))
        )
        if not token:
            raise SynapseError(
                "no Synapse agent token: the librarian profile's .env has no "
                "SYNAPSE_AGENT_JWT (set LIBRARIAN_SYNAPSE_ENV to its path)"
            )
        tenant = str(_claims(token).get("tenant_id") or "").strip()
        if not tenant:
            raise SynapseError("the Synapse agent token names no tenant_id")
        return cls(url, token, tenant)

    # -- transport ----------------------------------------------------------

    def _request(self, path: str, body: dict[str, Any] | None, timeout: float) -> Any:
        req = urllib.request.Request(
            f"{self.url}{path}",
            data=json.dumps(body).encode() if body is not None else None,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "User-Agent": "pantheon-librarian-tools/0.3",
            },
        )
        try:
            # https-only, checked in __init__.
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read()[:300].decode("utf-8", "replace")
            raise SynapseError(f"Synapse {path}: HTTP {exc.code} {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise SynapseError(f"Synapse {path}: {exc}") from exc

    def mcp(self, method: str, params: dict[str, Any], timeout: float = 60) -> Any:
        body = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": params,
        }
        data = self._request("/v2/mcp", body, timeout)
        if not isinstance(data, dict):
            raise SynapseError(f"{method}: malformed JSON-RPC reply")
        if data.get("error"):
            err = data["error"]
            msg = err.get("message") if isinstance(err, dict) else err
            raise SynapseError(f"{method}: {msg}")
        return data.get("result")

    # -- API ----------------------------------------------------------------

    def nodes(self) -> list[dict[str, Any]]:
        data = self._request(f"/v2/reports/nodes/{self.tenant}?limit=200", None, 30)
        rows = data if isinstance(data, list) else (data or {}).get("nodes") or []
        return [r for r in rows if isinstance(r, dict)]

    def tools(self) -> list[dict[str, Any]]:
        res = self.mcp("synapse.list_tools", {"tenant_id": self.tenant, "limit": 500})
        rows = (res or {}).get("tools") if isinstance(res, dict) else res
        return [r for r in (rows or []) if isinstance(r, dict)]

    def invoke(
        self, node_id: str, digest: str, args: dict[str, Any], deadline: int = 120
    ) -> dict[str, Any]:
        """-> the node's result (``exit_kind``, ``exit_code``, ``inline_output``)."""
        res = self.mcp(
            "synapse.invoke",
            {
                "tenant_id": self.tenant,
                "node_id": node_id,
                "tool_digest": digest,
                "args": args,
                "deadline_seconds": deadline,
            },
            timeout=deadline + 30,
        )
        result = (res or {}).get("result") if isinstance(res, dict) else None
        if not isinstance(result, dict):
            raise SynapseError("synapse.invoke returned no result (node unreachable?)")
        return result


def candidate_digests(tools: list[dict[str, Any]], name: str) -> list[str]:
    """Digests to try for a tool name, best first: catalog releases (the
    current published ones, auto-registered by wasm-publish) before older
    tenant uploads, newest registration first. A node too old for the newest
    release (a new host import) falls through to the next candidate."""
    rows = [t for t in tools if t.get("tool_name") == name and t.get("tool_digest")]
    rows.sort(
        key=lambda t: (t.get("source") == "catalog", str(t.get("uploaded_at") or "")),
        reverse=True,
    )
    out: list[str] = []
    for t in rows:
        d = str(t["tool_digest"])
        if d not in out:
            out.append(d)
    return out
