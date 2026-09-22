"""Convert a tool's ``tool.toml`` into the Synapse ``ToolManifest`` JSON sidecar.

Each WASM tool in this catalog ships a checked-in ``tool.toml`` declaring the
capabilities it intends to use at runtime (``network_mode`` / ``mounts`` /
``host_apis``). The publish workflows (``wasm-publish`` and ``manifest-backfill``)
run this converter to build the ``sha256-<oci>.manifest`` sidecar they push to
GHCR next to the WASM layer.

The Synapse control plane serves that sidecar at
``GET /v2/catalog/manifests/:digest`` and, since synapse #185, defaults a
lease's capability vector from its ``declared_capabilities`` (synapse #190 then
surfaces the catalog through ``list_tools`` / ``tool_spec``). So a real sidecar
here means every tenant gets correct caps with zero per-tenant ``spec_toml``
uploads.

The output shape is a byte-for-byte match for what
``synapse-proto/src/manifest/tool_toml.rs::from_tool_toml`` produces, so
``serde_json::from_slice::<ToolManifest>`` (``synapse-proto/src/manifest/mod.rs``)
parses it. This module intentionally does NOT depend on the Rust crate; it
replicates the field mapping and validates against the same closed sets.
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from typing import Any

# Canonical host-API ids the Synapse host exposes.
# Source of truth: synapse/crates/synapse-host/src/lib.rs (the `pub const`
# api-id constants). A tool.toml may only declare ids from this set — anything
# else can never be granted by a lease, so it is a publish-time error.
KNOWN_HOST_APIS: frozenset[str] = frozenset(
    {
        "package.query",
        "package.install",
        "package.uninstall",
        "service.restart",
        "service.stop",
        "service.status",
        "service.enable",
        "service.disable",
        "tls.inspect",
        "inventory.list-installed",
        "inventory.os-info",
        "fs.read-file",
        "fs.stat",
        "fs.list-dir",
        "process.list-processes",
        "process.list-sockets",
    }
)

# NetworkMode serializes lowercase in synapse-proto/src/overlay.rs.
NETWORK_MODES: frozenset[str] = frozenset({"none", "http", "direct"})

# Language enum (synapse-proto/src/manifest/mod.rs, serde rename_all=lowercase);
# `go`/`py`/`ts` are accepted aliases by from_tool_toml and normalized here.
_LANGUAGE_ALIASES: dict[str, str] = {
    "rust": "rust",
    "tinygo": "tinygo",
    "go": "tinygo",
    "python": "python",
    "py": "python",
    "typescript": "typescript",
    "ts": "typescript",
}

# entry contract (synapse-proto EntryContract, serde rename_all=snake_case).
_VALID_ENTRIES: frozenset[str] = frozenset({"wasi_cli_run", "wasi-cli-run"})
_ENTRY_CANONICAL = "wasi_cli_run"

SCHEMA_VERSION = 1


class ManifestError(ValueError):
    """A tool.toml is malformed or declares something outside the closed sets."""


def _require_str(table: dict[str, Any], key: str, ctx: str) -> str:
    val = table.get(key)
    if not isinstance(val, str) or not val:
        raise ManifestError(f"{ctx}.{key} must be a non-empty string")
    return val


def _str_list(table: dict[str, Any], key: str, ctx: str) -> list[str]:
    val = table.get(key, [])
    if not isinstance(val, list):
        raise ManifestError(f"{ctx}.{key} must be an array")
    out: list[str] = []
    for item in val:
        if not isinstance(item, str):
            raise ManifestError(f"{ctx}.{key} entries must be strings")
        out.append(item)
    return out


def build_manifest(
    toml_text: str,
    extra_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Parse ``tool.toml`` text and return the ToolManifest as a JSON-ready dict.

    ``extra_metadata`` (e.g. commit sha + publish provenance from CI) is merged
    on top of any ``[tool.metadata]`` table in the toml.
    """
    parsed: dict[str, Any] = tomllib.loads(toml_text)

    tool = parsed.get("tool")
    if not isinstance(tool, dict):
        raise ManifestError("tool.toml must have a [tool] table")

    name = _require_str(tool, "name", "tool")
    version = _require_str(tool, "version", "tool")
    raw_language = _require_str(tool, "language", "tool").lower()
    language = _LANGUAGE_ALIASES.get(raw_language)
    if language is None:
        raise ManifestError(
            f"unknown language {raw_language!r} "
            f"(accepted: {', '.join(sorted(set(_LANGUAGE_ALIASES)))})"
        )

    entry_raw = tool.get("entry")
    if entry_raw is not None and (
        not isinstance(entry_raw, str) or entry_raw not in _VALID_ENTRIES
    ):
        raise ManifestError(f"unknown entry {entry_raw!r} (accepted: wasi_cli_run)")

    caps_table = tool.get("capabilities")
    if caps_table is None:
        caps_table = {}
    if not isinstance(caps_table, dict):
        raise ManifestError("[tool.capabilities] must be a table")

    network_mode = caps_table.get("network_mode", "none")
    if not isinstance(network_mode, str) or network_mode not in NETWORK_MODES:
        raise ManifestError(
            f"network_mode must be one of {sorted(NETWORK_MODES)} "
            f"(got {network_mode!r})"
        )

    mounts = _str_list(caps_table, "mounts", "tool.capabilities")
    host_apis = _str_list(caps_table, "host_apis", "tool.capabilities")
    unknown = [api for api in host_apis if api not in KNOWN_HOST_APIS]
    if unknown:
        raise ManifestError(
            f"host_apis not in the known synapse-host set: {unknown} "
            f"(known: {sorted(KNOWN_HOST_APIS)})"
        )

    metadata: dict[str, Any] = {}
    toml_metadata = tool.get("metadata")
    if isinstance(toml_metadata, dict):
        metadata.update(toml_metadata)
    if extra_metadata:
        metadata.update(extra_metadata)

    return {
        "schema_version": SCHEMA_VERSION,
        "name": name,
        "version": version,
        "language": language,
        "entry": _ENTRY_CANONICAL,
        "declared_capabilities": {
            "network_mode": network_mode,
            "mounts": mounts,
            "host_apis": host_apis,
        },
        "metadata": metadata,
    }


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert a tool.toml into a ToolManifest JSON sidecar."
    )
    parser.add_argument(
        "--tool-toml",
        required=True,
        help="path to the tool's tool.toml",
    )
    parser.add_argument(
        "--metadata",
        default=None,
        help="JSON object merged into the manifest `metadata` field",
    )
    parser.add_argument(
        "--expect-name",
        default=None,
        help="fail unless [tool].name equals this (publish-tag guard)",
    )
    parser.add_argument(
        "--expect-version",
        default=None,
        help="fail unless [tool].version equals this (publish-tag guard)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    extra_metadata: dict[str, Any] | None = None
    if args.metadata:
        loaded: Any = json.loads(args.metadata)
        if not isinstance(loaded, dict):
            print("--metadata must be a JSON object", file=sys.stderr)
            return 2
        extra_metadata = loaded

    with open(args.tool_toml, "rb") as handle:
        toml_text = handle.read().decode("utf-8")

    try:
        manifest = build_manifest(toml_text, extra_metadata)
    except (ManifestError, tomllib.TOMLDecodeError) as err:
        print(f"{args.tool_toml}: {err}", file=sys.stderr)
        return 1

    if args.expect_name is not None and manifest["name"] != args.expect_name:
        print(
            f"{args.tool_toml}: name {manifest['name']!r} != "
            f"expected {args.expect_name!r}",
            file=sys.stderr,
        )
        return 1
    if args.expect_version is not None and manifest["version"] != args.expect_version:
        print(
            f"{args.tool_toml}: version {manifest['version']!r} != "
            f"expected {args.expect_version!r}",
            file=sys.stderr,
        )
        return 1

    # Compact single-line JSON — matches the sidecar convention the workflows
    # previously emitted via printf.
    json.dump(manifest, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
