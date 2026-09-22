"""Unit tests for the per-tool ``tool.toml`` capability declarations and the
``tools/_shared/tool_manifest.py`` converter that turns them into the Synapse
``ToolManifest`` sidecar (issue #37; synapse #185/#190).

These run in the fast unit lane (no Docker). They guard three things:

1. every WASM tool ships a ``tool.toml``;
2. each ``tool.toml`` parses, matches its ``Cargo.toml`` name/version, and only
   declares ``host_apis`` / ``network_mode`` from the closed synapse-host sets;
3. the converter emits JSON whose shape matches ``ToolManifest``
   (``synapse-proto/src/manifest/mod.rs``) so
   ``serde_json::from_slice::<ToolManifest>`` parses it.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from tools._shared.tool_manifest import (
    KNOWN_HOST_APIS,
    NETWORK_MODES,
    ManifestError,
    build_manifest,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"


def _wasm_tool_dirs() -> list[Path]:
    """WASM tools are the dirs carrying both a Cargo.toml and a build.sh."""
    return sorted(
        p
        for p in TOOLS_DIR.iterdir()
        if p.is_dir()
        and (p / "Cargo.toml").is_file()
        and (p / "build.sh").is_file()
    )


def _tool_toml_paths() -> list[Path]:
    return sorted(TOOLS_DIR.glob("*/tool.toml"))


WASM_TOOLS = _wasm_tool_dirs()
TOOL_TOMLS = _tool_toml_paths()


def _cargo_version(tool_dir: Path) -> str:
    cargo = tomllib.loads((tool_dir / "Cargo.toml").read_text())
    package = cargo["package"]
    assert isinstance(package, dict)
    version = package["version"]
    assert isinstance(version, str)
    return version


def test_every_wasm_tool_has_a_tool_toml() -> None:
    missing = [p.name for p in WASM_TOOLS if not (p / "tool.toml").is_file()]
    assert not missing, f"WASM tools missing tool.toml: {missing}"
    # Regression guard: the current catalog is 32 WASM tools.
    assert len(TOOL_TOMLS) == 32
    assert len(TOOL_TOMLS) == len(WASM_TOOLS)


@pytest.mark.parametrize("toml_path", TOOL_TOMLS, ids=lambda p: p.parent.name)
def test_tool_toml_parses_and_is_consistent(toml_path: Path) -> None:
    tool_name = toml_path.parent.name
    raw = tomllib.loads(toml_path.read_text())

    assert "tool" in raw, f"{tool_name}: missing [tool] table"
    tool = raw["tool"]
    assert isinstance(tool, dict)

    assert tool["name"] == tool_name, "tool.toml name must match its directory"
    assert tool["version"] == _cargo_version(toml_path.parent), (
        "tool.toml version must match Cargo.toml"
    )
    assert tool["language"] == "rust"

    caps = tool.get("capabilities", {})
    assert isinstance(caps, dict)

    network_mode = caps.get("network_mode", "none")
    assert network_mode in NETWORK_MODES

    mounts = caps.get("mounts", [])
    assert isinstance(mounts, list)
    assert all(isinstance(m, str) for m in mounts)

    host_apis = caps.get("host_apis", [])
    assert isinstance(host_apis, list)
    unknown = [api for api in host_apis if api not in KNOWN_HOST_APIS]
    assert not unknown, f"{tool_name}: host_apis outside synapse-host set: {unknown}"


@pytest.mark.parametrize("toml_path", TOOL_TOMLS, ids=lambda p: p.parent.name)
def test_converter_emits_toolmanifest_shape(toml_path: Path) -> None:
    """The generated JSON must round-trip through json and carry every field
    ToolManifest declares, with the right types (a fixture-style shape check)."""
    manifest = build_manifest(
        toml_path.read_text(),
        extra_metadata={"commit": "deadbeef", "published_by": "unit-test"},
    )
    # Round-trips as JSON (what oras pushes / the CP serves).
    reparsed = json.loads(json.dumps(manifest))

    assert reparsed["schema_version"] == 1
    assert isinstance(reparsed["name"], str)
    assert isinstance(reparsed["version"], str)
    assert reparsed["language"] == "rust"
    assert reparsed["entry"] == "wasi_cli_run"

    caps = reparsed["declared_capabilities"]
    assert set(caps) == {"network_mode", "mounts", "host_apis"}
    assert caps["network_mode"] in NETWORK_MODES
    assert isinstance(caps["mounts"], list)
    assert isinstance(caps["host_apis"], list)

    assert reparsed["metadata"]["commit"] == "deadbeef"


def test_converter_rejects_unknown_host_api() -> None:
    bad = """
[tool]
name = "x"
version = "0.1.0"
language = "rust"

[tool.capabilities]
network_mode = "none"
host_apis = ["package.query", "totally.bogus"]
"""
    with pytest.raises(ManifestError, match="totally.bogus"):
        build_manifest(bad)


def test_converter_rejects_bad_network_mode() -> None:
    bad = """
[tool]
name = "x"
version = "0.1.0"
language = "rust"

[tool.capabilities]
network_mode = "wide-open"
"""
    with pytest.raises(ManifestError, match="network_mode"):
        build_manifest(bad)
