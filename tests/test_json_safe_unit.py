"""Unit tests for tools._shared.json_safe (2026-09-29 regression).

The librarian's first production writes landed in the graph but every
response failed to encode: `Unable to serialize unknown type:
<class 'neo4j.time.DateTime'>`. These pin the conversion with the driver's
real value types, no Docker needed.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

from neo4j.spatial import CartesianPoint
from neo4j.time import Date, DateTime, Duration, Time

from tools._shared.json_safe import properties, to_json_safe
from tools.librarian.__main__ import _encode_response
from tools.librarian.query import _serialize_value
from tools.librarian.upsert_node import UpsertNodeResult, UpsertNodeToolResponse

STAMP = DateTime(2026, 9, 29, 5, 47, 46, tzinfo=dt.UTC)


def test_neo4j_temporal_types_become_iso_strings() -> None:
    assert to_json_safe(STAMP).startswith("2026-09-29T05:47:46")
    assert to_json_safe(Date(2026, 9, 29)) == "2026-09-29"
    assert to_json_safe(Time(5, 47, 46)).startswith("05:47:46")
    assert isinstance(to_json_safe(Duration(days=1)), str)


def test_nested_python_and_spatial_values() -> None:
    out = to_json_safe({
        "when": dt.datetime(2026, 9, 29, tzinfo=dt.UTC),
        "tags": ("a", "b"),
        "at": CartesianPoint((1.0, 2.0)),
        "raw": b"\x00\x01",
        "n": 3, "ok": True, "none": None,
    })
    json.dumps(out)
    assert out["tags"] == ["a", "b"]
    assert out["at"]["x"] == 1.0 and out["at"]["y"] == 2.0
    assert out["raw"] == "AAE="


def test_properties_of_a_node_like_mapping() -> None:
    node: dict[str, Any] = {"name": "tek.local", "commissioned_at": STAMP}
    props = properties(node)
    assert props["name"] == "tek.local"
    assert isinstance(props["commissioned_at"], str)


def test_upsert_response_encodes_after_conversion() -> None:
    resp = UpsertNodeToolResponse(
        ok=True,
        result=UpsertNodeResult(
            element_id="4:x:1", labels=["Host"], created=True,
            properties=properties({"name": "tek.local", "commissioned_at": STAMP}),
        ),
    )
    wire = json.loads(resp.model_dump_json())
    assert wire["result"]["properties"]["commissioned_at"].startswith("2026-09-29")


def test_backstop_encoder_never_hides_the_outcome() -> None:
    # A raw DateTime slipping through must still encode, not raise.
    resp = UpsertNodeToolResponse(
        ok=True,
        result=UpsertNodeResult(
            element_id="4:x:1", labels=["Host"], created=True,
            properties={"commissioned_at": STAMP},
        ),
    )
    wire = json.loads(_encode_response(resp))
    assert wire["ok"] is True
    assert wire["result"]["properties"]["commissioned_at"].startswith("2026-09-29")


def test_query_scalar_and_nested_values_are_safe() -> None:
    assert isinstance(_serialize_value(STAMP), str)
    assert isinstance(_serialize_value([STAMP])[0], str)
    assert isinstance(_serialize_value({"at": STAMP})["at"], str)
