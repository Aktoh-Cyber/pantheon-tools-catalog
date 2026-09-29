"""Make Neo4j values JSON-safe before they go into a tool response.

Regression (2026-09-29, tenant aktoh, the first time the librarian's write
tools ever ran in production): every `librarian.upsert_node` call WROTE the
node, then failed with

    Unable to serialize unknown type: <class 'neo4j.time.DateTime'>

The tools stamp `commissioned_at = datetime()` server-side, and the result
echoes the node's properties back via `dict(node)`. That includes the
driver's `neo4j.time.DateTime`, which pydantic cannot JSON-encode. The agent
saw a failure for a write that had in fact landed. `librarian.query` had the
same flaw for any node or relationship carrying provenance. The unit and
integration tests called `run()` and inspected Python objects, never
JSON-encoding the response, which is why the flaw went unnoticed.

`to_json_safe` converts, recursively:
- Neo4j temporal types (DateTime, Date, Time, Duration) and Python
  datetime/date/time to ISO-8601 strings;
- spatial Points to `{srid, x, y[, z]}`;
- bytes to base64 text.
Everything else JSON already understands passes through unchanged.
"""

from __future__ import annotations

import base64
import datetime as _dt
from typing import Any

from neo4j.spatial import Point
from neo4j.time import Date, DateTime, Duration, Time

_PY_TEMPORAL = (_dt.datetime, _dt.date, _dt.time)


def to_json_safe(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, DateTime | Date | Time | Duration):
        return str(value.iso_format())
    if isinstance(value, _PY_TEMPORAL):
        return value.isoformat()
    if isinstance(value, Point):
        out: dict[str, Any] = {"srid": getattr(value, "srid", None)}
        for axis, v in zip(("x", "y", "z"), tuple(value), strict=False):
            out[axis] = v
        return out
    if isinstance(value, bytes | bytearray):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, dict):
        return {str(k): to_json_safe(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [to_json_safe(v) for v in value]
    return value


def properties(entity: Any) -> dict[str, Any]:
    """JSON-safe property bag of a Neo4j Node or Relationship."""
    return {str(k): to_json_safe(v) for k, v in dict(entity).items()}


__all__ = ["properties", "to_json_safe"]
