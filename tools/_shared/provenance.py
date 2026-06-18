"""Provenance stamping for librarian's write tools.

Every node or edge that librarian writes carries:
- `commissioned_by`: the calling agent's short handle (set from the
  MCP request envelope's `principal_id` field — see callers in
  `librarian.upsert_node` / `librarian.upsert_edge`).
- `commissioned_at`: server-side Neo4j `datetime()` (NOT a string
  passed from the caller — keeps timestamps comparable across
  agents and immune to client clock skew).
- `session_id`: the operator's session ID for per-session cleanup
  (`librarian.purge_session` reads this).

These three keys are **reserved**: callers cannot override them
via the `props` argument. If they try, the write tool returns a
structured error pointing at the conflicting key.
"""
from __future__ import annotations

RESERVED_PROVENANCE_KEYS = frozenset(
    {"commissioned_by", "commissioned_at", "session_id"}
)


class ReservedKeyConflict(ValueError):
    """Raised when caller's `props` collides with a reserved
    provenance key. Surfaces as structured error to the tool's
    response shape."""

    def __init__(self, key: str) -> None:
        super().__init__(
            f"Reserved provenance key `{key}` cannot be overridden via "
            "props. Librarian sets it server-side. Rename your "
            "property (e.g. `commissioned_by_caller` for an "
            "application-level field)."
        )
        self.key = key


def assert_no_reserved_keys(props: dict[str, object]) -> None:
    """Raise `ReservedKeyConflict` if any key in `props` is a
    reserved provenance field. Pass otherwise."""
    for key in props:
        if key in RESERVED_PROVENANCE_KEYS:
            raise ReservedKeyConflict(key=key)
