"""Reject write-Cypher at the tool layer.

`librarian.query` exposes Cypher to the operator chat through PMC.
Cedar gates `LibrarianWrite` at the principal level — but that
permit is granted to AgentService principals (so infosec etc. CAN
write). The operator (User principal) hitting `librarian.query`
gets the read-only permit, but a write Cypher would still execute
against Neo4j if it slipped past the principal check.

Defense in depth: parse the Cypher for write keywords + reject
before sending. False positives (e.g. "create" inside a string
literal in a property value) are tolerated — they fail loud and
the operator can rephrase.

Whitelist approach (only allow these top-level keywords) would
break complex but legitimate read queries (e.g. `WITH` chains).
We blacklist instead.
"""
from __future__ import annotations

import re

# Write-side keywords Cypher recognises. Each must be a standalone
# token (\b boundaries) and case-insensitive. The list:
# - MERGE, CREATE, DELETE, DETACH DELETE — direct node/edge writes
# - SET, REMOVE — property mutations
# - DROP — index/constraint drops (also writes)
# - CALL ... apoc.* with `*.create` `*.merge` `*.set` `*.delete`
#   isn't covered here; APOC is an extra surface, addressed by Cedar
#   permit scoping (no permit, no APOC).
_WRITE_KEYWORDS = (
    "MERGE",
    "CREATE",
    "DELETE",
    "SET",
    "REMOVE",
    "DROP",
)

_WRITE_PATTERN = re.compile(
    r"\b(" + "|".join(_WRITE_KEYWORDS) + r")\b",
    re.IGNORECASE,
)


class CypherWriteRejected(ValueError):
    """Raised when a read-only tool receives Cypher with write
    keywords. Tool catches this and converts to a structured
    `{ok: false, error: ...}` response."""

    def __init__(self, keyword: str, cypher: str) -> None:
        super().__init__(
            f"Write keyword `{keyword.upper()}` rejected at the "
            "librarian read-tool layer. The `librarian.query` tool "
            "is read-only — to write to the graph, sibling agents "
            "must use `librarian.upsert_node` / `librarian.upsert_edge` "
            "(AgentService-only). See Cedar permit "
            "`LibrarianWrite` (SYNAPSE-32)."
        )
        self.keyword = keyword
        self.cypher = cypher


def assert_read_only(cypher: str) -> None:
    """Raise `CypherWriteRejected` if `cypher` contains any write
    keyword as a standalone token. Pass otherwise."""
    match = _WRITE_PATTERN.search(_strip_strings(cypher))
    if match is None:
        return
    raise CypherWriteRejected(keyword=match.group(1), cypher=cypher)


def _strip_strings(cypher: str) -> str:
    """Remove single- and double-quoted string literals before
    scanning for keywords. Without this, a Cypher like
    `RETURN "this CREATE is fake"` would be falsely rejected.

    Backtick-quoted identifiers are kept (they're legitimately
    part of the query structure).
    """
    return re.sub(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"", "", cypher)
