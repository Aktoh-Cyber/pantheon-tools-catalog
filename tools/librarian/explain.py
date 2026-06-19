"""librarian.explain — natural-language → Cypher.

Operator workflow: PMC `/graph` composer has an NL mode. Operator
types "what services run on the suspicious hosts?"; librarian
produces a candidate Cypher and (optionally) executes it.

Two-pass design:
1. Fetch the live schema (`librarian.schema` — node labels,
   relationship types, property keys). The LLM grounds its Cypher
   in the actual graph; without this it hallucinates labels.
2. Prompt the LLM with the operator's question + the schema +
   strict instructions (read-only operators allowed; structured
   output `{cypher: str, confidence: float, explanation: str}`).

If `execute=true` the tool runs the produced Cypher through the
same read-only safety layer as `librarian.query`. Otherwise it
returns the Cypher candidate without executing.

LLM client: injected via a module-level factory so tests can
substitute a stub. Default factory wraps the Anthropic SDK against
`ANTHROPIC_API_KEY` from env.
"""
from __future__ import annotations

import json
import os
from typing import Any, Awaitable, Callable, Optional

from pydantic import BaseModel, Field

from tools._shared.cypher_safety import (
    CypherWriteRejected,
    assert_read_only,
)
from tools._shared.neo4j_client import get_driver
from tools.librarian.query import (
    GraphData,
    QueryResult,
    _project_graph,
    _rows_contain_graph,
    _serialize_rows,
)
from tools.librarian.schema import SchemaInput, run as run_schema

# Type for an LLM call: takes a system prompt + user prompt + a JSON
# schema, returns the parsed JSON dict. Async so the tool's `run`
# can `await` it.
LLMCall = Callable[[str, str, dict[str, Any]], Awaitable[dict[str, Any]]]

_DEFAULT_MODEL = "claude-sonnet-4-6"


class ExplainInput(BaseModel):
    question: str = Field(..., min_length=1)
    execute: bool = Field(
        default=False,
        description="If True, run the produced Cypher through "
        "librarian.query's read-only path and include rows in the "
        "result. If False, return the Cypher candidate only.",
    )


class ExplainCandidate(BaseModel):
    cypher: str
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str


class ExplainResult(BaseModel):
    candidate: ExplainCandidate
    executed: bool = False
    rows: list[dict[str, Any]] | None = None
    graph: GraphData | None = None


class ExplainToolResponse(BaseModel):
    ok: bool
    result: ExplainResult | None = None
    error: str | None = None
    details: dict[str, Any] | None = None


# --- LLM injection point ----------------------------------------------------


def _default_llm_call() -> LLMCall:
    """Default factory: returns a function that calls the Anthropic
    SDK. Import inside the function so the SDK isn't a hard dep at
    import time — tests don't need it."""

    async def _call(
        system: str, user: str, output_schema: dict[str, Any]
    ) -> dict[str, Any]:
        # Lazy import; the SDK is in the catalog's runtime deps but
        # not the test deps.
        from anthropic import AsyncAnthropic  # type: ignore[import-not-found]

        client = AsyncAnthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
        resp = await client.messages.create(
            model=os.environ.get("LIBRARIAN_EXPLAIN_MODEL", _DEFAULT_MODEL),
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        # Extract the text content and parse as JSON.
        text = "".join(
            block.text for block in resp.content if hasattr(block, "text")
        )
        return _parse_json_or_raise(text)

    return _call


_llm_factory: Callable[[], LLMCall] = _default_llm_call


def set_llm_factory(factory: Callable[[], LLMCall]) -> None:
    """Test seam: replace the LLM-client factory. Tests pass in a
    stub that returns a deterministic Cypher candidate."""
    global _llm_factory
    _llm_factory = factory


def reset_llm_factory_for_testing() -> None:
    global _llm_factory
    _llm_factory = _default_llm_call


# --- main entry --------------------------------------------------------------


_SYSTEM_PROMPT = """\
You translate natural-language questions about a knowledge graph
into Cypher queries. You ground every query in the schema you are
given; you do not invent labels, relationship types, or properties
that the schema doesn't include.

Hard constraints:
- The Cypher you return MUST be read-only. No MERGE, CREATE,
  DELETE, SET, REMOVE, or DROP.
- Use parameterised values whenever the operator's question
  includes a literal (e.g. an IP address); never inline.
- If the operator's question can't be answered with the given
  schema, return a candidate of the form `MATCH (n) RETURN 0 LIMIT 0`
  with confidence=0.0 and explanation noting which label or
  property is missing.

Output a single JSON object:
  {"cypher": str, "confidence": float in [0,1], "explanation": str}
"""

_USER_PROMPT_TMPL = """\
Schema:
- Node labels:        {node_labels}
- Relationship types: {relationship_types}
- Property keys:      {property_keys}

Operator question:
> {question}

Return JSON only.
"""


async def run(input: ExplainInput) -> ExplainToolResponse:
    """Two-pass NL→Cypher with optional read-only execute."""
    try:
        schema_payload = await _fetch_schema()
    except Exception as exc:  # noqa: BLE001
        return ExplainToolResponse(
            ok=False,
            error=f"schema fetch failed: {type(exc).__name__}: {exc}",
            details={"tool": "librarian.explain", "stage": "schema"},
        )

    user_prompt = _USER_PROMPT_TMPL.format(
        node_labels=", ".join(schema_payload["node_labels"]) or "(none)",
        relationship_types=", ".join(schema_payload["relationship_types"])
        or "(none)",
        property_keys=", ".join(schema_payload["property_keys"]) or "(none)",
        question=input.question.strip(),
    )

    try:
        llm = _llm_factory()
        raw = await llm(
            _SYSTEM_PROMPT,
            user_prompt,
            output_schema=ExplainCandidate.model_json_schema(),
        )
        candidate = ExplainCandidate.model_validate(raw)
    except Exception as exc:  # noqa: BLE001
        return ExplainToolResponse(
            ok=False,
            error=f"LLM call failed: {type(exc).__name__}: {exc}",
            details={"tool": "librarian.explain", "stage": "llm"},
        )

    # Always sanity-check the LLM's output before optionally executing.
    try:
        assert_read_only(candidate.cypher)
    except CypherWriteRejected as exc:
        return ExplainToolResponse(
            ok=False,
            error=str(exc),
            details={
                "tool": "librarian.explain",
                "stage": "safety",
                "candidate_cypher": candidate.cypher,
                "rejected_keyword": exc.keyword,
            },
        )

    if not input.execute:
        return ExplainToolResponse(
            ok=True,
            result=ExplainResult(candidate=candidate, executed=False),
        )

    # Execute via the same driver path librarian.query uses.
    try:
        driver = get_driver()
        async with driver.session() as session:
            result = await session.run(candidate.cypher)
            rows = [dict(record) async for record in result]
    except Exception as exc:  # noqa: BLE001
        return ExplainToolResponse(
            ok=False,
            error=f"executing candidate Cypher failed: "
            f"{type(exc).__name__}: {exc}",
            details={
                "tool": "librarian.explain",
                "stage": "execute",
                "candidate_cypher": candidate.cypher,
            },
        )

    graph = _project_graph(rows) if _rows_contain_graph(rows) else None
    return ExplainToolResponse(
        ok=True,
        result=ExplainResult(
            candidate=candidate,
            executed=True,
            rows=_serialize_rows(rows),
            graph=graph,
        ),
    )


# --- helpers ----------------------------------------------------------------


async def _fetch_schema() -> dict[str, list[str]]:
    """Delegate to librarian.schema rather than re-running the same
    three Cyphers. Keeps the schema-discovery logic in one place."""
    resp = await run_schema(SchemaInput())
    if not resp.ok or resp.result is None:
        # Surface as a raisable error so the caller's stage="schema"
        # error path handles it. The original error is in `resp.error`.
        raise RuntimeError(
            resp.error or "librarian.schema returned a non-ok response"
        )
    return {
        "node_labels": resp.result.node_labels,
        "relationship_types": resp.result.relationship_types,
        "property_keys": resp.result.property_keys,
    }


def _parse_json_or_raise(text: str) -> dict[str, Any]:
    """Extract a JSON object from the LLM's response — accepts the
    object verbatim, or one wrapped in ```json fences."""
    s = text.strip()
    if s.startswith("```"):
        # Strip opening fence (with or without lang tag) + closing fence.
        first_newline = s.find("\n")
        if first_newline != -1:
            s = s[first_newline + 1 :]
        if s.endswith("```"):
            s = s[:-3]
        s = s.strip()
    return json.loads(s)
