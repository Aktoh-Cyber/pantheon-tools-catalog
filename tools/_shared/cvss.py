"""CVSS v3.x base score from a vector string, and OSV severity normalisation.

OSV records carry severity as a vector (``CVSS:3.1/AV:N/AC:L/...``), not a
number. The base score follows the CVSS v3.1 specification (section 7.1 and
Appendix A ``Roundup``); v3.0 vectors use the same formula. CVSS v4 and v2
vectors are kept as-is with no computed score: a guessed score is worse than
an honest ``unknown``.
"""

from __future__ import annotations

import math
from typing import Any

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

LEVELS = ("critical", "high", "medium", "low", "negligible", "none", "unknown")
LEVEL_RANK = {lvl: i for i, lvl in enumerate(LEVELS)}


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A: smallest 1-decimal number >= value, computed on
    integers to dodge floating-point artefacts."""
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """Base score for a CVSS:3.0/3.1 vector, or None if it is not one."""
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k] = v
    try:
        scope_changed = metrics["S"] == "C"
        av, ac, ui = _AV[metrics["AV"]], _AC[metrics["AC"]], _UI[metrics["UI"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        c, i, a = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def level_for_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


# Debian urgency / Ubuntu priority / GHSA words -> level.
_WORDS = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
    "low*": "low",
    "negligible": "negligible",
    "unimportant": "negligible",
}


def severity_of(record: dict[str, Any], urgency: str | None = None) -> dict[str, Any]:
    """``{level, level_source, cvss_score?, cvss_level?, cvss_vector?, urgency?}``.

    The level is the VENDOR's triage when there is one, as Trivy and the
    distro trackers do for OS packages: the distribution's urgency for this
    package (Debian ``unimportant`` = no security impact as shipped), else a
    qualitative severity the record states (Ubuntu priority, GHSA). Only
    without a vendor word does the CVSS v3 base score decide. The CVSS score
    and its level are always kept, so both views stay queryable."""
    out: dict[str, Any] = {"level": "unknown", "level_source": "none"}
    vectors: list[str] = [
        str(s["score"])
        for s in (record.get("severity") or [])
        if isinstance(s, dict) and isinstance(s.get("score"), str)
    ]
    for v in vectors:
        if v.startswith("CVSS:"):
            out.setdefault("cvss_vector", v)
        score = cvss3_base_score(v)
        if score is not None:
            out.update(
                cvss_vector=v, cvss_score=score, cvss_level=level_for_score(score)
            )
            break
    if urgency:
        out["urgency"] = urgency
    words: list[str] = [urgency] if urgency else []
    words += [
        str(s.get("score"))
        for s in (record.get("severity") or [])
        if isinstance(s, dict) and s.get("type") == "Ubuntu"
    ]
    ds = record.get("database_specific")
    if isinstance(ds, dict) and isinstance(ds.get("severity"), str):
        words.append(ds["severity"])
    for w in words:
        lvl = _WORDS.get(w.strip().lower())
        if lvl:
            out.update(level=lvl, level_source="vendor")
            return out
    if "cvss_level" in out:
        out.update(level=out["cvss_level"], level_source="cvss")
    return out


def max_level(levels: list[str]) -> str:
    """Most severe level in a list (``critical`` first); ``unknown`` if empty."""
    known = [lvl for lvl in levels if lvl in LEVEL_RANK]
    return min(known, key=LEVEL_RANK.__getitem__) if known else "unknown"
