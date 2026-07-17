"""Unique operational prune report-cell check."""
from __future__ import annotations

from typing import Any

from .schema import DISTINGUISHED, NON_UNIQUE, REJECTED, UNIQUE_SAME_CELL


def check_uniqueness(matrix: dict[str, Any], session: dict[str, Any] | None = None) -> dict[str, Any]:
    cases = matrix.get("cases") or {}
    session = session or {"session_complete": False, "verifier_invocation_completed": False, "ringbuf_lost_events": -1, "collector_parse_errors": -1}
    reasons: list[str] = []
    reps: dict[str, list[str]] = {}
    if session.get("session_complete") is not True:
        reasons.append("session capture is incomplete")
    if session.get("verifier_invocation_completed") is not True:
        reasons.append("verifier invocation did not complete")
    if int(session.get("ringbuf_lost_events", 0)) != 0:
        reasons.append(f"ringbuf lost events={session.get('ringbuf_lost_events')}")
    if int(session.get("collector_parse_errors", 0)) != 0:
        reasons.append(f"collector parse errors={session.get('collector_parse_errors')}")
    for case in ("a=0", "a=1"):
        values = list((cases.get(case) or {}).get("representatives") or (cases.get(case) or {}).get("retained_representatives") or [])
        if len(values) == 0:
            reasons.append(f"{case} has no retained representative")
        elif len(values) > 1:
            reasons.append(f"{case} has non-unique retained representatives {values}")
        reps[case] = values
    if reasons:
        result = NON_UNIQUE if any("non-unique" in r for r in reasons) else REJECTED
    elif reps["a=0"][0] == reps["a=1"][0]:
        result = UNIQUE_SAME_CELL
    else:
        result = DISTINGUISHED
    return {
        "schema": "rac-unique-report-cell-v2",
        "session_complete": session.get("session_complete") is True,
        "verifier_invocation_completed": session.get("verifier_invocation_completed") is True,
        "events_lost": int(session.get("ringbuf_lost_events", 0)),
        "collector_parse_errors": int(session.get("collector_parse_errors", 0)),
        "retained_roots": matrix.get("retained_roots", []),
        "representatives": reps,
        "result": result,
        "reasons": reasons,
    }
