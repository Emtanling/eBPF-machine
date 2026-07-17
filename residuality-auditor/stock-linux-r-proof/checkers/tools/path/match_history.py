"""Match normalized verifier histories to xlated branch semantics."""
from __future__ import annotations

from typing import Any


def selected_frontier_event(frontier_check: dict[str, Any]) -> dict[str, Any]:
    if frontier_check.get("result") != "FRONTIER_ELIGIBLE":
        raise ValueError("path correspondence requires FRONTIER_ELIGIBLE")
    passed = [e for e in frontier_check.get("events", []) if isinstance(e, dict) and e.get("passed") is True]
    if len(passed) != 1:
        raise ValueError(f"expected exactly one passed frontier event, found {len(passed)}")
    return passed[0]


def _single_hit(history: dict[str, Any], side: str) -> int:
    hits = history.get("branch_call_hits") if isinstance(history, dict) else None
    if not isinstance(hits, list) or len(hits) != 1:
        raise ValueError(f"{side} history must contain exactly one branch_call_hit")
    return int(hits[0])


def match_histories(frontier_event: dict[str, Any], selector_cases: dict[str, Any]) -> dict[str, Any]:
    side_hits = {
        "history_left": _single_hit(frontier_event.get("history_left"), "history_left"),
        "history_right": _single_hit(frontier_event.get("history_right"), "history_right"),
    }
    call_to_case = {int(case.branch_call): case for case in selector_cases.values()}
    if set(side_hits.values()) != set(call_to_case):
        raise ValueError(
            f"history branch hits {sorted(side_hits.values())} do not match selector calls {sorted(call_to_case)}"
        )
    case_to_side: dict[str, dict[str, Any]] = {}
    for side, call in side_hits.items():
        case = call_to_case[call]
        history = frontier_event.get(side)
        case_to_side[case.case] = {
            "history_side": side,
            "branch_call": call,
            "branch_name": case.branch_name,
            "selector_edge": case.selector_edge,
            "entries": history.get("entries", []) if isinstance(history, dict) else [],
            "captured_count": history.get("captured_count") if isinstance(history, dict) else None,
            "total_count": history.get("total_count") if isinstance(history, dict) else None,
            "truncated": history.get("truncated") if isinstance(history, dict) else None,
        }
    if set(case_to_side) != {"a=0", "a=1"}:
        raise ValueError("histories did not cover both runtime input cases")
    return {
        "schema": "rac-history-path-match-v1",
        "case_to_history": case_to_side,
        "side_hits": side_hits,
    }
