"""Runtime prefix semantics for the RAC witness."""
from __future__ import annotations

from typing import Any

STATE_BITS = {"S": 1 << 0, "A": 1 << 1, "B": 1 << 2}
EXPECTED_BY_BRANCH = {
    "select_s": {"case": "a=0", "selected_mask": STATE_BITS["S"], "selected_state": ["S"], "observation_success": True},
    "select_a": {"case": "a=1", "selected_mask": STATE_BITS["S"] | STATE_BITS["A"], "selected_state": ["S", "A"], "observation_success": False},
}


def state_mask(state: Any) -> int:
    if not isinstance(state, list):
        raise ValueError("runtime selected_state must be a list")
    mask = 0
    for item in state:
        if item not in STATE_BITS:
            raise ValueError(f"unknown runtime state component {item!r}")
        mask |= STATE_BITS[item]
    return mask


def runtime_prefixes(runtime: dict[str, Any]) -> dict[str, dict[str, Any]]:
    runs = runtime.get("runs")
    if not isinstance(runs, list):
        raise ValueError("runtime.json lacks runs[]")
    by_case: dict[str, dict[str, Any]] = {}
    for run in runs:
        if not isinstance(run, dict):
            continue
        case = run.get("case")
        if case in {"a=0", "a=1"}:
            selected = run.get("selected_state")
            observation = run.get("observation") if isinstance(run.get("observation"), dict) else {}
            by_case[case] = {
                "case": case,
                "selected_state": selected,
                "selected_mask": state_mask(selected),
                "final_state": run.get("final_state"),
                "observation_success": observation.get("success"),
                "observation_retval": observation.get("retval"),
                "context": run.get("context"),
                "suffix": run.get("suffix"),
            }
    if set(by_case) != {"a=0", "a=1"}:
        raise ValueError("runtime evidence must include exactly a=0 and a=1 runs")
    return by_case


def check_runtime_against_branch(case: str, branch_name: str, runtime_case: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    expected = EXPECTED_BY_BRANCH.get(branch_name)
    if expected is None:
        return [f"unknown branch semantic {branch_name}"]
    if expected["case"] != case:
        reasons.append(f"{case} mapped to {branch_name}, expected {expected['case']}")
    if runtime_case.get("selected_mask") != expected["selected_mask"]:
        reasons.append(
            f"{case} runtime selected mask {runtime_case.get('selected_mask')} != expected {expected['selected_mask']} for {branch_name}"
        )
    if runtime_case.get("observation_success") is not expected["observation_success"]:
        reasons.append(
            f"{case} runtime observation success {runtime_case.get('observation_success')} != expected {expected['observation_success']}"
        )
    return reasons
