"""Verdict lattice for the integrated Definition 2 checker."""
from __future__ import annotations

from typing import Any


R_NOT_ESTABLISHED = "R_NOT_ESTABLISHED"
FRONTIER_ONLY = "FRONTIER_ONLY"
LINUX_R_CANDIDATE = "LINUX_R_CANDIDATE"
JOINT_COVERAGE_ONLY = "JOINT_COVERAGE_ONLY"
FACTORIZATION_FAILURE_WITHOUT_UNIQUENESS = "FACTORIZATION_FAILURE_WITHOUT_UNIQUENESS"
STOCK_LINUX_R_ESTABLISHED_FOR_FROZEN_TUPLE = "STOCK_LINUX_R_ESTABLISHED_FOR_FROZEN_TUPLE"

DEFINITION2_CHECKS = (
    "artifact_accepted",
    "identity_consistent",
    "concrete_states_reachable",
    "context_same",
    "selected_state_different",
    "same_suffix",
    "suffix_outputs_differ",
    "same_actual_report_cell",
    "unique_cell_on_chosen_fiber",
    "behavioral_quotient_different",
    "factorization_failure",
    "stock_linux_four_checks",
    "evidence_hashes_match",
)


def _passed(checks: dict[str, Any], name: str) -> bool:
    item = checks.get(name)
    if isinstance(item, dict):
        return item.get("passed") is True
    return item is True


def choose_verdict(checks: dict[str, Any]) -> str:
    if all(_passed(checks, name) for name in DEFINITION2_CHECKS):
        return STOCK_LINUX_R_ESTABLISHED_FOR_FROZEN_TUPLE
    if _passed(checks, "factorization_failure") and not _passed(checks, "unique_cell_on_chosen_fiber"):
        return FACTORIZATION_FAILURE_WITHOUT_UNIQUENESS
    if _passed(checks, "concrete_states_reachable"):
        return JOINT_COVERAGE_ONLY
    if _passed(checks, "artifact_accepted") and _passed(checks, "same_suffix") and _passed(checks, "suffix_outputs_differ"):
        return LINUX_R_CANDIDATE
    if _passed(checks, "artifact_accepted"):
        return FRONTIER_ONLY
    return R_NOT_ESTABLISHED


def verdict_rank(verdict: str) -> int:
    order = [
        R_NOT_ESTABLISHED,
        FRONTIER_ONLY,
        LINUX_R_CANDIDATE,
        JOINT_COVERAGE_ONLY,
        FACTORIZATION_FAILURE_WITHOUT_UNIQUENESS,
        STOCK_LINUX_R_ESTABLISHED_FOR_FROZEN_TUPLE,
    ]
    return order.index(verdict) if verdict in order else -1
