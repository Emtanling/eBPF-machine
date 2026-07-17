"""Check operational prune-cell coverage for the two concrete cases."""
from __future__ import annotations

from typing import Any

DIRECT_RESULTS = {"a=0": "SIGMA_A0_IN_DIRECT_GAMMA", "a=1": "SIGMA_A1_IN_DIRECT_GAMMA"}


def check_coverage(path_report: dict[str, Any], memberships: dict[str, Any], prune_edges: dict[str, Any], retained_hash: str, current_hash: str) -> dict[str, Any]:
    edge_list = prune_edges.get("edges") or []
    matching_edges = [e for e in edge_list if e.get("current_state_hash") == current_hash and e.get("retained_state_hash") == retained_hash and int(e.get("visit_insn", -1)) == int((path_report.get("frontier") or {}).get("join_insn", -2))]
    cases = {
        "a=0": {
            "case": "a=0",
            "direct_abstract_role": "current",
            "direct_state_hash": current_hash,
            "membership_result": memberships["a=0"].get("result"),
            "representatives": [retained_hash] if matching_edges and memberships["a=0"].get("result") == DIRECT_RESULTS["a=0"] else [],
            "via": "current_pruned_by_retained",
        },
        "a=1": {
            "case": "a=1",
            "direct_abstract_role": "retained",
            "direct_state_hash": retained_hash,
            "membership_result": memberships["a=1"].get("result"),
            "representatives": [retained_hash] if memberships["a=1"].get("result") == DIRECT_RESULTS["a=1"] else [],
            "via": "direct_retained_member",
        },
    }
    checks = {
        "path_a0_current": (path_report.get("a0") or {}).get("abstract_role") == "current" and (path_report.get("a0") or {}).get("direct_state_hash") == current_hash,
        "path_a1_retained": (path_report.get("a1") or {}).get("abstract_role") == "retained" and (path_report.get("a1") or {}).get("direct_state_hash") == retained_hash,
        "membership_a0_direct": memberships["a=0"].get("result") == DIRECT_RESULTS["a=0"],
        "membership_a1_direct": memberships["a=1"].get("result") == DIRECT_RESULTS["a=1"],
        "actual_prune_edge_observed": bool(matching_edges),
        "both_cases_have_representative": all(cases[c]["representatives"] == [retained_hash] for c in ("a=0", "a=1")),
    }
    return {
        "schema": "rac-prune-cell-coverage-v1",
        "representative": retained_hash,
        "direct_members": ["sigma-a1"] if checks["membership_a1_direct"] else [],
        "members_via_prune_edge": ["sigma-a0"] if checks["membership_a0_direct"] and checks["actual_prune_edge_observed"] else [],
        "prune_edges": matching_edges,
        "cases": cases,
        "checks": checks,
        "result": "BOTH_CASES_IN_OPERATIONAL_PRUNE_CELL" if all(checks.values()) else "PRUNE_CELL_COVERAGE_NOT_ESTABLISHED",
    }
