"""Build sigma-to-operational-prune representative matrix."""
from __future__ import annotations

from typing import Any

from .resolve_prune_roots import resolve


def build_matrix(coverage: dict[str, Any], graph: dict[str, Any]) -> dict[str, Any]:
    cases = {}
    for case, item in sorted((coverage.get("cases") or {}).items()):
        direct_hash = item.get("direct_state_hash")
        reps = resolve(direct_hash, graph) if direct_hash else []
        cases[case] = {
            "case": case,
            "direct_abstract_role": item.get("direct_abstract_role"),
            "direct_state_hash": direct_hash,
            "membership_result": item.get("membership_result"),
            "representatives": reps,
        }
    return {"schema": "rac-prune-membership-matrix-v1", "cases": cases, "retained_roots": graph.get("retained_roots", [])}
