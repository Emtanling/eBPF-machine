"""Build sigma-to-retained coverage relation."""
from __future__ import annotations

from typing import Any

HISTORY_SIDE_TO_ROLE = {"history_left": "retained", "history_right": "current"}


def build_coverage(path_report: dict[str, Any], memberships: dict[str, Any], subsumption: dict[str, Any], retained_hash: str, current_hash: str) -> dict[str, Any]:
    # Legacy helper retained for compatibility. The v2 report-map path uses
    # check_prune_cell_coverage.py and an observed prune edge, not restricted
    # subsumption, for final R coverage.
    cases = {}
    for case in ("a=0", "a=1"):
        prefix = path_report["prefixes"][case]
        direct_role = HISTORY_SIDE_TO_ROLE[prefix["history_side"]]
        direct_hash = retained_hash if direct_role == "retained" else current_hash
        representatives = []
        if memberships[case].get("passed"):
            if direct_role == "retained":
                representatives.append(retained_hash)
            elif subsumption.get("result") == "RESTRICTED_SUBSUMPTION_ESTABLISHED":
                representatives.append(retained_hash)
        cases[case] = {
            "case": case,
            "direct_abstract_role": direct_role,
            "direct_state_hash": direct_hash,
            "retained_representatives": sorted(set(representatives)),
            "membership_result": memberships[case].get("result"),
            "coverage_basis": "direct_retained_member" if direct_role == "retained" else "legacy_restricted_subsumption_not_final_r",
        }
    return {"schema": "rac-report-coverage-v1", "cases": cases}
