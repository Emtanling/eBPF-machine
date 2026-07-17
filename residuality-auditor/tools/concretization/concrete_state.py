"""Construct local concrete sigma artifacts from path/state proofs."""
from __future__ import annotations

from typing import Any

from .frame_constraints import concrete_for_frame


def state_for_role(states: dict[str, dict[str, Any]], role: str) -> dict[str, Any]:
    return states[role]["snapshot"]


def sigma_for_case(case: str, prefix: dict[str, Any], abstract_role: str, abstract_snapshot: dict[str, Any], identity: dict[str, Any]) -> dict[str, Any]:
    state = abstract_snapshot["state_v2"]
    frame = state["frames"][0]
    return {
        "schema": "rac-concrete-sigma-v1",
        "case": case,
        "abstract_role": abstract_role,
        "identity": identity,
        "frontier_pc": abstract_snapshot["insn_idx"],
        "branch_name": prefix["branch_name"],
        "branch_call": prefix["branch_call"],
        "selected_state": prefix["runtime_selected_state"],
        "selected_mask": prefix["runtime_selected_mask"],
        "observation_success": prefix["runtime_observation_success"],
        "frame": concrete_for_frame(frame),
        "omitted_runtime_component": {
            "name": "G0 key-set map occupancy before shared suffix",
            "value": prefix["runtime_selected_state"],
            "reason": "dedicated map occupancy is intentionally outside verifier-state V2 and is checked as selected concrete state",
        },
    }


def environment(runtime: dict[str, Any], path_report: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "rac-local-environment-v1",
        "identity": path_report.get("identity"),
        "runtime_schema": runtime.get("schema"),
        "serialized_execution": True,
        "single_artifact": True,
        "no_external_interference": True,
        "same_suffix": path_report.get("common_suffix", {}).get("same_remaining_xlated_suffix") is True,
    }
