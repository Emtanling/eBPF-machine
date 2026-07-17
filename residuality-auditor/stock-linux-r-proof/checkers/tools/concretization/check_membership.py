#!/usr/bin/env python3
"""Materialize local concrete states and check membership in State V2 abstractions."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .concrete_state import environment as make_environment
from .concrete_state import sigma_for_case, state_for_role
from .frame_constraints import check_frame

HISTORY_SIDE_TO_ROLE = {"history_left": "retained", "history_right": "current"}
CASE_RESULT = {"a=0": "SIGMA_A0_IN_DIRECT_GAMMA", "a=1": "SIGMA_A1_IN_DIRECT_GAMMA"}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _write(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def _rule_for(field: str, context: str) -> str:
    if field == "var_off":
        return "scalar-tnum" if "SCALAR" in context else "ptr-tnum"
    if field in {"umin_value", "umax_value", "smin_value", "smax_value", "u32_min_value", "u32_max_value", "s32_min_value", "s32_max_value"}:
        return "scalar-range"
    if field == "type":
        return "register-type-kind"
    if field == "uninitialized":
        return "not-init"
    if field in {"ptr_kind", "offset"}:
        return "pointer-kind-and-offset"
    if field in {"initialized", "slot_type", "spilled_ptr"}:
        return "stack-slot-shape"
    if field.startswith("environment."):
        return "environment-contract"
    if field == "frontier_pc":
        return "frontier-pc-match"
    if field == "omitted_map_occupancy_recorded":
        return "omitted-runtime-component-recorded"
    if field in {"frameno", "allocated_stack"}:
        return "frame-shape"
    return "field-equality"


def _flat_check(field: str, check: dict[str, Any], context: str) -> dict[str, Any]:
    item = {
        "field": field,
        "rule": _rule_for(str(check.get("field", field)), context),
        "result": "PASS" if check.get("passed") is True else "FAIL",
        "passed": check.get("passed") is True,
    }
    for key in ("abstract", "concrete", "concrete_kind", "bound", "tnum"):
        if key in check:
            item[key] = check[key]
    return item


def _field_checks(top_checks: list[dict[str, Any]], frame_check: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for check in top_checks:
        out.append(_flat_check(str(check.get("field")), check, "membership"))
    for check in frame_check.get("checks") or []:
        out.append(_flat_check(f"frame.{check.get('field')}", check, "frame"))
    for reg in frame_check.get("registers") or []:
        reg_name = f"regs.r{reg.get('reg')}"
        reg_type = str(reg.get("type", ""))
        for check in reg.get("checks") or []:
            out.append(_flat_check(f"{reg_name}.{check.get('field')}", check, reg_type))
    for slot in frame_check.get("stack_slots") or []:
        slot_name = f"stack.slot{slot.get('slot')}"
        for check in slot.get("checks") or []:
            out.append(_flat_check(f"{slot_name}.{check.get('field')}", check, "stack"))
            detail = check.get("detail") if isinstance(check.get("detail"), dict) else None
            if detail:
                detail_type = str(detail.get("type", ""))
                for nested in detail.get("checks") or []:
                    out.append(_flat_check(f"{slot_name}.spilled_ptr.{nested.get('field')}", nested, detail_type))
    return out


def _membership(case: str, sigma: dict[str, Any], abstract_snapshot: dict[str, Any], env: dict[str, Any]) -> dict[str, Any]:
    state = abstract_snapshot.get("state_v2") or {}
    frames = state.get("frames") or []
    reasons: list[str] = []
    checks: list[dict[str, Any]] = []
    if state.get("valid") is not True:
        reasons.append("abstract state_v2 is not valid")
    unsupported_fields: list[str] = []
    if int(state.get("unsupported_mask", 0)) != 0:
        unsupported_fields.append(f"unsupported_mask={state.get('unsupported_mask')}")
        reasons.append(f"abstract state has unsupported_mask={state.get('unsupported_mask')}")
    checks.append({"field": "frontier_pc", "passed": sigma.get("frontier_pc") == abstract_snapshot.get("insn_idx"), "concrete": sigma.get("frontier_pc"), "abstract": abstract_snapshot.get("insn_idx")})
    checks.append({"field": "environment.same_suffix", "passed": env.get("same_suffix") is True})
    checks.append({"field": "environment.serialized_execution", "passed": env.get("serialized_execution") is True})
    checks.append({"field": "omitted_map_occupancy_recorded", "passed": bool(sigma.get("omitted_runtime_component", {}).get("value"))})
    if not frames:
        reasons.append("abstract state has no frame")
        frame_check = {"passed": False, "reasons": ["missing frame"]}
    else:
        frame_check = check_frame(sigma.get("frame") or {}, frames[0])
    field_checks = _field_checks(checks, frame_check)
    passed = (
        not reasons
        and not unsupported_fields
        and all(item.get("passed") for item in checks)
        and frame_check.get("passed") is True
        and bool(field_checks)
        and all(item.get("result") == "PASS" for item in field_checks)
    )
    return {
        "schema": "rac-direct-membership-v1",
        "case": case,
        "result": CASE_RESULT[case] if passed else f"{CASE_RESULT[case]}_REJECTED",
        "passed": passed,
        "abstract_role": sigma.get("abstract_role"),
        "concrete_state": f"proof/concrete/sigma-a{case[-1]}.json",
        "abstract_state": f"proof/states/{sigma.get('abstract_role')}-state.json",
        "unsupported_fields": unsupported_fields,
        "field_checks": field_checks,
        "checks": checks,
        "frame": frame_check,
        "reasons": reasons,
    }


def _markdown(report: dict[str, Any]) -> str:
    lines = ["# Local Concretization", ""]
    for case in ("a=0", "a=1"):
        item = report["memberships"][case]
        lines.append(f"- `{case}`: `{item['result']}` using `{item['abstract_role']}` state")
    lines.extend(["", f"Joint coverage: `{report['joint_coverage']['result']}`", ""])
    lines.append("Each membership file contains per-register, range, tnum, stack, frame, and environment checks.")
    return "\n".join(lines) + "\n"


def check(bundle: Path, concrete_out: Path | None = None, out: Path | None = None) -> dict[str, Any]:
    states_dir = bundle / "proof" / "states"
    path_dir = bundle / "proof" / "path"
    concrete_out = concrete_out or bundle / "proof" / "concrete"
    out = out or bundle / "proof" / "concretization"
    concrete_out.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)

    runtime = _load(bundle / "runtime.json")
    path_report = _load(path_dir / "path-correspondence.json")
    states = {
        "retained": _load(states_dir / "retained-state.json"),
        "current": _load(states_dir / "current-state.json"),
    }
    env = make_environment(runtime, path_report)
    _write(concrete_out / "environment.json", env)

    sigmas: dict[str, dict[str, Any]] = {}
    memberships: dict[str, dict[str, Any]] = {}
    reachability: dict[str, Any] = {"schema": "rac-concrete-reachability-v1", "cases": {}}
    for case, fname in (("a=0", "sigma-a0.json"), ("a=1", "sigma-a1.json")):
        prefix = path_report["prefixes"][case]
        role = HISTORY_SIDE_TO_ROLE[prefix["history_side"]]
        abstract = state_for_role(states, role)
        sigma = sigma_for_case(case, prefix, role, abstract, path_report.get("identity") or {})
        sigmas[case] = sigma
        _write(concrete_out / fname, sigma)
        reachability["cases"][case] = {
            "branch_name": prefix["branch_name"],
            "branch_call": prefix["branch_call"],
            "history_side": prefix["history_side"],
            "abstract_role": role,
            "frontier_pc": sigma["frontier_pc"],
        }
        membership = _membership(case, sigma, abstract, env)
        memberships[case] = membership
        _write(out / ("membership-a0.json" if case == "a=0" else "membership-a1.json"), membership)
    _write(concrete_out / "reachability.json", reachability)

    both_pass = memberships["a=0"]["passed"] and memberships["a=1"]["passed"]
    joint = {
        "schema": "rac-local-joint-coverage-v1",
        "result": "JOINT_COVERAGE_CANDIDATE" if both_pass else "JOINT_COVERAGE_REJECTED",
        "passed_memberships": both_pass,
        "same_frontier": sigmas["a=0"]["frontier_pc"] == sigmas["a=1"]["frontier_pc"],
        "selected_masks": {case: sigmas[case]["selected_mask"] for case in ("a=0", "a=1")},
        "selected_masks_differ": sigmas["a=0"]["selected_mask"] != sigmas["a=1"]["selected_mask"],
        "same_suffix": env.get("same_suffix") is True,
    }
    _write(out / "joint-coverage.json", joint)
    spec = {
        "schema": "rac-direct-concretization-spec-v1",
        "state_tuple": ["pc", "regs", "stack", "frames", "refs", "svc", "env"],
        "direct_verifier_components": ["pc", "regs", "stack", "frames", "refs"],
        "service_component": "svc is intentionally unconstrained by the direct verifier-state component, while its identity and admissibility are constrained by the frozen environment contract.",
        "environment_component": "fixed map identity, capacity, flags, serialized scheduling, and no external writes during the frozen runtime witness",
        "scope": "witness-local direct verifier-state membership only; not a general Linux verifier concretization theorem",
    }
    _write(out / "concretization-spec.json", spec)
    (out / "concretization-spec.md").write_text("# Direct concretization specification\n\n" + spec["service_component"] + "\n")
    report = {"schema": "rac-local-concretization-v1", "memberships": memberships, "joint_coverage": joint, "spec": spec}
    (out / "concretization.md").write_text(_markdown(report))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args(argv)
    report = check(args.bundle)
    for case in ("a=0", "a=1"):
        print(report["memberships"][case]["result"])
    return 0 if all(report["memberships"][case]["passed"] for case in ("a=0", "a=1")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
