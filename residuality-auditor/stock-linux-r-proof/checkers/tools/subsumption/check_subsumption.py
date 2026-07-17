#!/usr/bin/env python3
"""Establish a restricted current-subsumed-by-retained lemma for one RAC bundle."""
from __future__ import annotations

import argparse
import json
import platform
from pathlib import Path
from typing import Any

from tools.concretization.schema import NOT_INIT, PTR_TO_STACK, SCALAR_VALUE

SUPPORTED_TYPES = {NOT_INIT, SCALAR_VALUE, PTR_TO_STACK}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _write(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def _load_selected_event(bundle: Path, visit: int) -> dict[str, Any]:
    for line in (bundle / "events.jsonl").read_text().splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("event") == "prune_hit" and int(event.get("visit_insn", -1)) == visit:
            return event
    return {}


def _tnum_subset(cur: dict[str, Any], retained: dict[str, Any]) -> bool:
    cv, cm = int(cur.get("value", 0)), int(cur.get("mask", 0))
    rv, rm = int(retained.get("value", 0)), int(retained.get("mask", 0))
    # Every bit known by retained must be known to the same value by current.
    return (cv & ~rm) == (rv & ~rm) and (cm | rm) == rm


def _range_subset(cur: dict[str, Any], retained: dict[str, Any]) -> bool:
    fields = [
        ("umin_value", ">="), ("umax_value", "<="),
        ("smin_value", ">="), ("smax_value", "<="),
        ("u32_min_value", ">="), ("u32_max_value", "<="),
        ("s32_min_value", ">="), ("s32_max_value", "<="),
    ]
    for field, op in fields:
        c, r = int(cur.get(field, 0)), int(retained.get(field, 0))
        if op == ">=" and c < r:
            return False
        if op == "<=" and c > r:
            return False
    return True


def _reg_subsumption(idx: int, cur: dict[str, Any], retained: dict[str, Any]) -> dict[str, Any]:
    ct, rt = int(cur.get("type")), int(retained.get("type"))
    reasons: list[str] = []
    if ct not in SUPPORTED_TYPES or rt not in SUPPORTED_TYPES:
        reasons.append(f"unsupported reg type current={ct} retained={rt}")
    if rt == NOT_INIT:
        passed = not reasons
        basis = "retained NOT_INIT is treated as future-dead/top in this restricted observed exact=0 comparison"
    elif ct != rt:
        passed = False
        basis = "type mismatch is not covered by restricted checker"
    elif ct == SCALAR_VALUE:
        passed = _tnum_subset(cur.get("var_off") or {}, retained.get("var_off") or {}) and _range_subset(cur, retained)
        basis = "scalar tnum and numeric ranges are subsets"
    elif ct == PTR_TO_STACK:
        passed = cur.get("off") == retained.get("off") and (cur.get("var_off") or {}) == (retained.get("var_off") or {})
        basis = "stack pointer frame/offset/var_off match"
    else:
        passed = not reasons
        basis = "identical supported type"
    if not passed and not reasons:
        reasons.append("field relation is not a subset under restricted model")
    return {"reg": idx, "current_type": ct, "retained_type": rt, "passed": passed, "basis": basis, "reasons": reasons}


def _stack_subsumption(cur_slots: list[dict[str, Any]], retained_slots: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_slot = {int(slot.get("slot")): slot for slot in retained_slots}
    results = []
    for cur in cur_slots:
        slot_id = int(cur.get("slot"))
        retained = by_slot.get(slot_id, {"slot": slot_id, "initialized": False, "slot_type": []})
        if not retained.get("initialized"):
            results.append({
                "slot": slot_id,
                "passed": True,
                "basis": "retained stack slot is future-dead/uninitialized in restricted observed comparison",
                "current_slot_type": cur.get("slot_type"),
                "retained_slot_type": retained.get("slot_type"),
                "reasons": [],
            })
        else:
            same = cur.get("slot_type") == retained.get("slot_type")
            results.append({"slot": slot_id, "passed": same, "basis": "slot_type equality", "reasons": [] if same else ["slot_type mismatch"]})
    return results


def _markdown(report: dict[str, Any]) -> str:
    return f"""# Restricted Shape Lemma

Result: `{report['result']}`

This lemma is restricted to kernel `{report['kernel']['kernel_release']}`, exact comparison mode `{report['comparison_mode']}`, frontier `{report['frontier']['join_insn']}`, and the captured State V2 witness shape. It does not claim general Linux `states_equal` semantics.

Modeled relation: `gamma_l(current) subseteq gamma_l(retained)` for the local future-observable fields represented in this proof bundle.
"""


def check(bundle: Path, out: Path | None = None) -> dict[str, Any]:
    out = out or bundle / "proof" / "subsumption"
    out.mkdir(parents=True, exist_ok=True)
    state_check = _load(bundle / "proof" / "states" / "state-capture-check.json")
    path_report = _load(bundle / "proof" / "path" / "path-correspondence.json")
    conc_a0 = _load(bundle / "proof" / "concretization" / "membership-a0.json")
    conc_a1 = _load(bundle / "proof" / "concretization" / "membership-a1.json")
    retained = _load(bundle / "proof" / "states" / "retained-state.json")["snapshot"]["state_v2"]["frames"][0]
    current = _load(bundle / "proof" / "states" / "current-state.json")["snapshot"]["state_v2"]["frames"][0]
    frontier = path_report["frontier"]
    event = _load_selected_event(bundle, int(frontier["join_insn"]))
    comparison_mode = event.get("exact_level")

    preconditions = {
        "state_v2": state_check.get("result") == "STATE_V2_CAPTURE_OK",
        "path_correspondence": path_report.get("result") == "PATH_CORRESPONDENCE_VERIFIED",
        "membership_a0": conc_a0.get("result") == "SIGMA_A0_IN_DIRECT_GAMMA",
        "membership_a1": conc_a1.get("result") == "SIGMA_A1_IN_DIRECT_GAMMA",
        "states_equal_success": event.get("states_equal_success") is True,
        "is_state_visited_prune": event.get("is_state_visited_prune") is True,
        "exact_level_supported": comparison_mode == 0,
    }
    reg_results = [_reg_subsumption(i, c, r) for i, (c, r) in enumerate(zip(current.get("regs") or [], retained.get("regs") or []))]
    stack_results = _stack_subsumption(current.get("stack_slots") or [], retained.get("stack_slots") or [])
    unsupported = [r for r in reg_results if not r["passed"]] + [s for s in stack_results if not s["passed"]]
    passed = all(preconditions.values()) and not unsupported
    result = "RESTRICTED_SUBSUMPTION_ESTABLISHED" if passed else "RESTRICTED_SUBSUMPTION_REJECTED"

    kernel = {
        "kernel_release": _load(bundle / "runtime.json").get("kernel_release"),
        "program_identity": path_report.get("identity"),
        "source_body_available": False,
        "source_basis": "local Ubuntu headers expose BTF/types but not kernel/bpf/verifier.c bodies; this checker therefore records a restricted field model and refuses unsupported types/branches",
        "host": platform.platform(),
    }
    compared = {
        "schema": "rac-compared-fields-v1",
        "registers": reg_results,
        "stack_slots": stack_results,
        "direction": "current_to_retained",
    }
    unsupported_doc = {"schema": "rac-unsupported-branches-v1", "unsupported": unsupported, "preconditions": preconditions}
    report = {
        "schema": "rac-restricted-subsumption-v1",
        "result": result,
        "kernel": kernel,
        "comparison_mode": comparison_mode,
        "frontier": frontier,
        "preconditions": preconditions,
        "compared_fields": compared,
        "unsupported": unsupported,
        "theorem_scope": ["specific kernel build", "exact_level=0", "captured State V2 shape", "frontier join", "local future-observable projection"],
    }
    _write(out / "kernel-source-map.json", kernel)
    _write(out / "compared-fields.json", compared)
    _write(out / "unsupported-branches.json", unsupported_doc)
    _write(out / "subsumption-check.json", report)
    (out / "restricted-shape-lemma.md").write_text(_markdown(report))
    (out / "checker-trace.md").write_text(_markdown(report) + "\nSee compared-fields.json for per-field trace.\n")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args(argv)
    report = check(args.bundle)
    print(report["result"])
    return 0 if report["result"] == "RESTRICTED_SUBSUMPTION_ESTABLISHED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
