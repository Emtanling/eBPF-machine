#!/usr/bin/env python3
"""Validate and materialize verifier-state V2 capture for one frontier event."""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

MASK64 = (1 << 64) - 1
MIX_CONST = 0x9E3779B97F4A7C15
STATE_HASH_SEED = 0x84222325CBF29CE4
SCHEMA_VERSION = 1

UNSUPPORTED_BITS = {
    0: "multi_frame",
    1: "refs_or_ref_obj_id",
    2: "locks",
    3: "callback",
    4: "stack_truncated",
    5: "dynptr",
    6: "iterator",
    7: "socket_ref",
    8: "packet_range",
    9: "sleepable_or_rcu",
    10: "reg_parent",
}


def _as_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return default
        try:
            return int(text, 0)
        except ValueError:
            return default
    return default


def _u64(value: Any) -> int:
    return _as_int(value) & MASK64


def _u32(value: Any) -> int:
    return _as_int(value) & 0xFFFFFFFF


def mix64(h: int, value: Any) -> int:
    v = _u64(value)
    h &= MASK64
    return (h ^ ((v + MIX_CONST + ((h << 6) & MASK64) + (h >> 2)) & MASK64)) & MASK64


def _hash_reg(reg: dict[str, Any], h: int) -> int:
    var_off = reg.get("var_off") if isinstance(reg.get("var_off"), dict) else {}
    h = mix64(h, reg.get("type"))
    h = mix64(h, reg.get("id"))
    h = mix64(h, _u32(reg.get("off")))
    h = mix64(h, var_off.get("value"))
    h = mix64(h, var_off.get("mask"))
    h = mix64(h, reg.get("smin_value"))
    h = mix64(h, reg.get("smax_value"))
    h = mix64(h, reg.get("umin_value"))
    h = mix64(h, reg.get("umax_value"))
    h = mix64(h, reg.get("live"))
    h = mix64(h, reg.get("precise"))
    return h


def recompute_legacy_state_hash(snapshot: dict[str, Any]) -> str:
    state = snapshot.get("state_v2")
    if not isinstance(state, dict):
        raise ValueError("snapshot lacks state_v2")
    frames = state.get("frames")
    if not isinstance(frames, list) or not frames:
        raise ValueError("state_v2 lacks frame[0]")
    frame0 = frames[0]
    regs = frame0.get("regs") if isinstance(frame0, dict) else None
    if not isinstance(regs, list) or len(regs) != 11:
        raise ValueError("state_v2 frame[0] must carry exactly 11 regs")
    h = STATE_HASH_SEED
    h = mix64(h, state.get("insn_idx"))
    h = mix64(h, state.get("curframe"))
    h = mix64(h, state.get("speculative"))
    h = mix64(h, state.get("branches"))
    h = mix64(h, state.get("may_goto_depth"))
    for reg in regs:
        if not isinstance(reg, dict):
            raise ValueError("malformed register entry")
        h = _hash_reg(reg, h)
    h = mix64(h, frame0.get("callsite"))
    h = mix64(h, frame0.get("allocated_stack"))
    return f"{h:016x}"


def unsupported_reasons(mask: int) -> list[str]:
    reasons = [name for bit, name in sorted(UNSUPPORTED_BITS.items()) if mask & (1 << bit)]
    known = 0
    for bit in UNSUPPORTED_BITS:
        known |= 1 << bit
    unknown = mask & ~known
    if unknown:
        reasons.append(f"unknown_bits:0x{unknown:x}")
    return reasons


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def load_jsonl(path: Path) -> list[tuple[int, dict[str, Any]]]:
    rows: list[tuple[int, dict[str, Any]]] = []
    for lineno, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        rows.append((lineno, json.loads(line)))
    return rows


def select_frontier_event(frontier: dict[str, Any], events: list[tuple[int, dict[str, Any]]]) -> tuple[dict[str, Any], dict[str, Any]]:
    passed = [e for e in frontier.get("events", []) if isinstance(e, dict) and e.get("passed") is True]
    if not passed:
        raise ValueError("frontier-check has no passed event")
    selected = passed[0]
    line = _as_int(selected.get("line"), -1)
    visit = _as_int(selected.get("visit_insn"), -1)
    if line > 0:
        for lineno, event in events:
            if lineno == line:
                return selected, event
    for _lineno, event in events:
        if event.get("event") == "prune_hit" and _as_int(event.get("visit_insn"), -2) == visit:
            return selected, event
    raise ValueError("could not match frontier event to events.jsonl")


def identity_from_bundle(bundle: Path, frontier: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    identity = dict(frontier.get("identity") or {})
    for key in ("object_sha256", "program_id", "program_tag", "program_pin", "xlated_sha256"):
        if key not in identity and key in event:
            identity[key] = event[key]
    runtime_path = bundle / "runtime.json"
    if runtime_path.exists():
        runtime = load_json(runtime_path)
        for key in ("object_sha256", "program_id", "program_tag", "program_pin", "xlated_sha256"):
            if key not in identity and key in runtime:
                identity[key] = runtime[key]
    return identity


def validate_snapshot(role: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    checks: dict[str, Any] = {"role": role, "passed": True, "reasons": []}
    state = snapshot.get("state_v2")
    if not isinstance(state, dict):
        checks["passed"] = False
        checks["reasons"].append("MISSING_STATE_V2")
        return checks
    if state.get("schema") != "rac-verifier-state-v2":
        checks["passed"] = False
        checks["reasons"].append("WRONG_STATE_V2_SCHEMA")
    if _as_int(state.get("schema_version")) != SCHEMA_VERSION:
        checks["passed"] = False
        checks["reasons"].append("WRONG_STATE_V2_VERSION")
    if state.get("valid") is not True:
        checks["passed"] = False
        checks["reasons"].append("STATE_V2_INVALID")
    frames = state.get("frames")
    if not isinstance(frames, list) or len(frames) != _as_int(state.get("captured_frame_count")):
        checks["passed"] = False
        checks["reasons"].append("FRAME_COUNT_MISMATCH")
    if _as_int(state.get("captured_frame_count")) != 1:
        checks["passed"] = False
        checks["reasons"].append("EXPECTED_ONE_CAPTURED_FRAME")
    if snapshot.get("history_truncated") is True:
        checks["passed"] = False
        checks["reasons"].append("HISTORY_TRUNCATED")
    mask = _as_int(state.get("unsupported_mask"))
    checks["unsupported_mask"] = mask
    checks["unsupported_reasons"] = unsupported_reasons(mask)
    if mask:
        checks["passed"] = False
        checks["reasons"].append("UNSUPPORTED_STATE_SHAPE")
    try:
        recomputed = recompute_legacy_state_hash(snapshot)
    except ValueError as exc:
        checks["passed"] = False
        checks["reasons"].append(str(exc))
        recomputed = None
    recorded = str(snapshot.get("state_hash", "")).lower()
    checks["recorded_state_hash"] = recorded
    checks["recomputed_state_hash"] = recomputed
    checks["state_hash_matches"] = bool(recomputed and recorded == recomputed)
    if not checks["state_hash_matches"]:
        checks["passed"] = False
        checks["reasons"].append("STATE_HASH_RECOMPUTE_MISMATCH")
    return checks


def materialize(bundle: Path, frontier_path: Path, out: Path) -> dict[str, Any]:
    frontier = load_json(frontier_path)
    if frontier.get("result") != "FRONTIER_ELIGIBLE":
        raise ValueError("state V2 requires FRONTIER_ELIGIBLE input")
    events = load_jsonl(bundle / "events.jsonl")
    selected_frontier, event = select_frontier_event(frontier, events)
    old = event.get("old")
    current = event.get("current")
    if not isinstance(old, dict) or not isinstance(current, dict):
        raise ValueError("selected prune event lacks old/current snapshots")

    out.mkdir(parents=True, exist_ok=True)
    identity = identity_from_bundle(bundle, frontier, event)
    old_check = validate_snapshot("retained", old)
    current_check = validate_snapshot("current", current)
    unsupported = sorted(set(old_check.get("unsupported_reasons", [])) | set(current_check.get("unsupported_reasons", [])))
    all_checks_passed = bool(old_check.get("passed") and current_check.get("passed"))
    if unsupported:
        result = "UNSUPPORTED_STATE_SHAPE"
    elif all_checks_passed:
        result = "STATE_V2_CAPTURE_OK"
    else:
        result = "STATE_V2_CAPTURE_REJECTED"

    retained_doc = {
        "schema": "rac-retained-state-v2-proof",
        "role": "retained",
        "identity": identity,
        "snapshot": old,
    }
    current_doc = {
        "schema": "rac-current-state-v2-proof",
        "role": "current",
        "identity": identity,
        "snapshot": current,
    }
    comparison = {
        "schema": "rac-state-v2-comparison",
        "comparison_mode": event.get("exact_level"),
        "visit_insn": event.get("visit_insn"),
        "frontier": frontier.get("frontier"),
        "identity": identity,
        "states_equal_success": event.get("states_equal_success"),
        "is_state_visited_prune": event.get("is_state_visited_prune"),
        "retained_state_hash": old.get("state_hash"),
        "current_state_hash": current.get("state_hash"),
        "retained_recomputed_state_hash": old_check.get("recomputed_state_hash"),
        "current_recomputed_state_hash": current_check.get("recomputed_state_hash"),
        "history_left": selected_frontier.get("history_left"),
        "history_right": selected_frontier.get("history_right"),
    }
    shape = {
        "schema": "rac-state-v2-shape",
        "result": "SUPPORTED_STATE_SHAPE" if result == "STATE_V2_CAPTURE_OK" else result,
        "scope_constraints": [
            "single frame",
            "no dynptr",
            "no socket/reference ownership",
            "no iterator/callback",
            "no packet range",
            "bounded verifier stack capture",
        ],
        "unsupported_reasons": unsupported,
        "retained": {
            "unsupported_mask": old_check.get("unsupported_mask"),
            "unsupported_reasons": old_check.get("unsupported_reasons"),
        },
        "current": {
            "unsupported_mask": current_check.get("unsupported_mask"),
            "unsupported_reasons": current_check.get("unsupported_reasons"),
        },
    }
    report = {
        "schema": "rac-state-v2-capture-check",
        "result": result,
        "frontier_result": frontier.get("result"),
        "selected_event_line": selected_frontier.get("line"),
        "visit_insn": event.get("visit_insn"),
        "identity": identity,
        "checks": {
            "retained": old_check,
            "current": current_check,
            "all_checks_passed": all_checks_passed,
        },
        "outputs": {
            "retained_state": "retained-state.json",
            "current_state": "current-state.json",
            "comparison": "comparison.json",
            "state_shape": "state-shape.json",
            "state_schema": "state_schema.json",
        },
    }

    (out / "retained-state.json").write_text(json.dumps(retained_doc, indent=2, sort_keys=True) + "\n")
    (out / "current-state.json").write_text(json.dumps(current_doc, indent=2, sort_keys=True) + "\n")
    (out / "comparison.json").write_text(json.dumps(comparison, indent=2, sort_keys=True) + "\n")
    (out / "state-shape.json").write_text(json.dumps(shape, indent=2, sort_keys=True) + "\n")
    schema_src = Path("linux/tracer/state_schema.json")
    if schema_src.exists():
        shutil.copyfile(schema_src, out / "state_schema.json")
    (out / "state-capture-check.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="Linux evidence bundle containing events.jsonl")
    parser.add_argument("--frontier-check", type=Path, default=None, help="frontier-check.json path")
    parser.add_argument("--out", type=Path, default=None, help="output proof/states directory")
    args = parser.parse_args(argv)
    bundle = args.bundle
    frontier_path = args.frontier_check or bundle / "frontier-check.json"
    out = args.out or bundle / "proof" / "states"
    report = materialize(bundle, frontier_path, out)
    print(report["result"])
    return 0 if report["result"] == "STATE_V2_CAPTURE_OK" else 1


if __name__ == "__main__":
    raise SystemExit(main())
