"""Fail-closed v0.3.2 frontier checker for a pinned Linux-R evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    # Support the documented direct-script form as well as ``python -m``.
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from tools.frontier.build_cfg import build_cfg
    from tools.frontier.locate_calls import locate_frontier
    from tools.frontier.parse_xlated import parse_xlated_file
    from tools.frontier.schema import Frontier, FrontierError
else:
    from .build_cfg import build_cfg
    from .locate_calls import locate_frontier
    from .parse_xlated import parse_xlated_file
    from .schema import Frontier, FrontierError


_SHA256_RE = re.compile(r"\b([0-9a-fA-F]{64})\b")
_PROGRAM_NAME = "rac_single"
_LEGACY_PRUNE_SOURCES = {
    "fexit/states_equal+is_state_visited",
    "kprobe+ kretprobe states_equal/is_state_visited",
}
_CHECKER_SCHEMA = "rac-frontier-check-v1"
_CHECKER_VERSION = "0.3.2"
_PROOF_ARTIFACTS = (
    "cfg.json",
    "call-sites.json",
    "shared-suffix.json",
    "frontier.json",
    "frontier-check.json",
    "frontier-check.md",
)


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _text(value: Any) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def _lookup(value: Any, keys: set[str]) -> Any:
    """Read one scalar identity field from the documented top-level object.

    bpftool program JSON and ``rac-linux-runtime-v1`` expose program identity
    at their roots.  Looking through arbitrary nested metadata lets unrelated
    map IDs either override the program identity or satisfy a missing one.
    """

    if not isinstance(value, dict):
        return None
    candidates: list[Any] = []
    for key, item in value.items():
        if key.lower() in keys and not isinstance(item, (dict, list)):
            candidates.append(item)
    unique: list[Any] = []
    for item in candidates:
        if item not in unique:
            unique.append(item)
    return unique[0] if len(unique) == 1 else None


def _top_values(event: dict[str, Any], keys: set[str]) -> list[Any]:
    values: list[Any] = []
    for key, value in event.items():
        if key.lower() in keys and not isinstance(value, (dict, list)):
            values.append(value)
    program = event.get("program")
    if isinstance(program, dict):
        for key, value in program.items():
            if key.lower() in keys and not isinstance(value, (dict, list)):
                values.append(value)
    unique: list[Any] = []
    for value in values:
        if value not in unique:
            unique.append(value)
    return unique


def _top_lookup(event: dict[str, Any], keys: set[str]) -> Any:
    values = _top_values(event, keys)
    return values[0] if len(values) == 1 else None


def _normalize_sha(value: Any) -> str | None:
    text = _text(value)
    if text and re.fullmatch(r"[0-9a-fA-F]{64}", text):
        return text.lower()
    return None


def _normalize_tag(value: Any) -> str | None:
    text = _text(value)
    if text and re.fullmatch(r"[0-9a-fA-F]+", text):
        return text.lower()
    return None


def _read_object_sha(path: Path) -> str | None:
    match = _SHA256_RE.search(path.read_text(encoding="utf-8"))
    return match.group(1).lower() if match else None


def _input_hashes(bundle: Path) -> dict[str, str]:
    return {
        path.name: _sha256(path)
        for path in sorted(bundle.iterdir())
        if path.is_file()
        and path.name
        in {
            "object.sha256",
            "runtime.json",
            "program-info.json",
            "program-pin.txt",
            "events.jsonl",
            "events.raw.jsonl",
            "xlated-rac_single.txt",
            "xlated-rac_single.sha256",
        }
    }


def _bundle_identity(bundle: Path, input_hashes: dict[str, str]) -> tuple[dict[str, Any], list[str]]:
    """Bind object, pinned program, and exact xlated bytes from one bundle."""

    reasons: list[str] = []
    required = [
        "object.sha256",
        "runtime.json",
        "program-info.json",
        "program-pin.txt",
        "xlated-rac_single.txt",
        "xlated-rac_single.sha256",
    ]
    for name in required:
        if not (bundle / name).is_file():
            reasons.append(f"MISSING_ARTIFACT:{name}")
    if reasons:
        return {"input_sha256": input_hashes}, reasons
    try:
        object_sha = _read_object_sha(bundle / "object.sha256")
        runtime = _read_json(bundle / "runtime.json")
        program_info = _read_json(bundle / "program-info.json")
        pin = (bundle / "program-pin.txt").read_text(encoding="utf-8").strip()
        recorded_xlated_sha = _read_object_sha(bundle / "xlated-rac_single.sha256")
    except (OSError, json.JSONDecodeError) as error:
        return {"input_sha256": input_hashes}, [f"IDENTITY_ARTIFACT_UNREADABLE:{error}"]

    runtime_sha = _normalize_sha(_lookup(runtime, {"object_sha256", "object_sha"}))
    runtime_id = _int(_lookup(runtime, {"program_id", "prog_id"}))
    runtime_tag = _normalize_tag(_lookup(runtime, {"program_tag", "prog_tag"}))
    runtime_pin = _text(_lookup(runtime, {"program_pin", "pin_path", "pinned_path"}))
    program_id = _int(_lookup(program_info, {"id", "program_id", "prog_id"}))
    program_tag = _normalize_tag(_lookup(program_info, {"tag", "program_tag", "prog_tag"}))
    program_name = _text(_lookup(program_info, {"name", "program_name"}))
    program_bytes_xlated = _int(_lookup(program_info, {"bytes_xlated"}))
    runtime_xlated_sha = _normalize_sha(_lookup(runtime, {"xlated_sha256", "xlated_sha"}))
    xlated_sha = input_hashes.get("xlated-rac_single.txt")
    identity: dict[str, Any] = {
        "schema": "rac-frontier-identity-v1",
        "object_sha256": object_sha,
        "runtime_object_sha256": runtime_sha,
        "program_id": program_id,
        "runtime_program_id": runtime_id,
        "program_tag": program_tag,
        "runtime_program_tag": runtime_tag,
        "program_name": program_name,
        "program_bytes_xlated": program_bytes_xlated,
        "program_pin": pin or None,
        "runtime_program_pin": runtime_pin,
        "xlated_sha256": xlated_sha,
        "recorded_xlated_sha256": recorded_xlated_sha,
        "runtime_xlated_sha256": runtime_xlated_sha,
        "input_sha256": input_hashes,
    }
    if object_sha is None:
        reasons.append("OBJECT_SHA_UNAVAILABLE")
    if runtime_sha != object_sha:
        reasons.append("OBJECT_SHA_RUNTIME_MISMATCH")
    if program_id is None or runtime_id != program_id:
        reasons.append("PROGRAM_ID_MISMATCH")
    if program_tag is None or runtime_tag != program_tag:
        reasons.append("PROGRAM_TAG_MISMATCH")
    if program_name != _PROGRAM_NAME:
        reasons.append("PROGRAM_NAME_NOT_RAC_SINGLE")
    if not pin or runtime_pin != pin:
        reasons.append("PROGRAM_PIN_MISMATCH")
    if recorded_xlated_sha is None or recorded_xlated_sha != xlated_sha:
        reasons.append("XLATED_SHA_SIDECAR_MISMATCH")
    if runtime_xlated_sha is None:
        reasons.append("XLATED_SHA_RUNTIME_UNAVAILABLE")
    elif runtime_xlated_sha != xlated_sha:
        reasons.append("XLATED_SHA_RUNTIME_MISMATCH")
    return identity, reasons


def _xlated_length_reasons(
    instructions: list[Any], identity: dict[str, Any]
) -> list[str]:
    """Bind the dump's instruction slots to bpftool's pinned-program length."""

    if not instructions:
        return ["XLATED_INSTRUCTION_SLOTS_UNAVAILABLE"]
    slots = max(instruction.next_pc for instruction in instructions)
    occupied: set[int] = set()
    coverage_errors: set[str] = set()
    for instruction in instructions:
        for slot in range(instruction.pc, instruction.next_pc):
            if slot in occupied:
                coverage_errors.add("XLATED_INSTRUCTION_SLOT_OVERLAP")
            occupied.add(slot)
    if occupied != set(range(slots)):
        coverage_errors.add("XLATED_INSTRUCTION_SLOT_GAP")
    expected_bytes = _int(identity.get("program_bytes_xlated"))
    identity["xlated_instruction_slots"] = slots
    identity["xlated_instruction_bytes"] = slots * 8
    reasons = sorted(coverage_errors)
    if expected_bytes is None:
        return reasons + ["PROGRAM_XLATED_LENGTH_UNAVAILABLE"]
    if expected_bytes != slots * 8:
        reasons.append("PROGRAM_XLATED_LENGTH_MISMATCH")
    return reasons


_TYPED_RESULT_KEYS = {"result", "return", "ret", "status", "success", "value"}


def _success(value: Any) -> bool:
    """Decode explicit verifier result evidence without inferring from a leaf.

    A structured result must expose one or more designated scalar result
    fields, and every supplied field must say success.  This rejects records
    such as ``{"return": -1, "status": "success"}`` instead of promoting
    one convenient positive token to a verifier fact.
    """

    if value is True or value == 1:
        return True
    if isinstance(value, str):
        return value.lower() in {"1", "true", "success", "equal", "pruned", "visited"}
    if isinstance(value, dict):
        results = [
            item
            for key, item in value.items()
            if key.lower() in _TYPED_RESULT_KEYS and not isinstance(item, (dict, list))
        ]
        return bool(results) and all(_success(item) for item in results)
    return False


def _event_success_values(event: dict[str, Any], keys: set[str]) -> list[Any]:
    values: list[Any] = []
    for key, value in event.items():
        if key.lower() in keys:
            values.append(value)
    verifier = event.get("verification")
    if isinstance(verifier, dict):
        for key, value in verifier.items():
            if key.lower() in keys:
                values.append(value)
    return values


def _source_proves(event: dict[str, Any]) -> bool:
    """Accept only the collector's documented joined-prune provenance."""

    return (
        event.get("event") == "prune_hit"
        and _top_lookup(event, {"source"}) in _LEGACY_PRUNE_SOURCES
    )


def _operation_succeeded(event: dict[str, Any], keys: set[str]) -> bool:
    """Prefer typed evidence; a legacy source label is a fallback only if absent."""

    values = _event_success_values(event, keys)
    return all(_success(value) for value in values) if values else _source_proves(event)


def _looks_like_prune(event: dict[str, Any]) -> bool:
    return event.get("event") == "prune_hit"


def _history(snapshot: dict[str, Any]) -> tuple[list[Any] | None, int | None, int | None, bool | None]:
    entries = snapshot.get("history_entries")
    if entries is None:
        entries = snapshot.get("path_history")
    if isinstance(entries, dict):
        entries = entries.get("entries")
    total = _int(snapshot.get("history_total_count"))
    captured = _int(snapshot.get("history_captured_count"))
    truncated = snapshot.get("history_truncated")
    return entries if isinstance(entries, list) else None, total, captured, truncated if isinstance(truncated, bool) else None


def _entry_pcs(entries: list[Any]) -> tuple[set[int], set[str]]:
    pcs: set[int] = set()
    reasons: set[str] = set()
    for entry in entries:
        if isinstance(entry, int):
            pcs.add(entry)
        elif isinstance(entry, dict):
            values = {
                value
                for key in ("insn_idx", "instruction", "idx", "pc")
                if (value := _int(entry.get(key))) is not None
            }
            if len(values) == 1:
                pcs.update(values)
            elif values:
                reasons.add("HISTORY_ENTRY_INSN_CONFLICT")
            else:
                reasons.add("HISTORY_ENTRY_INSN_UNAVAILABLE")
        else:
            reasons.add("HISTORY_ENTRY_INSN_UNAVAILABLE")
    return pcs, reasons


def _entry_single_value(entry: Any, keys: tuple[str, ...]) -> int | None:
    if not isinstance(entry, dict):
        return None
    values = {value for key in keys if (value := _int(entry.get(key))) is not None}
    return next(iter(values)) if len(values) == 1 else None


def _branch_provenance_hits(
    entries: list[Any],
    frontier: Frontier,
    instruction_by_pc: dict[int, Any],
    function_by_pc: dict[int, str | None],
) -> set[int]:
    hits: set[int] = set()
    for entry in entries:
        if isinstance(entry, int):
            pc = entry
            prev_pc = None
        else:
            pc = _entry_single_value(entry, ("insn_idx", "instruction", "idx", "pc"))
            prev_pc = _entry_single_value(entry, ("prev_insn_idx", "prev_instruction", "prev_idx", "prev_pc"))
        if pc is None:
            continue
        for call_pc in frontier.branch_calls:
            instruction = instruction_by_pc.get(call_pc)
            if pc == call_pc:
                hits.add(call_pc)
            elif instruction is not None and pc == instruction.next_pc and prev_pc is not None:
                prev_function = function_by_pc.get(prev_pc)
                if prev_function is not None and prev_function != instruction.function:
                    hits.add(call_pc)
    return hits

def _history_reasons(
    old: dict[str, Any],
    current: dict[str, Any],
    frontier: Frontier,
    instruction_by_pc: dict[int, Any],
    function_by_pc: dict[int, str | None],
) -> list[str]:
    old_entries, old_total, old_captured, old_truncated = _history(old)
    current_entries, current_total, current_captured, current_truncated = _history(current)
    values = ((old_entries, old_total, old_captured, old_truncated), (current_entries, current_total, current_captured, current_truncated))
    if any(entries is None for entries, _, _, _ in values):
        return ["HISTORY_PROVENANCE_UNAVAILABLE"]
    if any(total is None or captured is None or truncated is None for _, total, captured, truncated in values):
        return ["HISTORY_CAPTURE_METADATA_UNAVAILABLE"]
    if any(truncated or total != captured or captured != len(entries) for entries, total, captured, truncated in values):
        return ["HISTORY_TRUNCATED_OR_INCOMPLETE"]
    assert old_entries is not None and current_entries is not None
    if old_entries == current_entries:
        return ["HISTORIES_NOT_DISTINCT"]
    old_pcs, old_entry_reasons = _entry_pcs(old_entries)
    current_pcs, current_entry_reasons = _entry_pcs(current_entries)
    if old_entry_reasons or current_entry_reasons:
        return sorted(old_entry_reasons | current_entry_reasons)
    old_hits = _branch_provenance_hits(old_entries, frontier, instruction_by_pc, function_by_pc)
    current_hits = _branch_provenance_hits(current_entries, frontier, instruction_by_pc, function_by_pc)
    if len(old_hits) != 1 or len(current_hits) != 1 or old_hits == current_hits:
        return ["HISTORY_BRANCH_PROVENANCE_AMBIGUOUS"]
    return []


def _history_summary(
    snapshot: dict[str, Any],
    frontier: Frontier,
    instruction_by_pc: dict[int, Any],
    function_by_pc: dict[int, str | None],
) -> dict[str, Any]:
    entries, total, captured, truncated = _history(snapshot)
    entry_pcs, entry_reasons = _entry_pcs(entries) if entries else (set(), set())
    branch_hits = sorted(_branch_provenance_hits(entries or [], frontier, instruction_by_pc, function_by_pc))
    return {
        "entries": entries if entries is not None else [],
        "total_count": total,
        "captured_count": captured,
        "truncated": truncated,
        "branch_call_hits": branch_hits,
        "entry_reasons": sorted(entry_reasons),
    }


def _event_identity_reasons(event: dict[str, Any], identity: dict[str, Any]) -> list[str]:
    event_sha = _normalize_sha(_top_lookup(event, {"object_sha256", "object_sha"}))
    event_tag = _normalize_tag(_top_lookup(event, {"program_tag", "prog_tag", "object_tag"}))
    event_id = _int(_top_lookup(event, {"program_id", "prog_id"}))
    event_pin = _text(_top_lookup(event, {"program_pin", "pin_path", "pinned_path"}))
    reasons: list[str] = []
    if event_sha is None:
        reasons.append("EVENT_OBJECT_SHA_UNAVAILABLE")
    elif event_sha != identity.get("object_sha256"):
        reasons.append("EVENT_OBJECT_SHA_MISMATCH")
    if event_tag is None:
        reasons.append("EVENT_PROGRAM_TAG_UNAVAILABLE")
    elif event_tag != identity.get("program_tag"):
        reasons.append("EVENT_PROGRAM_TAG_MISMATCH")
    if event_id is None:
        reasons.append("EVENT_PROGRAM_ID_UNAVAILABLE")
    elif event_id != identity.get("program_id"):
        reasons.append("EVENT_PROGRAM_ID_MISMATCH")
    if event_pin is None:
        reasons.append("EVENT_PROGRAM_PIN_UNAVAILABLE")
    elif event_pin != identity.get("program_pin"):
        reasons.append("EVENT_PROGRAM_PIN_MISMATCH")
    return reasons


def _event_check(
    event: dict[str, Any],
    line: int,
    frontier: Frontier,
    identity: dict[str, Any],
    global_reasons: list[str],
    function_by_pc: dict[int, str | None],
    instruction_by_pc: dict[int, Any],
) -> dict[str, Any]:
    reasons = list(global_reasons)
    reasons.extend(_event_identity_reasons(event, identity))
    old = event.get("old")
    current = event.get("current")
    if not isinstance(old, dict) or not isinstance(current, dict):
        reasons.append("VERIFIER_STATE_SNAPSHOTS_UNAVAILABLE")
    states_equal_success = _operation_succeeded(
        event, {"states_equal", "states_equal_result", "states_equal_ret", "equal_result"}
    )
    if not states_equal_success:
        reasons.append("STATES_EQUAL_SUCCESS_UNPROVEN")
    is_state_visited_prune = _operation_succeeded(
        event, {"is_state_visited", "is_state_visited_pruned", "is_state_visited_result", "pruned"}
    )
    if not is_state_visited_prune:
        reasons.append("IS_STATE_VISITED_PRUNE_UNPROVEN")
    event_program = _text(_top_lookup(event, {"program_name", "program"}))
    if event_program != _PROGRAM_NAME:
        reasons.append("EVENT_PROGRAM_NOT_RAC_SINGLE")
    visit = _int(event.get("visit_insn"))
    conflicting_visits = [
        value
        for key in ("visited_insn", "target_insn")
        if (value := _int(event.get(key))) is not None and value != visit
    ]
    if visit is None:
        reasons.append("FIXED_VISIT_INSN_UNAVAILABLE")
    elif conflicting_visits:
        reasons.append("FIXED_VISIT_INSN_CONFLICT")
    elif visit != frontier.join_insn:
        if function_by_pc.get(visit) == "rac_single" and visit > frontier.join_insn:
            reasons.append("VISIT_AFTER_FIRST_SENSITIVE")
        else:
            reasons.append("VISIT_OUTSIDE_CANONICAL_PRE_SUFFIX_FRONTIER")
    if isinstance(old, dict) and isinstance(current, dict):
        reasons.extend(_history_reasons(old, current, frontier, instruction_by_pc, function_by_pc))
    return {
        "line": line,
        "visit_insn": visit,
        "old_state_insn_idx": _int(old.get("insn_idx")) if isinstance(old, dict) else None,
        "current_state_insn_idx": _int(current.get("insn_idx")) if isinstance(current, dict) else None,
        "states_equal_success": states_equal_success,
        "is_state_visited_prune": is_state_visited_prune,
        "history_left": _history_summary(old, frontier, instruction_by_pc, function_by_pc) if isinstance(old, dict) else None,
        "history_right": _history_summary(current, frontier, instruction_by_pc, function_by_pc) if isinstance(current, dict) else None,
        "same_remaining_xlated_suffix": visit == frontier.join_insn,
        "passed": not reasons,
        "reasons": sorted(set(reasons)),
    }


def _read_events(path: Path) -> tuple[list[tuple[int, dict[str, Any]]], list[str]]:
    events: list[tuple[int, dict[str, Any]]] = []
    errors: list[str] = []
    if not path.is_file():
        return events, ["MISSING_ARTIFACT:events.jsonl"]
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            errors.append(f"EVENT_JSON_INVALID:line={line_number}:{error.msg}")
            continue
        if isinstance(event, dict) and _looks_like_prune(event):
            events.append((line_number, event))
    return events, errors


def _markdown(report: dict[str, Any]) -> str:
    lines = ["# v0.3.2 Frontier Check", "", f"Verdict: `{report['result']}`", ""]
    frontier = report.get("frontier")
    if isinstance(frontier, dict):
        lines.extend(
            [
                "## Canonical frontier",
                "",
                f"- shared-suffix call (eligible pre-call state): `{frontier.get('join_insn')}`",
                f"- shared-suffix entry: `{frontier.get('suffix_entry_insn')}`",
                f"- first state-sensitive helper: `{frontier.get('first_sensitive_insn')}`",
                "",
            ]
        )
    lines.extend(["## Event decisions", ""])
    decisions = report.get("events", [])
    if not decisions:
        lines.append("- No prune event was eligible.")
    for event in decisions:
        if event.get("passed"):
            lines.append(f"- line {event['line']}: eligible at visit `{event['visit_insn']}`")
        else:
            lines.append(f"- line {event['line']}: rejected — {', '.join(event['reasons'])}")
    return "\n".join(lines) + "\n"


def _check_bundle(bundle: Path, output: Path) -> dict[str, Any]:
    """Check a bundle into an already-isolated proof staging directory.

    The result is intentionally fail-closed: legacy history hashes are never
    promoted to branch provenance, and a caller instruction after the suffix
    call is never treated as a pre-suffix state.
    """

    hashes = _input_hashes(bundle) if bundle.is_dir() else {}
    identity, identity_reasons = _bundle_identity(bundle, hashes) if bundle.is_dir() else ({"input_sha256": hashes}, ["BUNDLE_NOT_DIRECTORY"])

    instructions = []
    parse_reasons: list[str] = []
    try:
        instructions = parse_xlated_file(bundle / "xlated-rac_single.txt")
        cfg: dict[str, object] = build_cfg(instructions)
        cfg["xlated_sha256"] = hashes.get("xlated-rac_single.txt")
        identity_reasons.extend(_xlated_length_reasons(instructions, identity))
    except (OSError, FrontierError) as error:
        cfg = {"schema": "rac-frontier-cfg-v1", "instructions": [], "edges": [], "error": str(error)}
        parse_reasons.append(f"XLATED_PARSE_OR_CFG_FAILED:{error}")
    _write_json(output / "cfg.json", cfg)

    frontier: Frontier | None = None
    call_sites: dict[str, Any] = {"schema": "rac-frontier-shape-v1"}
    try:
        if not instructions:
            raise FrontierError("no xlated instructions available")
        frontier, call_sites = locate_frontier(instructions)
    except FrontierError as error:
        parse_reasons.append(f"FRONTIER_SHAPE_UNAVAILABLE:{error}")
        call_sites["error"] = str(error)
    _write_json(output / "call-sites.json", call_sites)
    shared_suffix: dict[str, Any] = {
        "schema": "rac-frontier-shared-suffix-v1",
        "entry": frontier.suffix_entry_insn if frontier else None,
        "first_state_sensitive_helper": frontier.first_sensitive_insn if frontier else None,
    }
    _write_json(output / "shared-suffix.json", shared_suffix)
    candidates, event_read_reasons = _read_events(bundle / "events.jsonl") if bundle.is_dir() else ([], ["BUNDLE_NOT_DIRECTORY"])
    function_by_pc = {item.pc: item.function for item in instructions}
    instruction_by_pc = {item.pc: item for item in instructions}
    decisions: list[dict[str, Any]] = []
    global_reasons = identity_reasons + parse_reasons + event_read_reasons
    if frontier is not None:
        decisions = [
            _event_check(event, line, frontier, identity, global_reasons, function_by_pc, instruction_by_pc)
            for line, event in candidates
        ]
    if any(item["passed"] for item in decisions):
        result = "FRONTIER_ELIGIBLE"
    elif not candidates and not global_reasons:
        result = "NO_ELIGIBLE_FRONTIER_EVENT"
    elif not candidates:
        result = "FRONTIER_REJECTED"
    else:
        result = "FRONTIER_REJECTED"
    selected = next((event for event in decisions if event["passed"]), None)
    selected_left = selected.get("history_left") if selected else None
    selected_right = selected.get("history_right") if selected else None
    frontier_json: dict[str, Any] = {
        "schema": "rac-frontier-v1",
        "object_sha256": identity.get("object_sha256"),
        "program_id": identity.get("program_id"),
        "program_tag": identity.get("program_tag"),
        "xlated_sha256": identity.get("xlated_sha256"),
        "join_insn": frontier.join_insn if frontier else None,
        "suffix_entry_insn": frontier.suffix_entry_insn if frontier else None,
        "first_sensitive_insn": frontier.first_sensitive_insn if frontier else None,
        "selected_visit_insn": selected.get("visit_insn") if selected else None,
        "history_left": selected_left.get("entries", []) if isinstance(selected_left, dict) else [],
        "history_right": selected_right.get("entries", []) if isinstance(selected_right, dict) else [],
        "same_remaining_xlated_suffix": selected.get("same_remaining_xlated_suffix") if selected else False,
        "identity": identity,
        "frontier": frontier.to_dict() if frontier else None,
        "canonical_eligible_execution_segment": call_sites.get("canonical_eligible_execution_segment"),
        "reasons": sorted(set(identity_reasons + parse_reasons)),
    }
    _write_json(output / "frontier.json", frontier_json)
    report: dict[str, Any] = {
        "schema": _CHECKER_SCHEMA,
        "checker": {"name": "rac-frontier-checker", "version": _CHECKER_VERSION},
        "result": result,
        "identity": identity,
        "frontier": frontier.to_dict() if frontier else None,
        "candidate_event_count": len(candidates),
        "eligible_event_count": sum(1 for item in decisions if item["passed"]),
        "search_outcome": "FRONTIER_ELIGIBLE" if selected else "NO_ELIGIBLE_FRONTIER_EVENT",
        "events": decisions,
        "global_reasons": sorted(set(global_reasons)),
        "input_sha256": hashes,
    }
    _write_json(output / "frontier-check.json", report)
    (output / "frontier-check.md").write_text(_markdown(report), encoding="utf-8")
    return report


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _failure_report(error: BaseException) -> dict[str, Any]:
    """Return a bounded, machine-readable report for an unexpected failure."""

    return {
        "schema": _CHECKER_SCHEMA,
        "checker": {"name": "rac-frontier-checker", "version": _CHECKER_VERSION},
        "result": "FRONTIER_REJECTED",
        "identity": {"schema": "rac-frontier-identity-v1", "input_sha256": {}},
        "frontier": None,
        "candidate_event_count": 0,
        "eligible_event_count": 0,
        "search_outcome": "NO_ELIGIBLE_FRONTIER_EVENT",
        "events": [],
        "global_reasons": [f"CHECKER_EXECUTION_FAILED:{type(error).__name__}"],
        "input_sha256": {},
    }


def _write_failure_proof(output: Path, report: dict[str, Any]) -> None:
    """Keep the proof-set shape stable even when decoding failed unexpectedly."""

    reason = report["global_reasons"][0]
    _write_json(
        output / "cfg.json",
        {"schema": "rac-frontier-cfg-v1", "instructions": [], "edges": [], "error": reason},
    )
    _write_json(output / "call-sites.json", {"schema": "rac-frontier-shape-v1", "error": reason})
    _write_json(
        output / "shared-suffix.json",
        {"schema": "rac-frontier-shared-suffix-v1", "entry": None, "first_state_sensitive_helper": None},
    )
    _write_json(
        output / "frontier.json",
        {
            "schema": "rac-frontier-v1",
            "object_sha256": None,
            "program_id": None,
            "program_tag": None,
            "xlated_sha256": None,
            "join_insn": None,
            "suffix_entry_insn": None,
            "first_sensitive_insn": None,
            "selected_visit_insn": None,
            "history_left": [],
            "history_right": [],
            "same_remaining_xlated_suffix": False,
            "identity": report["identity"],
            "frontier": None,
            "canonical_eligible_execution_segment": None,
            "reasons": [reason],
        },
    )
    _write_json(output / "frontier-check.json", report)
    (output / "frontier-check.md").write_text(_markdown(report), encoding="utf-8")


def _publish_proof(stage: Path, output: Path, report: dict[str, Any]) -> None:
    """Atomically publish a complete, attributable proof directory once."""

    missing = [name for name in _PROOF_ARTIFACTS if not (stage / name).is_file()]
    if missing:
        raise RuntimeError(f"proof staging incomplete: {', '.join(missing)}")
    run_id = uuid.uuid4().hex
    artifact_sha256 = {name: _sha256(stage / name) for name in _PROOF_ARTIFACTS}
    manifest = {
        "schema": "rac-frontier-proof-manifest-v1",
        "run_id": run_id,
        "status": "complete",
        "checker": report["checker"],
        "result": report["result"],
        "input_sha256": report["input_sha256"],
        "artifact_sha256": artifact_sha256,
        "completion_marker": "COMPLETE",
    }
    _write_json(stage / "run-manifest.json", manifest)
    (stage / "COMPLETE").write_text(run_id + "\n", encoding="utf-8")
    os.replace(stage, output)


def check_bundle(bundle: Path, output: Path | None = None) -> dict[str, Any]:
    """Check an immutable evidence bundle and publish a separate proof set.

    ``output`` is deliberately mandatory and must be a new directory outside
    ``bundle``.  This keeps raw capture immutable and makes an interrupted run
    unable to masquerade as an earlier report.
    """

    if output is None:
        raise ValueError("an explicit proof output directory is required")
    bundle = bundle.resolve()
    output = output.resolve()
    if _is_within(output, bundle):
        raise ValueError("proof output must be outside the evidence bundle")
    if output.exists():
        raise FileExistsError(f"proof output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent))
    try:
        try:
            report = _check_bundle(bundle, stage)
        except Exception as error:  # publish a structured rejection, never a stale partial proof
            report = _failure_report(error)
            _write_failure_proof(stage, report)
        _publish_proof(stage, output, report)
        return report
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="pinned Linux-R output directory")
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="new proof output directory outside the immutable evidence bundle",
    )
    args = parser.parse_args()
    report = check_bundle(args.bundle, args.out)
    print(report["result"])
    return 0 if report["result"] == "FRONTIER_ELIGIBLE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
