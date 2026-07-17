#!/usr/bin/env python3
"""Emit a fail-closed path-correspondence proof for a RAC evidence bundle."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from tools.frontier.parse_xlated import parse_xlated_file
from tools.path.check_common_suffix import common_suffix
from tools.path.match_history import match_histories, selected_frontier_event
from tools.path.walk_prefix import check_runtime_against_branch, runtime_prefixes
from tools.path.xlated_semantics import selector_cases, semantics_summary


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _xlated_path(bundle: Path) -> Path:
    for name in ("xlated.txt", "xlated-rac_single.txt"):
        path = bundle / name
        if path.exists():
            return path
    raise FileNotFoundError(f"no xlated.txt or xlated-rac_single.txt in {bundle}")


def _identity(frontier: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    value = dict(frontier.get("identity") or {})
    for key in ("object_sha256", "program_id", "program_tag", "program_pin", "xlated_sha256"):
        if key not in value and key in runtime:
            value[key] = runtime[key]
    return value


def _capture_event_for_frontier(bundle: Path, selected: dict[str, Any]) -> dict[str, Any]:
    """Return the raw/enriched prune event backing the selected frontier row.

    frontier-check.json intentionally stores a small normalized view for proof
    review.  The state hashes live in events.jsonl/events.raw.jsonl.  Match by
    the selected source line first, then by visit/current/old insn indices.
    """
    path = bundle / "events.jsonl"
    if not path.exists():
        return {}
    want_line = selected.get("line")
    want_visit = selected.get("visit_insn")
    want_old = selected.get("old_state_insn_idx")
    want_current = selected.get("current_state_insn_idx")
    candidates: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict) or event.get("event") != "prune_hit":
            continue
        old = event.get("old") if isinstance(event.get("old"), dict) else {}
        current = event.get("current") if isinstance(event.get("current"), dict) else {}
        by_line = want_line is not None and line_no == int(want_line)
        by_shape = (
            want_visit is not None
            and int(event.get("visit_insn", -1)) == int(want_visit)
            and want_old is not None
            and int(old.get("insn_idx", -1)) == int(want_old)
            and want_current is not None
            and int(current.get("insn_idx", -1)) == int(want_current)
        )
        if by_line or by_shape:
            copy = dict(event)
            copy["_capture_ref"] = {"path": "events.jsonl", "line": line_no}
            candidates.append(copy)
    if len(candidates) == 1:
        return candidates[0]
    line_matches = [c for c in candidates if (c.get("_capture_ref") or {}).get("line") == want_line]
    if len(line_matches) == 1:
        return line_matches[0]
    return {}


def _prefix_doc(case: str, semantics_case: Any, history: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "rac-prefix-correspondence-v1",
        "case": case,
        "input_value": semantics_case.input_value,
        "branch_name": semantics_case.branch_name,
        "branch_call": semantics_case.branch_call,
        "selector_edge": semantics_case.selector_edge,
        "history_side": history["history_side"],
        "history_entries": history["entries"],
        "runtime_selected_state": runtime["selected_state"],
        "runtime_selected_mask": runtime["selected_mask"],
        "runtime_observation_success": runtime["observation_success"],
        "runtime_observation_retval": runtime["observation_retval"],
        "runtime_context": runtime["context"],
    }


def _markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Path Correspondence Proof",
        "",
        f"Result: `{report['result']}`",
        "",
        f"Frontier join: `{report['frontier']['join_insn']}`",
        f"Object SHA256: `{report['identity'].get('object_sha256')}`",
        f"Program tag: `{report['identity'].get('program_tag')}`",
        "",
        "| Runtime case | Branch | Call PC | History side | Selected mask | Observation |",
        "|---|---|---:|---|---:|---|",
    ]
    for case in ("a=0", "a=1"):
        prefix = report["prefixes"][case]
        lines.append(
            f"| `{case}` | `{prefix['branch_name']}` | {prefix['branch_call']} | "
            f"`{prefix['history_side']}` | {prefix['runtime_selected_mask']} | "
            f"{prefix['runtime_observation_success']} |"
        )
    if report["reasons"]:
        lines.extend(["", "## Reject reasons", ""])
        lines.extend(f"- {reason}" for reason in report["reasons"])
    else:
        lines.extend([
            "",
            "Both verifier histories hit the xlated branch call predicted for their runtime input,",
            "and both reach the same pre-suffix frontier with the same remaining xlated suffix.",
        ])
    return "\n".join(lines) + "\n"


def emit(bundle: Path, out: Path | None = None) -> dict[str, Any]:
    out = out or bundle / "proof" / "path"
    out.mkdir(parents=True, exist_ok=True)
    frontier = _load_json(bundle / "frontier-check.json")
    runtime = _load_json(bundle / "runtime.json")
    xlated = parse_xlated_file(_xlated_path(bundle))
    selected = selected_frontier_event(frontier)
    cases = selector_cases(xlated)
    semantics = semantics_summary(xlated)
    history_match = match_histories(selected, cases)
    runtime_by_case = runtime_prefixes(runtime)
    suffix = common_suffix(xlated, selected)

    reasons: list[str] = []
    prefixes: dict[str, dict[str, Any]] = {}
    for case in ("a=0", "a=1"):
        sem_case = cases[case]
        hist = history_match["case_to_history"][case]
        rt = runtime_by_case[case]
        if hist["branch_call"] != sem_case.branch_call:
            reasons.append(f"{case} history branch call does not match xlated selector case")
        if hist["branch_name"] != sem_case.branch_name:
            reasons.append(f"{case} history branch name does not match xlated selector case")
        reasons.extend(check_runtime_against_branch(case, sem_case.branch_name, rt))
        prefixes[case] = _prefix_doc(case, sem_case, hist, rt)

    result = "PATH_CORRESPONDENCE_VERIFIED" if not reasons else "PATH_CORRESPONDENCE_REJECTED"
    selected_capture = _capture_event_for_frontier(bundle, selected)
    selected_old = selected_capture.get("old") if isinstance(selected_capture.get("old"), dict) else selected.get("old") or {}
    selected_current = selected_capture.get("current") if isinstance(selected_capture.get("current"), dict) else selected.get("current") or {}
    identity = _identity(frontier, runtime)
    report = {
        "schema": "rac-path-correspondence-v1",
        "result": result,
        "identity_verified": not reasons and bool(identity.get("object_sha256")) and bool(identity.get("program_tag")),
        "identity": identity,
        "frontier": frontier.get("frontier"),
        "selector_semantics": semantics,
        "history_match": history_match,
        "common_suffix": suffix,
        "same_frontier": not reasons and suffix.get("join_insn") == (frontier.get("frontier") or {}).get("join_insn"),
        "same_remaining_xlated_suffix": suffix.get("same_remaining_xlated_suffix") is True,
        "sensitive_operation_after_frontier": int(suffix.get("first_sensitive_insn", -1)) > int((frontier.get("frontier") or {}).get("join_insn", 10**9)),
        "selected_capture_ref": selected_capture.get("_capture_ref", {}),
        "a0": {
            "direct_state_hash": selected_current.get("state_hash"),
            "abstract_role": "current",
            "history_matches": prefixes.get("a=0", {}).get("history_side") == "history_right",
            "runtime_selected_state": prefixes.get("a=0", {}).get("runtime_selected_state"),
        },
        "a1": {
            "direct_state_hash": selected_old.get("state_hash"),
            "abstract_role": "retained",
            "history_matches": prefixes.get("a=1", {}).get("history_side") == "history_left",
            "runtime_selected_state": prefixes.get("a=1", {}).get("runtime_selected_state"),
        },
        "prefixes": prefixes,
        "reasons": reasons,
    }
    (out / "prefix-a0.json").write_text(json.dumps(prefixes["a=0"], indent=2, sort_keys=True) + "\n")
    (out / "prefix-a1.json").write_text(json.dumps(prefixes["a=1"], indent=2, sort_keys=True) + "\n")
    (out / "common-suffix.json").write_text(json.dumps(suffix, indent=2, sort_keys=True) + "\n")
    (out / "path-correspondence.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    (out / "path-correspondence.md").write_text(_markdown(report))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    report = emit(args.bundle, args.out)
    print(report["result"])
    return 0 if report["result"] == "PATH_CORRESPONDENCE_VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
