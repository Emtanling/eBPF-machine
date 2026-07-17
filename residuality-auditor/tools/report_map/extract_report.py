#!/usr/bin/env python3
"""Extract operational prune report cells and certificate-backed report map."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from .build_membership_matrix import build_matrix
from .build_prune_graph import build_graph
from .check_prune_cell_coverage import check_coverage
from .check_uniqueness import check_uniqueness
from .parse_prune_events import raw_event_ref, read_jsonl, sha256_file
from .session_completeness import check_session
from .verify_event_identity import verify_identity


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _event_state_hash(event: dict[str, Any], side: str) -> str | None:
    value = event.get(side)
    return value.get("state_hash") if isinstance(value, dict) else None


def _frontier_event(rows: list[dict[str, Any]], *, join: int, retained_hash: str, current_hash: str) -> dict[str, Any]:
    matches = [
        e for e in rows
        if e.get("event") == "prune_hit"
        and int(e.get("visit_insn", -1)) == int(join)
        and e.get("states_equal_success") is True
        and e.get("is_state_visited_prune") is True
        and _event_state_hash(e, "old") == retained_hash
        and _event_state_hash(e, "current") == current_hash
    ]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one frontier prune edge {current_hash}->{retained_hash} at {join}, found {len(matches)}")
    return matches[0]


def _evidence_ref(bundle: Path, rel: str) -> dict[str, Any]:
    return {"path": rel, "sha256": sha256_file(bundle / rel)}


def _definition() -> dict[str, Any]:
    return {
        "schema": "rac-prune-cell-definition-v1",
        "cell_carrier": "retained verifier-state representatives",
        "membership_rule": [
            "direct membership in retained representative",
            "direct membership in a current state actually pruned by that representative",
        ],
        "behavior_independent": True,
        "name": "operational prune-report cell",
        "scope": "frozen verifier session, target program, target frontier, and chosen fiber only",
    }


def _markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Operational Prune Report Map",
        "",
        f"Result: `{report['certificate_results']['unique_cell']}`",
        "",
        "| Certificate | Result |",
        "|---|---|",
    ]
    for name, result in report["certificate_results"].items():
        if name == "representatives":
            continue
        lines.append(f"| `{name}` | `{result}` |")
    lines.extend(["", "Evidence references are hash-bound in `report-map.json` under `evidence_refs`.", ""])
    return "\n".join(lines)


def extract(bundle: Path, out: Path | None = None) -> dict[str, Any]:
    out = out or bundle / "proof" / "report"
    out.mkdir(parents=True, exist_ok=True)
    path_report = _load(bundle / "proof" / "path" / "path-correspondence.json")
    memberships = {
        "a=0": _load(bundle / "proof" / "concretization" / "membership-a0.json"),
        "a=1": _load(bundle / "proof" / "concretization" / "membership-a1.json"),
    }
    runtime = _load(bundle / "runtime.json")
    retained_doc = _load(bundle / "proof" / "states" / "retained-state.json")
    current_doc = _load(bundle / "proof" / "states" / "current-state.json")
    retained_hash = retained_doc["snapshot"]["state_hash"]
    current_hash = current_doc["snapshot"]["state_hash"]
    frontier = path_report["frontier"]
    join = int(frontier["join_insn"])
    raw_path = bundle / "events.raw.jsonl"
    enriched_path = bundle / "events.jsonl"
    raw_rows, raw_parse_errors = read_jsonl(raw_path)
    enriched_rows, enriched_parse_errors = read_jsonl(enriched_path)
    raw_event = _frontier_event(raw_rows, join=join, retained_hash=retained_hash, current_hash=current_hash)
    enriched_event = _frontier_event(enriched_rows, join=join, retained_hash=retained_hash, current_hash=current_hash)
    identity = path_report.get("identity") or {}
    identity_check = verify_identity(enriched_event, identity)

    definition = _definition()
    _write(out / "prune-cell-definition.json", definition)
    session = check_session(raw_rows, parse_errors=raw_parse_errors + enriched_parse_errors, join_insn=join, program_name=identity.get("program_name", "rac_single"), runtime=runtime)
    _write(out / "session-completeness.json", session)

    retained_states = {
        "schema": "rac-retained-states-v1",
        "frontier": frontier,
        "states": [
            {"role": "retained", "state_hash": retained_hash, "insn_idx": retained_doc["snapshot"].get("insn_idx"), "source": "frontier_event.old"},
            {"role": "current", "state_hash": current_hash, "insn_idx": current_doc["snapshot"].get("insn_idx"), "source": "frontier_event.current"},
        ],
    }
    _write(out / "retained-states.json", retained_states)

    raw_ref = raw_event_ref(raw_path, raw_event)
    edge = {
        "edge": "current_pruned_by_retained",
        "current_state_hash": current_hash,
        "retained_state_hash": retained_hash,
        "visit_insn": raw_event.get("visit_insn"),
        "exact_level": raw_event.get("exact_level"),
        "observed_at_ns": raw_event.get("observed_at_ns"),
        "sequence": raw_event.get("sequence"),
        "session_id": raw_event.get("session_id"),
        "cell_id": raw_event.get("cell_id"),
        "raw_event_ref": raw_ref,
        "enriched_event_identity": identity_check,
        "from_fixture": "fixture" in str(raw_event.get("source", "")).lower(),
    }
    prune_edges = {"schema": "rac-prune-edges-v1", "edges": [edge]}
    _write(out / "prune-edges.json", prune_edges)

    coverage = check_coverage(path_report, memberships, prune_edges, retained_hash, current_hash)
    coverage["definition"] = "proof/report/prune-cell-definition.json"
    coverage["identity_check"] = identity_check
    if edge["from_fixture"]:
        coverage["result"] = "PRUNE_CELL_COVERAGE_NOT_ESTABLISHED"
        coverage.setdefault("checks", {})["raw_event_not_fixture"] = False
    else:
        coverage.setdefault("checks", {})["raw_event_not_fixture"] = True
        if coverage["result"] == "BOTH_CASES_IN_OPERATIONAL_PRUNE_CELL" and not identity_check["passed"]:
            coverage["result"] = "PRUNE_CELL_COVERAGE_NOT_ESTABLISHED"
    _write(out / "prune-cell-coverage.json", coverage)
    _write(out / "coverage-relation.json", {"schema": "rac-operational-prune-coverage-relation-v1", "cases": coverage.get("cases", {})})

    graph = build_graph(prune_edges["edges"])
    matrix = build_matrix(coverage, graph)
    _write(out / "membership-matrix.json", matrix)
    unique = check_uniqueness(matrix, session)
    _write(out / "unique-cell-check.json", unique)

    refs = {
        "path_correspondence": _evidence_ref(bundle, "proof/path/path-correspondence.json"),
        "membership_a0": _evidence_ref(bundle, "proof/concretization/membership-a0.json"),
        "membership_a1": _evidence_ref(bundle, "proof/concretization/membership-a1.json"),
        "prune_cell_definition": _evidence_ref(bundle, "proof/report/prune-cell-definition.json"),
        "prune_cell_coverage": _evidence_ref(bundle, "proof/report/prune-cell-coverage.json"),
        "session_completeness": _evidence_ref(bundle, "proof/report/session-completeness.json"),
        "membership_matrix": _evidence_ref(bundle, "proof/report/membership-matrix.json"),
        "unique_cell": _evidence_ref(bundle, "proof/report/unique-cell-check.json"),
    }
    report = {
        "schema": "rac-report-map-v2",
        "identity": identity,
        "frontier": frontier,
        "report_cell_definition": "operational prune-report cell",
        "evidence_refs": refs,
        "certificate_results": {
            "path_correspondence": path_report.get("result"),
            "membership_a0": memberships["a=0"].get("result"),
            "membership_a1": memberships["a=1"].get("result"),
            "prune_cell_coverage": coverage.get("result"),
            "session_completeness": session.get("result"),
            "unique_cell": unique.get("result"),
            "representatives": unique.get("representatives"),
        },
    }
    _write(out / "report-map.json", report)
    (out / "report-map.md").write_text(_markdown(report), encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args(argv)
    report = extract(args.bundle)
    result = report["certificate_results"]["unique_cell"]
    print(result)
    return 0 if result == "UNIQUE_SAME_REPORT_CELL" else 1


if __name__ == "__main__":
    raise SystemExit(main())
