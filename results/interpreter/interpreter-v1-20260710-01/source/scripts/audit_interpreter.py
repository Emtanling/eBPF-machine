#!/usr/bin/env python3
"""Semantic audit for the bounded residual-circuit interpreter evidence."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


class Audit:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.metrics: dict[str, int] = defaultdict(int)

    def require(self, condition: bool, message: str) -> None:
        if not condition:
            self.failures.append(message)


def load_rows(path: Path, audit: Audit) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        audit.require(False, f"missing result: {path.name}")
        return rows
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            audit.require(False, f"{path.name}:{line_number}: invalid JSON: {exc}")
            continue
        audit.require(isinstance(row, dict),
                      f"{path.name}:{line_number}: JSON row is not an object")
        if isinstance(row, dict):
            rows.append(row)
    audit.require(bool(rows), f"{path.name}: no rows")
    return rows


def all_passed(rows: list[dict[str, Any]], audit: Audit, label: str) -> None:
    for index, row in enumerate(rows):
        audit.require(row.get("passed") is True,
                      f"{label}:{index}: passed is not true")


def verify_runs_and_gates(rows: list[dict[str, Any]], audit: Audit, label: str,
                          variant_id: int, gate_cap: int,
                          require_logical: bool, require_all_one: bool,
                          baseline: bool = False) -> None:
    runs = [row for row in rows if row.get("record") == "run"]
    gates = [row for row in rows if row.get("record") == "gate"]
    audit.require(len(runs) > 0, f"{label}: no run records")
    audit.require(len(runs) + len(gates) == len(rows),
                  f"{label}: unexpected record kind")
    all_passed(rows, audit, label)
    ids = {row.get("program_id") for row in rows}
    audit.require(len(ids) == 1 and next(iter(ids), None) not in (None, 0),
                  f"{label}: expected exactly one nonzero program_id, got {ids}")

    gate_groups: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in gates:
        key = (row.get("circuit"), row.get("run_seq"))
        gate_groups[key].append(row)
        audit.require(row.get("variant_id") == variant_id,
                      f"{label}: gate has wrong variant_id")
        audit.require(row.get("passed") is True, f"{label}: gate failed")
        if baseline:
            audit.require(row.get("trace_valid") is False,
                          f"{label}: baseline trace must be invalid")
        else:
            raw = row.get("second_update_raw_ret")
            actual = row.get("actual")
            audit.require(row.get("trace_valid") is True,
                          f"{label}: residual trace is missing")
            audit.require(isinstance(raw, int) and raw <= 0,
                          f"{label}: residual raw return is not non-positive")
            audit.require(actual == int(raw == 0),
                          f"{label}: gate output does not equal [raw==0]")
        if require_all_one:
            audit.require(row.get("actual") == 1,
                          f"{label}: ablation gate did not collapse to one")

    for run in runs:
        key = (run.get("circuit"), run.get("run_seq"))
        expected_count = run.get("gate_count")
        observed = sorted(gate.get("gate") for gate in gate_groups.get(key, []))
        audit.require(isinstance(expected_count, int) and expected_count >= 0,
                      f"{label}: invalid gate_count")
        if isinstance(expected_count, int) and expected_count >= 0:
            audit.require(observed == list(range(expected_count)),
                          f"{label}: run {key} has incomplete or duplicate gate trace")
        audit.require(run.get("variant_id") == variant_id,
                      f"{label}: run has wrong variant_id")
        audit.require(run.get("gate_cap") == gate_cap,
                      f"{label}: run has wrong gate capacity")
        audit.require(run.get("status") == 0,
                      f"{label}: run status is nonzero")
        audit.require(run.get("executed") == expected_count,
                      f"{label}: run executed count mismatch")
        audit.require(run.get("failing_gate") == 0xFFFFFFFF,
                      f"{label}: run has failing gate")
        audit.require(run.get("gate_error_count") == 0,
                      f"{label}: setup error was observed")
        audit.require(run.get("trace_passed") is True,
                      f"{label}: trace aggregate failed")
        audit.require(run.get("variant_expected") == run.get("actual"),
                      f"{label}: variant oracle does not match actual output")
        if require_logical:
            audit.require(run.get("logical_expected") == run.get("actual"),
                          f"{label}: logical oracle does not match actual output")

    audit.metrics[f"{label}_rows"] += len(rows)
    audit.metrics[f"{label}_runs"] += len(runs)
    audit.metrics[f"{label}_gates"] += len(gates)


def verify_negative(rows: list[dict[str, Any]], audit: Audit) -> None:
    expected = {
        "bad_abi": 1,
        "bad_input_count": 2,
        "bad_gate_count": 3,
        "bad_wire_count": 4,
        "bad_op": 5,
        "bad_dst": 5,
        "forward_reference": 5,
    }
    audit.require(len(rows) == len(expected),
                  "negative: unexpected number of rows")
    seen: dict[str, int] = {}
    for row in rows:
        name = row.get("case")
        seen[name] = seen.get(name, 0) + 1
        audit.require(row.get("record") == "negative", "negative: wrong record")
        audit.require(row.get("passed") is True, f"negative:{name}: failed")
        audit.require(row.get("actual_status") == expected.get(name),
                      f"negative:{name}: wrong status")
        expected_gate = 0xFFFFFFFF if name in {
            "bad_abi", "bad_input_count", "bad_gate_count", "bad_wire_count"
        } else 0
        audit.require(row.get("actual_failing_gate") == expected_gate,
                      f"negative:{name}: wrong failing gate")
    audit.require(set(seen) == set(expected) and all(count == 1 for count in seen.values()),
                  "negative: missing or duplicate case")
    audit.metrics["negative_rows"] += len(rows)


def verify_stress(rows: list[dict[str, Any]], audit: Audit) -> None:
    audit.require(len(rows) >= 10_000, "stress: fewer than 10,000 runs")
    all_passed(rows, audit, "stress")
    ids = {row.get("program_id") for row in rows}
    audit.require(len(ids) == 1 and next(iter(ids), None) not in (None, 0),
                  f"stress: expected one program_id, got {ids}")
    sequences = [row.get("run_seq") for row in rows]
    audit.require(sequences == list(range(1, len(rows) + 1)),
                  "stress: run sequence is not contiguous")
    audit.metrics["stress_runs"] += len(rows)


def audit_results(results_dir: Path) -> Audit:
    audit = Audit()
    known = load_rows(results_dir / "interpreter_known.jsonl", audit)
    verify_runs_and_gates(known, audit, "normal_known", 1, 2, True, False)
    normal_gates = [row for row in known if row.get("record") == "gate"]
    raw_values = {row.get("second_update_raw_ret") for row in normal_gates}
    audit.require(0 in raw_values and any(isinstance(value, int) and value < 0
                                           for value in raw_values),
                  "normal_known: no observed zero/negative residual contrast")

    random_rows = load_rows(results_dir / "interpreter_random.jsonl", audit)
    verify_runs_and_gates(random_rows, audit, "normal_random", 1, 2, True, False)
    random_runs = [row for row in random_rows if row.get("record") == "run"]
    audit.require(len({row.get("circuit") for row in random_runs}) >= 100,
                  "normal_random: fewer than 100 distinct circuits")

    boundary = load_rows(results_dir / "interpreter_boundary.jsonl", audit)
    verify_runs_and_gates(boundary, audit, "normal_boundary", 1, 2, True, False)
    boundary_runs = [row for row in boundary if row.get("record") == "run"]
    audit.require(len(boundary_runs) == 2 and
                  all(row.get("gate_count") == 512 for row in boundary_runs),
                  "normal_boundary: declared 512-gate boundary was not exercised")

    zero_gate = load_rows(results_dir / "interpreter_zero_gate.jsonl", audit)
    verify_runs_and_gates(zero_gate, audit, "normal_zero_gate", 1, 2, True, False)
    zero_runs = [row for row in zero_gate if row.get("record") == "run"]
    audit.require(len(zero_runs) == 1 and zero_runs[0].get("gate_count") == 0,
                  "normal_zero_gate: zero-gate descriptor was not exercised")

    negative = load_rows(results_dir / "interpreter_negative.jsonl", audit)
    verify_negative(negative, audit)
    stress = load_rows(results_dir / "interpreter_stress.jsonl", audit)
    verify_stress(stress, audit)

    cap64 = load_rows(results_dir / "interpreter_cap64.jsonl", audit)
    verify_runs_and_gates(cap64, audit, "cap64", 2, 64, False, True)
    cap64_runs = [row for row in cap64 if row.get("record") == "run"]
    audit.require(any(row.get("logical_expected") != row.get("actual")
                      for row in cap64_runs),
                  "cap64: no visible divergence from the logical oracle")

    sentinel = load_rows(results_dir / "interpreter_sentinel.jsonl", audit)
    verify_runs_and_gates(sentinel, audit, "sentinel", 3, 2, False, True)
    sentinel_runs = [row for row in sentinel if row.get("record") == "run"]
    audit.require(any(row.get("logical_expected") != row.get("actual")
                      for row in sentinel_runs),
                  "sentinel: no visible divergence from the logical oracle")

    baseline = load_rows(results_dir / "interpreter_baseline.jsonl", audit)
    verify_runs_and_gates(baseline, audit, "baseline", 4, 2, True, False,
                          baseline=True)
    return audit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results_dir", nargs="?", type=Path, default=Path("results"))
    args = parser.parse_args(argv)
    audit = audit_results(args.results_dir)
    for key in sorted(audit.metrics):
        print(f"{key}={audit.metrics[key]}")
    if audit.failures:
        for failure in audit.failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        print(f"interpreter audit: FAILED ({len(audit.failures)} issue(s))", file=sys.stderr)
        return 1
    print("interpreter audit: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
