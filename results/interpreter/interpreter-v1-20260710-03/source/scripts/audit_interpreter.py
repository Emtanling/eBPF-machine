#!/usr/bin/env python3
"""Semantic audit for the bounded residual-circuit interpreter evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

# A run's source snapshot is covered by its integrity manifest.  The auditor
# must never create an unbound __pycache__ entry merely by being executed there.
sys.dont_write_bytecode = True

import circuit_tool


KNOWN_CIRCUITS = {
    "const_one", "nand", "not", "and", "or", "xor", "mux",
    "half_adder", "full_adder",
}
STRESS_CIRCUITS = ("nand", "full_adder", "mux")
CORPUS_SEED = 3235823838
CORPUS_COUNT = 100
CORPUS_MAX_INPUTS = 6
CORPUS_MAX_GATES = 24
PROGRAM_TAG_RE = re.compile(r"^[0-9a-f]{16}$")


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


def require_runtime_identity(rows: list[dict[str, Any]], audit: Audit,
                             label: str, expected_tag: str | None) -> str | None:
    ids = {row.get("program_id") for row in rows}
    audit.require(len(ids) == 1 and next(iter(ids), None) not in (None, 0),
                  f"{label}: expected exactly one nonzero program_id, got {ids}")
    tags = {row.get("program_tag") for row in rows}
    audit.require(len(tags) == 1,
                  f"{label}: expected exactly one program_tag, got {tags}")
    tag = next(iter(tags), None) if len(tags) == 1 else None
    audit.require(isinstance(tag, str) and PROGRAM_TAG_RE.fullmatch(tag),
                  f"{label}: invalid program_tag {tag!r}")
    if expected_tag is not None:
        audit.require(tag == expected_tag,
                      f"{label}: runtime program_tag does not match captured variant tag")
    return tag if isinstance(tag, str) else None


def load_variant_program_tag(results_dir: Path, label: str, audit: Audit) -> str | None:
    path = results_dir / "variants" / label / "wm_circuit.prog.txt"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        audit.require(False, f"{label}: cannot read captured program metadata: {exc}")
        return None
    tags = re.findall(r"\btag\s+([0-9a-f]{16})\b", text)
    audit.require(len(tags) == 1,
                  f"{label}: captured program metadata lacks one unambiguous tag")
    return tags[0] if len(tags) == 1 else None


def load_descriptors(results_dir: Path, audit: Audit) -> dict[str, circuit_tool.Circuit]:
    descriptors: dict[str, circuit_tool.Circuit] = {}
    for path in sorted(results_dir.rglob("*.wmc")):
        try:
            circuit = circuit_tool.decode_wmc(path.read_text(encoding="utf-8"))
        except (OSError, circuit_tool.CircuitError) as exc:
            audit.require(False, f"descriptor {path.relative_to(results_dir)}: {exc}")
            continue
        audit.require(circuit.name not in descriptors,
                      f"duplicate descriptor name: {circuit.name}")
        descriptors[circuit.name] = circuit
    audit.require(bool(descriptors), "no WMC1 descriptors found")
    return descriptors


def require_exhaustive_runs(runs: list[dict[str, Any]], expected_names: set[str],
                            descriptors: dict[str, circuit_tool.Circuit],
                            audit: Audit, label: str) -> None:
    by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for run in runs:
        by_name[run.get("circuit")].append(run)
        audit.require(run.get("kind") == "exhaustive",
                      f"{label}: run is not marked exhaustive")
    audit.require(set(by_name) == expected_names,
                  f"{label}: circuit set does not match declared corpus")
    for name in expected_names:
        circuit = descriptors.get(name)
        rows = by_name.get(name, [])
        if circuit is None:
            audit.require(False, f"{label}: missing descriptor {name}")
            continue
        assignments = [row.get("assignment") for row in rows]
        expected_assignments = list(range(1 << circuit.input_count))
        audit.require(sorted(assignments) == expected_assignments,
                      f"{label}: incomplete input coverage for {name}")
        audit.require(len({row.get("run_seq") for row in rows}) == len(rows),
                      f"{label}: duplicate run sequence for {name}")


def load_corpus_manifest(results_dir: Path, audit: Audit) -> set[str]:
    corpus_dir = results_dir / "corpus"
    path = corpus_dir / "manifest.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        audit.require(False, f"corpus manifest: {exc}")
        return set()
    audit.require(manifest.get("seed") == CORPUS_SEED,
                  "corpus manifest: wrong seed")
    audit.require(manifest.get("count") == CORPUS_COUNT,
                  "corpus manifest: wrong count")
    records = manifest.get("circuits")
    audit.require(isinstance(records, list) and len(records) == CORPUS_COUNT,
                  "corpus manifest: wrong descriptor count")
    if not isinstance(records, list) or len(records) != CORPUS_COUNT:
        return set()

    # The seed is a scientific claim only if it fixes the corpus.  Recreate the
    # DAGs with the separately snapshotted generator, then compare the manifest
    # and every generated source/descriptor byte-for-byte.
    with tempfile.TemporaryDirectory(prefix="wm-corpus-audit-") as temporary:
        expected_dir = Path(temporary) / "corpus"
        expected_records = circuit_tool.create_corpus(
            expected_dir, CORPUS_SEED, CORPUS_COUNT,
            CORPUS_MAX_INPUTS, CORPUS_MAX_GATES,
        )
        audit.require(
            manifest == {
                "seed": CORPUS_SEED,
                "count": CORPUS_COUNT,
                "circuits": expected_records,
            },
            "corpus manifest: differs from the fixed-seed regenerated corpus",
        )
        expected_names = {record["name"] for record in expected_records}
        expected_files = {"manifest.json"}
        for record in expected_records:
            for field in ("source", "descriptor"):
                filename = record[field]
                expected_files.add(filename)
                candidate = corpus_dir / filename
                audit.require(candidate.is_file(),
                              f"corpus manifest: missing {field} for {record['name']}")
                if candidate.is_file():
                    audit.require(candidate.read_bytes() ==
                                  (expected_dir / filename).read_bytes(),
                                  f"corpus manifest: {field} bytes differ for {record['name']}")
            descriptor = corpus_dir / record["descriptor"]
            if descriptor.is_file():
                observed_hash = hashlib.sha256(descriptor.read_bytes()).hexdigest()
                audit.require(observed_hash == record["sha256"],
                              f"corpus manifest: descriptor hash mismatch for {record['name']}")
        actual_files = {candidate.name for candidate in corpus_dir.iterdir()
                        if candidate.is_file()} if corpus_dir.is_dir() else set()
        audit.require(actual_files == expected_files,
                      "corpus manifest: file set differs from regenerated corpus")
    return expected_names


def variant_name(variant_id: int) -> str:
    return {1: "logical", 2: "cap64", 3: "sentinel", 4: "logical"}[variant_id]


def independent_wires(run: dict[str, Any], descriptors: dict[str, circuit_tool.Circuit],
                      audit: Audit, label: str, variant_id: int) -> tuple[list[int], list[int]] | None:
    name = run.get("circuit")
    circuit = descriptors.get(name)
    if circuit is None:
        audit.require(False, f"{label}: missing descriptor for circuit {name!r}")
        return None
    assignment = run.get("assignment")
    audit.require(isinstance(assignment, int) and assignment >= 0,
                  f"{label}: invalid assignment for {name}")
    if not isinstance(assignment, int) or assignment < 0:
        return None
    audit.require(run.get("input_count") == circuit.input_count,
                  f"{label}: input_count disagrees with descriptor {name}")
    audit.require(run.get("gate_count") == circuit.gate_count,
                  f"{label}: gate_count disagrees with descriptor {name}")
    logical = circuit_tool.evaluate_wires(circuit, assignment, variant="logical")
    variant = circuit_tool.evaluate_wires(circuit, assignment,
                                          variant=variant_name(variant_id))
    logical_word = circuit_tool.output_word([logical[index] for index in circuit.outputs])
    variant_word = circuit_tool.output_word([variant[index] for index in circuit.outputs])
    audit.require(run.get("logical_expected") == logical_word,
                  f"{label}: harness logical oracle disagrees for {name}")
    audit.require(run.get("variant_expected") == variant_word,
                  f"{label}: harness variant oracle disagrees for {name}")
    return logical, variant


def verify_runs_and_gates(rows: list[dict[str, Any]], audit: Audit, label: str,
                          variant_id: int, gate_cap: int,
                          require_logical: bool, require_all_one: bool,
                          descriptors: dict[str, circuit_tool.Circuit],
                          baseline: bool = False,
                          expected_program_tag: str | None = None) -> None:
    runs = [row for row in rows if row.get("record") == "run"]
    gates = [row for row in rows if row.get("record") == "gate"]
    audit.require(len(runs) > 0, f"{label}: no run records")
    audit.require(len(runs) + len(gates) == len(rows),
                  f"{label}: unexpected record kind")
    all_passed(rows, audit, label)
    require_runtime_identity(rows, audit, label, expected_program_tag)

    run_by_key: dict[tuple[str, int], dict[str, Any]] = {}
    expected_wires: dict[tuple[str, int], list[int]] = {}
    for run in runs:
        key = (run.get("circuit"), run.get("run_seq"))
        audit.require(key not in run_by_key, f"{label}: duplicate run identity {key}")
        run_by_key[key] = run
        values = independent_wires(run, descriptors, audit, label, variant_id)
        if values is not None:
            expected_wires[key] = values[1]

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
        run = run_by_key.get(key)
        audit.require(run is not None, f"{label}: gate has no parent run")
        circuit = descriptors.get(row.get("circuit"))
        index = row.get("gate")
        if circuit is None or not isinstance(index, int) or not 0 <= index < circuit.gate_count:
            audit.require(False, f"{label}: invalid descriptor gate reference")
            continue
        gate = circuit.gates[index]
        audit.require((row.get("src0"), row.get("src1"), row.get("dst")) ==
                      (gate.src0, gate.src1, gate.dst),
                      f"{label}: gate record disagrees with descriptor")
        wires = expected_wires.get(key)
        if wires is not None:
            audit.require(row.get("expected") == wires[gate.dst],
                          f"{label}: harness gate oracle disagrees with independent oracle")
            audit.require(row.get("actual") == wires[gate.dst],
                          f"{label}: actual gate output disagrees with independent oracle")

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


def verify_negative(rows: list[dict[str, Any]], audit: Audit,
                    expected_program_tag: str | None = None) -> None:
    expected = {
        "bad_abi": 1,
        "bad_input_count": 2,
        "bad_gate_count": 3,
        "bad_wire_count": 4,
        "bad_op": 5,
        "bad_dst": 5,
        "forward_reference": 5,
        "bad_late_dst": 5,
    }
    audit.require(len(rows) == len(expected),
                  "negative: unexpected number of rows")
    require_runtime_identity(rows, audit, "negative", expected_program_tag)
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
        } else (1 if name == "bad_late_dst" else 0)
        expected_executed = 1 if name == "bad_late_dst" else 0
        audit.require(row.get("actual_failing_gate") == expected_gate,
                      f"negative:{name}: wrong failing gate")
        audit.require(row.get("expected_executed") == expected_executed and
                      row.get("actual_executed") == expected_executed,
                      f"negative:{name}: wrong executed prefix")
    audit.require(set(seen) == set(expected) and all(count == 1 for count in seen.values()),
                  "negative: missing or duplicate case")
    audit.metrics["negative_rows"] += len(rows)


def verify_stress(rows: list[dict[str, Any]], audit: Audit,
                  descriptors: dict[str, circuit_tool.Circuit],
                  expected_program_tag: str | None = None) -> None:
    audit.require(len(rows) == 10_000, "stress: expected exactly 10,000 runs")
    audit.require(all(row.get("record") == "run" for row in rows),
                  "stress: non-run record present")
    all_passed(rows, audit, "stress")
    require_runtime_identity(rows, audit, "stress", expected_program_tag)
    sequences = [row.get("run_seq") for row in rows]
    audit.require(sequences == list(range(1, len(rows) + 1)),
                  "stress: run sequence is not contiguous")
    for ordinal, row in enumerate(rows):
        expected_name = STRESS_CIRCUITS[ordinal % len(STRESS_CIRCUITS)]
        audit.require(row.get("circuit") == expected_name,
                      "stress: descriptor alternation is wrong")
        audit.require(row.get("kind") == "alternating_stress",
                      "stress: kind is wrong")
        audit.require(row.get("ordinal") == ordinal % len(STRESS_CIRCUITS),
                      "stress: ordinal is wrong")
        audit.require(row.get("variant_id") == 1 and row.get("gate_cap") == 2,
                      "stress: wrong normal variant")
        circuit = descriptors.get(expected_name)
        expected_gates = circuit.gate_count if circuit else None
        audit.require(row.get("status") == 0 and row.get("executed") == expected_gates and
                      row.get("failing_gate") == 0xFFFFFFFF and
                      row.get("gate_error_count") == 0 and
                      row.get("trace_passed") is True,
                      "stress: execution status is invalid")
        values = independent_wires(row, descriptors, audit, "stress", 1)
        if values is not None:
            expected = circuit_tool.output_word(
                [values[1][index] for index in descriptors[row["circuit"]].outputs]
            )
            audit.require(row.get("actual") == expected,
                          "stress: actual output disagrees with independent oracle")
    audit.metrics["stress_runs"] += len(rows)


def audit_results(results_dir: Path) -> Audit:
    audit = Audit()
    descriptors = load_descriptors(results_dir, audit)
    normal_tag = load_variant_program_tag(results_dir, "normal", audit)
    cap64_tag = load_variant_program_tag(results_dir, "cap64", audit)
    sentinel_tag = load_variant_program_tag(results_dir, "sentinel", audit)
    baseline_tag = load_variant_program_tag(results_dir, "baseline", audit)
    known = load_rows(results_dir / "interpreter_known.jsonl", audit)
    verify_runs_and_gates(known, audit, "normal_known", 1, 2, True, False,
                          descriptors, expected_program_tag=normal_tag)
    known_runs = [row for row in known if row.get("record") == "run"]
    require_exhaustive_runs(known_runs, KNOWN_CIRCUITS, descriptors, audit,
                            "normal_known")
    normal_gates = [row for row in known if row.get("record") == "gate"]
    raw_values = {row.get("second_update_raw_ret") for row in normal_gates}
    audit.require(0 in raw_values and any(isinstance(value, int) and value < 0
                                           for value in raw_values),
                  "normal_known: no observed zero/negative residual contrast")

    random_rows = load_rows(results_dir / "interpreter_random.jsonl", audit)
    verify_runs_and_gates(random_rows, audit, "normal_random", 1, 2, True, False,
                          descriptors, expected_program_tag=normal_tag)
    random_runs = [row for row in random_rows if row.get("record") == "run"]
    corpus_names = load_corpus_manifest(results_dir, audit)
    require_exhaustive_runs(random_runs, corpus_names, descriptors, audit,
                            "normal_random")

    boundary = load_rows(results_dir / "interpreter_boundary.jsonl", audit)
    verify_runs_and_gates(boundary, audit, "normal_boundary", 1, 2, True, False,
                          descriptors, expected_program_tag=normal_tag)
    boundary_runs = [row for row in boundary if row.get("record") == "run"]
    audit.require(len(boundary_runs) == 2 and
                  all(row.get("circuit") == "deep_512" and
                      row.get("gate_count") == 512 and
                      row.get("kind") == "exhaustive" for row in boundary_runs) and
                  sorted(row.get("assignment") for row in boundary_runs) == [0, 1],
                  "normal_boundary: declared 512-gate boundary was not exercised")

    zero_gate = load_rows(results_dir / "interpreter_zero_gate.jsonl", audit)
    verify_runs_and_gates(zero_gate, audit, "normal_zero_gate", 1, 2, True, False,
                          descriptors, expected_program_tag=normal_tag)
    zero_runs = [row for row in zero_gate if row.get("record") == "run"]
    audit.require(len(zero_runs) == 1 and zero_runs[0].get("circuit") == "const_one" and
                  zero_runs[0].get("gate_count") == 0 and
                  zero_runs[0].get("assignment") == 0 and
                  zero_runs[0].get("kind") == "exhaustive",
                  "normal_zero_gate: zero-gate descriptor was not exercised")

    negative = load_rows(results_dir / "interpreter_negative.jsonl", audit)
    verify_negative(negative, audit, normal_tag)
    stress = load_rows(results_dir / "interpreter_stress.jsonl", audit)
    verify_stress(stress, audit, descriptors, normal_tag)

    cap64 = load_rows(results_dir / "interpreter_cap64.jsonl", audit)
    verify_runs_and_gates(cap64, audit, "cap64", 2, 64, False, True, descriptors,
                          expected_program_tag=cap64_tag)
    cap64_runs = [row for row in cap64 if row.get("record") == "run"]
    require_exhaustive_runs(cap64_runs, KNOWN_CIRCUITS, descriptors, audit, "cap64")
    audit.require(any(row.get("logical_expected") != row.get("actual")
                      for row in cap64_runs),
                  "cap64: no visible divergence from the logical oracle")

    sentinel = load_rows(results_dir / "interpreter_sentinel.jsonl", audit)
    verify_runs_and_gates(sentinel, audit, "sentinel", 3, 2, False, True, descriptors,
                          expected_program_tag=sentinel_tag)
    sentinel_runs = [row for row in sentinel if row.get("record") == "run"]
    require_exhaustive_runs(sentinel_runs, KNOWN_CIRCUITS, descriptors, audit, "sentinel")
    audit.require(any(row.get("logical_expected") != row.get("actual")
                      for row in sentinel_runs),
                  "sentinel: no visible divergence from the logical oracle")

    baseline = load_rows(results_dir / "interpreter_baseline.jsonl", audit)
    verify_runs_and_gates(baseline, audit, "baseline", 4, 2, True, False,
                          descriptors, baseline=True,
                          expected_program_tag=baseline_tag)
    baseline_runs = [row for row in baseline if row.get("record") == "run"]
    require_exhaustive_runs(baseline_runs, KNOWN_CIRCUITS, descriptors, audit, "baseline")
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
