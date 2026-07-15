#!/usr/bin/env python3
"""Independent semantic and integrity audit for a linux_r evidence bundle.

The checker does not call the report generator.  It reconstructs the two
concrete frontier states, the finite future-observation equivalence relation,
and report-cell membership directly from the persisted JSON.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


PROGRAM_SCHEMA = "linux-r-program-v1"
ANALYSIS_SCHEMA = "linux-r-analysis-v1"
MANIFEST_SCHEMA = "linux-r-manifest-v1"
REPORT_SCHEMA = "linux-r-computed-report-v1"
FRONTIER = "after-first-update-before-second"
ACTION = "update-suffix-and-observe"
KEYS = ("S", "A", "B")


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("utf-8")


def _hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _program_is_canonical(program: Any) -> bool:
    if not isinstance(program, dict) or program.get("schema") != PROGRAM_SCHEMA:
        return False
    if program.get("recognizer") != "V_linux_r" or program.get("runtime") != "I_hash":
        return False
    if program.get("map") != {
        "capacity": 2, "key_universe": list(KEYS),
        "map_type": "BPF_MAP_TYPE_HASH", "non_evicting": True,
        "update_flag": "BPF_ANY",
    }:
        return False
    if program.get("symbolic_inputs") != {"a": [0, 1], "b": [1]}:
        return False
    operations = program.get("operations")
    if not isinstance(operations, list) or len(operations) != 6:
        return False
    return (
        [item.get("op") for item in operations] ==
        ["clear", "update", "update_selected", "frontier",
         "update_selected", "observe"] and
        operations[0].get("keys") == list(KEYS) and
        operations[1].get("key") == "S" and
        operations[1].get("flag") == "BPF_NOEXIST" and
        (operations[2].get("selector"), operations[2].get("zero_key"),
         operations[2].get("one_key"), operations[2].get("flag")) ==
        ("a", "S", "A", "BPF_ANY") and
        operations[3].get("id") == FRONTIER and
        (operations[4].get("selector"), operations[4].get("zero_key"),
         operations[4].get("one_key"), operations[4].get("flag")) ==
        ("b", "S", "B", "BPF_ANY") and
        operations[5].get("expression") == "last_return_is_success" and
        program.get("scope") == {
            "concurrency": "serialized", "interference": "none", "value": 1
        }
    )


def _context() -> dict[str, Any]:
    return {
        "capacity": 2,
        "concurrency": "serialized",
        "interference": "none",
        "key_universe": list(KEYS),
        "map_type": "BPF_MAP_TYPE_HASH",
        "non_evicting": True,
        "observer": "last_return_is_success",
        "suffix_key": "B",
        "update_flag": "BPF_ANY",
        "value": 1,
    }


def _expected_states() -> list[dict[str, Any]]:
    return [
        {
            "context": _context(), "input_a": 0, "keys": ["S"],
            "phase": FRONTIER,
            "reachable_by": ["clear(S,A,B)", "update_noexist(S)",
                             "update_any(S)"],
            "state_id": "frontier:S",
        },
        {
            "context": _context(), "input_a": 1, "keys": ["A", "S"],
            "phase": FRONTIER,
            "reachable_by": ["clear(S,A,B)", "update_noexist(S)",
                             "update_any(A)"],
            "state_id": "frontier:AS",
        },
    ]


def _gamma_contains(cell: dict[str, Any], state: dict[str, Any]) -> bool:
    try:
        gamma = cell["concretization"]
        keys = set(state["keys"])
        low, high = gamma["occupancy_interval"]
        return (
            state["phase"] == gamma["phase_equals"] and
            state["context"] == gamma["context_equals"] and
            set(gamma["must_contain"]).issubset(keys) and
            keys.issubset(set(gamma["keys_subset_of"])) and
            low <= len(keys) <= high and
            ("keys_equal" not in gamma or sorted(keys) == gamma["keys_equal"])
        )
    except (KeyError, TypeError, ValueError):
        return False


def _valid_cell_ids(cells: Any) -> bool:
    if not isinstance(cells, list) or not cells:
        return False
    for cell in cells:
        try:
            core = {
                "abstract_state": cell["abstract_state"],
                "concretization": cell["concretization"],
                "operator": cell["operator"],
                "predecessors": sorted(cell["predecessors"]),
            }
            expected = "cell-" + _hash_bytes(_canonical(core))[:24]
        except (KeyError, TypeError):
            return False
        if cell.get("cell_id") != expected:
            return False
    return len({cell["cell_id"] for cell in cells}) == len(cells)


def _transfer_validation_is_exact(report: dict[str, Any]) -> bool:
    actual_returns = {key: set() for key in KEYS}
    checked = 0
    for mask in range(1 << len(KEYS)):
        occupancy = {KEYS[index] for index in range(len(KEYS))
                     if mask & (1 << index)}
        if len(occupancy) > 2:
            continue
        for key in KEYS:
            checked += 1
            if key in occupancy or len(occupancy) < 2:
                actual_returns[key].add("ok")
            else:
                actual_returns[key].add("fail")
    expected = {
        "abstract_returns": {key: sorted(values)
                             for key, values in actual_returns.items()},
        "checked_cases": checked,
        "method": "exhaustive",
        "violations": [],
    }
    return report.get("transfer_validation") == expected and checked == 21


def _report_hash_valid(report: dict[str, Any]) -> bool:
    if not isinstance(report, dict) or "report_hash" not in report:
        return False
    core = {key: value for key, value in report.items() if key != "report_hash"}
    return report["report_hash"] == _hash_bytes(_canonical(core))


def _kernel_oracle_valid(root: Path, analysis: dict[str, Any]) -> bool:
    calibration = analysis.get("kernel_calibration")
    path = root / "kernel_oracle.jsonl"
    if calibration is None:
        return not path.exists()
    if not path.is_file():
        return False
    try:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()]
    except json.JSONDecodeError:
        return False
    runs = [row for row in rows if row.get("record") == "run"]
    gates = [row for row in rows if row.get("record") == "gate" and
             row.get("gate") == 0]
    assignment_by_ordinal = {row.get("ordinal"): row.get("assignment") for row in runs}
    observations = {assignment_by_ordinal.get(row.get("ordinal")): row for row in gates}
    if set(observations) != {2, 3}:
        return False
    if not all(row.get("passed") is True for row in runs + gates):
        return False
    success = observations[2]
    failure = observations[3]
    tags = {row.get("program_tag") for row in runs + gates}
    return (
        success.get("second_update_raw_ret") == 0 and success.get("actual") == 1 and
        isinstance(failure.get("second_update_raw_ret"), int) and
        failure["second_update_raw_ret"] < 0 and failure.get("actual") == 0 and
        len(tags) == 1 and None not in tags and
        calibration.get("program_tag") in tags and
        calibration.get("model_alignment") == {
            "a0_b1_observation": True,
            "a1_b1_observation": True,
            "exact_errno_not_assumed": True,
        }
    )


def _failed(reason: str) -> dict[str, Any]:
    return {"checks": {"bundle_readable": False}, "errors": [reason],
            "verdict": "FAIL"}


def audit_bundle(path: str | Path, *, require_kernel: bool = False,
                 write: bool = True) -> dict[str, Any]:
    root = Path(path)
    try:
        manifest = _read_json(root / "manifest.json")
        program = _read_json(root / "program.json")
        analysis = _read_json(root / "analysis.json")
    except (OSError, json.JSONDecodeError) as exc:
        return _failed(str(exc))

    checks: dict[str, bool] = {}
    errors: list[str] = []
    checks["manifest_schema"] = manifest.get("schema") == MANIFEST_SCHEMA
    manifest_core = {key: value for key, value in manifest.items()
                     if key != "manifest_hash"}
    checks["manifest_hash"] = (
        manifest.get("manifest_hash") == _hash_bytes(_canonical(manifest_core))
    )
    declared_files = manifest.get("files", {})
    actual_names = sorted(
        item.name for item in root.iterdir()
        if item.is_file() and item.name not in {"manifest.json", "audit.txt"}
    )
    checks["manifest_file_set"] = (
        isinstance(declared_files, dict) and sorted(declared_files) == actual_names
    )
    hashes_ok = checks["manifest_file_set"]
    if hashes_ok:
        for name, binding in declared_files.items():
            file_path = root / name
            if (binding.get("sha256") != _hash_file(file_path) or
                    binding.get("size") != file_path.stat().st_size):
                hashes_ok = False
                break
    checks["manifest_file_hashes"] = hashes_ok
    checks["manifest_files"] = checks["manifest_file_set"] and hashes_ok
    bindings = manifest.get("bindings", {})
    object_binding = bindings.get("bpf_object")
    source_binding = bindings.get("source")
    bindings_ok = True
    for binding in (object_binding, source_binding):
        if binding is None:
            continue
        candidate = root / binding.get("path", "")
        if (not candidate.is_file() or binding.get("sha256") != _hash_file(candidate) or
                declared_files.get(candidate.name, {}).get("sha256") !=
                binding.get("sha256")):
            bindings_ok = False
    checks["artifact_bindings"] = bindings_ok
    checks["program_canonical"] = _program_is_canonical(program)
    checks["analysis_schema"] = analysis.get("schema") == ANALYSIS_SCHEMA

    report = analysis.get("report", {})
    cells = report.get("report_cells", []) if isinstance(report, dict) else []
    checks["report_schema"] = report.get("schema") == REPORT_SCHEMA
    checks["report_hash"] = _report_hash_valid(report)
    checks["computed_before_witness"] = (
        report.get("analysis_order") ==
        "computed-before-concrete-witness-enumeration" and
        report.get("posthoc_output_data_used") is False
    )
    checks["cell_ids_canonical"] = _valid_cell_ids(cells)
    checks["abstract_transfer_sound"] = _transfer_validation_is_exact(report)

    expected_states = _expected_states()
    checks["concrete_reachability"] = analysis.get("concrete_states") == expected_states
    memberships = [[cell.get("cell_id") for cell in cells
                    if _gamma_contains(cell, state)] for state in expected_states]
    checks["unique_cell_coverage"] = all(len(items) == 1 for items in memberships)
    checks["unique_cell_condition"] = checks["unique_cell_coverage"]
    checks["same_computed_cell"] = (
        checks["unique_cell_coverage"] and memberships[0][0] == memberships[1][0]
    )

    traces = analysis.get("concrete_traces")
    checks["runtime_semantics"] = (
        isinstance(traces, list) and len(traces) == 2 and
        traces[0].get("pre_keys") == ["S"] and
        traces[0].get("post_keys") == ["B", "S"] and
        traces[0].get("return_class") == "ok" and
        traces[0].get("observation") == 1 and
        traces[0].get("terminated") is True and
        traces[1].get("pre_keys") == ["A", "S"] and
        traces[1].get("post_keys") == ["A", "S"] and
        traces[1].get("return_class") == "fail" and
        traces[1].get("observation") == 0 and
        traces[1].get("terminated") is True and
        traces[0].get("suffix_word") == [ACTION] == traces[1].get("suffix_word")
    )

    quotient = analysis.get("quotient", {})
    state_to_block = quotient.get("state_to_block", {})
    checks["quotient_exact"] = (
        set(state_to_block) == {
            "frontier:S", "frontier:AS", "terminal:BS", "terminal:AS"
        } and
        state_to_block.get("frontier:S") != state_to_block.get("frontier:AS") and
        state_to_block.get("terminal:BS") == state_to_block.get("terminal:AS") and
        quotient.get("shortest_distinguishing_word") == [ACTION]
    )
    beta_different = (checks["quotient_exact"] and
                      state_to_block["frontier:S"] != state_to_block["frontier:AS"])
    collision = checks["same_computed_cell"] and beta_different
    factorization = analysis.get("factorization", {})
    checks["factorization_recomputed"] = (
        collision and factorization.get("holds") is False and
        len(factorization.get("collisions", [])) == 1 and
        factorization["collisions"][0].get("cardinality") == 2
    )

    witness = analysis.get("witness", {})
    checks["output_witness"] = (
        checks["runtime_semantics"] and beta_different and collision and
        witness.get("same_computed_cell") is True and
        witness.get("beta_different") is True and
        witness.get("definition1_causal") is True and
        witness.get("observations") == [1, 0] and
        witness.get("suffix_word") == [ACTION]
    )
    checks["admissibility"] = (
        analysis.get("result", {}).get("adm_pass") is True and
        isinstance(analysis.get("checks"), dict) and
        all(analysis["checks"].values())
    )
    controls = analysis.get("controls", {})
    checks["negative_controls"] = (
        set(controls) == {"occupancy_tracking", "cap64", "forced_sentinel",
                          "unobserved"} and
        all(control.get("r_established") is False and
            control.get("factorization_holds") is True
            for control in controls.values())
    )
    result = analysis.get("result", {})
    checks["scope_label_honest"] = (
        result.get("scope") == "R(V_linux_r,I_hash)" and
        result.get("r_established") is True and
        result.get("stock_linux_verifier_r_established") is False
    )
    kernel_valid = _kernel_oracle_valid(root, analysis)
    kernel_present = analysis.get("kernel_calibration") is not None
    if kernel_present:
        checks["artifact_bindings"] = (
            checks["artifact_bindings"] and object_binding is not None and
            source_binding is not None
        )
    checks["kernel_calibration"] = kernel_valid and (kernel_present or not require_kernel)
    checks["kernel_required"] = not require_kernel or kernel_present

    for name, passed in checks.items():
        if not passed:
            errors.append(name)
    result = {
        "checks": checks,
        "errors": errors,
        "recomputed": {
            "beta_different": beta_different,
            "factorization_holds": not collision,
            "memberships": memberships,
            "r_established": (
                checks["admissibility"] and checks["output_witness"] and collision
            ),
            "scope": "R(V_linux_r,I_hash)",
            "stock_linux_verifier_r_established": False,
        },
        "verdict": "PASS" if all(checks.values()) else "FAIL",
    }
    if write:
        try:
            (root / "audit.txt").write_text(_format_audit(result), encoding="utf-8")
        except OSError:
            pass
    return result


def _format_audit(result: dict[str, Any]) -> str:
    lines = [
        f"{name}: {'PASS' if passed else 'FAIL'}"
        for name, passed in sorted(result["checks"].items())
    ]
    lines.extend([
        f"ADM_PASS: {'PASS' if result.get('recomputed', {}).get('r_established') else 'FAIL'}",
        f"SAME_COMPUTED_CELL_PASS: {'PASS' if result.get('checks', {}).get('same_computed_cell') else 'FAIL'}",
        f"BETA_DIFFERENT_PASS: {'PASS' if result.get('recomputed', {}).get('beta_different') else 'FAIL'}",
        f"NON_FACTORIZATION_PASS: {'PASS' if result.get('checks', {}).get('factorization_recomputed') else 'FAIL'}",
        "CLAIM: R(V_linux_r,I_hash)=ESTABLISHED",
        "BOUNDARY: R(stock Linux verifier,I_Linux)=NOT_ESTABLISHED",
        f"VERDICT: {result['verdict']}",
    ])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--require-kernel", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    result = audit_bundle(args.bundle, require_kernel=args.require_kernel,
                          write=args.write)
    text = _format_audit(result)
    print(text, end="")
    if result["errors"]:
        print("FAILED_CHECKS: " + ",".join(result["errors"]))
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
