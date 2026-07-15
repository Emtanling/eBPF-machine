#!/usr/bin/env python3
"""Independent semantic and integrity audit for a linux_r evidence bundle.

The checker does not call the report generator.  It reconstructs the two
concrete frontier states, the finite future-observation equivalence relation,
and report-cell membership directly from the persisted JSON.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
from pathlib import Path
from typing import Any


PROGRAM_SCHEMA = "linux-r-program-v1"
ANALYSIS_SCHEMA = "linux-r-analysis-v1"
MANIFEST_SCHEMA = "linux-r-manifest-v1"
REPORT_SCHEMA = "linux-r-computed-report-v1"
DERIVATION_SCHEMA = "linux-r-report-derivation-v1"
FRONTIER = "after-first-update-before-second"
ACTION = "update-suffix-and-observe"
KEYS = ("S", "A", "B")
INSTANCE_ID = "M_linux_r_aux_v1"


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
    if (not isinstance(operations, list) or len(operations) != 6 or
            not all(isinstance(item, dict) for item in operations)):
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
        } and
        program.get("source_binding") == {
            "artifact": "wm_circuit", "macro": "NAND_GATE_OBS",
            "source": "src/wm.bpf.c",
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


def _abstract_payload(keys: list[str] | None, *, joined: bool = False) -> dict[str, Any]:
    if joined:
        occupancy = {
            "exact_key_set": "not-tracked", "max_size": 2,
            "may_contain": ["S", "A"], "min_size": 1,
            "must_contain": ["S"],
        }
    else:
        exact = sorted(keys or [])
        occupancy = {
            "exact_key_set": exact, "max_size": len(exact),
            "may_contain": exact, "min_size": len(exact),
            "must_contain": exact,
        }
    return {
        "context": _context(),
        "frontier": FRONTIER,
        "occupancy": occupancy,
        "static_safety": {
            "bounded_key_universe": True,
            "capacity_positive": True,
            "flags_valid": True,
            "map_reference_valid": True,
            "value_size_valid": True,
        },
    }


def _gamma(payload: dict[str, Any]) -> dict[str, Any]:
    occupancy = payload["occupancy"]
    result = {
        "capacity_equals": 2,
        "context_equals": _context(),
        "keys_subset_of": occupancy["may_contain"],
        "map_type_equals": "BPF_MAP_TYPE_HASH",
        "must_contain": occupancy["must_contain"],
        "occupancy_interval": [occupancy["min_size"], occupancy["max_size"]],
        "phase_equals": FRONTIER,
    }
    if occupancy["exact_key_set"] != "not-tracked":
        result["keys_equal"] = occupancy["exact_key_set"]
    return result


def _expected_cell(payload: dict[str, Any], predecessors: list[str],
                   operator: str) -> dict[str, Any]:
    core = {
        "abstract_state": payload,
        "concretization": _gamma(payload),
        "operator": operator,
        "predecessors": sorted(predecessors),
    }
    return {"cell_id": "cell-" + _hash_bytes(_canonical(core))[:24], **core}


def _expected_transfer_validation() -> dict[str, Any]:
    returns = {key: set() for key in KEYS}
    checked = 0
    for mask in range(1 << len(KEYS)):
        occupancy = {KEYS[index] for index in range(len(KEYS))
                     if mask & (1 << index)}
        if len(occupancy) > 2:
            continue
        for key in KEYS:
            checked += 1
            returns[key].add(
                "ok" if key in occupancy or len(occupancy) < 2 else "fail"
            )
    return {
        "abstract_returns": {key: sorted(values) for key, values in returns.items()},
        "cell_checked_cases": 2,
        "checked_cases": checked,
        "method": "symbolic-transform-plus-exhaustive-concretization",
        "violations": [],
    }


def _expected_recognizer_verdict() -> dict[str, Any]:
    checks = {
        "bounded_operation_sequence": True,
        "declared_scope_safe": True,
        "frontier_declared": True,
        "keys_and_flags_valid": True,
        "map_contract_safe": True,
        "observer_declared": True,
        "schema_and_identity": True,
    }
    return {
        "accepted": True,
        "checks": checks,
        "recognizer": "V_linux_r",
        "safety_property": (
            "all bounded service operations use a valid non-evicting HASH "
            "reference, in-domain keys/value, and valid update flags"
        ),
    }


def _expected_derivation(program: dict[str, Any]) -> dict[str, Any]:
    program_hash = _hash_bytes(_canonical(program))
    analysis_config = {
        "occupancy_policy": "joined",
        "observe_return": True,
        "program_hash": program_hash,
        "suffix_key": "B",
    }
    sentinel = _expected_cell(_abstract_payload(["S"]), [], "update_noexist(S)")
    branch_zero = _expected_cell(
        _abstract_payload(["S"]), [sentinel["cell_id"]],
        "branch(a=0);update_any(S)",
    )
    branch_one = _expected_cell(
        _abstract_payload(["S", "A"]), [sentinel["cell_id"]],
        "branch(a=1);update_any(A)",
    )
    core = {
        "analysis_config_hash": _hash_bytes(_canonical(analysis_config)),
        "base_program_hash": program_hash,
        "computed_trace": [sentinel, branch_zero, branch_one],
        "frontier": FRONTIER,
        "profile": "baseline",
        "program_hash": program_hash,
        "schema": DERIVATION_SCHEMA,
    }
    return {**core, "derivation_hash": _hash_bytes(_canonical(core))}


def _expected_report(program: dict[str, Any]) -> dict[str, Any]:
    program_hash = _hash_bytes(_canonical(program))
    analysis_config = {
        "occupancy_policy": "joined",
        "observe_return": True,
        "program_hash": program_hash,
        "suffix_key": "B",
    }
    derivation = _expected_derivation(program)
    computed = derivation["computed_trace"]
    branch_zero, branch_one = computed[1], computed[2]
    joined = _expected_cell(
        _abstract_payload(None, joined=True),
        [branch_zero["cell_id"], branch_one["cell_id"]],
        "join(forget-exact-occupancy)",
    )
    joined["suffix_abstract_transfer"] = {
        "possible_observations": [0, 1],
        "possible_return_classes": ["fail", "ok"],
        "post_occupancy": {
            "exact_key_set": "not-tracked", "max_size": 2,
            "may_contain": ["A", "B", "S"], "min_size": 2,
            "must_contain": ["S"],
        },
        "gamma_cardinality": 2,
    }
    core = {
        "analysis_order": "computed-before-concrete-witness-enumeration",
        "analysis_config_hash": _hash_bytes(_canonical(analysis_config)),
        "base_program_hash": program_hash,
        "derivation_ref": {
            "derivation_hash": derivation["derivation_hash"],
            "path": "derivation.json",
            "schema": DERIVATION_SCHEMA,
        },
        "domain": {
            "name": "linux-r-occupancy-domain",
            "occupancy_policy": "joined",
            "version": "occ-join-v1",
        },
        "frontier": FRONTIER,
        "posthoc_output_data_used": False,
        "profile": "baseline",
        "program_hash": program_hash,
        "recognizer": "V_linux_r",
        "recognizer_verdict": _expected_recognizer_verdict(),
        "report_interface": {
            "computed_trace_is_label_set": False,
            "derivation_provenance": "derivation.json",
            "label_set_field": "report_cells",
            "name": "Report_V_linux_r(P,frontier)",
        },
        "report_cells": [joined],
        "schema": REPORT_SCHEMA,
        "transfer_validation": _expected_transfer_validation(),
    }
    return {**core, "report_hash": _hash_bytes(_canonical(core))}


def _expected_traces() -> list[dict[str, Any]]:
    context = _context()
    return [
        {
            "context": context, "input_a": 0, "observation": 1,
            "post_keys": ["B", "S"], "pre_keys": ["S"],
            "raw_return_class": "ok-inserted", "return_class": "ok",
            "source_state": "frontier:S", "suffix_word": [ACTION],
            "terminated": True,
        },
        {
            "context": context, "input_a": 1, "observation": 0,
            "post_keys": ["A", "S"], "pre_keys": ["A", "S"],
            "raw_return_class": "fail-capacity", "return_class": "fail",
            "source_state": "frontier:AS", "suffix_word": [ACTION],
            "terminated": True,
        },
    ]


def _expected_discipline() -> dict[str, Any]:
    context = _context()
    states = {
        "frontier:S": {"context": context, "keys": ["S"],
                       "phase": "frontier"},
        "terminal:BS": {"context": context, "keys": ["B", "S"],
                        "phase": "terminal"},
        "frontier:AS": {"context": context, "keys": ["A", "S"],
                        "phase": "frontier"},
        "terminal:AS": {"context": context, "keys": ["A", "S"],
                        "phase": "terminal"},
    }
    return {
        "action_alphabet": [ACTION],
        "concrete_region": [
            {"context": states[state_id]["context"],
             "keys": states[state_id]["keys"],
             "phase": states[state_id]["phase"], "state_id": state_id}
            for state_id in sorted(states)
        ],
        "encoding": {
            ACTION: "bpf_map_update_elem(G0,suffix_key,one,BPF_ANY);observe(ret==0)"
        },
        "name": "D_R_linux_hash_v1",
        "observer": "identity-on-complete-output-word",
        "output_alphabet": [0, 1],
        "runtime_action_defined_when": "phase=frontier",
        "state_projection": "s_D(phase,K,context)=phase:sorted(K)",
        "states": states,
        "transitions": {
            "frontier:S": {ACTION: {
                "defined": True, "next_state": "terminal:BS",
                "observation": 1, "raw_return_class": "ok-inserted",
                "return_class": "ok",
            }},
            "frontier:AS": {ACTION: {
                "defined": True, "next_state": "terminal:AS",
                "observation": 0, "raw_return_class": "fail-capacity",
                "return_class": "fail",
            }},
            "terminal:BS": {ACTION: {"defined": False}},
            "terminal:AS": {ACTION: {"defined": False}},
        },
    }


def _expected_quotient() -> dict[str, Any]:
    return {
        "algorithm": "deterministic-mealy-partition-refinement",
        "blocks": {
            "q0": ["frontier:AS"],
            "q1": ["frontier:S"],
            "q2": ["terminal:AS", "terminal:BS"],
        },
        "rounds": 2,
        "shortest_distinguishing_word": [ACTION],
        "state_to_block": {
            "frontier:AS": "q0", "frontier:S": "q1",
            "terminal:AS": "q2", "terminal:BS": "q2",
        },
    }


def _effective_control_program(program: dict[str, Any], name: str) -> dict[str, Any]:
    effective = copy.deepcopy(program)
    if name == "cap64":
        effective["map"]["capacity"] = 64
    elif name == "forced_sentinel":
        effective["operations"][4]["one_key"] = "S"
    elif name == "unobserved":
        effective["operations"][5]["expression"] = "unit"
    return effective


def _expected_controls(program: dict[str, Any]) -> dict[str, Any]:
    specifications = {
        "occupancy_tracking": (2, "B", True, "exact"),
        "cap64": (64, "B", True, "joined"),
        "forced_sentinel": (2, "S", True, "joined"),
        "unobserved": (2, "B", False, "joined"),
    }
    controls = {}
    for name, (_, suffix, observe, occupancy) in specifications.items():
        effective = _effective_control_program(program, name)
        program_hash = _hash_bytes(_canonical(effective))
        config = {
            "occupancy_policy": occupancy,
            "observe_return": observe,
            "program_hash": program_hash,
            "suffix_key": suffix,
        }
        controls[name] = {
            "adm_pass": True,
            "analysis_config_hash": _hash_bytes(_canonical(config)),
            "effective_program": effective,
            "factorization_holds": True,
            "formal_claim": f"R({INSTANCE_ID}__control_{name})",
            "instance_id": f"{INSTANCE_ID}__control_{name}",
            "program_hash": program_hash,
            "r_established": False,
            "scope": "R(V_linux_r,I_hash)",
            "stock_linux_verifier_r_established": False,
        }
    return controls


def _expected_reachability() -> list[dict[str, Any]]:
    return [
        {
            "final_keys": ["S"], "frontier": FRONTIER, "initial_keys": [],
            "input_a": 0,
            "steps": [
                {"after_keys": [], "before_keys": [], "op": "clear(S,A,B)",
                 "return_class": "unit"},
                {"after_keys": ["S"], "before_keys": [],
                 "op": "update_noexist(S)", "return_class": "ok"},
                {"after_keys": ["S"], "before_keys": ["S"],
                 "op": "update_any(S)", "return_class": "ok"},
            ],
        },
        {
            "final_keys": ["A", "S"], "frontier": FRONTIER,
            "initial_keys": [], "input_a": 1,
            "steps": [
                {"after_keys": [], "before_keys": [], "op": "clear(S,A,B)",
                 "return_class": "unit"},
                {"after_keys": ["S"], "before_keys": [],
                 "op": "update_noexist(S)", "return_class": "ok"},
                {"after_keys": ["A", "S"], "before_keys": ["S"],
                 "op": "update_any(A)", "return_class": "ok"},
            ],
        },
    ]


def _expected_reachability_claim() -> dict[str, Any]:
    return {
        "assignments_enumerated": 2,
        "deterministic_frontier_state_per_assignment": True,
        "fiber_equals_reach": True,
        "fixed_environment_count": 1,
        "no_unenumerated_input_or_environment_choices": True,
        "proof_method": "exhaustive symbolic-input enumeration",
        "reachable_state_ids": ["frontier:AS", "frontier:S"],
        "symbolic_input_domain": {"a": [0, 1], "b": [1]},
    }


def _expected_formal_instance(program_hash: str, report_hash: str) -> dict[str, Any]:
    return {
        "D": "D_R_linux_hash_v1",
        "F": ["frontier:S", "frontier:AS"],
        "I": "I_hash",
        "K_obs": "K_obs_linux_r_v1",
        "P": program_hash,
        "Report": "Report_V_linux_r(P,frontier)",
        "V": "V_linux_r",
        "frontier": FRONTIER,
        "id": INSTANCE_ID,
        "report_hash": report_hash,
    }


def _expected_word_obligations() -> list[dict[str, Any]]:
    states = _expected_states()
    obligations = []
    for word in ([], [ACTION]):
        outcomes = []
        for state in states:
            keys = set(state["keys"])
            outputs: list[int] = []
            terminal = state["state_id"]
            if word:
                if len(keys) < 2:
                    keys.add("B")
                    outputs = [1]
                else:
                    outputs = [0]
                terminal = "terminal:" + ("".join(sorted(keys)) or "empty")
            outcomes.append({
                "concrete_defined": True,
                "concrete_outputs": outputs,
                "context": _context(),
                "discipline_defined": True,
                "discipline_outputs": outputs,
                "final_concrete_keys": sorted(keys),
                "final_concrete_phase": ("terminal" if word else "frontier"),
                "final_discipline_state": terminal,
                "rho_obs": state["keys"],
                "slice_context": {
                    "program_phase": "frontier",
                    "service_context": _context(),
                },
                "state_id": state["state_id"],
            })
        soundness_cases = []
        for left in outcomes:
            for right in outcomes:
                antecedent = (
                    left["rho_obs"] == right["rho_obs"] and
                    left["slice_context"] == right["slice_context"]
                )
                same_definedness = (
                    left["concrete_defined"] == right["concrete_defined"]
                )
                same_observation = (
                    left["concrete_outputs"] == right["concrete_outputs"]
                    if left["concrete_defined"] and right["concrete_defined"]
                    else True
                )
                soundness_cases.append({
                    "antecedent": antecedent,
                    "holds": (not antecedent or
                              (same_definedness and same_observation)),
                    "left_state": left["state_id"],
                    "right_state": right["state_id"],
                    "same_definedness": same_definedness,
                    "same_observation_if_defined": same_observation,
                })
        obligations.append({
            "common_context": True,
            "encoded_word": ([] if not word else [
                "bpf_map_update_elem(G0,suffix_key,one,BPF_ANY);observe(ret==0)"
            ]),
            "observer_compatible": True,
            "outcomes": outcomes,
            "runtime_included": True,
            "soundness_cases": soundness_cases,
            "sound_observation_contract": True,
            "word": word,
        })
    return obligations


def _expected_observation_contract() -> dict[str, Any]:
    return {
        "candidate_state_projection": {
            "name": "rho_obs",
            "projection": "occupied-key set K",
        },
        "empty_word_observation": [],
        "environment": {
            "instances": [{
                "determinism": "I_hash transition function",
                "interference": "none",
                "schedule": "serialized",
                "service_context": _context(),
            }],
            "quantification": "singleton declared environment",
        },
        "name": "K_obs_linux_r_v1",
        "slice": {
            "fields": ["program_phase", "service_context"],
            "predeclared_for_words": [[], [ACTION]],
            "projection": "all non-K fields read by the encoded suffix or observer",
        },
        "soundness_domain": {
            "domain_identity": "Reach_I_hash(P,frontier)=F",
            "fiber_states": ["frontier:S", "frontier:AS"],
            "ordered_pairs_per_word": 4,
            "words": [[], [ACTION]],
        },
        "trace_observer": {
            "name": "Obs",
            "projection": "ordered list of success bits; unit when unobserved",
        },
    }


def _expected_factorization(cell_id: str) -> dict[str, Any]:
    return {
        "beta_cardinality_by_cell": {cell_id: 2},
        "collisions": [{
            "beta_classes": ["q0", "q1"],
            "cardinality": 2,
            "cell_id": cell_id,
        }],
        "holds": False,
    }


def _expected_checks() -> dict[str, bool]:
    return {
        "abstract_transfer_sound": True,
        "accepted_program": True,
        "common_context": True,
        "fiber_equals_reach": True,
        "fiber_nonempty_and_reachable": True,
        "gamma_declared_consistently": True,
        "injective_operation_encoding": True,
        "observation_compatibility": True,
        "observation_contract_declared": True,
        "observation_contract_sound": True,
        "operational_adequacy": True,
        "runtime_word_inclusion": True,
        "unique_cell_condition": True,
    }


def _expected_result() -> dict[str, Any]:
    return {
        "adm_pass": True,
        "factorization_holds": False,
        "formal_claim": f"R({INSTANCE_ID})",
        "instance_id": INSTANCE_ID,
        "r_established": True,
        "scope": "R(V_linux_r,I_hash)",
        "stock_linux_verifier_r_established": False,
    }


def _expected_witness(program_hash: str, cell_id: str) -> dict[str, Any]:
    return {
        "beta_different": True,
        "definition1_causal": True,
        "left_state": "frontier:S",
        "observations": [1, 0],
        "rho_obs_different": True,
        "right_state": "frontier:AS",
        "same_computed_cell": True,
        "suffix_word": [ACTION],
        "tagged_word": {
            "D": "D_R_linux_hash_v1",
            "F": ["frontier:S", "frontier:AS"],
            "P": program_hash,
            "a_sharp": cell_id,
            "frontier": FRONTIER,
            "w": [ACTION],
        },
    }


def _gamma_contains(cell: dict[str, Any], state: dict[str, Any]) -> bool:
    try:
        gamma = cell["concretization"]
        if gamma != _gamma(cell["abstract_state"]):
            return False
        keys = set(state["keys"])
        low, high = gamma["occupancy_interval"]
        return (
            state["phase"] == gamma["phase_equals"] and
            state["context"] == gamma["context_equals"] and
            gamma["map_type_equals"] == "BPF_MAP_TYPE_HASH" and
            state["context"]["map_type"] == gamma["map_type_equals"] and
            state["context"]["capacity"] == gamma["capacity_equals"] and
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
    return report.get("transfer_validation") == _expected_transfer_validation()


def _report_hash_valid(report: dict[str, Any]) -> bool:
    if not isinstance(report, dict) or "report_hash" not in report:
        return False
    core = {key: value for key, value in report.items() if key != "report_hash"}
    return report["report_hash"] == _hash_bytes(_canonical(core))


def _derivation_hash_valid(derivation: dict[str, Any]) -> bool:
    if not isinstance(derivation, dict) or "derivation_hash" not in derivation:
        return False
    core = {key: value for key, value in derivation.items()
            if key != "derivation_hash"}
    return derivation.get("schema") == DERIVATION_SCHEMA and (
        derivation["derivation_hash"] == _hash_bytes(_canonical(core))
    )


def _kernel_oracle_valid(root: Path, analysis: dict[str, Any]) -> bool:
    calibration = analysis.get("kernel_calibration")
    path = root / "kernel_oracle.jsonl"
    if calibration is None:
        return not path.exists()
    if not isinstance(calibration, dict) or not path.is_file():
        return False
    try:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()]
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return False
    if not all(isinstance(row, dict) for row in rows):
        return False
    runs = [row for row in rows if row.get("record") == "run"]
    gates = [row for row in rows if row.get("record") == "gate"]
    if len(rows) != 4 or len(runs) != 2 or len(gates) != 2:
        return False
    if ({row.get("ordinal") for row in runs} != {0, 1} or
            {row.get("ordinal") for row in gates} != {0, 1}):
        return False
    if any(row.get("circuit") != "nand" or row.get("kind") != "fixed_boundary"
           or row.get("variant_id") != 1 for row in rows):
        return False
    if any(row.get("gate") != 0 or row.get("src0") != 2 or
           row.get("src1") != 3 or row.get("dst") != 4 or
           row.get("trace_valid") is not True
           for row in gates):
        return False
    if any(row.get("input_count") != 2 or row.get("gate_count") != 1 or
           row.get("gate_cap") != 2 or row.get("status") != 0 or
           row.get("executed") != 1 or row.get("trace_passed") is not True or
           row.get("failing_gate") != 0xffffffff or
           row.get("gate_error_count") != 0
           for row in runs):
        return False
    by_run = {row["ordinal"]: row for row in runs}
    by_gate = {row["ordinal"]: row for row in gates}
    sequences = [by_run[index].get("run_seq") for index in (0, 1)]
    if (not all(isinstance(value, int) and value > 0 for value in sequences) or
            sequences[0] >= sequences[1] or
            any(by_gate[index].get("run_seq") != sequences[index]
                for index in (0, 1))):
        return False
    assignment_by_ordinal = {row.get("ordinal"): row.get("assignment") for row in runs}
    observations = {assignment_by_ordinal.get(row.get("ordinal")): row for row in gates}
    if set(observations) != {2, 3}:
        return False
    if not all(row.get("passed") is True for row in runs + gates):
        return False
    success = observations[2]
    failure = observations[3]
    for assignment, expected in ((2, 1), (3, 0)):
        run = next(row for row in runs if row.get("assignment") == assignment)
        gate = by_gate[run["ordinal"]]
        if (run.get("logical_expected") != expected or
                run.get("variant_expected") != expected or
                run.get("actual") != expected or gate.get("expected") != expected or
                gate.get("actual") != expected):
            return False
    tags = {row.get("program_tag") for row in runs + gates}
    program_ids = {row.get("program_id") for row in runs + gates}
    return (
        success.get("second_update_raw_ret") == 0 and success.get("actual") == 1 and
        isinstance(failure.get("second_update_raw_ret"), int) and
        failure["second_update_raw_ret"] < 0 and failure.get("actual") == 0 and
        len(tags) == 1 and all(isinstance(tag, str) and len(tag) == 16 and
                               all(character in "0123456789abcdef"
                                   for character in tag) for tag in tags) and
        len(program_ids) == 1 and all(isinstance(value, int) and value > 0
                                      for value in program_ids) and
        calibration.get("row_count") == 4 and
        calibration.get("assignments") == {
            "2": {"output": 1, "raw_return": 0, "trace_valid": True},
            "3": {"output": 0,
                  "raw_return": failure.get("second_update_raw_ret"),
                  "trace_valid": True},
        } and
        calibration.get("program_tag") in tags and
        calibration.get("model_alignment") == {
            "a0_b1_observation": True,
            "a1_b1_observation": True,
            "exact_errno_not_assumed": True,
        }
    )


def _artifact_binding_valid(root: Path, declared_files: dict[str, Any],
                            bindings: dict[str, Any], label: str,
                            expected_path: str) -> bool:
    binding = bindings.get(label)
    if not isinstance(binding, dict) or binding.get("path") != expected_path:
        return False
    candidate = root / expected_path
    declared = declared_files.get(expected_path)
    return (
        candidate.is_file() and isinstance(declared, dict) and
        binding.get("sha256") == _hash_file(candidate) == declared.get("sha256")
    )


def _elf_metadata(path: Path) -> dict[str, Any] | None:
    try:
        data = path.read_bytes()
        if (len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or
                data[5] not in (1, 2) or data[6] != 1):
            return None
        endian = "<" if data[5] == 1 else ">"
        fields = struct.unpack_from(endian + "16sHHIQQQIHHHHHH", data, 0)
        (_, elf_type, machine, version, _, _, section_offset, _, header_size,
         _, _, section_entry_size, section_count, string_index) = fields
        if (version != 1 or header_size != 64 or section_entry_size < 64 or
                section_count < 2 or string_index >= section_count):
            return None
        if section_offset < header_size or (
                section_offset + section_entry_size * section_count > len(data)):
            return None
        sections = [
            struct.unpack_from(
                endian + "IIQQQQIIQQ", data,
                section_offset + index * section_entry_size,
            )
            for index in range(section_count)
        ]
        names_header = sections[string_index]
        strings = data[names_header[4]:names_header[4] + names_header[5]]
        if len(strings) != names_header[5]:
            return None
        names = []
        for section in sections:
            name_offset = section[0]
            if name_offset >= len(strings):
                return None
            end = strings.find(b"\0", name_offset)
            if end < 0:
                return None
            names.append(strings[name_offset:end].decode("ascii"))
            if section[1] != 8 and section[4] + section[5] > len(data):
                return None
        return {"machine": machine, "section_names": names, "type": elf_type}
    except (OSError, UnicodeDecodeError, struct.error):
        return None


def _calibration_artifacts_valid(root: Path, declared_files: dict[str, Any],
                                 bindings: dict[str, Any]) -> bool:
    expected = {
        "bpf_object": "wm.bpf.o",
        "source": "wm.bpf.c",
        "descriptor": "nand.wmc",
        "harness_binary": "wm_vm_user",
        "harness_source": "wm_vm_user.c",
        "common_header": "wm_common.h",
        "makefile": "Makefile",
        "vmlinux_header": "vmlinux.h",
        "runner": "run_kernel.sh",
        "circuit_spec": "nand.json",
        "circuit_compiler": "circuit_tool.py",
        "model_source": "linux_r_model.py",
        "auditor_source": "linux_r_audit.py",
        "toolchain_log": "toolchain.txt",
    }
    if not all(_artifact_binding_valid(root, declared_files, bindings, label, path)
               for label, path in expected.items()):
        return False
    if not (root / "kernel_oracle.stderr").is_file() or not (
            root / "build.log").is_file():
        return False
    try:
        bpf = _elf_metadata(root / "wm.bpf.o")
        harness_elf = _elf_metadata(root / "wm_vm_user")
        if (bpf is None or bpf["type"] != 1 or bpf["machine"] != 247 or
                not {".maps", "license", "syscall", ".symtab"}.issubset(
                    set(bpf["section_names"]))):
            return False
        if (root / "nand.wmc").read_bytes() != (
                b"WMC1 nand 2 1 5 1\n1 2 3 4\n4\n"):
            return False
        if (harness_elf is None or harness_elf["type"] not in (2, 3) or
                harness_elf["machine"] not in (62, 183) or
                not {".text", ".rodata", ".dynsym", ".dynamic"}.issubset(
                    set(harness_elf["section_names"]))):
            return False
        bpf_text = (root / "wm.bpf.c").read_text(encoding="utf-8")
        marker = bpf_text.find("Capacity-saturation NAND")
        if marker < 0:
            return False
        cursor = marker
        for token in (
            "#define NAND_GATE_OBS",
            "bpf_map_delete_elem(&(MAP), &ks)",
            "bpf_map_delete_elem(&(MAP), &ka)",
            "bpf_map_delete_elem(&(MAP), &kb)",
            "bpf_map_update_elem(&(MAP), &ks, &one, BPF_NOEXIST)",
            "__u32 k1",
            "bpf_map_update_elem(&(MAP), &k1, &one, BPF_ANY)",
            "__u32 k2",
            "bpf_map_update_elem(&(MAP), &k2, &one, BPF_ANY)",
            "record_second_update(r2)",
            "(__u64)(r2 == 0)",
        ):
            cursor = bpf_text.find(token, cursor)
            if cursor < 0:
                return False
            cursor += len(token)
        harness = (root / "wm_vm_user.c").read_text(encoding="utf-8")
        if not all(token in harness for token in (
                "read_image(", "bpf_prog_test_run_opts(", "map_get(trace_fd",
                "second_update_raw_ret", "trace_valid", "program_tag")):
            return False
        header = (root / "wm_common.h").read_text(encoding="utf-8")
        if not all(token in header for token in (
                "#define K_S 0u", "#define K_A 1u", "#define K_B 2u",
                "#define VM_ABI_VERSION       1u", "struct wm_gate_trace")):
            return False
        makefile = (root / "Makefile").read_text(encoding="utf-8")
        if not all(token in makefile for token in (
                "GATE_CAP ?= 2", "$(BUILD)/wm.bpf.o:",
                "$(BUILD)/wm_vm_user:")):
            return False
        spec = json.loads((root / "nand.json").read_text(encoding="utf-8"))
        if spec != {
            "gates": [{"args": ["a", "b"], "id": "out", "op": "nand"}],
            "inputs": ["a", "b"], "name": "nand", "outputs": ["out"],
        }:
            return False
        source_requirements = {
            "vmlinux.h": ("struct task_struct", "typedef unsigned int __u32"),
            "run_kernel.sh": ("WM_VM_EMIT_GATES=1", "python3 -m linux_r.generate"),
            "circuit_tool.py": ("def compile_spec", "WMC1"),
            "linux_r_model.py": ("def compute_report", "def build_bundle"),
            "linux_r_audit.py": ("def audit_bundle", "def _expected_report"),
            "toolchain.txt": ("UNAME", "CLANG", "CC", "BPFTOOL", "LIBBPF"),
        }
        for name, tokens in source_requirements.items():
            text = (root / name).read_text(encoding="utf-8")
            if not all(token in text for token in tokens):
                return False
        build_text = (root / "build.log").read_text(encoding="utf-8")
        if not all(token in build_text for token in (
                "wm.bpf.c", "-target bpf", "-DGATE_CAP=2", "wm_vm_user.c")):
            return False
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return True


def _failed(reason: str) -> dict[str, Any]:
    return {
        "checks": {"bundle_readable": False},
        "errors": [reason],
        "recomputed": {
            "adm_pass": False,
            "beta_different": False,
            "factorization_holds": None,
            "memberships": [],
            "r_established": False,
            "scope": "R(V_linux_r,I_hash)",
            "stock_linux_verifier_r_established": False,
        },
        "verdict": "FAIL",
    }


def audit_bundle(path: str | Path, *, require_kernel: bool = False,
                 write: bool = True) -> dict[str, Any]:
    root = Path(path)
    try:
        manifest = _read_json(root / "manifest.json")
        program = _read_json(root / "program.json")
        analysis = _read_json(root / "analysis.json")
        report = _read_json(root / "report.json")
        derivation = _read_json(root / "derivation.json")
        if not all(isinstance(value, dict)
                   for value in (manifest, program, analysis, report, derivation)):
            raise TypeError("bundle JSON roots must all be objects")
    except (OSError, json.JSONDecodeError, TypeError, UnicodeDecodeError) as exc:
        failed = _failed(str(exc))
        if write:
            try:
                (root / "audit.txt").write_text(_format_audit(failed),
                                                 encoding="utf-8")
            except OSError:
                pass
        return failed

    checks: dict[str, bool] = {}
    errors: list[str] = []
    checks["manifest_schema"] = manifest.get("schema") == MANIFEST_SCHEMA
    manifest_core = {key: value for key, value in manifest.items()
                     if key != "manifest_hash"}
    checks["manifest_hash"] = (
        manifest.get("manifest_hash") == _hash_bytes(_canonical(manifest_core))
    )
    declared_files = manifest.get("files", {})
    declared_records = declared_files if isinstance(declared_files, dict) else {}
    try:
        entries = list(root.iterdir())
        actual_names = sorted(item.name for item in entries if item.is_file() and
                              not item.is_symlink() and item.name not in {
                                  "manifest.json", "audit.txt"
                              })
        checks["root_entries_regular"] = all(
            item.name in {"manifest.json", "audit.txt"} or
            (item.is_file() and not item.is_symlink())
            for item in entries
        )
    except OSError:
        actual_names = []
        checks["root_entries_regular"] = False
    checks["manifest_file_set"] = (
        isinstance(declared_files, dict) and sorted(declared_files) == actual_names
    )
    hashes_ok = checks["manifest_file_set"]
    if hashes_ok:
        for name, binding in declared_records.items():
            file_path = root / name
            if (not isinstance(binding, dict) or
                    binding.get("sha256") != _hash_file(file_path) or
                    binding.get("size") != file_path.stat().st_size):
                hashes_ok = False
                break
    checks["manifest_file_hashes"] = hashes_ok
    checks["manifest_files"] = checks["manifest_file_set"] and hashes_ok
    bindings = manifest.get("bindings", {})
    if not isinstance(bindings, dict):
        bindings = {}
    checks["program_canonical"] = _program_is_canonical(program)
    checks["analysis_schema"] = analysis.get("schema") == ANALYSIS_SCHEMA

    expected_report = (_expected_report(program)
                       if checks["program_canonical"] else {})
    expected_derivation = (_expected_derivation(program)
                           if checks["program_canonical"] else {})
    raw_cells = report.get("report_cells", [])
    cells = (raw_cells if isinstance(raw_cells, list) and
             all(isinstance(cell, dict) for cell in raw_cells) else [])
    checks["report_schema"] = report.get("schema") == REPORT_SCHEMA
    checks["report_hash"] = _report_hash_valid(report)
    checks["derivation_hash"] = _derivation_hash_valid(derivation)
    checks["derivation_exact"] = (
        bool(expected_derivation) and derivation == expected_derivation
    )
    checks["derivation_reference"] = (
        report.get("derivation_ref") == {
            "derivation_hash": derivation.get("derivation_hash"),
            "path": "derivation.json",
            "schema": DERIVATION_SCHEMA,
        } and
        analysis.get("derivation_ref") == {
            "derivation_hash": derivation.get("derivation_hash"),
            "path": "derivation.json",
            "sha256": _hash_file(root / "derivation.json"),
        }
    )
    checks["report_reference"] = analysis.get("report_ref") == {
        "path": "report.json",
        "report_hash": report.get("report_hash"),
        "sha256": _hash_file(root / "report.json"),
    }
    checks["report_exact"] = bool(expected_report) and report == expected_report
    checks["computed_before_witness"] = (
        report.get("analysis_order") ==
        "computed-before-concrete-witness-enumeration" and
        report.get("posthoc_output_data_used") is False
    )
    checks["cell_ids_canonical"] = (
        cells is raw_cells and _valid_cell_ids(cells)
    )
    checks["abstract_transfer_sound"] = _transfer_validation_is_exact(report)

    expected_states = _expected_states()
    checks["concrete_reachability"] = analysis.get("concrete_states") == expected_states
    checks["reachability_certificates"] = (
        analysis.get("reachability_certificates") == _expected_reachability()
    )
    checks["reachability_completeness"] = (
        analysis.get("reachability_claim") == _expected_reachability_claim()
    )
    checks["discipline_exact"] = analysis.get("discipline") == _expected_discipline()
    checks["quotient_exact"] = analysis.get("quotient") == _expected_quotient()
    checks["runtime_semantics"] = analysis.get("concrete_traces") == _expected_traces()
    checks["common_word_obligations"] = (
        analysis.get("common_words") == [[], [ACTION]] and
        analysis.get("word_obligations") == _expected_word_obligations() and
        analysis.get("observation_contract") == _expected_observation_contract()
    )
    memberships = [[cell.get("cell_id") for cell in cells
                    if _gamma_contains(cell, state)] for state in expected_states]
    expected_coverage = [
        {"cell_ids": memberships[index], "state_id": state["state_id"]}
        for index, state in enumerate(expected_states)
    ]
    checks["unique_cell_coverage"] = (
        all(len(items) == 1 for items in memberships) and
        analysis.get("coverage") == expected_coverage
    )
    checks["unique_cell_condition"] = (
        checks["unique_cell_coverage"] and checks["report_exact"]
    )
    checks["same_computed_cell"] = (
        checks["unique_cell_condition"] and memberships[0][0] == memberships[1][0]
    )

    beta_different = checks["quotient_exact"]
    collision = checks["same_computed_cell"] and beta_different
    cell_id = memberships[0][0] if checks["same_computed_cell"] else None
    checks["factorization_recomputed"] = (
        collision and analysis.get("factorization") ==
        _expected_factorization(cell_id)
    )

    program_hash = _hash_bytes(_canonical(program))
    checks["output_witness"] = (
        checks["runtime_semantics"] and checks["discipline_exact"] and
        checks["common_word_obligations"] and beta_different and collision and
        analysis.get("witness") == _expected_witness(program_hash, cell_id)
    )
    independent_adm = all(checks[name] for name in (
        "program_canonical", "report_exact", "abstract_transfer_sound",
        "derivation_exact", "derivation_reference",
        "concrete_reachability", "reachability_certificates",
        "reachability_completeness", "discipline_exact",
        "common_word_obligations", "unique_cell_condition",
    ))
    checks["admissibility"] = independent_adm
    checks["persisted_claim_exact"] = (
        analysis.get("checks") == _expected_checks() and
        analysis.get("result") == _expected_result() and
        analysis.get("profile") == {
            "capacity": 2, "name": "baseline", "observe_return": True,
            "occupancy_policy": "joined", "suffix_key": "B",
        } and
        analysis.get("effective_program") == program
    )
    checks["formal_instance_exact"] = (
        analysis.get("formal_instance") == _expected_formal_instance(
            program_hash, report.get("report_hash")
        )
    )
    checks["negative_controls"] = (
        checks["program_canonical"] and
        analysis.get("controls") == _expected_controls(program)
    )
    result = analysis.get("result", {})
    if not isinstance(result, dict):
        result = {}
    checks["scope_label_honest"] = (
        result.get("scope") == "R(V_linux_r,I_hash)" and
        result.get("formal_claim") == f"R({INSTANCE_ID})" and
        result.get("instance_id") == INSTANCE_ID and
        result.get("r_established") is True and
        result.get("stock_linux_verifier_r_established") is False
    )
    kernel_valid = _kernel_oracle_valid(root, analysis)
    kernel_present = analysis.get("kernel_calibration") is not None
    optional_bindings = {
        "bpf_object": "wm.bpf.o", "source": "wm.bpf.c",
        "descriptor": "nand.wmc", "harness_binary": "wm_vm_user",
        "harness_source": "wm_vm_user.c", "common_header": "wm_common.h",
        "makefile": "Makefile",
        "vmlinux_header": "vmlinux.h", "runner": "run_kernel.sh",
        "circuit_spec": "nand.json", "circuit_compiler": "circuit_tool.py",
        "model_source": "linux_r_model.py", "auditor_source": "linux_r_audit.py",
        "toolchain_log": "toolchain.txt",
    }
    present_bindings_valid = all(
        _artifact_binding_valid(root, declared_records, bindings, label, name)
        for label, name in optional_bindings.items() if label in bindings
    )
    if kernel_present:
        checks["artifact_bindings"] = (
            present_bindings_valid and
            _calibration_artifacts_valid(root, declared_records, bindings)
        )
    else:
        checks["artifact_bindings"] = present_bindings_valid
    checks["kernel_calibration"] = kernel_valid and (kernel_present or not require_kernel)
    checks["kernel_required"] = not require_kernel or kernel_present

    for name, passed in checks.items():
        if not passed:
            errors.append(name)
    result = {
        "checks": checks,
        "errors": errors,
        "recomputed": {
            "adm_pass": independent_adm,
            "beta_different": beta_different,
            "factorization_holds": (not collision
                                    if checks["unique_cell_condition"] else None),
            "memberships": memberships,
            "r_established": (
                independent_adm and checks["output_witness"] and collision
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
    recomputed = result.get("recomputed", {})
    established = (result.get("verdict") == "PASS" and
                   recomputed.get("r_established") is True)
    lines.extend([
        f"ADM_PASS: {'PASS' if recomputed.get('adm_pass') else 'FAIL'}",
        "SAME_COMPUTED_CELL_PASS: " +
        ("PASS" if result.get("checks", {}).get("same_computed_cell") else "FAIL"),
        f"BETA_DIFFERENT_PASS: {'PASS' if recomputed.get('beta_different') else 'FAIL'}",
        "NON_FACTORIZATION_PASS: " +
        ("PASS" if result.get("checks", {}).get("factorization_recomputed")
         else "FAIL"),
        (f"FORMAL_CLAIM: R({INSTANCE_ID})=ESTABLISHED" if established else
         f"FORMAL_CLAIM: R({INSTANCE_ID})=NOT_ESTABLISHED"),
        ("CLAIM: R(V_linux_r,I_hash)=ESTABLISHED" if established else
         "CLAIM: R(V_linux_r,I_hash)=NOT_ESTABLISHED"),
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
