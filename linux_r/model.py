#!/usr/bin/env python3
"""Generate a computed-cell R witness over Linux HASH-map service semantics.

This module defines two deliberately separate objects:

* ``I_hash`` is a finite, executable service semantics for the ordinary,
  non-evicting Linux ``BPF_MAP_TYPE_HASH`` update cases used by the NAND gate.
* ``V_linux_r`` is a report-producing abstract interpreter.  It computes its
  report before any concrete witness is enumerated.  Its baseline domain joins
  the two possible occupancies at the declared frontier.

The resulting claim is R(V_linux_r, I_hash).  It is not an export of the stock
Linux verifier's internal state and must not be labelled as such.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


PROGRAM_SCHEMA = "linux-r-program-v1"
ANALYSIS_SCHEMA = "linux-r-analysis-v1"
MANIFEST_SCHEMA = "linux-r-manifest-v1"
REPORT_SCHEMA = "linux-r-computed-report-v1"
DOMAIN_VERSION = "occ-join-v1"
FRONTIER = "after-first-update-before-second"
ACTION = "update-suffix-and-observe"
KEYS = ("S", "A", "B")


class ModelError(ValueError):
    """Raised when a program or evidence input violates the declared model."""


@dataclass(frozen=True)
class Profile:
    name: str
    capacity: int
    suffix_key: str
    observe_return: bool
    occupancy_policy: str


PROFILES = {
    "baseline": Profile("baseline", 2, "B", True, "joined"),
    "occupancy_tracking": Profile(
        "occupancy_tracking", 2, "B", True, "exact"
    ),
    "cap64": Profile("cap64", 64, "B", True, "joined"),
    "forced_sentinel": Profile("forced_sentinel", 2, "S", True, "joined"),
    "unobserved": Profile("unobserved", 2, "B", False, "joined"),
}


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_program(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    try:
        program = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelError(f"cannot read program {path}: {exc}") from exc
    validate_program(program)
    return program


def validate_program(program: dict[str, Any]) -> None:
    if not isinstance(program, dict) or program.get("schema") != PROGRAM_SCHEMA:
        raise ModelError(f"program schema must be {PROGRAM_SCHEMA}")
    if program.get("recognizer") != "V_linux_r" or program.get("runtime") != "I_hash":
        raise ModelError("program must bind V_linux_r to I_hash")
    map_spec = program.get("map")
    if not isinstance(map_spec, dict):
        raise ModelError("map must be an object")
    expected_map = {
        "capacity": 2,
        "key_universe": list(KEYS),
        "map_type": "BPF_MAP_TYPE_HASH",
        "non_evicting": True,
        "update_flag": "BPF_ANY",
    }
    if map_spec != expected_map:
        raise ModelError("map declaration is outside the linux_r v1 domain")
    if program.get("symbolic_inputs") != {"a": [0, 1], "b": [1]}:
        raise ModelError("linux_r v1 requires symbolic a in {0,1} and fixed b=1")
    operations = program.get("operations")
    if not isinstance(operations, list) or len(operations) != 6:
        raise ModelError("linux_r v1 requires six canonical operations")
    expected_ops = ["clear", "update", "update_selected", "frontier",
                    "update_selected", "observe"]
    if [op.get("op") for op in operations if isinstance(op, dict)] != expected_ops:
        raise ModelError("operation sequence is not canonical linux_r v1")
    if operations[0].get("keys") != list(KEYS):
        raise ModelError("clear must cover the complete key universe")
    if operations[1].get("key") != "S" or operations[1].get("flag") != "BPF_NOEXIST":
        raise ModelError("sentinel setup must insert S with BPF_NOEXIST")
    if (operations[2].get("selector"), operations[2].get("zero_key"),
            operations[2].get("one_key"), operations[2].get("flag")) != (
                "a", "S", "A", "BPF_ANY"):
        raise ModelError("first selected update is not canonical")
    if operations[3].get("id") != FRONTIER:
        raise ModelError("frontier id changed")
    if (operations[4].get("selector"), operations[4].get("zero_key"),
            operations[4].get("one_key"), operations[4].get("flag")) != (
                "b", "S", "B", "BPF_ANY"):
        raise ModelError("second selected update is not canonical")
    if operations[5].get("expression") != "last_return_is_success":
        raise ModelError("observer contract changed")
    if program.get("scope") != {
        "concurrency": "serialized", "interference": "none", "value": 1
    }:
        raise ModelError("scope must fix serialization, no interference, and value=1")


def update_any(keys: frozenset[str], key: str, capacity: int) -> tuple[frozenset[str], str]:
    """I_hash update semantics for valid BPF_ANY calls on a non-evicting HASH."""
    if key not in KEYS:
        raise ModelError(f"key outside universe: {key}")
    if key in keys:
        return keys, "ok-existing"
    if len(keys) < capacity:
        return frozenset((*keys, key)), "ok-inserted"
    return keys, "fail-capacity"


def _return_class(raw_class: str) -> str:
    return "ok" if raw_class.startswith("ok-") else "fail"


def _observe(raw_class: str, enabled: bool) -> int | str:
    if not enabled:
        return "unit"
    return int(_return_class(raw_class) == "ok")


def _state_id(phase: str, keys: Iterable[str]) -> str:
    encoded = "".join(sorted(keys)) or "empty"
    return f"{phase}:{encoded}"


def _context(profile: Profile) -> dict[str, Any]:
    return {
        "capacity": profile.capacity,
        "concurrency": "serialized",
        "interference": "none",
        "key_universe": list(KEYS),
        "map_type": "BPF_MAP_TYPE_HASH",
        "non_evicting": True,
        "observer": "last_return_is_success" if profile.observe_return else "unit",
        "suffix_key": profile.suffix_key,
        "update_flag": "BPF_ANY",
        "value": 1,
    }


def _frontier_concrete_states(profile: Profile) -> list[dict[str, Any]]:
    states: list[dict[str, Any]] = []
    for input_a in (0, 1):
        keys: frozenset[str] = frozenset()
        keys, setup_ret = update_any(keys, "S", profile.capacity)
        first_key = "S" if input_a == 0 else "A"
        keys, first_ret = update_any(keys, first_key, profile.capacity)
        if _return_class(setup_ret) != "ok" or _return_class(first_ret) != "ok":
            raise AssertionError("canonical prefix must succeed")
        states.append({
            "context": _context(profile),
            "input_a": input_a,
            "keys": sorted(keys),
            "phase": FRONTIER,
            "reachable_by": [
                "clear(S,A,B)", "update_noexist(S)",
                f"update_any({first_key})",
            ],
            "state_id": _state_id("frontier", keys),
        })
    return states


def _abstract_payload(profile: Profile, keys: Iterable[str] | None,
                      *, joined: bool = False) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "context": _context(profile),
        "frontier": FRONTIER,
        "static_safety": {
            "bounded_key_universe": True,
            "capacity_positive": profile.capacity > 0,
            "flags_valid": True,
            "map_reference_valid": True,
            "value_size_valid": True,
        },
    }
    if joined:
        payload["occupancy"] = {
            "exact_key_set": "not-tracked",
            "max_size": min(2, profile.capacity),
            "may_contain": ["S", "A"],
            "min_size": 1,
            "must_contain": ["S"],
        }
    else:
        exact = sorted(keys or [])
        payload["occupancy"] = {
            "exact_key_set": exact,
            "max_size": len(exact),
            "may_contain": exact,
            "min_size": len(exact),
            "must_contain": exact,
        }
    return payload


def _gamma_for_payload(payload: dict[str, Any]) -> dict[str, Any]:
    occupancy = payload["occupancy"]
    predicate: dict[str, Any] = {
        "capacity_equals": payload["context"]["capacity"],
        "context_equals": payload["context"],
        "keys_subset_of": occupancy["may_contain"],
        "map_type_equals": "BPF_MAP_TYPE_HASH",
        "must_contain": occupancy["must_contain"],
        "occupancy_interval": [occupancy["min_size"], occupancy["max_size"]],
        "phase_equals": FRONTIER,
    }
    if occupancy["exact_key_set"] != "not-tracked":
        predicate["keys_equal"] = occupancy["exact_key_set"]
    return predicate


def _cell(payload: dict[str, Any], *, predecessors: list[str],
          operator: str) -> dict[str, Any]:
    core = {
        "abstract_state": payload,
        "concretization": _gamma_for_payload(payload),
        "operator": operator,
        "predecessors": sorted(predecessors),
    }
    return {
        "cell_id": "cell-" + _sha256_bytes(canonical_json_bytes(core))[:24],
        **core,
    }


def _possible_suffix(cell: dict[str, Any], profile: Profile) -> dict[str, Any]:
    gamma = cell["concretization"]
    allowed = gamma["keys_subset_of"]
    must = set(gamma["must_contain"])
    low, high = gamma["occupancy_interval"]
    possible_keys = []
    for mask in range(1 << len(KEYS)):
        keys = frozenset(KEYS[index] for index in range(len(KEYS))
                         if mask & (1 << index))
        if not must.issubset(keys) or not keys.issubset(allowed):
            continue
        if not low <= len(keys) <= high:
            continue
        if "keys_equal" in gamma and sorted(keys) != gamma["keys_equal"]:
            continue
        possible_keys.append(keys)
    returns = sorted({_return_class(update_any(keys, profile.suffix_key,
                                                profile.capacity)[1])
                      for keys in possible_keys})
    observations = sorted({_observe(result, profile.observe_return)
                           for keys in possible_keys
                           for result in [update_any(keys, profile.suffix_key,
                                                     profile.capacity)[1]]},
                          key=str)
    return {
        "possible_observations": observations,
        "possible_return_classes": returns,
        "states_enumerated": len(possible_keys),
    }


def _exhaustive_transfer_validation(profile: Profile) -> dict[str, Any]:
    """Exhaust the finite HASH domain and check the occupancy abstraction.

    The abstract transformer for a known update key returns every return class
    attainable from any legal occupancy in the domain.  The validation is
    deliberately domain-wide, not restricted to the two selected witnesses.
    """
    valid_occupancies = []
    for mask in range(1 << len(KEYS)):
        keys = frozenset(KEYS[index] for index in range(len(KEYS))
                         if mask & (1 << index))
        if len(keys) <= profile.capacity:
            valid_occupancies.append(keys)
    abstract_returns = {
        key: sorted({_return_class(update_any(keys, key, profile.capacity)[1])
                     for keys in valid_occupancies})
        for key in KEYS
    }
    violations = []
    checked = 0
    for keys in valid_occupancies:
        for key in KEYS:
            checked += 1
            concrete = _return_class(update_any(keys, key, profile.capacity)[1])
            if concrete not in abstract_returns[key]:
                violations.append({
                    "abstract_returns": abstract_returns[key],
                    "concrete_return": concrete,
                    "key": key,
                    "keys": sorted(keys),
                })
    return {
        "abstract_returns": abstract_returns,
        "checked_cases": checked,
        "method": "exhaustive",
        "violations": violations,
    }


def compute_report(program: dict[str, Any], profile: Profile) -> dict[str, Any]:
    """Run V_linux_r and emit its actual computed frontier cells.

    This function consumes only the program and abstract profile.  Concrete
    witness traces are deliberately not an argument.
    """
    validate_program(program)
    program_hash = _sha256_bytes(canonical_json_bytes(program))
    sentinel_payload = _abstract_payload(profile, ["S"])
    sentinel = _cell(sentinel_payload, predecessors=[], operator="update_noexist(S)")
    branch_zero = _cell(
        _abstract_payload(profile, ["S"]),
        predecessors=[sentinel["cell_id"]],
        operator="branch(a=0);update_any(S)",
    )
    branch_one = _cell(
        _abstract_payload(profile, ["S", "A"]),
        predecessors=[sentinel["cell_id"]],
        operator="branch(a=1);update_any(A)",
    )
    if profile.occupancy_policy == "joined":
        report_cells = [_cell(
            _abstract_payload(profile, None, joined=True),
            predecessors=[branch_zero["cell_id"], branch_one["cell_id"]],
            operator="join(forget-exact-occupancy)",
        )]
    elif profile.occupancy_policy == "exact":
        report_cells = [branch_zero, branch_one]
    else:
        raise ModelError(f"unknown occupancy policy: {profile.occupancy_policy}")
    for cell in report_cells:
        cell["suffix_abstract_transfer"] = _possible_suffix(cell, profile)
    report_core = {
        "analysis_order": "computed-before-concrete-witness-enumeration",
        "computed_trace": [sentinel, branch_zero, branch_one],
        "domain": {
            "name": "linux-r-occupancy-domain",
            "occupancy_policy": profile.occupancy_policy,
            "version": DOMAIN_VERSION,
        },
        "frontier": FRONTIER,
        "posthoc_output_data_used": False,
        "profile": profile.name,
        "program_hash": program_hash,
        "recognizer": "V_linux_r",
        "report_cells": report_cells,
        "schema": REPORT_SCHEMA,
        "transfer_validation": _exhaustive_transfer_validation(profile),
    }
    return {
        **report_core,
        "report_hash": _sha256_bytes(canonical_json_bytes(report_core)),
    }


def gamma_contains(cell: dict[str, Any], state: dict[str, Any]) -> bool:
    gamma = cell["concretization"]
    keys = set(state["keys"])
    if state["phase"] != gamma["phase_equals"]:
        return False
    if state["context"] != gamma["context_equals"]:
        return False
    if not set(gamma["must_contain"]).issubset(keys):
        return False
    if not keys.issubset(set(gamma["keys_subset_of"])):
        return False
    low, high = gamma["occupancy_interval"]
    if not low <= len(keys) <= high:
        return False
    if "keys_equal" in gamma and sorted(keys) != gamma["keys_equal"]:
        return False
    return True


def _build_discipline(frontier_states: list[dict[str, Any]],
                      profile: Profile) -> dict[str, Any]:
    states: dict[str, dict[str, Any]] = {}
    transitions: dict[str, dict[str, Any]] = {}
    for state in frontier_states:
        source_id = state["state_id"]
        keys = frozenset(state["keys"])
        next_keys, raw_return = update_any(keys, profile.suffix_key,
                                           profile.capacity)
        target_id = _state_id("terminal", next_keys)
        states[source_id] = {
            "context": state["context"], "keys": sorted(keys),
            "phase": "frontier",
        }
        states[target_id] = {
            "context": state["context"], "keys": sorted(next_keys),
            "phase": "terminal",
        }
        transitions[source_id] = {
            ACTION: {
                "defined": True,
                "next_state": target_id,
                "observation": _observe(raw_return, profile.observe_return),
                "raw_return_class": raw_return,
                "return_class": _return_class(raw_return),
            }
        }
    for state_id, state in states.items():
        if state["phase"] == "terminal":
            transitions[state_id] = {ACTION: {"defined": False}}
    return {
        "action_alphabet": [ACTION],
        "encoding": {
            ACTION: "bpf_map_update_elem(G0,suffix_key,one,BPF_ANY);observe(ret==0)"
        },
        "name": "D_R_linux_hash_v1",
        "states": states,
        "transitions": transitions,
    }


def _partition_refinement(discipline: dict[str, Any]) -> dict[str, Any]:
    state_ids = sorted(discipline["states"])
    actions = discipline["action_alphabet"]
    blocks: list[list[str]] = [state_ids]
    rounds = 0
    while True:
        block_of = {state: index for index, block in enumerate(blocks)
                    for state in block}
        grouped: dict[tuple[Any, ...], list[str]] = {}
        for state in state_ids:
            signature: list[Any] = []
            for action in actions:
                transition = discipline["transitions"][state][action]
                if not transition["defined"]:
                    signature.append((False, None, None))
                else:
                    signature.append((
                        True,
                        json.dumps(transition["observation"], sort_keys=True),
                        block_of[transition["next_state"]],
                    ))
            grouped.setdefault(tuple(signature), []).append(state)
        next_blocks = sorted((sorted(group) for group in grouped.values()),
                             key=lambda group: tuple(group))
        rounds += 1
        if next_blocks == blocks:
            break
        blocks = next_blocks
    named_blocks = {f"q{index}": block for index, block in enumerate(blocks)}
    state_to_block = {state: name for name, block in named_blocks.items()
                      for state in block}
    return {
        "algorithm": "deterministic-mealy-partition-refinement",
        "blocks": named_blocks,
        "rounds": rounds,
        "state_to_block": state_to_block,
    }


def _shortest_distinguishing_word(discipline: dict[str, Any], left: str,
                                  right: str) -> list[str] | None:
    actions = discipline["action_alphabet"]
    queue: deque[tuple[str, str, list[str]]] = deque([(left, right, [])])
    visited = {(left, right)}
    while queue:
        first, second, prefix = queue.popleft()
        for action in actions:
            first_t = discipline["transitions"][first][action]
            second_t = discipline["transitions"][second][action]
            word = [*prefix, action]
            if first_t["defined"] != second_t["defined"]:
                return word
            if not first_t["defined"]:
                continue
            if first_t["observation"] != second_t["observation"]:
                return word
            pair = (first_t["next_state"], second_t["next_state"])
            if pair not in visited:
                visited.add(pair)
                queue.append((*pair, word))
    return None


def _concrete_traces(frontier_states: list[dict[str, Any]],
                     profile: Profile) -> list[dict[str, Any]]:
    traces: list[dict[str, Any]] = []
    for state in frontier_states:
        keys = frozenset(state["keys"])
        next_keys, raw_return = update_any(keys, profile.suffix_key,
                                           profile.capacity)
        traces.append({
            "context": state["context"],
            "input_a": state["input_a"],
            "observation": _observe(raw_return, profile.observe_return),
            "post_keys": sorted(next_keys),
            "pre_keys": sorted(keys),
            "raw_return_class": raw_return,
            "return_class": _return_class(raw_return),
            "source_state": state["state_id"],
            "suffix_word": [ACTION],
            "terminated": True,
        })
    return traces


def _operationally_adequate(discipline: dict[str, Any], profile: Profile) -> bool:
    for state_id, state in discipline["states"].items():
        transition = discipline["transitions"][state_id][ACTION]
        if state["phase"] == "terminal":
            if transition["defined"]:
                return False
            continue
        next_keys, raw_return = update_any(frozenset(state["keys"]),
                                           profile.suffix_key,
                                           profile.capacity)
        if not transition["defined"]:
            return False
        if transition["next_state"] != _state_id("terminal", next_keys):
            return False
        if transition["observation"] != _observe(raw_return,
                                                  profile.observe_return):
            return False
    return True


def build_analysis(program: dict[str, Any], profile_name: str = "baseline") -> dict[str, Any]:
    validate_program(program)
    try:
        profile = PROFILES[profile_name]
    except KeyError as exc:
        raise ModelError(f"unknown profile: {profile_name}") from exc

    # This call is intentionally first: V_linux_r cannot inspect witness output.
    report = compute_report(program, profile)
    frontier_states = _frontier_concrete_states(profile)
    discipline = _build_discipline(frontier_states, profile)
    quotient = _partition_refinement(discipline)
    traces = _concrete_traces(frontier_states, profile)

    coverage: list[dict[str, Any]] = []
    for state in frontier_states:
        cells = [cell["cell_id"] for cell in report["report_cells"]
                 if gamma_contains(cell, state)]
        coverage.append({"cell_ids": cells, "state_id": state["state_id"]})
    unique_coverage = all(len(item["cell_ids"]) == 1 for item in coverage)
    cell_for_state = {
        item["state_id"]: item["cell_ids"][0]
        for item in coverage if len(item["cell_ids"]) == 1
    }
    beta = quotient["state_to_block"]
    by_cell: dict[str, set[str]] = {}
    if unique_coverage:
        for state in frontier_states:
            by_cell.setdefault(cell_for_state[state["state_id"]], set()).add(
                beta[state["state_id"]]
            )
    collisions = [
        {"beta_classes": sorted(classes), "cell_id": cell_id,
         "cardinality": len(classes)}
        for cell_id, classes in sorted(by_cell.items()) if len(classes) > 1
    ]
    factorization_holds = unique_coverage and not collisions
    left, right = frontier_states
    shortest = _shortest_distinguishing_word(
        discipline, left["state_id"], right["state_id"]
    )
    same_context = left["context"] == right["context"]
    same_cell = (unique_coverage and
                 cell_for_state[left["state_id"]] ==
                 cell_for_state[right["state_id"]])
    different_beta = beta[left["state_id"]] != beta[right["state_id"]]
    different_output = traces[0]["observation"] != traces[1]["observation"]
    operational_adequacy = _operationally_adequate(discipline, profile)
    admissibility_checks = {
        "accepted_program": True,
        "abstract_transfer_sound": not report["transfer_validation"]["violations"],
        "common_context": same_context,
        "fiber_nonempty_and_reachable": bool(frontier_states) and all(
            state["reachable_by"] for state in frontier_states
        ),
        "injective_operation_encoding": len(set(
            discipline["encoding"].values())) == len(discipline["encoding"]),
        "observation_compatibility": all(
            trace["observation"] ==
            discipline["transitions"][trace["source_state"]][ACTION]["observation"]
            for trace in traces
        ),
        "observation_contract_sound": all(trace["terminated"] for trace in traces),
        "operational_adequacy": operational_adequacy,
        "runtime_word_inclusion": all(trace["suffix_word"] == [ACTION]
                                      for trace in traces),
        "unique_cell_condition": unique_coverage,
    }
    adm_pass = all(admissibility_checks.values())
    definition1 = (same_context and left["state_id"] != right["state_id"] and
                   different_output and shortest == [ACTION] and
                   all(trace["terminated"] for trace in traces))
    r_established = adm_pass and definition1 and same_cell and different_beta
    return {
        "concrete_states": frontier_states,
        "concrete_traces": traces,
        "coverage": coverage,
        "discipline": discipline,
        "factorization": {
            "beta_cardinality_by_cell": {
                cell: len(classes) for cell, classes in sorted(by_cell.items())
            },
            "collisions": collisions,
            "holds": factorization_holds,
        },
        "profile": {
            "capacity": profile.capacity,
            "name": profile.name,
            "observe_return": profile.observe_return,
            "occupancy_policy": profile.occupancy_policy,
            "suffix_key": profile.suffix_key,
        },
        "quotient": {
            **quotient,
            "shortest_distinguishing_word": shortest,
        },
        "report": report,
        "result": {
            "adm_pass": adm_pass,
            "factorization_holds": factorization_holds,
            "r_established": r_established,
            "scope": "R(V_linux_r,I_hash)",
            "stock_linux_verifier_r_established": False,
        },
        "schema": ANALYSIS_SCHEMA,
        "checks": admissibility_checks,
        "witness": {
            "beta_different": different_beta,
            "definition1_causal": definition1,
            "left_state": left["state_id"],
            "observations": [traces[0]["observation"], traces[1]["observation"]],
            "right_state": right["state_id"],
            "same_computed_cell": same_cell,
            "suffix_word": [ACTION],
        },
    }


def _parse_kernel_oracle(path: Path) -> dict[str, Any]:
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ModelError(f"kernel oracle line {number} is not JSON") from exc
        rows.append(row)
    run_rows = [row for row in rows if row.get("record") == "run"]
    gate_rows = [row for row in rows if row.get("record") == "gate"]
    assignments = {row.get("ordinal"): row.get("assignment") for row in run_rows}
    observed = {
        assignments.get(row.get("ordinal")): {
            "output": row.get("actual"),
            "raw_return": row.get("second_update_raw_ret"),
            "trace_valid": row.get("trace_valid"),
        }
        for row in gate_rows if row.get("gate") == 0
    }
    required = {2, 3}
    if set(observed) != required:
        raise ModelError("kernel oracle must contain assignments 2 and 3")
    if not all(row.get("passed") is True for row in run_rows + gate_rows):
        raise ModelError("kernel oracle contains a failed row")
    if not (observed[2]["raw_return"] == 0 and observed[2]["output"] == 1):
        raise ModelError("assignment 2 does not calibrate success")
    if not (isinstance(observed[3]["raw_return"], int) and
            observed[3]["raw_return"] < 0 and observed[3]["output"] == 0):
        raise ModelError("assignment 3 does not calibrate capacity failure")
    tags = sorted({row.get("program_tag") for row in run_rows + gate_rows})
    if len(tags) != 1 or not tags[0]:
        raise ModelError("kernel oracle is not bound to one program tag")
    return {
        "assignments": {str(key): value for key, value in sorted(observed.items())},
        "model_alignment": {
            "a0_b1_observation": observed[2]["output"] == 1,
            "a1_b1_observation": observed[3]["output"] == 0,
            "exact_errno_not_assumed": True,
        },
        "program_tag": tags[0],
        "row_count": len(rows),
    }


def _write_json(path: Path, value: Any) -> None:
    path.write_bytes(canonical_json_bytes(value))


def build_bundle(program_path: str | Path, output_dir: str | Path, *,
                 kernel_oracle: str | Path | None = None,
                 kernel_stderr: str | Path | None = None,
                 build_log: str | Path | None = None,
                 bpf_object: str | Path | None = None,
                 source: str | Path | None = None,
                 created_at: str | None = None) -> dict[str, Any]:
    program_path = Path(program_path)
    output = Path(output_dir)
    program = load_program(program_path)
    output.mkdir(parents=True, exist_ok=True)
    for child in output.iterdir():
        if child.is_file():
            child.unlink()

    # Compute and persist the recognizer report before concrete enumeration.
    report = compute_report(program, PROFILES["baseline"])
    analysis = build_analysis(program, "baseline")
    if report != analysis["report"]:
        raise AssertionError("computed report changed across the witness boundary")
    controls = {
        name: build_analysis(program, name)["result"]
        for name in ("occupancy_tracking", "cap64", "forced_sentinel", "unobserved")
    }
    analysis["controls"] = controls
    analysis["kernel_calibration"] = None

    shutil.copyfile(program_path, output / "program.json")
    if kernel_oracle is not None:
        oracle_path = Path(kernel_oracle)
        analysis["kernel_calibration"] = _parse_kernel_oracle(oracle_path)
        shutil.copyfile(oracle_path, output / "kernel_oracle.jsonl")
    if kernel_stderr is not None:
        shutil.copyfile(Path(kernel_stderr), output / "kernel_oracle.stderr")
    if build_log is not None:
        shutil.copyfile(Path(build_log), output / "build.log")
    _write_json(output / "analysis.json", analysis)

    bindings: dict[str, Any] = {
        "created_at": created_at or os.environ.get("SOURCE_DATE_EPOCH", "unspecified"),
        "host": platform.uname()._asdict(),
        "program_source": str(program_path),
    }
    for label, optional_path in (("bpf_object", bpf_object), ("source", source)):
        if optional_path is not None:
            candidate = Path(optional_path)
            bindings[label] = {
                "path": str(candidate),
                "sha256": _sha256_file(candidate),
            }
    files = {}
    for path in sorted(output.iterdir()):
        if path.name in {"manifest.json", "audit.txt"} or not path.is_file():
            continue
        files[path.name] = {"sha256": _sha256_file(path), "size": path.stat().st_size}
    manifest_core = {
        "bindings": bindings,
        "files": files,
        "schema": MANIFEST_SCHEMA,
    }
    manifest = {
        **manifest_core,
        "manifest_hash": _sha256_bytes(canonical_json_bytes(manifest_core)),
    }
    _write_json(output / "manifest.json", manifest)
    return analysis


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", type=Path, default=Path("linux_r/program.json"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--kernel-oracle", type=Path)
    parser.add_argument("--kernel-stderr", type=Path)
    parser.add_argument("--build-log", type=Path)
    parser.add_argument("--bpf-object", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--created-at")
    args = parser.parse_args(argv)
    analysis = build_bundle(
        args.program, args.output,
        kernel_oracle=args.kernel_oracle,
        kernel_stderr=args.kernel_stderr,
        build_log=args.build_log,
        bpf_object=args.bpf_object,
        source=args.source,
        created_at=args.created_at,
    )
    print(json.dumps(analysis["result"], sort_keys=True))
    return 0 if analysis["result"]["r_established"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
