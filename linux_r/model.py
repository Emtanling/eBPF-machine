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
import copy
import hashlib
import json
import os
import platform
import shutil
import struct
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


PROGRAM_SCHEMA = "linux-r-program-v1"
ANALYSIS_SCHEMA = "linux-r-analysis-v1"
MANIFEST_SCHEMA = "linux-r-manifest-v1"
REPORT_SCHEMA = "linux-r-computed-report-v1"
DERIVATION_SCHEMA = "linux-r-report-derivation-v1"
DOMAIN_VERSION = "occ-join-v1"
INSTANCE_ID = "M_linux_r_aux_v1"
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
    if program.get("source_binding") != {
        "artifact": "wm_circuit", "macro": "NAND_GATE_OBS",
        "source": "src/wm.bpf.c",
    }:
        raise ModelError("source binding is not the canonical wm_circuit gate slice")


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


def _execute_encoded_action(phase: str, keys: frozenset[str],
                            profile: Profile) -> dict[str, Any] | None:
    """Partial I_hash step for the encoded post-frontier program action.

    The helper service itself is callable in many contexts, but the encoded
    operation of this fixed program exists only while its program counter is
    at the declared frontier.  After that one instruction and observation the
    program is terminal, so a second encoded action is undefined.
    """
    if phase != "frontier":
        return None
    next_keys, raw_return = update_any(keys, profile.suffix_key,
                                       profile.capacity)
    return {
        "next_keys": next_keys,
        "next_phase": "terminal",
        "observation": _observe(raw_return, profile.observe_return),
        "raw_return_class": raw_return,
        "return_class": _return_class(raw_return),
    }


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


def _effective_program(program: dict[str, Any], profile: Profile) -> dict[str, Any]:
    """Return the explicitly declared program/contract used by an ablation.

    Controls that change capacity, suffix selection, or observation are not
    silently evaluated as the baseline P.  They receive their own canonical
    effective program and therefore their own program hash.  Exact-occupancy
    tracking changes only the report domain, so its program remains identical
    while its analysis-configuration hash differs.
    """
    effective = copy.deepcopy(program)
    if profile.name == "cap64":
        effective["map"]["capacity"] = 64
    elif profile.name == "forced_sentinel":
        effective["operations"][4]["one_key"] = "S"
    elif profile.name == "unobserved":
        effective["operations"][5]["expression"] = "unit"
    return effective


def _recognize_effective(program: dict[str, Any], profile: Profile) -> dict[str, Any]:
    """Run the safety recognizer on the declared effective program."""
    operations = program.get("operations") if isinstance(program, dict) else None
    map_spec = program.get("map") if isinstance(program, dict) else None
    checks = {
        "bounded_operation_sequence": (
            isinstance(operations, list) and len(operations) == 6 and
            [item.get("op") for item in operations if isinstance(item, dict)] ==
            ["clear", "update", "update_selected", "frontier",
             "update_selected", "observe"]
        ),
        "declared_scope_safe": program.get("scope") == {
            "concurrency": "serialized", "interference": "none", "value": 1
        } if isinstance(program, dict) else False,
        "keys_and_flags_valid": (
            isinstance(operations, list) and len(operations) == 6 and
            operations[0].get("keys") == list(KEYS) and
            operations[1].get("key") == "S" and
            operations[1].get("flag") == "BPF_NOEXIST" and
            operations[2].get("selector") == "a" and
            operations[2].get("zero_key") == "S" and
            operations[2].get("one_key") == "A" and
            operations[2].get("flag") == "BPF_ANY" and
            operations[4].get("selector") == "b" and
            operations[4].get("zero_key") == "S" and
            operations[4].get("one_key") == profile.suffix_key and
            operations[4].get("flag") == "BPF_ANY"
        ),
        "map_contract_safe": (
            isinstance(map_spec, dict) and
            map_spec.get("capacity") == profile.capacity and
            map_spec.get("key_universe") == list(KEYS) and
            map_spec.get("map_type") == "BPF_MAP_TYPE_HASH" and
            map_spec.get("non_evicting") is True and
            map_spec.get("update_flag") == "BPF_ANY" and
            isinstance(map_spec.get("capacity"), int) and
            map_spec["capacity"] > 0
        ),
        "observer_declared": (
            isinstance(operations, list) and len(operations) == 6 and
            operations[5].get("expression") == (
                "last_return_is_success" if profile.observe_return else "unit"
            )
        ),
        "schema_and_identity": (
            isinstance(program, dict) and program.get("schema") == PROGRAM_SCHEMA and
            program.get("recognizer") == "V_linux_r" and
            program.get("runtime") == "I_hash" and
            program.get("symbolic_inputs") == {"a": [0, 1], "b": [1]} and
            program.get("source_binding") == {
                "artifact": "wm_circuit", "macro": "NAND_GATE_OBS",
                "source": "src/wm.bpf.c",
            }
        ),
        "frontier_declared": (
            isinstance(operations, list) and len(operations) == 6 and
            operations[3].get("id") == FRONTIER
        ),
    }
    return {
        "accepted": all(checks.values()),
        "checks": checks,
        "recognizer": "V_linux_r",
        "safety_property": (
            "all bounded service operations use a valid non-evicting HASH "
            "reference, in-domain keys/value, and valid update flags"
        ),
    }


def _prefix_certificate(input_a: int, profile: Profile) -> dict[str, Any]:
    keys: frozenset[str] = frozenset()
    steps = [{"after_keys": [], "before_keys": [], "op": "clear(S,A,B)",
              "return_class": "unit"}]
    before = keys
    keys, setup_ret = update_any(keys, "S", profile.capacity)
    steps.append({"after_keys": sorted(keys), "before_keys": sorted(before),
                  "op": "update_noexist(S)",
                  "return_class": _return_class(setup_ret)})
    first_key = "S" if input_a == 0 else "A"
    before = keys
    keys, first_ret = update_any(keys, first_key, profile.capacity)
    steps.append({"after_keys": sorted(keys), "before_keys": sorted(before),
                  "op": f"update_any({first_key})",
                  "return_class": _return_class(first_ret)})
    if _return_class(setup_ret) != "ok" or _return_class(first_ret) != "ok":
        raise AssertionError("canonical prefix must succeed")
    return {
        "final_keys": sorted(keys),
        "frontier": FRONTIER,
        "initial_keys": [],
        "input_a": input_a,
        "steps": steps,
    }


def _frontier_concrete_states(profile: Profile) -> list[dict[str, Any]]:
    states: list[dict[str, Any]] = []
    for input_a in (0, 1):
        certificate = _prefix_certificate(input_a, profile)
        keys = frozenset(certificate["final_keys"])
        first_key = "S" if input_a == 0 else "A"
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


def _enumerate_occupancies(occupancy: dict[str, Any], capacity: int) -> list[frozenset[str]]:
    must = set(occupancy["must_contain"])
    allowed = set(occupancy["may_contain"])
    low, high = occupancy["min_size"], occupancy["max_size"]
    possible = []
    for mask in range(1 << len(KEYS)):
        keys = frozenset(KEYS[index] for index in range(len(KEYS))
                         if mask & (1 << index))
        if not must.issubset(keys) or not keys.issubset(allowed):
            continue
        if not low <= len(keys) <= min(high, capacity):
            continue
        if (occupancy["exact_key_set"] != "not-tracked" and
                sorted(keys) != occupancy["exact_key_set"]):
            continue
        possible.append(keys)
    return possible


def _occupancy_contains(occupancy: dict[str, Any], keys: frozenset[str],
                        capacity: int) -> bool:
    return keys in _enumerate_occupancies(occupancy, capacity)


def _abstract_update_summary(occupancy: dict[str, Any], key: str,
                             profile: Profile) -> dict[str, Any]:
    """Sound symbolic transformer over must/may/cardinality occupancy facts."""
    must = set(occupancy["must_contain"])
    may = set(occupancy["may_contain"])
    low, high = occupancy["min_size"], occupancy["max_size"]
    exact = occupancy["exact_key_set"]
    if exact != "not-tracked":
        next_keys, raw_return = update_any(frozenset(exact), key, profile.capacity)
        returns = [_return_class(raw_return)]
        post = {
            "exact_key_set": sorted(next_keys), "max_size": len(next_keys),
            "may_contain": sorted(next_keys), "min_size": len(next_keys),
            "must_contain": sorted(next_keys),
        }
    elif key in must:
        returns = ["ok"]
        post = copy.deepcopy(occupancy)
    elif key not in may and high < profile.capacity:
        returns = ["ok"]
        post = {
            "exact_key_set": "not-tracked",
            "max_size": high + 1,
            "may_contain": sorted(may | {key}),
            "min_size": low + 1,
            "must_contain": sorted(must | {key}),
        }
    elif key not in may and low >= profile.capacity:
        returns = ["fail"]
        post = copy.deepcopy(occupancy)
    else:
        returns = ["fail", "ok"] if high >= profile.capacity else ["ok"]
        post_low = low
        if key not in may:
            post_low = min(profile.capacity, low + 1)
        post = {
            "exact_key_set": "not-tracked",
            "max_size": min(profile.capacity, high + (0 if key in must else 1)),
            "may_contain": sorted(may | {key}),
            "min_size": post_low,
            "must_contain": sorted(must),
        }
    observations = sorted({(int(result == "ok")
                            if profile.observe_return else "unit")
                           for result in returns}, key=str)
    return {
        "possible_observations": observations,
        "possible_return_classes": sorted(returns),
        "post_occupancy": post,
    }


def _possible_suffix(cell: dict[str, Any], profile: Profile) -> dict[str, Any]:
    occupancy = cell["abstract_state"]["occupancy"]
    summary = _abstract_update_summary(occupancy, profile.suffix_key, profile)
    return {
        **summary,
        "gamma_cardinality": len(_enumerate_occupancies(occupancy,
                                                         profile.capacity)),
    }


def _exhaustive_transfer_validation(profile: Profile,
                                    cells: list[dict[str, Any]]) -> dict[str, Any]:
    """Check domain/action returns and the actual report-cell successors.

    The 21 domain/action cases establish return-class containment for every
    legal occupancy and key.  Separately, every concretization of each actual
    frontier report cell is checked for both return containment and abstract
    post-occupancy containment.
    """
    top = {
        "exact_key_set": "not-tracked", "max_size": min(len(KEYS), profile.capacity),
        "may_contain": list(KEYS), "min_size": 0, "must_contain": [],
    }
    valid_occupancies = _enumerate_occupancies(top, profile.capacity)
    abstract_returns = {
        key: _abstract_update_summary(top, key, profile)["possible_return_classes"]
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
                    "kind": "domain-return", "abstract_returns": abstract_returns[key],
                    "concrete_return": concrete, "key": key, "keys": sorted(keys),
                })
    cell_checked = 0
    for cell in cells:
        occupancy = cell["abstract_state"]["occupancy"]
        persisted = cell["suffix_abstract_transfer"]
        symbolic = _abstract_update_summary(occupancy, profile.suffix_key, profile)
        if any(persisted.get(key) != value for key, value in symbolic.items()):
            violations.append({"cell_id": cell["cell_id"],
                               "kind": "persisted-symbolic-mismatch"})
        for keys in _enumerate_occupancies(occupancy, profile.capacity):
            cell_checked += 1
            next_keys, raw = update_any(keys, profile.suffix_key, profile.capacity)
            concrete_return = _return_class(raw)
            if concrete_return not in symbolic["possible_return_classes"]:
                violations.append({"cell_id": cell["cell_id"],
                                   "kind": "cell-return", "keys": sorted(keys)})
            if not _occupancy_contains(symbolic["post_occupancy"], next_keys,
                                       profile.capacity):
                violations.append({"cell_id": cell["cell_id"],
                                   "kind": "cell-post", "keys": sorted(keys),
                                   "post_keys": sorted(next_keys)})
    return {
        "abstract_returns": abstract_returns,
        "cell_checked_cases": cell_checked,
        "checked_cases": checked,
        "method": "symbolic-transform-plus-exhaustive-concretization",
        "violations": violations,
    }


def _compute_report_components(
        program: dict[str, Any], profile: Profile
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run V_linux_r and separate its interface from derivation provenance."""
    validate_program(program)
    effective_program = _effective_program(program, profile)
    recognizer_verdict = _recognize_effective(effective_program, profile)
    if not recognizer_verdict["accepted"]:
        raise ModelError("V_linux_r rejected the effective program")
    base_program_hash = _sha256_bytes(canonical_json_bytes(program))
    program_hash = _sha256_bytes(canonical_json_bytes(effective_program))
    analysis_config = {
        "occupancy_policy": profile.occupancy_policy,
        "observe_return": profile.observe_return,
        "program_hash": program_hash,
        "suffix_key": profile.suffix_key,
    }
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
    derivation_core = {
        "analysis_config_hash": _sha256_bytes(canonical_json_bytes(analysis_config)),
        "base_program_hash": base_program_hash,
        "computed_trace": [sentinel, branch_zero, branch_one],
        "frontier": FRONTIER,
        "profile": profile.name,
        "program_hash": program_hash,
        "schema": DERIVATION_SCHEMA,
    }
    derivation = {
        **derivation_core,
        "derivation_hash": _sha256_bytes(canonical_json_bytes(derivation_core)),
    }
    report_core = {
        "analysis_order": "computed-before-concrete-witness-enumeration",
        "analysis_config_hash": derivation["analysis_config_hash"],
        "base_program_hash": base_program_hash,
        "derivation_ref": {
            "derivation_hash": derivation["derivation_hash"],
            "path": "derivation.json",
            "schema": DERIVATION_SCHEMA,
        },
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
        "recognizer_verdict": recognizer_verdict,
        "report_interface": {
            "computed_trace_is_label_set": False,
            "derivation_provenance": "derivation.json",
            "label_set_field": "report_cells",
            "name": "Report_V_linux_r(P,frontier)",
        },
        "report_cells": report_cells,
        "schema": REPORT_SCHEMA,
        "transfer_validation": _exhaustive_transfer_validation(profile,
                                                                 report_cells),
    }
    report = {
        **report_core,
        "report_hash": _sha256_bytes(canonical_json_bytes(report_core)),
    }
    return report, derivation


def compute_report(program: dict[str, Any], profile: Profile) -> dict[str, Any]:
    """Return only the actual report interface produced by V_linux_r.

    The abstract worklist trace is a separately hashed derivation object and
    is deliberately not part of ``Report_V(P,l)``'s label set.
    """
    report, _ = _compute_report_components(program, profile)
    return report


def gamma_contains(cell: dict[str, Any], state: dict[str, Any]) -> bool:
    gamma = cell["concretization"]
    if gamma != _gamma_for_payload(cell["abstract_state"]):
        return False
    keys = set(state["keys"])
    if state["phase"] != gamma["phase_equals"]:
        return False
    if state["context"] != gamma["context_equals"]:
        return False
    if (gamma["map_type_equals"] != "BPF_MAP_TYPE_HASH" or
            state["context"].get("map_type") != gamma["map_type_equals"] or
            state["context"].get("capacity") != gamma["capacity_equals"]):
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
        concrete_step = _execute_encoded_action("frontier", keys, profile)
        if concrete_step is None:
            raise AssertionError("frontier action must be defined")
        next_keys = concrete_step["next_keys"]
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
                "observation": concrete_step["observation"],
                "raw_return_class": concrete_step["raw_return_class"],
                "return_class": concrete_step["return_class"],
            }
        }
    for state_id, state in states.items():
        if state["phase"] == "terminal":
            transitions[state_id] = {ACTION: {"defined": False}}
    concrete_region = [
        {"context": state["context"], "keys": state["keys"],
         "phase": state["phase"], "state_id": state_id}
        for state_id, state in sorted(states.items())
    ]
    return {
        "action_alphabet": [ACTION],
        "concrete_region": concrete_region,
        "encoding": {
            ACTION: "bpf_map_update_elem(G0,suffix_key,one,BPF_ANY);observe(ret==0)"
        },
        "name": "D_R_linux_hash_v1",
        "observer": "identity-on-complete-output-word",
        "output_alphabet": ([0, 1] if profile.observe_return else ["unit"]),
        "runtime_action_defined_when": "phase=frontier",
        "state_projection": "s_D(phase,K,context)=phase:sorted(K)",
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
        concrete_step = _execute_encoded_action("frontier", keys, profile)
        if concrete_step is None:
            raise AssertionError("frontier action must be defined")
        next_keys = concrete_step["next_keys"]
        traces.append({
            "context": state["context"],
            "input_a": state["input_a"],
            "observation": concrete_step["observation"],
            "post_keys": sorted(next_keys),
            "pre_keys": sorted(keys),
            "raw_return_class": concrete_step["raw_return_class"],
            "return_class": concrete_step["return_class"],
            "source_state": state["state_id"],
            "suffix_word": [ACTION],
            "terminated": True,
        })
    return traces


def _operationally_adequate(discipline: dict[str, Any], profile: Profile) -> bool:
    for state_id, state in discipline["states"].items():
        transition = discipline["transitions"][state_id][ACTION]
        concrete = _execute_encoded_action(
            state["phase"], frozenset(state["keys"]), profile
        )
        if (concrete is None) != (not transition["defined"]):
            return False
        if concrete is None:
            continue
        if transition["next_state"] != _state_id(
                concrete["next_phase"], concrete["next_keys"]):
            return False
        if transition["observation"] != concrete["observation"]:
            return False
        if transition["return_class"] != concrete["return_class"]:
            return False
    return True


def _common_words(discipline: dict[str, Any], fiber: list[str]) -> list[list[str]]:
    """Enumerate all jointly enabled words of the finite partial discipline."""
    words: list[list[str]] = [[]]
    queue: deque[tuple[tuple[str, ...], list[str]]] = deque(
        [(tuple(fiber), [])]
    )
    seen = {(tuple(fiber), tuple())}
    while queue:
        states, prefix = queue.popleft()
        for action in discipline["action_alphabet"]:
            transitions = [discipline["transitions"][state][action]
                           for state in states]
            if not all(transition["defined"] for transition in transitions):
                continue
            word = [*prefix, action]
            words.append(word)
            successors = tuple(transition["next_state"]
                               for transition in transitions)
            marker = (successors, tuple(word))
            if marker not in seen:
                seen.add(marker)
                queue.append((successors, word))
    return words


def _word_obligations(frontier_states: list[dict[str, Any]],
                      discipline: dict[str, Any], profile: Profile) -> list[dict[str, Any]]:
    words = _common_words(discipline,
                          [state["state_id"] for state in frontier_states])
    obligations = []
    for word in words:
        outcomes = []
        for concrete in frontier_states:
            concrete_keys = frozenset(concrete["keys"])
            concrete_phase = "frontier"
            discipline_state = concrete["state_id"]
            concrete_outputs: list[int | str] = []
            discipline_outputs: list[int | str] = []
            concrete_defined = True
            discipline_defined = True
            for action in word:
                if action != ACTION:
                    concrete_defined = False
                    break
                if not discipline["transitions"][discipline_state][action]["defined"]:
                    discipline_defined = False
                    break
                concrete_step = _execute_encoded_action(
                    concrete_phase, concrete_keys, profile
                )
                if concrete_step is None:
                    concrete_defined = False
                    break
                concrete_keys = concrete_step["next_keys"]
                concrete_phase = concrete_step["next_phase"]
                concrete_outputs.append(concrete_step["observation"])
                transition = discipline["transitions"][discipline_state][action]
                discipline_outputs.append(transition["observation"])
                discipline_state = transition["next_state"]
            outcomes.append({
                "concrete_defined": concrete_defined,
                "concrete_outputs": concrete_outputs,
                "context": concrete["context"],
                "discipline_defined": discipline_defined,
                "discipline_outputs": discipline_outputs,
                "final_concrete_keys": sorted(concrete_keys),
                "final_concrete_phase": concrete_phase,
                "final_discipline_state": discipline_state,
                "rho_obs": concrete["keys"],
                "slice_context": {
                    "program_phase": "frontier",
                    "service_context": concrete["context"],
                },
                "state_id": concrete["state_id"],
            })
        runtime_included = all(outcome["concrete_defined"] for outcome in outcomes)
        observer_compatible = all(
            outcome["concrete_outputs"] == outcome["discipline_outputs"]
            for outcome in outcomes
        )
        contexts = [canonical_json_bytes(outcome["slice_context"])
                    for outcome in outcomes]
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
            "common_context": len(set(contexts)) == 1,
            "encoded_word": [discipline["encoding"][action] for action in word],
            "observer_compatible": observer_compatible,
            "outcomes": outcomes,
            "runtime_included": runtime_included,
            "soundness_cases": soundness_cases,
            "sound_observation_contract": (
                runtime_included and observer_compatible and
                all(outcome["discipline_defined"] for outcome in outcomes) and
                all(case["holds"] for case in soundness_cases)
            ),
            "word": word,
        })
    return obligations


def _observation_contract(profile: Profile,
                          frontier_states: list[dict[str, Any]],
                          common_words: list[list[str]]) -> dict[str, Any]:
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
                "service_context": _context(profile),
            }],
            "quantification": "singleton declared environment",
        },
        "name": "K_obs_linux_r_v1",
        "slice": {
            "fields": ["program_phase", "service_context"],
            "predeclared_for_words": common_words,
            "projection": "all non-K fields read by the encoded suffix or observer",
        },
        "soundness_domain": {
            "domain_identity": "Reach_I_hash(P,frontier)=F",
            "fiber_states": [state["state_id"] for state in frontier_states],
            "ordered_pairs_per_word": len(frontier_states) ** 2,
            "words": common_words,
        },
        "trace_observer": {
            "name": "Obs",
            "projection": "ordered list of success bits; unit when unobserved",
        },
    }


def _build_analysis_from_report(program: dict[str, Any], profile: Profile,
                                report: dict[str, Any]) -> dict[str, Any]:
    """Build witness obligations while treating the computed report as input."""
    frontier_states = _frontier_concrete_states(profile)
    reachability = [_prefix_certificate(input_a, profile) for input_a in (0, 1)]
    discipline = _build_discipline(frontier_states, profile)
    quotient = _partition_refinement(discipline)
    traces = _concrete_traces(frontier_states, profile)
    word_obligations = _word_obligations(frontier_states, discipline, profile)
    common_words = [item["word"] for item in word_obligations]
    observation_contract = _observation_contract(
        profile, frontier_states, common_words
    )
    instance_id = (INSTANCE_ID if profile.name == "baseline" else
                   f"{INSTANCE_ID}__control_{profile.name}")

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
    different_rho = left["keys"] != right["keys"]
    different_output = traces[0]["observation"] != traces[1]["observation"]
    operational_adequacy = _operationally_adequate(discipline, profile)
    reachability_valid = all(
        certificate["final_keys"] == state["keys"] and
        certificate["frontier"] == state["phase"] and
        certificate["input_a"] == state["input_a"] and
        all(step["return_class"] in {"unit", "ok"}
            for step in certificate["steps"])
        for certificate, state in zip(reachability, frontier_states)
    )
    reachable_ids = {
        _state_id("frontier", certificate["final_keys"])
        for certificate in reachability
    }
    fiber_equals_reach = (
        reachable_ids == {state["state_id"] for state in frontier_states} and
        {certificate["input_a"] for certificate in reachability} == {0, 1}
    )
    gamma_consistent = all(
        cell["concretization"] == _gamma_for_payload(cell["abstract_state"])
        for cell in report["report_cells"]
    )
    admissibility_checks = {
        "accepted_program": report["recognizer_verdict"]["accepted"],
        "abstract_transfer_sound": not report["transfer_validation"]["violations"],
        "common_context": (same_context and all(
            obligation["common_context"] for obligation in word_obligations
        )),
        "fiber_equals_reach": fiber_equals_reach,
        "fiber_nonempty_and_reachable": (
            bool(frontier_states) and reachability_valid and fiber_equals_reach
        ),
        "gamma_declared_consistently": gamma_consistent,
        "injective_operation_encoding": len(set(
            discipline["encoding"].values())) == len(discipline["encoding"]),
        "observation_compatibility": all(
            obligation["observer_compatible"] for obligation in word_obligations
        ),
        "observation_contract_sound": all(
            obligation["sound_observation_contract"]
            for obligation in word_obligations
        ),
        "observation_contract_declared": (
            observation_contract["candidate_state_projection"]["name"] ==
            "rho_obs" and
            observation_contract["soundness_domain"]["words"] == common_words
        ),
        "operational_adequacy": operational_adequacy,
        "runtime_word_inclusion": (
            common_words == [[], [ACTION]] and
            all(obligation["runtime_included"] for obligation in word_obligations)
        ),
        "unique_cell_condition": unique_coverage,
    }
    adm_pass = all(admissibility_checks.values())
    definition1 = (same_context and different_rho and
                   different_output and shortest == [ACTION] and
                   all(trace["terminated"] for trace in traces))
    r_established = adm_pass and definition1 and same_cell and different_beta
    return {
        "concrete_states": frontier_states,
        "concrete_traces": traces,
        "coverage": coverage,
        "discipline": discipline,
        "effective_program": _effective_program(program, profile),
        "factorization": {
            "beta_cardinality_by_cell": {
                cell: len(classes) for cell, classes in sorted(by_cell.items())
            },
            "collisions": collisions,
            "holds": factorization_holds,
        },
        "formal_instance": {
            "D": discipline["name"],
            "F": [state["state_id"] for state in frontier_states],
            "I": "I_hash",
            "K_obs": observation_contract["name"],
            "P": report["program_hash"],
            "Report": report["report_interface"]["name"],
            "V": "V_linux_r",
            "frontier": FRONTIER,
            "id": instance_id,
            "report_hash": report["report_hash"],
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
        "reachability_certificates": reachability,
        "reachability_claim": {
            "assignments_enumerated": 2,
            "deterministic_frontier_state_per_assignment": True,
            "fiber_equals_reach": fiber_equals_reach,
            "fixed_environment_count": 1,
            "no_unenumerated_input_or_environment_choices": True,
            "proof_method": "exhaustive symbolic-input enumeration",
            "reachable_state_ids": sorted(reachable_ids),
            "symbolic_input_domain": {"a": [0, 1], "b": [1]},
        },
        "common_words": common_words,
        "word_obligations": word_obligations,
        "observation_contract": observation_contract,
        "result": {
            "adm_pass": adm_pass,
            "factorization_holds": factorization_holds,
            "formal_claim": f"R({instance_id})",
            "instance_id": instance_id,
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
            "rho_obs_different": different_rho,
            "right_state": right["state_id"],
            "same_computed_cell": same_cell,
            "suffix_word": [ACTION],
            "tagged_word": {
                "D": discipline["name"],
                "F": [left["state_id"], right["state_id"]],
                "P": report["program_hash"],
                "a_sharp": (cell_for_state[left["state_id"]]
                            if same_cell else None),
                "frontier": FRONTIER,
                "w": [ACTION],
            },
        },
    }


def build_analysis(program: dict[str, Any], profile_name: str = "baseline") -> dict[str, Any]:
    validate_program(program)
    try:
        profile = PROFILES[profile_name]
    except KeyError as exc:
        raise ModelError(f"unknown profile: {profile_name}") from exc
    report, derivation = _compute_report_components(program, profile)
    analysis = _build_analysis_from_report(program, profile, report)
    analysis["derivation_provenance"] = derivation
    return analysis


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
    if len(rows) != 4 or len(run_rows) != 2 or len(gate_rows) != 2:
        raise ModelError("kernel oracle must contain exactly two run/gate pairs")
    if {row.get("ordinal") for row in run_rows} != {0, 1} or \
            {row.get("ordinal") for row in gate_rows} != {0, 1}:
        raise ModelError("kernel oracle ordinals are not a unique 0/1 pair")
    if any(row.get("circuit") != "nand" or row.get("kind") != "fixed_boundary"
           for row in rows):
        raise ModelError("kernel oracle is not the fixed NAND calibration")
    if any(row.get("variant_id") != 1 for row in rows):
        raise ModelError("kernel oracle is not the baseline capacity mechanism")
    if any(row.get("gate") != 0 or row.get("src0") != 2 or
           row.get("src1") != 3 or row.get("dst") != 4 or
           row.get("trace_valid") is not True
           for row in gate_rows):
        raise ModelError("kernel oracle gate trace is incomplete")
    if any(row.get("input_count") != 2 or row.get("gate_count") != 1 or
           row.get("gate_cap") != 2 or row.get("status") != 0 or
           row.get("executed") != 1 or row.get("trace_passed") is not True
           or row.get("failing_gate") != 0xffffffff or
           row.get("gate_error_count") != 0
           for row in run_rows):
        raise ModelError("kernel oracle run metadata is inconsistent")
    by_ordinal_run = {row["ordinal"]: row for row in run_rows}
    by_ordinal_gate = {row["ordinal"]: row for row in gate_rows}
    run_sequences = [by_ordinal_run[index].get("run_seq") for index in (0, 1)]
    if (not all(isinstance(value, int) and value > 0 for value in run_sequences) or
            run_sequences[0] >= run_sequences[1] or
            any(by_ordinal_gate[index].get("run_seq") != run_sequences[index]
                for index in (0, 1))):
        raise ModelError("kernel oracle run sequence is inconsistent")
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
    for assignment, expected in ((2, 1), (3, 0)):
        run = next(row for row in run_rows if row.get("assignment") == assignment)
        ordinal = run["ordinal"]
        gate = by_ordinal_gate[ordinal]
        if (run.get("logical_expected") != expected or
                run.get("variant_expected") != expected or
                run.get("actual") != expected or
                gate.get("expected") != expected or
                gate.get("actual") != expected):
            raise ModelError("kernel oracle run/gate values are inconsistent")
    if not (observed[2]["raw_return"] == 0 and observed[2]["output"] == 1):
        raise ModelError("assignment 2 does not calibrate success")
    if not (isinstance(observed[3]["raw_return"], int) and
            observed[3]["raw_return"] < 0 and observed[3]["output"] == 0):
        raise ModelError("assignment 3 does not calibrate capacity failure")
    tags = sorted({row.get("program_tag") for row in run_rows + gate_rows})
    program_ids = {row.get("program_id") for row in run_rows + gate_rows}
    if (len(tags) != 1 or not isinstance(tags[0], str) or len(tags[0]) != 16 or
            any(character not in "0123456789abcdef" for character in tags[0]) or
            len(program_ids) != 1 or not all(isinstance(value, int) and value > 0
                                             for value in program_ids)):
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


def _read_json_file(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ModelError(f"{path} must contain a JSON object")
    return value


def _require_regular_file(path: str | Path, label: str) -> Path:
    candidate = Path(path)
    if not candidate.is_file():
        raise ModelError(f"{label} is not a regular file: {candidate}")
    return candidate


def _validate_descriptor(path: Path) -> None:
    expected = b"WMC1 nand 2 1 5 1\n1 2 3 4\n4\n"
    if path.read_bytes() != expected:
        raise ModelError("kernel calibration descriptor is not canonical NAND WMC1")


def _require_tokens_in_order(text: str, tokens: list[str], label: str) -> None:
    cursor = 0
    for token in tokens:
        position = text.find(token, cursor)
        if position < 0:
            raise ModelError(f"{label} is missing ordered token: {token}")
        cursor = position + len(token)


def _elf_metadata(path: Path) -> dict[str, Any]:
    """Parse the bounded ELF64 header/section table needed by this bundle."""
    data = path.read_bytes()
    if (len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or
            data[5] not in (1, 2) or data[6] != 1):
        raise ModelError(f"{path} is not a supported ELF64 file")
    endian = "<" if data[5] == 1 else ">"
    fields = struct.unpack_from(endian + "16sHHIQQQIHHHHHH", data, 0)
    (_, elf_type, machine, version, _, _, section_offset, _, header_size,
     _, _, section_entry_size, section_count, string_index) = fields
    if (version != 1 or header_size != 64 or section_entry_size < 64 or
            section_count < 2 or string_index >= section_count):
        raise ModelError(f"{path} has an invalid ELF header")
    table_end = section_offset + section_entry_size * section_count
    if section_offset < header_size or table_end > len(data):
        raise ModelError(f"{path} has an out-of-range section table")
    sections = []
    for index in range(section_count):
        offset = section_offset + index * section_entry_size
        sections.append(struct.unpack_from(endian + "IIQQQQIIQQ", data, offset))
    string_header = sections[string_index]
    string_offset, string_size = string_header[4], string_header[5]
    if string_offset + string_size > len(data):
        raise ModelError(f"{path} has an out-of-range section-name table")
    strings = data[string_offset:string_offset + string_size]
    names = []
    for section in sections:
        name_offset = section[0]
        if name_offset >= len(strings):
            raise ModelError(f"{path} has an invalid section name")
        end = strings.find(b"\0", name_offset)
        if end < 0:
            raise ModelError(f"{path} has an unterminated section name")
        names.append(strings[name_offset:end].decode("ascii", errors="strict"))
        payload_offset, payload_size = section[4], section[5]
        if section[1] != 8 and payload_offset + payload_size > len(data):
            raise ModelError(f"{path} has an out-of-range section payload")
    return {"machine": machine, "section_names": names, "type": elf_type}


def _validate_binaries(bpf_object: Path, harness_binary: Path) -> None:
    bpf = _elf_metadata(bpf_object)
    if (bpf["type"] != 1 or bpf["machine"] != 247 or
            not {".maps", "license", "syscall", ".symtab"}.issubset(
                set(bpf["section_names"]))):
        raise ModelError("BPF object is not a relocatable EM_BPF wm_circuit object")
    harness = _elf_metadata(harness_binary)
    if (harness["type"] not in (2, 3) or harness["machine"] not in (62, 183) or
            not {".text", ".rodata", ".dynsym", ".dynamic"}.issubset(
                set(harness["section_names"]))):
        raise ModelError("userspace harness is not a supported Linux ELF executable")


def _validate_calibration_sources(source: Path, harness_source: Path,
                                  common_header: Path, makefile: Path) -> None:
    bpf_text = source.read_text(encoding="utf-8")
    marker = bpf_text.find("Capacity-saturation NAND")
    if marker < 0:
        raise ModelError("BPF source lacks the declared capacity-saturation slice")
    _require_tokens_in_order(
        bpf_text[marker:],
        [
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
        ],
        "BPF source",
    )
    harness_text = harness_source.read_text(encoding="utf-8")
    for token in (
        "read_image(", "bpf_prog_test_run_opts(", "map_get(trace_fd",
        "second_update_raw_ret", "trace_valid", "program_tag",
    ):
        if token not in harness_text:
            raise ModelError(
                f"userspace harness source is missing evidence token: {token}"
            )
    header_text = common_header.read_text(encoding="utf-8")
    for token in (
        "#define K_S 0u", "#define K_A 1u", "#define K_B 2u",
        "#define VM_ABI_VERSION       1u", "struct wm_gate_trace",
    ):
        if token not in header_text:
            raise ModelError(f"common header is missing ABI token: {token}")
    make_text = makefile.read_text(encoding="utf-8")
    for token in ("GATE_CAP ?= 2", "$(BUILD)/wm.bpf.o:",
                  "$(BUILD)/wm_vm_user:"):
        if token not in make_text:
            raise ModelError(f"Makefile is missing build token: {token}")


def _validate_snapshot_inputs(resolved: dict[str, Path], build_log: Path) -> None:
    expected_spec = {
        "gates": [{"args": ["a", "b"], "id": "out", "op": "nand"}],
        "inputs": ["a", "b"], "name": "nand", "outputs": ["out"],
    }
    try:
        if json.loads(resolved["nand.json"].read_text(encoding="utf-8")) != expected_spec:
            raise ModelError("NAND circuit source specification changed")
        text_requirements = {
            "vmlinux.h": ("struct task_struct", "typedef unsigned int __u32"),
            "run_kernel.sh": ("WM_VM_EMIT_GATES=1", "python3 -m linux_r.generate"),
            "circuit_tool.py": ("def compile_spec", "WMC1"),
            "linux_r_model.py": ("def compute_report", "def build_bundle"),
            "linux_r_audit.py": ("def audit_bundle", "def _expected_report"),
            "toolchain.txt": ("UNAME", "CLANG", "CC", "BPFTOOL", "LIBBPF"),
        }
        for name, tokens in text_requirements.items():
            text = resolved[name].read_text(encoding="utf-8")
            if not all(token in text for token in tokens):
                raise ModelError(f"{name} is missing snapshot evidence tokens")
        build_text = build_log.read_text(encoding="utf-8")
        if not all(token in build_text for token in (
                "wm.bpf.c", "-target bpf", "-DGATE_CAP=2", "wm_vm_user.c")):
            raise ModelError("build log does not contain both calibration build commands")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ModelError(f"cannot validate snapshot inputs: {exc}") from exc


def build_bundle(program_path: str | Path, output_dir: str | Path, *,
                 kernel_oracle: str | Path | None = None,
                 kernel_stderr: str | Path | None = None,
                 build_log: str | Path | None = None,
                 bpf_object: str | Path | None = None,
                 source: str | Path | None = None,
                 descriptor: str | Path | None = None,
                 harness_binary: str | Path | None = None,
                 harness_source: str | Path | None = None,
                 common_header: str | Path | None = None,
                 makefile: str | Path | None = None,
                 vmlinux_header: str | Path | None = None,
                 runner: str | Path | None = None,
                 circuit_spec: str | Path | None = None,
                 circuit_compiler: str | Path | None = None,
                 model_source: str | Path | None = None,
                 auditor_source: str | Path | None = None,
                 toolchain_log: str | Path | None = None,
                 created_at: str | None = None) -> dict[str, Any]:
    program_path = Path(program_path)
    output = Path(output_dir)
    program = load_program(program_path)
    output.mkdir(parents=True, exist_ok=True)
    for child in output.iterdir():
        if child.is_file():
            child.unlink()

    # Phase 1: compute, close, and hash the report before witness enumeration.
    report, derivation = _compute_report_components(
        program, PROFILES["baseline"]
    )
    _write_json(output / "derivation.json", derivation)
    _write_json(output / "report.json", report)
    persisted_derivation_sha256 = _sha256_file(output / "derivation.json")
    persisted_report_sha256 = _sha256_file(output / "report.json")
    persisted_derivation = _read_json_file(output / "derivation.json")
    persisted_report = _read_json_file(output / "report.json")

    # Phase 2: witness construction receives the closed report as an input and
    # has no API through which to alter the report producer.
    analysis = _build_analysis_from_report(program, PROFILES["baseline"],
                                           persisted_report)
    analysis.pop("report")
    analysis["report_ref"] = {
        "path": "report.json",
        "report_hash": report["report_hash"],
        "sha256": persisted_report_sha256,
    }
    analysis["derivation_ref"] = {
        "derivation_hash": persisted_derivation["derivation_hash"],
        "path": "derivation.json",
        "sha256": persisted_derivation_sha256,
    }
    controls = {}
    for name in ("occupancy_tracking", "cap64", "forced_sentinel", "unobserved"):
        control = build_analysis(program, name)
        controls[name] = {
            **control["result"],
            "analysis_config_hash": control["report"]["analysis_config_hash"],
            "effective_program": control["effective_program"],
            "program_hash": control["report"]["program_hash"],
        }
    analysis["controls"] = controls
    analysis["kernel_calibration"] = None

    shutil.copyfile(program_path, output / "program.json")
    if kernel_oracle is not None:
        required_artifacts = {
            "bpf_object": bpf_object,
            "source": source,
            "descriptor": descriptor,
            "harness_binary": harness_binary,
            "harness_source": harness_source,
            "common_header": common_header,
            "makefile": makefile,
            "vmlinux_header": vmlinux_header,
            "runner": runner,
            "circuit_spec": circuit_spec,
            "circuit_compiler": circuit_compiler,
            "model_source": model_source,
            "auditor_source": auditor_source,
            "toolchain_log": toolchain_log,
            "kernel_stderr": kernel_stderr,
            "build_log": build_log,
        }
        missing = sorted(label for label, value in required_artifacts.items()
                         if value is None)
        if missing:
            raise ModelError(
                "kernel calibration requires bound artifacts: " + ", ".join(missing)
            )
        oracle_path = Path(kernel_oracle)
        analysis["kernel_calibration"] = _parse_kernel_oracle(oracle_path)
        shutil.copyfile(oracle_path, output / "kernel_oracle.jsonl")
    if kernel_stderr is not None:
        shutil.copyfile(Path(kernel_stderr), output / "kernel_oracle.stderr")
    if build_log is not None:
        shutil.copyfile(Path(build_log), output / "build.log")
    artifact_sources = {
        "wm.bpf.o": (bpf_object, "BPF object"),
        "wm.bpf.c": (source, "BPF source"),
        "nand.wmc": (descriptor, "NAND descriptor"),
        "wm_vm_user": (harness_binary, "userspace harness"),
        "wm_vm_user.c": (harness_source, "userspace harness source"),
        "wm_common.h": (common_header, "common ABI header"),
        "Makefile": (makefile, "build recipe"),
        "vmlinux.h": (vmlinux_header, "kernel BTF-derived header"),
        "run_kernel.sh": (runner, "calibration runner"),
        "nand.json": (circuit_spec, "NAND circuit specification"),
        "circuit_tool.py": (circuit_compiler, "circuit descriptor compiler"),
        "linux_r_model.py": (model_source, "report generator source"),
        "linux_r_audit.py": (auditor_source, "independent auditor source"),
        "toolchain.txt": (toolchain_log, "toolchain snapshot"),
    }
    resolved: dict[str, Path] = {}
    for bundle_name, (candidate, label) in artifact_sources.items():
        if candidate is None:
            continue
        resolved[bundle_name] = _require_regular_file(candidate, label)
    if resolved:
        if {"wm.bpf.o", "wm_vm_user"}.issubset(resolved):
            _validate_binaries(resolved["wm.bpf.o"], resolved["wm_vm_user"])
        if "nand.wmc" in resolved:
            _validate_descriptor(resolved["nand.wmc"])
        source_names = {"wm.bpf.c", "wm_vm_user.c", "wm_common.h", "Makefile"}
        if source_names.issubset(resolved):
            _validate_calibration_sources(
                resolved["wm.bpf.c"], resolved["wm_vm_user.c"],
                resolved["wm_common.h"], resolved["Makefile"],
            )
        elif kernel_oracle is not None:
            raise ModelError("kernel calibration source bundle is incomplete")
        if kernel_oracle is not None:
            _validate_snapshot_inputs(
                resolved, _require_regular_file(build_log, "build log")
            )
        for bundle_name, candidate in resolved.items():
            shutil.copy2(candidate, output / bundle_name)
    _write_json(output / "analysis.json", analysis)
    if _sha256_file(output / "derivation.json") != persisted_derivation_sha256:
        raise AssertionError("persisted derivation changed during witness construction")
    if _sha256_file(output / "report.json") != persisted_report_sha256:
        raise AssertionError("persisted report changed during witness construction")

    bindings: dict[str, Any] = {
        "created_at": created_at or os.environ.get("SOURCE_DATE_EPOCH", "unspecified"),
        "host": platform.uname()._asdict(),
        "program_source": str(program_path),
    }
    for label, bundle_name in (
        ("bpf_object", "wm.bpf.o"),
        ("source", "wm.bpf.c"),
        ("descriptor", "nand.wmc"),
        ("harness_binary", "wm_vm_user"),
        ("harness_source", "wm_vm_user.c"),
        ("common_header", "wm_common.h"),
        ("makefile", "Makefile"),
        ("vmlinux_header", "vmlinux.h"),
        ("runner", "run_kernel.sh"),
        ("circuit_spec", "nand.json"),
        ("circuit_compiler", "circuit_tool.py"),
        ("model_source", "linux_r_model.py"),
        ("auditor_source", "linux_r_audit.py"),
        ("toolchain_log", "toolchain.txt"),
    ):
        candidate = output / bundle_name
        if candidate.is_file():
            bindings[label] = {
                "path": bundle_name,
                "sha256": _sha256_file(candidate),
            }
    files = {}
    for path in sorted(output.iterdir()):
        if path.name in {"manifest.json", "audit.txt"} or not path.is_file():
            continue
        metadata = path.stat()
        files[path.name] = {
            "mode": metadata.st_mode & 0o7777,
            "sha256": _sha256_file(path),
            "size": metadata.st_size,
        }
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
    parser.add_argument("--descriptor", type=Path)
    parser.add_argument("--harness-binary", type=Path)
    parser.add_argument("--harness-source", type=Path)
    parser.add_argument("--common-header", type=Path)
    parser.add_argument("--makefile", type=Path)
    parser.add_argument("--vmlinux-header", type=Path)
    parser.add_argument("--runner", type=Path)
    parser.add_argument("--circuit-spec", type=Path)
    parser.add_argument("--circuit-compiler", type=Path)
    parser.add_argument("--model-source", type=Path)
    parser.add_argument("--auditor-source", type=Path)
    parser.add_argument("--toolchain-log", type=Path)
    parser.add_argument("--created-at")
    args = parser.parse_args(argv)
    analysis = build_bundle(
        args.program, args.output,
        kernel_oracle=args.kernel_oracle,
        kernel_stderr=args.kernel_stderr,
        build_log=args.build_log,
        bpf_object=args.bpf_object,
        source=args.source,
        descriptor=args.descriptor,
        harness_binary=args.harness_binary,
        harness_source=args.harness_source,
        common_header=args.common_header,
        makefile=args.makefile,
        vmlinux_header=args.vmlinux_header,
        runner=args.runner,
        circuit_spec=args.circuit_spec,
        circuit_compiler=args.circuit_compiler,
        model_source=args.model_source,
        auditor_source=args.auditor_source,
        toolchain_log=args.toolchain_log,
        created_at=args.created_at,
    )
    print(json.dumps(analysis["result"], sort_keys=True))
    return 0 if analysis["result"]["r_established"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
