"""Fail-closed structural auditor for the prospective Stock-R V2 experiment.

This module deliberately separates a complete, direct verifier observation
from outcome eligibility.  A successful V2 capture can show a unique
operational prune and repeated divergent observations, but it remains
``UNKNOWN`` until a separately checked must-outcome or fixed-environment
determinism proof is bound to the exact query.

The document shapes here are experiment-local raw-capture contracts.  They do
not implement the general ``evidence-v1`` semantic evaluator.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


class StockRV2Error(ValueError):
    """Raised when a V2 input is malformed rather than merely incomplete."""


QUERY_SCHEMA = "rac-stock-r-v2-query-v1"
POLICY_SCHEMA = "rac-stock-r-v2-selection-policy-v1"
PRECOMMIT_SCHEMA = "rac-stock-r-v2-precommit-v1"
EVENT_STREAM_SCHEMA = "rac-stock-r-v2-event-stream-v1"
SESSION_SCHEMA = "rac-stock-r-v2-session-v1"
RUNTIME_SCHEMA = "rac-stock-r-v2-runtime-v1"
CAPTURE_CONTRACT_SCHEMA = "rac-stock-r-v2-capture-contract-v1"
AUDIT_SCHEMA = "rac-stock-r-v2-audit-v1"
SOURCE_CLOSURE_SCHEMA = "rac-stock-r-v2-source-closure-v1"
BUILD_CLOSURE_SCHEMA = "rac-stock-r-v2-build-closure-v1"
MUST_OUTCOME_PROOF_SCHEMA = "rac-stock-r-v2-must-outcome-proof-v1"
MUST_OUTCOME_PROOF_PATH = "proof/must-outcome-proof.json"
HISTORY_CASE_BINDING_SCHEMA = "rac-stock-r-v2-history-case-binding-v1"
HISTORY_CASE_BINDING_PATH = "proof/history-case-binding.json"
PRUNE_SOURCE = "fentry/fexit invocation-scoped states_equal/is_state_visited"
TARGET_COMM = "rac-v2-witness"
PROOF_ID = "stock-r-v2.array-map.must-outcome"
PROOF_CALCULUS = "stock-r-v2-array-map-must-outcome-v1"
HISTORY_CASE_BINDING_ID = "stock-r-v2.array-map.history-case-binding"
HISTORY_CASE_BINDING_CALCULUS = "stock-r-v2-history-case-binding-v1"
PROOF_CHECKER_SOURCE_PATH = "residuality-auditor/src/residuality_auditor/stock_r_v2.py"
PROOF_ASSUMPTIONS = [
    "ARRAY_MAP_KEY_ZERO_IN_RANGE",
    "ARRAY_MAP_UPDATE_BPF_ANY_SUCCEEDS_FOR_KEY_ZERO",
    "ARRAY_MAP_LOOKUP_AFTER_SUCCESSFUL_UPDATE_RETURNS_SLOT",
    "BPF_PROG_TEST_RUN_SUPPLIES_ONE_INPUT_BYTE",
    "XDP_RETVAL_OBSERVER_IS_PROGRAM_RETVAL_LOW_BIT",
]
HISTORY_CASE_BINDING_ASSUMPTIONS = [
    "STOCK_R_V2_NAMED_WITNESS_ROLE_ORDER_OLD_ZERO_CURRENT_ONE",
]


def _canonical(value: Any) -> bytes:
    """Encode the local V2 contract canonically with no floating-point values."""

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise StockRV2Error(f"document is not canonical-JSON encodable: {exc}") from exc


def canonical_sha256(value: Any) -> str:
    """Return the SHA-256 digest over the V2 local canonical JSON encoding."""

    return hashlib.sha256(_canonical(value)).hexdigest()


def _require_dict(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StockRV2Error(f"{name} must be an object")
    return value


def _require_list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise StockRV2Error(f"{name} must be an array")
    return value


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise StockRV2Error(f"{name} must be a non-empty string")
    return value


def _require_sha256(value: Any, name: str) -> str:
    digest = _require_str(value, name)
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise StockRV2Error(f"{name} must be a lowercase SHA-256")
    return digest


def _require_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StockRV2Error(f"{name} must be an integer")
    return value


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_exact_int(value: Any, expected: int) -> bool:
    return _is_int(value) and value == expected


def _require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise StockRV2Error(f"{name} must be boolean")
    return value


def _proof_fail(reason: str) -> None:
    raise StockRV2Error(reason)


def _proof_exact_object(value: Any, name: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        _proof_fail("MUST_OUTCOME_PROOF_MALFORMED")
    missing = keys - set(value)
    if missing:
        _proof_fail("MUST_OUTCOME_PROOF_MISSING_FIELD")
    extra = set(value) - keys
    if extra:
        _proof_fail("MUST_OUTCOME_PROOF_UNEXPECTED_FIELD")
    return value


def _identity(document: Any, name: str, *, require_dynamic: bool) -> dict[str, Any]:
    value = _require_dict(document, name)
    required = [
        "program_name",
        "object_sha256",
        "kernel_release",
        "btf_sha256",
    ]
    if require_dynamic:
        required.extend(("program_id", "program_tag", "program_load_time", "xlated_sha256"))
    for field in required:
        if field not in value:
            raise StockRV2Error(f"{name}.{field} is required")
    _require_str(value["program_name"], f"{name}.program_name")
    if require_dynamic:
        program_id = _require_int(value["program_id"], f"{name}.program_id")
        if program_id <= 0:
            raise StockRV2Error(f"{name}.program_id must be positive")
        tag = _require_str(value["program_tag"], f"{name}.program_tag")
        if len(tag) != 16 or any(ch not in "0123456789abcdef" for ch in tag):
            raise StockRV2Error(f"{name}.program_tag must be a lowercase BPF tag")
        load_time = _require_int(value["program_load_time"], f"{name}.program_load_time")
        if load_time <= 0:
            raise StockRV2Error(f"{name}.program_load_time must be positive")
    for field in ("object_sha256", "btf_sha256") + (("xlated_sha256",) if require_dynamic else ()):
        _require_sha256(value[field], f"{name}.{field}")
    _require_str(value["kernel_release"], f"{name}.kernel_release")
    return value


def _query(document: Any) -> dict[str, Any]:
    query = _require_dict(document, "query")
    if query.get("schema") != QUERY_SCHEMA:
        raise StockRV2Error(f"query.schema must be {QUERY_SCHEMA}")
    _require_str(query.get("query_id"), "query.query_id")
    _identity(query.get("identity"), "query.identity", require_dynamic=False)
    _require_sha256(query.get("source_closure_sha256"), "query.source_closure_sha256")
    _require_sha256(query.get("build_closure_sha256"), "query.build_closure_sha256")
    selector = _require_dict(query.get("event_selector"), "query.event_selector")
    if not _is_exact_int(selector.get("exact_level"), 0):
        raise StockRV2Error("query.event_selector.exact_level must be 0")
    for field in ("require_distinct_histories", "require_complete_history", "require_supported_state"):
        if selector.get(field) is not True:
            raise StockRV2Error(f"query.event_selector.{field} must be true")
    if selector.get("uniqueness") != "EXACTLY_ONE":
        raise StockRV2Error("query.event_selector.uniqueness must be EXACTLY_ONE")
    plan = _require_dict(query.get("trial_plan"), "query.trial_plan")
    cases = _require_list(plan.get("cases"), "query.trial_plan.cases")
    if len(cases) != 2 or any(not _is_int(case) for case in cases) or cases != [0, 1]:
        raise StockRV2Error("query.trial_plan.cases must be [0, 1]")
    if _require_int(plan.get("per_case"), "query.trial_plan.per_case") < 2:
        raise StockRV2Error("query.trial_plan.per_case must be at least 2")
    if plan.get("schedule") != "ALTERNATING_START_ZERO":
        raise StockRV2Error("query.trial_plan.schedule must be ALTERNATING_START_ZERO")
    if plan.get("observer") != "XDP_RETURN_BIT":
        raise StockRV2Error("query.trial_plan.observer must be XDP_RETURN_BIT")
    return query


def _policy(document: Any, query: dict[str, Any]) -> dict[str, Any]:
    policy = _require_dict(document, "selection_policy")
    if policy.get("schema") != POLICY_SCHEMA:
        raise StockRV2Error(f"selection_policy.schema must be {POLICY_SCHEMA}")
    _require_str(policy.get("policy_id"), "selection_policy.policy_id")
    if policy.get("query_digest_sha256") != canonical_sha256(query):
        raise StockRV2Error("selection_policy.query_digest_sha256 does not bind query")
    if policy.get("selector") != "EXACTLY_ONE_DIRECT_PRUNE":
        raise StockRV2Error("selection_policy.selector must be EXACTLY_ONE_DIRECT_PRUNE")
    if policy.get("outcome_free") is not True:
        raise StockRV2Error("selection_policy.outcome_free must be true")
    prefixes = _require_list(policy.get("forbidden_input_prefixes"), "selection_policy.forbidden_input_prefixes")
    if not {"runtime.trials", "runtime.outcomes"}.issubset(set(prefixes)):
        raise StockRV2Error("selection_policy must forbid runtime outcomes from selection")
    return policy


def make_precommit(query_document: Any, policy_document: Any, *, recorded_at_ns: int) -> dict[str, Any]:
    """Produce the record that must be written before capture and execution."""

    query = _query(query_document)
    policy = _policy(policy_document, query)
    if recorded_at_ns < 0:
        raise StockRV2Error("recorded_at_ns must be nonnegative")
    return {
        "schema": PRECOMMIT_SCHEMA,
        "query_digest_sha256": canonical_sha256(query),
        "selection_policy_sha256": canonical_sha256(policy),
        "recorded_at_ns": recorded_at_ns,
        "phase": "PRE_LOAD",
    }


def _expected_witness_descriptor() -> dict[str, Any]:
    return {
        "program_name": "rac_v2_single",
        "observer": "XDP_RETURN_BIT",
        "input": {"min_size": 1, "case_byte_offset": 0, "case_mask": 1},
        "state_map": {
            "name": "g0",
            "type": "BPF_MAP_TYPE_ARRAY",
            "max_entries": 1,
            "key_type": "u32",
            "value_type": "u32",
            "slot": 0,
        },
        "suffix": "shared_suffix",
    }


def _expected_helper_contracts() -> list[dict[str, Any]]:
    return [
        {
            "helper": "bpf_map_update_elem",
            "map": "g0",
            "key": 0,
            "flag": "BPF_ANY",
            "preconditions": ["array_map_preallocated", "key_in_range", "value_width_u32"],
            "postcondition": "slot_equals_value",
            "result": "SUCCESS",
        },
        {
            "helper": "bpf_map_lookup_elem",
            "map": "g0",
            "key": 0,
            "preconditions": ["array_map_preallocated", "key_in_range", "after_successful_update"],
            "postcondition": "returns_pointer_to_slot",
            "result": "PRESENT",
        },
    ]


def _expected_case_derivation(case: int) -> dict[str, Any]:
    return {
        "case": case,
        "input": {"byte": case, "low_bit": case & 1},
        "steps": [
            {"rule": "input-low-bit", "offset": 0, "mask": 1, "value": case & 1},
            {"rule": "array-update-slot", "map": "g0", "key": 0, "value": case & 1, "rc": 0},
            {
                "rule": "array-lookup-slot",
                "map": "g0",
                "key": 0,
                "value": case & 1,
                "lookup_missing": False,
            },
            {"rule": "return-low-bit", "value": case & 1, "mask": 1, "retval": case & 1},
        ],
        "outcome": case & 1,
    }


def _expected_derived_outcomes(query: dict[str, Any]) -> dict[str, int]:
    return {str(case): case & 1 for case in query["trial_plan"]["cases"]}


def _proof_exact_step(value: Any, keys: set[str], rule: str) -> dict[str, Any]:
    step = _proof_exact_object(value, "must_outcome_proof.step", keys | {"rule"})
    if step.get("rule") != rule:
        _proof_fail("MUST_OUTCOME_PROOF_DERIVATION_INVALID")
    return step


def _replay_case_derivation(case_document: Any, expected_case: int) -> int:
    case_proof = _proof_exact_object(
        case_document,
        "must_outcome_proof.cases[]",
        {"case", "input", "steps", "outcome"},
    )
    if not _is_exact_int(case_proof.get("case"), expected_case):
        _proof_fail("MUST_OUTCOME_PROOF_DERIVATION_INVALID")
    input_document = _proof_exact_object(
        case_proof.get("input"),
        "must_outcome_proof.cases[].input",
        {"byte", "low_bit"},
    )
    input_byte = input_document.get("byte")
    input_low_bit = input_document.get("low_bit")
    if not _is_exact_int(input_byte, expected_case) or not _is_exact_int(input_low_bit, expected_case & 1):
        _proof_fail("MUST_OUTCOME_PROOF_DERIVATION_INVALID")
    steps = _require_list(case_proof.get("steps"), "must_outcome_proof.cases[].steps")
    if len(steps) != 4:
        _proof_fail("MUST_OUTCOME_PROOF_DERIVATION_INVALID")

    input_step = _proof_exact_step(steps[0], {"offset", "mask", "value"}, "input-low-bit")
    if (
        not _is_exact_int(input_step.get("offset"), 0)
        or not _is_exact_int(input_step.get("mask"), 1)
        or not _is_exact_int(input_step.get("value"), input_byte & 1)
    ):
        _proof_fail("MUST_OUTCOME_PROOF_DERIVATION_INVALID")
    branch = input_step["value"]

    update_step = _proof_exact_step(
        steps[1],
        {"map", "key", "value", "rc"},
        "array-update-slot",
    )
    if (
        update_step.get("map") != "g0"
        or not _is_exact_int(update_step.get("key"), 0)
        or not _is_exact_int(update_step.get("value"), branch)
        or not _is_exact_int(update_step.get("rc"), 0)
    ):
        _proof_fail("MUST_OUTCOME_PROOF_DERIVATION_INVALID")
    map_slot_0 = update_step["value"]

    lookup_step = _proof_exact_step(
        steps[2],
        {"map", "key", "value", "lookup_missing"},
        "array-lookup-slot",
    )
    if (
        lookup_step.get("map") != "g0"
        or not _is_exact_int(lookup_step.get("key"), 0)
        or lookup_step.get("lookup_missing") is not False
        or not _is_exact_int(lookup_step.get("value"), map_slot_0)
    ):
        _proof_fail("MUST_OUTCOME_PROOF_DERIVATION_INVALID")
    observed = lookup_step["value"]

    return_step = _proof_exact_step(
        steps[3],
        {"value", "mask", "retval"},
        "return-low-bit",
    )
    if (
        not _is_exact_int(return_step.get("value"), observed)
        or not _is_exact_int(return_step.get("mask"), 1)
        or not _is_exact_int(return_step.get("retval"), observed & 1)
    ):
        _proof_fail("MUST_OUTCOME_PROOF_DERIVATION_INVALID")
    outcome = return_step["retval"]
    if not _is_exact_int(case_proof.get("outcome"), outcome):
        _proof_fail("MUST_OUTCOME_PROOF_DERIVATION_INVALID")
    return outcome


def _replay_proof_cases(proof: dict[str, Any], query: dict[str, Any]) -> dict[str, int]:
    cases = _require_list(proof.get("cases"), "must_outcome_proof.cases")
    expected_cases = query["trial_plan"]["cases"]
    if len(cases) != len(expected_cases):
        _proof_fail("MUST_OUTCOME_PROOF_DERIVATION_INVALID")
    derived: dict[str, int] = {}
    for case_document, expected_case in zip(cases, expected_cases):
        derived[str(expected_case)] = _replay_case_derivation(case_document, expected_case)
    return derived


def make_must_outcome_proof(query_document: Any, runtime_document: Any) -> dict[str, Any]:
    """Create the V2-local proof object for the controlled array-map witness."""

    query = _query(query_document)
    runtime = _require_dict(runtime_document, "runtime")
    identity = _identity(runtime.get("identity"), "runtime.identity", require_dynamic=True)
    return {
        "schema": MUST_OUTCOME_PROOF_SCHEMA,
        "proof_id": PROOF_ID,
        "checker": {
            "calculus": PROOF_CALCULUS,
            "source_path": PROOF_CHECKER_SOURCE_PATH,
            "source_closure_sha256": query["source_closure_sha256"],
        },
        "query_digest_sha256": canonical_sha256(query),
        "source_closure_sha256": query["source_closure_sha256"],
        "build_closure_sha256": query["build_closure_sha256"],
        "identity": {
            "program_name": identity["program_name"],
            "program_id": identity["program_id"],
            "program_tag": identity["program_tag"],
            "program_load_time": identity["program_load_time"],
            "object_sha256": identity["object_sha256"],
            "xlated_sha256": identity["xlated_sha256"],
            "kernel_release": identity["kernel_release"],
            "btf_sha256": identity["btf_sha256"],
        },
        "witness": _expected_witness_descriptor(),
        "helper_contracts": _expected_helper_contracts(),
        "cases": [_expected_case_derivation(case) for case in query["trial_plan"]["cases"]],
        "derived_outcomes": _expected_derived_outcomes(query),
        "assumptions": list(PROOF_ASSUMPTIONS),
    }


def _check_must_outcome_proof_or_raise(
    proof_document: Any, query_document: Any, runtime_document: Any
) -> dict[str, Any]:
    proof = _proof_exact_object(
        proof_document,
        "must_outcome_proof",
        {
            "schema",
            "proof_id",
            "checker",
            "query_digest_sha256",
            "source_closure_sha256",
            "build_closure_sha256",
            "identity",
            "witness",
            "helper_contracts",
            "cases",
            "derived_outcomes",
            "assumptions",
        },
    )
    if proof.get("schema") != MUST_OUTCOME_PROOF_SCHEMA:
        _proof_fail("MUST_OUTCOME_PROOF_SCHEMA_MISMATCH")
    if proof.get("proof_id") != PROOF_ID:
        _proof_fail("MUST_OUTCOME_PROOF_ID_MISMATCH")

    query = _query(query_document)
    runtime = _require_dict(runtime_document, "runtime")
    runtime_identity = _identity(runtime.get("identity"), "runtime.identity", require_dynamic=True)
    if proof.get("query_digest_sha256") != canonical_sha256(query):
        _proof_fail("MUST_OUTCOME_PROOF_QUERY_DIGEST_MISMATCH")
    if proof.get("source_closure_sha256") != query["source_closure_sha256"]:
        _proof_fail("MUST_OUTCOME_PROOF_SOURCE_CLOSURE_MISMATCH")
    if proof.get("build_closure_sha256") != query["build_closure_sha256"]:
        _proof_fail("MUST_OUTCOME_PROOF_BUILD_CLOSURE_MISMATCH")
    checker = _proof_exact_object(
        proof.get("checker"),
        "must_outcome_proof.checker",
        {"calculus", "source_path", "source_closure_sha256"},
    )
    if checker.get("calculus") != PROOF_CALCULUS:
        _proof_fail("MUST_OUTCOME_PROOF_CALCULUS_MISMATCH")
    if checker.get("source_path") != PROOF_CHECKER_SOURCE_PATH:
        _proof_fail("MUST_OUTCOME_PROOF_CHECKER_SOURCE_MISMATCH")
    if checker.get("source_closure_sha256") != query["source_closure_sha256"]:
        _proof_fail("MUST_OUTCOME_PROOF_CHECKER_SOURCE_CLOSURE_MISMATCH")

    proof_identity = _identity(proof.get("identity"), "must_outcome_proof.identity", require_dynamic=True)
    identity_reason = {
        "program_name": "MUST_OUTCOME_PROOF_PROGRAM_NAME_MISMATCH",
        "program_id": "MUST_OUTCOME_PROOF_PROGRAM_ID_MISMATCH",
        "program_tag": "MUST_OUTCOME_PROOF_PROGRAM_TAG_MISMATCH",
        "program_load_time": "MUST_OUTCOME_PROOF_PROGRAM_LOAD_TIME_MISMATCH",
        "object_sha256": "MUST_OUTCOME_PROOF_OBJECT_DIGEST_MISMATCH",
        "xlated_sha256": "MUST_OUTCOME_PROOF_XLATED_DIGEST_MISMATCH",
        "kernel_release": "MUST_OUTCOME_PROOF_KERNEL_RELEASE_MISMATCH",
        "btf_sha256": "MUST_OUTCOME_PROOF_BTF_DIGEST_MISMATCH",
    }
    for field, reason in identity_reason.items():
        if proof_identity.get(field) != runtime_identity.get(field):
            _proof_fail(reason)
    for field in ("program_name", "object_sha256", "kernel_release", "btf_sha256"):
        if proof_identity.get(field) != query["identity"].get(field):
            _proof_fail(identity_reason[field])

    if proof.get("witness") != _expected_witness_descriptor():
        _proof_fail("MUST_OUTCOME_PROOF_WITNESS_DESCRIPTOR_MISMATCH")
    if proof.get("helper_contracts") != _expected_helper_contracts():
        _proof_fail("MUST_OUTCOME_PROOF_HELPER_CONTRACT_MISMATCH")
    if proof.get("assumptions") != PROOF_ASSUMPTIONS:
        _proof_fail("MUST_OUTCOME_PROOF_ASSUMPTIONS_MISMATCH")
    replayed_outcomes = _replay_proof_cases(proof, query)
    derived = _require_dict(proof.get("derived_outcomes"), "must_outcome_proof.derived_outcomes")
    if set(derived) != set(replayed_outcomes) or any(
        not _is_exact_int(derived.get(key), value)
        for key, value in replayed_outcomes.items()
    ):
        _proof_fail("MUST_OUTCOME_PROOF_DERIVED_OUTCOMES_MISMATCH")
    return {
        "status": "VERIFIED",
        "proof_digest_sha256": canonical_sha256(proof),
        "derived_outcomes": replayed_outcomes,
        "assumptions": list(PROOF_ASSUMPTIONS),
    }


def check_must_outcome_proof(proof_document: Any, query_document: Any, runtime_document: Any) -> dict[str, Any]:
    """Check the V2-local must-outcome proof and return a fail-closed result."""

    try:
        return _check_must_outcome_proof_or_raise(proof_document, query_document, runtime_document)
    except StockRV2Error as exc:
        reason = str(exc)
        if not reason.startswith("MUST_OUTCOME_PROOF_"):
            reason = "MUST_OUTCOME_PROOF_MALFORMED"
        return {"status": "INVALID", "invalid_reasons": [reason]}


def _binding_fail(reason: str) -> None:
    raise StockRV2Error(reason)


def _binding_exact_object(value: Any, name: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        _binding_fail("HISTORY_CASE_BINDING_MALFORMED")
    missing = keys - set(value)
    if missing:
        _binding_fail("HISTORY_CASE_BINDING_MISSING_FIELD")
    extra = set(value) - keys
    if extra:
        _binding_fail("HISTORY_CASE_BINDING_UNEXPECTED_FIELD")
    return value


def _history_digest(snapshot: Any) -> str:
    return canonical_sha256(_require_dict(snapshot, "history_snapshot"))


def _report_cell_id(event: dict[str, Any]) -> str:
    return canonical_sha256(
        {
            "authority": "OPERATIONAL_OBSERVATION",
            "relation": PRUNE_SOURCE,
            "source": event.get("source"),
            "session_id": event.get("session_id"),
            "sequence": event.get("sequence"),
            "equality_sequence": event.get("equality_sequence"),
            "visit_sequence": event.get("visit_sequence"),
            "invocation_token": event.get("invocation_token"),
            "exact_level": event.get("exact_level"),
            "visit_insn": event.get("visit_insn"),
            "old_history_digest_sha256": _history_digest(event.get("old")),
            "current_history_digest_sha256": _history_digest(event.get("current")),
        }
    )


def _frontier(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": PRUNE_SOURCE,
        "exact_level": event.get("exact_level"),
        "visit_insn": event.get("visit_insn"),
    }


def _report_cell(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "authority": "OPERATIONAL_OBSERVATION",
        "relation": PRUNE_SOURCE,
        "cell_id": _report_cell_id(event),
    }


def _scope_vector(
    query: dict[str, Any],
    runtime_identity: dict[str, Any],
    event: dict[str, Any],
    proof: dict[str, Any],
) -> dict[str, Any]:
    witness = _require_dict(proof.get("witness"), "must_outcome_proof.witness")
    return {
        "artifact": {
            "program_name": query["identity"]["program_name"],
            "object_sha256": query["identity"]["object_sha256"],
            "xlated_sha256": runtime_identity["xlated_sha256"],
            "btf_sha256": query["identity"]["btf_sha256"],
        },
        "implementation": {
            "kernel_release": query["identity"]["kernel_release"],
            "program_id": runtime_identity["program_id"],
            "program_tag": runtime_identity["program_tag"],
            "program_load_time": runtime_identity["program_load_time"],
        },
        "frontier": _frontier(event),
        "context": {
            "input": witness.get("input"),
            "state_map": witness.get("state_map"),
        },
        "report": _report_cell(event),
        "observer": witness.get("observer"),
        "suffix": witness.get("suffix"),
        "environment": {
            "target_comm": TARGET_COMM,
            "capture_backend": "fentry+fexit",
        },
    }


def _history_binding(
    role: str,
    case: int,
    snapshot: dict[str, Any],
    derived_outcomes: dict[str, int],
) -> dict[str, Any]:
    outcome = derived_outcomes[str(case)]
    return {
        "role": role,
        "case": case,
        "history_digest_sha256": _history_digest(snapshot),
        "history_entries": snapshot["history_entries"],
        "outcome": outcome,
    }


def make_history_case_binding(
    query_document: Any,
    event_document: Any,
    runtime_document: Any,
    must_outcome_proof_document: Any,
) -> dict[str, Any]:
    """Create the exact V2 proof term joining prune histories to proof cases."""

    query = _query(query_document)
    event = _require_dict(event_document, "event")
    runtime = _require_dict(runtime_document, "runtime")
    runtime_identity = _identity(runtime.get("identity"), "runtime.identity", require_dynamic=True)
    if not _qualifies(event, query, runtime_identity):
        raise StockRV2Error("HISTORY_CASE_BINDING_PRUNE_NOT_QUALIFYING")
    proof = _require_dict(must_outcome_proof_document, "must_outcome_proof")
    proof_result = check_must_outcome_proof(proof, query_document, runtime_document)
    if proof_result["status"] != "VERIFIED":
        raise StockRV2Error("HISTORY_CASE_BINDING_MUST_OUTCOME_PROOF_INVALID")
    scope = _scope_vector(query, runtime_identity, event, proof)
    return {
        "schema": HISTORY_CASE_BINDING_SCHEMA,
        "proof_id": HISTORY_CASE_BINDING_ID,
        "checker": {
            "calculus": HISTORY_CASE_BINDING_CALCULUS,
            "source_path": PROOF_CHECKER_SOURCE_PATH,
            "source_closure_sha256": query["source_closure_sha256"],
        },
        "query_digest_sha256": canonical_sha256(query),
        "source_closure_sha256": query["source_closure_sha256"],
        "build_closure_sha256": query["build_closure_sha256"],
        "must_outcome_proof_digest_sha256": proof_result["proof_digest_sha256"],
        "identity": {
            "program_name": runtime_identity["program_name"],
            "program_id": runtime_identity["program_id"],
            "program_tag": runtime_identity["program_tag"],
            "program_load_time": runtime_identity["program_load_time"],
            "object_sha256": runtime_identity["object_sha256"],
            "xlated_sha256": runtime_identity["xlated_sha256"],
            "kernel_release": runtime_identity["kernel_release"],
            "btf_sha256": runtime_identity["btf_sha256"],
        },
        "frontier": _frontier(event),
        "report_cell": _report_cell(event),
        "suffix": proof["witness"]["suffix"],
        "observer": proof["witness"]["observer"],
        "histories": [
            _history_binding("old", 0, _require_dict(event.get("old"), "event.old"), proof_result["derived_outcomes"]),
            _history_binding(
                "current",
                1,
                _require_dict(event.get("current"), "event.current"),
                proof_result["derived_outcomes"],
            ),
        ],
        "observer_inequality": {
            "left_role": "old",
            "left_case": 0,
            "left_outcome": proof_result["derived_outcomes"]["0"],
            "right_role": "current",
            "right_case": 1,
            "right_outcome": proof_result["derived_outcomes"]["1"],
            "observer": proof["witness"]["observer"],
            "holds": proof_result["derived_outcomes"]["0"] != proof_result["derived_outcomes"]["1"],
        },
        "scope": scope,
        "scope_digest_sha256": canonical_sha256(scope),
        "assumptions": list(HISTORY_CASE_BINDING_ASSUMPTIONS),
    }


def make_history_case_binding_from_events(
    query_document: Any,
    event_rows: Iterable[Any],
    runtime_document: Any,
    must_outcome_proof_document: Any,
) -> dict[str, Any]:
    """Create a binding from a full event stream by selecting the unique prune."""

    query = _query(query_document)
    runtime = _require_dict(runtime_document, "runtime")
    runtime_identity = _identity(runtime.get("identity"), "runtime.identity", require_dynamic=True)
    events = [_require_dict(row, "events[]") for row in event_rows]
    qualifying = [event for event in events if _qualifies(event, query, runtime_identity)]
    if len(qualifying) != 1:
        raise StockRV2Error("HISTORY_CASE_BINDING_QUALIFYING_PRUNE_NOT_UNIQUE")
    return make_history_case_binding(query_document, qualifying[0], runtime_document, must_outcome_proof_document)


def _expected_history_document(
    role: str,
    case: int,
    event: dict[str, Any],
    proof_result: dict[str, Any],
) -> dict[str, Any]:
    snapshot = _require_dict(event.get(role), f"event.{role}")
    return _history_binding(role, case, snapshot, proof_result["derived_outcomes"])


def _check_history_case_binding_or_raise(
    binding_document: Any,
    query_document: Any,
    event_document: Any,
    runtime_document: Any,
    must_outcome_proof_document: Any,
) -> dict[str, Any]:
    binding = _binding_exact_object(
        binding_document,
        "history_case_binding",
        {
            "schema",
            "proof_id",
            "checker",
            "query_digest_sha256",
            "source_closure_sha256",
            "build_closure_sha256",
            "must_outcome_proof_digest_sha256",
            "identity",
            "frontier",
            "report_cell",
            "suffix",
            "observer",
            "histories",
            "observer_inequality",
            "scope",
            "scope_digest_sha256",
            "assumptions",
        },
    )
    if binding.get("schema") != HISTORY_CASE_BINDING_SCHEMA:
        _binding_fail("HISTORY_CASE_BINDING_SCHEMA_MISMATCH")
    if binding.get("proof_id") != HISTORY_CASE_BINDING_ID:
        _binding_fail("HISTORY_CASE_BINDING_ID_MISMATCH")

    query = _query(query_document)
    event = _require_dict(event_document, "event")
    runtime = _require_dict(runtime_document, "runtime")
    runtime_identity = _identity(runtime.get("identity"), "runtime.identity", require_dynamic=True)
    if not _qualifies(event, query, runtime_identity):
        _binding_fail("HISTORY_CASE_BINDING_PRUNE_NOT_QUALIFYING")
    proof = _require_dict(must_outcome_proof_document, "must_outcome_proof")
    proof_result = check_must_outcome_proof(proof, query_document, runtime_document)
    if proof_result["status"] != "VERIFIED":
        _binding_fail("HISTORY_CASE_BINDING_MUST_OUTCOME_PROOF_INVALID")

    if binding.get("query_digest_sha256") != canonical_sha256(query):
        _binding_fail("HISTORY_CASE_BINDING_QUERY_DIGEST_MISMATCH")
    if binding.get("source_closure_sha256") != query["source_closure_sha256"]:
        _binding_fail("HISTORY_CASE_BINDING_SOURCE_CLOSURE_MISMATCH")
    if binding.get("build_closure_sha256") != query["build_closure_sha256"]:
        _binding_fail("HISTORY_CASE_BINDING_BUILD_CLOSURE_MISMATCH")
    if binding.get("must_outcome_proof_digest_sha256") != proof_result["proof_digest_sha256"]:
        _binding_fail("HISTORY_CASE_BINDING_MUST_OUTCOME_PROOF_DIGEST_MISMATCH")

    checker = _binding_exact_object(
        binding.get("checker"),
        "history_case_binding.checker",
        {"calculus", "source_path", "source_closure_sha256"},
    )
    if checker.get("calculus") != HISTORY_CASE_BINDING_CALCULUS:
        _binding_fail("HISTORY_CASE_BINDING_CALCULUS_MISMATCH")
    if checker.get("source_path") != PROOF_CHECKER_SOURCE_PATH:
        _binding_fail("HISTORY_CASE_BINDING_CHECKER_SOURCE_MISMATCH")
    if checker.get("source_closure_sha256") != query["source_closure_sha256"]:
        _binding_fail("HISTORY_CASE_BINDING_CHECKER_SOURCE_CLOSURE_MISMATCH")

    binding_identity = _identity(binding.get("identity"), "history_case_binding.identity", require_dynamic=True)
    for field in (
        "program_name",
        "program_id",
        "program_tag",
        "program_load_time",
        "object_sha256",
        "xlated_sha256",
        "kernel_release",
        "btf_sha256",
    ):
        if binding_identity.get(field) != runtime_identity.get(field):
            _binding_fail("HISTORY_CASE_BINDING_IDENTITY_MISMATCH")
    for field in ("program_name", "object_sha256", "kernel_release", "btf_sha256"):
        if binding_identity.get(field) != query["identity"].get(field):
            _binding_fail("HISTORY_CASE_BINDING_QUERY_IDENTITY_MISMATCH")

    if binding.get("frontier") != _frontier(event):
        _binding_fail("HISTORY_CASE_BINDING_FRONTIER_MISMATCH")
    if binding.get("report_cell") != _report_cell(event):
        _binding_fail("HISTORY_CASE_BINDING_REPORT_CELL_MISMATCH")
    witness = _require_dict(proof.get("witness"), "must_outcome_proof.witness")
    if binding.get("suffix") != witness.get("suffix"):
        _binding_fail("HISTORY_CASE_BINDING_SUFFIX_MISMATCH")
    if binding.get("observer") != witness.get("observer") or binding.get("observer") != query["trial_plan"]["observer"]:
        _binding_fail("HISTORY_CASE_BINDING_OBSERVER_MISMATCH")

    histories = _require_list(binding.get("histories"), "history_case_binding.histories")
    expected_histories = [
        _expected_history_document("old", 0, event, proof_result),
        _expected_history_document("current", 1, event, proof_result),
    ]
    if histories != expected_histories:
        _binding_fail("HISTORY_CASE_BINDING_HISTORY_CASE_MISMATCH")

    expected_inequality = {
        "left_role": "old",
        "left_case": 0,
        "left_outcome": proof_result["derived_outcomes"]["0"],
        "right_role": "current",
        "right_case": 1,
        "right_outcome": proof_result["derived_outcomes"]["1"],
        "observer": witness.get("observer"),
        "holds": proof_result["derived_outcomes"]["0"] != proof_result["derived_outcomes"]["1"],
    }
    if binding.get("observer_inequality") != expected_inequality or expected_inequality["holds"] is not True:
        _binding_fail("HISTORY_CASE_BINDING_OBSERVER_INEQUALITY_MISMATCH")

    expected_scope = _scope_vector(query, runtime_identity, event, proof)
    if binding.get("scope") != expected_scope:
        _binding_fail("HISTORY_CASE_BINDING_SCOPE_MISMATCH")
    if binding.get("scope_digest_sha256") != canonical_sha256(expected_scope):
        _binding_fail("HISTORY_CASE_BINDING_SCOPE_DIGEST_MISMATCH")
    if binding.get("assumptions") != HISTORY_CASE_BINDING_ASSUMPTIONS:
        _binding_fail("HISTORY_CASE_BINDING_ASSUMPTIONS_MISMATCH")

    return {
        "status": "VERIFIED",
        "binding_digest_sha256": canonical_sha256(binding),
        "scope_digest_sha256": canonical_sha256(expected_scope),
        "report_cell_id": _report_cell_id(event),
        "history_cases": expected_histories,
        "assumptions": list(HISTORY_CASE_BINDING_ASSUMPTIONS),
    }


def check_history_case_binding(
    binding_document: Any,
    query_document: Any,
    event_document: Any,
    runtime_document: Any,
    must_outcome_proof_document: Any,
) -> dict[str, Any]:
    """Check the exact V2 history-to-case join proof and fail closed."""

    try:
        return _check_history_case_binding_or_raise(
            binding_document,
            query_document,
            event_document,
            runtime_document,
            must_outcome_proof_document,
        )
    except StockRV2Error as exc:
        reason = str(exc)
        if not reason.startswith("HISTORY_CASE_BINDING_"):
            reason = "HISTORY_CASE_BINDING_MALFORMED"
        return {"status": "INVALID", "invalid_reasons": [reason]}


def _precommit(document: Any, query: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    precommit = _require_dict(document, "precommit")
    if precommit.get("schema") != PRECOMMIT_SCHEMA:
        raise StockRV2Error(f"precommit.schema must be {PRECOMMIT_SCHEMA}")
    if _require_int(precommit.get("recorded_at_ns"), "precommit.recorded_at_ns") < 0:
        raise StockRV2Error("precommit.recorded_at_ns must be nonnegative")
    _require_str(precommit.get("query_digest_sha256"), "precommit.query_digest_sha256")
    _require_str(precommit.get("selection_policy_sha256"), "precommit.selection_policy_sha256")
    if precommit.get("phase") != "PRE_LOAD":
        raise StockRV2Error("precommit.phase must be PRE_LOAD")
    return precommit


def _snapshot_is_complete(snapshot: Any) -> bool:
    try:
        value = _require_dict(snapshot, "snapshot")
        entries = _require_list(value.get("history_entries"), "snapshot.history_entries")
        total = _require_int(value.get("history_total_count"), "snapshot.history_total_count")
        captured = _require_int(value.get("history_captured_count"), "snapshot.history_captured_count")
        truncated = _require_bool(value.get("history_truncated"), "snapshot.history_truncated")
        state = _require_dict(value.get("state_v2"), "snapshot.state_v2")
        return (
            total == captured == len(entries)
            and not truncated
            and state.get("valid") is True
            and _is_exact_int(state.get("unsupported_mask"), 0)
        )
    except StockRV2Error:
        return False


def _histories_distinct(event: dict[str, Any]) -> bool:
    old = _require_dict(event.get("old"), "event.old")
    current = _require_dict(event.get("current"), "event.current")
    return old.get("history_entries") != current.get("history_entries")


def _validate_prune_event(event: dict[str, Any], reasons: list[str]) -> None:
    """Reject malformed raw event scalars; incompleteness stays non-qualifying."""

    if event.get("source") != PRUNE_SOURCE:
        reasons.append("PRUNE_SOURCE_MISMATCH")
    if not isinstance(event.get("session_id"), str) or not event["session_id"]:
        reasons.append("PRUNE_SESSION_ID_INVALID")
    for field in ("sequence", "equality_sequence", "visit_sequence", "invocation_token", "program_load_time"):
        if not _is_int(event.get(field)) or event[field] <= 0:
            reasons.append("PRUNE_" + field.upper() + "_INVALID")
    for field in ("visit_insn", "exact_level"):
        if not _is_int(event.get(field)):
            reasons.append("PRUNE_" + field.upper() + "_INVALID")
    if not _is_int(event.get("states_equal_success_count")) or event["states_equal_success_count"] < 0:
        reasons.append("PRUNE_STATES_EQUAL_SUCCESS_COUNT_INVALID")
    if not isinstance(event.get("program_name"), str) or not event["program_name"]:
        reasons.append("PRUNE_PROGRAM_NAME_INVALID")
    tag = event.get("program_tag")
    if not isinstance(tag, str) or len(tag) != 16 or any(ch not in "0123456789abcdef" for ch in tag):
        reasons.append("PRUNE_PROGRAM_TAG_INVALID")


def _event_matches_identity(event: dict[str, Any], identity: dict[str, Any]) -> bool:
    return (
        event.get("program_name") == identity.get("program_name")
        and event.get("program_tag") == identity.get("program_tag")
        and _is_int(event.get("program_load_time"))
        and event.get("program_load_time") == identity.get("program_load_time")
    )


def _qualifies(event: dict[str, Any], query: dict[str, Any], runtime_identity: dict[str, Any]) -> bool:
    selector = query["event_selector"]
    return (
        event.get("event") == "prune_hit"
        and event.get("source") == PRUNE_SOURCE
        and _event_matches_identity(event, runtime_identity)
        and _is_exact_int(event.get("exact_level"), selector["exact_level"])
        and _is_exact_int(event.get("states_equal_success_count"), 1)
        and _is_int(event.get("invocation_token"))
        and event["invocation_token"] > 0
        and _snapshot_is_complete(event.get("old"))
        and _snapshot_is_complete(event.get("current"))
        and _histories_distinct(event)
    )


def _counter_is_zero(document: dict[str, Any], name: str, reasons: list[str], reason: str) -> None:
    value = document.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value != 0:
        reasons.append(reason)


def _capture_contract(document: Any, query: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    contract = _require_dict(document, "capture_contract")
    if contract.get("schema") != CAPTURE_CONTRACT_SCHEMA:
        raise StockRV2Error(f"capture_contract.schema must be {CAPTURE_CONTRACT_SCHEMA}")
    _require_str(contract.get("query_digest_sha256"), "capture_contract.query_digest_sha256")
    _require_str(contract.get("selection_policy_sha256"), "capture_contract.selection_policy_sha256")
    _require_sha256(contract.get("source_closure_sha256"), "capture_contract.source_closure_sha256")
    _require_sha256(contract.get("build_closure_sha256"), "capture_contract.build_closure_sha256")
    if contract.get("backend") != "fentry+fexit":
        raise StockRV2Error("capture_contract.backend must be fentry+fexit")
    if contract.get("target_comm") != TARGET_COMM:
        raise StockRV2Error(f"capture_contract.target_comm must be {TARGET_COMM}")
    if contract.get("program_name") != query["identity"]["program_name"]:
        raise StockRV2Error("capture_contract.program_name must bind the query program")
    if contract.get("source_closure_sha256") != query["source_closure_sha256"]:
        raise StockRV2Error("capture_contract.source_closure_sha256 must bind the query")
    if contract.get("build_closure_sha256") != query["build_closure_sha256"]:
        raise StockRV2Error("capture_contract.build_closure_sha256 must bind the query")
    if contract.get("trial_count") != query["trial_plan"]["per_case"] * len(query["trial_plan"]["cases"]):
        raise StockRV2Error("capture_contract.trial_count must bind the query trial plan")
    if contract.get("outcome_free_selection") is not True:
        raise StockRV2Error("capture_contract.outcome_free_selection must be true")
    return contract


def _session(
    rows: Iterable[Any], query: dict[str, Any], precommit: dict[str, Any], reasons: list[str]
) -> tuple[list[dict[str, Any]], dict[str, Any] | None, dict[str, Any] | None]:
    events = [_require_dict(row, "events[]") for row in rows]
    metadata = [row for row in events if row.get("event") == "metadata"]
    complete = [row for row in events if row.get("event") == "capture_complete"]
    prune_events = [row for row in events if row.get("event") == "prune_hit"]
    for event in prune_events:
        _validate_prune_event(event, reasons)
    if len(metadata) != 1:
        reasons.append("METADATA_NOT_UNIQUE")
        return prune_events, None, None
    if len(complete) != 1:
        reasons.append("CAPTURE_COMPLETE_NOT_UNIQUE")
        return prune_events, metadata[0], None
    start, end = metadata[0], complete[0]
    if not events or events[0] is not start or events[-1] is not end:
        reasons.append("SESSION_DOCUMENT_ORDER_INVALID")
    if any(row.get("event") not in {"metadata", "prune_hit", "capture_complete"} for row in events):
        reasons.append("SESSION_EVENT_KIND_INVALID")
    if start.get("schema") != EVENT_STREAM_SCHEMA:
        reasons.append("EVENT_STREAM_SCHEMA_MISMATCH")
    if end.get("schema") != SESSION_SCHEMA:
        reasons.append("SESSION_SCHEMA_MISMATCH")
    session_id = start.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        reasons.append("SESSION_ID_MISSING")
    elif end.get("session_id") != session_id or any(row.get("session_id") != session_id for row in prune_events):
        reasons.append("SESSION_ID_MISMATCH")
    start_ns = start.get("capture_started_ns")
    attached_ns = start.get("capture_attached_ns")
    end_ns = end.get("capture_ended_ns")
    if isinstance(start_ns, bool) or not isinstance(start_ns, int):
        reasons.append("CAPTURE_START_MISSING")
    elif precommit["recorded_at_ns"] >= start_ns:
        reasons.append("PRECOMMIT_NOT_BEFORE_CAPTURE")
    if (
        isinstance(attached_ns, bool)
        or not isinstance(attached_ns, int)
        or not isinstance(start_ns, int)
        or attached_ns < start_ns
    ):
        reasons.append("CAPTURE_ATTACH_TIME_INVALID")
    if (
        isinstance(end_ns, bool)
        or not isinstance(end_ns, int)
        or not isinstance(start_ns, int)
        or end_ns <= start_ns
    ):
        reasons.append("CAPTURE_TIME_INVALID")
    if end.get("capture_started_ns") != start_ns:
        reasons.append("CAPTURE_START_TIME_MISMATCH")
    if start.get("kernel_release") != query["identity"]["kernel_release"]:
        reasons.append("EVENT_KERNEL_RELEASE_MISMATCH")
    if start.get("backend") != "fentry+fexit" or start.get("target_comm") != TARGET_COMM:
        reasons.append("CAPTURE_BACKEND_OR_TARGET_MISMATCH")
    if end.get("completed") is not True:
        reasons.append("CAPTURE_NOT_COMPLETED")
    _counter_is_zero(end, "ringbuf_lost_events", reasons, "RINGBUF_LOSS")
    _counter_is_zero(end, "collector_parse_errors", reasons, "COLLECTOR_PARSE_ERRORS")
    _counter_is_zero(end, "unmatched_equal_events", reasons, "UNMATCHED_EQUAL_EVENT")
    _counter_is_zero(end, "ambiguous_visit_events", reasons, "AMBIGUOUS_VISIT_EVENT")
    _counter_is_zero(end, "dangling_visit_contexts", reasons, "DANGLING_VISIT_CONTEXT")
    _counter_is_zero(end, "tracer_map_update_failures", reasons, "TRACER_MAP_UPDATE_FAILURE")
    _counter_is_zero(end, "active_visit_contexts", reasons, "ACTIVE_VISIT_CONTEXT_LEAK")
    _counter_is_zero(end, "sequence_gaps", reasons, "EVENT_SEQUENCE_GAP")
    if not _is_exact_int(end.get("events_seen"), len(prune_events)):
        reasons.append("EVENT_COUNT_MISMATCH")
    if not _is_int(end.get("tracer_events_emitted")) or end.get("tracer_events_emitted") != end.get("events_seen"):
        reasons.append("TRACER_EVENT_COUNT_MISMATCH")
    sequences = [event.get("sequence") for event in prune_events]
    if sequences != list(range(1, len(prune_events) + 1)):
        reasons.append("EVENT_SEQUENCE_GAP")
    return prune_events, start, end


def _trial_reason_prefix(field: str) -> str:
    return "TRIAL_" + field.upper()


def _runtime(
    document: Any,
    query: dict[str, Any],
    precommit: dict[str, Any],
    capture_started_ns: Any,
    capture_attached_ns: Any,
    capture_ended_ns: Any,
    reasons: list[str],
) -> dict[str, Any]:
    runtime = _require_dict(document, "runtime")
    if runtime.get("schema") != RUNTIME_SCHEMA:
        raise StockRV2Error(f"runtime.schema must be {RUNTIME_SCHEMA}")
    identity = _identity(runtime.get("identity"), "runtime.identity", require_dynamic=True)
    expected_identity = query["identity"]
    for field, value in expected_identity.items():
        if identity.get(field) != value:
            reasons.append(f"RUNTIME_{field.upper()}_MISMATCH")
    started = _require_int(runtime.get("runtime_started_ns"), "runtime.runtime_started_ns")
    ended = _require_int(runtime.get("runtime_ended_ns"), "runtime.runtime_ended_ns")
    load_started = _require_int(runtime.get("program_load_started_ns"), "runtime.program_load_started_ns")
    load_completed = _require_int(runtime.get("program_load_completed_ns"), "runtime.program_load_completed_ns")
    if precommit["recorded_at_ns"] >= load_started:
        reasons.append("PRECOMMIT_NOT_BEFORE_PROGRAM_LOAD")
    if load_completed < load_started:
        reasons.append("PROGRAM_LOAD_TIME_INVALID")
    if started < load_completed:
        reasons.append("RUNTIME_BEFORE_PROGRAM_LOAD_COMPLETED")
    if precommit["recorded_at_ns"] >= started:
        reasons.append("PRECOMMIT_NOT_BEFORE_RUNTIME")
    if ended <= started:
        reasons.append("RUNTIME_TIME_INVALID")
    if (
        not isinstance(capture_started_ns, int)
        or isinstance(capture_started_ns, bool)
        or not isinstance(capture_attached_ns, int)
        or isinstance(capture_attached_ns, bool)
        or not isinstance(capture_ended_ns, int)
        or isinstance(capture_ended_ns, bool)
        or load_started < capture_attached_ns
        or ended > capture_ended_ns
    ):
        reasons.append("RUNTIME_NOT_COVERED_BY_CAPTURE")
    trials = _require_list(runtime.get("trials"), "runtime.trials")
    plan = query["trial_plan"]
    expected_total = plan["per_case"] * len(plan["cases"])
    if len(trials) != expected_total:
        reasons.append("TRIAL_COUNT_MISMATCH")
    outcomes: dict[str, set[int]] = {str(case): set() for case in plan["cases"]}
    counts: dict[str, int] = {str(case): 0 for case in plan["cases"]}
    for index, raw_trial in enumerate(trials):
        trial = _require_dict(raw_trial, f"runtime.trials[{index}]")
        expected_case = index % 2
        if not _is_exact_int(trial.get("trial_id"), index):
            reasons.append("TRIAL_ID_SEQUENCE_MISMATCH")
        if not _is_exact_int(trial.get("case"), expected_case):
            reasons.append("TRIAL_SCHEDULE_MISMATCH")
        case = trial.get("case")
        if not _is_int(case) or case not in plan["cases"]:
            reasons.append("TRIAL_CASE_INVALID")
            continue
        key = str(case)
        counts[key] += 1
        for field in ("test_run_rc", "test_run_errno", "map_read_rc", "trace_read_rc"):
            if not _is_exact_int(trial.get(field), 0):
                reasons.append(_trial_reason_prefix(field) + "_NONZERO")
        trial_identity = _require_dict(trial.get("program_identity"), f"runtime.trials[{index}].program_identity")
        for field in ("program_name", "program_id", "program_tag", "program_load_time"):
            if trial_identity.get(field) != identity[field]:
                reasons.append(f"TRIAL_{field.upper()}_MISMATCH")
        trace = _require_dict(trial.get("trace"), f"runtime.trials[{index}].trace")
        if not _is_exact_int(trace.get("branch"), case):
            reasons.append("TRIAL_BRANCH_TRACE_MISMATCH")
        for field in ("reset_rc", "branch_rc", "trace_errors"):
            if not _is_exact_int(trace.get(field), 0):
                reasons.append(_trial_reason_prefix(field) + "_NONZERO")
        if trace.get("lookup_missing") is not False:
            reasons.append("TRIAL_LOOKUP_MISSING")
        retval = trial.get("retval")
        observed = trace.get("observed_value")
        selected = trace.get("selected_value")
        final = trial.get("map_value_after")
        if not all(_is_int(value) for value in (retval, observed, selected, final)):
            reasons.append("TRIAL_OBSERVER_VALUE_INVALID")
            continue
        if retval != observed:
            reasons.append("TRIAL_OBSERVER_TRACE_MISMATCH")
        if any(value != case for value in (retval, observed, selected, final)):
            reasons.append("TRIAL_CASE_SEMANTICS_MISMATCH")
        outcomes[key].add(retval)
    for case in plan["cases"]:
        key = str(case)
        if counts[key] != plan["per_case"]:
            reasons.append("TRIAL_CASE_BALANCE_MISMATCH")
        if len(outcomes[key]) != 1:
            reasons.append("TRIAL_OUTCOME_NOT_SINGLETON")
    return {
        "status": "REPLICATION_OBSERVED" if not reasons else "INVALID",
        "identity": identity,
        "outcomes_by_case": {key: sorted(values) for key, values in outcomes.items()},
        "counts_by_case": counts,
    }


def _unique_reasons(values: Iterable[str]) -> list[str]:
    return sorted(set(values))


def audit_capture(
    query_document: Any,
    policy_document: Any,
    precommit_document: Any,
    event_rows: Iterable[Any],
    runtime_document: Any,
    capture_contract_document: Any,
    *,
    extra_invalid_reasons: Iterable[str] = (),
    must_outcome_proof_document: Any | None = None,
    history_case_binding_document: Any | None = None,
) -> dict[str, Any]:
    """Audit one V2 run without giving repetitions semantic must-outcome force."""

    query = _query(query_document)
    policy = _policy(policy_document, query)
    precommit = _precommit(precommit_document, query, policy)
    invalid_reasons: list[str] = []
    contract = _capture_contract(capture_contract_document, query, policy)
    if contract["query_digest_sha256"] != canonical_sha256(query):
        invalid_reasons.append("CAPTURE_CONTRACT_QUERY_DIGEST_MISMATCH")
    if contract["selection_policy_sha256"] != canonical_sha256(policy):
        invalid_reasons.append("CAPTURE_CONTRACT_POLICY_DIGEST_MISMATCH")
    if precommit.get("query_digest_sha256") != canonical_sha256(query):
        invalid_reasons.append("PRECOMMIT_QUERY_DIGEST_MISMATCH")
    if precommit.get("selection_policy_sha256") != canonical_sha256(policy):
        invalid_reasons.append("PRECOMMIT_POLICY_DIGEST_MISMATCH")
    prune_events, start, end = _session(event_rows, query, precommit, invalid_reasons)
    replication = _runtime(
        runtime_document,
        query,
        precommit,
        start.get("capture_started_ns") if start else None,
        start.get("capture_attached_ns") if start else None,
        end.get("capture_ended_ns") if end else None,
        invalid_reasons,
    )
    invalid_reasons.extend(extra_invalid_reasons)
    proof_result: dict[str, Any] = {"status": "ABSENT"}
    if must_outcome_proof_document is not None:
        proof_result = check_must_outcome_proof(must_outcome_proof_document, query_document, runtime_document)
        if proof_result["status"] == "INVALID":
            invalid_reasons.extend(proof_result["invalid_reasons"])
        else:
            runtime_outcomes = {
                key: values[0]
                for key, values in replication["outcomes_by_case"].items()
                if isinstance(values, list) and len(values) == 1
            }
            if runtime_outcomes != proof_result["derived_outcomes"]:
                invalid_reasons.append("MUST_OUTCOME_PROOF_RUNTIME_OUTCOME_MISMATCH")
    qualifying = [event for event in prune_events if _qualifies(event, query, replication["identity"])]
    if len(qualifying) > 1:
        invalid_reasons.append("QUALIFYING_PRUNE_NOT_UNIQUE")
    binding_result: dict[str, Any] = {"status": "ABSENT"}
    if history_case_binding_document is not None:
        if len(qualifying) != 1:
            binding_result = {
                "status": "INVALID",
                "invalid_reasons": ["HISTORY_CASE_BINDING_QUALIFYING_PRUNE_NOT_UNIQUE"],
            }
        elif proof_result["status"] != "VERIFIED" or must_outcome_proof_document is None:
            binding_result = {
                "status": "INVALID",
                "invalid_reasons": ["HISTORY_CASE_BINDING_MUST_OUTCOME_PROOF_INVALID"],
            }
        else:
            binding_result = check_history_case_binding(
                history_case_binding_document,
                query_document,
                qualifying[0],
                runtime_document,
                must_outcome_proof_document,
            )
        if binding_result["status"] == "INVALID":
            invalid_reasons.extend(binding_result["invalid_reasons"])
    invalid_reasons = _unique_reasons(invalid_reasons)
    if invalid_reasons:
        return {
            "schema": AUDIT_SCHEMA,
            "capture": {"status": "INVALID"},
            "operational_prune": {"status": "NOT_EVALUATED", "qualifying_event_count": len(qualifying)},
            "runtime_replication": replication,
            "outcome_eligibility": {
                "status": "NOT_ESTABLISHED",
                "method": "NONE",
                "unmet_obligations": ["INVALID_EVIDENCE_MUST_BE_REPAIRED_FIRST"],
                "must_outcome_proof": proof_result,
                "history_case_binding": binding_result,
            },
            "assessment": {"status": "INVALID_EVIDENCE"},
            "invalid_reasons": invalid_reasons,
        }
    operational = (
        {"status": "OPERATIONAL_PRUNE_OBSERVED", "qualifying_event_count": 1, "event": qualifying[0]}
        if qualifying
        else {"status": "OPERATIONAL_PRUNE_NOT_OBSERVED", "qualifying_event_count": 0}
    )
    if qualifying and proof_result["status"] == "VERIFIED" and binding_result["status"] == "VERIFIED":
        return {
            "schema": AUDIT_SCHEMA,
            "capture": {"status": "CAPTURE_COMPLETE"},
            "operational_prune": operational,
            "runtime_replication": replication,
            "outcome_eligibility": {
                "status": "ESTABLISHED",
                "method": "MUST_OUTCOME_PROOF_WITH_HISTORY_CASE_BINDING",
                "proof_digest_sha256": proof_result["proof_digest_sha256"],
                "derived_outcomes": proof_result["derived_outcomes"],
                "assumptions": proof_result["assumptions"],
                "history_case_binding": binding_result,
            },
            "assessment": {
                "status": "NONFACTORING",
                "scope": "EXACT_STOCK_R_V2_QUERY",
                "scope_digest_sha256": binding_result["scope_digest_sha256"],
                "certificate": f"NONFACTORING@{binding_result['scope_digest_sha256']}",
                "reason": "OPERATIONAL_PRUNE_WITH_DISTINCT_MUST_OUTCOMES",
            },
            "invalid_reasons": [],
        }
    missing = []
    if not qualifying:
        missing.append("NO_QUALIFYING_OPERATIONAL_PRUNE")
    if proof_result["status"] != "VERIFIED":
        missing.append("MUST_OUTCOME_PROOF_OR_FIXED_ENVIRONMENT_DETERMINISM")
    if proof_result["status"] == "VERIFIED" and binding_result["status"] != "VERIFIED":
        missing.append("HISTORY_CASE_BINDING")
    return {
        "schema": AUDIT_SCHEMA,
        "capture": {"status": "CAPTURE_COMPLETE"},
        "operational_prune": operational,
        "runtime_replication": replication,
        "outcome_eligibility": {
            "status": "NOT_ESTABLISHED",
            "method": "NONE",
            "unmet_obligations": missing,
            "must_outcome_proof": proof_result,
            "history_case_binding": binding_result,
        },
        "assessment": {"status": "UNKNOWN", "missing_obligations": missing},
        "invalid_reasons": [],
    }


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StockRV2Error(f"cannot read JSON {path}: {exc}") from exc


def _read_optional_json(path: Path, invalid_reasons: list[str], reason: str) -> Any | None:
    if not path.exists():
        return None
    try:
        return _read_json(path)
    except StockRV2Error:
        invalid_reasons.append(reason)
        return None


def _read_jsonl(path: Path) -> list[Any]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise StockRV2Error(f"cannot read JSONL {path}: {exc}") from exc
    rows = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise StockRV2Error(f"invalid JSON at {path}:{number}: {exc}") from exc
    return rows


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest_entry_path(value: Any, name: str, *, single_component: bool) -> PurePosixPath:
    raw = _require_str(value, name)
    path = PurePosixPath(raw)
    if raw in {".", ".."} or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise StockRV2Error(f"{name} must be a safe relative path")
    if single_component and len(path.parts) != 1:
        raise StockRV2Error(f"{name} must be a single file name")
    return path


def _closure_manifest_reasons(
    root: Path,
    manifest_path: Path,
    expected_digest: str,
    schema: str,
    base_dir: Path,
    digest_reason: str,
    entry_reason: str,
    *,
    single_component: bool,
) -> list[str]:
    reasons: list[str] = []
    try:
        raw = manifest_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected_digest:
            reasons.append(digest_reason)
        document = json.loads(raw.decode("utf-8"))
        manifest = _require_dict(document, manifest_path.name)
        if manifest.get("schema") != schema:
            raise StockRV2Error("closure manifest schema mismatch")
        entries = _require_list(manifest.get("entries"), "closure.entries")
        if not entries:
            raise StockRV2Error("closure manifest must not be empty")
        seen: set[str] = set()
        for index, raw_entry in enumerate(entries):
            entry = _require_dict(raw_entry, f"closure.entries[{index}]")
            rel = _manifest_entry_path(
                entry.get("path"),
                f"closure.entries[{index}].path",
                single_component=single_component,
            )
            rel_s = rel.as_posix()
            if rel_s in seen:
                raise StockRV2Error("duplicate closure manifest entry")
            seen.add(rel_s)
            expected_entry_digest = _require_sha256(entry.get("sha256"), f"closure.entries[{index}].sha256")
            expected_entry_size = _require_int(entry.get("size"), f"closure.entries[{index}].size")
            if expected_entry_size < 0:
                raise StockRV2Error("closure entry size must be nonnegative")
            file_path = base_dir.joinpath(*rel.parts)
            if (
                not file_path.is_file()
                or file_path.stat().st_size != expected_entry_size
                or _file_sha256(file_path) != expected_entry_digest
            ):
                reasons.append(entry_reason)
                break
    except (StockRV2Error, OSError, UnicodeDecodeError, json.JSONDecodeError):
        reasons.append(digest_reason)
    return reasons


def _bundle_integrity_reasons(
    root: Path, query: dict[str, Any], runtime: dict[str, Any]
) -> list[str]:
    """Check locally retained identity receipts without treating them as trust roots."""

    reasons: list[str] = []
    static = query["identity"]
    runtime_identity = runtime.get("identity") if isinstance(runtime.get("identity"), dict) else {}
    reasons.extend(
        _closure_manifest_reasons(
            root,
            root / "build" / "source-manifest.json",
            query["source_closure_sha256"],
            SOURCE_CLOSURE_SCHEMA,
            root / "build" / "source",
            "BUNDLE_SOURCE_CLOSURE_MISMATCH",
            "BUNDLE_SOURCE_ENTRY_MISMATCH",
            single_component=False,
        )
    )
    reasons.extend(
        _closure_manifest_reasons(
            root,
            root / "build" / "artifact-manifest.json",
            query["build_closure_sha256"],
            BUILD_CLOSURE_SCHEMA,
            root / "build",
            "BUNDLE_BUILD_CLOSURE_MISMATCH",
            "BUNDLE_BUILD_ENTRY_MISMATCH",
            single_component=True,
        )
    )
    receipts = (
        (
            root / "build" / "rac_v2_witness.bpf.o",
            static["object_sha256"],
            "BUNDLE_OBJECT_RECEIPT_MISMATCH",
        ),
        (root / "build" / "btf-vmlinux", static["btf_sha256"], "BUNDLE_BTF_RECEIPT_MISMATCH"),
        (
            root / "raw" / "xlated-rac_v2_single.txt",
            runtime_identity.get("xlated_sha256"),
            "BUNDLE_XLATED_RECEIPT_MISMATCH",
        ),
    )
    for path, expected, reason in receipts:
        try:
            if not isinstance(expected, str) or _file_sha256(path) != expected:
                reasons.append(reason)
        except OSError:
            reasons.append(reason)

    info_path = root / "raw" / "program-info.json"
    try:
        info = json.loads(info_path.read_text(encoding="utf-8"))
        if isinstance(info, list):
            if len(info) != 1 or not isinstance(info[0], dict):
                raise StockRV2Error("program-info must contain exactly one program")
            info = info[0]
        if not isinstance(info, dict):
            raise StockRV2Error("program-info must be an object")
        info_load_time = info.get("load_time")
        if (
            info.get("id") != runtime_identity.get("program_id")
            or info.get("tag") != runtime_identity.get("program_tag")
            or info.get("name") != runtime_identity.get("program_name")
            or (info_load_time is not None and info_load_time != runtime_identity.get("program_load_time"))
        ):
            reasons.append("BUNDLE_PROGRAM_INFO_MISMATCH")
    except (StockRV2Error, OSError, json.JSONDecodeError):
        reasons.append("BUNDLE_PROGRAM_INFO_MISMATCH")
    return reasons


def audit_bundle(bundle: str | Path) -> dict[str, Any]:
    """Load the documented V2 bundle layout and audit its raw capture facts."""

    root = Path(bundle)
    query = _read_json(root / "query" / "query.json")
    policy = _read_json(root / "query" / "selection-policy.json")
    precommit = _read_json(root / "query" / "precommit.json")
    runtime = _read_json(root / "raw" / "runtime.json")
    validated_query = _query(query)
    extra_invalid_reasons = _bundle_integrity_reasons(root, validated_query, runtime)
    proof = _read_optional_json(
        root / MUST_OUTCOME_PROOF_PATH,
        extra_invalid_reasons,
        "MUST_OUTCOME_PROOF_JSON_INVALID",
    )
    history_case_binding = _read_optional_json(
        root / HISTORY_CASE_BINDING_PATH,
        extra_invalid_reasons,
        "HISTORY_CASE_BINDING_JSON_INVALID",
    )
    return audit_capture(
        query,
        policy,
        precommit,
        _read_jsonl(root / "raw" / "events.jsonl"),
        runtime,
        _read_json(root / "contract" / "capture-contract.json"),
        extra_invalid_reasons=extra_invalid_reasons,
        must_outcome_proof_document=proof,
        history_case_binding_document=history_case_binding,
    )
