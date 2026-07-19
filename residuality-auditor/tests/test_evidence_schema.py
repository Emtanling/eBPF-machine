import copy
import hashlib
import json
import unittest
from pathlib import Path

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
STOCK_BUNDLE = ROOT / "stock-linux-r-proof"
STOCK_HARNESS = ROOT / "linux" / "witness" / "rac_witness.c"
ZERO = "0" * 64
ONE = "1" * 64
TWO = "2" * 64
THREE = "3" * 64
FOUR = "4" * 64
FIVE = "5" * 64
SIX = "6" * 64
SEVEN = "7" * 64
EIGHT = "8" * 64
NINE = "9" * 64


def _load_schema(name):
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


SCHEMAS = {
    "query": _load_schema("query-v1.schema.json"),
    "evidence": _load_schema("evidence-v1.schema.json"),
    "assessment": _load_schema("assessment-v1.schema.json"),
}
VALIDATORS = {
    name: Draft202012Validator(schema, format_checker=FormatChecker())
    for name, schema in SCHEMAS.items()
}


def _schema_errors(kind, document):
    return sorted(
        (error.json_path, error.message)
        for error in VALIDATORS[kind].iter_errors(document)
    )


def _has_schema_errors(kind, document):
    return next(VALIDATORS[kind].iter_errors(document), None) is not None


def _canonical_digest(value):
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def _json_pointer_value(document, pointer):
    value = document
    for token in pointer.lstrip("/").split("/"):
        if not isinstance(value, dict) or token not in value:
            return None
        value = value[token]
    return value


def _normalize_canonical_query(canonical_query):
    normalized = copy.deepcopy(canonical_query)
    set_arrays = SCHEMAS["query"]["x-rac-canonicalization"]["set_arrays"]
    for pointer, identifier_field in set_arrays.items():
        values = _json_pointer_value(normalized, pointer)
        if values is None:
            continue
        identifiers = set()
        for item in values:
            identifier = item if identifier_field == "$value" else item[identifier_field]
            if identifier in identifiers:
                raise ValueError(f"duplicate canonical identifier at {pointer}: {identifier}")
            identifiers.add(identifier)
        values.sort(
            key=(
                (lambda item: item)
                if identifier_field == "$value"
                else (lambda item: item[identifier_field])
            )
        )
    return normalized


def _canonical_query_digest(canonical_query):
    return _canonical_digest(_normalize_canonical_query(canonical_query))


def _canonical_document_digest(document):
    """Digest the canonical bytes used as fixture file bytes in this U1 contract."""
    return _canonical_digest(document)


def _target_system_identity_digest(query):
    normalized = _normalize_canonical_query(query["canonical_query"])
    return _canonical_digest(normalized["scope"]["target_system"])


def _scope_digest(query):
    normalized = _normalize_canonical_query(query["canonical_query"])
    return _canonical_digest(normalized["scope"])


def _bind_query(query):
    query = copy.deepcopy(query)
    digest = _canonical_query_digest(query["canonical_query"])
    query["query_digest_sha256"] = digest
    query["freeze"]["frozen_digest_sha256"] = digest
    if "precommit_ref" in query["freeze"]:
        query["freeze"]["precommit_ref"][
            "recorded_query_digest_sha256"
        ] = digest
    return query


def _manifest_index(evidence):
    index = {}
    duplicates = set()
    for descriptor in evidence["provenance"]["manifest"]:
        source_ref = descriptor["source_ref"]
        if source_ref in index:
            duplicates.add(source_ref)
        else:
            index[source_ref] = descriptor
    return index, duplicates


def _resolved_manifest_descriptors(index, source_refs):
    missing = set(source_refs) - set(index)
    if missing:
        raise ValueError(f"unmanifested source refs: {sorted(missing)}")
    return [copy.deepcopy(index[source_ref]) for source_ref in sorted(source_refs)]


def _eligibility_binding_digest(query, evidence, summary):
    manifest, duplicate_manifest_refs = _manifest_index(evidence)
    if duplicate_manifest_refs:
        raise ValueError(
            f"duplicate manifest source refs: {sorted(duplicate_manifest_refs)}"
        )
    history_outcomes = sorted(
        (
            {
                "history_id": item["history_id"],
                "outcome_ids": sorted(item["outcome_ids"]),
            }
            for item in summary["history_outcomes"]
        ),
        key=lambda item: item["history_id"],
    )
    history_ids = {item["history_id"] for item in history_outcomes}
    relevant_histories = sorted(
        (
            copy.deepcopy(item)
            for item in evidence["facts"]["histories"]
            if item["history_id"] in history_ids
        ),
        key=lambda item: (item["history_id"], _canonical_digest(item)),
    )
    relevant_path_constraints = sorted(
        (
            copy.deepcopy(item)
            for item in evidence["facts"]["path_constraints"]
            if item["history_id"] in history_ids
        ),
        key=lambda item: (item["constraint_id"], _canonical_digest(item)),
    )
    relevant_observations = sorted(
        (
            copy.deepcopy(item)
            for item in evidence["facts"]["observations"]
            if item["history_id"] in history_ids
            and item["context_id"] == summary["context_id"]
            and item["suffix_id"] == summary["suffix_id"]
        ),
        key=lambda item: (item["observation_id"], _canonical_digest(item)),
    )
    relevant_facts = (
        relevant_histories + relevant_path_constraints + relevant_observations
    )
    fact_source_refs = {
        source_ref
        for fact in relevant_facts
        for source_ref in fact["source_refs"]
    }

    trust_by_id = {}
    for assumption in evidence["trust_assumptions"]:
        assumption_id = assumption["assumption_id"]
        if assumption_id in trust_by_id:
            raise ValueError(f"duplicate trust assumption: {assumption_id}")
        trust_by_id[assumption_id] = assumption
    resolved_trust = []
    for assumption_id in sorted(summary["trust_assumption_refs"]):
        assumption = trust_by_id.get(assumption_id)
        if assumption is None:
            raise ValueError(f"unknown trust assumption: {assumption_id}")
        resolved_trust.append(
            {
                "assumption": copy.deepcopy(assumption),
                "basis_manifest": _resolved_manifest_descriptors(
                    manifest, assumption["basis_refs"]
                ),
            }
        )

    return _canonical_digest(
        {
            "query_digest_sha256": query["query_digest_sha256"],
            "scope_digest_sha256": _scope_digest(query),
            "environment_digest_sha256": _canonical_digest(
                _normalize_canonical_query(query["canonical_query"])["environment"]
            ),
            "context_id": summary["context_id"],
            "suffix_id": summary["suffix_id"],
            "observer_id": summary["observer_id"],
            "method": summary["method"],
            "history_outcomes": history_outcomes,
            "relevant_facts": {
                "histories": relevant_histories,
                "path_constraints": relevant_path_constraints,
                "observations": relevant_observations,
            },
            "fact_source_manifest": _resolved_manifest_descriptors(
                manifest, fact_source_refs
            ),
            "basis_manifest": _resolved_manifest_descriptors(
                manifest, summary["basis_refs"]
            ),
            "resolved_trust_assumptions": resolved_trust,
        }
    )


def _defined_query():
    return _bind_query(
        {
            "schema": "rac-query-v1",
            "query_id": "q.control.exact",
            "canonical_query": {
                "scope": {
                    "scope_id": "scope.control.exact",
                    "artifact": {
                        "artifact_id": "control-model",
                        "kind": "FINITE_MODEL",
                        "sha256": ZERO,
                    },
                    "target_system": {
                        "system_id": "control-system",
                        "identity": [
                            {"name": "version", "value": "1"},
                            {"name": "architecture", "value": "abstract"},
                        ],
                    },
                    "frontier_id": "frontier.join",
                    "context_id": "ctx.fixed",
                },
                "report_rule": {
                    "defined": True,
                    "rule_id": "report.coarse",
                    "relation_semantics": "PARTIAL_MEMBERSHIP_RELATION",
                    "source_kind": "RESEARCHER_DECLARED",
                },
                "observer": {
                    "defined": True,
                    "observer_id": "observer.result",
                    "projection": ["result"],
                    "equivalence": "OUTCOME_ID_EQUALITY",
                },
                "continuation_universe": {
                    "universe_id": "suffixes.control",
                    "no_fresh_elements": True,
                    "suffixes": [
                        {"suffix_id": "suffix.shared", "actions": ["step"]}
                    ],
                },
                "environment": {
                    "environment_id": "env.fixed",
                    "parameters": [
                        {
                            "name": "serialized",
                            "semantic_kind": "EXECUTION_SERIALIZATION",
                            "value": True,
                        },
                        {
                            "name": "reset_protocol",
                            "semantic_kind": "RESET_PROTOCOL",
                            "value": "fresh-instance",
                        },
                    ],
                },
                "admissible_assumptions": [
                    {
                        "assumption_id": "assume.serialized",
                        "kind": "ENVIRONMENT",
                        "environment_parameter_ref": "serialized",
                        "predicate": "EQUALS",
                        "value": True,
                    }
                ],
                "bounded_completion": {
                    "fragment": "BOUNDED_NO_FRESH_V1",
                    "require_nonempty": True,
                    "no_fresh_elements": True,
                    "universes": {
                        "histories": ["h.left", "h.right"],
                        "report_cells": ["cell.shared"],
                        "outcomes": [
                            {"outcome_id": "out.ok", "value": {"result": 1}},
                            {"outcome_id": "out.fail", "value": {"result": 0}},
                        ],
                        "contexts": ["ctx.fixed"],
                    },
                    "max_cardinalities": {
                        "histories": 2,
                        "report_cells": 1,
                        "suffixes": 1,
                        "outcomes": 2,
                        "contexts": 1,
                        "report_memberships": 2,
                        "observations": 4,
                        "completions": 64,
                    },
                    "totalization": {
                        "report_membership": "ENUMERATE_PARTIAL_RELATION_EXTENSIONS",
                        "observations": "ENUMERATE_PARTIAL_RELATION_EXTENSIONS",
                        "absent_fact": "UNKNOWN_NOT_FALSE",
                    },
                    "canonical_enumeration_order": [
                        "history_id",
                        "report_cell_id",
                        "context_id",
                        "suffix_id",
                        "outcome_id",
                    ],
                },
                "resource_bounds": {
                    "max_files": 64,
                    "max_total_bytes": 1048576,
                    "max_json_nesting": 32,
                    "max_cpu_milliseconds": 10000,
                    "max_wall_milliseconds": 20000,
                    "max_memory_bytes": 67108864,
                },
            },
            "query_digest_sha256": ZERO,
            "freeze": {
                "audit_query_frozen": True,
                "frozen_digest_sha256": ZERO,
                "contract_precommitted": False,
                "selection_timing": "RETROSPECTIVE",
                "outcome_free_definition": False,
            },
        }
    )


def _precommitted_query():
    query = _defined_query()
    query["freeze"].update(
        {
            "contract_precommitted": True,
            "selection_timing": "PROSPECTIVE",
            "outcome_free_definition": True,
            "precommit_ref": {
                "path": "freeze/precommit.json",
                "file_sha256": SIX,
                "recorded_query_digest_sha256": ZERO,
                "recorded_selection_policy_sha256": SEVEN,
            },
        }
    )
    return _bind_query(query)


def _coverage(status="OPEN"):
    semantic = {
        "status": status,
        "basis_refs": (
            ["proof.factoring", "checker.factoring"] if status == "CLOSED" else []
        ),
        "missing_obligations": [] if status == "CLOSED" else ["coverage.not-closed"],
    }
    return {
        "capture_accounting": {
            "status": "COMPLETE",
            "basis_refs": ["raw-runtime"],
            "missing_obligations": [],
        },
        "history": copy.deepcopy(semantic),
        "report": copy.deepcopy(semantic),
        "transition_outcome": copy.deepcopy(semantic),
        "continuation": copy.deepcopy(semantic),
        "environment_determinism": copy.deepcopy(semantic),
    }


def _evidence(query, *, eligible=False, semantic_status="OPEN"):
    eligibility = {
        "eligibility_id": "eligibility.pair",
        "status": "ESTABLISHED" if eligible else "NOT_ESTABLISHED",
        "method": "MUST_OUTCOME_PROOF" if eligible else "NONE",
        "history_outcomes": [
            {"history_id": "h.left", "outcome_ids": ["out.ok"]},
            {"history_id": "h.right", "outcome_ids": ["out.fail"]},
        ],
        "context_id": "ctx.fixed",
        "suffix_id": "suffix.shared",
        "observer_id": "observer.result",
        "basis_refs": (
            ["raw-runtime", "proof.eligibility", "checker.eligibility"]
            if eligible
            else []
        ),
        "trust_assumption_refs": ["trust.capture"],
        "unmet_obligations": [] if eligible else ["must-outcome.not-established"],
    }
    selection_provenance = {
        "selection_timing": query["freeze"]["selection_timing"],
        "contract_precommitted": query["freeze"]["contract_precommitted"],
        "query_digest_consumed": query["query_digest_sha256"],
        "outcome_free_definition": query["freeze"]["outcome_free_definition"],
    }
    if query["freeze"]["contract_precommitted"]:
        selection_provenance.update(
            {
                "selection_policy_ref": {
                    "policy_id": "policy.control",
                    "path": "freeze/selection-policy.json",
                    "sha256": query["freeze"]["precommit_ref"][
                        "recorded_selection_policy_sha256"
                    ],
                },
                "precommit_ref": copy.deepcopy(query["freeze"]["precommit_ref"]),
            }
        )
    query_file_sha256 = _canonical_document_digest(query)
    provenance_manifest = [
        {
            "source_ref": "query.document",
            "path": "queries/control.json",
            "role": "QUERY",
            "sha256": query_file_sha256,
            "size": 1024,
        },
        {
            "source_ref": "raw-runtime",
            "path": "raw/runtime.json",
            "role": "RAW_FACT",
            "sha256": ZERO,
            "size": 100,
        },
    ]
    if query["freeze"]["contract_precommitted"]:
        provenance_manifest.extend(
            [
                {
                    "source_ref": "freeze.precommit",
                    "path": query["freeze"]["precommit_ref"]["path"],
                    "role": "PRECOMMITMENT",
                    "sha256": query["freeze"]["precommit_ref"]["file_sha256"],
                    "size": 256,
                },
                {
                    "source_ref": "policy.control",
                    "path": selection_provenance["selection_policy_ref"]["path"],
                    "role": "SELECTION_POLICY",
                    "sha256": selection_provenance["selection_policy_ref"]["sha256"],
                    "size": 256,
                },
            ]
        )
    if eligible:
        provenance_manifest.extend(
            [
                {
                    "source_ref": "proof.eligibility",
                    "path": "proof/eligibility.json",
                    "role": "OUTCOME_ELIGIBILITY_PROOF",
                    "sha256": FOUR,
                    "size": 256,
                },
                {
                    "source_ref": "checker.eligibility",
                    "path": "checkers/eligibility.bin",
                    "role": "CHECKER",
                    "sha256": FIVE,
                    "size": 512,
                },
            ]
        )
    if semantic_status == "CLOSED":
        provenance_manifest.extend(
            [
                {
                    "source_ref": "proof.factoring",
                    "path": "proof/factoring.json",
                    "role": "FACTORIZATION_PROOF",
                    "sha256": EIGHT,
                    "size": 256,
                },
                {
                    "source_ref": "checker.factoring",
                    "path": "checkers/factoring.bin",
                    "role": "CHECKER",
                    "sha256": NINE,
                    "size": 512,
                },
            ]
        )

    evidence = {
        "schema": "rac-evidence-v1",
        "evidence_id": "e.control.partial",
        "query_ref": {
            "query_id": query["query_id"],
            "query_digest_sha256": query["query_digest_sha256"],
            "path": "queries/control.json",
            "file_sha256": query_file_sha256,
        },
        "scope_identity": {
            "scope_id": "scope.control.exact",
            "scope_digest_sha256": _scope_digest(query),
            "artifact_id": "control-model",
            "artifact_sha256": ZERO,
            "target_system_identity_sha256": _target_system_identity_digest(query),
            "frontier_id": "frontier.join",
            "context_id": "ctx.fixed",
        },
        "selection_provenance": selection_provenance,
        "provenance": {
            "bundle_root_id": "bundle.control",
            "source_bundle_digest_sha256": THREE,
            "immutable_input": True,
            "manifest": provenance_manifest,
            "transformations": [],
        },
        "facts": {
            "histories": [
                {
                    "history_id": "h.left",
                    "context_id": "ctx.fixed",
                    "source_refs": ["raw-runtime"],
                },
                {
                    "history_id": "h.right",
                    "context_id": "ctx.fixed",
                    "source_refs": ["raw-runtime"],
                },
            ],
            "path_constraints": [],
            "report_memberships": [
                {
                    "history_id": "h.left",
                    "report_cell_id": "cell.shared",
                    "membership": "MEMBER",
                    "source_refs": ["raw-runtime"],
                },
                {
                    "history_id": "h.right",
                    "report_cell_id": "cell.shared",
                    "membership": "MEMBER",
                    "source_refs": ["raw-runtime"],
                },
            ],
            "observations": [
                {
                    "observation_id": "obs.left.1",
                    "history_id": "h.left",
                    "context_id": "ctx.fixed",
                    "suffix_id": "suffix.shared",
                    "outcome_id": "out.ok",
                    "trial_id": "trial.left.1",
                    "mode": "OBSERVED_SAMPLE",
                    "source_refs": ["raw-runtime"],
                },
                {
                    "observation_id": "obs.right.1",
                    "history_id": "h.right",
                    "context_id": "ctx.fixed",
                    "suffix_id": "suffix.shared",
                    "outcome_id": "out.fail",
                    "trial_id": "trial.right.1",
                    "mode": "OBSERVED_SAMPLE",
                    "source_refs": ["raw-runtime"],
                },
            ],
        },
        "coverage": _coverage(semantic_status),
        "outcome_eligibility_summaries": [eligibility],
        "trust_assumptions": [
            {
                "assumption_id": "trust.capture",
                "kind": "CAPTURE_FIDELITY",
                "status": "SUPPORTED" if eligible else "DECLARED_NOT_PROVED",
                "basis_refs": ["raw-runtime"],
            }
        ],
    }
    if eligible:
        eligibility["eligibility_proof"] = {
            "proof_ref": "proof.eligibility",
            "proof_digest_sha256": FOUR,
            "checker_ref": "checker.eligibility",
            "checker_digest_sha256": FIVE,
            "bound_input_digest_sha256": ZERO,
        }
        eligibility["eligibility_proof"][
            "bound_input_digest_sha256"
        ] = _eligibility_binding_digest(query, evidence, eligibility)
    return evidence


def _assessment(query, evidence, verdict="UNKNOWN"):
    status_map = {
        key: value["status"] for key, value in evidence["coverage"].items()
    }
    assessment = {
        "schema": "rac-assessment-v1",
        "assessment_id": "a.control.exact",
        "query_ref": {
            "query_id": query["query_id"],
            "query_digest_sha256": query["query_digest_sha256"],
        },
        "evidence_ref": {
            "evidence_id": evidence["evidence_id"],
            "evidence_digest_sha256": _canonical_digest(evidence),
            "path": "evidence/control.json",
            "file_sha256": _canonical_document_digest(evidence),
        },
        "scope": copy.deepcopy(evidence["scope_identity"]),
        "assessment_status": "ASSESSED",
        "verdict": verdict,
        "coverage": status_map,
        "provenance_digest_sha256": evidence["provenance"][
            "source_bundle_digest_sha256"
        ],
        "selection_provenance": copy.deepcopy(evidence["selection_provenance"]),
        "trust_assumption_refs": ["trust.capture"],
        "related_assessments": [],
    }
    if verdict == "UNKNOWN":
        assessment["decision_basis"] = {
            "kind": "MISSING_OBLIGATIONS",
            "missing_obligations": ["must-outcome.not-established"],
        }
    elif verdict == "NONFACTORING":
        assessment["decision_basis"] = {
            "kind": "ROBUST_WITNESS",
            "witnesses": [
                {
                    "left_history_id": "h.left",
                    "right_history_id": "h.right",
                    "report_cell_id": "cell.shared",
                    "context_id": "ctx.fixed",
                    "suffix_id": "suffix.shared",
                    "left_outcome_id": "out.ok",
                    "right_outcome_id": "out.fail",
                    "outcome_eligibility_ref": "eligibility.pair",
                }
            ],
        }
    elif verdict == "FACTORING":
        assessment["decision_basis"] = {
            "kind": "CLOSED_FINITE_PROOF",
            "completion_count": 1,
            "proof_ref": "proof.factoring",
            "proof_digest_sha256": EIGHT,
            "checker_ref": "checker.factoring",
            "checker_digest_sha256": NINE,
            "input_refs": ["query.document", "raw-runtime"],
            "bound_query_digest_sha256": query["query_digest_sha256"],
            "bound_scope_digest_sha256": evidence["scope_identity"][
                "scope_digest_sha256"
            ],
            "bound_evidence_digest_sha256": _canonical_digest(evidence),
            "closure_dimensions": {
                "history": "CLOSED",
                "report": "CLOSED",
                "transition_outcome": "CLOSED",
                "continuation": "CLOSED",
                "environment_determinism": "CLOSED",
            },
        }
    return assessment


def _stock_manifested_json(manifest, path, source_ref, role):
    """Read one selected frozen input and verify its manifest descriptor."""
    descriptor = manifest["files"][path]
    raw = (STOCK_BUNDLE / path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != descriptor["sha256"]:
        raise AssertionError(f"frozen digest mismatch: {path}")
    if len(raw) != descriptor["size"]:
        raise AssertionError(f"frozen size mismatch: {path}")
    return json.loads(raw), {
        "source_ref": source_ref,
        "path": path,
        "role": role,
        "sha256": descriptor["sha256"],
        "size": descriptor["size"],
    }


def _stock_linux_inputs():
    """Load only identity, runtime, and operational-prune premises from V1."""
    manifest_raw = (STOCK_BUNDLE / "MANIFEST.json").read_bytes()
    manifest = json.loads(manifest_raw)
    selected = {}
    descriptors = []
    for name, path, role in (
        ("kernel", "raw/kernel/kernel-identity.json", "IDENTITY"),
        ("program", "raw/object/program-info.json", "IDENTITY"),
        ("runtime", "raw/runtime/runtime.json", "RAW_FACT"),
        ("contract", "raw/runtime/contract.json", "RAW_FACT"),
        ("prune_edges", "normalized/report/prune-edges.json", "NORMALIZED_FACT"),
        (
            "prune_definition",
            "normalized/report/prune-cell-definition.json",
            "NORMALIZED_FACT",
        ),
        (
            "prune_coverage",
            "normalized/report/prune-cell-coverage.json",
            "NORMALIZED_FACT",
        ),
    ):
        value, descriptor = _stock_manifested_json(
            manifest, path, f"stock.{name}", role
        )
        selected[name] = value
        descriptors.append(descriptor)

    # Deliberately ignore MANIFEST.final_verdict, definition2_verdict, and all
    # proof/factorization, proof/definition2, quotient, verdict, and result files.
    tuple_identity = {
        key: manifest["frozen_tuple"][key]
        for key in (
            "btf_sha256",
            "config_sha256",
            "kernel_release",
            "object_sha256",
            "program_id",
            "program_pin",
            "program_tag",
            "xlated_sha256",
        )
    }
    runtime = selected["runtime"]
    kernel = selected["kernel"]
    program = selected["program"]
    if runtime["kernel_release"] != tuple_identity["kernel_release"]:
        raise AssertionError("runtime kernel does not match frozen tuple")
    if runtime["object_sha256"] != tuple_identity["object_sha256"]:
        raise AssertionError("runtime object does not match frozen tuple")
    if runtime["xlated_sha256"] != tuple_identity["xlated_sha256"]:
        raise AssertionError("runtime xlated code does not match frozen tuple")
    if runtime["program_id"] != tuple_identity["program_id"]:
        raise AssertionError("runtime program id does not match frozen tuple")
    if runtime["program_tag"] != tuple_identity["program_tag"]:
        raise AssertionError("runtime program tag does not match frozen tuple")
    if kernel["btf"]["sha256"] != tuple_identity["btf_sha256"]:
        raise AssertionError("BTF does not match frozen tuple")
    if kernel["config"]["sha256"] != tuple_identity["config_sha256"]:
        raise AssertionError("kernel config does not match frozen tuple")
    if program["id"] != tuple_identity["program_id"] or program["tag"] != tuple_identity[
        "program_tag"
    ]:
        raise AssertionError("program identity does not match frozen tuple")
    return {
        **selected,
        "tuple_identity": tuple_identity,
        "manifest_digest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "descriptors": descriptors,
    }


def _stock_linux_query(stock, *, broader_runs=False, undefined_report=False):
    query = _defined_query()
    runtime = stock["runtime"]
    tuple_identity = stock["tuple_identity"]
    edge = stock["prune_edges"]["edges"][0]
    scope = query["canonical_query"]["scope"]
    query["query_id"] = (
        "q.stock-linux-v1.broader-runs"
        if broader_runs
        else "q.stock-linux-v1.exact-operational-prune"
    )
    scope.update(
        {
            "scope_id": (
                "scope.stock-linux-v1.broader-runs"
                if broader_runs
                else "scope.stock-linux-v1.exact"
            ),
            "artifact": {
                "artifact_id": "rac-witness-bpf-object",
                "kind": "EBPF_OBJECT",
                "sha256": tuple_identity["object_sha256"],
            },
            "target_system": {
                "system_id": "stock-linux-v1-frozen-tuple",
                "identity": [
                    {"name": key, "value": value}
                    for key, value in tuple_identity.items()
                ]
                + [
                    {
                        "name": "runtime_context_sha256",
                        "value": _canonical_digest(runtime["runs"][0]["context"]),
                    },
                    {"name": "visit_insn", "value": edge["visit_insn"]},
                    {
                        "name": "current_state_hash",
                        "value": edge["current_state_hash"],
                    },
                    {
                        "name": "retained_state_hash",
                        "value": edge["retained_state_hash"],
                    },
                ],
            },
            "frontier_id": "frontier.visit-insn-41",
            "context_id": "ctx.stock-linux-v1",
        }
    )
    if undefined_report:
        query["canonical_query"]["report_rule"] = {
            "defined": False,
            "rule_id": "report.linux.functional",
            "relation_semantics": "PARTIAL_MEMBERSHIP_RELATION",
            "source_kind": "TARGET_CONTRACT_UNDEFINED",
            "undefined_reason": "No Linux-specified functional report contract is identified.",
        }
    else:
        query["canonical_query"]["report_rule"].update(
            {
                "rule_id": "report.operational-prune-cell-1",
                "source_kind": "OPERATIONAL_OBSERVATION",
            }
        )
    query["canonical_query"]["observer"].update(
        {
            "observer_id": "observer.runtime-result",
            "projection": ["retval", "success"],
            "equivalence": "CANONICAL_JSON_EQUALITY",
        }
    )
    query["canonical_query"]["continuation_universe"] = {
        "universe_id": "suffixes.stock-linux-v1",
        "no_fresh_elements": True,
        "suffixes": [
            {
                "suffix_id": "suffix.shared",
                "actions": ["shared-post-join-insert-fresh-key-B"],
            }
        ],
    }
    query["canonical_query"]["environment"]["environment_id"] = (
        "env.stock-linux-v1"
    )
    for parameter in query["canonical_query"]["environment"]["parameters"]:
        if parameter["name"] == "reset_protocol":
            parameter["value"] = "none"
    universes = query["canonical_query"]["bounded_completion"]["universes"]
    universes["histories"] = ["h.left", "h.right"]
    universes["contexts"] = [scope["context_id"]]
    if broader_runs:
        universes["histories"].append("h.unsampled")
    universes["outcomes"] = [
        {
            "outcome_id": "out.ok",
            "value": copy.deepcopy(runtime["runs"][0]["observation"]),
        },
        {
            "outcome_id": "out.fail",
            "value": copy.deepcopy(runtime["runs"][1]["observation"]),
        },
    ]
    query["canonical_query"]["bounded_completion"]["max_cardinalities"][
        "histories"
    ] = len(universes["histories"])
    return _bind_query(query)


def _stock_linux_evidence(query, stock):
    evidence = _evidence(query)
    canonical = query["canonical_query"]
    scope = canonical["scope"]
    runtime = stock["runtime"]
    edge = stock["prune_edges"]["edges"][0]
    coverage = stock["prune_coverage"]
    evidence["evidence_id"] = "e.stock-linux-v1.observed-samples"
    evidence["scope_identity"] = {
        "scope_id": scope["scope_id"],
        "scope_digest_sha256": _scope_digest(query),
        "artifact_id": scope["artifact"]["artifact_id"],
        "artifact_sha256": scope["artifact"]["sha256"],
        "target_system_identity_sha256": _target_system_identity_digest(query),
        "frontier_id": scope["frontier_id"],
        "context_id": scope["context_id"],
    }
    query_file = _manifest_entry(evidence, "query.document")
    evidence["provenance"] = {
        "bundle_root_id": "stock-linux-r-proof-v1-selected-premises",
        "source_bundle_digest_sha256": stock["manifest_digest_sha256"],
        "immutable_input": True,
        "manifest": [query_file] + copy.deepcopy(stock["descriptors"]),
        "transformations": [],
    }
    runs = runtime["runs"]
    evidence["facts"] = {
        "histories": [
            {
                "history_id": "h.left",
                "context_id": scope["context_id"],
                "attributes": {
                    "case": runs[0]["case"],
                    "selected_state": runs[0]["selected_state"],
                },
                "source_refs": ["stock.runtime", "stock.prune_coverage"],
            },
            {
                "history_id": "h.right",
                "context_id": scope["context_id"],
                "attributes": {
                    "case": runs[1]["case"],
                    "selected_state": runs[1]["selected_state"],
                },
                "source_refs": ["stock.runtime", "stock.prune_coverage"],
            },
        ],
        "path_constraints": [
            {
                "constraint_id": "path.frontier.left",
                "history_id": "h.left",
                "kind": "FRONTIER",
                "value": {
                    "visit_insn": edge["visit_insn"],
                    "state_hash": edge["current_state_hash"],
                },
                "source_refs": ["stock.prune_edges"],
            },
            {
                "constraint_id": "path.frontier.right",
                "history_id": "h.right",
                "kind": "FRONTIER",
                "value": {
                    "visit_insn": edge["visit_insn"],
                    "state_hash": edge["retained_state_hash"],
                },
                "source_refs": ["stock.prune_edges"],
            },
            {
                "constraint_id": "path.suffix.left",
                "history_id": "h.left",
                "kind": "COMMON_SUFFIX",
                "value": copy.deepcopy(runs[0]["suffix"]),
                "source_refs": ["stock.runtime", "stock.contract"],
            },
            {
                "constraint_id": "path.suffix.right",
                "history_id": "h.right",
                "kind": "COMMON_SUFFIX",
                "value": copy.deepcopy(runs[1]["suffix"]),
                "source_refs": ["stock.runtime", "stock.contract"],
            },
        ],
        "report_memberships": [
            {
                "history_id": "h.left",
                "report_cell_id": "cell.shared",
                "membership": "MEMBER",
                "source_refs": [
                    "stock.prune_coverage",
                    "stock.prune_definition",
                ],
            },
            {
                "history_id": "h.right",
                "report_cell_id": "cell.shared",
                "membership": "MEMBER",
                "source_refs": [
                    "stock.prune_coverage",
                    "stock.prune_definition",
                ],
            },
        ],
        "observations": [
            {
                "observation_id": "obs.stock.a0.1",
                "history_id": "h.left",
                "context_id": scope["context_id"],
                "suffix_id": "suffix.shared",
                "outcome_id": "out.ok",
                "trial_id": "trial.a0.1",
                "mode": "OBSERVED_SAMPLE",
                "source_refs": ["stock.runtime"],
            },
            {
                "observation_id": "obs.stock.a1.1",
                "history_id": "h.right",
                "context_id": scope["context_id"],
                "suffix_id": "suffix.shared",
                "outcome_id": "out.fail",
                "trial_id": "trial.a1.1",
                "mode": "OBSERVED_SAMPLE",
                "source_refs": ["stock.runtime"],
            },
        ],
    }
    evidence["coverage"] = {
        "capture_accounting": {
            "status": "UNKNOWN",
            "basis_refs": ["stock.runtime"],
            "missing_obligations": ["capture.trial-accounting"],
        },
        "history": {
            "status": "OPEN",
            "basis_refs": ["stock.prune_edges", "stock.prune_coverage"],
            "missing_obligations": ["history.closed-world-proof"],
        },
        "report": {
            "status": "OPEN",
            "basis_refs": ["stock.prune_definition", "stock.prune_coverage"],
            "missing_obligations": ["report.closed-world-proof"],
        },
        "transition_outcome": {
            "status": "OPEN",
            "basis_refs": ["stock.runtime"],
            "missing_obligations": ["outcome.must-proof"],
        },
        "continuation": {
            "status": "OPEN",
            "basis_refs": ["stock.runtime", "stock.contract"],
            "missing_obligations": ["continuation.exhaustive-proof"],
        },
        "environment_determinism": {
            "status": "UNKNOWN",
            "basis_refs": ["stock.runtime", "stock.contract"],
            "missing_obligations": ["environment.determinism-proof"],
        },
    }
    summary = evidence["outcome_eligibility_summaries"][0]
    summary.update(
        {
            "eligibility_id": "eligibility.stock-linux-v1",
            "status": "NOT_ESTABLISHED",
            "method": "NONE",
            "context_id": scope["context_id"],
            "observer_id": "observer.runtime-result",
            "basis_refs": ["stock.runtime", "stock.contract"],
            "trust_assumption_refs": [
                "trust.stock-harness",
                "trust.stock-interference",
            ],
            "unmet_obligations": [
                "must-outcome.not-established",
                "fixed-environment-determinism.not-established",
            ],
        }
    )
    evidence["trust_assumptions"] = [
        {
            "assumption_id": "trust.stock-harness",
            "kind": "HARNESS_CORRECTNESS",
            "status": "DECLARED_NOT_PROVED",
            "basis_refs": ["stock.runtime", "stock.contract"],
        },
        {
            "assumption_id": "trust.stock-interference",
            "kind": "NO_EXTERNAL_INTERFERENCE",
            "status": "DECLARED_NOT_PROVED",
            "basis_refs": ["stock.contract"],
        },
    ]
    if coverage["cases"]["a=0"]["representatives"] != coverage["cases"]["a=1"][
        "representatives"
    ]:
        raise AssertionError("frozen cases do not share an operational representative")
    return evidence


def _stock_unknown_assessment(query, evidence):
    assessment = _assessment(query, evidence)
    assessment["assessment_id"] = "a.stock-linux-v1.unknown"
    assessment["trust_assumption_refs"] = [
        "trust.stock-harness",
        "trust.stock-interference",
    ]
    assessment["decision_basis"]["missing_obligations"] = [
        "must-outcome.not-established",
        "fixed-environment-determinism.not-established",
    ]
    return assessment


def _manifest_entry(evidence, source_ref):
    index, duplicates = _manifest_index(evidence)
    return None if source_ref in duplicates else index.get(source_ref)


def _manifest_path_entry(evidence, path):
    matches = [
        item
        for item in evidence["provenance"]["manifest"]
        if item["path"] == path
    ]
    return matches[0] if len(matches) == 1 else None


def _eligibility_summary_errors(query, evidence, summary):
    if summary["status"] != "ESTABLISHED":
        return []
    errors = []
    history_ids = [item["history_id"] for item in summary["history_outcomes"]]
    if len(history_ids) != len(set(history_ids)):
        errors.append("eligibility-duplicate-history")
    proof = summary.get("eligibility_proof")
    if not proof:
        errors.append("eligibility-proof-ref")
        return errors
    proof_entry = _manifest_entry(evidence, proof["proof_ref"])
    checker_entry = _manifest_entry(evidence, proof["checker_ref"])
    if not proof_entry or proof_entry["role"] != "OUTCOME_ELIGIBILITY_PROOF":
        errors.append("eligibility-proof-ref")
    elif proof_entry["sha256"] != proof["proof_digest_sha256"]:
        errors.append("eligibility-proof-digest")
    if not checker_entry or checker_entry["role"] != "CHECKER":
        errors.append("eligibility-checker-ref")
    elif checker_entry["sha256"] != proof["checker_digest_sha256"]:
        errors.append("eligibility-checker-digest")
    if not {proof["proof_ref"], proof["checker_ref"]} <= set(
        summary["basis_refs"]
    ):
        errors.append("eligibility-proof-basis")
    try:
        expected_binding = _eligibility_binding_digest(query, evidence, summary)
    except ValueError:
        expected_binding = None
    if proof["bound_input_digest_sha256"] != expected_binding:
        errors.append("eligibility-proof-input-binding")

    trust = {
        item["assumption_id"]: item for item in evidence["trust_assumptions"]
    }
    if any(
        trust.get(ref, {}).get("status") != "SUPPORTED"
        or not trust.get(ref, {}).get("basis_refs")
        for ref in summary["trust_assumption_refs"]
    ):
        errors.append("eligibility-unproved-trust")
    return errors


def _precommit_combination_errors(value, required_refs):
    if not isinstance(value, dict) or "contract_precommitted" not in value:
        return []
    precommitted = value["contract_precommitted"]
    expected_timing = "PROSPECTIVE" if precommitted else "RETROSPECTIVE"
    expected_outcome_free = precommitted
    refs_present = all(ref in value for ref in required_refs)
    refs_absent = all(ref not in value for ref in required_refs)
    if (
        value.get("selection_timing") != expected_timing
        or value.get("outcome_free_definition") is not expected_outcome_free
        or (precommitted and not refs_present)
        or (not precommitted and not refs_absent)
    ):
        return ["precommit-combination"]
    return []


def _outcomes_equivalent(query, left_outcome_id, right_outcome_id):
    observer = query["canonical_query"]["observer"]
    if observer["equivalence"] == "OUTCOME_ID_EQUALITY":
        return left_outcome_id == right_outcome_id

    outcomes = {
        item["outcome_id"]: item["value"]
        for item in query["canonical_query"]["bounded_completion"]["universes"][
            "outcomes"
        ]
    }
    left = outcomes.get(left_outcome_id)
    right = outcomes.get(right_outcome_id)
    projection = observer["projection"]
    if (
        not isinstance(left, dict)
        or not isinstance(right, dict)
        or any(field not in left or field not in right for field in projection)
    ):
        return None
    return _canonical_digest({field: left[field] for field in projection}) == (
        _canonical_digest({field: right[field] for field in projection})
    )


def _bounded_completion_errors(canonical_query):
    bounded = canonical_query["bounded_completion"]
    universes = bounded["universes"]
    universe_sizes = {
        "histories": len(universes["histories"]),
        "report_cells": len(universes["report_cells"]),
        "suffixes": len(canonical_query["continuation_universe"]["suffixes"]),
        "outcomes": len(universes["outcomes"]),
        "contexts": len(universes["contexts"]),
    }
    errors = []
    for name, size in universe_sizes.items():
        if size > bounded["max_cardinalities"][name]:
            errors.append(f"{name}-universe-cardinality")
        if bounded["require_nonempty"] and size == 0:
            errors.append(f"empty-{name}-universe")
    return errors


def _query_validation(query):
    errors = _precommit_combination_errors(query.get("freeze"), ("precommit_ref",))
    if _has_schema_errors("query", query):
        errors.append("query-schema")
        return sorted(set(errors)), None
    try:
        digest = _canonical_query_digest(query["canonical_query"])
    except ValueError:
        return ["duplicate-query-identifier"], None
    if query["query_digest_sha256"] != digest:
        errors.append("query-digest")
    if query["freeze"]["frozen_digest_sha256"] != digest:
        errors.append("frozen-digest")
    errors.extend(_bounded_completion_errors(query["canonical_query"]))
    return sorted(set(errors)), digest


def _contract_errors(query, evidence):
    """Executable U1 cross-document contract; production validation belongs to U2."""
    errors, digest = _query_validation(query)
    if digest is None:
        return errors
    selection = evidence.get("selection_provenance", {})
    freeze = query["freeze"]
    errors.extend(
        _precommit_combination_errors(
            selection,
            ("selection_policy_ref", "precommit_ref"),
        )
    )
    for field in (
        "selection_timing",
        "contract_precommitted",
        "outcome_free_definition",
    ):
        if selection.get(field) != freeze[field]:
            errors.append(f"selection-{field.replace('_', '-')}-mismatch")
    if _has_schema_errors("evidence", evidence):
        errors.append("evidence-schema")
        return sorted(set(errors))

    manifest, duplicate_manifest_refs = _manifest_index(evidence)
    if duplicate_manifest_refs:
        errors.append("duplicate-manifest-source-ref")
    manifest_refs = set(manifest)

    qref = evidence["query_ref"]
    if qref["query_id"] != query["query_id"] or qref["query_digest_sha256"] != digest:
        errors.append("query-ref")
    if qref["file_sha256"] != _canonical_document_digest(query):
        errors.append("query-file-digest")
    if selection["query_digest_consumed"] != digest:
        errors.append("capture-query-ref")

    query_entry = _manifest_path_entry(evidence, qref["path"])
    if (
        not query_entry
        or query_entry["role"] != "QUERY"
        or query_entry["sha256"] != qref["file_sha256"]
    ):
        errors.append("query-file-ref")

    if freeze["contract_precommitted"]:
        precommit = freeze["precommit_ref"]
        evidence_precommit = selection.get("precommit_ref")
        policy = selection.get("selection_policy_ref")
        if precommit["recorded_query_digest_sha256"] != digest:
            errors.append("precommit-query-digest")
        if precommit != evidence_precommit:
            errors.append("precommit-ref-mismatch")
        if not policy:
            errors.append("selection-policy-ref")
            return sorted(set(errors))
        if precommit["recorded_selection_policy_sha256"] != policy["sha256"]:
            errors.append("precommit-policy-digest")
        precommit_entry = _manifest_path_entry(evidence, precommit["path"])
        if (
            not precommit_entry
            or precommit_entry["role"] != "PRECOMMITMENT"
            or precommit_entry["sha256"] != precommit["file_sha256"]
        ):
            errors.append("precommit-file-ref")
        policy_entry = _manifest_path_entry(evidence, policy["path"])
        if (
            not policy_entry
            or policy_entry["role"] != "SELECTION_POLICY"
            or policy_entry["sha256"] != policy["sha256"]
        ):
            errors.append("selection-policy-ref")

    canonical = query["canonical_query"]
    qscope = canonical["scope"]
    escope = evidence["scope_identity"]
    if any(
        qscope[name] != escope[name]
        for name in ("scope_id", "frontier_id", "context_id")
    ):
        errors.append("scope-mismatch")
    if qscope["artifact"]["artifact_id"] != escope["artifact_id"]:
        errors.append("artifact-id-mismatch")
    if qscope["artifact"]["sha256"] != escope["artifact_sha256"]:
        errors.append("artifact-hash-mismatch")
    if escope["target_system_identity_sha256"] != _target_system_identity_digest(
        query
    ):
        errors.append("target-system-identity-mismatch")
    if escope["scope_digest_sha256"] != _scope_digest(query):
        errors.append("scope-digest-mismatch")

    bounded = canonical["bounded_completion"]
    universes = bounded["universes"]
    histories = set(universes["histories"])
    cells = set(universes["report_cells"])
    contexts = set(universes["contexts"])
    outcomes = {item["outcome_id"] for item in universes["outcomes"]}
    suffixes = {
        item["suffix_id"] for item in canonical["continuation_universe"]["suffixes"]
    }
    if len(evidence["facts"]["histories"]) > bounded["max_cardinalities"]["histories"]:
        errors.append("history-cardinality")
    if len(evidence["facts"]["report_memberships"]) > bounded["max_cardinalities"][
        "report_memberships"
    ]:
        errors.append("membership-cardinality")
    if len(evidence["facts"]["observations"]) > bounded["max_cardinalities"][
        "observations"
    ]:
        errors.append("observation-cardinality")

    for item in evidence["facts"]["histories"]:
        if item["history_id"] not in histories or item["context_id"] not in contexts:
            errors.append("fresh-history-element")
        if not set(item["source_refs"]) <= manifest_refs:
            errors.append("unknown-source-ref")

    for item in evidence["facts"]["path_constraints"]:
        if item["history_id"] not in histories:
            errors.append("fresh-path-element")
        if not set(item["source_refs"]) <= manifest_refs:
            errors.append("unknown-source-ref")

    membership_values = {}
    for item in evidence["facts"]["report_memberships"]:
        if item["history_id"] not in histories or item["report_cell_id"] not in cells:
            errors.append("fresh-report-element")
        key = (item["history_id"], item["report_cell_id"])
        old = membership_values.setdefault(key, item["membership"])
        if old != item["membership"]:
            errors.append("conflicting-membership")
        if not set(item["source_refs"]) <= manifest_refs:
            errors.append("unknown-source-ref")

    observation_values = {}
    for item in evidence["facts"]["observations"]:
        if (
            item["history_id"] not in histories
            or item["context_id"] not in contexts
            or item["suffix_id"] not in suffixes
            or item["outcome_id"] not in outcomes
        ):
            errors.append("fresh-observation-element")
        key = (
            item["history_id"],
            item["context_id"],
            item["suffix_id"],
            item["trial_id"],
        )
        old = observation_values.setdefault(key, item["outcome_id"])
        if old != item["outcome_id"]:
            errors.append("conflicting-observation")
        if not set(item["source_refs"]) <= manifest_refs:
            errors.append("unknown-source-ref")

    paths = {}
    for item in evidence["provenance"]["manifest"]:
        old = paths.setdefault(item["path"], (item["sha256"], item["size"]))
        if old != (item["sha256"], item["size"]):
            errors.append("conflicting-provenance")

    for transformation in evidence["provenance"]["transformations"]:
        if transformation["tool_ref"] not in manifest_refs:
            errors.append("unknown-transformation-ref")
        elif manifest[transformation["tool_ref"]]["role"] != "TRANSFORM_TOOL":
            errors.append("invalid-transformation-tool-ref")
        if not set(transformation["input_refs"]) <= manifest_refs or not set(
            transformation["output_refs"]
        ) <= manifest_refs:
            errors.append("unknown-transformation-ref")

    for coverage in evidence["coverage"].values():
        if not set(coverage["basis_refs"]) <= manifest_refs:
            errors.append("unknown-coverage-basis-ref")

    environment_parameters = {
        item["name"]: item for item in canonical["environment"]["parameters"]
    }
    for assumption in canonical["admissible_assumptions"]:
        if assumption["kind"] == "ENVIRONMENT":
            parameter = environment_parameters.get(
                assumption["environment_parameter_ref"]
            )
            if not parameter:
                errors.append("inadmissible-assumption-ref")
            elif assumption["value"] != parameter["value"]:
                errors.append("inadmissible-assumption-value")

    trust_by_id = {}
    for assumption in evidence["trust_assumptions"]:
        assumption_id = assumption["assumption_id"]
        if assumption_id in trust_by_id:
            errors.append("duplicate-trust-assumption-id")
        else:
            trust_by_id[assumption_id] = assumption
        if not set(assumption["basis_refs"]) <= manifest_refs:
            errors.append("unknown-trust-basis-ref")
        if assumption["status"] == "SUPPORTED" and not assumption["basis_refs"]:
            errors.append("unsupported-empty-trust-basis")
    trust_ids = set(trust_by_id)
    eligibility_ids = set()
    for summary in evidence["outcome_eligibility_summaries"]:
        if summary["eligibility_id"] in eligibility_ids:
            errors.append("duplicate-eligibility-id")
        eligibility_ids.add(summary["eligibility_id"])
        if summary["context_id"] not in contexts or summary["suffix_id"] not in suffixes:
            errors.append("eligibility-scope")
        if summary["observer_id"] != canonical["observer"].get("observer_id"):
            errors.append("eligibility-observer")
        if not set(summary["basis_refs"]) <= manifest_refs:
            errors.append("unknown-eligibility-basis-ref")
        if not set(summary["trust_assumption_refs"]) <= trust_ids:
            errors.append("eligibility-trust-ref")
        for item in summary["history_outcomes"]:
            if item["history_id"] not in histories or not set(item["outcome_ids"]) <= outcomes:
                errors.append("eligibility-fresh-element")
        errors.extend(_eligibility_summary_errors(query, evidence, summary))
    return sorted(set(errors))


def _assessment_contract_errors(query, evidence, assessment):
    query_errors, _ = _query_validation(query)
    if query_errors:
        return query_errors
    errors = _precommit_combination_errors(
        assessment.get("selection_provenance"),
        ("selection_policy_ref", "precommit_ref"),
    )
    if "selection_provenance" in assessment and assessment.get(
        "selection_provenance"
    ) != evidence.get("selection_provenance"):
        errors.append("assessment-selection-provenance")
    if _has_schema_errors("assessment", assessment):
        errors.append("assessment-schema")
        return sorted(set(errors))
    canonical = query["canonical_query"]
    undefined_components = {
        name
        for name, component in (
            ("REPORT_RULE", canonical["report_rule"]),
            ("OBSERVER", canonical["observer"]),
        )
        if component["defined"] is False
    }
    if assessment["assessment_status"] == "OUT_OF_SCOPE":
        if assessment["query_ref"] != {
            "query_id": query["query_id"],
            "query_digest_sha256": query["query_digest_sha256"],
        }:
            errors.append("assessment-query-ref")
        if set(assessment["undefined_components"]) != undefined_components:
            errors.append("out-of-scope-component-mismatch")
        return sorted(set(errors))
    if assessment["assessment_status"] == "INVALID_EVIDENCE":
        return errors
    if undefined_components:
        errors.append("semantic-assessment-for-undefined-query")
    if assessment["query_ref"] != {
        "query_id": query["query_id"],
        "query_digest_sha256": query["query_digest_sha256"],
    }:
        errors.append("assessment-query-ref")
    evidence_ref = assessment["evidence_ref"]
    if evidence_ref["evidence_id"] != evidence["evidence_id"]:
        errors.append("assessment-evidence-ref")
    if evidence_ref["evidence_digest_sha256"] != _canonical_digest(evidence):
        errors.append("assessment-evidence-digest")
    if evidence_ref["file_sha256"] != _canonical_document_digest(evidence):
        errors.append("assessment-evidence-file-digest")
    if assessment["scope"] != evidence["scope_identity"]:
        errors.append("assessment-scope-mismatch")
    if (
        assessment["provenance_digest_sha256"]
        != evidence["provenance"]["source_bundle_digest_sha256"]
    ):
        errors.append("assessment-provenance-digest")
    if assessment["selection_provenance"] != evidence["selection_provenance"]:
        errors.append("assessment-selection-provenance")
    trust_by_id = {
        item["assumption_id"]: item for item in evidence["trust_assumptions"]
    }
    if not set(assessment["trust_assumption_refs"]) <= set(trust_by_id):
        errors.append("assessment-trust-ref")
    manifest, duplicate_manifest_refs = _manifest_index(evidence)
    if duplicate_manifest_refs:
        errors.append("duplicate-manifest-source-ref")
    if any(
        not set(trust_by_id[ref]["basis_refs"]) <= set(manifest)
        for ref in assessment["trust_assumption_refs"]
        if ref in trust_by_id
    ):
        errors.append("assessment-trust-basis-ref")
    if assessment["verdict"] == "NONFACTORING":
        eligibility = {
            item["eligibility_id"]: item
            for item in evidence["outcome_eligibility_summaries"]
        }
        member_facts = {
            (item["history_id"], item["report_cell_id"])
            for item in evidence["facts"]["report_memberships"]
            if item["membership"] == "MEMBER"
        }
        history_contexts = {
            (item["history_id"], item["context_id"])
            for item in evidence["facts"]["histories"]
        }
        observations = {
            (
                item["history_id"],
                item["context_id"],
                item["suffix_id"],
                item["outcome_id"],
            )
            for item in evidence["facts"]["observations"]
        }
        for witness in assessment["decision_basis"]["witnesses"]:
            summary = eligibility.get(witness["outcome_eligibility_ref"])
            if (
                not summary
                or summary["status"] != "ESTABLISHED"
                or _eligibility_summary_errors(query, evidence, summary)
            ):
                errors.append("witness-not-outcome-eligible")
                continue
            left_history = witness["left_history_id"]
            right_history = witness["right_history_id"]
            context = witness["context_id"]
            suffix = witness["suffix_id"]
            cell = witness["report_cell_id"]
            left_outcome = witness["left_outcome_id"]
            right_outcome = witness["right_outcome_id"]
            if left_history == right_history:
                errors.append("witness-histories-equal")
            if summary["context_id"] != context or context != canonical["scope"][
                "context_id"
            ]:
                errors.append("witness-context-mismatch")
            if summary["suffix_id"] != suffix:
                errors.append("witness-suffix-mismatch")
            if summary["observer_id"] != canonical["observer"].get("observer_id"):
                errors.append("witness-observer-mismatch")
            if (
                (left_history, context) not in history_contexts
                or (right_history, context) not in history_contexts
            ):
                errors.append("witness-history-fact-mismatch")
            if (
                (left_history, cell) not in member_facts
                or (right_history, cell) not in member_facts
            ):
                errors.append("witness-membership-mismatch")
            summary_outcomes = {
                item["history_id"]: item["outcome_ids"]
                for item in summary["history_outcomes"]
            }
            if summary_outcomes.get(left_history) != [left_outcome] or (
                summary_outcomes.get(right_history) != [right_outcome]
            ):
                errors.append("witness-outcome-mismatch")
            if (
                (left_history, context, suffix, left_outcome) not in observations
                or (right_history, context, suffix, right_outcome) not in observations
            ):
                errors.append("witness-observation-mismatch")
            equivalent = _outcomes_equivalent(query, left_outcome, right_outcome)
            if equivalent is None:
                errors.append("witness-observer-projection-missing")
            elif equivalent:
                errors.append("witness-outcomes-equal")
    if assessment["verdict"] == "FACTORING":
        basis = assessment["decision_basis"]
        closure = basis["closure_dimensions"]
        evidence_coverage = {
            name: value["status"] for name, value in evidence["coverage"].items()
        }
        if assessment["coverage"] != evidence_coverage:
            errors.append("assessment-coverage-mismatch")
        if any(
            evidence_coverage[name] != status or status != "CLOSED"
            for name, status in closure.items()
        ):
            errors.append("factoring-with-open-coverage")
        proof_entry = _manifest_entry(evidence, basis["proof_ref"])
        checker_entry = _manifest_entry(evidence, basis["checker_ref"])
        if not proof_entry or proof_entry["role"] != "FACTORIZATION_PROOF":
            errors.append("factoring-proof-ref")
        elif proof_entry["sha256"] != basis["proof_digest_sha256"]:
            errors.append("factoring-proof-digest")
        if not checker_entry or checker_entry["role"] != "CHECKER":
            errors.append("factoring-checker-ref")
        elif checker_entry["sha256"] != basis["checker_digest_sha256"]:
            errors.append("factoring-checker-digest")
        input_refs = set(basis["input_refs"])
        if not input_refs <= set(manifest):
            errors.append("factoring-proof-input-ref")
        proof_output_roles = {
            "OUTCOME_ELIGIBILITY_PROOF",
            "FACTORIZATION_PROOF",
            "CHECKER",
        }
        if any(
            ref in {basis["proof_ref"], basis["checker_ref"]}
            or manifest.get(ref, {}).get("role") in proof_output_roles
            for ref in input_refs
        ):
            errors.append("factoring-proof-output-as-input")
        query_entry = _manifest_path_entry(evidence, evidence["query_ref"]["path"])
        fact_source_refs = {
            ref
            for fact_kind in (
                "histories",
                "path_constraints",
                "report_memberships",
                "observations",
            )
            for fact in evidence["facts"][fact_kind]
            for ref in fact["source_refs"]
        }
        required_inputs = fact_source_refs
        if query_entry:
            required_inputs.add(query_entry["source_ref"])
        if not required_inputs <= input_refs:
            errors.append("factoring-proof-input-binding")
        if basis["bound_query_digest_sha256"] != query["query_digest_sha256"]:
            errors.append("factoring-query-binding")
        if basis["bound_scope_digest_sha256"] != _scope_digest(query) or basis[
            "bound_scope_digest_sha256"
        ] != evidence["scope_identity"]["scope_digest_sha256"]:
            errors.append("factoring-scope-binding")
        if basis["bound_evidence_digest_sha256"] != _canonical_digest(evidence):
            errors.append("factoring-evidence-binding")
        if basis["completion_count"] > canonical["bounded_completion"][
            "max_cardinalities"
        ]["completions"]:
            errors.append("factoring-completion-count")
    return sorted(set(errors))


class EvidenceSchemaTests(unittest.TestCase):
    def test_schemas_are_valid_draft_2020_12(self):
        for schema in SCHEMAS.values():
            Draft202012Validator.check_schema(schema)

    def test_defined_partial_evidence_and_unknown_assessment_are_valid(self):
        query = _defined_query()
        evidence = _evidence(query)
        assessment = _assessment(query, evidence)

        self.assertEqual([], _schema_errors("query", query))
        self.assertEqual([], _schema_errors("evidence", evidence))
        self.assertEqual([], _schema_errors("assessment", assessment))
        self.assertEqual([], _contract_errors(query, evidence))
        self.assertEqual([], _assessment_contract_errors(query, evidence, assessment))

    def test_capture_complete_does_not_close_semantic_coverage(self):
        query = _defined_query()
        evidence = _evidence(query)

        self.assertEqual("COMPLETE", evidence["coverage"]["capture_accounting"]["status"])
        for name in (
            "history",
            "report",
            "transition_outcome",
            "continuation",
            "environment_determinism",
        ):
            self.assertEqual("OPEN", evidence["coverage"][name]["status"])
        self.assertEqual([], _schema_errors("evidence", evidence))

    def test_partial_outcome_eligible_witness_requires_a_typed_synthetic_proof(self):
        query = _defined_query()
        evidence = _evidence(query, eligible=True)
        assessment = _assessment(query, evidence, "NONFACTORING")

        self.assertEqual([], _schema_errors("evidence", evidence))
        self.assertEqual([], _schema_errors("assessment", assessment))
        self.assertEqual([], _contract_errors(query, evidence))
        self.assertEqual([], _assessment_contract_errors(query, evidence, assessment))
        self.assertEqual("OPEN", evidence["coverage"]["report"]["status"])
        proof = evidence["outcome_eligibility_summaries"][0][
            "eligibility_proof"
        ]
        self.assertEqual("proof.eligibility", proof["proof_ref"])
        self.assertEqual("checker.eligibility", proof["checker_ref"])

    def test_raw_v1_shaped_samples_cannot_self_certify_must_outcomes(self):
        query = _defined_query()
        query["query_id"] = "q.v1.exact-operational-prune"
        query["canonical_query"]["report_rule"].update(
            {
                "rule_id": "report.operational-prune",
                "source_kind": "OPERATIONAL_OBSERVATION",
            }
        )
        query = _bind_query(query)
        evidence = _evidence(query, eligible=False)
        summary = evidence["outcome_eligibility_summaries"][0]
        summary.update(
            {
                "status": "ESTABLISHED",
                "method": "MUST_OUTCOME_PROOF",
                "basis_refs": ["raw-runtime"],
                "unmet_obligations": [],
                "eligibility_proof": {
                    "proof_ref": "raw-runtime",
                    "proof_digest_sha256": ZERO,
                    "checker_ref": "raw-runtime",
                    "checker_digest_sha256": ZERO,
                    "bound_input_digest_sha256": ZERO,
                },
            }
        )
        summary["eligibility_proof"][
            "bound_input_digest_sha256"
        ] = _eligibility_binding_digest(query, evidence, summary)

        self.assertEqual([], _schema_errors("evidence", evidence))
        errors = _contract_errors(query, evidence)
        self.assertIn("eligibility-proof-ref", errors)
        self.assertIn("eligibility-checker-ref", errors)
        self.assertIn("eligibility-unproved-trust", errors)

        raw_v1 = _evidence(query, eligible=False)
        self.assertEqual([], _contract_errors(query, raw_v1))
        self.assertEqual(
            [],
            _assessment_contract_errors(query, raw_v1, _assessment(query, raw_v1)),
        )

    def test_eligibility_proof_binds_exact_facts_manifest_and_resolved_trust(self):
        query = _defined_query()
        evidence = _evidence(query, eligible=True)
        self.assertEqual([], _contract_errors(query, evidence))

        mutations = (
            lambda value: value["facts"]["histories"][0].__setitem__(
                "attributes", {"branch": "mutated"}
            ),
            lambda value: value["facts"]["path_constraints"].append(
                {
                    "constraint_id": "path.mutated",
                    "history_id": "h.left",
                    "kind": "PREFIX_HISTORY",
                    "value": {"step": 1},
                    "source_refs": ["raw-runtime"],
                }
            ),
            lambda value: value["facts"]["observations"][0].__setitem__(
                "trial_id", "trial.left.changed"
            ),
            lambda value: _manifest_entry(value, "raw-runtime").__setitem__(
                "sha256", ONE
            ),
            lambda value: value["outcome_eligibility_summaries"][0][
                "basis_refs"
            ].remove("raw-runtime"),
            lambda value: value["trust_assumptions"][0].__setitem__(
                "kind", "HARNESS_CORRECTNESS"
            ),
            lambda value: value["trust_assumptions"][0]["basis_refs"].append(
                "query.document"
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                forged = copy.deepcopy(evidence)
                mutation(forged)
                self.assertIn(
                    "eligibility-proof-input-binding",
                    _contract_errors(query, forged),
                )

        unsupported_shape = copy.deepcopy(evidence)
        unsupported_shape["trust_assumptions"][0]["basis_refs"] = []
        self.assertTrue(_has_schema_errors("evidence", unsupported_shape))

    def test_every_manifest_reference_is_checked_through_one_unique_index(self):
        query = _defined_query()

        duplicate = _evidence(query)
        duplicate["provenance"]["manifest"].append(
            copy.deepcopy(_manifest_entry(duplicate, "raw-runtime"))
        )
        self.assertIn(
            "duplicate-manifest-source-ref", _contract_errors(query, duplicate)
        )

        reference_mutations = (
            (
                "history",
                lambda value: value["facts"]["histories"][0][
                    "source_refs"
                ].append("missing.source"),
                "unknown-source-ref",
            ),
            (
                "path",
                lambda value: value["facts"]["path_constraints"].append(
                    {
                        "constraint_id": "path.unmanifested",
                        "history_id": "h.left",
                        "kind": "PREFIX_HISTORY",
                        "value": {},
                        "source_refs": ["missing.source"],
                    }
                ),
                "unknown-source-ref",
            ),
            (
                "report",
                lambda value: value["facts"]["report_memberships"][0][
                    "source_refs"
                ].append("missing.source"),
                "unknown-source-ref",
            ),
            (
                "observation",
                lambda value: value["facts"]["observations"][0][
                    "source_refs"
                ].append("missing.source"),
                "unknown-source-ref",
            ),
            (
                "transformation",
                lambda value: value["provenance"]["transformations"].append(
                    {
                        "transformation_id": "transform.unmanifested",
                        "tool_ref": "missing.tool",
                        "input_refs": ["raw-runtime"],
                        "output_refs": ["missing.output"],
                        "deterministic": True,
                    }
                ),
                "unknown-transformation-ref",
            ),
            (
                "coverage",
                lambda value: value["coverage"]["history"]["basis_refs"].append(
                    "missing.source"
                ),
                "unknown-coverage-basis-ref",
            ),
            (
                "eligibility",
                lambda value: value["outcome_eligibility_summaries"][0][
                    "basis_refs"
                ].append("missing.source"),
                "unknown-eligibility-basis-ref",
            ),
            (
                "trust",
                lambda value: value["trust_assumptions"][0]["basis_refs"].append(
                    "missing.source"
                ),
                "unknown-trust-basis-ref",
            ),
        )
        for name, mutation, expected in reference_mutations:
            with self.subTest(name=name):
                evidence = _evidence(query)
                mutation(evidence)
                self.assertIn(expected, _contract_errors(query, evidence))

        evidence = _evidence(query)
        assessment = _assessment(query, evidence)
        assessment["trust_assumption_refs"].append("trust.missing")
        self.assertIn(
            "assessment-trust-ref",
            _assessment_contract_errors(query, evidence, assessment),
        )

    def test_precommit_boolean_controls_timing_outcome_freedom_and_refs(self):
        retrospective_query = _defined_query()
        prospective_query = _precommitted_query()
        retrospective_evidence = _evidence(retrospective_query)
        prospective_evidence = _evidence(prospective_query)
        retrospective_assessment = _assessment(
            retrospective_query, retrospective_evidence
        )
        prospective_assessment = _assessment(prospective_query, prospective_evidence)

        self.assertEqual([], _schema_errors("query", retrospective_query))
        self.assertEqual([], _schema_errors("query", prospective_query))
        self.assertEqual([], _schema_errors("evidence", retrospective_evidence))
        self.assertEqual([], _schema_errors("evidence", prospective_evidence))
        self.assertEqual([], _schema_errors("assessment", retrospective_assessment))
        self.assertEqual([], _schema_errors("assessment", prospective_assessment))

        invalid_values = []
        for base, required_refs in (
            (retrospective_query["freeze"], ("precommit_ref",)),
            (
                retrospective_evidence["selection_provenance"],
                ("selection_policy_ref", "precommit_ref"),
            ),
            (
                retrospective_assessment["selection_provenance"],
                ("selection_policy_ref", "precommit_ref"),
            ),
        ):
            wrong_timing = copy.deepcopy(base)
            wrong_timing["selection_timing"] = "PROSPECTIVE"
            invalid_values.append((wrong_timing, required_refs))
            wrong_outcome_free = copy.deepcopy(base)
            wrong_outcome_free["outcome_free_definition"] = True
            invalid_values.append((wrong_outcome_free, required_refs))
        for base, required_refs in (
            (prospective_query["freeze"], ("precommit_ref",)),
            (
                prospective_evidence["selection_provenance"],
                ("selection_policy_ref", "precommit_ref"),
            ),
            (
                prospective_assessment["selection_provenance"],
                ("selection_policy_ref", "precommit_ref"),
            ),
        ):
            wrong_timing = copy.deepcopy(base)
            wrong_timing["selection_timing"] = "RETROSPECTIVE"
            invalid_values.append((wrong_timing, required_refs))
            wrong_outcome_free = copy.deepcopy(base)
            wrong_outcome_free["outcome_free_definition"] = False
            invalid_values.append((wrong_outcome_free, required_refs))
            missing_ref = copy.deepcopy(base)
            del missing_ref[required_refs[0]]
            invalid_values.append((missing_ref, required_refs))
        for value, required_refs in invalid_values:
            with self.subTest(value=value):
                self.assertEqual(
                    ["precommit-combination"],
                    _precommit_combination_errors(value, required_refs),
                )

        for kind, document, field in (
            ("query", retrospective_query, "freeze"),
            ("evidence", retrospective_evidence, "selection_provenance"),
            ("assessment", retrospective_assessment, "selection_provenance"),
        ):
            with self.subTest(kind=kind):
                invalid = copy.deepcopy(document)
                invalid[field]["selection_timing"] = "PROSPECTIVE"
                self.assertTrue(_has_schema_errors(kind, invalid))

    def test_stock_linux_v1_read_only_premises_yield_unknown_not_nonfactoring(self):
        stock = _stock_linux_inputs()
        runtime = stock["runtime"]
        case_counts = {
            case: sum(run["case"] == case for run in runtime["runs"])
            for case in ("a=0", "a=1")
        }
        self.assertEqual({"a=0": 1, "a=1": 1}, case_counts)
        self.assertEqual(2, len(runtime["runs"]))
        harness = STOCK_HARNESS.read_text(encoding="utf-8")
        self.assertEqual(1, harness.count(".repeat = 1"))

        query = _stock_linux_query(stock)
        evidence = _stock_linux_evidence(query, stock)
        assessment = _stock_unknown_assessment(query, evidence)
        self.assertEqual([], _schema_errors("query", query))
        self.assertEqual([], _schema_errors("evidence", evidence))
        self.assertEqual([], _schema_errors("assessment", assessment))
        self.assertEqual([], _contract_errors(query, evidence))
        self.assertEqual(
            [], _assessment_contract_errors(query, evidence, assessment)
        )
        self.assertEqual("NOT_ESTABLISHED", evidence[
            "outcome_eligibility_summaries"
        ][0]["status"])
        self.assertEqual("UNKNOWN", assessment["verdict"])
        self.assertEqual(2, len(evidence["facts"]["observations"]))

        invalid_nonfactoring = _assessment(query, evidence, "NONFACTORING")
        invalid_nonfactoring["trust_assumption_refs"] = copy.deepcopy(
            assessment["trust_assumption_refs"]
        )
        self.assertIn(
            "witness-not-outcome-eligible",
            _assessment_contract_errors(query, evidence, invalid_nonfactoring),
        )

        broader_query = _stock_linux_query(stock, broader_runs=True)
        broader_evidence = _stock_linux_evidence(broader_query, stock)
        broader_assessment = _stock_unknown_assessment(
            broader_query, broader_evidence
        )
        self.assertIn(
            "h.unsampled",
            broader_query["canonical_query"]["bounded_completion"]["universes"][
                "histories"
            ],
        )
        self.assertEqual([], _contract_errors(broader_query, broader_evidence))
        self.assertEqual(
            [],
            _assessment_contract_errors(
                broader_query, broader_evidence, broader_assessment
            ),
        )
        self.assertEqual("UNKNOWN", broader_assessment["verdict"])

        undefined_query = _stock_linux_query(stock, undefined_report=True)
        undefined_evidence = _stock_linux_evidence(undefined_query, stock)
        out_of_scope = {
            "schema": "rac-assessment-v1",
            "assessment_id": "a.stock-linux-functional-report.undefined",
            "query_ref": {
                "query_id": undefined_query["query_id"],
                "query_digest_sha256": undefined_query["query_digest_sha256"],
            },
            "assessment_status": "OUT_OF_SCOPE",
            "undefined_components": ["REPORT_RULE"],
            "reasons": [
                {
                    "code": "REPORT_RULE_UNDEFINED",
                    "message": "No Linux-specified functional report contract is identified.",
                }
            ],
        }
        self.assertEqual([], _schema_errors("assessment", out_of_scope))
        self.assertEqual(
            [],
            _assessment_contract_errors(
                undefined_query, undefined_evidence, out_of_scope
            ),
        )

    def test_nondeterministic_samples_without_must_proof_remain_unknown(self):
        query = _defined_query()
        evidence = _evidence(query, eligible=False)
        invalid_claim = _assessment(query, evidence, "NONFACTORING")

        self.assertEqual([], _schema_errors("evidence", evidence))
        self.assertIn(
            "witness-not-outcome-eligible",
            _assessment_contract_errors(query, evidence, invalid_claim),
        )
        self.assertEqual(
            [],
            _assessment_contract_errors(query, evidence, _assessment(query, evidence)),
        )

    def test_nonfactoring_witness_is_joined_to_every_eligibility_and_fact_field(self):
        query = _defined_query()
        evidence = _evidence(query, eligible=True)
        assessment = _assessment(query, evidence, "NONFACTORING")

        witness_mutations = (
            (
                "left_history_id",
                "h.forged",
                "witness-outcome-mismatch",
            ),
            (
                "right_history_id",
                "h.left",
                "witness-histories-equal",
            ),
            (
                "report_cell_id",
                "cell.forged",
                "witness-membership-mismatch",
            ),
            (
                "context_id",
                "ctx.other",
                "witness-context-mismatch",
            ),
            (
                "suffix_id",
                "suffix.other",
                "witness-suffix-mismatch",
            ),
            (
                "left_outcome_id",
                "out.fail",
                "witness-outcome-mismatch",
            ),
            (
                "right_outcome_id",
                "out.ok",
                "witness-outcome-mismatch",
            ),
        )
        for field, value, expected in witness_mutations:
            with self.subTest(field=field):
                forged = copy.deepcopy(assessment)
                forged["decision_basis"]["witnesses"][0][field] = value
                self.assertIn(
                    expected,
                    _assessment_contract_errors(query, evidence, forged),
                )

        nonmember = copy.deepcopy(evidence)
        nonmember["facts"]["report_memberships"][1]["membership"] = "NON_MEMBER"
        self.assertIn(
            "witness-membership-mismatch",
            _assessment_contract_errors(
                query,
                nonmember,
                _assessment(query, nonmember, "NONFACTORING"),
            ),
        )

        wrong_history_context = copy.deepcopy(evidence)
        wrong_history_context["facts"]["histories"][1]["context_id"] = "ctx.other"
        wrong_summary = wrong_history_context["outcome_eligibility_summaries"][0]
        wrong_summary["eligibility_proof"][
            "bound_input_digest_sha256"
        ] = _eligibility_binding_digest(query, wrong_history_context, wrong_summary)
        self.assertIn(
            "witness-history-fact-mismatch",
            _assessment_contract_errors(
                query,
                wrong_history_context,
                _assessment(query, wrong_history_context, "NONFACTORING"),
            ),
        )

        wrong_observer = copy.deepcopy(evidence)
        summary = wrong_observer["outcome_eligibility_summaries"][0]
        summary["observer_id"] = "observer.other"
        summary["eligibility_proof"][
            "bound_input_digest_sha256"
        ] = _eligibility_binding_digest(query, wrong_observer, summary)
        self.assertIn(
            "witness-observer-mismatch",
            _assessment_contract_errors(
                query,
                wrong_observer,
                _assessment(query, wrong_observer, "NONFACTORING"),
            ),
        )

    def test_nonfactoring_requires_observer_distinct_not_just_distinct_ids(self):
        query = _defined_query()
        query["canonical_query"]["observer"][
            "equivalence"
        ] = "CANONICAL_JSON_EQUALITY"
        query["canonical_query"]["bounded_completion"]["universes"]["outcomes"][
            1
        ]["value"] = {"result": 1}
        query = _bind_query(query)
        evidence = _evidence(query, eligible=True)
        assessment = _assessment(query, evidence, "NONFACTORING")

        self.assertIn(
            "witness-outcomes-equal",
            _assessment_contract_errors(query, evidence, assessment),
        )

    def test_explicit_undefined_query_is_out_of_scope_but_missing_field_is_invalid(self):
        query = _defined_query()
        query["canonical_query"]["report_rule"] = {
            "defined": False,
            "rule_id": "report.linux.functional",
            "relation_semantics": "PARTIAL_MEMBERSHIP_RELATION",
            "source_kind": "TARGET_CONTRACT_UNDEFINED",
            "undefined_reason": "The target exposes no specified functional report contract.",
        }
        query = _bind_query(query)
        out_of_scope = {
            "schema": "rac-assessment-v1",
            "assessment_id": "a.undefined-report",
            "query_ref": {
                "query_id": query["query_id"],
                "query_digest_sha256": query["query_digest_sha256"],
            },
            "assessment_status": "OUT_OF_SCOPE",
            "undefined_components": ["REPORT_RULE"],
            "reasons": [
                {"code": "REPORT_RULE_UNDEFINED", "message": "No target contract."}
            ],
        }
        malformed = copy.deepcopy(query)
        del malformed["canonical_query"]["observer"]

        self.assertEqual([], _schema_errors("query", query))
        self.assertEqual([], _schema_errors("assessment", out_of_scope))
        evidence = _evidence(query)
        self.assertEqual(
            [],
            _assessment_contract_errors(query, evidence, out_of_scope),
        )
        self.assertIn(
            "semantic-assessment-for-undefined-query",
            _assessment_contract_errors(
                query,
                evidence,
                _assessment(query, evidence),
            ),
        )
        self.assertTrue(_has_schema_errors("query", malformed))
        self.assertIn(
            "query-schema",
            _assessment_contract_errors(malformed, evidence, out_of_scope),
        )

        stale_digest = copy.deepcopy(query)
        stale_digest["query_digest_sha256"] = ZERO
        self.assertIn(
            "query-digest",
            _assessment_contract_errors(stale_digest, evidence, out_of_scope),
        )

        stale_freeze = copy.deepcopy(query)
        stale_freeze["freeze"]["frozen_digest_sha256"] = ZERO
        self.assertIn(
            "frozen-digest",
            _assessment_contract_errors(stale_freeze, evidence, out_of_scope),
        )

        invalid = {
            "schema": "rac-assessment-v1",
            "assessment_id": "a.invalid-query",
            "assessment_status": "INVALID_EVIDENCE",
            "input_refs": [
                {"input_id": "query-input", "path": "query.json", "file_sha256": ZERO}
            ],
            "reasons": [
                {"code": "REQUIRED_FIELD_MISSING", "message": "observer is missing"}
            ],
        }
        self.assertEqual([], _schema_errors("assessment", invalid))

    def test_target_specification_requires_an_immutable_source_reference(self):
        query = _defined_query()
        query["canonical_query"]["report_rule"][
            "source_kind"
        ] = "TARGET_SPECIFICATION"
        query = _bind_query(query)
        self.assertTrue(_has_schema_errors("query", query))

        query["canonical_query"]["report_rule"]["specification_ref"] = {
            "document_id": "target.report.contract",
            "sha256": ONE,
        }
        query = _bind_query(query)
        self.assertEqual([], _schema_errors("query", query))
        sourced_digest = query["query_digest_sha256"]
        query["canonical_query"]["report_rule"]["specification_ref"][
            "sha256"
        ] = TWO
        query = _bind_query(query)
        self.assertNotEqual(sourced_digest, query["query_digest_sha256"])

        query["canonical_query"]["report_rule"] = {
            "defined": False,
            "rule_id": "report.linux.functional",
            "relation_semantics": "PARTIAL_MEMBERSHIP_RELATION",
            "source_kind": "TARGET_CONTRACT_UNDEFINED",
            "undefined_reason": "No immutable target report contract is identified.",
        }
        query = _bind_query(query)
        out_of_scope = {
            "schema": "rac-assessment-v1",
            "assessment_id": "a.no-target-contract",
            "query_ref": {
                "query_id": query["query_id"],
                "query_digest_sha256": query["query_digest_sha256"],
            },
            "assessment_status": "OUT_OF_SCOPE",
            "undefined_components": ["REPORT_RULE"],
            "reasons": [
                {
                    "code": "REPORT_RULE_UNDEFINED",
                    "message": "No target report contract is identified.",
                }
            ],
        }
        self.assertEqual([], _schema_errors("query", query))
        self.assertEqual([], _schema_errors("assessment", out_of_scope))
        self.assertEqual(
            [],
            _assessment_contract_errors(query, _evidence(query), out_of_scope),
        )

    def test_assumptions_cannot_use_verdict_or_coverage_variants(self):
        query = _defined_query()
        query["canonical_query"]["admissible_assumptions"].append(
            {
                "assumption_id": "assume.answer",
                "kind": "VERDICT",
                "desired": "NONFACTORING",
            }
        )
        self.assertTrue(_has_schema_errors("query", query))

        query = _defined_query()
        query["canonical_query"]["admissible_assumptions"][0][
            "environment_parameter_ref"
        ] = "unobserved_outcome"
        query = _bind_query(query)
        self.assertIn("inadmissible-assumption-ref", _contract_errors(query, _evidence(query)))

        for name in (
            "report_consistent",
            "only_possible_outcomes",
            "coverage_complete",
            "desired_verdict",
        ):
            with self.subTest(environment_parameter=name):
                query = _defined_query()
                query["canonical_query"]["environment"]["parameters"].append(
                    {
                        "name": name,
                        "semantic_kind": "EXECUTION_SERIALIZATION",
                        "value": True,
                    }
                )
                query["canonical_query"]["admissible_assumptions"].append(
                    {
                        "assumption_id": f"assume.{name}",
                        "kind": "ENVIRONMENT",
                        "environment_parameter_ref": name,
                        "predicate": "EQUALS",
                        "value": True,
                    }
                )
                query = _bind_query(query)
                self.assertTrue(_has_schema_errors("query", query))

        query = _defined_query()
        query["canonical_query"]["environment"]["parameters"][0][
            "semantic_kind"
        ] = "RESET_PROTOCOL"
        query = _bind_query(query)
        self.assertTrue(_has_schema_errors("query", query))

        query = _defined_query()
        query["canonical_query"]["admissible_assumptions"][0][
            "value"
        ] = "NONFACTORING"
        query = _bind_query(query)
        self.assertIn(
            "inadmissible-assumption-value",
            _contract_errors(query, _evidence(query)),
        )

    def test_canonical_digest_ignores_object_key_order_and_binds_semantics(self):
        query = _defined_query()
        reordered = json.loads(
            json.dumps(query["canonical_query"], sort_keys=True),
            object_pairs_hook=lambda pairs: dict(reversed(pairs)),
        )
        changed = copy.deepcopy(query["canonical_query"])
        changed["scope"]["context_id"] = "ctx.changed"

        self.assertEqual(
            query["query_digest_sha256"],
            _canonical_query_digest(reordered),
        )
        self.assertNotEqual(
            query["query_digest_sha256"],
            _canonical_query_digest(changed),
        )

    def test_canonical_digest_normalizes_every_schema_declared_set_array(self):
        query = _defined_query()
        canonical = query["canonical_query"]
        canonical["observer"]["projection"].append("status")
        canonical["continuation_universe"]["suffixes"].append(
            {"suffix_id": "suffix.other", "actions": ["other-step"]}
        )
        canonical["admissible_assumptions"].append(
            {
                "assumption_id": "assume.reset",
                "kind": "ENVIRONMENT",
                "environment_parameter_ref": "reset_protocol",
                "predicate": "EQUALS",
                "value": "fresh-instance",
            }
        )
        universes = canonical["bounded_completion"]["universes"]
        universes["report_cells"].append("cell.other")
        universes["contexts"].append("ctx.other")
        cardinalities = canonical["bounded_completion"]["max_cardinalities"]
        cardinalities.update(
            {
                "report_cells": len(universes["report_cells"]),
                "suffixes": len(canonical["continuation_universe"]["suffixes"]),
                "contexts": len(universes["contexts"]),
            }
        )
        query = _bind_query(query)
        baseline = query["query_digest_sha256"]

        set_paths = SCHEMAS["query"]["x-rac-canonicalization"]["set_arrays"]
        for pointer in set_paths:
            with self.subTest(pointer=pointer):
                permuted = copy.deepcopy(query["canonical_query"])
                _json_pointer_value(permuted, pointer).reverse()
                self.assertEqual(baseline, _canonical_query_digest(permuted))

        permuted_query = copy.deepcopy(query)
        for pointer in set_paths:
            _json_pointer_value(permuted_query["canonical_query"], pointer).reverse()
        evidence = _evidence(query)
        evidence["query_ref"]["file_sha256"] = _canonical_document_digest(
            permuted_query
        )
        _manifest_entry(evidence, "query.document")["sha256"] = evidence[
            "query_ref"
        ]["file_sha256"]
        self.assertEqual([], _contract_errors(permuted_query, evidence))

    def test_canonical_digest_preserves_ordered_arrays_and_json_values(self):
        query = _defined_query()
        query["canonical_query"]["continuation_universe"]["suffixes"][0][
            "actions"
        ] = ["step", "finish"]
        query["canonical_query"]["bounded_completion"]["universes"]["outcomes"][
            0
        ]["value"]["trace"] = ["first", "second"]
        canonical = query["canonical_query"]
        baseline = _canonical_query_digest(canonical)

        reversed_actions = copy.deepcopy(canonical)
        reversed_actions["continuation_universe"]["suffixes"][0][
            "actions"
        ].reverse()
        self.assertNotEqual(baseline, _canonical_query_digest(reversed_actions))

        reordered_enumeration = copy.deepcopy(canonical)
        reordered_enumeration["bounded_completion"][
            "canonical_enumeration_order"
        ][0:2] = reversed(
            reordered_enumeration["bounded_completion"][
                "canonical_enumeration_order"
            ][0:2]
        )
        self.assertNotEqual(baseline, _canonical_query_digest(reordered_enumeration))

        reversed_json_value = copy.deepcopy(canonical)
        reversed_json_value["bounded_completion"]["universes"]["outcomes"][0][
            "value"
        ]["trace"].reverse()
        self.assertNotEqual(baseline, _canonical_query_digest(reversed_json_value))

    def test_canonical_digest_rejects_duplicate_set_identifiers(self):
        duplicate_mutations = (
            lambda canonical: canonical["scope"]["target_system"][
                "identity"
            ].append({"name": "version", "value": "other"}),
            lambda canonical: canonical["observer"]["projection"].append("result"),
            lambda canonical: canonical["continuation_universe"]["suffixes"].append(
                {"suffix_id": "suffix.shared", "actions": ["other"]}
            ),
            lambda canonical: canonical["environment"]["parameters"].append(
                {
                    "name": "serialized",
                    "semantic_kind": "EXECUTION_SERIALIZATION",
                    "value": False,
                }
            ),
            lambda canonical: canonical["admissible_assumptions"].append(
                {
                    "assumption_id": "assume.serialized",
                    "kind": "ENVIRONMENT",
                    "environment_parameter_ref": "serialized",
                    "predicate": "EQUALS",
                    "value": False,
                }
            ),
            lambda canonical: canonical["bounded_completion"]["universes"][
                "histories"
            ].append("h.left"),
            lambda canonical: canonical["bounded_completion"]["universes"][
                "report_cells"
            ].append("cell.shared"),
            lambda canonical: canonical["bounded_completion"]["universes"][
                "outcomes"
            ].append({"outcome_id": "out.ok", "value": {"result": 2}}),
            lambda canonical: canonical["bounded_completion"]["universes"][
                "contexts"
            ].append("ctx.fixed"),
        )
        for mutation in duplicate_mutations:
            with self.subTest(mutation=mutation):
                query = _defined_query()
                mutation(query["canonical_query"])
                with self.assertRaises(ValueError):
                    _canonical_query_digest(query["canonical_query"])

        query = _defined_query()
        evidence = _evidence(query)
        query["canonical_query"]["scope"]["target_system"]["identity"].append(
            {"name": "version", "value": "other"}
        )
        self.assertIn(
            "duplicate-query-identifier",
            _contract_errors(query, evidence),
        )

        query = _defined_query()
        evidence = _evidence(query)
        query["canonical_query"]["scope"]["target_system"]["identity"].append(
            {"name": "version", "value": "other"}
        )
        assessment = _assessment(query, evidence)
        self.assertFalse(_has_schema_errors("query", query))
        self.assertIn(
            "duplicate-query-identifier",
            _assessment_contract_errors(query, evidence, assessment),
        )

    def test_canonical_digest_binds_payload_changes_under_stable_identifiers(self):
        query = _defined_query()
        changed = copy.deepcopy(query["canonical_query"])
        changed["scope"]["target_system"]["identity"][0]["value"] = "2"
        self.assertNotEqual(
            query["query_digest_sha256"],
            _canonical_query_digest(changed),
        )

    def test_query_ref_and_capture_digest_mismatches_are_invalid(self):
        query = _defined_query()
        evidence = _evidence(query)
        evidence["query_ref"]["query_digest_sha256"] = ZERO
        evidence["selection_provenance"]["query_digest_consumed"] = ONE

        errors = _contract_errors(query, evidence)
        self.assertIn("query-ref", errors)
        self.assertIn("capture-query-ref", errors)

    def test_selection_provenance_is_bound_across_query_evidence_and_assessment(self):
        query = _defined_query()
        for field, value in (
            ("selection_timing", "PROSPECTIVE"),
            ("outcome_free_definition", True),
        ):
            with self.subTest(direction="retrospective-to-prospective", field=field):
                evidence = _evidence(query)
                evidence["selection_provenance"][field] = value
                self.assertIn(
                    f"selection-{field.replace('_', '-')}-mismatch",
                    _contract_errors(query, evidence),
                )

        prospective_query = _precommitted_query()
        prospective_evidence = _evidence(prospective_query)
        self.assertEqual([], _contract_errors(prospective_query, prospective_evidence))

        retro_with_precommit = _evidence(prospective_query)
        retro_with_precommit["query_ref"].update(
            {
                "query_id": query["query_id"],
                "query_digest_sha256": query["query_digest_sha256"],
            }
        )
        retro_with_precommit["selection_provenance"][
            "query_digest_consumed"
        ] = query["query_digest_sha256"]
        self.assertIn(
            "selection-contract-precommitted-mismatch",
            _contract_errors(query, retro_with_precommit),
        )

        precommit_removed = _evidence(prospective_query)
        precommit_removed["selection_provenance"].update(
            {
                "contract_precommitted": False,
                "selection_timing": "RETROSPECTIVE",
                "outcome_free_definition": False,
            }
        )
        del precommit_removed["selection_provenance"]["selection_policy_ref"]
        del precommit_removed["selection_provenance"]["precommit_ref"]
        self.assertEqual([], _schema_errors("evidence", precommit_removed))
        self.assertIn(
            "selection-contract-precommitted-mismatch",
            _contract_errors(prospective_query, precommit_removed),
        )

        assessment = _assessment(
            prospective_query,
            prospective_evidence,
        )
        for mutation in (
            lambda value: value.__setitem__("selection_timing", "RETROSPECTIVE"),
            lambda value: value.__setitem__("outcome_free_definition", False),
            lambda value: value.__setitem__("query_digest_consumed", ZERO),
            lambda value: value["selection_policy_ref"].__setitem__("sha256", ZERO),
            lambda value: value["precommit_ref"].__setitem__("file_sha256", ZERO),
        ):
            with self.subTest(mutation=mutation):
                forged = copy.deepcopy(assessment)
                mutation(forged["selection_provenance"])
                self.assertIn(
                    "assessment-selection-provenance",
                    _assessment_contract_errors(
                        prospective_query, prospective_evidence, forged
                    ),
                )

    def test_precommit_and_selection_policy_refs_are_manifest_bound(self):
        query = _precommitted_query()
        evidence = _evidence(query)

        bad_precommit = copy.deepcopy(evidence)
        bad_precommit["selection_provenance"]["precommit_ref"][
            "file_sha256"
        ] = ZERO
        self.assertIn("precommit-ref-mismatch", _contract_errors(query, bad_precommit))

        bad_policy = copy.deepcopy(evidence)
        bad_policy["selection_provenance"]["selection_policy_ref"][
            "sha256"
        ] = ZERO
        self.assertIn("precommit-policy-digest", _contract_errors(query, bad_policy))

        wrong_roles = copy.deepcopy(evidence)
        _manifest_entry(wrong_roles, "freeze.precommit")["role"] = "OTHER"
        _manifest_entry(wrong_roles, "policy.control")["role"] = "OTHER"
        errors = _contract_errors(query, wrong_roles)
        self.assertIn("precommit-file-ref", errors)
        self.assertIn("selection-policy-ref", errors)

        bad_query_freeze = copy.deepcopy(query)
        bad_query_freeze["freeze"]["precommit_ref"][
            "recorded_query_digest_sha256"
        ] = ZERO
        self.assertIn(
            "precommit-query-digest",
            _contract_errors(bad_query_freeze, _evidence(bad_query_freeze)),
        )

    def test_target_and_complete_scope_digests_reject_tuple_substitution(self):
        query = _defined_query()
        evidence = _evidence(query)

        target_swap = copy.deepcopy(evidence)
        target_swap["scope_identity"]["target_system_identity_sha256"] = ZERO
        self.assertIn(
            "target-system-identity-mismatch",
            _contract_errors(query, target_swap),
        )

        scope_swap = copy.deepcopy(evidence)
        scope_swap["scope_identity"]["scope_digest_sha256"] = ZERO
        self.assertIn("scope-digest-mismatch", _contract_errors(query, scope_swap))

        for mutation in (
            lambda value: value["canonical_query"]["scope"]["target_system"].__setitem__(
                "system_id", "other-system"
            ),
            lambda value: value["canonical_query"]["scope"]["target_system"][
                "identity"
            ][0].__setitem__("value", "2"),
        ):
            with self.subTest(mutation=mutation):
                substituted_query = copy.deepcopy(query)
                mutation(substituted_query)
                substituted_query = _bind_query(substituted_query)
                substituted_evidence = copy.deepcopy(evidence)
                substituted_evidence["query_ref"][
                    "query_digest_sha256"
                ] = substituted_query["query_digest_sha256"]
                substituted_evidence["selection_provenance"][
                    "query_digest_consumed"
                ] = substituted_query["query_digest_sha256"]
                substituted_evidence["query_ref"][
                    "file_sha256"
                ] = _canonical_document_digest(substituted_query)
                _manifest_entry(substituted_evidence, "query.document")[
                    "sha256"
                ] = substituted_evidence["query_ref"]["file_sha256"]
                errors = _contract_errors(substituted_query, substituted_evidence)
                self.assertIn("target-system-identity-mismatch", errors)
                self.assertIn("scope-digest-mismatch", errors)

    def test_assessment_scope_and_document_digests_echo_validated_inputs(self):
        query = _defined_query()
        evidence = _evidence(query)
        assessment = _assessment(query, evidence)

        replacements = {
            "scope_id": "scope.other",
            "scope_digest_sha256": ZERO,
            "artifact_id": "artifact.other",
            "artifact_sha256": ONE,
            "target_system_identity_sha256": TWO,
            "frontier_id": "frontier.other",
            "context_id": "ctx.other",
        }
        for field, value in replacements.items():
            with self.subTest(field=field):
                forged = copy.deepcopy(assessment)
                forged["scope"][field] = value
                self.assertIn(
                    "assessment-scope-mismatch",
                    _assessment_contract_errors(query, evidence, forged),
                )

        forged_query_file = copy.deepcopy(evidence)
        forged_query_file["query_ref"]["file_sha256"] = ZERO
        _manifest_entry(forged_query_file, "query.document")["sha256"] = ZERO
        self.assertIn(
            "query-file-digest",
            _contract_errors(query, forged_query_file),
        )

        forged_evidence_file = copy.deepcopy(assessment)
        forged_evidence_file["evidence_ref"]["evidence_digest_sha256"] = ZERO
        forged_evidence_file["evidence_ref"]["file_sha256"] = ZERO
        errors = _assessment_contract_errors(query, evidence, forged_evidence_file)
        self.assertIn("assessment-evidence-digest", errors)
        self.assertIn("assessment-evidence-file-digest", errors)

    def test_no_fresh_element_and_cardinality_contracts_fail_closed(self):
        query = _defined_query()
        evidence = _evidence(query)
        evidence["facts"]["report_memberships"][0]["report_cell_id"] = "cell.fresh"
        self.assertIn("fresh-report-element", _contract_errors(query, evidence))

        evidence = _evidence(query)
        evidence["facts"]["observations"].append(
            copy.deepcopy(evidence["facts"]["observations"][0])
        )
        evidence["facts"]["observations"][-1]["observation_id"] = "obs.extra"
        query["canonical_query"]["bounded_completion"]["max_cardinalities"][
            "observations"
        ] = 2
        query = _bind_query(query)
        evidence["query_ref"]["query_digest_sha256"] = query["query_digest_sha256"]
        evidence["selection_provenance"]["query_digest_consumed"] = query[
            "query_digest_sha256"
        ]
        self.assertIn("observation-cardinality", _contract_errors(query, evidence))

    def test_bounded_completion_universes_are_nonempty_and_within_limits(self):
        universe_lists = {
            "histories": lambda value: value["canonical_query"][
                "bounded_completion"
            ]["universes"]["histories"],
            "report_cells": lambda value: value["canonical_query"][
                "bounded_completion"
            ]["universes"]["report_cells"],
            "suffixes": lambda value: value["canonical_query"][
                "continuation_universe"
            ]["suffixes"],
            "outcomes": lambda value: value["canonical_query"][
                "bounded_completion"
            ]["universes"]["outcomes"],
            "contexts": lambda value: value["canonical_query"][
                "bounded_completion"
            ]["universes"]["contexts"],
        }
        for name, universe in universe_lists.items():
            with self.subTest(kind="over-limit", universe=name):
                query = _defined_query()
                query["canonical_query"]["bounded_completion"][
                    "max_cardinalities"
                ][name] = 0
                query = _bind_query(query)
                evidence = _evidence(query)
                assessment = _assessment(query, evidence)

                self.assertIn(
                    f"{name}-universe-cardinality", _contract_errors(query, evidence)
                )
                self.assertIn(
                    f"{name}-universe-cardinality",
                    _assessment_contract_errors(query, evidence, assessment),
                )

            with self.subTest(kind="empty", universe=name):
                query = _defined_query()
                universe(query).clear()
                query = _bind_query(query)
                evidence = _evidence(query)
                assessment = _assessment(query, evidence)

                self.assertIn(
                    f"empty-{name}-universe", _contract_errors(query, evidence)
                )
                self.assertIn(
                    f"empty-{name}-universe",
                    _assessment_contract_errors(query, evidence, assessment),
                )

    def test_conflicts_make_the_completion_class_invalid_not_vacuously_true(self):
        query = _defined_query()
        evidence = _evidence(query)
        conflict = copy.deepcopy(evidence["facts"]["report_memberships"][0])
        conflict["membership"] = "NON_MEMBER"
        evidence["facts"]["report_memberships"].append(conflict)

        self.assertIn("conflicting-membership", _contract_errors(query, evidence))

        evidence = _evidence(query)
        duplicate = copy.deepcopy(_manifest_entry(evidence, "raw-runtime"))
        duplicate["source_ref"] = "raw-runtime-conflict"
        duplicate["sha256"] = ONE
        evidence["provenance"]["manifest"].append(duplicate)
        self.assertIn("conflicting-provenance", _contract_errors(query, evidence))

    def test_assessment_branches_require_their_proof_objects(self):
        query = _defined_query()
        eligible = _evidence(query, eligible=True)
        nonfactoring = _assessment(query, eligible, "NONFACTORING")
        del nonfactoring["decision_basis"]["witnesses"]
        self.assertTrue(_has_schema_errors("assessment", nonfactoring))

        closed = _evidence(query, semantic_status="CLOSED")
        factoring = _assessment(query, closed, "FACTORING")
        self.assertEqual([], _schema_errors("assessment", factoring))
        del factoring["decision_basis"]["closure_dimensions"]
        self.assertTrue(_has_schema_errors("assessment", factoring))

        unknown = _assessment(query, eligible)
        unknown["decision_basis"]["missing_obligations"] = []
        self.assertTrue(_has_schema_errors("assessment", unknown))

    def test_factoring_coverage_and_proof_refs_are_evidence_bound(self):
        query = _defined_query()
        closed = _evidence(query, semantic_status="CLOSED")
        assessment = _assessment(query, closed, "FACTORING")
        self.assertEqual([], _assessment_contract_errors(query, closed, assessment))

        open_evidence = _evidence(query, semantic_status="OPEN")
        forged_closed = _assessment(query, open_evidence, "FACTORING")
        for name in forged_closed["decision_basis"]["closure_dimensions"]:
            forged_closed["coverage"][name] = "CLOSED"
        self.assertEqual([], _schema_errors("assessment", forged_closed))
        errors = _assessment_contract_errors(query, open_evidence, forged_closed)
        self.assertIn("assessment-coverage-mismatch", errors)
        self.assertIn("factoring-with-open-coverage", errors)

        mutation_cases = (
            (
                "proof-role",
                lambda evidence, basis: _manifest_entry(
                    evidence, "proof.factoring"
                ).__setitem__("role", "OTHER"),
                "factoring-proof-ref",
            ),
            (
                "proof-digest",
                lambda evidence, basis: basis.__setitem__(
                    "proof_digest_sha256", ZERO
                ),
                "factoring-proof-digest",
            ),
            (
                "checker-role",
                lambda evidence, basis: _manifest_entry(
                    evidence, "checker.factoring"
                ).__setitem__("role", "OTHER"),
                "factoring-checker-ref",
            ),
            (
                "checker-digest",
                lambda evidence, basis: basis.__setitem__(
                    "checker_digest_sha256", ZERO
                ),
                "factoring-checker-digest",
            ),
            (
                "missing-query-input",
                lambda evidence, basis: basis["input_refs"].remove(
                    "query.document"
                ),
                "factoring-proof-input-binding",
            ),
            (
                "missing-raw-input",
                lambda evidence, basis: basis["input_refs"].remove("raw-runtime"),
                "factoring-proof-input-binding",
            ),
            (
                "proof-output-as-input",
                lambda evidence, basis: basis["input_refs"].append(
                    "proof.factoring"
                ),
                "factoring-proof-output-as-input",
            ),
            (
                "dangling-input",
                lambda evidence, basis: basis["input_refs"].append(
                    "input.forged"
                ),
                "factoring-proof-input-ref",
            ),
            (
                "query-binding",
                lambda evidence, basis: basis.__setitem__(
                    "bound_query_digest_sha256", ZERO
                ),
                "factoring-query-binding",
            ),
            (
                "scope-binding",
                lambda evidence, basis: basis.__setitem__(
                    "bound_scope_digest_sha256", ZERO
                ),
                "factoring-scope-binding",
            ),
            (
                "evidence-binding",
                lambda evidence, basis: basis.__setitem__(
                    "bound_evidence_digest_sha256", ZERO
                ),
                "factoring-evidence-binding",
            ),
            (
                "completion-count",
                lambda evidence, basis: basis.__setitem__("completion_count", 65),
                "factoring-completion-count",
            ),
        )
        for name, mutation, expected in mutation_cases:
            with self.subTest(name=name):
                mutated_evidence = copy.deepcopy(closed)
                mutated = _assessment(query, mutated_evidence, "FACTORING")
                mutation(mutated_evidence, mutated["decision_basis"])
                self.assertIn(
                    expected,
                    _assessment_contract_errors(query, mutated_evidence, mutated),
                )

    def test_meta_results_cannot_carry_semantic_verdicts(self):
        out_of_scope = {
            "schema": "rac-assessment-v1",
            "assessment_id": "a.out",
            "query_ref": {"query_id": "q.out", "query_digest_sha256": ZERO},
            "assessment_status": "OUT_OF_SCOPE",
            "undefined_components": ["REPORT_RULE"],
            "reasons": [{"code": "UNDEFINED", "message": "undefined"}],
            "verdict": "UNKNOWN",
        }
        self.assertTrue(_has_schema_errors("assessment", out_of_scope))

    def test_unknown_fields_bad_hashes_and_unsafe_paths_are_rejected(self):
        query = _defined_query()
        query["unexpected"] = True
        self.assertTrue(_has_schema_errors("query", query))

        evidence = _evidence(_defined_query())
        evidence["query_ref"]["file_sha256"] = "ABC"
        evidence["provenance"]["manifest"][0]["path"] = "../escape.json"
        self.assertTrue(_has_schema_errors("evidence", evidence))

        evidence = _evidence(_defined_query())
        evidence["provenance"]["manifest"][0]["path"] = "raw//runtime.json"
        self.assertTrue(_has_schema_errors("evidence", evidence))


if __name__ == "__main__":
    unittest.main()
