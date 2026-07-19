"""Hostile mutations for one retained exact EBRC certificate.

The matrix is an evaluation tool, not an additional proof rule.  It starts
from a certificate that the generic checker accepts, makes one forbidden lift
or integrity mutation at a time, updates only the bindings an attacker could
legitimately recompute, and records the fail-closed result.
"""
from __future__ import annotations

import copy
from collections import Counter
from typing import Any, Callable

from .ebrc import canonical_digest, check_certificate


MUTATION_MATRIX_SCHEMA = "rac-ebrc-hostile-mutation-matrix-v1"

Mutation = Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], None]


def _rebind_requested_claim(
    _graph: dict[str, Any], claim: dict[str, Any], proof: dict[str, Any]
) -> None:
    proof["requested_claim_digest_sha256"] = canonical_digest(claim)


def _claim_field_mutation(path: tuple[str, ...], value: Any) -> Mutation:
    def mutate(graph: dict[str, Any], claim: dict[str, Any], proof: dict[str, Any]) -> None:
        target: dict[str, Any] = claim
        for field in path[:-1]:
            target = target[field]
        target[path[-1]] = value
        _rebind_requested_claim(graph, claim, proof)

    return mutate


def _proof_wide_claim_mutation(path: tuple[str, ...], value: Any) -> Mutation:
    def mutate(graph: dict[str, Any], claim: dict[str, Any], proof: dict[str, Any]) -> None:
        documents = [claim, *(step["conclusion"] for step in proof["steps"])]
        for document in documents:
            target: dict[str, Any] = document
            for field in path[:-1]:
                target = target[field]
            target[path[-1]] = value
        _rebind_requested_claim(graph, claim, proof)

    return mutate


def _add_outcome_selector_dependency(
    graph: dict[str, Any], _claim: dict[str, Any], proof: dict[str, Any]
) -> None:
    outcome = next(
        node["node_id"]
        for node in graph["nodes"]
        if node["role"] in {"RAW_EVENT", "RUNTIME_OBSERVATION"}
    )
    selector = next(
        node["node_id"] for node in graph["nodes"] if node["role"] == "SELECTION_POLICY"
    )
    graph["edges"].append(
        {
            "edge_id": "edge.hostile.outcome-to-selector",
            "role": "CONSUMED_BY",
            "source": outcome,
            "target": selector,
        }
    )
    proof["graph_digest_sha256"] = canonical_digest(graph)


def _tamper_node_payload(
    graph: dict[str, Any], _claim: dict[str, Any], _proof: dict[str, Any]
) -> None:
    query = next(node for node in graph["nodes"] if node["role"] == "QUERY")
    query["payload"]["hostile_tamper"] = True


def _replace_root_premise(
    _graph: dict[str, Any], _claim: dict[str, Any], proof: dict[str, Any]
) -> None:
    root_id = proof["root_step_id"]
    root = next(step for step in proof["steps"] if step["step_id"] == root_id)
    root["premises"] = ["step.hostile.missing"]


_CASES: tuple[tuple[str, str, str, str, Mutation], ...] = (
    (
        "claim.forall-family",
        "replace exact AT quantification with an unsupported universal family claim",
        "BLOCKED",
        "REQUESTED_CLAIM_NOT_DERIVED",
        _claim_field_mutation(("quantifier",), "FORALL"),
    ),
    (
        "claim.specified-report",
        "promote an operational report to implementation-specified authority",
        "BLOCKED",
        "REQUESTED_CLAIM_NOT_DERIVED",
        _claim_field_mutation(("scope", "report_authority"), "IMPLEMENTATION_SPECIFIED"),
    ),
    (
        "claim.changed-observer",
        "reuse the witness under a different observer without an inequality bridge",
        "BLOCKED",
        "REQUESTED_CLAIM_NOT_DERIVED",
        _claim_field_mutation(("scope", "observer_id"), "observer.hostile.coarsened"),
    ),
    (
        "claim.enlarged-suffix",
        "reuse one common suffix as an enlarged continuation universe",
        "BLOCKED",
        "REQUESTED_CLAIM_NOT_DERIVED",
        _claim_field_mutation(("scope", "suffix_id"), "suffix.hostile.enlarged"),
    ),
    (
        "claim.transported-grade",
        "claim a transported evidence grade without a transport proof",
        "BLOCKED",
        "REQUESTED_CLAIM_NOT_DERIVED",
        _claim_field_mutation(("evidence_grade",), "TRANSPORTED"),
    ),
    (
        "proof.self-consistent-forall",
        "rewrite every proof conclusion as a universal family claim",
        "INVALID_GRAPH",
        "RULE_QUANTIFIER_UNSUPPORTED",
        _proof_wide_claim_mutation(("quantifier",), "FORALL"),
    ),
    (
        "proof.self-consistent-specified-report",
        "rewrite every proof conclusion with implementation-specified report authority",
        "INVALID_GRAPH",
        "RULE_REPORT_AUTHORITY_UNSUPPORTED",
        _proof_wide_claim_mutation(
            ("scope", "report_authority"), "IMPLEMENTATION_SPECIFIED"
        ),
    ),
    (
        "proof.self-consistent-transported-grade",
        "rewrite every proof conclusion with an unsupported transported grade",
        "INVALID_GRAPH",
        "RULE_EVIDENCE_GRADE_UNSUPPORTED",
        _proof_wide_claim_mutation(("evidence_grade",), "TRANSPORTED"),
    ),
    (
        "proof.self-consistent-report-relation",
        "rewrite every proof conclusion for a different report relation",
        "INVALID_GRAPH",
        "COLLISION_RULE_SCOPE_MISMATCH",
        _proof_wide_claim_mutation(
            ("scope", "report_relation_id"), "report.hostile.relation"
        ),
    ),
    (
        "graph.outcome-selector-dependency",
        "make the prospective selector consume an outcome node",
        "INVALID_GRAPH",
        "PROSPECTIVE_OUTCOME_DEPENDENCY",
        _add_outcome_selector_dependency,
    ),
    (
        "graph.payload-tamper",
        "change a graph payload without updating its bound digest",
        "INVALID_GRAPH",
        "GRAPH_NODE_PAYLOAD_DIGEST_MISMATCH",
        _tamper_node_payload,
    ),
    (
        "proof.unknown-premise",
        "replace the root premise with an absent proof step",
        "INVALID_GRAPH",
        "PROOF_UNKNOWN_PREMISE",
        _replace_root_premise,
    ),
)


def _markers(result: dict[str, Any]) -> list[str]:
    return sorted(
        set(result.get("invalid_reasons", []))
        | set(result.get("missing_obligations", []))
    )


def run_hostile_mutation_matrix(
    graph_document: dict[str, Any],
    claim_document: dict[str, Any],
    proof_document: dict[str, Any],
) -> dict[str, Any]:
    """Run the fixed U4 forbidden-lift and integrity mutation matrix."""

    graph = copy.deepcopy(graph_document)
    claim = copy.deepcopy(claim_document)
    proof = copy.deepcopy(proof_document)
    baseline = check_certificate(graph, claim, proof)
    if baseline.get("status") != "CERTIFIED":
        raise ValueError("hostile mutation matrix requires a CERTIFIED baseline")

    cases: list[dict[str, Any]] = []
    for mutation_id, description, expected_status, expected_marker, mutate in _CASES:
        mutated_graph = copy.deepcopy(graph)
        mutated_claim = copy.deepcopy(claim)
        mutated_proof = copy.deepcopy(proof)
        mutate(mutated_graph, mutated_claim, mutated_proof)
        result = check_certificate(mutated_graph, mutated_claim, mutated_proof)
        observed_markers = _markers(result)
        matched = (
            result.get("status") == expected_status
            and expected_marker in observed_markers
        )
        cases.append(
            {
                "mutation_id": mutation_id,
                "description": description,
                "expected_status": expected_status,
                "expected_marker": expected_marker,
                "observed_status": result.get("status"),
                "observed_markers": observed_markers,
                "matched_expectation": matched,
                "mutated_claim_digest_sha256": canonical_digest(mutated_claim),
                "mutated_graph_digest_sha256": canonical_digest(mutated_graph),
                "mutated_proof_digest_sha256": canonical_digest(mutated_proof),
            }
        )

    counts = Counter(case["observed_status"] for case in cases)
    return {
        "schema": MUTATION_MATRIX_SCHEMA,
        "baseline": {
            "status": baseline["status"],
            "assessment": baseline.get("assessment"),
            "certificate": baseline.get("certificate"),
            "claim_digest_sha256": canonical_digest(claim),
            "graph_digest_sha256": canonical_digest(graph),
            "proof_digest_sha256": canonical_digest(proof),
        },
        "cases": cases,
        "summary": dict(sorted(counts.items())),
        "all_expected": all(case["matched_expectation"] for case in cases),
    }
