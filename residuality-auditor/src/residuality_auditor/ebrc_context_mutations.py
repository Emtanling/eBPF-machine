"""Hostile mutations for contextual EBRC transport certificates."""
from __future__ import annotations

import copy
from collections import Counter
from typing import Any, Callable

from .ebrc import canonical_digest, check_certificate


MUTATION_MATRIX_SCHEMA = "rac-ebrc-context-hostile-mutation-matrix-v1"

Mutation = Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], None]


def _rebind_graph(graph: dict[str, Any], proof: dict[str, Any]) -> None:
    proof["graph_digest_sha256"] = canonical_digest(graph)


def _rebind_claim(claim: dict[str, Any], proof: dict[str, Any]) -> None:
    proof["requested_claim_digest_sha256"] = canonical_digest(claim)


def _transport_payload(graph: dict[str, Any]) -> dict[str, Any]:
    return next(node for node in graph["nodes"] if node["role"] == "TRANSPORT_PROOF")["payload"]


def _transform_payload(graph: dict[str, Any]) -> dict[str, Any]:
    return next(node for node in graph["nodes"] if node["role"] == "TRANSFORMATION")["payload"]


def _rehash_payload_node(graph: dict[str, Any], role: str) -> None:
    node = next(item for item in graph["nodes"] if item["role"] == role)
    node["payload_digest_sha256"] = canonical_digest(node["payload"])


def _mutate_claim_field(path: tuple[str, ...], value: Any) -> Mutation:
    def mutate(_graph: dict[str, Any], claim: dict[str, Any], proof: dict[str, Any]) -> None:
        target: dict[str, Any] = claim
        for field in path[:-1]:
            target = target[field]
        target[path[-1]] = value
        _rebind_claim(claim, proof)

    return mutate


def _mutate_proof_wide_claim_field(path: tuple[str, ...], value: Any) -> Mutation:
    def mutate(graph: dict[str, Any], claim: dict[str, Any], proof: dict[str, Any]) -> None:
        for document in [claim, *(step["conclusion"] for step in proof["steps"])]:
            target: dict[str, Any] = document
            for field in path[:-1]:
                target = target[field]
            target[path[-1]] = value
        transport = _transport_payload(graph)
        transport["derivation_chain"]["target_claim_digest_sha256"] = canonical_digest(
            proof["steps"][-1]["conclusion"]
        )
        _rehash_payload_node(graph, "TRANSPORT_PROOF")
        _rebind_graph(graph, proof)
        _rebind_claim(claim, proof)

    return mutate


def _set_obligation(name: str, value: bool) -> Mutation:
    def mutate(graph: dict[str, Any], _claim: dict[str, Any], proof: dict[str, Any]) -> None:
        transport = _transport_payload(graph)
        transport["obligations"][name] = value
        _rehash_payload_node(graph, "TRANSPORT_PROOF")
        _rebind_graph(graph, proof)

    return mutate


def _write_footprint_resource(graph: dict[str, Any], _claim: dict[str, Any], proof: dict[str, Any]) -> None:
    transport = _transport_payload(graph)
    transport["effect"]["writes"].append(transport["footprint"]["resources"][0])
    _rehash_payload_node(graph, "TRANSPORT_PROOF")
    _rebind_graph(graph, proof)


def _drop_history_map(graph: dict[str, Any], _claim: dict[str, Any], proof: dict[str, Any]) -> None:
    transport = _transport_payload(graph)
    transport["history_map"] = transport["history_map"][:1]
    _rehash_payload_node(graph, "TRANSPORT_PROOF")
    _rebind_graph(graph, proof)


def _add_outcome_transform_dependency(graph: dict[str, Any], _claim: dict[str, Any], proof: dict[str, Any]) -> None:
    graph["nodes"].append(
        {
            "node_id": "runtime.hostile.outcome",
            "role": "RUNTIME_OBSERVATION",
            "payload": {"status": "OBSERVED", "history_id": "history.target.0", "outcome": 0},
            "payload_digest_sha256": canonical_digest(
                {"status": "OBSERVED", "history_id": "history.target.0", "outcome": 0}
            ),
        }
    )
    graph["edges"].append(
        {
            "edge_id": "edge.hostile.outcome-to-transform",
            "role": "CONSUMED_BY",
            "source": "runtime.hostile.outcome",
            "target": "transform.context",
        }
    )
    _rebind_graph(graph, proof)


def _add_target_terminal_verdict(graph: dict[str, Any], _claim: dict[str, Any], proof: dict[str, Any]) -> None:
    transport = _transport_payload(graph)
    transport["target_terminal_verdict"] = "NONFACTORING"
    _rehash_payload_node(graph, "TRANSPORT_PROOF")
    _rebind_graph(graph, proof)


def _make_runtime_only_blocked(_graph: dict[str, Any], _claim: dict[str, Any], proof: dict[str, Any]) -> None:
    proof["root_step_id"] = None
    proof["steps"] = []
    proof["declared_missing_obligations"] = ["TARGET_CONFORMANCE_BRIDGE"]


def _tamper_transform_digest(graph: dict[str, Any], _claim: dict[str, Any], proof: dict[str, Any]) -> None:
    transform = _transform_payload(graph)
    parameters = transform.setdefault("parameters", {})
    stale_values = parameters.setdefault("hostile_stale_digest_values", [])
    stale_values.append(10)
    _rehash_payload_node(graph, "TRANSFORMATION")
    transport = _transport_payload(graph)
    transport["derivation_chain"]["transform_digest_sha256"] = canonical_digest(transform)
    _rehash_payload_node(graph, "TRANSPORT_PROOF")
    _rebind_graph(graph, proof)


def _tamper_derivation_chain_kind(graph: dict[str, Any], _claim: dict[str, Any], proof: dict[str, Any]) -> None:
    transport = _transport_payload(graph)
    transport["derivation_kind"] = "DERIVED_UNCHECKED"
    transport["derivation_chain"]["kind"] = "DERIVED_UNCHECKED"
    _rehash_payload_node(graph, "TRANSPORT_PROOF")
    _rebind_graph(graph, proof)


_CASES: tuple[tuple[str, str, str, str, Mutation], ...] = (
    (
        "claim.forall-contexts",
        "rewrite an exact target certificate into an EBRC FORALL claim",
        "BLOCKED",
        "REQUESTED_CLAIM_NOT_DERIVED",
        _mutate_claim_field(("quantifier",), "FORALL"),
    ),
    (
        "claim.specified-report",
        "promote the target report authority",
        "BLOCKED",
        "REQUESTED_CLAIM_NOT_DERIVED",
        _mutate_claim_field(("scope", "report_authority"), "IMPLEMENTATION_SPECIFIED"),
    ),
    (
        "proof.self-consistent-forall",
        "rewrite every proof conclusion to FORALL",
        "INVALID_GRAPH",
        "CONTEXT_RULE_QUANTIFIER_UNSUPPORTED",
        _mutate_proof_wide_claim_field(("quantifier",), "FORALL"),
    ),
    (
        "proof.self-consistent-specified-report",
        "rewrite every proof conclusion to implementation-specified report authority",
        "INVALID_GRAPH",
        "CONTEXT_RULE_REPORT_AUTHORITY_UNSUPPORTED",
        _mutate_proof_wide_claim_field(("scope", "report_authority"), "IMPLEMENTATION_SPECIFIED"),
    ),
    (
        "transport.missing-bridge",
        "mark the target conformance bridge as absent",
        "INVALID_GRAPH",
        "CONTEXT_OBLIGATION_FAILED",
        _set_obligation("target_conformance_bridge", False),
    ),
    (
        "transport.runtime-only-blocked",
        "keep validation data but withhold the bridge proof",
        "BLOCKED",
        "TARGET_CONFORMANCE_BRIDGE",
        _make_runtime_only_blocked,
    ),
    (
        "transport.footprint-effect-conflict",
        "write a resource in the witness footprint",
        "INVALID_GRAPH",
        "CONTEXT_FOOTPRINT_EFFECT_CONFLICT",
        _write_footprint_resource,
    ),
    (
        "transport.history-map-incomplete",
        "drop one source history from the target history map",
        "INVALID_GRAPH",
        "CONTEXT_HISTORY_MAP_INCOMPLETE",
        _drop_history_map,
    ),
    (
        "graph.outcome-transform-dependency",
        "make the selected transform consume a target outcome",
        "INVALID_GRAPH",
        "CONTEXT_OUTCOME_DEPENDENCY",
        _add_outcome_transform_dependency,
    ),
    (
        "transport.target-terminal-verdict",
        "cite a stored target terminal verdict inside the transport proof",
        "INVALID_GRAPH",
        "CONTEXT_TARGET_VERDICT_PREMISE",
        _add_target_terminal_verdict,
    ),
    (
        "transport.transform-digest-stale",
        "modify the transform after the transport proof binds its digest",
        "INVALID_GRAPH",
        "CONTEXT_TRANSPORT_BINDING_MISMATCH",
        _tamper_transform_digest,
    ),
    (
        "transport.derivation-chain-kind",
        "rewrite the contextual derivation chain kind",
        "INVALID_GRAPH",
        "CONTEXT_DERIVATION_CHAIN_INVALID",
        _tamper_derivation_chain_kind,
    ),
)


def _markers(result: dict[str, Any]) -> list[str]:
    return sorted(set(result.get("invalid_reasons", [])) | set(result.get("missing_obligations", [])))


def run_context_hostile_mutation_matrix(
    graph_document: dict[str, Any],
    claim_document: dict[str, Any],
    proof_document: dict[str, Any],
) -> dict[str, Any]:
    graph = copy.deepcopy(graph_document)
    claim = copy.deepcopy(claim_document)
    proof = copy.deepcopy(proof_document)
    baseline = check_certificate(graph, claim, proof)
    if baseline.get("status") != "CERTIFIED":
        raise ValueError("context hostile mutation matrix requires a CERTIFIED baseline")

    cases: list[dict[str, Any]] = []
    for mutation_id, description, expected_status, expected_marker, mutate in _CASES:
        mutated_graph = copy.deepcopy(graph)
        mutated_claim = copy.deepcopy(claim)
        mutated_proof = copy.deepcopy(proof)
        mutate(mutated_graph, mutated_claim, mutated_proof)
        result = check_certificate(mutated_graph, mutated_claim, mutated_proof)
        observed_markers = _markers(result)
        matched = result.get("status") == expected_status and expected_marker in observed_markers
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
