"""Contextual Residual Lifting helpers for EBRC certificates.

This module builds small, source-neutral CRL documents.  It deliberately does
not inspect Linux terminal verdicts; the production checker in ``ebrc.py`` is
the only component that derives a target ``NONFACTORING`` certificate.
"""
from __future__ import annotations

import copy
from typing import Any

from .ebrc import (
    GRAPH_SCHEMA,
    PROOF_SCHEMA,
    canonical_digest,
    check_certificate,
    make_claim,
    make_node,
)


TRANSFORM_SCHEMA = "rac-ebrc-context-transform-v1"
TRANSPORT_SCHEMA = "rac-ebrc-context-transport-v1"
CONTEXT_RESULT_SCHEMA = "rac-ebrc-context-result-v1"
DERIVED_CONTEXTUAL = "DERIVED_CONTEXTUAL"

_SOURCE_XLATED = "0" * 64
_TARGET_XLATED = "1" * 64


def _edge(edge_id: str, role: str, source: str, target: str) -> dict[str, str]:
    return {"edge_id": edge_id, "role": role, "source": source, "target": target}


def make_context_scope(label: str) -> dict[str, str]:
    """Return a deterministic exact EBRC scope for a synthetic CRL target."""

    scope_vector = {
        "artifact": {"label": label},
        "implementation": {"contract": "synthetic-crl-v1"},
        "frontier": {"id": f"frontier.{label}"},
        "context": {"id": f"context.{label}"},
        "report": {
            "authority": "OPERATIONAL_OBSERVATION",
            "relation": "report.operational.cell",
            "cell_id": f"cell.{label}",
        },
        "observer": f"observer.{label}",
        "suffix": f"suffix.{label}",
        "environment": {"kind": "synthetic"},
    }
    return {
        "scope_digest_sha256": canonical_digest(scope_vector),
        "report_authority": "OPERATIONAL_OBSERVATION",
        "report_relation_id": "report.operational.cell",
        "frontier_id": f"frontier.{label}",
        "context_id": f"context.{label}",
        "suffix_id": f"suffix.{label}",
        "observer_id": f"observer.{label}",
    }


def make_context_transform(
    source_scope: dict[str, str],
    target_scope: dict[str, str],
    *,
    trivial: bool = False,
    source_xlated_sha256: str = _SOURCE_XLATED,
    target_xlated_sha256: str = _TARGET_XLATED,
) -> dict[str, Any]:
    return {
        "schema": TRANSFORM_SCHEMA,
        "kind": "CONTEXT_TERM",
        "status": "VERIFIED",
        "transform_id": "context.post-collision-framed-v1",
        "primitive": "POST_COLLISION_FRAMED_COMPUTATION",
        "trivial": trivial,
        "source_scope_digest_sha256": source_scope["scope_digest_sha256"],
        "target_scope_digest_sha256": target_scope["scope_digest_sha256"],
        "source_xlated_sha256": source_xlated_sha256,
        "target_xlated_sha256": target_xlated_sha256,
        "parameters": {"framed_insns": [8, 9]},
    }


def _default_obligations() -> dict[str, bool]:
    return {
        "source_certificate": True,
        "source_target_scope_distinct_or_identity_marked": True,
        "instruction_correspondence_total_on_witness": True,
        "footprint_effect_disjoint": True,
        "collision_preserved": True,
        "common_suffix_preserved": True,
        "must_outcomes_preserved": True,
        "observer_reflected": True,
        "report_cell_preserved": True,
        "frontier_preserved": True,
        "history_map_total": True,
        "target_conformance_bridge": True,
        "outcome_independent_selection": True,
        "no_target_terminal_verdict": True,
    }


def make_context_transport(
    source_claim: dict[str, Any],
    target_claim: dict[str, Any],
    transform: dict[str, Any],
    *,
    obligations: dict[str, bool] | None = None,
    target_identity_digest_sha256: str | None = None,
) -> dict[str, Any]:
    source_claim_digest = canonical_digest(source_claim)
    target_claim_digest = canonical_digest(target_claim)
    transform_digest = canonical_digest(transform)
    history_map = [
        {"source_history_id": source, "target_history_id": target}
        for source, target in zip(
            source_claim["subject"]["history_ids"],
            target_claim["subject"]["history_ids"],
            strict=True,
        )
    ]
    document = {
        "schema": TRANSPORT_SCHEMA,
        "kind": "CONTEXT_TRANSPORT",
        "status": "VERIFIED",
        "transport_id": "transport.synthetic-context-v1",
        "derivation_kind": DERIVED_CONTEXTUAL,
        "derivation_chain": {
            "kind": DERIVED_CONTEXTUAL,
            "rule": "CONTEXT_TRANSPORT",
            "source_claim_digest_sha256": source_claim_digest,
            "transform_digest_sha256": transform_digest,
            "target_claim_digest_sha256": target_claim_digest,
        },
        "source_claim_digest_sha256": source_claim_digest,
        "source_scope_digest_sha256": source_claim["scope"]["scope_digest_sha256"],
        "target_scope_digest_sha256": target_claim["scope"]["scope_digest_sha256"],
        "transform_digest_sha256": transform_digest,
        "target_scope": copy.deepcopy(target_claim["scope"]),
        "target_subject": copy.deepcopy(target_claim["subject"]),
        "obligations": obligations if obligations is not None else _default_obligations(),
        "instruction_correspondence": {
            "status": "VERIFIED",
            "total_on_witness": True,
            "entries": [
                {"source_insn": 0, "target_insn": 0, "relation": "IDENTITY"},
                {"source_insn": 1, "target_insn": 1, "relation": "FRAMED"},
            ],
        },
        "footprint": {
            "resources": [
                "reg:r1",
                "reg:r2",
                "stack:-8..-1",
                "map:witness.0",
                "frontier:source",
            ]
        },
        "effect": {"writes": ["reg:r9", "stack:-32..-25"]},
        "history_map": history_map,
    }
    if target_identity_digest_sha256 is not None:
        document["target_identity_digest_sha256"] = target_identity_digest_sha256
    return document


def make_context_documents(
    *,
    trivial: bool = False,
    include_runtime_validation: bool = False,
    blocked_missing: list[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Build a complete synthetic CRL certificate or a blocked near-miss."""

    source_scope = make_context_scope("source")
    target_scope = source_scope if trivial else make_context_scope("target")
    source_subject = {
        "history_ids": ["history.source.0", "history.source.1"],
        "report_cell_id": "cell.source",
        "outcomes": [0, 1],
    }
    target_subject = {
        "history_ids": ["history.target.0", "history.target.1"],
        "report_cell_id": "cell.target",
        "outcomes": [0, 1],
    }
    if trivial:
        target_subject = copy.deepcopy(source_subject)

    source_claim = make_claim(
        "claim.synthetic-source.nonfactor",
        "NONFACTORING",
        source_scope,
        source_subject,
        evidence_grade="OUTCOME_FREE_PRECOMMITTED",
    )
    target_claim = make_claim(
        "claim.synthetic-target.transport",
        "NONFACTORING",
        target_scope,
        target_subject,
        evidence_grade="TRANSPORTED",
    )
    transform = make_context_transform(
        source_scope,
        target_scope,
        trivial=trivial,
        target_xlated_sha256=_SOURCE_XLATED if trivial else _TARGET_XLATED,
    )
    transport = make_context_transport(source_claim, target_claim, transform)
    nodes = [
        make_node(
            "source.certificate",
            "CLAIM",
            {
                "kind": "SOURCE_EBRC_CERTIFICATE",
                "status": "CERTIFIED",
                "claim": copy.deepcopy(source_claim),
                "claim_digest_sha256": canonical_digest(source_claim),
                "certificate": f"NONFACTORING@{source_scope['scope_digest_sha256']}",
            },
        ),
        make_node("transform.context", "TRANSFORMATION", transform),
        make_node("transport.context", "TRANSPORT_PROOF", transport),
        make_node(
            "checker.context",
            "CHECKER",
            {
                "kind": "CONTEXTUAL_TRANSPORT_CHECKER",
                "status": "VERIFIED",
                "source_path": "residuality-auditor/src/residuality_auditor/ebrc.py",
            },
        ),
    ]
    edges = [
        _edge("edge.source-to-transport", "TRANSPORTS_TO", "source.certificate", "transport.context"),
        _edge("edge.transform-to-transport", "CONSUMED_BY", "transform.context", "transport.context"),
        _edge("edge.transport-checked", "CHECKED_BY", "transport.context", "checker.context"),
    ]
    if include_runtime_validation:
        nodes.append(
            make_node(
                "runtime.target.validation",
                "RUNTIME_OBSERVATION",
                {"status": "OBSERVED", "history_id": "history.target.0", "outcome": 0},
            )
        )
    step = {
        "step_id": "step.derived-contextual",
        "rule": "CONTEXT_TRANSPORT",
        "premises": [],
        "evidence_refs": [
            "source.certificate",
            "transform.context",
            "transport.context",
            "checker.context",
        ],
        "conclusion": copy.deepcopy(target_claim),
    }
    graph = {
        "schema": GRAPH_SCHEMA,
        "graph_id": f"graph.context.{target_scope['scope_digest_sha256'][:16]}",
        "scope_digest_sha256": target_scope["scope_digest_sha256"],
        "nodes": nodes,
        "edges": edges,
    }
    missing = sorted(set(blocked_missing or []))
    proof = {
        "schema": PROOF_SCHEMA,
        "proof_id": f"proof.context.{target_scope['scope_digest_sha256'][:16]}",
        "graph_digest_sha256": canonical_digest(graph),
        "requested_claim_digest_sha256": canonical_digest(target_claim),
        "root_step_id": None if missing else step["step_id"],
        "steps": [] if missing else [step],
        "declared_missing_obligations": missing,
    }
    return {"graph": graph, "claim": target_claim, "proof": proof}


def check_context_documents(documents: dict[str, dict[str, Any]]) -> dict[str, Any]:
    result = check_certificate(
        documents["graph"],
        documents["claim"],
        documents["proof"],
    )
    return {"schema": CONTEXT_RESULT_SCHEMA, **result}


def _identity_from_graph(graph: dict[str, Any], scope_digest: str) -> dict[str, Any]:
    for node in graph.get("nodes", []):
        if node.get("role") == "IDENTITY_RECEIPT":
            payload = node.get("payload", {})
            if payload.get("status") == "VERIFIED":
                return copy.deepcopy(payload)
    raise ValueError(f"source graph has no verified identity receipt for {scope_digest}")


def _target_scope_from_source(
    source_claim: dict[str, Any],
    target_identity: dict[str, Any],
    transform_metadata: dict[str, Any],
) -> dict[str, str]:
    source_scope = source_claim["scope"]
    variant_id = str(transform_metadata.get("variant_id", "context-target"))
    scope_vector = {
        "source_scope_digest_sha256": source_scope["scope_digest_sha256"],
        "target_identity": copy.deepcopy(target_identity),
        "transform": copy.deepcopy(transform_metadata),
        "preserved_scope_fields": {
            "report_relation_id": source_scope["report_relation_id"],
            "frontier_id": source_scope["frontier_id"],
            "suffix_id": source_scope["suffix_id"],
            "observer_id": source_scope["observer_id"],
        },
    }
    return {
        "scope_digest_sha256": canonical_digest(scope_vector),
        "report_authority": "OPERATIONAL_OBSERVATION",
        "report_relation_id": source_scope["report_relation_id"],
        "frontier_id": source_scope["frontier_id"],
        "context_id": f"context.crl.{variant_id}",
        "suffix_id": source_scope["suffix_id"],
        "observer_id": source_scope["observer_id"],
    }


def make_stock_r_context_documents(
    source_graph: dict[str, Any],
    source_claim: dict[str, Any],
    source_proof: dict[str, Any],
    target_identity: dict[str, Any],
    transform_metadata: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Derive a CRL target certificate from a checked Stock-R V2 source."""

    source_result = check_certificate(source_graph, source_claim, source_proof)
    if source_result.get("status") != "CERTIFIED":
        raise ValueError("source EBRC certificate must be CERTIFIED")
    source_scope_digest = source_claim["scope"]["scope_digest_sha256"]
    source_identity = _identity_from_graph(source_graph, source_scope_digest)
    target_identity_payload = {"status": "VERIFIED", **copy.deepcopy(target_identity)}
    target_scope = _target_scope_from_source(
        source_claim,
        target_identity_payload,
        transform_metadata,
    )
    target_histories = [
        f"history.crl.{history_id}"
        for history_id in source_claim["subject"]["history_ids"]
    ]
    target_subject = {
        "history_ids": target_histories,
        "report_cell_id": source_claim["subject"]["report_cell_id"],
        "outcomes": copy.deepcopy(source_claim["subject"]["outcomes"]),
    }
    target_claim = make_claim(
        "claim.stock-r-v2.context-target.transport",
        "NONFACTORING",
        target_scope,
        target_subject,
        evidence_grade="TRANSPORTED",
    )
    transform = make_context_transform(
        source_claim["scope"],
        target_scope,
        trivial=False,
        source_xlated_sha256=source_identity["xlated_sha256"],
        target_xlated_sha256=target_identity["xlated_sha256"],
    )
    transform["transform_id"] = str(transform_metadata.get("transform_id", transform["transform_id"]))
    transform["primitive"] = str(transform_metadata.get("primitive", transform["primitive"]))
    transform["parameters"] = copy.deepcopy(transform_metadata.get("parameters", {}))
    target_identity_digest = canonical_digest(target_identity_payload)
    transport = make_context_transport(
        source_claim,
        target_claim,
        transform,
        target_identity_digest_sha256=target_identity_digest,
    )
    if "instruction_correspondence" in transform_metadata:
        transport["instruction_correspondence"] = copy.deepcopy(
            transform_metadata["instruction_correspondence"]
        )
    if "footprint" in transform_metadata:
        transport["footprint"] = copy.deepcopy(transform_metadata["footprint"])
    if "effect" in transform_metadata:
        transport["effect"] = copy.deepcopy(transform_metadata["effect"])
    if "obligations" in transform_metadata:
        transport["obligations"] = copy.deepcopy(transform_metadata["obligations"])
    nodes = [
        make_node(
            "source.certificate",
            "CLAIM",
            {
                "kind": "SOURCE_EBRC_CERTIFICATE",
                "status": "CERTIFIED",
                "claim": copy.deepcopy(source_claim),
                "claim_digest_sha256": canonical_digest(source_claim),
                "certificate": source_result["certificate"],
            },
        ),
        make_node("identity.target", "IDENTITY_RECEIPT", target_identity_payload),
        make_node("transform.context", "TRANSFORMATION", transform),
        make_node("transport.context", "TRANSPORT_PROOF", transport),
        make_node(
            "checker.context",
            "CHECKER",
            {
                "kind": "CONTEXTUAL_TRANSPORT_CHECKER",
                "status": "VERIFIED",
                "source_path": "residuality-auditor/src/residuality_auditor/ebrc.py",
            },
        ),
    ]
    edges = [
        _edge("edge.source-to-transport", "TRANSPORTS_TO", "source.certificate", "transport.context"),
        _edge("edge.identity-to-transport", "BINDS", "identity.target", "transport.context"),
        _edge("edge.transform-to-transport", "CONSUMED_BY", "transform.context", "transport.context"),
        _edge("edge.transport-checked", "CHECKED_BY", "transport.context", "checker.context"),
    ]
    step = {
        "step_id": "step.derived-contextual",
        "rule": "CONTEXT_TRANSPORT",
        "premises": [],
        "evidence_refs": [
            "source.certificate",
            "identity.target",
            "transform.context",
            "transport.context",
            "checker.context",
        ],
        "conclusion": copy.deepcopy(target_claim),
    }
    graph = {
        "schema": GRAPH_SCHEMA,
        "graph_id": f"graph.context-stock-r-v2.{target_scope['scope_digest_sha256'][:16]}",
        "scope_digest_sha256": target_scope["scope_digest_sha256"],
        "nodes": nodes,
        "edges": edges,
    }
    parameters = transform_metadata.get("parameters", {})
    behavior_mutation = (
        parameters.get("behavior_mutation")
        if isinstance(parameters, dict)
        else None
    )
    if behavior_mutation == "ADD_OUTCOME_TRANSFORM_DEPENDENCY":
        outcome_payload = {
            "status": "OBSERVED",
            "history_id": target_histories[0],
            "outcome": 0,
        }
        graph["nodes"].append(
            make_node(
                "runtime.context-case.outcome",
                "RUNTIME_OBSERVATION",
                outcome_payload,
            )
        )
        graph["edges"].append(
            _edge(
                "edge.context-case.outcome-to-transform",
                "CONSUMED_BY",
                "runtime.context-case.outcome",
                "transform.context",
            )
        )
    bridge_withheld = behavior_mutation == "WITHHOLD_TARGET_BRIDGE"
    proof = {
        "schema": PROOF_SCHEMA,
        "proof_id": f"proof.context-stock-r-v2.{target_scope['scope_digest_sha256'][:16]}",
        "graph_digest_sha256": canonical_digest(graph),
        "requested_claim_digest_sha256": canonical_digest(target_claim),
        "root_step_id": None if bridge_withheld else step["step_id"],
        "steps": [] if bridge_withheld else [step],
        "declared_missing_obligations": (
            ["TARGET_CONFORMANCE_BRIDGE"] if bridge_withheld else []
        ),
    }
    return {"graph": graph, "claim": target_claim, "proof": proof}
