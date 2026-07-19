"""Small fail-closed checker for Evidence-Bounded Residual Certification.

The checker knows only the generic EBRC graph roles and proof rules.  Bundle-
specific adapters must validate their source evidence and compile it into the
three public documents accepted here: a requested claim, an evidence graph,
and a proof DAG.  In particular, this module never reads legacy Stock-Linux or
Stock-R V2 verdict strings.
"""
from __future__ import annotations

import copy
import hashlib
from typing import Any, Iterable

import rfc8785


CLAIM_SCHEMA = "rac-ebrc-claim-v1"
GRAPH_SCHEMA = "rac-ebrc-evidence-graph-v1"
PROOF_SCHEMA = "rac-ebrc-proof-v1"
RESULT_SCHEMA = "rac-ebrc-result-v1"
DERIVED_CONTEXTUAL = "DERIVED_CONTEXTUAL"

NODE_ROLES = {
    "QUERY",
    "SELECTION_POLICY",
    "PRECOMMITMENT",
    "RAW_EVENT",
    "RUNTIME_OBSERVATION",
    "IDENTITY_RECEIPT",
    "SOURCE_CLOSURE",
    "BUILD_CLOSURE",
    "TRANSFORMATION",
    "SEMANTIC_PROOF",
    "TRANSPORT_PROOF",
    "CHECKER",
    "TRUST_ASSUMPTION",
    "CLAIM",
    "ASSESSMENT",
}
EDGE_ROLES = {
    "BINDS",
    "DERIVES_FROM",
    "CHECKED_BY",
    "CONSUMED_BY",
    "SELECTED_BY",
    "PRECEDES",
    "IMPLEMENTS",
    "TRANSPORTS_TO",
}
PREDICATES = {
    "MAY_OUTCOME",
    "MUST_OUTCOME",
    "REPORT_COLLISION",
    "OBSERVER_INEQUALITY",
    "NONFACTORING",
}
GRADES = {
    "RETROSPECTIVE_EXACT",
    "OUTCOME_FREE_PRECOMMITTED",
    "TRANSPORTED",
}
GRADE_RANK = {
    "RETROSPECTIVE_EXACT": 0,
    "OUTCOME_FREE_PRECOMMITTED": 1,
    "TRANSPORTED": 1,
}
FLOW_ROLES = {"BINDS", "DERIVES_FROM", "CONSUMED_BY", "SELECTED_BY", "TRANSPORTS_TO"}
CONTEXT_TRANSPORT_OBLIGATIONS = {
    "source_certificate",
    "source_target_scope_distinct_or_identity_marked",
    "instruction_correspondence_total_on_witness",
    "footprint_effect_disjoint",
    "collision_preserved",
    "common_suffix_preserved",
    "must_outcomes_preserved",
    "observer_reflected",
    "report_cell_preserved",
    "frontier_preserved",
    "history_map_total",
    "target_conformance_bridge",
    "outcome_independent_selection",
    "no_target_terminal_verdict",
}
CONTEXT_FORBIDDEN_PAYLOAD_KEYS = {
    "target_assessment",
    "target_claim",
    "target_nonfactoring_verdict",
    "target_terminal_verdict",
}


class EBRCInvalid(ValueError):
    """A malformed, contradictory, or misbound graph/proof document."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def canonical_digest(value: Any) -> str:
    """Return the RFC 8785 SHA-256 digest used for EBRC cross-bindings."""

    try:
        return hashlib.sha256(rfc8785.dumps(value)).hexdigest()
    except (TypeError, ValueError) as exc:
        raise EBRCInvalid("DOCUMENT_NOT_CANONICAL_JSON") from exc


def make_node(
    node_id: str,
    role: str,
    payload: dict[str, Any],
    *,
    recorded_at_ns: int | None = None,
) -> dict[str, Any]:
    node = {
        "node_id": node_id,
        "role": role,
        "payload": copy.deepcopy(payload),
        "payload_digest_sha256": canonical_digest(payload),
    }
    if recorded_at_ns is not None:
        node["recorded_at_ns"] = recorded_at_ns
    return node


def make_claim(
    claim_id: str,
    predicate: str,
    scope: dict[str, Any],
    subject: dict[str, Any],
    *,
    evidence_grade: str = "RETROSPECTIVE_EXACT",
    quantifier: str = "AT",
) -> dict[str, Any]:
    return {
        "schema": CLAIM_SCHEMA,
        "claim_id": claim_id,
        "predicate": predicate,
        "quantifier": quantifier,
        "scope": copy.deepcopy(scope),
        "evidence_grade": evidence_grade,
        "subject": copy.deepcopy(subject),
    }


def _require_dict(value: Any, reason: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EBRCInvalid(reason)
    return value


def _require_list(value: Any, reason: str) -> list[Any]:
    if not isinstance(value, list):
        raise EBRCInvalid(reason)
    return value


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_claim(claim: Any, graph_scope_digest: str | None = None) -> dict[str, Any]:
    value = _require_dict(claim, "CLAIM_MALFORMED")
    required = {
        "schema",
        "claim_id",
        "predicate",
        "quantifier",
        "scope",
        "evidence_grade",
        "subject",
    }
    if set(value) != required or value.get("schema") != CLAIM_SCHEMA:
        raise EBRCInvalid("CLAIM_MALFORMED")
    if not isinstance(value.get("claim_id"), str) or not value["claim_id"]:
        raise EBRCInvalid("CLAIM_ID_INVALID")
    if value.get("predicate") not in PREDICATES:
        raise EBRCInvalid("CLAIM_PREDICATE_INVALID")
    if value.get("quantifier") not in {"AT", "EXISTS", "FORALL"}:
        raise EBRCInvalid("CLAIM_QUANTIFIER_INVALID")
    if value.get("evidence_grade") not in GRADES:
        raise EBRCInvalid("CLAIM_GRADE_INVALID")
    scope = _require_dict(value.get("scope"), "CLAIM_SCOPE_MALFORMED")
    scope_fields = {
        "scope_digest_sha256",
        "report_authority",
        "report_relation_id",
        "frontier_id",
        "context_id",
        "suffix_id",
        "observer_id",
    }
    if set(scope) != scope_fields or not _is_sha256(scope.get("scope_digest_sha256")):
        raise EBRCInvalid("CLAIM_SCOPE_MALFORMED")
    if scope.get("report_authority") not in {
        "OPERATIONAL_OBSERVATION",
        "IMPLEMENTATION_SPECIFIED",
        "EXTERNAL_SPECIFIED",
    }:
        raise EBRCInvalid("CLAIM_REPORT_AUTHORITY_INVALID")
    for field in scope_fields - {"scope_digest_sha256", "report_authority"}:
        if not isinstance(scope.get(field), str) or not scope[field]:
            raise EBRCInvalid("CLAIM_SCOPE_MALFORMED")
    if graph_scope_digest is not None and scope["scope_digest_sha256"] != graph_scope_digest:
        raise EBRCInvalid("CLAIM_SCOPE_GRAPH_MISMATCH")
    subject = _require_dict(value.get("subject"), "CLAIM_SUBJECT_MALFORMED")
    if not subject:
        raise EBRCInvalid("CLAIM_SUBJECT_MALFORMED")
    canonical_digest(value)
    return value


def _validate_graph(graph: Any) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    value = _require_dict(graph, "GRAPH_MALFORMED")
    if set(value) != {"schema", "graph_id", "scope_digest_sha256", "nodes", "edges"}:
        raise EBRCInvalid("GRAPH_MALFORMED")
    if value.get("schema") != GRAPH_SCHEMA or not _is_sha256(value.get("scope_digest_sha256")):
        raise EBRCInvalid("GRAPH_MALFORMED")
    if not isinstance(value.get("graph_id"), str) or not value["graph_id"]:
        raise EBRCInvalid("GRAPH_ID_INVALID")
    nodes: dict[str, dict[str, Any]] = {}
    for raw_node in _require_list(value.get("nodes"), "GRAPH_NODES_MALFORMED"):
        node = _require_dict(raw_node, "GRAPH_NODE_MALFORMED")
        allowed = {"node_id", "role", "payload", "payload_digest_sha256", "recorded_at_ns"}
        if not {"node_id", "role", "payload", "payload_digest_sha256"}.issubset(node) or set(node) - allowed:
            raise EBRCInvalid("GRAPH_NODE_MALFORMED")
        node_id = node.get("node_id")
        if not isinstance(node_id, str) or not node_id or node_id in nodes:
            raise EBRCInvalid("GRAPH_DUPLICATE_OR_INVALID_NODE_ID")
        if node.get("role") not in NODE_ROLES:
            raise EBRCInvalid("GRAPH_NODE_ROLE_INVALID")
        payload = _require_dict(node.get("payload"), "GRAPH_NODE_PAYLOAD_MALFORMED")
        if node.get("payload_digest_sha256") != canonical_digest(payload):
            raise EBRCInvalid("GRAPH_NODE_PAYLOAD_DIGEST_MISMATCH")
        recorded_at = node.get("recorded_at_ns")
        if recorded_at is not None and (
            isinstance(recorded_at, bool) or not isinstance(recorded_at, int) or recorded_at < 0
        ):
            raise EBRCInvalid("GRAPH_NODE_TIME_INVALID")
        nodes[node_id] = node
    if not nodes:
        raise EBRCInvalid("GRAPH_EMPTY")

    edge_ids: set[str] = set()
    adjacency: dict[str, list[str]] = {node_id: [] for node_id in nodes}
    indegree: dict[str, int] = {node_id: 0 for node_id in nodes}
    for raw_edge in _require_list(value.get("edges"), "GRAPH_EDGES_MALFORMED"):
        edge = _require_dict(raw_edge, "GRAPH_EDGE_MALFORMED")
        if set(edge) != {"edge_id", "role", "source", "target"}:
            raise EBRCInvalid("GRAPH_EDGE_MALFORMED")
        edge_id = edge.get("edge_id")
        if not isinstance(edge_id, str) or not edge_id or edge_id in edge_ids:
            raise EBRCInvalid("GRAPH_DUPLICATE_OR_INVALID_EDGE_ID")
        edge_ids.add(edge_id)
        if edge.get("role") not in EDGE_ROLES:
            raise EBRCInvalid("GRAPH_EDGE_ROLE_INVALID")
        if (
            not isinstance(edge.get("source"), str)
            or not edge["source"]
            or not isinstance(edge.get("target"), str)
            or not edge["target"]
        ):
            raise EBRCInvalid("GRAPH_EDGE_ENDPOINT_INVALID")
        if edge.get("source") not in nodes or edge.get("target") not in nodes:
            raise EBRCInvalid("GRAPH_EDGE_ENDPOINT_MISSING")
        if edge["source"] == edge["target"]:
            raise EBRCInvalid("GRAPH_SELF_EDGE")
        adjacency[edge["source"]].append(edge["target"])
        indegree[edge["target"]] += 1
        if edge["role"] == "PRECEDES":
            source_time = nodes[edge["source"]].get("recorded_at_ns")
            target_time = nodes[edge["target"]].get("recorded_at_ns")
            if source_time is not None and target_time is not None and source_time >= target_time:
                raise EBRCInvalid("GRAPH_PRECEDENCE_TIME_INVALID")
    pending = [node_id for node_id, degree in indegree.items() if degree == 0]
    visited = 0
    while pending:
        source = pending.pop()
        visited += 1
        for target in adjacency[source]:
            indegree[target] -= 1
            if indegree[target] == 0:
                pending.append(target)
    if visited != len(nodes):
        raise EBRCInvalid("GRAPH_CYCLE")
    canonical_digest(value)
    return value, nodes


def _claim_semantic_key(claim: dict[str, Any]) -> str:
    return canonical_digest(
        {
            "predicate": claim["predicate"],
            "quantifier": claim["quantifier"],
            "scope": claim["scope"],
            "subject": claim["subject"],
        }
    )


def _same_semantic_claim(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return _claim_semantic_key(left) == _claim_semantic_key(right)


def _node_payload(nodes: dict[str, dict[str, Any]], reference: str, role: str) -> dict[str, Any]:
    node = nodes.get(reference)
    if node is None:
        raise EBRCInvalid("PROOF_UNKNOWN_EVIDENCE_REF")
    if node["role"] != role:
        raise EBRCInvalid("PROOF_EVIDENCE_ROLE_MISMATCH")
    return node["payload"]


def _require_exact_operational_rule_claim(
    claim: dict[str, Any], expected_grade: str
) -> None:
    """Restrict U4 proof rules to their implemented exact operational fragment."""

    if claim["quantifier"] != "AT":
        raise EBRCInvalid("RULE_QUANTIFIER_UNSUPPORTED")
    if claim["scope"]["report_authority"] != "OPERATIONAL_OBSERVATION":
        raise EBRCInvalid("RULE_REPORT_AUTHORITY_UNSUPPORTED")
    if claim["evidence_grade"] != expected_grade:
        raise EBRCInvalid("RULE_EVIDENCE_GRADE_UNSUPPORTED")


def _require_context_transport_rule_claim(claim: dict[str, Any]) -> None:
    """Restrict CRL transport to exact target claims with transported grade."""

    if claim["predicate"] != "NONFACTORING":
        raise EBRCInvalid("CONTEXT_RULE_PREDICATE_UNSUPPORTED")
    if claim["quantifier"] != "AT":
        raise EBRCInvalid("CONTEXT_RULE_QUANTIFIER_UNSUPPORTED")
    if claim["scope"]["report_authority"] != "OPERATIONAL_OBSERVATION":
        raise EBRCInvalid("CONTEXT_RULE_REPORT_AUTHORITY_UNSUPPORTED")
    if claim["evidence_grade"] != "TRANSPORTED":
        raise EBRCInvalid("CONTEXT_RULE_EVIDENCE_GRADE_UNSUPPORTED")


def _same_scope(claims: Iterable[dict[str, Any]]) -> bool:
    digests = {claim["scope"]["scope_digest_sha256"] for claim in claims}
    return len(digests) == 1


def _check_raw(step: dict[str, Any], nodes: dict[str, dict[str, Any]]) -> None:
    if step["premises"] or len(step["evidence_refs"]) != 1:
        raise EBRCInvalid("RAW_RULE_SHAPE_INVALID")
    payload = _node_payload(nodes, step["evidence_refs"][0], "RUNTIME_OBSERVATION")
    conclusion = step["conclusion"]
    _require_exact_operational_rule_claim(conclusion, "RETROSPECTIVE_EXACT")
    if payload.get("status") != "OBSERVED" or conclusion["predicate"] != "MAY_OUTCOME":
        raise EBRCInvalid("RAW_RULE_EVIDENCE_INVALID")
    expected = {"history_id": payload.get("history_id"), "outcome": payload.get("outcome")}
    if conclusion["subject"] != expected:
        raise EBRCInvalid("RAW_RULE_CONCLUSION_MISMATCH")


def _check_must(step: dict[str, Any], nodes: dict[str, dict[str, Any]]) -> None:
    if step["premises"] or len(step["evidence_refs"]) != 2:
        raise EBRCInvalid("MUST_RULE_SHAPE_INVALID")
    referenced_nodes = [nodes[reference] for reference in step["evidence_refs"] if reference in nodes]
    if len(referenced_nodes) != 2 or {node["role"] for node in referenced_nodes} != {
        "SEMANTIC_PROOF",
        "TRANSFORMATION",
    }:
        raise EBRCInvalid("MUST_RULE_EVIDENCE_INVALID")
    payload_by_role = {node["role"]: node["payload"] for node in referenced_nodes}
    semantic = payload_by_role["SEMANTIC_PROOF"]
    binding = payload_by_role["TRANSFORMATION"]
    if (
        semantic.get("kind") != "MUST_OUTCOME"
        or binding.get("kind") != "HISTORY_CASE_BINDING"
    ):
        raise EBRCInvalid("MUST_RULE_EVIDENCE_INVALID")
    if semantic.get("status") != "VERIFIED" or binding.get("status") != "VERIFIED":
        raise EBRCInvalid("MUST_RULE_EVIDENCE_INVALID")
    if (
        not isinstance(semantic.get("history_id"), str)
        or not semantic["history_id"]
        or not _is_sha256(semantic.get("scope_digest_sha256"))
    ):
        raise EBRCInvalid("MUST_RULE_EVIDENCE_INVALID")
    fields = ("history_id", "outcome", "scope_digest_sha256")
    if any(semantic.get(field) != binding.get(field) for field in fields):
        raise EBRCInvalid("MUST_RULE_BINDING_MISMATCH")
    conclusion = step["conclusion"]
    _require_exact_operational_rule_claim(conclusion, "RETROSPECTIVE_EXACT")
    if conclusion["predicate"] != "MUST_OUTCOME" or conclusion["subject"] != {
        "history_id": semantic["history_id"],
        "outcome": semantic["outcome"],
    }:
        raise EBRCInvalid("MUST_RULE_CONCLUSION_MISMATCH")
    if conclusion["scope"]["scope_digest_sha256"] != semantic["scope_digest_sha256"]:
        raise EBRCInvalid("MUST_RULE_SCOPE_MISMATCH")


def _check_collision(step: dict[str, Any], nodes: dict[str, dict[str, Any]]) -> None:
    if step["premises"] or len(step["evidence_refs"]) != 1:
        raise EBRCInvalid("COLLISION_RULE_SHAPE_INVALID")
    payload = _node_payload(nodes, step["evidence_refs"][0], "RAW_EVENT")
    conclusion = step["conclusion"]
    _require_exact_operational_rule_claim(conclusion, "RETROSPECTIVE_EXACT")
    histories = payload.get("history_ids")
    if (
        payload.get("status") != "VERIFIED"
        or payload.get("kind") != "REPORT_COLLISION"
        or not isinstance(histories, list)
        or len(histories) != 2
        or any(not isinstance(history, str) or not history for history in histories)
        or histories[0] == histories[1]
        or not isinstance(payload.get("report_cell_id"), str)
        or not payload["report_cell_id"]
    ):
        raise EBRCInvalid("COLLISION_RULE_EVIDENCE_INVALID")
    expected = {"history_ids": histories, "report_cell_id": payload.get("report_cell_id")}
    if conclusion["predicate"] != "REPORT_COLLISION" or conclusion["subject"] != expected:
        raise EBRCInvalid("COLLISION_RULE_CONCLUSION_MISMATCH")
    for field in ("report_relation_id", "frontier_id", "context_id", "suffix_id"):
        if (
            not isinstance(payload.get(field), str)
            or not payload[field]
            or conclusion["scope"][field] != payload[field]
        ):
            raise EBRCInvalid("COLLISION_RULE_SCOPE_MISMATCH")
    if conclusion["scope"]["scope_digest_sha256"] != payload.get(
        "scope_digest_sha256"
    ):
        raise EBRCInvalid("COLLISION_RULE_SCOPE_MISMATCH")


def _check_inequality(step: dict[str, Any], nodes: dict[str, dict[str, Any]]) -> None:
    if step["premises"] or len(step["evidence_refs"]) != 1:
        raise EBRCInvalid("OBSERVER_RULE_SHAPE_INVALID")
    payload = _node_payload(nodes, step["evidence_refs"][0], "SEMANTIC_PROOF")
    outcomes = payload.get("outcomes")
    observations = payload.get("observations")
    if (
        payload.get("status") != "VERIFIED"
        or payload.get("kind") != "OBSERVER_INEQUALITY"
        or not isinstance(outcomes, list)
        or len(outcomes) != 2
        or not isinstance(observations, list)
        or len(observations) != 2
        or observations[0] == observations[1]
        or not isinstance(payload.get("observer_id"), str)
        or not payload["observer_id"]
    ):
        raise EBRCInvalid("OBSERVER_RULE_EVIDENCE_INVALID")
    conclusion = step["conclusion"]
    _require_exact_operational_rule_claim(conclusion, "RETROSPECTIVE_EXACT")
    if conclusion["predicate"] != "OBSERVER_INEQUALITY" or conclusion["subject"] != {
        "outcomes": outcomes
    }:
        raise EBRCInvalid("OBSERVER_RULE_CONCLUSION_MISMATCH")
    if conclusion["scope"]["observer_id"] != payload.get("observer_id"):
        raise EBRCInvalid("OBSERVER_RULE_SCOPE_MISMATCH")
    if conclusion["scope"]["scope_digest_sha256"] != payload.get(
        "scope_digest_sha256"
    ):
        raise EBRCInvalid("OBSERVER_RULE_SCOPE_MISMATCH")


def _check_nonfactor(step: dict[str, Any], premises: list[dict[str, Any]]) -> None:
    if step["evidence_refs"] or len(premises) != 4 or not _same_scope(premises):
        raise EBRCInvalid("NONFACTOR_RULE_SHAPE_INVALID")
    collision = next((claim for claim in premises if claim["predicate"] == "REPORT_COLLISION"), None)
    inequality = next((claim for claim in premises if claim["predicate"] == "OBSERVER_INEQUALITY"), None)
    musts = [claim for claim in premises if claim["predicate"] == "MUST_OUTCOME"]
    if collision is None or inequality is None or len(musts) != 2:
        raise EBRCInvalid("NONFACTOR_RULE_PREMISES_INVALID")
    history_ids = collision["subject"].get("history_ids")
    must_by_history = {claim["subject"].get("history_id"): claim for claim in musts}
    if set(must_by_history) != set(history_ids):
        raise EBRCInvalid("NONFACTOR_RULE_HISTORY_MISMATCH")
    outcomes = [must_by_history[history_id]["subject"].get("outcome") for history_id in history_ids]
    if inequality["subject"].get("outcomes") != outcomes:
        raise EBRCInvalid("NONFACTOR_RULE_OBSERVER_MISMATCH")
    conclusion = step["conclusion"]
    _require_exact_operational_rule_claim(conclusion, "RETROSPECTIVE_EXACT")
    expected_subject = {
        "history_ids": history_ids,
        "report_cell_id": collision["subject"].get("report_cell_id"),
        "outcomes": outcomes,
    }
    if (
        conclusion["predicate"] != "NONFACTORING"
        or conclusion["evidence_grade"] != "RETROSPECTIVE_EXACT"
        or conclusion["subject"] != expected_subject
        or conclusion["scope"] != collision["scope"]
    ):
        raise EBRCInvalid("NONFACTOR_RULE_CONCLUSION_MISMATCH")


def _flow_path_exists(
    graph: dict[str, Any],
    sources: set[str],
    targets: set[str],
) -> bool:
    adjacency: dict[str, list[str]] = {}
    for edge in graph["edges"]:
        if edge["role"] in FLOW_ROLES:
            adjacency.setdefault(edge["source"], []).append(edge["target"])
    pending = list(sources)
    seen = set(sources)
    while pending:
        current = pending.pop()
        if current in targets:
            return True
        for target in adjacency.get(current, []):
            if target not in seen:
                seen.add(target)
                pending.append(target)
    return False


def _check_prospective(
    step: dict[str, Any],
    premise: dict[str, Any],
    graph: dict[str, Any],
    nodes: dict[str, dict[str, Any]],
) -> None:
    if len(step["evidence_refs"]) != 3 or premise["predicate"] != "NONFACTORING":
        raise EBRCInvalid("PROSPECTIVE_RULE_SHAPE_INVALID")
    references_by_role: dict[str, str] = {}
    for reference in step["evidence_refs"]:
        node = nodes.get(reference)
        if node is None:
            raise EBRCInvalid("PROOF_UNKNOWN_EVIDENCE_REF")
        references_by_role[node["role"]] = reference
    if set(references_by_role) != {"QUERY", "SELECTION_POLICY", "PRECOMMITMENT"}:
        raise EBRCInvalid("PROSPECTIVE_RULE_EVIDENCE_INVALID")
    policy = nodes[references_by_role["SELECTION_POLICY"]]["payload"]
    precommit = nodes[references_by_role["PRECOMMITMENT"]]["payload"]
    if policy.get("outcome_free") is not True or precommit.get("status") != "VERIFIED":
        raise EBRCInvalid("PROSPECTIVE_RULE_EVIDENCE_INVALID")

    outcome_nodes = {
        node_id
        for node_id, node in nodes.items()
        if node["role"] in {"RAW_EVENT", "RUNTIME_OBSERVATION"}
    }
    selector_nodes = {
        references_by_role["QUERY"],
        references_by_role["SELECTION_POLICY"],
    }
    if _flow_path_exists(graph, outcome_nodes, selector_nodes):
        raise EBRCInvalid("PROSPECTIVE_OUTCOME_DEPENDENCY")
    precedence = {
        (edge["source"], edge["target"])
        for edge in graph["edges"]
        if edge["role"] == "PRECEDES"
    }
    precommit_id = references_by_role["PRECOMMITMENT"]
    if any((precommit_id, outcome_id) not in precedence for outcome_id in outcome_nodes):
        raise EBRCInvalid("PROSPECTIVE_PRECOMMIT_ORDER_MISSING")

    conclusion = step["conclusion"]
    _require_exact_operational_rule_claim(conclusion, "OUTCOME_FREE_PRECOMMITTED")
    if (
        not _same_semantic_claim(conclusion, premise)
        or conclusion["evidence_grade"] != "OUTCOME_FREE_PRECOMMITTED"
    ):
        raise EBRCInvalid("PROSPECTIVE_RULE_CONCLUSION_MISMATCH")


def _check_unique_resources(resources: Any, reason: str) -> list[str]:
    if (
        not isinstance(resources, list)
        or any(not isinstance(resource, str) or not resource for resource in resources)
        or len(set(resources)) != len(resources)
    ):
        raise EBRCInvalid(reason)
    return resources


def _check_instruction_correspondence(value: Any) -> None:
    mapping = _require_dict(value, "CONTEXT_INSTRUCTION_MAP_MALFORMED")
    entries = _require_list(mapping.get("entries"), "CONTEXT_INSTRUCTION_MAP_MALFORMED")
    if mapping.get("status") != "VERIFIED" or mapping.get("total_on_witness") is not True:
        raise EBRCInvalid("CONTEXT_INSTRUCTION_MAP_INCOMPLETE")
    source_offsets: set[int] = set()
    target_offsets: set[int] = set()
    for raw_entry in entries:
        entry = _require_dict(raw_entry, "CONTEXT_INSTRUCTION_MAP_MALFORMED")
        if set(entry) != {"source_insn", "target_insn", "relation"}:
            raise EBRCInvalid("CONTEXT_INSTRUCTION_MAP_MALFORMED")
        source = entry.get("source_insn")
        target = entry.get("target_insn")
        if (
            isinstance(source, bool)
            or isinstance(target, bool)
            or not isinstance(source, int)
            or not isinstance(target, int)
            or source < 0
            or target < 0
            or entry.get("relation") not in {"IDENTITY", "RENAMED", "FRAMED"}
        ):
            raise EBRCInvalid("CONTEXT_INSTRUCTION_MAP_MALFORMED")
        if source in source_offsets or target in target_offsets:
            raise EBRCInvalid("CONTEXT_INSTRUCTION_MAP_DUPLICATE")
        source_offsets.add(source)
        target_offsets.add(target)
    if not entries:
        raise EBRCInvalid("CONTEXT_INSTRUCTION_MAP_INCOMPLETE")


def _check_context_transport(
    step: dict[str, Any],
    graph: dict[str, Any],
    nodes: dict[str, dict[str, Any]],
) -> None:
    if step["premises"] or len(step["evidence_refs"]) not in {4, 5}:
        raise EBRCInvalid("CONTEXT_RULE_SHAPE_INVALID")

    referenced_nodes = []
    for reference in step["evidence_refs"]:
        node = nodes.get(reference)
        if node is None:
            raise EBRCInvalid("PROOF_UNKNOWN_EVIDENCE_REF")
        referenced_nodes.append(node)
    by_role = {node["role"]: node for node in referenced_nodes}
    if not {"CLAIM", "TRANSFORMATION", "TRANSPORT_PROOF", "CHECKER"}.issubset(by_role) or (
        set(by_role) - {"CLAIM", "TRANSFORMATION", "TRANSPORT_PROOF", "CHECKER", "IDENTITY_RECEIPT"}
    ):
        raise EBRCInvalid("CONTEXT_RULE_EVIDENCE_INVALID")

    source_payload = by_role["CLAIM"]["payload"]
    transform = by_role["TRANSFORMATION"]["payload"]
    transport = by_role["TRANSPORT_PROOF"]["payload"]
    checker = by_role["CHECKER"]["payload"]
    target_identity = by_role.get("IDENTITY_RECEIPT", {}).get("payload")
    if any(key in transport for key in CONTEXT_FORBIDDEN_PAYLOAD_KEYS):
        raise EBRCInvalid("CONTEXT_TARGET_VERDICT_PREMISE")
    if checker.get("kind") != "CONTEXTUAL_TRANSPORT_CHECKER" or checker.get("status") != "VERIFIED":
        raise EBRCInvalid("CONTEXT_RULE_EVIDENCE_INVALID")

    if source_payload.get("kind") != "SOURCE_EBRC_CERTIFICATE" or source_payload.get("status") != "CERTIFIED":
        raise EBRCInvalid("CONTEXT_SOURCE_CERTIFICATE_INVALID")
    source_claim = _validate_claim(source_payload.get("claim"))
    if source_payload.get("claim_digest_sha256") != canonical_digest(source_claim):
        raise EBRCInvalid("CONTEXT_SOURCE_CERTIFICATE_DIGEST_MISMATCH")
    if (
        source_claim["predicate"] != "NONFACTORING"
        or source_claim["quantifier"] != "AT"
        or source_claim["scope"]["report_authority"] != "OPERATIONAL_OBSERVATION"
        or source_claim["evidence_grade"] not in {"OUTCOME_FREE_PRECOMMITTED", "TRANSPORTED"}
    ):
        raise EBRCInvalid("CONTEXT_SOURCE_CERTIFICATE_UNSUPPORTED")
    source_scope_digest = source_claim["scope"]["scope_digest_sha256"]
    if source_payload.get("certificate") != f"NONFACTORING@{source_scope_digest}":
        raise EBRCInvalid("CONTEXT_SOURCE_CERTIFICATE_MISMATCH")

    if transform.get("kind") != "CONTEXT_TERM" or transform.get("status") != "VERIFIED":
        raise EBRCInvalid("CONTEXT_TRANSFORM_INVALID")
    target_scope_digest = graph["scope_digest_sha256"]
    if (
        transform.get("source_scope_digest_sha256") != source_scope_digest
        or transform.get("target_scope_digest_sha256") != target_scope_digest
    ):
        raise EBRCInvalid("CONTEXT_TRANSFORM_SCOPE_MISMATCH")
    trivial = transform.get("trivial")
    if not isinstance(trivial, bool):
        raise EBRCInvalid("CONTEXT_TRANSFORM_INVALID")
    if source_scope_digest == target_scope_digest and trivial is not True:
        raise EBRCInvalid("CONTEXT_TRANSFORM_TRIVIALITY_MISMATCH")
    source_xlated = transform.get("source_xlated_sha256")
    target_xlated = transform.get("target_xlated_sha256")
    if not _is_sha256(source_xlated) or not _is_sha256(target_xlated):
        raise EBRCInvalid("CONTEXT_TRANSFORM_IDENTITY_INVALID")
    if trivial is False and source_xlated == target_xlated:
        raise EBRCInvalid("CONTEXT_TRANSFORM_NONTRIVIALITY_INVALID")
    if target_identity is not None:
        if target_identity.get("status") != "VERIFIED":
            raise EBRCInvalid("CONTEXT_TARGET_IDENTITY_INVALID")
        for field in ("object_sha256", "xlated_sha256", "btf_sha256"):
            if not _is_sha256(target_identity.get(field)):
                raise EBRCInvalid("CONTEXT_TARGET_IDENTITY_INVALID")
        if (
            not isinstance(target_identity.get("kernel_release"), str)
            or not target_identity["kernel_release"]
            or target_identity.get("xlated_sha256") != target_xlated
        ):
            raise EBRCInvalid("CONTEXT_TARGET_IDENTITY_MISMATCH")

    if transport.get("kind") != "CONTEXT_TRANSPORT" or transport.get("status") != "VERIFIED":
        raise EBRCInvalid("CONTEXT_TRANSPORT_INVALID")
    if transport.get("derivation_kind") != DERIVED_CONTEXTUAL:
        raise EBRCInvalid("CONTEXT_DERIVATION_CHAIN_INVALID")
    derivation_chain = _require_dict(
        transport.get("derivation_chain"),
        "CONTEXT_DERIVATION_CHAIN_INVALID",
    )
    expected_chain = {
        "kind": DERIVED_CONTEXTUAL,
        "rule": "CONTEXT_TRANSPORT",
        "source_claim_digest_sha256": canonical_digest(source_claim),
        "transform_digest_sha256": canonical_digest(transform),
        "target_claim_digest_sha256": canonical_digest(step["conclusion"]),
    }
    if derivation_chain != expected_chain:
        raise EBRCInvalid("CONTEXT_DERIVATION_CHAIN_INVALID")
    if target_identity is not None and transport.get("target_identity_digest_sha256") != canonical_digest(target_identity):
        raise EBRCInvalid("CONTEXT_TARGET_IDENTITY_MISMATCH")
    if (
        transport.get("source_claim_digest_sha256") != canonical_digest(source_claim)
        or transport.get("source_scope_digest_sha256") != source_scope_digest
        or transport.get("target_scope_digest_sha256") != target_scope_digest
        or transport.get("transform_digest_sha256") != canonical_digest(transform)
    ):
        raise EBRCInvalid("CONTEXT_TRANSPORT_BINDING_MISMATCH")

    obligations = _require_dict(transport.get("obligations"), "CONTEXT_OBLIGATIONS_MALFORMED")
    if set(obligations) != CONTEXT_TRANSPORT_OBLIGATIONS:
        raise EBRCInvalid("CONTEXT_OBLIGATIONS_MALFORMED")
    if any(value is not True for value in obligations.values()):
        raise EBRCInvalid("CONTEXT_OBLIGATION_FAILED")
    _check_instruction_correspondence(transport.get("instruction_correspondence"))

    footprint = _require_dict(transport.get("footprint"), "CONTEXT_FOOTPRINT_MALFORMED")
    effect = _require_dict(transport.get("effect"), "CONTEXT_EFFECT_MALFORMED")
    footprint_resources = set(_check_unique_resources(footprint.get("resources"), "CONTEXT_FOOTPRINT_MALFORMED"))
    written_resources = set(_check_unique_resources(effect.get("writes"), "CONTEXT_EFFECT_MALFORMED"))
    if footprint_resources & written_resources:
        raise EBRCInvalid("CONTEXT_FOOTPRINT_EFFECT_CONFLICT")

    history_map = _require_list(transport.get("history_map"), "CONTEXT_HISTORY_MAP_MALFORMED")
    source_histories = source_claim["subject"].get("history_ids")
    if not isinstance(source_histories, list) or len(source_histories) != 2:
        raise EBRCInvalid("CONTEXT_SOURCE_CERTIFICATE_UNSUPPORTED")
    mapped_histories: list[str] = []
    seen_sources: set[str] = set()
    seen_targets: set[str] = set()
    for raw_entry in history_map:
        entry = _require_dict(raw_entry, "CONTEXT_HISTORY_MAP_MALFORMED")
        if set(entry) != {"source_history_id", "target_history_id"}:
            raise EBRCInvalid("CONTEXT_HISTORY_MAP_MALFORMED")
        source = entry.get("source_history_id")
        target = entry.get("target_history_id")
        if (
            not isinstance(source, str)
            or not source
            or not isinstance(target, str)
            or not target
            or source in seen_sources
            or target in seen_targets
        ):
            raise EBRCInvalid("CONTEXT_HISTORY_MAP_MALFORMED")
        seen_sources.add(source)
        seen_targets.add(target)
    if set(source_histories) != seen_sources:
        raise EBRCInvalid("CONTEXT_HISTORY_MAP_INCOMPLETE")
    for source in source_histories:
        mapped_histories.append(
            next(entry["target_history_id"] for entry in history_map if entry["source_history_id"] == source)
        )

    conclusion = step["conclusion"]
    _require_context_transport_rule_claim(conclusion)
    if conclusion["scope"]["scope_digest_sha256"] != target_scope_digest:
        raise EBRCInvalid("CONTEXT_TARGET_SCOPE_MISMATCH")
    target_scope = transport.get("target_scope")
    if target_scope is not None and target_scope != conclusion["scope"]:
        raise EBRCInvalid("CONTEXT_TARGET_SCOPE_MISMATCH")
    expected_subject = copy.deepcopy(transport.get("target_subject"))
    if not isinstance(expected_subject, dict) or not expected_subject:
        raise EBRCInvalid("CONTEXT_TARGET_SUBJECT_MALFORMED")
    if expected_subject.get("history_ids") != mapped_histories:
        raise EBRCInvalid("CONTEXT_HISTORY_MAP_TARGET_MISMATCH")
    if expected_subject.get("outcomes") != source_claim["subject"].get("outcomes"):
        raise EBRCInvalid("CONTEXT_OUTCOME_PRESERVATION_MISMATCH")
    if conclusion["subject"] != expected_subject:
        raise EBRCInvalid("CONTEXT_TARGET_SUBJECT_MISMATCH")

    outcome_nodes = {
        node_id
        for node_id, node in nodes.items()
        if node["role"] in {"RAW_EVENT", "RUNTIME_OBSERVATION"}
    }
    transform_nodes = {node["node_id"] for node in referenced_nodes if node["role"] == "TRANSFORMATION"}
    if _flow_path_exists(graph, outcome_nodes, transform_nodes):
        raise EBRCInvalid("CONTEXT_OUTCOME_DEPENDENCY")


def _profile(claims: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    strongest: dict[str, dict[str, Any]] = {}
    for claim in claims:
        key = _claim_semantic_key(claim)
        current = strongest.get(key)
        if current is None or GRADE_RANK[claim["evidence_grade"]] > GRADE_RANK[current["evidence_grade"]]:
            strongest[key] = copy.deepcopy(claim)
    return sorted(
        strongest.values(),
        key=lambda item: (
            item["predicate"],
            item["scope"]["scope_digest_sha256"],
            canonical_digest(item["subject"]),
        ),
    )


def _evaluate_proof(
    graph: dict[str, Any],
    nodes: dict[str, dict[str, Any]],
    proof: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    raw_steps = _require_list(proof.get("steps"), "PROOF_STEPS_MALFORMED")
    steps: dict[str, dict[str, Any]] = {}
    for raw_step in raw_steps:
        step = _require_dict(raw_step, "PROOF_STEP_MALFORMED")
        if set(step) != {"step_id", "rule", "premises", "evidence_refs", "conclusion"}:
            raise EBRCInvalid("PROOF_STEP_MALFORMED")
        step_id = step.get("step_id")
        if not isinstance(step_id, str) or not step_id or step_id in steps:
            raise EBRCInvalid("PROOF_DUPLICATE_OR_INVALID_STEP_ID")
        if step.get("rule") not in {
            "RAW",
            "MUST",
            "COLLISION",
            "OBSERVER_INEQUALITY",
            "NONFACTOR",
            "PROSPECTIVE",
            "CONTEXT_TRANSPORT",
        }:
            raise EBRCInvalid("PROOF_RULE_INVALID")
        premises = _require_list(step.get("premises"), "PROOF_PREMISES_MALFORMED")
        evidence_refs = _require_list(step.get("evidence_refs"), "PROOF_EVIDENCE_REFS_MALFORMED")
        if any(not isinstance(reference, str) or not reference for reference in premises):
            raise EBRCInvalid("PROOF_PREMISES_MALFORMED")
        if any(not isinstance(reference, str) or not reference for reference in evidence_refs):
            raise EBRCInvalid("PROOF_EVIDENCE_REFS_MALFORMED")
        if len(set(premises)) != len(premises) or len(set(evidence_refs)) != len(evidence_refs):
            raise EBRCInvalid("PROOF_DUPLICATE_REFERENCE")
        _validate_claim(step.get("conclusion"), graph["scope_digest_sha256"])
        steps[step_id] = step
    for step in steps.values():
        if any(premise not in steps for premise in step["premises"]):
            raise EBRCInvalid("PROOF_UNKNOWN_PREMISE")
        if any(reference not in nodes for reference in step["evidence_refs"]):
            raise EBRCInvalid("PROOF_UNKNOWN_EVIDENCE_REF")

    evaluated: dict[str, dict[str, Any]] = {}
    visiting: set[str] = set()
    trace: list[str] = []

    def evaluate(step_id: str) -> dict[str, Any]:
        if step_id in evaluated:
            return evaluated[step_id]
        if step_id in visiting:
            raise EBRCInvalid("PROOF_CYCLE")
        visiting.add(step_id)
        step = steps[step_id]
        premise_claims = [evaluate(premise) for premise in step["premises"]]
        rule = step["rule"]
        if rule == "RAW":
            _check_raw(step, nodes)
        elif rule == "MUST":
            _check_must(step, nodes)
        elif rule == "COLLISION":
            _check_collision(step, nodes)
        elif rule == "OBSERVER_INEQUALITY":
            _check_inequality(step, nodes)
        elif rule == "NONFACTOR":
            _check_nonfactor(step, premise_claims)
        elif rule == "PROSPECTIVE":
            if len(premise_claims) != 1:
                raise EBRCInvalid("PROSPECTIVE_RULE_SHAPE_INVALID")
            _check_prospective(step, premise_claims[0], graph, nodes)
        elif rule == "CONTEXT_TRANSPORT":
            _check_context_transport(step, graph, nodes)
        conclusion = copy.deepcopy(step["conclusion"])
        visiting.remove(step_id)
        evaluated[step_id] = conclusion
        trace.append(step_id)
        return conclusion

    for step_id in steps:
        evaluate(step_id)
    return evaluated, trace


def check_certificate(graph_document: Any, claim_document: Any, proof_document: Any) -> dict[str, Any]:
    """Check one exact EBRC certificate and return a fail-closed result object."""

    try:
        graph, nodes = _validate_graph(graph_document)
        claim = _validate_claim(claim_document, graph["scope_digest_sha256"])
        proof = _require_dict(proof_document, "PROOF_MALFORMED")
        required = {
            "schema",
            "proof_id",
            "graph_digest_sha256",
            "requested_claim_digest_sha256",
            "root_step_id",
            "steps",
            "declared_missing_obligations",
        }
        if set(proof) != required or proof.get("schema") != PROOF_SCHEMA:
            raise EBRCInvalid("PROOF_MALFORMED")
        if not isinstance(proof.get("proof_id"), str) or not proof["proof_id"]:
            raise EBRCInvalid("PROOF_ID_INVALID")
        root_step_id = proof.get("root_step_id")
        if root_step_id is not None and (
            not isinstance(root_step_id, str) or not root_step_id
        ):
            raise EBRCInvalid("PROOF_ROOT_STEP_INVALID")
        if proof.get("graph_digest_sha256") != canonical_digest(graph):
            raise EBRCInvalid("PROOF_GRAPH_DIGEST_MISMATCH")
        if proof.get("requested_claim_digest_sha256") != canonical_digest(claim):
            raise EBRCInvalid("PROOF_CLAIM_DIGEST_MISMATCH")
        missing = _require_list(
            proof.get("declared_missing_obligations"),
            "PROOF_MISSING_OBLIGATIONS_MALFORMED",
        )
        if any(not isinstance(item, str) or not item for item in missing) or len(set(missing)) != len(missing):
            raise EBRCInvalid("PROOF_MISSING_OBLIGATIONS_MALFORMED")
        evaluated, trace = _evaluate_proof(graph, nodes, proof)
        profile = _profile(evaluated.values())
        if root_step_id is None:
            obligations = sorted(set(missing + ["PROOF_FOR_REQUESTED_CLAIM"]))
            return {
                "schema": RESULT_SCHEMA,
                "status": "BLOCKED",
                "unknown_kind": "INCONCLUSIVE",
                "claim": copy.deepcopy(claim),
                "missing_obligations": obligations,
                "invalid_reasons": [],
                "strongest_claim_profile": profile,
                "proof_trace": trace,
            }
        if root_step_id not in evaluated:
            raise EBRCInvalid("PROOF_ROOT_STEP_MISSING")
        root_claim = evaluated[root_step_id]
        if canonical_digest(root_claim) != canonical_digest(claim):
            obligations = sorted(set(missing + ["REQUESTED_CLAIM_NOT_DERIVED"]))
            return {
                "schema": RESULT_SCHEMA,
                "status": "BLOCKED",
                "unknown_kind": "INCONCLUSIVE",
                "claim": copy.deepcopy(claim),
                "missing_obligations": obligations,
                "invalid_reasons": [],
                "strongest_claim_profile": profile,
                "proof_trace": trace,
            }
        result = {
            "schema": RESULT_SCHEMA,
            "status": "CERTIFIED",
            "assessment": claim["predicate"],
            "claim": copy.deepcopy(claim),
            "missing_obligations": [],
            "invalid_reasons": [],
            "strongest_claim_profile": profile,
            "proof_trace": trace,
        }
        if claim["predicate"] == "NONFACTORING" and claim["quantifier"] == "AT":
            result["certificate"] = f"NONFACTORING@{claim['scope']['scope_digest_sha256']}"
        return result
    except EBRCInvalid as exc:
        return {
            "schema": RESULT_SCHEMA,
            "status": "INVALID_GRAPH",
            "invalid_reasons": [exc.reason],
            "missing_obligations": [],
            "strongest_claim_profile": [],
            "proof_trace": [],
        }
