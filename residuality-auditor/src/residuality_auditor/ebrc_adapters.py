"""Evidence-only compiler adapters for the generic EBRC checker.

Adapters validate source-specific bytes and compile facts into generic proof
terms.  They deliberately ignore legacy/final verdict fields: the generic
checker in :mod:`residuality_auditor.ebrc` is the only component that emits an
EBRC terminal result.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from .ebrc import GRAPH_SCHEMA, PROOF_SCHEMA, canonical_digest, make_claim, make_node
from .stock_r_v2 import (
    StockRV2Error,
    audit_bundle,
    canonical_sha256 as v2_digest,
    check_history_case_binding,
    check_must_outcome_proof,
    make_history_case_binding,
)


class EBRCAdapterError(ValueError):
    """The source bundle is malformed and cannot be compiled safely."""


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EBRCAdapterError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EBRCAdapterError(f"JSON root must be an object: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise EBRCAdapterError(f"JSONL row {line_number} is not an object: {path}")
            rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise EBRCAdapterError(f"cannot read JSONL {path}: {exc}") from exc
    return rows


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise EBRCAdapterError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def _edge(edge_id: str, role: str, source: str, target: str) -> dict[str, str]:
    return {"edge_id": edge_id, "role": role, "source": source, "target": target}


def _proof_document(
    proof_id: str,
    graph: dict[str, Any],
    claim: dict[str, Any],
    steps: list[dict[str, Any]],
    root_step_id: str | None,
    missing: list[str],
) -> dict[str, Any]:
    return {
        "schema": PROOF_SCHEMA,
        "proof_id": proof_id,
        "graph_digest_sha256": canonical_digest(graph),
        "requested_claim_digest_sha256": canonical_digest(claim),
        "root_step_id": root_step_id,
        "steps": steps,
        "declared_missing_obligations": sorted(set(missing)),
    }


def _scope_descriptor(scope_vector: dict[str, Any], scope_digest: str) -> dict[str, Any]:
    frontier = scope_vector["frontier"]
    report = scope_vector["report"]
    return {
        "scope_digest_sha256": scope_digest,
        "report_authority": report["authority"],
        "report_relation_id": f"report.operational.{report['cell_id']}",
        "frontier_id": f"frontier.insn-{frontier['visit_insn']}",
        "context_id": "context.stock-r-v2.array-map",
        "suffix_id": str(scope_vector["suffix"]),
        "observer_id": str(scope_vector["observer"]),
    }


def _fallback_v2_scope(
    query: dict[str, Any],
    runtime: dict[str, Any],
    event: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    histories = []
    for role, case in (("old", 0), ("current", 1)):
        snapshot = event.get(role, {})
        histories.append(
            {
                "role": role,
                "case": case,
                "history_digest_sha256": canonical_digest(snapshot.get("history_entries", [])),
                "outcome": case,
            }
        )
    report_cell_id = canonical_digest(
        {
            "source": event.get("source"),
            "visit_insn": event.get("visit_insn"),
            "exact_level": event.get("exact_level"),
            "histories": [history["history_digest_sha256"] for history in histories],
        }
    )
    identity = runtime["identity"]
    scope_vector = {
        "artifact": {
            "program_name": query["identity"]["program_name"],
            "object_sha256": query["identity"]["object_sha256"],
            "xlated_sha256": identity["xlated_sha256"],
            "btf_sha256": query["identity"]["btf_sha256"],
        },
        "implementation": {
            "kernel_release": query["identity"]["kernel_release"],
            "program_id": identity["program_id"],
            "program_tag": identity["program_tag"],
            "program_load_time": identity["program_load_time"],
        },
        "frontier": {
            "source": event.get("source"),
            "exact_level": event.get("exact_level"),
            "visit_insn": event.get("visit_insn"),
        },
        "context": {"trial_plan": copy.deepcopy(query["trial_plan"])},
        "report": {
            "authority": "OPERATIONAL_OBSERVATION",
            "relation": event.get("source"),
            "cell_id": report_cell_id,
        },
        "observer": query["trial_plan"]["observer"],
        "suffix": "shared_suffix",
        "environment": {
            "target_comm": "rac-v2-witness",
            "capture_backend": "fentry+fexit",
        },
    }
    return scope_vector, histories


def _v2_graph_and_proof(bundle: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    query = _read_json(bundle / "query" / "query.json")
    policy = _read_json(bundle / "query" / "selection-policy.json")
    precommit = _read_json(bundle / "query" / "precommit.json")
    runtime = _read_json(bundle / "raw" / "runtime.json")
    audit = audit_bundle(bundle)
    if audit.get("invalid_reasons") or audit.get("assessment", {}).get("status") == "INVALID_EVIDENCE":
        raise EBRCAdapterError(
            "invalid Stock-R V2 evidence: " + ", ".join(audit.get("invalid_reasons", []))
        )
    operational = audit.get("operational_prune", {})
    event = operational.get("event")
    if not isinstance(event, dict):
        raise EBRCAdapterError("Stock-R V2 bundle has no qualifying operational prune")

    proof_path = bundle / "proof" / "must-outcome-proof.json"
    source_proof = _read_json(proof_path) if proof_path.is_file() else None
    proof_result = (
        check_must_outcome_proof(source_proof, query, runtime)
        if source_proof is not None
        else {"status": "ABSENT"}
    )
    if proof_result.get("status") == "INVALID":
        raise EBRCAdapterError("invalid Stock-R V2 must-outcome proof")

    candidate_binding: dict[str, Any] | None = None
    if source_proof is not None and proof_result.get("status") == "VERIFIED":
        try:
            candidate_binding = make_history_case_binding(query, event, runtime, source_proof)
        except StockRV2Error as exc:
            raise EBRCAdapterError(f"cannot derive V2 exact scope: {exc}") from exc
    binding_path = bundle / "proof" / "history-case-binding.json"
    source_binding = _read_json(binding_path) if binding_path.is_file() else None
    binding_result = (
        check_history_case_binding(source_binding, query, event, runtime, source_proof)
        if source_binding is not None
        else {"status": "ABSENT"}
    )
    if binding_result.get("status") == "INVALID":
        raise EBRCAdapterError("invalid Stock-R V2 history-case binding")
    binding_verified = binding_result.get("status") == "VERIFIED"
    if binding_verified:
        binding = source_binding
        scope_vector = binding["scope"]
        histories = binding["histories"]
    elif candidate_binding is not None:
        binding = candidate_binding
        scope_vector = binding["scope"]
        histories = binding["histories"]
    else:
        scope_vector, histories = _fallback_v2_scope(query, runtime, event)
        binding = {
            "scope": scope_vector,
            "scope_digest_sha256": canonical_digest(scope_vector),
            "histories": histories,
            "report_cell": scope_vector["report"],
        }
    scope_digest = binding["scope_digest_sha256"]
    scope = _scope_descriptor(scope_vector, scope_digest)

    history_ids = [f"history.{history['history_digest_sha256']}" for history in histories]
    outcomes = [history["outcome"] for history in histories]
    report_cell_id = binding["report_cell"]["cell_id"]
    requested_subject = {
        "history_ids": history_ids,
        "report_cell_id": report_cell_id,
        "outcomes": outcomes,
    }
    claim = make_claim(
        "claim.stock-r-v2.exact-operational-nonfactor",
        "NONFACTORING",
        scope,
        requested_subject,
        evidence_grade="OUTCOME_FREE_PRECOMMITTED",
    )

    precommit_time = precommit["recorded_at_ns"]
    runtime_time = runtime.get("runtime_ended_ns", runtime.get("runtime_started_ns", precommit_time + 1))
    event_time = event.get("observed_at_ns", runtime.get("program_load_completed_ns", precommit_time + 1))
    nodes = [
        make_node(
            "query.exact",
            "QUERY",
            {
                "query_id": query["query_id"],
                "query_digest_sha256": v2_digest(query),
                "source_closure_sha256": query["source_closure_sha256"],
                "build_closure_sha256": query["build_closure_sha256"],
            },
            recorded_at_ns=precommit_time,
        ),
        make_node(
            "selection.policy",
            "SELECTION_POLICY",
            {
                "policy_id": policy["policy_id"],
                "query_digest_sha256": policy["query_digest_sha256"],
                "outcome_free": policy["outcome_free"],
                "forbidden_input_prefixes": policy["forbidden_input_prefixes"],
            },
            recorded_at_ns=precommit_time,
        ),
        make_node(
            "precommit.record",
            "PRECOMMITMENT",
            {
                "status": "VERIFIED",
                "phase": precommit["phase"],
                "query_digest_sha256": precommit["query_digest_sha256"],
                "selection_policy_sha256": precommit["selection_policy_sha256"],
            },
            recorded_at_ns=precommit_time,
        ),
        make_node(
            "identity.runtime",
            "IDENTITY_RECEIPT",
            {"status": "VERIFIED", **copy.deepcopy(runtime["identity"])},
            recorded_at_ns=runtime.get("program_load_completed_ns"),
        ),
        make_node(
            "event.operational-collision",
            "RAW_EVENT",
            {
                "status": "VERIFIED",
                "kind": "REPORT_COLLISION",
                "history_ids": history_ids,
                "report_cell_id": report_cell_id,
                "report_relation_id": scope["report_relation_id"],
                "frontier_id": scope["frontier_id"],
                "context_id": scope["context_id"],
                "suffix_id": scope["suffix_id"],
                "scope_digest_sha256": scope_digest,
            },
            recorded_at_ns=event_time,
        ),
        make_node(
            "checker.stock-r-v2",
            "CHECKER",
            {
                "calculus": (
                    source_proof["checker"]["calculus"]
                    if source_proof is not None
                    else "stock-r-v2-array-map-must-outcome-v1"
                ),
                "source_path": (
                    source_proof["checker"]["source_path"]
                    if source_proof is not None
                    else "residuality-auditor/src/residuality_auditor/stock_r_v2.py"
                ),
                "status": "VERIFIED" if proof_result.get("status") == "VERIFIED" else "ABSENT",
            },
        ),
    ]
    steps: list[dict[str, Any]] = []
    edges = [
        _edge("edge.query-selected-by-policy", "SELECTED_BY", "query.exact", "selection.policy"),
        _edge("edge.precommit-query", "BINDS", "precommit.record", "query.exact"),
        _edge("edge.precommit-policy", "BINDS", "precommit.record", "selection.policy"),
        _edge("edge.identity-event", "BINDS", "identity.runtime", "event.operational-collision"),
        _edge("edge.precedes-event", "PRECEDES", "precommit.record", "event.operational-collision"),
    ]

    case_to_history = {
        history["case"]: history_ids[index]
        for index, history in enumerate(histories)
    }
    replication = audit["runtime_replication"]
    for case_string, observed_values in sorted(replication["outcomes_by_case"].items()):
        case = int(case_string)
        if not isinstance(observed_values, list) or len(observed_values) != 1:
            raise EBRCAdapterError("V2 runtime observation is not a singleton sample set")
        history_id = case_to_history.get(case, f"case.{case}") if binding_verified else f"case.{case}"
        node_id = f"runtime.case.{case}"
        nodes.append(
            make_node(
                node_id,
                "RUNTIME_OBSERVATION",
                {
                    "status": "OBSERVED",
                    "case": case,
                    "history_id": history_id,
                    "outcome": observed_values[0],
                    "trial_count": replication["counts_by_case"][case_string],
                },
                recorded_at_ns=runtime_time,
            )
        )
        edges.extend(
            [
                _edge(f"edge.identity-runtime-{case}", "BINDS", "identity.runtime", node_id),
                _edge(f"edge.precedes-runtime-{case}", "PRECEDES", "precommit.record", node_id),
            ]
        )
        may_claim = make_claim(
            f"claim.may.case-{case}",
            "MAY_OUTCOME",
            scope,
            {"history_id": history_id, "outcome": observed_values[0]},
        )
        steps.append(
            {
                "step_id": f"step.raw.case-{case}",
                "rule": "RAW",
                "premises": [],
                "evidence_refs": [node_id],
                "conclusion": may_claim,
            }
        )

    collision_claim = make_claim(
        "claim.collision.exact",
        "REPORT_COLLISION",
        scope,
        {"history_ids": history_ids, "report_cell_id": report_cell_id},
    )
    steps.append(
        {
            "step_id": "step.collision",
            "rule": "COLLISION",
            "premises": [],
            "evidence_refs": ["event.operational-collision"],
            "conclusion": collision_claim,
        }
    )

    missing: list[str] = []
    root_step_id: str | None = None
    if proof_result.get("status") != "VERIFIED":
        missing.append("MUST_OUTCOME_PROOF")
    if not binding_verified:
        missing.append("HISTORY_CASE_BINDING")
    else:
        for index, history in enumerate(histories):
            history_id = history_ids[index]
            case = history["case"]
            semantic_node = f"semantic.must.case.{case}"
            binding_node = f"binding.history.case.{case}"
            semantic_payload = {
                "status": "VERIFIED",
                "kind": "MUST_OUTCOME",
                "case": case,
                "history_id": history_id,
                "outcome": history["outcome"],
                "scope_digest_sha256": scope_digest,
                "source_proof_digest_sha256": proof_result["proof_digest_sha256"],
            }
            binding_payload = {
                "status": "VERIFIED",
                "kind": "HISTORY_CASE_BINDING",
                "case": case,
                "history_id": history_id,
                "outcome": history["outcome"],
                "scope_digest_sha256": scope_digest,
                "source_binding_digest_sha256": binding_result["binding_digest_sha256"],
            }
            nodes.extend(
                [
                    make_node(semantic_node, "SEMANTIC_PROOF", semantic_payload),
                    make_node(binding_node, "TRANSFORMATION", binding_payload),
                ]
            )
            edges.extend(
                [
                    _edge(
                        f"edge.must-checked-{case}",
                        "CHECKED_BY",
                        semantic_node,
                        "checker.stock-r-v2",
                    ),
                    _edge(
                        f"edge.binding-from-event-{case}",
                        "DERIVES_FROM",
                        "event.operational-collision",
                        binding_node,
                    ),
                    _edge(
                        f"edge.binding-from-must-{case}",
                        "DERIVES_FROM",
                        semantic_node,
                        binding_node,
                    ),
                ]
            )
            must_claim = make_claim(
                f"claim.must.case-{case}",
                "MUST_OUTCOME",
                scope,
                {"history_id": history_id, "outcome": history["outcome"]},
            )
            steps.append(
                {
                    "step_id": f"step.must.case-{case}",
                    "rule": "MUST",
                    "premises": [],
                    "evidence_refs": [semantic_node, binding_node],
                    "conclusion": must_claim,
                }
            )

        observer_node = "semantic.observer-inequality"
        nodes.append(
            make_node(
                observer_node,
                "SEMANTIC_PROOF",
                {
                    "status": "VERIFIED",
                    "kind": "OBSERVER_INEQUALITY",
                    "observer_id": scope["observer_id"],
                    "outcomes": outcomes,
                    "observations": outcomes,
                    "scope_digest_sha256": scope_digest,
                },
            )
        )
        edges.append(
            _edge(
                "edge.observer-checked",
                "CHECKED_BY",
                observer_node,
                "checker.stock-r-v2",
            )
        )
        inequality_claim = make_claim(
            "claim.observer-inequality",
            "OBSERVER_INEQUALITY",
            scope,
            {"outcomes": outcomes},
        )
        steps.append(
            {
                "step_id": "step.observer-inequality",
                "rule": "OBSERVER_INEQUALITY",
                "premises": [],
                "evidence_refs": [observer_node],
                "conclusion": inequality_claim,
            }
        )
        nonfactor_claim = make_claim(
            "claim.stock-r-v2.retrospective-nonfactor",
            "NONFACTORING",
            scope,
            requested_subject,
        )
        steps.append(
            {
                "step_id": "step.nonfactor",
                "rule": "NONFACTOR",
                "premises": [
                    "step.collision",
                    "step.must.case-0",
                    "step.must.case-1",
                    "step.observer-inequality",
                ],
                "evidence_refs": [],
                "conclusion": nonfactor_claim,
            }
        )
        steps.append(
            {
                "step_id": "step.prospective",
                "rule": "PROSPECTIVE",
                "premises": ["step.nonfactor"],
                "evidence_refs": ["query.exact", "selection.policy", "precommit.record"],
                "conclusion": copy.deepcopy(claim),
            }
        )
        root_step_id = "step.prospective"

    graph = {
        "schema": GRAPH_SCHEMA,
        "graph_id": f"graph.stock-r-v2.{scope_digest[:16]}",
        "scope_digest_sha256": scope_digest,
        "nodes": nodes,
        "edges": edges,
    }
    proof = _proof_document(
        f"proof.stock-r-v2.{scope_digest[:16]}",
        graph,
        claim,
        steps,
        root_step_id,
        missing,
    )
    return graph, claim, proof


def compile_stock_r_v2_bundle(bundle: str | Path) -> dict[str, dict[str, Any]]:
    """Compile a structurally valid V2 bundle into generic EBRC documents."""

    graph, claim, proof = _v2_graph_and_proof(Path(bundle))
    return {"graph": graph, "claim": claim, "proof": proof}


def _verify_manifested_file(root: Path, manifest: dict[str, Any], relative: str) -> None:
    descriptor = manifest.get("files", {}).get(relative)
    if not isinstance(descriptor, dict):
        raise EBRCAdapterError(f"V1 manifest omits {relative}")
    path = root / relative
    if descriptor.get("sha256") != _file_sha256(path) or descriptor.get("size") != path.stat().st_size:
        raise EBRCAdapterError(f"V1 manifested file mismatch: {relative}")


def compile_stock_linux_v1_bundle(bundle: str | Path) -> dict[str, dict[str, Any]]:
    """Compile only V1 identity, raw runtime, and operational-prune premises.

    ``final_verdict``, ``definition2_verdict``, proof/factorization outputs, and
    every legacy terminal result are intentionally outside this adapter's input
    projection.
    """

    root = Path(bundle)
    manifest = _read_json(root / "MANIFEST.json")
    selected_paths = [
        "raw/runtime/runtime.json",
        "raw/verifier-events/events.jsonl",
        "raw/object/program-info.json",
        "raw/kernel/kernel-identity.json",
    ]
    for relative in selected_paths:
        _verify_manifested_file(root, manifest, relative)
    runtime = _read_json(root / "raw" / "runtime" / "runtime.json")
    events = _read_jsonl(root / "raw" / "verifier-events" / "events.jsonl")
    prune_events = [row for row in events if row.get("event") == "prune_hit"]
    if not prune_events:
        raise EBRCAdapterError("V1 has no retained operational prune event")
    event = prune_events[0]
    runs = runtime.get("runs")
    if not isinstance(runs, list) or len(runs) != 2:
        raise EBRCAdapterError("V1 runtime must contain the two retained samples")

    frozen = manifest.get("frozen_tuple", {})
    identity = {
        key: frozen.get(key)
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
    scope_vector = {
        "artifact": {
            "object_sha256": identity["object_sha256"],
            "xlated_sha256": identity["xlated_sha256"],
        },
        "implementation": identity,
        "frontier": {"source": event.get("source"), "visit_insn": event.get("visit_insn")},
        "context": copy.deepcopy(runs[0].get("context")),
        "report": {
            "authority": "OPERATIONAL_OBSERVATION",
            "relation": event.get("source"),
            "cell_id": str(event.get("cell_id")),
        },
        "observer": "runtime.retval+success",
        "suffix": copy.deepcopy(runs[0].get("suffix")),
        "environment": {
            "serialized": runs[0].get("context", {}).get("serialized"),
            "capture_accounting": "UNKNOWN",
        },
    }
    scope_digest = canonical_digest(scope_vector)
    scope = {
        "scope_digest_sha256": scope_digest,
        "report_authority": "OPERATIONAL_OBSERVATION",
        "report_relation_id": f"report.operational.cell-{event.get('cell_id')}",
        "frontier_id": f"frontier.insn-{event.get('visit_insn')}",
        "context_id": "context.stock-linux-v1",
        "suffix_id": "suffix.shared",
        "observer_id": "observer.runtime-result",
    }
    collision_histories = [
        f"history.prune-old.{event['old']['history_hash']}",
        f"history.prune-current.{event['current']['history_hash']}",
    ]
    observed_outcomes = [run["observation"] for run in runs]
    claim = make_claim(
        "claim.stock-linux-v1.exact-operational-nonfactor",
        "NONFACTORING",
        scope,
        {
            "history_ids": collision_histories,
            "report_cell_id": str(event.get("cell_id")),
            "outcomes": observed_outcomes,
        },
    )

    nodes = [
        make_node(
            "query.v1.exact",
            "QUERY",
            {
                "query_id": "stock-linux-v1.exact-operational-prune",
                "scope_vector_digest_sha256": scope_digest,
            },
        ),
        make_node("identity.v1", "IDENTITY_RECEIPT", {"status": "VERIFIED", **identity}),
        make_node(
            "event.v1.operational-collision",
            "RAW_EVENT",
            {
                "status": "VERIFIED",
                "kind": "REPORT_COLLISION",
                "history_ids": collision_histories,
                "report_cell_id": str(event.get("cell_id")),
                "report_relation_id": scope["report_relation_id"],
                "frontier_id": scope["frontier_id"],
                "context_id": scope["context_id"],
                "suffix_id": scope["suffix_id"],
                "scope_digest_sha256": scope_digest,
            },
            recorded_at_ns=event.get("observed_at_ns"),
        ),
    ]
    edges = [
        _edge("edge.v1.identity-event", "BINDS", "identity.v1", "event.v1.operational-collision"),
        _edge("edge.v1.query-event", "BINDS", "query.v1.exact", "event.v1.operational-collision"),
    ]
    steps: list[dict[str, Any]] = []
    for index, run in enumerate(runs):
        history_id = f"history.sample.{run['case'].replace('=', '-') }"
        node_id = f"runtime.v1.sample.{index}"
        nodes.append(
            make_node(
                node_id,
                "RUNTIME_OBSERVATION",
                {
                    "status": "OBSERVED",
                    "history_id": history_id,
                    "outcome": copy.deepcopy(run["observation"]),
                    "case": run["case"],
                    "sample_count": 1,
                },
            )
        )
        edges.append(_edge(f"edge.v1.identity-runtime-{index}", "BINDS", "identity.v1", node_id))
        steps.append(
            {
                "step_id": f"step.v1.raw.{index}",
                "rule": "RAW",
                "premises": [],
                "evidence_refs": [node_id],
                "conclusion": make_claim(
                    f"claim.v1.may.{index}",
                    "MAY_OUTCOME",
                    scope,
                    {"history_id": history_id, "outcome": copy.deepcopy(run["observation"])},
                ),
            }
        )
    steps.append(
        {
            "step_id": "step.v1.collision",
            "rule": "COLLISION",
            "premises": [],
            "evidence_refs": ["event.v1.operational-collision"],
            "conclusion": make_claim(
                "claim.v1.collision",
                "REPORT_COLLISION",
                scope,
                {
                    "history_ids": collision_histories,
                    "report_cell_id": str(event.get("cell_id")),
                },
            ),
        }
    )
    graph = {
        "schema": GRAPH_SCHEMA,
        "graph_id": f"graph.stock-linux-v1.{scope_digest[:16]}",
        "scope_digest_sha256": scope_digest,
        "nodes": nodes,
        "edges": edges,
    }
    proof = _proof_document(
        f"proof.stock-linux-v1.{scope_digest[:16]}",
        graph,
        claim,
        steps,
        None,
        [
            "MUST_OUTCOME_PROOF",
            "HISTORY_CASE_BINDING",
            "OUTCOME_FREE_PRECOMMITMENT",
        ],
    )
    return {"graph": graph, "claim": claim, "proof": proof}
