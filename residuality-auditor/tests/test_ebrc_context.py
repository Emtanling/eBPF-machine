from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from jsonschema import Draft202012Validator

from residuality_auditor.ebrc import canonical_digest, check_certificate
from residuality_auditor.ebrc_adapters import (
    compile_stock_linux_v1_bundle,
    compile_stock_r_v2_bundle,
)
from residuality_auditor.ebrc_context import (
    check_context_documents,
    make_context_documents,
    make_stock_r_context_documents,
)
from residuality_auditor.ebrc_context_mutations import run_context_hostile_mutation_matrix
from residuality_auditor.ebrc_context_oracle import (
    contextual_nonfactor_holds,
    positive_synthetic_world,
)
from residuality_auditor.context_suite import load_context_suite, render_context_target
from tests.test_ebrc import V1_BUNDLE, _complete_v2_bundle


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
CONTEXT_SUITE = ROOT / "linux" / "context-suite-v1.json"
BASE_SOURCE = ROOT / "linux" / "witness" / "rac_v2_witness.bpf.c"


def _load_schema(name: str) -> dict[str, object]:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def _node_by_role(graph: dict[str, object], role: str) -> dict[str, object]:
    return next(node for node in graph["nodes"] if node["role"] == role)


def _rehash_role(graph: dict[str, object], role: str) -> None:
    node = _node_by_role(graph, role)
    node["payload_digest_sha256"] = canonical_digest(node["payload"])


class EBRCContextCheckerTests(unittest.TestCase):
    def _stock_context_documents(self, case_id: str) -> dict[str, dict[str, object]]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _complete_v2_bundle(root)
            source = compile_stock_r_v2_bundle(root)
        suite = load_context_suite(CONTEXT_SUITE)
        rendered = render_context_target(
            BASE_SOURCE.read_text(encoding="utf-8"),
            suite,
            suite.case(case_id),
        )
        target_identity = {
            "program_name": "rac_v2_single",
            "program_id": 8001,
            "program_tag": "fedcba9876543210",
            "program_load_time": 999,
            "object_sha256": "9" * 64,
            "xlated_sha256": "8" * 64,
            "kernel_release": "6.17.0-test",
            "btf_sha256": "7" * 64,
        }
        return make_stock_r_context_documents(
            source["graph"],
            source["claim"],
            source["proof"],
            target_identity,
            rendered.metadata,
        )

    def test_suite_missing_bridge_case_is_blocked_at_the_named_obligation(self) -> None:
        documents = self._stock_context_documents("reject.missing-bridge")

        result = check_context_documents(documents)

        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("TARGET_CONFORMANCE_BRIDGE", result["missing_obligations"])

    def test_suite_outcome_dependency_case_is_rejected_by_crl(self) -> None:
        documents = self._stock_context_documents(
            "reject.outcome-dependent-selection"
        )

        result = check_context_documents(documents)

        self.assertEqual(result["status"], "INVALID_GRAPH")
        self.assertIn("CONTEXT_OUTCOME_DEPENDENCY", result["invalid_reasons"])

    def test_context_documents_satisfy_public_schemas(self) -> None:
        documents = make_context_documents()
        graph = documents["graph"]
        proof = documents["proof"]
        transform = _node_by_role(graph, "TRANSFORMATION")["payload"]
        transport = _node_by_role(graph, "TRANSPORT_PROOF")["payload"]

        for value, schema_name in (
            (transform, "ebrc-context-transform-v1.schema.json"),
            (transport, "ebrc-context-transport-v1.schema.json"),
            (proof, "ebrc-proof-v1.schema.json"),
        ):
            errors = sorted(
                Draft202012Validator(_load_schema(schema_name)).iter_errors(value),
                key=lambda error: list(error.path),
            )
            self.assertEqual(errors, [], [(list(error.path), error.message) for error in errors])

    def test_nontrivial_context_transport_emits_target_bound_certificate(self) -> None:
        documents = make_context_documents()
        result = check_context_documents(documents)
        transport = _node_by_role(documents["graph"], "TRANSPORT_PROOF")["payload"]

        self.assertEqual(result["status"], "CERTIFIED")
        self.assertEqual(result["assessment"], "NONFACTORING")
        self.assertEqual(result["claim"]["quantifier"], "AT")
        self.assertEqual(result["claim"]["evidence_grade"], "TRANSPORTED")
        self.assertEqual(result["proof_trace"], ["step.derived-contextual"])
        self.assertEqual(transport["derivation_kind"], "DERIVED_CONTEXTUAL")
        self.assertEqual(transport["derivation_chain"]["kind"], "DERIVED_CONTEXTUAL")
        self.assertEqual(transport["derivation_chain"]["rule"], "CONTEXT_TRANSPORT")
        self.assertEqual(
            transport["derivation_chain"]["target_claim_digest_sha256"],
            canonical_digest(documents["claim"]),
        )
        self.assertEqual(
            result["certificate"],
            f"NONFACTORING@{documents['claim']['scope']['scope_digest_sha256']}",
        )
        self.assertNotEqual(
            transport["source_scope_digest_sha256"],
            transport["target_scope_digest_sha256"],
        )

    def test_stock_r_v2_source_certificate_can_seed_context_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _complete_v2_bundle(root)
            source = compile_stock_r_v2_bundle(root)

        target_identity = {
            "program_name": "rac_v2_single",
            "program_id": 8001,
            "program_tag": "fedcba9876543210",
            "program_load_time": 999,
            "object_sha256": "9" * 64,
            "xlated_sha256": "8" * 64,
            "kernel_release": "6.17.0-test",
            "btf_sha256": "7" * 64,
        }
        transform_metadata = {
            "variant_id": "post-collision-frame",
            "transform_id": "context.stock-r-v2.post-collision-frame",
            "primitive": "POST_COLLISION_FRAMED_COMPUTATION",
            "parameters": {"frame_map": "context_scratch"},
        }
        documents = make_stock_r_context_documents(
            source["graph"],
            source["claim"],
            source["proof"],
            target_identity,
            transform_metadata,
        )
        result = check_certificate(documents["graph"], documents["claim"], documents["proof"])
        source_scope = source["claim"]["scope"]["scope_digest_sha256"]

        self.assertEqual(result["status"], "CERTIFIED")
        self.assertEqual(result["claim"]["evidence_grade"], "TRANSPORTED")
        self.assertEqual(result["proof_trace"], ["step.derived-contextual"])
        self.assertNotEqual(result["claim"]["scope"]["scope_digest_sha256"], source_scope)
        self.assertEqual(
            result["certificate"],
            f"NONFACTORING@{result['claim']['scope']['scope_digest_sha256']}",
        )
        matrix = run_context_hostile_mutation_matrix(
            documents["graph"],
            documents["claim"],
            documents["proof"],
        )
        self.assertTrue(matrix["all_expected"])

    def test_identity_context_is_accepted_but_marked_trivial(self) -> None:
        documents = make_context_documents(trivial=True)
        result = check_certificate(documents["graph"], documents["claim"], documents["proof"])
        transform = _node_by_role(documents["graph"], "TRANSFORMATION")["payload"]

        self.assertEqual(result["status"], "CERTIFIED")
        self.assertTrue(transform["trivial"])
        self.assertEqual(
            transform["source_scope_digest_sha256"],
            transform["target_scope_digest_sha256"],
        )

    def test_runtime_only_target_without_bridge_is_blocked(self) -> None:
        documents = make_context_documents(
            include_runtime_validation=True,
            blocked_missing=["TARGET_CONFORMANCE_BRIDGE"],
        )
        result = check_certificate(documents["graph"], documents["claim"], documents["proof"])

        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("TARGET_CONFORMANCE_BRIDGE", result["missing_obligations"])
        self.assertIn("PROOF_FOR_REQUESTED_CLAIM", result["missing_obligations"])

    def test_footprint_effect_conflict_fails_closed(self) -> None:
        documents = make_context_documents()
        graph = copy.deepcopy(documents["graph"])
        proof = copy.deepcopy(documents["proof"])
        transport = _node_by_role(graph, "TRANSPORT_PROOF")["payload"]
        transport["effect"]["writes"].append("reg:r1")
        _rehash_role(graph, "TRANSPORT_PROOF")
        proof["graph_digest_sha256"] = canonical_digest(graph)
        result = check_certificate(graph, documents["claim"], proof)

        self.assertEqual(result["status"], "INVALID_GRAPH")
        self.assertIn("CONTEXT_FOOTPRINT_EFFECT_CONFLICT", result["invalid_reasons"])

    def test_target_terminal_verdict_is_rejected_as_circular(self) -> None:
        documents = make_context_documents()
        graph = copy.deepcopy(documents["graph"])
        proof = copy.deepcopy(documents["proof"])
        transport = _node_by_role(graph, "TRANSPORT_PROOF")["payload"]
        transport["target_terminal_verdict"] = "NONFACTORING"
        _rehash_role(graph, "TRANSPORT_PROOF")
        proof["graph_digest_sha256"] = canonical_digest(graph)
        result = check_certificate(graph, documents["claim"], proof)

        self.assertEqual(result["status"], "INVALID_GRAPH")
        self.assertIn("CONTEXT_TARGET_VERDICT_PREMISE", result["invalid_reasons"])

    def test_context_hostile_mutation_matrix_blocks_declared_attacks(self) -> None:
        documents = make_context_documents()
        matrix = run_context_hostile_mutation_matrix(
            documents["graph"],
            documents["claim"],
            documents["proof"],
        )

        self.assertTrue(matrix["all_expected"])
        self.assertEqual(matrix["baseline"]["status"], "CERTIFIED")
        self.assertEqual(matrix["summary"], {"BLOCKED": 3, "INVALID_GRAPH": 9})

    def test_context_oracle_agrees_on_bounded_synthetic_world(self) -> None:
        world = positive_synthetic_world()
        self.assertTrue(contextual_nonfactor_holds(world))

        nondeterministic_target = copy.deepcopy(world)
        nondeterministic_target["target_histories"]["history.target.0"] = [0, 1]
        self.assertFalse(contextual_nonfactor_holds(nondeterministic_target))

        collapsed_observer = copy.deepcopy(world)
        collapsed_observer["observer"] = {"0": "same", "1": "same"}
        self.assertFalse(contextual_nonfactor_holds(collapsed_observer))

    def test_existing_v1_and_v2_results_do_not_change(self) -> None:
        v1 = compile_stock_linux_v1_bundle(V1_BUNDLE)
        v1_result = check_certificate(v1["graph"], v1["claim"], v1["proof"])
        self.assertEqual(v1_result["status"], "BLOCKED")
        self.assertIn("MUST_OUTCOME_PROOF", v1_result["missing_obligations"])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _complete_v2_bundle(root)
            v2 = compile_stock_r_v2_bundle(root)
        v2_result = check_certificate(v2["graph"], v2["claim"], v2["proof"])
        self.assertEqual(v2_result["status"], "CERTIFIED")
        self.assertEqual(v2_result["claim"]["evidence_grade"], "OUTCOME_FREE_PRECOMMITTED")


if __name__ == "__main__":
    unittest.main()
