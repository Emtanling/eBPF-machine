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
from residuality_auditor.ebrc_oracle import enumerate_nonfactor_witnesses
from residuality_auditor.ebrc_mutations import run_hostile_mutation_matrix
from residuality_auditor.stock_r_v2 import make_history_case_binding, make_must_outcome_proof
from tests.test_stock_r_v2 import _bundle, _events


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
V1_BUNDLE = ROOT / "stock-linux-r-proof"


def _load_schema(name: str) -> dict[str, object]:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def _complete_v2_bundle(root: Path) -> None:
    _bundle(root)
    query = json.loads((root / "query" / "query.json").read_text(encoding="utf-8"))
    runtime = json.loads((root / "raw" / "runtime.json").read_text(encoding="utf-8"))
    proof = make_must_outcome_proof(query, runtime)
    binding = make_history_case_binding(query, _events(runtime["identity"])[1], runtime, proof)
    (root / "proof").mkdir(parents=True, exist_ok=True)
    (root / "proof" / "must-outcome-proof.json").write_text(
        json.dumps(proof, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (root / "proof" / "history-case-binding.json").write_text(
        json.dumps(binding, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


class EBRCReferenceCheckerTests(unittest.TestCase):
    def test_compiled_documents_satisfy_public_schemas(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _complete_v2_bundle(root)
            compiled = compile_stock_r_v2_bundle(root)

        for key, schema_name in (
            ("claim", "ebrc-claim-v1.schema.json"),
            ("graph", "ebrc-evidence-graph-v1.schema.json"),
            ("proof", "ebrc-proof-v1.schema.json"),
        ):
            errors = sorted(
                Draft202012Validator(_load_schema(schema_name)).iter_errors(compiled[key]),
                key=lambda error: list(error.path),
            )
            self.assertEqual(errors, [], [(list(error.path), error.message) for error in errors])

    def test_v1_compiles_to_blocked_without_reading_legacy_verdict(self) -> None:
        compiled = compile_stock_linux_v1_bundle(V1_BUNDLE)
        result = check_certificate(compiled["graph"], compiled["claim"], compiled["proof"])

        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["unknown_kind"], "INCONCLUSIVE")
        self.assertIn("MUST_OUTCOME_PROOF", result["missing_obligations"])
        self.assertFalse(any(item["predicate"] == "NONFACTORING" for item in result["strongest_claim_profile"]))
        self.assertTrue(any(item["predicate"] == "MAY_OUTCOME" for item in result["strongest_claim_profile"]))

    def test_v2_compiles_to_exact_prospective_nonfactor_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _complete_v2_bundle(root)
            compiled = compile_stock_r_v2_bundle(root)
            result = check_certificate(compiled["graph"], compiled["claim"], compiled["proof"])

        self.assertEqual(result["status"], "CERTIFIED")
        self.assertEqual(result["assessment"], "NONFACTORING")
        self.assertEqual(result["claim"]["quantifier"], "AT")
        self.assertEqual(result["claim"]["scope"]["report_authority"], "OPERATIONAL_OBSERVATION")
        self.assertEqual(result["claim"]["evidence_grade"], "OUTCOME_FREE_PRECOMMITTED")
        self.assertEqual(
            result["certificate"],
            f"NONFACTORING@{result['claim']['scope']['scope_digest_sha256']}",
        )

    def test_v2_without_history_case_binding_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _bundle(root)
            query = json.loads((root / "query" / "query.json").read_text(encoding="utf-8"))
            runtime = json.loads((root / "raw" / "runtime.json").read_text(encoding="utf-8"))
            proof = make_must_outcome_proof(query, runtime)
            (root / "proof").mkdir(parents=True, exist_ok=True)
            (root / "proof" / "must-outcome-proof.json").write_text(
                json.dumps(proof, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            compiled = compile_stock_r_v2_bundle(root)
            result = check_certificate(compiled["graph"], compiled["claim"], compiled["proof"])

        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("HISTORY_CASE_BINDING", result["missing_obligations"])

    def test_v2_without_must_proof_is_blocked_not_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _bundle(root)
            compiled = compile_stock_r_v2_bundle(root)
            result = check_certificate(compiled["graph"], compiled["claim"], compiled["proof"])

        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("MUST_OUTCOME_PROOF", result["missing_obligations"])
        self.assertIn("HISTORY_CASE_BINDING", result["missing_obligations"])

    def test_graph_and_proof_tampering_are_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _complete_v2_bundle(root)
            compiled = compile_stock_r_v2_bundle(root)

        tampered_graph = copy.deepcopy(compiled["graph"])
        tampered_graph["nodes"][0]["payload"]["query_id"] = "tampered"
        graph_result = check_certificate(tampered_graph, compiled["claim"], compiled["proof"])
        self.assertEqual(graph_result["status"], "INVALID_GRAPH")
        self.assertIn("GRAPH_NODE_PAYLOAD_DIGEST_MISMATCH", graph_result["invalid_reasons"])

        tampered_proof = copy.deepcopy(compiled["proof"])
        tampered_proof["steps"][-1]["premises"] = ["missing.step"]
        tampered_proof["graph_digest_sha256"] = canonical_digest(compiled["graph"])
        proof_result = check_certificate(compiled["graph"], compiled["claim"], tampered_proof)
        self.assertEqual(proof_result["status"], "INVALID_GRAPH")
        self.assertIn("PROOF_UNKNOWN_PREMISE", proof_result["invalid_reasons"])

    def test_outcome_to_selector_dependency_invalidates_prospective_step(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _complete_v2_bundle(root)
            compiled = compile_stock_r_v2_bundle(root)

        graph = copy.deepcopy(compiled["graph"])
        graph["edges"].append(
            {
                "edge_id": "edge.tampered.outcome-to-selector",
                "role": "CONSUMED_BY",
                "source": "runtime.case.0",
                "target": "selection.policy",
            }
        )
        proof = copy.deepcopy(compiled["proof"])
        proof["graph_digest_sha256"] = canonical_digest(graph)
        result = check_certificate(graph, compiled["claim"], proof)
        self.assertEqual(result["status"], "INVALID_GRAPH")
        self.assertIn("PROSPECTIVE_OUTCOME_DEPENDENCY", result["invalid_reasons"])

    def test_self_consistent_universal_and_specified_lifts_are_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _complete_v2_bundle(root)
            compiled = compile_stock_r_v2_bundle(root)

        for path, value, reason in (
            (("quantifier",), "FORALL", "RULE_QUANTIFIER_UNSUPPORTED"),
            (
                ("scope", "report_authority"),
                "IMPLEMENTATION_SPECIFIED",
                "RULE_REPORT_AUTHORITY_UNSUPPORTED",
            ),
            (
                ("evidence_grade",),
                "TRANSPORTED",
                "RULE_EVIDENCE_GRADE_UNSUPPORTED",
            ),
            (
                ("scope", "report_relation_id"),
                "report.hostile.relation",
                "COLLISION_RULE_SCOPE_MISMATCH",
            ),
        ):
            claim = copy.deepcopy(compiled["claim"])
            proof = copy.deepcopy(compiled["proof"])
            documents = [claim, *(step["conclusion"] for step in proof["steps"])]
            for document in documents:
                target = document
                for field in path[:-1]:
                    target = target[field]
                target[path[-1]] = value
            proof["requested_claim_digest_sha256"] = canonical_digest(claim)
            result = check_certificate(compiled["graph"], claim, proof)
            self.assertEqual(result["status"], "INVALID_GRAPH", result)
            self.assertIn(reason, result["invalid_reasons"])

    def test_malformed_references_and_observer_payload_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _complete_v2_bundle(root)
            compiled = compile_stock_r_v2_bundle(root)

        malformed_proof = copy.deepcopy(compiled["proof"])
        malformed_proof["steps"][-1]["premises"] = [{"not": "a step id"}]
        proof_result = check_certificate(
            compiled["graph"], compiled["claim"], malformed_proof
        )
        self.assertEqual(proof_result["status"], "INVALID_GRAPH")
        self.assertIn("PROOF_PREMISES_MALFORMED", proof_result["invalid_reasons"])

        malformed_root = copy.deepcopy(compiled["proof"])
        malformed_root["root_step_id"] = {"not": "a step id"}
        root_result = check_certificate(
            compiled["graph"], compiled["claim"], malformed_root
        )
        self.assertEqual(root_result["status"], "INVALID_GRAPH")
        self.assertIn("PROOF_ROOT_STEP_INVALID", root_result["invalid_reasons"])

        malformed_edge_graph = copy.deepcopy(compiled["graph"])
        malformed_edge_graph["edges"][0]["source"] = {"not": "a node id"}
        edge_result = check_certificate(
            malformed_edge_graph, compiled["claim"], compiled["proof"]
        )
        self.assertEqual(edge_result["status"], "INVALID_GRAPH")
        self.assertIn("GRAPH_EDGE_ENDPOINT_INVALID", edge_result["invalid_reasons"])

        malformed_graph = copy.deepcopy(compiled["graph"])
        inequality_node = next(
            node
            for node in malformed_graph["nodes"]
            if node["role"] == "SEMANTIC_PROOF"
            and node["payload"].get("kind") == "OBSERVER_INEQUALITY"
        )
        inequality_node["payload"]["observations"] = []
        inequality_node["payload_digest_sha256"] = canonical_digest(
            inequality_node["payload"]
        )
        malformed_binding = copy.deepcopy(compiled["proof"])
        malformed_binding["graph_digest_sha256"] = canonical_digest(malformed_graph)
        graph_result = check_certificate(
            malformed_graph, compiled["claim"], malformed_binding
        )
        self.assertEqual(graph_result["status"], "INVALID_GRAPH")
        self.assertIn("OBSERVER_RULE_EVIDENCE_INVALID", graph_result["invalid_reasons"])

        role_swapped_graph = copy.deepcopy(compiled["graph"])
        must_step = next(
            step for step in compiled["proof"]["steps"] if step["rule"] == "MUST"
        )
        must_nodes = {
            node["node_id"]: node
            for node in role_swapped_graph["nodes"]
            if node["node_id"] in must_step["evidence_refs"]
        }
        semantic_node = next(
            node for node in must_nodes.values() if node["role"] == "SEMANTIC_PROOF"
        )
        binding_node = next(
            node for node in must_nodes.values() if node["role"] == "TRANSFORMATION"
        )
        semantic_node["role"], binding_node["role"] = (
            binding_node["role"],
            semantic_node["role"],
        )
        role_swapped_proof = copy.deepcopy(compiled["proof"])
        role_swapped_proof["graph_digest_sha256"] = canonical_digest(
            role_swapped_graph
        )
        role_result = check_certificate(
            role_swapped_graph, compiled["claim"], role_swapped_proof
        )
        self.assertEqual(role_result["status"], "INVALID_GRAPH")
        self.assertIn("MUST_RULE_EVIDENCE_INVALID", role_result["invalid_reasons"])

    def test_independent_oracle_agrees_and_rejects_non_singletons(self) -> None:
        world = {
            "histories": [
                {"history_id": "h0", "report_cell_id": "c", "outcomes": [0]},
                {"history_id": "h1", "report_cell_id": "c", "outcomes": [1]},
            ],
            "observer": {"0": "zero", "1": "one"},
        }
        self.assertEqual(
            enumerate_nonfactor_witnesses(world),
            [
                {
                    "history_ids": ["h0", "h1"],
                    "outcomes": [0, 1],
                    "report_cell_id": "c",
                }
            ],
        )

        world["histories"][0]["outcomes"] = [0, 1]
        self.assertEqual(enumerate_nonfactor_witnesses(world), [])

    def test_hostile_mutation_matrix_blocks_every_forbidden_lift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _complete_v2_bundle(root)
            compiled = compile_stock_r_v2_bundle(root)
            matrix = run_hostile_mutation_matrix(
                compiled["graph"], compiled["claim"], compiled["proof"]
            )

        self.assertTrue(matrix["all_expected"])
        self.assertEqual(matrix["baseline"]["status"], "CERTIFIED")
        self.assertEqual(matrix["summary"], {"BLOCKED": 5, "INVALID_GRAPH": 7})
        self.assertEqual(
            {case["mutation_id"] for case in matrix["cases"]},
            {
                "claim.forall-family",
                "claim.specified-report",
                "claim.changed-observer",
                "claim.enlarged-suffix",
                "claim.transported-grade",
                "proof.self-consistent-forall",
                "proof.self-consistent-specified-report",
                "proof.self-consistent-transported-grade",
                "proof.self-consistent-report-relation",
                "graph.outcome-selector-dependency",
                "graph.payload-tamper",
                "proof.unknown-premise",
            },
        )
        for case in matrix["cases"]:
            self.assertTrue(case["matched_expectation"], case)


if __name__ == "__main__":
    unittest.main()
