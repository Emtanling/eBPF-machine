import json
import tempfile
import unittest
from pathlib import Path

from tools.proof.check_definition2 import evaluate
from tools.proof.verdict import (
    FACTORIZATION_FAILURE_WITHOUT_UNIQUENESS,
    STOCK_LINUX_R_ESTABLISHED_FOR_FROZEN_TUPLE,
)
from tools.proof.verify_hashes import REQUIRED_EVIDENCE, sha256_file


def _write(path: Path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")


def _evidence_ref(bundle: Path, rel: str) -> dict[str, str]:
    return {"path": rel, "sha256": sha256_file(bundle / rel)}


class Definition2Tests(unittest.TestCase):
    def _bundle(self, *, unique=True):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        bundle = Path(td.name) / "bundle"
        object_sha = "ab" * 32
        program_tag = "100c248465bce0b0"
        program_pin = "/sys/fs/bpf/rac-v03/rac_single"
        program_id = 11
        kernel_release = "test-kernel"
        retained_hash = "retained"
        current_hash = "current"

        event = {
            "event": "prune_hit",
            "session_id": "test-session",
            "sequence": 1,
            "visit_insn": 41,
            "exact_level": 0,
            "states_equal_success": True,
            "is_state_visited_prune": True,
            "old": {"insn_idx": 41, "state_hash": retained_hash},
            "current": {"insn_idx": 41, "state_hash": current_hash},
        }
        _write(bundle / "events.jsonl", json.dumps({"event": "metadata", "session_id": "test-session"}) + "\n" + json.dumps(event) + "\n" + json.dumps({"event": "capture_complete", "session_id": "test-session", "completed": True, "ringbuf_lost_events": 0, "collector_parse_errors": 0}) + "\n")
        _write(bundle / "events.raw.jsonl", (bundle / "events.jsonl").read_text(encoding="utf-8"))
        _write(bundle / "object.sha256", f"{object_sha}  rac_witness.bpf.o\n")
        _write(bundle / "program-info.json", {"id": program_id, "tag": program_tag, "name": "rac_single", "type": "sched_cls"})
        _write(bundle / "program-pin.txt", program_pin + "\n")
        _write(bundle / "xlated-rac_single.txt", "0: exit\n")
        xlated_sha = sha256_file(bundle / "xlated-rac_single.txt")
        _write(bundle / "xlated-rac_single.sha256", f"{xlated_sha}  xlated-rac_single.txt\n")
        runtime = {
            "schema": "rac-linux-runtime-v1",
            "kernel_release": kernel_release,
            "object_sha256": object_sha,
            "program_id": program_id,
            "program_tag": program_tag,
            "program_pin": program_pin,
            "xlated_sha256": xlated_sha,
            "runs": [
                {
                    "case": "a=0",
                    "context": {"serialized": True, "single_artifact": True, "map_type": "BPF_MAP_TYPE_HASH"},
                    "selected_state": ["S"],
                    "observation": {"success": True, "retval": 1},
                    "suffix": {"operation": "insert B", "program": "rac_single"},
                },
                {
                    "case": "a=1",
                    "context": {"serialized": True, "single_artifact": True, "map_type": "BPF_MAP_TYPE_HASH"},
                    "selected_state": ["S", "A"],
                    "observation": {"success": False, "retval": 0},
                    "suffix": {"operation": "insert B", "program": "rac_single"},
                },
            ],
        }
        _write(bundle / "runtime.json", runtime)
        input_sha256 = {
            rel: sha256_file(bundle / rel)
            for rel in [
                "events.jsonl",
                "events.raw.jsonl",
                "object.sha256",
                "program-info.json",
                "program-pin.txt",
                "runtime.json",
                "xlated-rac_single.sha256",
                "xlated-rac_single.txt",
            ]
        }
        identity = {
            "schema": "rac-frontier-identity-v1",
            "input_sha256": input_sha256,
            "object_sha256": object_sha,
            "program_id": program_id,
            "program_name": "rac_single",
            "program_pin": program_pin,
            "program_tag": program_tag,
            "runtime_object_sha256": object_sha,
            "runtime_program_id": program_id,
            "runtime_program_pin": program_pin,
            "runtime_program_tag": program_tag,
            "runtime_xlated_sha256": xlated_sha,
            "recorded_xlated_sha256": xlated_sha,
            "xlated_sha256": xlated_sha,
        }
        frontier = {"join_insn": 41, "suffix_entry_insn": 107, "first_sensitive_insn": 118, "branch_calls": [46, 48]}
        _write(bundle / "frontier-check.json", {"schema": "rac-frontier-check-v1", "result": "FRONTIER_ELIGIBLE", "identity": identity, "frontier": frontier})
        _write(bundle / "proof" / "states" / "state-capture-check.json", {"schema": "rac-state-v2-capture-check-v1", "result": "STATE_V2_CAPTURE_OK", "identity": identity})
        _write(bundle / "proof" / "states" / "retained-state.json", {"snapshot": {"state_hash": retained_hash}})
        _write(bundle / "proof" / "states" / "current-state.json", {"snapshot": {"state_hash": current_hash}})
        _write(
            bundle / "proof" / "path" / "path-correspondence.json",
            {
                "schema": "rac-path-correspondence-v1",
                "result": "PATH_CORRESPONDENCE_VERIFIED",
                "identity_verified": True,
                "identity": identity,
                "frontier": frontier,
                "common_suffix": {"same_remaining_xlated_suffix": True},
                "a0": {"abstract_role": "current", "direct_state_hash": current_hash, "history_matches": True},
                "a1": {"abstract_role": "retained", "direct_state_hash": retained_hash, "history_matches": True},
            },
        )
        _write(bundle / "proof" / "concretization" / "joint-coverage.json", {"schema": "rac-local-joint-coverage-v1", "result": "JOINT_COVERAGE_CANDIDATE", "selected_masks_differ": True, "selected_masks": {"a=0": 1, "a=1": 3}})
        field_checks_a0 = [{"field": "regs.r0.type", "rule": "register-type-kind", "result": "PASS", "passed": True}]
        field_checks_a1 = [{"field": "regs.r0.type", "rule": "register-type-kind", "result": "PASS", "passed": True}]
        _write(bundle / "proof" / "concretization" / "membership-a0.json", {"schema": "rac-direct-membership-v1", "case": "a=0", "result": "SIGMA_A0_IN_DIRECT_GAMMA", "unsupported_fields": [], "field_checks": field_checks_a0})
        _write(bundle / "proof" / "concretization" / "membership-a1.json", {"schema": "rac-direct-membership-v1", "case": "a=1", "result": "SIGMA_A1_IN_DIRECT_GAMMA", "unsupported_fields": [], "field_checks": field_checks_a1})
        _write(bundle / "proof" / "subsumption" / "kernel-source-map.json", {"schema": "rac-kernel-source-map-v1", "kernel_release": kernel_release, "program_identity": identity})
        _write(bundle / "proof" / "subsumption" / "subsumption-check.json", {"schema": "rac-restricted-subsumption-v1", "result": "RESTRICTED_SUBSUMPTION_REJECTED", "kernel": {"kernel_release": kernel_release}})

        representatives = {"a=0": [retained_hash], "a=1": [retained_hash] if unique else ["other"]}
        unique_result = "UNIQUE_SAME_REPORT_CELL" if unique else "REPORT_DISTINGUISHES_BEHAVIORAL_STATES"
        _write(bundle / "proof" / "report" / "prune-cell-definition.json", {"schema": "rac-prune-cell-definition-v1", "cell_kind": "operational prune-report cell", "representative_role": "retained", "frontier": frontier})
        _write(
            bundle / "proof" / "report" / "prune-cell-coverage.json",
            {
                "schema": "rac-prune-cell-coverage-v1",
                "result": "BOTH_CASES_IN_OPERATIONAL_PRUNE_CELL",
                "representative": retained_hash,
                "checks": {
                    "path_a0_current": True,
                    "path_a1_retained": True,
                    "membership_a0_direct": True,
                    "membership_a1_direct": True,
                    "actual_prune_edge_observed": True,
                    "both_cases_have_representative": True,
                    "raw_event_not_fixture": True,
                },
                "cases": {"a=0": {"representatives": [retained_hash]}, "a=1": {"representatives": [retained_hash]}},
            },
        )
        _write(bundle / "proof" / "report" / "session-completeness.json", {"schema": "rac-session-completeness-v1", "result": "SESSION_CAPTURE_COMPLETE", "session_complete": True, "verifier_invocation_completed": True, "ringbuf_lost_events": 0, "events_lost": 0, "collector_parse_errors": 0})
        _write(bundle / "proof" / "report" / "membership-matrix.json", {"schema": "rac-membership-matrix-v1", "rows": [{"case": "a=0", "direct_state_hash": current_hash, "representatives": [retained_hash]}, {"case": "a=1", "direct_state_hash": retained_hash, "representatives": representatives["a=1"]}]})
        _write(bundle / "proof" / "report" / "unique-cell-check.json", {"schema": "rac-unique-report-cell-v2", "result": unique_result, "representatives": representatives, "retained_roots": [retained_hash], "session_complete": True, "verifier_invocation_completed": True, "events_lost": 0, "collector_parse_errors": 0, "reasons": [] if unique else ["representatives differ"]})

        _write(bundle / "proof" / "factorization" / "behavioral-quotient.json", {"classes": [{"class": "Q0", "states": ["sigma-a0"]}, {"class": "Q1", "states": ["sigma-a1"]}]})
        _write(bundle / "proof" / "factorization" / "beta-map.json", {"beta_D": {"sigma-a0": "Q0", "sigma-a1": "Q1"}})
        _write(
            bundle / "proof" / "factorization" / "factorization.json",
            {
                "schema": "rac-stock-linux-factorization-v1",
                "result": "REPORT_FACTORIZATION_FAILURE_ESTABLISHED",
                "beta_D": {"sigma-a0": "Q0", "sigma-a1": "Q1"},
                "conditions": {
                    "pi_R_equal": True,
                    "beta_D_different": True,
                    "observations_differ": True,
                    "auditor_R_output_witnessed": True,
                    "auditor_R_non_factorization": True,
                    "preconditions_passed": True,
                },
            },
        )
        _write(bundle / "proof" / "factorization" / "suffix-witness.json", {"runtime_suffix": {"same_operation": True}, "suffix_word": ["insert B"]})
        _write(
            bundle / "proof" / "definition2" / "kernel-identity.json",
            {
                "schema": "rac-kernel-identity-v1",
                "kernel_release": kernel_release,
                "btf": {"available": True, "sha256": "cd" * 32, "size": 1},
                "config": {"available": True, "sha256": "ef" * 32, "size": 1},
            },
        )
        _write(bundle / "proof" / "definition2" / "stock-linux-r-check.json", {"schema": "rac-stock-linux-r-four-checks-v1", "result": "PLACEHOLDER_REGENERATED_BY_EVALUATE"})

        evidence_refs = {
            "path_correspondence": _evidence_ref(bundle, "proof/path/path-correspondence.json"),
            "membership_a0": _evidence_ref(bundle, "proof/concretization/membership-a0.json"),
            "membership_a1": _evidence_ref(bundle, "proof/concretization/membership-a1.json"),
            "prune_cell_definition": _evidence_ref(bundle, "proof/report/prune-cell-definition.json"),
            "prune_cell_coverage": _evidence_ref(bundle, "proof/report/prune-cell-coverage.json"),
            "session_completeness": _evidence_ref(bundle, "proof/report/session-completeness.json"),
            "membership_matrix": _evidence_ref(bundle, "proof/report/membership-matrix.json"),
            "unique_cell": _evidence_ref(bundle, "proof/report/unique-cell-check.json"),
        }
        _write(
            bundle / "proof" / "report" / "report-map.json",
            {
                "schema": "rac-report-map-v2",
                "identity": identity,
                "frontier": frontier,
                "report_cell_definition": "operational prune-report cell",
                "evidence_refs": evidence_refs,
                "certificate_results": {
                    "path_correspondence": "PATH_CORRESPONDENCE_VERIFIED",
                    "membership_a0": "SIGMA_A0_IN_DIRECT_GAMMA",
                    "membership_a1": "SIGMA_A1_IN_DIRECT_GAMMA",
                    "prune_cell_coverage": "BOTH_CASES_IN_OPERATIONAL_PRUNE_CELL",
                    "session_completeness": "SESSION_CAPTURE_COMPLETE",
                    "unique_cell": unique_result,
                    "representatives": representatives,
                },
            },
        )

        # Sanity guard: the fixture should cover every manifest-required input.
        for rel in REQUIRED_EVIDENCE:
            self.assertTrue((bundle / rel).exists(), rel)
        return bundle

    def test_definition2_establishes_frozen_tuple(self):
        bundle = self._bundle()

        report = evaluate(bundle, refresh_manifest=True)

        self.assertEqual(STOCK_LINUX_R_ESTABLISHED_FOR_FROZEN_TUPLE, report["verdict"])
        self.assertFalse(report["reasons"])
        report_path = bundle / "proof" / "definition2" / "definition2-report.md"
        self.assertTrue(report_path.exists())
        rendered = report_path.read_text(encoding="utf-8")
        self.assertIn("# Legacy-Adapter Definition 2 Check for a Frozen Stock-Linux Tuple", rendered)
        self.assertIn("not a verdict about real Linux behavior or a real-Linux R verdict", rendered)
        self.assertNotIn("four independent stock-Linux R certificates", rendered)

    def test_factorization_without_uniqueness_is_not_final_r(self):
        bundle = self._bundle(unique=False)

        report = evaluate(bundle, refresh_manifest=True)

        self.assertEqual(FACTORIZATION_FAILURE_WITHOUT_UNIQUENESS, report["verdict"])
        self.assertIn("unique_cell_on_chosen_fiber", report["reasons"])


if __name__ == "__main__":
    unittest.main()
