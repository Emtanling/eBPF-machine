import json
import tempfile
import unittest
from pathlib import Path

from residuality_auditor.adapters.stock_linux import (
    RESULT_ESTABLISHED,
    RESULT_REJECTED,
    extract_factorization,
)


def _write(path: Path, payload: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")


class StockLinuxAdapterTests(unittest.TestCase):
    def _bundle(self, *, same_observation=False):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        bundle = Path(td.name) / "bundle"
        identity = {
            "object_sha256": "ab" * 32,
            "program_tag": "0123456789abcdef",
            "program_pin": "/sys/fs/bpf/rac-v03/rac_single",
            "program_id": 7,
            "xlated_sha256": "cd" * 32,
        }
        _write(
            bundle / "proof" / "path" / "path-correspondence.json",
            {
                "schema": "rac-path-correspondence-v1",
                "result": "PATH_CORRESPONDENCE_VERIFIED",
                "identity": identity,
                "frontier": {"join_insn": 41, "suffix_entry_insn": 107, "first_sensitive_insn": 118},
                "common_suffix": {"same_remaining_xlated_suffix": True},
            },
        )
        _write(
            bundle / "proof" / "concretization" / "joint-coverage.json",
            {"schema": "rac-local-joint-coverage-v1", "result": "JOINT_COVERAGE_CANDIDATE"},
        )
        _write(
            bundle / "proof" / "concretization" / "membership-a0.json",
            {"case": "a=0", "result": "SIGMA_A0_IN_DIRECT_GAMMA"},
        )
        _write(
            bundle / "proof" / "concretization" / "membership-a1.json",
            {"case": "a=1", "result": "SIGMA_A1_IN_DIRECT_GAMMA"},
        )
        _write(
            bundle / "proof" / "subsumption" / "subsumption-check.json",
            {
                "schema": "rac-restricted-subsumption-v1",
                "result": "RESTRICTED_SUBSUMPTION_ESTABLISHED",
                "kernel": {"release": "test"},
                "theorem_scope": {"local": True},
            },
        )

        _write(
            bundle / "proof" / "report" / "prune-cell-coverage.json",
            {
                "schema": "rac-prune-cell-coverage-v1",
                "result": "BOTH_CASES_IN_OPERATIONAL_PRUNE_CELL",
                "representative": "retained-hash",
                "checks": {
                    "path_a0_current": True,
                    "path_a1_retained": True,
                    "membership_a0_direct": True,
                    "membership_a1_direct": True,
                    "actual_prune_edge_observed": True,
                    "both_cases_have_representative": True,
                    "raw_event_not_fixture": True,
                },
            },
        )
        _write(
            bundle / "proof" / "report" / "session-completeness.json",
            {
                "schema": "rac-session-completeness-v1",
                "result": "SESSION_CAPTURE_COMPLETE",
                "session_complete": True,
                "ringbuf_lost_events": 0,
                "collector_parse_errors": 0,
            },
        )
        _write(
            bundle / "proof" / "report" / "report-map.json",
            {
                "schema": "rac-report-map-v1",
                "identity": identity,
                "unique_cell_check": {
                    "schema": "rac-unique-report-cell-v1",
                    "result": "UNIQUE_SAME_REPORT_CELL",
                    "representatives": {"a=0": ["retained-hash"], "a=1": ["retained-hash"]},
                },
            },
        )
        obs1 = {"success": True, "retval": 1} if same_observation else {"success": False, "retval": 0}
        run_context = {"serialized": True, "single_artifact": True}
        suffix = {"operation": "shared post-join insert of fresh key B", "program": "rac_single"}
        _write(
            bundle / "runtime.json",
            {
                "schema": "rac-linux-runtime-v1",
                **identity,
                "runs": [
                    {
                        "case": "a=0",
                        "context": run_context,
                        "selected_state": ["S"],
                        "observation": {"success": True, "retval": 1},
                        "suffix": suffix,
                    },
                    {
                        "case": "a=1",
                        "context": run_context,
                        "selected_state": ["S", "A"],
                        "observation": obs1,
                        "suffix": suffix,
                    },
                ],
            },
        )
        return bundle

    def test_establishes_report_factorization_failure(self):
        bundle = self._bundle()

        result = extract_factorization(bundle)

        self.assertEqual(RESULT_ESTABLISHED, result["result"])
        self.assertTrue(result["conditions"]["pi_R_equal"])
        self.assertTrue(result["conditions"]["beta_D_different"])
        self.assertTrue(result["conditions"]["observations_differ"])
        self.assertEqual(result["pi_R"]["sigma-a0"], result["pi_R"]["sigma-a1"])
        self.assertNotEqual(result["beta_D"]["sigma-a0"], result["beta_D"]["sigma-a1"])
        self.assertTrue((bundle / "proof" / "factorization" / "factorization.md").exists())

    def test_rejects_when_common_suffix_observations_do_not_differ(self):
        bundle = self._bundle(same_observation=True)

        result = extract_factorization(bundle)

        self.assertEqual(RESULT_REJECTED, result["result"])
        self.assertFalse(result["conditions"]["observations_differ"])
        self.assertIn("runtime_observations_differ", result["precondition_reasons"])


if __name__ == "__main__":
    unittest.main()
