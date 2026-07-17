from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from residuality_auditor.linux_r import LinuxRError, analyze_linux_r


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "linux" / "fixtures"


class LinuxRTests(unittest.TestCase):
    def test_candidate_requires_review(self) -> None:
        result = analyze_linux_r(
            FIXTURES / "events.jsonl",
            FIXTURES / "runtime.json",
            FIXTURES / "contract-candidate.json",
        )
        self.assertEqual(
            result["verdict"],
            "LINUX_R_CANDIDATE_REQUIRES_CONCRETIZATION_AND_REPORT_CONTRACT_REVIEW",
        )
        self.assertTrue(result["summary"]["linux_R_candidate"])
        self.assertFalse(result["summary"]["linux_R_established"])
        self.assertEqual(result["selected_operational_cell"]["program_name"], "rac_prefix")

    def test_established_only_under_declared_review(self) -> None:
        result = analyze_linux_r(
            FIXTURES / "events.jsonl",
            FIXTURES / "runtime.json",
            FIXTURES / "contract-established.json",
        )
        self.assertEqual(result["verdict"], "LINUX_R_ESTABLISHED_UNDER_DECLARED_CONTRACT")
        self.assertTrue(result["summary"]["linux_R_established"])

    def test_wrong_program_does_not_establish(self) -> None:
        contract = json.loads((FIXTURES / "contract-established.json").read_text())
        contract["program_name"] = "another_prog"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "contract.json"
            path.write_text(json.dumps(contract))
            result = analyze_linux_r(FIXTURES / "events.jsonl", FIXTURES / "runtime.json", path)
        self.assertEqual(result["verdict"], "LINUX_R_NOT_ESTABLISHED")
        self.assertFalse(result["prerequisites"]["joint_operational_prune_cell"])

    def test_missing_frontier_fails_closed(self) -> None:
        contract = json.loads((FIXTURES / "contract-candidate.json").read_text())
        contract["frontier"] = {}
        contract["path_correspondence_reviewed"] = False
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "contract.json"
            path.write_text(json.dumps(contract))
            result = analyze_linux_r(FIXTURES / "events.jsonl", FIXTURES / "runtime.json", path)
        self.assertEqual(result["verdict"], "LINUX_R_NOT_ESTABLISHED")
        self.assertFalse(result["prerequisites"]["frontier_declared"])

    def test_malformed_runtime_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "runtime.json"
            path.write_text('{"schema":"wrong","runs":[]}')
            with self.assertRaises(LinuxRError):
                analyze_linux_r(FIXTURES / "events.jsonl", path, FIXTURES / "contract-candidate.json")


if __name__ == "__main__":
    unittest.main()
