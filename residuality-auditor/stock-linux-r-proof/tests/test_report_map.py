import unittest

from tools.report_map.check_uniqueness import check_uniqueness


class ReportMapTests(unittest.TestCase):
    def _complete_session(self):
        return {"session_complete": True, "verifier_invocation_completed": True, "ringbuf_lost_events": 0, "collector_parse_errors": 0}

    def test_unique_same_report_cell(self):
        coverage = {"cases": {"a=0": {"retained_representatives": ["r"]}, "a=1": {"retained_representatives": ["r"]}}}
        self.assertEqual("UNIQUE_SAME_REPORT_CELL", check_uniqueness(coverage, self._complete_session())["result"])

    def test_distinguishes_when_representatives_differ(self):
        coverage = {"cases": {"a=0": {"retained_representatives": ["r0"]}, "a=1": {"retained_representatives": ["r1"]}}}
        self.assertEqual("REPORT_DISTINGUISHES_BEHAVIORAL_STATES", check_uniqueness(coverage, self._complete_session())["result"])

    def test_non_unique_report_cell_rejected(self):
        coverage = {"cases": {"a=0": {"retained_representatives": ["r0", "r1"]}, "a=1": {"retained_representatives": ["r0"]}}}
        self.assertEqual("JOINT_COVERAGE_WITH_NON_UNIQUE_REPORT", check_uniqueness(coverage, self._complete_session())["result"])

    def test_missing_session_cannot_claim_global_unique_cell(self):
        coverage = {"cases": {"a=0": {"retained_representatives": ["r"]}, "a=1": {"retained_representatives": ["r"]}}}
        report = check_uniqueness(coverage)
        self.assertNotEqual("UNIQUE_SAME_REPORT_CELL", report["result"])
        self.assertIn("verifier invocation did not complete", report["reasons"])


if __name__ == "__main__":
    unittest.main()
