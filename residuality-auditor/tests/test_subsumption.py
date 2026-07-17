import json
import tempfile
import unittest
from pathlib import Path

from tools.concretization.check_membership import check as check_concretization
from tools.subsumption.check_subsumption import check as check_subsumption
from tests.test_concretization import _path_report, _runtime, _state_doc


class SubsumptionTests(unittest.TestCase):
    def _bundle(self, exact_level=0):
        td = tempfile.TemporaryDirectory()
        bundle = Path(td.name) / "bundle"
        (bundle / "proof" / "states").mkdir(parents=True)
        (bundle / "proof" / "path").mkdir(parents=True)
        path = _path_report()
        path["result"] = "PATH_CORRESPONDENCE_VERIFIED"
        path["frontier"] = {"join_insn": 41}
        (bundle / "runtime.json").write_text(json.dumps({"schema": "rac-linux-runtime-v1", "kernel_release": "test-kernel", "runs": []}))
        (bundle / "events.jsonl").write_text(json.dumps({"event": "prune_hit", "visit_insn": 41, "exact_level": exact_level, "states_equal_success": True, "is_state_visited_prune": True}) + "\n")
        (bundle / "proof" / "path" / "path-correspondence.json").write_text(json.dumps(path))
        state_check = {"result": "STATE_V2_CAPTURE_OK"}
        (bundle / "proof" / "states" / "state-capture-check.json").write_text(json.dumps(state_check))
        (bundle / "proof" / "states" / "retained-state.json").write_text(json.dumps(_state_doc("retained")))
        (bundle / "proof" / "states" / "current-state.json").write_text(json.dumps(_state_doc("current")))
        check_concretization(bundle)
        return td, bundle

    def test_establishes_restricted_subsumption_for_supported_shape(self):
        td, bundle = self._bundle()
        self.addCleanup(td.cleanup)

        report = check_subsumption(bundle)

        self.assertEqual("RESTRICTED_SUBSUMPTION_ESTABLISHED", report["result"])

    def test_rejects_unsupported_exact_mode(self):
        td, bundle = self._bundle(exact_level=1)
        self.addCleanup(td.cleanup)

        report = check_subsumption(bundle)

        self.assertEqual("RESTRICTED_SUBSUMPTION_REJECTED", report["result"])
        self.assertFalse(report["preconditions"]["exact_level_supported"])


if __name__ == "__main__":
    unittest.main()
