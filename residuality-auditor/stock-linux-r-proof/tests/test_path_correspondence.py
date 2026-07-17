import json
import tempfile
import unittest
from pathlib import Path

from tools.path.emit_correspondence import emit


XLATED = """
int rac_single(struct xdp_md * ctx):
  10: (85) call pc+34#bpf_prog_x_select_branch
  11: (85) call pc+88#bpf_prog_x_shared_suffix
  12: (95) exit
long select_branch(__u8 a):
  45: (15) if r1 == 0x0 goto pc+2
  46: (85) call pc+13#bpf_prog_x_select_a
  47: (05) goto pc+1
  48: (85) call pc+31#bpf_prog_x_select_s
  49: (95) exit
long select_a(void):
  60: (85) call 0x2
  61: (95) exit
long select_s(void):
  80: (85) call 0x2
  81: (95) exit
int shared_suffix(void):
  100: (85) call 0x2
  101: (95) exit
"""


def _runtime(a1_state=None):
    return {
        "schema": "rac-linux-runtime-v1",
        "object_sha256": "ab" * 32,
        "program_tag": "tag",
        "runs": [
            {
                "case": "a=0",
                "selected_state": ["S"],
                "final_state": ["S", "B"],
                "observation": {"success": True, "retval": 1},
                "context": {"serialized": True},
                "suffix": {"program": "rac_single"},
            },
            {
                "case": "a=1",
                "selected_state": a1_state or ["S", "A"],
                "final_state": ["S", "A"],
                "observation": {"success": False, "retval": 0},
                "context": {"serialized": True},
                "suffix": {"program": "rac_single"},
            },
        ],
    }


def _frontier():
    return {
        "result": "FRONTIER_ELIGIBLE",
        "identity": {"object_sha256": "ab" * 32, "program_tag": "tag"},
        "frontier": {
            "branch_dispatch_call": 10,
            "join_insn": 11,
            "suffix_entry_insn": 100,
            "first_sensitive_insn": 100,
            "branch_calls": [46, 48],
        },
        "events": [
            {
                "passed": True,
                "visit_insn": 11,
                "same_remaining_xlated_suffix": True,
                "history_left": {
                    "branch_call_hits": [48],
                    "entries": [{"insn_idx": 49, "prev_insn_idx": 80}],
                    "captured_count": 1,
                    "total_count": 1,
                    "truncated": False,
                },
                "history_right": {
                    "branch_call_hits": [46],
                    "entries": [{"insn_idx": 47, "prev_insn_idx": 60}],
                    "captured_count": 1,
                    "total_count": 1,
                    "truncated": False,
                },
            }
        ],
    }


class PathCorrespondenceTests(unittest.TestCase):
    def _bundle(self, runtime=None):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        bundle = root / "bundle"
        bundle.mkdir()
        (bundle / "xlated.txt").write_text(XLATED)
        (bundle / "frontier-check.json").write_text(json.dumps(_frontier()) + "\n")
        (bundle / "runtime.json").write_text(json.dumps(runtime or _runtime()) + "\n")
        return td, bundle

    def test_verifies_path_correspondence_without_left_right_guessing(self):
        td, bundle = self._bundle()
        self.addCleanup(td.cleanup)

        report = emit(bundle)

        self.assertEqual("PATH_CORRESPONDENCE_VERIFIED", report["result"])
        self.assertEqual("select_s", report["prefixes"]["a=0"]["branch_name"])
        self.assertEqual("history_left", report["prefixes"]["a=0"]["history_side"])
        self.assertEqual("select_a", report["prefixes"]["a=1"]["branch_name"])
        self.assertTrue((bundle / "proof" / "path" / "path-correspondence.md").exists())

    def test_rejects_runtime_mask_mismatch(self):
        td, bundle = self._bundle(runtime=_runtime(a1_state=["S"]))
        self.addCleanup(td.cleanup)

        report = emit(bundle)

        self.assertEqual("PATH_CORRESPONDENCE_REJECTED", report["result"])
        self.assertTrue(any("selected mask" in reason for reason in report["reasons"]))


if __name__ == "__main__":
    unittest.main()
