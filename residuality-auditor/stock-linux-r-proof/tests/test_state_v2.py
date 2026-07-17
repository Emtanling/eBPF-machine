import json
import tempfile
import unittest
from pathlib import Path

from tools.state_v2.check_state_capture import materialize, recompute_legacy_state_hash


def _reg(reg_type=0):
    return {
        "type": reg_type,
        "off": 0,
        "var_off": {"value": 0, "mask": 0},
        "smin_value": 0,
        "smax_value": 0,
        "umin_value": 0,
        "umax_value": 0,
        "s32_min_value": 0,
        "s32_max_value": 0,
        "u32_min_value": 0,
        "u32_max_value": 0,
        "id": 0,
        "ref_obj_id": 0,
        "frameno": 0,
        "subreg_def": 0,
        "live": 0,
        "precise": False,
        "raw": {"raw1": 0, "raw2": 0},
        "parent_present": False,
    }


def _snapshot(unsupported_mask=0):
    state = {
        "schema": "rac-verifier-state-v2",
        "schema_version": 1,
        "valid": True,
        "unsupported_mask": unsupported_mask,
        "unsupported_mask_hex": hex(unsupported_mask),
        "insn_idx": 40,
        "first_insn_idx": 45,
        "last_insn_idx": 105,
        "curframe": 0,
        "dfs_depth": 5,
        "branches": 0,
        "acquired_refs": 0,
        "active_locks": 0,
        "active_preempt_locks": 0,
        "active_irq_id": 0,
        "active_lock_id": 0,
        "active_rcu_lock": False,
        "speculative": False,
        "in_sleepable": False,
        "callback_unroll_depth": 0,
        "may_goto_depth": 0,
        "parent_present": False,
        "equal_state_present": False,
        "refs_present": False,
        "frame_count": 1,
        "captured_frame_count": 1,
        "limits": {"max_supported_frames": 1, "max_supported_stack_slots": 32},
        "frames": [
            {
                "present": True,
                "frameno": 0,
                "callsite": -1,
                "subprogno": 0,
                "async_entry_cnt": 0,
                "callback_ret_range": {"min": 0, "max": 0},
                "in_callback_fn": False,
                "in_async_callback_fn": False,
                "in_exception_callback_fn": False,
                "callback_depth": 0,
                "allocated_stack": 0,
                "stack_slot_count": 0,
                "stack_nonzero_slot_count": 0,
                "stack_truncated": False,
                "regs": [_reg() for _ in range(11)],
                "stack_slots": [],
            }
        ],
    }
    snap = {
        "insn_idx": 40,
        "first_insn_idx": 45,
        "last_insn_idx": 105,
        "curframe": 0,
        "dfs_depth": 5,
        "history_hash": "1",
        "history_count": 1,
        "history_total_count": 1,
        "history_captured_count": 1,
        "history_truncated": False,
        "history_entries": [{"insn_idx": 45, "prev_insn_idx": 72}],
        "state_v2": state,
    }
    snap["state_hash"] = recompute_legacy_state_hash(snap)
    return snap


class StateV2CaptureTests(unittest.TestCase):
    def _bundle(self, old=None, current=None):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        bundle = root / "bundle"
        bundle.mkdir()
        old = old or _snapshot()
        current = current or _snapshot()
        event = {
            "event": "prune_hit",
            "states_equal_success": True,
            "is_state_visited_prune": True,
            "visit_insn": 40,
            "exact_level": 0,
            "old": old,
            "current": current,
        }
        (bundle / "events.jsonl").write_text(json.dumps(event) + "\n")
        frontier = {
            "result": "FRONTIER_ELIGIBLE",
            "identity": {"object_sha256": "00" * 32, "program_tag": "tag"},
            "frontier": {"join_insn": 40},
            "events": [{"passed": True, "line": 1, "visit_insn": 40, "history_left": {}, "history_right": {}}],
        }
        frontier_path = bundle / "frontier-check.json"
        frontier_path.write_text(json.dumps(frontier) + "\n")
        return td, bundle, frontier_path

    def test_materializes_state_v2_proof_outputs(self):
        td, bundle, frontier = self._bundle()
        self.addCleanup(td.cleanup)
        out = bundle / "proof" / "states"

        report = materialize(bundle, frontier, out)

        self.assertEqual("STATE_V2_CAPTURE_OK", report["result"])
        for name in [
            "retained-state.json",
            "current-state.json",
            "comparison.json",
            "state-shape.json",
            "state-capture-check.json",
        ]:
            self.assertTrue((out / name).exists(), name)

    def test_unsupported_shape_fails_closed(self):
        current = _snapshot(unsupported_mask=1 << 8)
        td, bundle, frontier = self._bundle(current=current)
        self.addCleanup(td.cleanup)

        report = materialize(bundle, frontier, bundle / "proof" / "states")

        self.assertEqual("UNSUPPORTED_STATE_SHAPE", report["result"])
        self.assertIn("packet_range", report["checks"]["current"]["unsupported_reasons"])

    def test_state_hash_mismatch_is_rejected(self):
        current = _snapshot()
        current["state_hash"] = "deadbeef"
        td, bundle, frontier = self._bundle(current=current)
        self.addCleanup(td.cleanup)

        report = materialize(bundle, frontier, bundle / "proof" / "states")

        self.assertEqual("STATE_V2_CAPTURE_REJECTED", report["result"])
        self.assertIn("STATE_HASH_RECOMPUTE_MISMATCH", report["checks"]["current"]["reasons"])


if __name__ == "__main__":
    unittest.main()
