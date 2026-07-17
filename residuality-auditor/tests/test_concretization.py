import json
import tempfile
import unittest
from pathlib import Path

from tools.concretization.check_membership import check


def _reg(t=0):
    return {
        "type": t,
        "off": 0,
        "var_off": {"value": 0, "mask": 0 if t == 6 else (2**64 - 1)},
        "smin_value": 0 if t in (1, 6) else -(2**63),
        "smax_value": 0 if t in (1, 6) else 2**63 - 1,
        "umin_value": 0,
        "umax_value": 0 if t in (1, 6) else 2**64 - 1,
        "s32_min_value": 0 if t in (1, 6) else -(2**31),
        "s32_max_value": 0 if t in (1, 6) else 2**31 - 1,
        "u32_min_value": 0,
        "u32_max_value": 0 if t in (1, 6) else 2**32 - 1,
        "id": 0,
        "ref_obj_id": 0,
        "frameno": 0,
        "subreg_def": 0,
        "live": 0,
        "precise": False,
    }


def _state_doc(role, bad=False):
    regs = [_reg() for _ in range(11)]
    regs[10] = _reg(6)
    if bad:
        regs[0]["type"] = 8
    snapshot = {
        "insn_idx": 41,
        "state_v2": {
            "valid": True,
            "unsupported_mask": 0,
            "frames": [{"present": True, "frameno": 0, "allocated_stack": 0, "regs": regs, "stack_slots": []}],
        },
    }
    return {"schema": f"rac-{role}-state-v2-proof", "role": role, "snapshot": snapshot}


def _path_report():
    return {
        "identity": {"object_sha256": "ab" * 32, "program_tag": "tag"},
        "common_suffix": {"same_remaining_xlated_suffix": True},
        "prefixes": {
            "a=0": {"history_side": "history_right", "branch_name": "select_s", "branch_call": 48, "runtime_selected_state": ["S"], "runtime_selected_mask": 1, "runtime_observation_success": True},
            "a=1": {"history_side": "history_left", "branch_name": "select_a", "branch_call": 46, "runtime_selected_state": ["S", "A"], "runtime_selected_mask": 3, "runtime_observation_success": False},
        },
    }


def _runtime():
    return {"schema": "rac-linux-runtime-v1", "runs": []}


class ConcretizationTests(unittest.TestCase):
    def _bundle(self, bad_retained=False):
        td = tempfile.TemporaryDirectory()
        bundle = Path(td.name) / "bundle"
        (bundle / "proof" / "states").mkdir(parents=True)
        (bundle / "proof" / "path").mkdir(parents=True)
        (bundle / "runtime.json").write_text(json.dumps(_runtime()))
        (bundle / "proof" / "path" / "path-correspondence.json").write_text(json.dumps(_path_report()))
        (bundle / "proof" / "states" / "retained-state.json").write_text(json.dumps(_state_doc("retained", bad=bad_retained)))
        (bundle / "proof" / "states" / "current-state.json").write_text(json.dumps(_state_doc("current")))
        return td, bundle

    def test_membership_passes_for_supported_local_shape(self):
        td, bundle = self._bundle()
        self.addCleanup(td.cleanup)

        report = check(bundle)

        self.assertEqual("SIGMA_A0_IN_DIRECT_GAMMA", report["memberships"]["a=0"]["result"])
        self.assertEqual("SIGMA_A1_IN_DIRECT_GAMMA", report["memberships"]["a=1"]["result"])
        self.assertEqual("JOINT_COVERAGE_CANDIDATE", report["joint_coverage"]["result"])

    def test_unsupported_register_type_rejects_membership(self):
        td, bundle = self._bundle(bad_retained=True)
        self.addCleanup(td.cleanup)

        report = check(bundle)

        self.assertEqual("SIGMA_A1_IN_DIRECT_GAMMA_REJECTED", report["memberships"]["a=1"]["result"])


if __name__ == "__main__":
    unittest.main()
