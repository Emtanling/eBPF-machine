"""Regression tests for the fail-closed v0.3.2 frontier gate."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.frontier.check_frontier import check_bundle
from tools.frontier.parse_xlated import parse_xlated_file


ROOT = Path(__file__).resolve().parent
ELIGIBLE = ROOT / "fixtures" / "frontier-eligible" / "synthetic"
CURRENT_EVENT = ROOT / "fixtures" / "frontier-invalid" / "current-event"


class FrontierCheckTests(unittest.TestCase):
    def _copied_fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        target = Path(temporary.name) / "bundle"
        shutil.copytree(ELIGIBLE, target)
        return temporary, target

    def _event(self, bundle: Path) -> dict[str, object]:
        return json.loads((bundle / "events.jsonl").read_text(encoding="utf-8"))

    def _write_event(self, bundle: Path, event: dict[str, object]) -> None:
        (bundle / "events.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")

    def _write_runtime(self, bundle: Path, runtime: dict[str, object]) -> None:
        (bundle / "runtime.json").write_text(json.dumps(runtime) + "\n", encoding="utf-8")

    def _write_program_info(self, bundle: Path, program_info: dict[str, object]) -> None:
        (bundle / "program-info.json").write_text(json.dumps(program_info) + "\n", encoding="utf-8")

    def _write_xlated(self, bundle: Path, text: str) -> None:
        (bundle / "xlated-rac_single.txt").write_text(text, encoding="utf-8")

    def test_synthetic_post_return_pre_suffix_event_is_eligible(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            report = check_bundle(bundle, Path(temporary.name) / "proof")
        self.assertEqual("FRONTIER_ELIGIBLE", report["result"])
        self.assertEqual(2, report["frontier"]["join_insn"])
        self.assertEqual(21, report["frontier"]["first_sensitive_insn"])

    def test_branch_call_return_pc_counts_as_history_provenance(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            event = self._event(bundle)
            event["old"]["history_entries"] = [{"insn_idx": 7, "prev_insn_idx": 13}]
            event["current"]["history_entries"] = [{"insn_idx": 9, "prev_insn_idx": 15}]
            self._write_event(bundle, event)
            report = check_bundle(bundle, Path(temporary.name) / "proof")
        self.assertEqual("FRONTIER_ELIGIBLE", report["result"])
        self.assertEqual([6], report["events"][0]["history_left"]["branch_call_hits"])
        self.assertEqual([8], report["events"][0]["history_right"]["branch_call_hits"])

    def test_common_normalizer_before_shared_suffix_is_eligible(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            self._write_xlated(
                bundle,
                """rac_single:
0: (bf) r6 = r1
1: (85) call pc+4#select_branch
2: (85) call pc+13#normalize_join
3: (85) call pc+14#shared_suffix
4: (bf) r0 = r6
5: (95) exit
select_branch:
6: (15) if r1 == 0x0 goto pc+2
7: (85) call pc+4#select_a
8: (05) goto pc+2
9: (85) call pc+4#select_s
10: (05) goto pc+0
11: (95) exit
select_a:
12: (b7) r0 = 0
13: (95) exit
select_s:
14: (b7) r0 = 0
15: (95) exit
normalize_join:
16: (b7) r0 = 0
17: (95) exit
shared_suffix:
18: (b7) r1 = 0
19: (85) call 2
20: (95) exit
""",
            )
            xlated_sha = hashlib.sha256((bundle / "xlated-rac_single.txt").read_bytes()).hexdigest()
            (bundle / "xlated-rac_single.sha256").write_text(
                f"{xlated_sha}  xlated-rac_single.txt\n", encoding="utf-8"
            )
            runtime = json.loads((bundle / "runtime.json").read_text(encoding="utf-8"))
            runtime["xlated_sha256"] = xlated_sha
            self._write_runtime(bundle, runtime)
            program_info = json.loads((bundle / "program-info.json").read_text(encoding="utf-8"))
            program_info["bytes_xlated"] = 168
            self._write_program_info(bundle, program_info)

            event = self._event(bundle)
            event["visit_insn"] = 3
            event["old"]["history_entries"] = [{"insn_idx": 8, "prev_insn_idx": 13}]
            event["old"]["history_total_count"] = 1
            event["old"]["history_captured_count"] = 1
            event["current"]["history_entries"] = [{"insn_idx": 10, "prev_insn_idx": 15}]
            event["current"]["history_total_count"] = 1
            event["current"]["history_captured_count"] = 1
            self._write_event(bundle, event)
            report = check_bundle(bundle, Path(temporary.name) / "proof")
        self.assertEqual("FRONTIER_ELIGIBLE", report["result"])
        self.assertEqual(3, report["frontier"]["join_insn"])
        self.assertEqual(19, report["frontier"]["first_sensitive_insn"])

    def test_checker_requires_an_external_new_output_directory(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            with self.assertRaises(ValueError):
                check_bundle(bundle)
            with self.assertRaises(ValueError):
                check_bundle(bundle, bundle / "proof")
            output = Path(temporary.name) / "proof"
            check_bundle(bundle, output)
            with self.assertRaises(FileExistsError):
                check_bundle(bundle, output)
        self.assertFalse((bundle / "proof").exists())

    def test_direct_script_cli_is_supported(self) -> None:
        script = ROOT.parent / "tools" / "frontier" / "check_frontier.py"
        completed = subprocess.run(
            [sys.executable, str(script), "--help"],
            cwd=ROOT.parent,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("--out", completed.stdout)

    def test_real_event_after_or_outside_target_frontier_is_rejected(self) -> None:
        self.assertTrue(CURRENT_EVENT.is_dir(), "current v0.3.1 event fixture must be preserved")
        with tempfile.TemporaryDirectory() as temporary:
            report = check_bundle(CURRENT_EVENT, Path(temporary) / "proof")
        self.assertEqual("FRONTIER_REJECTED", report["result"])
        self.assertEqual(
            {
                "join_insn": 39,
                "suffix_entry_insn": 95,
                "first_sensitive_insn": 106,
            },
            {
                key: report["frontier"][key]
                for key in ("join_insn", "suffix_entry_insn", "first_sensitive_insn")
            },
        )
        decisions = {event["visit_insn"]: event for event in report["events"]}
        self.assertEqual({41, 107}, set(decisions))
        self.assertTrue(decisions[41]["states_equal_success"])
        self.assertTrue(decisions[41]["is_state_visited_prune"])
        self.assertIn("VISIT_AFTER_FIRST_SENSITIVE", decisions[41]["reasons"])
        self.assertIn("VISIT_OUTSIDE_CANONICAL_PRE_SUFFIX_FRONTIER", decisions[107]["reasons"])

    def test_ldimm64_width_is_preserved_in_cfg_and_length_binding(self) -> None:
        instructions = parse_xlated_file(CURRENT_EVENT / "xlated-rac_single.txt")
        self.assertEqual(2, next(item for item in instructions if item.pc == 14).slots)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "proof"
            check_bundle(CURRENT_EVENT, output)
            cfg = json.loads((output / "cfg.json").read_text(encoding="utf-8"))
        self.assertIn({"from": 14, "to": 16, "kind": "fallthrough"}, cfg["edges"])

    def test_hash_difference_alone_is_not_branch_provenance(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            event = self._event(bundle)
            for key in ("old", "current"):
                state = event[key]
                state.pop("history_entries")
                state["history_hash"] = "different-" + key
                state["history_count"] = 1
            self._write_event(bundle, event)
            report = check_bundle(bundle, Path(temporary.name) / "proof")
        self.assertEqual("FRONTIER_REJECTED", report["result"])
        self.assertIn("HISTORY_PROVENANCE_UNAVAILABLE", report["events"][0]["reasons"])

    def test_truncated_history_fails_closed(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            event = self._event(bundle)
            event["old"]["history_truncated"] = True
            self._write_event(bundle, event)
            report = check_bundle(bundle, Path(temporary.name) / "proof")
        self.assertEqual("FRONTIER_REJECTED", report["result"])
        self.assertIn("HISTORY_TRUNCATED_OR_INCOMPLETE", report["events"][0]["reasons"])

    def test_conflicting_history_entry_aliases_fail_closed(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            event = self._event(bundle)
            event["old"]["history_entries"] = [{"insn_idx": 6, "pc": 8}]
            event["current"]["history_entries"] = [{"insn_idx": 8, "pc": 6}]
            self._write_event(bundle, event)
            report = check_bundle(bundle, Path(temporary.name) / "proof")
        self.assertEqual("FRONTIER_REJECTED", report["result"])
        self.assertIn("HISTORY_ENTRY_INSN_CONFLICT", report["events"][0]["reasons"])

    def test_post_suffix_return_is_rejected_without_cross_function_pc_math(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            xlated_sha = hashlib.sha256((bundle / "xlated-rac_single.txt").read_bytes()).hexdigest()
            (bundle / "xlated-rac_single.sha256").write_text(
                f"{xlated_sha}  xlated-rac_single.txt\n", encoding="utf-8"
            )
            runtime = json.loads((bundle / "runtime.json").read_text(encoding="utf-8"))
            runtime["xlated_sha256"] = xlated_sha
            self._write_runtime(bundle, runtime)
            program_info = json.loads((bundle / "program-info.json").read_text(encoding="utf-8"))
            program_info["bytes_xlated"] = 168
            self._write_program_info(bundle, program_info)

            event = self._event(bundle)
            event["visit_insn"] = 3
            self._write_event(bundle, event)
            report = check_bundle(bundle, Path(temporary.name) / "proof")
        self.assertEqual("FRONTIER_REJECTED", report["result"])
        self.assertIn("VISIT_AFTER_FIRST_SENSITIVE", report["events"][0]["reasons"])

    def test_checker_writes_the_complete_proof_set(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            output = Path(temporary.name) / "proof"
            check_bundle(bundle, output)
            names = {path.name for path in output.iterdir()}
            frontier = json.loads((output / "frontier.json").read_text(encoding="utf-8"))
            manifest = json.loads((output / "run-manifest.json").read_text(encoding="utf-8"))
            completion = (output / "COMPLETE").read_text(encoding="utf-8").strip()
        self.assertTrue(
            {
                "cfg.json",
                "call-sites.json",
                "shared-suffix.json",
                "frontier.json",
                "frontier-check.json",
                "frontier-check.md",
                "run-manifest.json",
                "COMPLETE",
            }.issubset(names)
        )
        for key in (
            "object_sha256",
            "program_id",
            "program_tag",
            "join_insn",
            "suffix_entry_insn",
            "first_sensitive_insn",
            "selected_visit_insn",
            "history_left",
            "history_right",
        ):
            self.assertIn(key, frontier)
        self.assertEqual(2, frontier["selected_visit_insn"])
        self.assertEqual([{"insn_idx": 6}], frontier["history_left"])
        self.assertEqual([{"insn_idx": 8}], frontier["history_right"])
        self.assertEqual("complete", manifest["status"])
        self.assertEqual(completion, manifest["run_id"])
        self.assertEqual("0.3.2", manifest["checker"]["version"])

    def test_runtime_xlated_digest_is_required(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            runtime = json.loads((bundle / "runtime.json").read_text(encoding="utf-8"))
            runtime.pop("xlated_sha256")
            self._write_runtime(bundle, runtime)
            report = check_bundle(bundle, Path(temporary.name) / "proof")
        self.assertEqual("FRONTIER_REJECTED", report["result"])
        self.assertIn("XLATED_SHA_RUNTIME_UNAVAILABLE", report["global_reasons"])

    def test_xlated_digest_mismatch_is_rejected(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            xlated = (bundle / "xlated-rac_single.txt").read_text(encoding="utf-8")
            self._write_xlated(bundle, xlated.replace("0: (bf) r6 = r1", "0: (bf) r6 = r2"))
            report = check_bundle(bundle, Path(temporary.name) / "proof")
        self.assertEqual("FRONTIER_REJECTED", report["result"])
        self.assertIn("XLATED_SHA_SIDECAR_MISMATCH", report["global_reasons"])
        self.assertIn("XLATED_SHA_RUNTIME_MISMATCH", report["global_reasons"])

    def test_unexplained_xlated_slot_gap_is_rejected(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            xlated = (bundle / "xlated-rac_single.txt").read_text(encoding="utf-8")
            self._write_xlated(bundle, xlated.replace("3: (bf) r0 = r6\n", ""))
            report = check_bundle(bundle, Path(temporary.name) / "proof")
        self.assertEqual("FRONTIER_REJECTED", report["result"])
        self.assertIn("XLATED_INSTRUCTION_SLOT_GAP", report["global_reasons"])

    def test_conflicting_visit_alias_is_rejected(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            event = self._event(bundle)
            event["target_insn"] = 3
            self._write_event(bundle, event)
            report = check_bundle(bundle, Path(temporary.name) / "proof")
        self.assertEqual("FRONTIER_REJECTED", report["result"])
        self.assertIn("FIXED_VISIT_INSN_CONFLICT", report["events"][0]["reasons"])

    def test_explicit_failed_verifier_result_overrides_legacy_source(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            event = self._event(bundle)
            event["source"] = "fexit/states_equal+is_state_visited"
            event["states_equal"] = False
            event["is_state_visited_pruned"] = False
            self._write_event(bundle, event)
            report = check_bundle(bundle, Path(temporary.name) / "proof")
        self.assertEqual("FRONTIER_REJECTED", report["result"])
        reasons = report["events"][0]["reasons"]
        self.assertIn("STATES_EQUAL_SUCCESS_UNPROVEN", reasons)
        self.assertIn("IS_STATE_VISITED_PRUNE_UNPROVEN", reasons)

    def test_contradictory_structured_verifier_result_fails_closed(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            event = self._event(bundle)
            event["states_equal"] = {"return": -1, "status": "success"}
            self._write_event(bundle, event)
            report = check_bundle(bundle, Path(temporary.name) / "proof")
        self.assertEqual("FRONTIER_REJECTED", report["result"])
        self.assertIn("STATES_EQUAL_SUCCESS_UNPROVEN", report["events"][0]["reasons"])

    def test_identity_uses_only_documented_top_level_fields(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            runtime = json.loads((bundle / "runtime.json").read_text(encoding="utf-8"))
            program_info = json.loads((bundle / "program-info.json").read_text(encoding="utf-8"))
            runtime["metadata"] = {"program_id": 999, "program_tag": "deadbeef"}
            program_info["metadata"] = {"id": 999, "name": "other"}
            self._write_runtime(bundle, runtime)
            self._write_program_info(bundle, program_info)
            report = check_bundle(bundle, Path(temporary.name) / "proof")
        self.assertEqual("FRONTIER_ELIGIBLE", report["result"])

    def test_nested_identity_cannot_substitute_for_missing_root_field(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            runtime = json.loads((bundle / "runtime.json").read_text(encoding="utf-8"))
            runtime.pop("program_id")
            runtime["metadata"] = {"program_id": 101}
            self._write_runtime(bundle, runtime)
            report = check_bundle(bundle, Path(temporary.name) / "proof")
        self.assertEqual("FRONTIER_REJECTED", report["result"])
        self.assertIn("PROGRAM_ID_MISMATCH", report["global_reasons"])

    def test_unexpected_decode_failure_publishes_complete_rejection(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            (bundle / "events.jsonl").write_bytes(b"\xff")
            output = Path(temporary.name) / "proof"
            report = check_bundle(bundle, output)
            manifest = json.loads((output / "run-manifest.json").read_text(encoding="utf-8"))
            names = {path.name for path in output.iterdir()}
        self.assertEqual("FRONTIER_REJECTED", report["result"])
        self.assertIn("CHECKER_EXECUTION_FAILED:UnicodeDecodeError", report["global_reasons"])
        self.assertEqual("FRONTIER_REJECTED", manifest["result"])
        self.assertEqual("complete", manifest["status"])
        self.assertTrue({"COMPLETE", "cfg.json", "frontier-check.json"}.issubset(names))

    def test_event_identity_including_id_and_pin_is_required(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            event = self._event(bundle)
            event["program_id"] = 102
            event["program_pin"] = "/sys/fs/bpf/other"
            self._write_event(bundle, event)
            report = check_bundle(bundle, Path(temporary.name) / "proof")
        self.assertEqual("FRONTIER_REJECTED", report["result"])
        reasons = report["events"][0]["reasons"]
        self.assertIn("EVENT_PROGRAM_ID_MISMATCH", reasons)
        self.assertIn("EVENT_PROGRAM_PIN_MISMATCH", reasons)

    def test_non_prune_record_never_becomes_a_candidate(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            event = self._event(bundle)
            event["event"] = "not_pruned"
            self._write_event(bundle, event)
            report = check_bundle(bundle, Path(temporary.name) / "proof")
        self.assertEqual(0, report["candidate_event_count"])
        self.assertNotEqual("FRONTIER_ELIGIBLE", report["result"])

    def test_pseudo_call_must_resolve_to_the_expected_callee_entry(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            xlated = (bundle / "xlated-rac_single.txt").read_text(encoding="utf-8")
            self._write_xlated(
                bundle,
                xlated.replace("1: (85) call pc+3#select_branch", "1: (85) call pc+0#select_branch"),
            )
            report = check_bundle(bundle, Path(temporary.name) / "proof")
        self.assertIsNone(report["frontier"])
        self.assertEqual("FRONTIER_REJECTED", report["result"])

    def test_cfg_models_pseudo_calls_without_a_skip_callee_edge(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            output = Path(temporary.name) / "proof"
            check_bundle(bundle, output)
            cfg = json.loads((output / "cfg.json").read_text(encoding="utf-8"))
        edges = [edge for edge in cfg["edges"] if edge["from"] == 2]
        self.assertNotIn({"from": 2, "to": 3, "kind": "fallthrough"}, edges)
        self.assertIn({"from": 2, "to": 20, "kind": "call"}, edges)

    def test_selector_branch_calls_must_be_exclusive(self) -> None:
        temporary, bundle = self._copied_fixture()
        with temporary:
            xlated = (bundle / "xlated-rac_single.txt").read_text(encoding="utf-8")
            old_selector = "\n".join(
                (
                    "5: (15) if r1 == 0x0 goto pc+2",
                    "6: (85) call pc+5#select_a",
                    "7: (05) goto pc+2",
                    "8: (85) call pc+5#select_s",
                    "9: (05) goto pc+0",
                    "10: (95) exit",
                )
            )
            sequential_selector = "\n".join(
                (
                    "5: (85) call pc+6#select_a",
                    "6: (85) call pc+8#select_s",
                    "7: (95) exit",
                )
            )
            self._write_xlated(bundle, xlated.replace(old_selector, sequential_selector))
            report = check_bundle(bundle, Path(temporary.name) / "proof")
        self.assertIsNone(report["frontier"])
        self.assertEqual("FRONTIER_REJECTED", report["result"])


if __name__ == "__main__":
    unittest.main()
