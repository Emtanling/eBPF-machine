from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from residuality_auditor.context_suite import load_context_suite


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent
MAKEFILE = REPO_ROOT / "Makefile"
GENERATOR = ROOT / "linux" / "scripts" / "generate_stock_r_context.py"
BASE_SOURCE = ROOT / "linux" / "witness" / "rac_v2_witness.bpf.c"
SUITE = ROOT / "linux" / "context-suite-v1.json"
RUNNER = ROOT / "linux" / "scripts" / "run_stock_r_context.sh"
BATCH_RUNNER = ROOT / "linux" / "scripts" / "run_stock_r_context_suite.py"


class EBRCContextRunnerTests(unittest.TestCase):
    def test_batch_runner_invokes_every_frozen_case_once_without_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "base-bundle"
            base.mkdir()
            output = root / "matrix"
            call_log = root / "calls.txt"
            fake_runner = root / "fake-single-runner.py"
            fake_runner.write_text(
                """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

case_id = os.environ["RAC_CONTEXT_CASE_ID"]
with Path(os.environ["CALL_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(case_id + "\\n")
suite = json.loads(Path(os.environ["RAC_CONTEXT_SUITE"]).read_text(encoding="utf-8"))
expected = next(case["expected"] for case in suite["cases"] if case["case_id"] == case_id)
observed = {name: value for name, value in expected.items() if name != "reason"}
observed["reasons"] = [] if expected["reason"] is None else [expected["reason"]]
out = Path(sys.argv[2])
(out / "context").mkdir(parents=True)
(out / "context" / "case-result.json").write_text(
    json.dumps(
        {
            "case_id": case_id,
            "observed": observed,
        },
        sort_keys=True,
    ) + "\\n",
    encoding="utf-8",
)
""",
                encoding="utf-8",
            )
            fake_runner.chmod(0o755)
            environment = dict(os.environ)
            environment["CALL_LOG"] = str(call_log)

            completed = subprocess.run(
                [
                    sys.executable,
                    str(BATCH_RUNNER),
                    str(base),
                    str(output),
                    "--suite",
                    str(SUITE),
                    "--single-runner",
                    str(fake_runner),
                    "--python",
                    sys.executable,
                ],
                cwd=REPO_ROOT,
                env=environment,
                check=False,
            )
            matrix = json.loads(
                (output / "contextual-matrix.json").read_text(encoding="utf-8")
            )
            calls = call_log.read_text(encoding="utf-8").splitlines()

        expected_ids = [case.case_id for case in load_context_suite(SUITE).cases]
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(calls, expected_ids)
        self.assertEqual(len(calls), len(set(calls)))
        self.assertEqual(matrix["counts"]["total"], 12)
        self.assertEqual(matrix["counts"]["expected"], 12)
        self.assertEqual(matrix["unexpected_results"], [])
        self.assertTrue(matrix["all_expected"])

    def test_batch_runner_uses_bpffs_safe_pin_directory_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "base-bundle"
            base.mkdir()
            output = root / "matrix"
            pin_log = root / "pins.txt"
            fake_runner = root / "fake-single-runner.py"
            fake_runner.write_text(
                """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

case_id = os.environ["RAC_CONTEXT_CASE_ID"]
with Path(os.environ["PIN_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(os.environ.get("RAC_CONTEXT_PIN_DIR", "MISSING") + "\\n")
suite = json.loads(Path(os.environ["RAC_CONTEXT_SUITE"]).read_text(encoding="utf-8"))
expected = next(case["expected"] for case in suite["cases"] if case["case_id"] == case_id)
observed = {name: value for name, value in expected.items() if name != "reason"}
observed["reasons"] = [] if expected["reason"] is None else [expected["reason"]]
out = Path(sys.argv[2])
(out / "context").mkdir(parents=True)
(out / "context" / "case-result.json").write_text(
    json.dumps({"case_id": case_id, "observed": observed}, sort_keys=True) + "\\n",
    encoding="utf-8",
)
""",
                encoding="utf-8",
            )
            fake_runner.chmod(0o755)
            environment = dict(os.environ)
            environment["PIN_LOG"] = str(pin_log)
            environment["PYTHONPATH"] = f"{ROOT / 'src'}:{ROOT}"

            completed = subprocess.run(
                [
                    sys.executable,
                    str(BATCH_RUNNER),
                    str(base),
                    str(output),
                    "--suite",
                    str(SUITE),
                    "--single-runner",
                    str(fake_runner),
                    "--python",
                    sys.executable,
                ],
                cwd=REPO_ROOT,
                env=environment,
                check=False,
            )
            pins = pin_log.read_text(encoding="utf-8").splitlines()

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(len(pins), 12)
        self.assertEqual(len(pins), len(set(pins)))
        for pin_dir in pins:
            name = Path(pin_dir).name
            self.assertTrue(pin_dir.startswith("/sys/fs/bpf/rac-v2-context-"))
            self.assertLessEqual(len(name), 63)
            self.assertRegex(name, r"^[A-Za-z0-9_-]+$")

    def test_generator_accepts_a_frozen_suite_case(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "rac_v2_witness.bpf.c"
            metadata_path = Path(temporary) / "transform-metadata.json"
            subprocess.run(
                [
                    sys.executable,
                    str(GENERATOR),
                    str(BASE_SOURCE),
                    str(output),
                    "--metadata",
                    str(metadata_path),
                    "--suite",
                    str(SUITE),
                    "--case-id",
                    "transparent.two-map.depth2",
                ],
                cwd=REPO_ROOT,
                check=True,
            )
            generated = output.read_text(encoding="utf-8")
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

        self.assertIn("ctx_pair_a SEC", generated)
        self.assertIn("ctx_pair_b SEC", generated)
        self.assertEqual(metadata["suite_id"], "stock-r-v2-crl-bounded-v1")
        self.assertEqual(metadata["case_id"], "transparent.two-map.depth2")
        self.assertEqual(metadata["claim_boundary"], "EXACT_TARGET_ONLY")

    def test_generator_inserts_post_collision_frame_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "rac_v2_witness.bpf.c"
            metadata_path = Path(temporary) / "transform-metadata.json"
            subprocess.run(
                [
                    sys.executable,
                    str(GENERATOR),
                    str(BASE_SOURCE),
                    str(output),
                    "--metadata",
                    str(metadata_path),
                ],
                cwd=REPO_ROOT,
                check=True,
            )
            generated = output.read_text(encoding="utf-8")
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

        self.assertIn("context_scratch SEC", generated)
        self.assertIn("context_frame((__u32)observed);", generated)
        self.assertEqual(metadata["variant_id"], "post-collision-frame")
        self.assertEqual(metadata["primitive"], "POST_COLLISION_FRAMED_COMPUTATION")
        self.assertTrue(metadata["obligations"]["target_conformance_bridge"])

    def test_generator_can_emit_a_distinct_affine_frame_variant(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base_output = Path(temporary) / "base" / "rac_v2_witness.bpf.c"
            base_metadata_path = Path(temporary) / "base" / "transform-metadata.json"
            affine_output = Path(temporary) / "affine" / "rac_v2_witness.bpf.c"
            affine_metadata_path = Path(temporary) / "affine" / "transform-metadata.json"
            subprocess.run(
                [
                    sys.executable,
                    str(GENERATOR),
                    str(BASE_SOURCE),
                    str(base_output),
                    "--metadata",
                    str(base_metadata_path),
                ],
                cwd=REPO_ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    str(GENERATOR),
                    str(BASE_SOURCE),
                    str(affine_output),
                    "--metadata",
                    str(affine_metadata_path),
                    "--variant",
                    "post-collision-affine-frame",
                ],
                cwd=REPO_ROOT,
                check=True,
            )
            base_metadata = json.loads(base_metadata_path.read_text(encoding="utf-8"))
            affine_generated = affine_output.read_text(encoding="utf-8")
            affine_metadata = json.loads(affine_metadata_path.read_text(encoding="utf-8"))

        self.assertIn("context_scratch_affine SEC", affine_generated)
        self.assertIn("context_affine_frame((__u32)observed);", affine_generated)
        self.assertEqual(affine_metadata["variant_id"], "post-collision-affine-frame")
        self.assertEqual(affine_metadata["primitive"], "POST_COLLISION_FRAMED_COMPUTATION")
        self.assertEqual(affine_metadata["effect"]["writes"], ["map:context_scratch_affine.0"])
        self.assertNotEqual(
            base_metadata["generated_sha256"],
            affine_metadata["generated_sha256"],
        )

    def test_runner_records_context_hostile_matrix_in_bundle(self) -> None:
        script = RUNNER.read_text(encoding="utf-8")

        self.assertIn("RAC_CONTEXT_VARIANT", script)
        self.assertIn("ebrc-context-mutations", script)
        self.assertIn("$OUT/context/hostile-matrix.json", script)

    def test_runner_retains_and_classifies_frozen_case_results(self) -> None:
        script = RUNNER.read_text(encoding="utf-8")

        self.assertIn("RAC_CONTEXT_SUITE", script)
        self.assertIn("RAC_CONTEXT_CASE_ID", script)
        self.assertIn("case-result.json", script)
        self.assertIn("compare_case_result", script)

    def test_repository_exposes_the_optional_live_matrix_target(self) -> None:
        makefile = MAKEFILE.read_text(encoding="utf-8")

        self.assertIn("contextual-matrix-live:", makefile)
        self.assertIn("STOCK_R_V2_BUNDLE", makefile)
        self.assertIn("run_stock_r_context_suite.py", makefile)


if __name__ == "__main__":
    unittest.main()
