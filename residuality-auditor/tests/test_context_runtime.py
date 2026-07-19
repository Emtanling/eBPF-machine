from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from residuality_auditor.context_runtime import main, validate_context_runtime


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def valid_fixture(root: Path) -> tuple[dict[str, object], dict[str, object], dict[str, Path]]:
    receipt_paths = {
        "object": root / "target.bpf.o",
        "btf": root / "btf-vmlinux",
        "xlated": root / "xlated.txt",
    }
    receipt_bytes = {
        "object": b"bounded-context-object\n",
        "btf": b"bounded-context-btf\n",
        "xlated": b"0: r0 = 0\n1: exit\n",
    }
    for name, path in receipt_paths.items():
        path.write_bytes(receipt_bytes[name])

    identity: dict[str, object] = {
        "program_name": "rac_v2_single",
        "program_id": 7001,
        "program_tag": "0123456789abcdef",
        "program_load_time": 123456789,
        "object_sha256": _sha256(receipt_bytes["object"]),
        "xlated_sha256": _sha256(receipt_bytes["xlated"]),
        "kernel_release": "6.17.0-test",
        "btf_sha256": _sha256(receipt_bytes["btf"]),
    }
    trials: list[dict[str, object]] = []
    for trial_id, case in enumerate((0, 1, 0, 1)):
        trial_identity = dict(identity)
        trial_identity["xlated_sha256"] = ""
        trials.append(
            {
                "trial_id": trial_id,
                "case": case,
                "test_run_rc": 0,
                "test_run_errno": 0,
                "retval": case,
                "map_value_after": case,
                "map_read_rc": 0,
                "trace_read_rc": 0,
                "program_identity": trial_identity,
                "trace": {
                    "branch": case,
                    "reset_rc": 0,
                    "branch_rc": 0,
                    "lookup_missing": False,
                    "selected_value": case,
                    "observed_value": case,
                    "trace_errors": 0,
                },
            }
        )
    runtime: dict[str, object] = {
        "schema": "rac-stock-r-v2-runtime-v1",
        "identity": copy.deepcopy(identity),
        "trials": trials,
    }
    return runtime, identity, receipt_paths


class ContextRuntimeTests(unittest.TestCase):
    def test_valid_receipts_are_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime, identity, receipts = valid_fixture(Path(temporary))

            result = validate_context_runtime(runtime, identity, receipts)

        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["trial_count"], 4)
        self.assertEqual(result["invalid_reasons"], [])

    def test_return_mismatch_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime, identity, receipts = valid_fixture(Path(temporary))
            runtime["trials"][1]["retval"] = 0

            result = validate_context_runtime(runtime, identity, receipts)

        self.assertEqual(result["status"], "INVALID")
        self.assertIn("RETVAL_CASE_MISMATCH", result["invalid_reasons"])

    def test_trace_mismatch_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime, identity, receipts = valid_fixture(Path(temporary))
            runtime["trials"][2]["trace"]["observed_value"] = 1

            result = validate_context_runtime(runtime, identity, receipts)

        self.assertIn("TRACE_CASE_MISMATCH", result["invalid_reasons"])

    def test_target_identity_mismatch_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime, identity, receipts = valid_fixture(Path(temporary))
            identity["program_tag"] = "fedcba9876543210"

            result = validate_context_runtime(runtime, identity, receipts)

        self.assertIn("TARGET_IDENTITY_MISMATCH", result["invalid_reasons"])

    def test_schedule_mismatch_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime, identity, receipts = valid_fixture(Path(temporary))
            runtime["trials"][2]["case"] = 1

            result = validate_context_runtime(runtime, identity, receipts)

        self.assertIn("TRIAL_SCHEDULE_MISMATCH", result["invalid_reasons"])

    def test_object_digest_mismatch_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime, identity, receipts = valid_fixture(Path(temporary))
            receipts["object"].write_bytes(b"different object\n")

            result = validate_context_runtime(runtime, identity, receipts)

        self.assertIn("OBJECT_DIGEST_MISMATCH", result["invalid_reasons"])

    def test_translated_digest_mismatch_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime, identity, receipts = valid_fixture(Path(temporary))
            receipts["xlated"].write_bytes(b"different translated program\n")

            result = validate_context_runtime(runtime, identity, receipts)

        self.assertIn("XLATED_DIGEST_MISMATCH", result["invalid_reasons"])

    def test_cli_writes_canonical_invalid_report_and_returns_one(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime, identity, receipts = valid_fixture(root)
            runtime["trials"][0]["retval"] = 1
            runtime_path = root / "runtime.json"
            identity_path = root / "identity.json"
            output_path = root / "validation.json"
            runtime_path.write_text(json.dumps(runtime), encoding="utf-8")
            identity_path.write_text(json.dumps(identity), encoding="utf-8")

            exit_code = main(
                [
                    "--runtime",
                    str(runtime_path),
                    "--target-identity",
                    str(identity_path),
                    "--object",
                    str(receipts["object"]),
                    "--btf",
                    str(receipts["btf"]),
                    "--xlated",
                    str(receipts["xlated"]),
                    "--json-out",
                    str(output_path),
                ]
            )
            encoded = output_path.read_text(encoding="utf-8")

        self.assertEqual(exit_code, 1)
        self.assertTrue(encoded.endswith("\n"))
        self.assertIn('"status": "INVALID"', encoded)


if __name__ == "__main__":
    unittest.main()
