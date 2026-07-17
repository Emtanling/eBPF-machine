from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from residuality_auditor.analysis import analyze_model, execute, shortest_output_witness
from residuality_auditor.model import ModelError, load_model


ROOT = Path(__file__).resolve().parents[1]


class AuditorTests(unittest.TestCase):
    def test_coarse_report_detects_c_r_and_nand(self) -> None:
        model = load_model(ROOT / "examples" / "map_nand_coarse_report.json")
        result = analyze_model(model)
        self.assertTrue(result["summary"]["A_acceptance"])
        self.assertTrue(result["summary"]["C_output_witnessed"])
        self.assertTrue(result["summary"]["R_non_factorization"])
        self.assertTrue(result["summary"]["R_output_witnessed"])
        self.assertTrue(result["gate_certificate"]["reset_verified"])
        self.assertTrue(result["gate_certificate"]["truth_table_verified"])

    def test_exact_report_is_negative_control(self) -> None:
        model = load_model(ROOT / "examples" / "map_nand_exact_report.json")
        result = analyze_model(model)
        self.assertTrue(result["summary"]["C_output_witnessed"])
        self.assertFalse(result["summary"]["R_non_factorization"])
        self.assertFalse(result["summary"]["R_output_witnessed"])

    def test_paper_style_c_witness(self) -> None:
        model = load_model(ROOT / "examples" / "map_nand_coarse_report.json")
        witness = shortest_output_witness(model, "S", "SA")
        self.assertIsNotNone(witness)
        assert witness is not None
        self.assertEqual(witness.word, ("put_b",))
        self.assertEqual(witness.left_execution.outputs, ("ok",))
        self.assertEqual(witness.right_execution.outputs, ("full",))

    def test_nand_rows(self) -> None:
        model = load_model(ROOT / "examples" / "map_nand_coarse_report.json")
        cases = {
            "00": (["put_s", "put_s"], "ok"),
            "01": (["put_s", "put_b"], "ok"),
            "10": (["put_a", "put_s"], "ok"),
            "11": (["put_a", "put_b"], "full"),
        }
        for _, (word, output) in cases.items():
            run = execute(model, "S", word)
            self.assertTrue(run.defined)
            self.assertEqual(run.outputs[-1], output)

    def test_overlapping_report_is_not_assessable(self) -> None:
        raw = json.loads((ROOT / "examples" / "map_nand_exact_report.json").read_text())
        raw["report"]["cells"]["overlap"] = ["S"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text(json.dumps(raw))
            model = load_model(path)
            result = analyze_model(model)
            self.assertFalse(result["R"]["assessable"])
            self.assertTrue(result["R"]["errors"])

    def test_unknown_state_is_rejected(self) -> None:
        raw = json.loads((ROOT / "examples" / "map_nand_exact_report.json").read_text())
        raw["transitions"]["S"]["put_s"]["next"] = "missing"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text(json.dumps(raw))
            with self.assertRaises(ModelError):
                load_model(path)


if __name__ == "__main__":
    unittest.main()
