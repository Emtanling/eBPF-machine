#!/usr/bin/env python3
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "write_interpreter_provenance", ROOT / "scripts" / "write_interpreter_provenance.py"
)
assert SPEC and SPEC.loader
provenance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = provenance
SPEC.loader.exec_module(provenance)


class InterpreterProvenanceTests(unittest.TestCase):
    def make_run(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "unit-run"
        root.mkdir()
        (root / "evidence.txt").write_text("evidence\n", encoding="utf-8")
        provenance.write_manifest(root, "unit-run")
        return temporary, root

    def test_valid_manifest_verifies(self):
        temporary, root = self.make_run()
        self.addCleanup(temporary.cleanup)
        self.assertEqual(provenance.verify_manifest(root), [])

    def test_bounds_tampering_is_rejected(self):
        temporary, root = self.make_run()
        self.addCleanup(temporary.cleanup)
        path = root / provenance.MANIFEST_NAME
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["bounds"]["max_gates"] = 513
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertIn("unexpected interpreter bounds", provenance.verify_manifest(root))

    def test_duplicate_path_is_rejected(self):
        temporary, root = self.make_run()
        self.addCleanup(temporary.cleanup)
        path = root / provenance.MANIFEST_NAME
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["files"].append(dict(manifest["files"][0]))
        path.write_text(json.dumps(manifest), encoding="utf-8")
        failures = provenance.verify_manifest(root)
        self.assertTrue(any("duplicate manifest path" in item for item in failures))

    def test_nested_manifest_named_file_is_bound(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "unit-run"
        nested = root / "nested"
        nested.mkdir(parents=True)
        (root / "evidence.txt").write_text("evidence\n", encoding="utf-8")
        (nested / provenance.MANIFEST_NAME).write_text("nested evidence\n",
                                                        encoding="utf-8")
        provenance.write_manifest(root, "unit-run")
        manifest = json.loads((root / provenance.MANIFEST_NAME).read_text(encoding="utf-8"))
        self.assertIn("nested/interpreter.provenance.json",
                      {entry["path"] for entry in manifest["files"]})
        self.assertEqual(provenance.verify_manifest(root), [])

    def test_report_is_in_suite_source_snapshot(self):
        runner = (ROOT / "scripts" / "run_interpreter_suite.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("\n    PAPER_REPORT.md\n", runner)
        self.assertIn("\n    PAPER_REPORT.tex\n", runner)


if __name__ == "__main__":
    unittest.main()
