#!/usr/bin/env python3
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


circuit_tool = load_module("circuit_tool", ROOT / "scripts" / "circuit_tool.py")
audit_interpreter = load_module(
    "audit_interpreter", ROOT / "scripts" / "audit_interpreter.py"
)


class InterpreterAuditTests(unittest.TestCase):
    def nand_descriptor(self):
        return circuit_tool.compile_spec({
            "name": "nand",
            "inputs": ["a", "b"],
            "gates": [{"id": "out", "op": "nand", "args": ["a", "b"]}],
            "outputs": ["out"],
        })

    def test_missing_exhaustive_assignment_is_rejected(self):
        audit = audit_interpreter.Audit()
        descriptor = self.nand_descriptor()
        rows = [{"circuit": "nand", "kind": "exhaustive", "assignment": 0, "run_seq": 1}]
        audit_interpreter.require_exhaustive_runs(
            rows, {"nand"}, {"nand": descriptor}, audit, "unit"
        )
        self.assertTrue(any("incomplete input coverage" in item for item in audit.failures))

    def test_non_run_stress_record_is_rejected(self):
        audit = audit_interpreter.Audit()
        descriptor = self.nand_descriptor()
        rows = []
        for index in range(10_000):
            rows.append({
                "record": "negative",
                "passed": True,
                "program_id": 1,
                "run_seq": index + 1,
                "circuit": "nand",
                "kind": "alternating_stress",
                "ordinal": 0,
                "variant_id": 1,
                "gate_cap": 2,
                "status": 0,
                "executed": 1,
                "failing_gate": 0xFFFFFFFF,
                "gate_error_count": 0,
                "trace_passed": True,
                "assignment": 0,
                "input_count": 2,
                "gate_count": 1,
                "logical_expected": 1,
                "variant_expected": 1,
                "actual": 1,
            })
        audit_interpreter.verify_stress(rows, audit, {"nand": descriptor})
        self.assertTrue(any("non-run record" in item for item in audit.failures))

    def test_corpus_must_match_fixed_seed_regeneration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = root / "corpus"
            circuit_tool.create_corpus(
                corpus,
                audit_interpreter.CORPUS_SEED,
                audit_interpreter.CORPUS_COUNT,
                audit_interpreter.CORPUS_MAX_INPUTS,
                audit_interpreter.CORPUS_MAX_GATES,
            )
            audit = audit_interpreter.Audit()
            names = audit_interpreter.load_corpus_manifest(root, audit)
            self.assertEqual(len(names), audit_interpreter.CORPUS_COUNT)
            self.assertEqual(audit.failures, [])

            descriptor = corpus / "rand_000.wmc"
            descriptor.write_text(descriptor.read_text(encoding="utf-8") + "\n",
                                  encoding="utf-8")
            tampered = audit_interpreter.Audit()
            audit_interpreter.load_corpus_manifest(root, tampered)
            self.assertTrue(any("bytes differ" in item for item in tampered.failures))

    def test_runtime_tag_must_match_captured_variant(self):
        rows = [{"program_id": 7, "program_tag": "0123456789abcdef"}]
        audit = audit_interpreter.Audit()
        audit_interpreter.require_runtime_identity(
            rows, audit, "unit", "0123456789abcdef"
        )
        self.assertEqual(audit.failures, [])

        mismatched = audit_interpreter.Audit()
        audit_interpreter.require_runtime_identity(
            rows, mismatched, "unit", "fedcba9876543210"
        )
        self.assertTrue(any("does not match" in item for item in mismatched.failures))

    def test_named_descriptor_must_match_source_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_dir = root / "source" / "circuits"
            descriptor_dir = root / "descriptors"
            source_dir.mkdir(parents=True)
            descriptor_dir.mkdir()
            for source in (ROOT / "circuits").glob("*.json"):
                copied = source_dir / source.name
                shutil.copyfile(source, copied)
                circuit_tool.compile_file(copied, descriptor_dir / f"{source.stem}.wmc")

            audit = audit_interpreter.Audit()
            audit_interpreter.verify_named_descriptor_sources(root, audit)
            self.assertEqual(audit.failures, [])

            nand = source_dir / "nand.json"
            spec = json.loads(nand.read_text(encoding="utf-8"))
            spec["gates"][0]["args"] = ["1", "1"]
            nand.write_text(json.dumps(spec), encoding="utf-8")
            tampered = audit_interpreter.Audit()
            audit_interpreter.verify_named_descriptor_sources(root, tampered)
            self.assertTrue(any("bytes differ for nand.wmc" in item
                                for item in tampered.failures))

    def test_deep_boundary_must_match_generator(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            circuit_tool.create_deep_chain(
                root / "boundary_deep_512.json",
                root / "boundary_deep_512.wmc",
                circuit_tool.VM_MAX_GATES,
            )
            audit = audit_interpreter.Audit()
            audit_interpreter.verify_deep_boundary_source(root, audit)
            self.assertEqual(audit.failures, [])

            boundary = root / "boundary_deep_512.wmc"
            boundary.write_text(boundary.read_text(encoding="utf-8") + "\n",
                                encoding="utf-8")
            tampered = audit_interpreter.Audit()
            audit_interpreter.verify_deep_boundary_source(root, tampered)
            self.assertTrue(any("bytes differ for boundary_deep_512.wmc" in item
                                for item in tampered.failures))

    def test_full_boundary_must_match_generator(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            circuit_tool.create_full_boundary(
                root / "boundary_full_64_512.json",
                root / "boundary_full_64_512.wmc",
            )
            audit = audit_interpreter.Audit()
            audit_interpreter.verify_full_boundary_source(root, audit)
            self.assertEqual(audit.failures, [])

            boundary = root / "boundary_full_64_512.json"
            spec = json.loads(boundary.read_text(encoding="utf-8"))
            spec["outputs"] = ["i0"]
            boundary.write_text(json.dumps(spec), encoding="utf-8")
            tampered = audit_interpreter.Audit()
            audit_interpreter.verify_full_boundary_source(root, tampered)
            self.assertTrue(any("bytes differ for boundary_full_64_512.json" in item
                                for item in tampered.failures))


if __name__ == "__main__":
    unittest.main()
