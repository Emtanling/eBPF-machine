#!/usr/bin/env python3
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "circuit_tool", ROOT / "scripts" / "circuit_tool.py"
)
assert SPEC and SPEC.loader
circuit_tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = circuit_tool
SPEC.loader.exec_module(circuit_tool)


class CircuitToolTests(unittest.TestCase):
    def compile_fixture(self, name):
        with (ROOT / "circuits" / f"{name}.json").open(encoding="utf-8") as handle:
            return circuit_tool.compile_spec(json.load(handle))

    def test_round_trip_is_deterministic(self):
        circuit = self.compile_fixture("full_adder")
        encoded = circuit_tool.encode_wmc(circuit)
        self.assertEqual(circuit, circuit_tool.decode_wmc(encoded))
        self.assertEqual(encoded, circuit_tool.encode_wmc(circuit))

    def test_full_adder_truth_table(self):
        circuit = self.compile_fixture("full_adder")
        for assignment in range(8):
            a, b, cin = ((assignment >> bit) & 1 for bit in range(3))
            self.assertEqual(
                circuit_tool.evaluate(circuit, assignment),
                [(a + b + cin) & 1, (a + b + cin) >> 1],
            )

    def test_forward_reference_is_rejected(self):
        bad = {
            "name": "bad_forward",
            "inputs": ["a"],
            "gates": [{"id": "out", "op": "nand", "args": ["a", "later"]}],
            "outputs": ["out"],
        }
        with self.assertRaises(circuit_tool.CircuitError):
            circuit_tool.compile_spec(bad)

    def test_corpus_is_seed_deterministic(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            circuit_tool.create_corpus(Path(first), 1234, 4, 4, 8)
            circuit_tool.create_corpus(Path(second), 1234, 4, 4, 8)
            names = [f"rand_{index:03d}.wmc" for index in range(4)]
            for name in names:
                self.assertEqual((Path(first) / name).read_bytes(),
                                 (Path(second) / name).read_bytes())

    def test_deep_chain_reaches_declared_gate_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            circuit = circuit_tool.create_deep_chain(
                root / "deep.json", root / "deep.wmc", circuit_tool.VM_MAX_GATES
            )
            self.assertEqual(circuit.gate_count, circuit_tool.VM_MAX_GATES)
            self.assertEqual(circuit.wire_count,
                             circuit_tool.VM_INPUT_BASE + 1 + circuit_tool.VM_MAX_GATES)
            self.assertEqual(circuit_tool.evaluate(circuit, 0), [0])
            self.assertEqual(circuit_tool.evaluate(circuit, 1), [1])

    def test_full_boundary_reaches_all_declared_abi_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            circuit = circuit_tool.create_full_boundary(
                root / "full.json", root / "full.wmc"
            )
            self.assertEqual(circuit.name, "full_64_512")
            self.assertEqual(circuit.input_count, circuit_tool.VM_MAX_INPUTS)
            self.assertEqual(circuit.gate_count, circuit_tool.VM_MAX_GATES)
            self.assertEqual(circuit.wire_count, circuit_tool.VM_MAX_WIRES)
            self.assertEqual(circuit.gates[-1].dst, circuit_tool.VM_MAX_WIRES - 1)
            self.assertEqual(circuit_tool.decode_wmc(
                (root / "full.wmc").read_text(encoding="utf-8")
            ), circuit)


if __name__ == "__main__":
    unittest.main()
