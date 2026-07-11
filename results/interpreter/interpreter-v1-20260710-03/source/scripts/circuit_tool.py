#!/usr/bin/env python3
"""WMC1 encoder and independent Boolean oracle for the residual-circuit VM.

The eBPF program accepts one fixed interpreter P_U.  This host-side tool does
not emit eBPF; it validates a named NAND DAG and serializes it into the
independent bounded WMC1 text ABI.  The host loader normalizes WMC1 core gates
and inputs into maps; P_U consumes that map configuration, not the text.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

VM_ABI_VERSION = 1
VM_OP_NAND = 1
VM_INPUT_BASE = 2
VM_MAX_INPUTS = 64
VM_MAX_GATES = 512
VM_MAX_OUTPUTS = 64
VM_MAX_WIRES = VM_INPUT_BASE + VM_MAX_INPUTS + VM_MAX_GATES
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class CircuitError(ValueError):
    """Raised for a source program or WMC1 descriptor outside the v1 domain."""


@dataclass(frozen=True)
class Gate:
    op: int
    src0: int
    src1: int
    dst: int


@dataclass(frozen=True)
class Circuit:
    name: str
    input_count: int
    gates: tuple[Gate, ...]
    outputs: tuple[int, ...]

    @property
    def gate_count(self) -> int:
        return len(self.gates)

    @property
    def wire_count(self) -> int:
        return VM_INPUT_BASE + self.input_count + self.gate_count


def _require_name(value: Any, field: str) -> str:
    if not isinstance(value, str) or not NAME_RE.fullmatch(value):
        raise CircuitError(f"{field} must match {NAME_RE.pattern}")
    return value


def _require_list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise CircuitError(f"{field} must be a list")
    return value


def compile_spec(spec: dict[str, Any]) -> Circuit:
    """Compile a symbolic, topologically ordered NAND DAG into WMC1 wires."""
    if not isinstance(spec, dict):
        raise CircuitError("source must be a JSON object")
    name = _require_name(spec.get("name"), "name")
    input_names = _require_list(spec.get("inputs"), "inputs")
    gates = _require_list(spec.get("gates"), "gates")
    output_names = _require_list(spec.get("outputs"), "outputs")

    if len(input_names) > VM_MAX_INPUTS:
        raise CircuitError("input count exceeds WMC1 bound")
    if len(gates) > VM_MAX_GATES:
        raise CircuitError("gate count exceeds WMC1 bound")
    if not output_names or len(output_names) > VM_MAX_OUTPUTS:
        raise CircuitError("output count must be in 1..VM_MAX_OUTPUTS")

    symbols: dict[str, int] = {"0": 0, "1": 1}
    for index, raw_name in enumerate(input_names):
        input_name = _require_name(raw_name, f"inputs[{index}]")
        if input_name in symbols:
            raise CircuitError(f"duplicate or reserved input name: {input_name}")
        symbols[input_name] = VM_INPUT_BASE + index

    compiled: list[Gate] = []
    for index, raw_gate in enumerate(gates):
        if not isinstance(raw_gate, dict):
            raise CircuitError(f"gates[{index}] must be an object")
        gate_id = _require_name(raw_gate.get("id"), f"gates[{index}].id")
        if gate_id in symbols:
            raise CircuitError(f"duplicate or reserved gate id: {gate_id}")
        if raw_gate.get("op") != "nand":
            raise CircuitError(f"gates[{index}].op must be nand")
        args = _require_list(raw_gate.get("args"), f"gates[{index}].args")
        if len(args) != 2:
            raise CircuitError(f"gates[{index}].args must have arity 2")
        src_names = [_require_name(arg, f"gates[{index}].args") for arg in args]
        try:
            src0, src1 = (symbols[src_names[0]], symbols[src_names[1]])
        except KeyError as exc:
            raise CircuitError(
                f"gates[{index}] has forward or unknown reference: {exc.args[0]}"
            ) from None
        dst = VM_INPUT_BASE + len(input_names) + index
        compiled.append(Gate(VM_OP_NAND, src0, src1, dst))
        symbols[gate_id] = dst

    outputs: list[int] = []
    for index, raw_output in enumerate(output_names):
        output = _require_name(raw_output, f"outputs[{index}]")
        if output not in symbols:
            raise CircuitError(f"unknown output: {output}")
        outputs.append(symbols[output])
    circuit = Circuit(name, len(input_names), tuple(compiled), tuple(outputs))
    validate_circuit(circuit)
    return circuit


def validate_circuit(circuit: Circuit) -> None:
    if not NAME_RE.fullmatch(circuit.name):
        raise CircuitError("invalid circuit name")
    if not 0 <= circuit.input_count <= VM_MAX_INPUTS:
        raise CircuitError("input count outside WMC1 bound")
    if not 0 <= circuit.gate_count <= VM_MAX_GATES:
        raise CircuitError("gate count outside WMC1 bound")
    if not 1 <= len(circuit.outputs) <= VM_MAX_OUTPUTS:
        raise CircuitError("output count outside WMC1 bound")
    if circuit.wire_count > VM_MAX_WIRES:
        raise CircuitError("wire count outside WMC1 bound")
    for index, gate in enumerate(circuit.gates):
        expected_dst = VM_INPUT_BASE + circuit.input_count + index
        if (gate.op != VM_OP_NAND or gate.dst != expected_dst or
                gate.src0 >= gate.dst or gate.src1 >= gate.dst):
            raise CircuitError(f"non-canonical gate {index}")
    for output in circuit.outputs:
        if not 0 <= output < circuit.wire_count:
            raise CircuitError(f"output wire outside circuit: {output}")


def encode_wmc(circuit: Circuit) -> str:
    """Serialize a validated circuit deterministically in strict WMC1 text."""
    validate_circuit(circuit)
    lines = [
        f"WMC{VM_ABI_VERSION} {circuit.name} {circuit.input_count} "
        f"{circuit.gate_count} {circuit.wire_count} {len(circuit.outputs)}"
    ]
    lines.extend(f"{gate.op} {gate.src0} {gate.src1} {gate.dst}"
                 for gate in circuit.gates)
    lines.append(" ".join(str(output) for output in circuit.outputs))
    return "\n".join(lines) + "\n"


def decode_wmc(text: str) -> Circuit:
    tokens = text.split()
    if len(tokens) < 6:
        raise CircuitError("WMC1 input is missing its header")
    magic, name = tokens[0], tokens[1]
    if magic != f"WMC{VM_ABI_VERSION}":
        raise CircuitError(f"unsupported WMC magic: {magic}")
    try:
        input_count, gate_count, wire_count, output_count = map(int, tokens[2:6])
    except ValueError as exc:
        raise CircuitError("non-integer WMC1 header count") from exc
    expected = 6 + 4 * gate_count + output_count
    if len(tokens) != expected:
        raise CircuitError(f"WMC1 token count is {len(tokens)}, expected {expected}")
    gates: list[Gate] = []
    offset = 6
    try:
        for _ in range(gate_count):
            op, src0, src1, dst = map(int, tokens[offset:offset + 4])
            gates.append(Gate(op, src0, src1, dst))
            offset += 4
        outputs = tuple(map(int, tokens[offset:offset + output_count]))
    except ValueError as exc:
        raise CircuitError("non-integer WMC1 gate or output") from exc
    circuit = Circuit(name, input_count, tuple(gates), outputs)
    if wire_count != circuit.wire_count:
        raise CircuitError("WMC1 wire_count is not canonical")
    validate_circuit(circuit)
    return circuit


def evaluate_wires(circuit: Circuit, assignment: int, *, variant: str = "logical") -> list[int]:
    """Independent full-wire reference semantics; never calls the eBPF program."""
    validate_circuit(circuit)
    if assignment < 0:
        raise CircuitError("assignment must be non-negative")
    if circuit.input_count < 64:
        assignment &= (1 << circuit.input_count) - 1
    wires = [0] * circuit.wire_count
    wires[0] = 0
    wires[1] = 1
    for i in range(circuit.input_count):
        wires[VM_INPUT_BASE + i] = (assignment >> i) & 1
    for gate in circuit.gates:
        if variant == "logical":
            wires[gate.dst] = int(not (wires[gate.src0] and wires[gate.src1]))
        elif variant in {"cap64", "sentinel"}:
            wires[gate.dst] = 1
        else:
            raise CircuitError(f"unknown evaluation variant: {variant}")
    return wires


def evaluate(circuit: Circuit, assignment: int, *, variant: str = "logical") -> list[int]:
    """Return selected outputs from the independent full-wire semantics."""
    wires = evaluate_wires(circuit, assignment, variant=variant)
    return [wires[index] for index in circuit.outputs]


def output_word(outputs: list[int]) -> int:
    return sum((bit & 1) << index for index, bit in enumerate(outputs))


def write_circuit(circuit: Circuit, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(encode_wmc(circuit), encoding="utf-8")


def compile_file(source: Path, output: Path) -> Circuit:
    with source.open("r", encoding="utf-8") as handle:
        spec = json.load(handle)
    circuit = compile_spec(spec)
    write_circuit(circuit, output)
    return circuit


def create_corpus(output_dir: Path, seed: int, count: int,
                  max_inputs: int, max_gates: int) -> list[dict[str, Any]]:
    if not 1 <= max_inputs <= min(8, VM_MAX_INPUTS):
        raise CircuitError("corpus max_inputs must be in 1..8")
    if not 1 <= max_gates <= min(32, VM_MAX_GATES):
        raise CircuitError("corpus max_gates must be in 1..32")
    if count < 1:
        raise CircuitError("corpus count must be positive")
    rng = random.Random(seed)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest: list[dict[str, Any]] = []
    for index in range(count):
        input_count = rng.randint(1, max_inputs)
        gate_count = rng.randint(1, max_gates)
        inputs = [f"i{i}" for i in range(input_count)]
        available = ["0", "1", *inputs]
        gates: list[dict[str, Any]] = []
        for gate_index in range(gate_count):
            gate_id = f"g{gate_index}"
            gates.append({
                "id": gate_id,
                "op": "nand",
                "args": [rng.choice(available), rng.choice(available)],
            })
            available.append(gate_id)
        output_count = 1 if gate_count == 1 else rng.randint(1, 2)
        outputs = [rng.choice(available) for _ in range(output_count)]
        spec = {
            "name": f"rand_{index:03d}",
            "inputs": inputs,
            "gates": gates,
            "outputs": outputs,
        }
        source = output_dir / f"rand_{index:03d}.json"
        target = output_dir / f"rand_{index:03d}.wmc"
        source.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")
        circuit = compile_file(source, target)
        encoded = target.read_bytes()
        manifest.append({
            "name": circuit.name,
            "source": source.name,
            "descriptor": target.name,
            "input_count": circuit.input_count,
            "gate_count": circuit.gate_count,
            "output_count": len(circuit.outputs),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        })
    (output_dir / "manifest.json").write_text(
        json.dumps({"seed": seed, "count": count, "circuits": manifest},
                   indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def create_deep_chain(source_path: Path, descriptor_path: Path,
                      gate_count: int) -> Circuit:
    """Create the declared-boundary deep chain without hand-written artifacts."""
    if not 1 <= gate_count <= VM_MAX_GATES:
        raise CircuitError("deep-chain gate count outside WMC1 bound")
    gates: list[dict[str, Any]] = []
    previous = "a"
    for index in range(gate_count):
        gate_id = f"g{index}"
        gates.append({"id": gate_id, "op": "nand", "args": [previous, previous]})
        previous = gate_id
    spec = {
        "name": f"deep_{gate_count}",
        "inputs": ["a"],
        "gates": gates,
        "outputs": [previous],
    }
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    return compile_file(source_path, descriptor_path)


def _cmd_compile(args: argparse.Namespace) -> int:
    circuit = compile_file(Path(args.source), Path(args.output))
    print(json.dumps({
        "name": circuit.name,
        "input_count": circuit.input_count,
        "gate_count": circuit.gate_count,
        "wire_count": circuit.wire_count,
        "output_count": len(circuit.outputs),
        "output": str(args.output),
    }, sort_keys=True))
    return 0


def _cmd_oracle(args: argparse.Namespace) -> int:
    circuit = decode_wmc(Path(args.descriptor).read_text(encoding="utf-8"))
    if circuit.input_count > 12 and not args.sample:
        raise CircuitError("use --sample for a circuit with more than 12 inputs")
    if args.sample:
        rng = random.Random(args.seed)
        assignments = [rng.getrandbits(circuit.input_count) for _ in range(args.sample)]
        kind = "fixed_seed_random"
    else:
        assignments = range(1 << circuit.input_count)
        kind = "exhaustive"
    for ordinal, assignment in enumerate(assignments):
        outputs = evaluate(circuit, assignment, variant=args.variant)
        print(json.dumps({
            "record": "oracle",
            "circuit": circuit.name,
            "kind": kind,
            "ordinal": ordinal,
            "assignment": assignment,
            "variant": args.variant,
            "outputs": outputs,
            "output_word": output_word(outputs),
        }, sort_keys=True))
    return 0


def _cmd_corpus(args: argparse.Namespace) -> int:
    manifest = create_corpus(Path(args.output_dir), args.seed, args.count,
                             args.max_inputs, args.max_gates)
    print(json.dumps({"count": len(manifest), "output_dir": args.output_dir,
                      "seed": args.seed}, sort_keys=True))
    return 0


def _cmd_deep(args: argparse.Namespace) -> int:
    circuit = create_deep_chain(Path(args.source), Path(args.output), args.gates)
    print(json.dumps({"gate_count": circuit.gate_count,
                      "name": circuit.name,
                      "output": args.output,
                      "source": args.source,
                      "wire_count": circuit.wire_count}, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    compile_parser = subcommands.add_parser("compile")
    compile_parser.add_argument("source")
    compile_parser.add_argument("output")
    compile_parser.set_defaults(func=_cmd_compile)
    oracle_parser = subcommands.add_parser("oracle")
    oracle_parser.add_argument("descriptor")
    oracle_parser.add_argument("--variant", choices=["logical", "cap64", "sentinel"],
                               default="logical")
    oracle_parser.add_argument("--sample", type=int, default=0)
    oracle_parser.add_argument("--seed", type=int, default=0xC0DEC0DE)
    oracle_parser.set_defaults(func=_cmd_oracle)
    corpus_parser = subcommands.add_parser("corpus")
    corpus_parser.add_argument("output_dir")
    corpus_parser.add_argument("--seed", type=int, default=0xC0DEC0DE)
    corpus_parser.add_argument("--count", type=int, default=100)
    corpus_parser.add_argument("--max-inputs", type=int, default=6)
    corpus_parser.add_argument("--max-gates", type=int, default=24)
    corpus_parser.set_defaults(func=_cmd_corpus)
    deep_parser = subcommands.add_parser("deep")
    deep_parser.add_argument("source")
    deep_parser.add_argument("output")
    deep_parser.add_argument("--gates", type=int, default=VM_MAX_GATES)
    deep_parser.set_defaults(func=_cmd_deep)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (CircuitError, json.JSONDecodeError, OSError) as exc:
        print(f"circuit_tool: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
