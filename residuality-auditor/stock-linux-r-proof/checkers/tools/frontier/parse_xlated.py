"""Parse bpftool's global xlated instruction dump without source-level guesses."""

from __future__ import annotations

import re
from pathlib import Path

from .schema import FrontierError, Instruction


_FUNCTION_RE = re.compile(
    r"^\s*(?:static\s+)?(?:[A-Za-z_][\w\s*]+\s+)?(?P<name>[A-Za-z_]\w*)(?:\([^;]*\))?:\s*$"
)
_INSN_RE = re.compile(
    r"^\s*(?P<pc>\d+):\s+\((?P<opcode>[0-9a-fA-F]+)\)\s+(?P<text>.*\S)\s*$"
)


def parse_xlated_text(text: str) -> list[Instruction]:
    """Return globally numbered instructions and their enclosing BPF function."""

    instructions: list[Instruction] = []
    current_function: str | None = None
    seen: set[int] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        function = _FUNCTION_RE.match(line)
        if function:
            current_function = function.group("name")
            continue
        instruction = _INSN_RE.match(line)
        if not instruction:
            continue
        pc = int(instruction.group("pc"))
        if pc in seen:
            raise FrontierError(f"duplicate global xlated instruction {pc}")
        seen.add(pc)
        # BPF_LD | BPF_DW | BPF_IMM (opcode 0x18) consumes a second, implicit
        # instruction slot. bpftool prints only its first slot, so preserve the
        # width instead of treating the following global PC as pc + 1.
        slots = 2 if int(instruction.group("opcode"), 16) == 0x18 else 1
        instructions.append(
            Instruction(
                pc=pc,
                text=instruction.group("text"),
                function=current_function,
                line_number=line_number,
                slots=slots,
            )
        )
    if not instructions:
        raise FrontierError("xlated dump contains no parseable global instructions")
    return sorted(instructions, key=lambda item: item.pc)


def parse_xlated_file(path: Path) -> list[Instruction]:
    return parse_xlated_text(path.read_text(encoding="utf-8"))
