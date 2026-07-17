"""Emit a compact CFG summary from the kernel-linked xlated dump."""

from __future__ import annotations

import re
from collections.abc import Iterable

from .schema import Instruction


_GOTO_RE = re.compile(r"goto pc([+-]\d+)")
_PC_CALL_RE = re.compile(r"\bcall\s+pc(?P<offset>[+-]\d+)")


def _successors(instruction: Instruction, by_pc: dict[int, Instruction]) -> list[tuple[int, str]]:
    pcs = set(by_pc)
    if _PC_CALL_RE.search(instruction.text):
        # A BPF-to-BPF pseudo-call does not execute its lexical next
        # instruction until its callee returns.  Call/return edges below model
        # that relationship explicitly; a plain fallthrough here would create
        # a false path that skips the callee.
        return []
    goto = _GOTO_RE.search(instruction.text)
    if goto:
        values = [instruction.next_pc + int(goto.group(1))]
        if not instruction.text.lstrip().startswith("goto "):
            values.append(instruction.next_pc)
        return [
            (value, "branch")
            for value in values
            if value in pcs and by_pc[value].function == instruction.function
        ]
    if "exit" not in instruction.text and instruction.next_pc in pcs:
        if by_pc[instruction.next_pc].function == instruction.function:
            return [(instruction.next_pc, "fallthrough")]
    return []


def build_cfg(instructions: Iterable[Instruction]) -> dict[str, object]:
    values = list(instructions)
    by_pc = {instruction.pc: instruction for instruction in values}
    edges = [
        {"from": instruction.pc, "to": target, "kind": kind}
        for instruction in values
        for target, kind in _successors(instruction, by_pc)
    ]
    for instruction in values:
        call = _PC_CALL_RE.search(instruction.text)
        if not call:
            continue
        target = instruction.next_pc + int(call.group("offset"))
        callee = by_pc.get(target)
        continuation = by_pc.get(instruction.next_pc)
        if callee is None or continuation is None:
            continue
        edges.append({"from": instruction.pc, "to": target, "kind": "call"})
        for exit_instruction in values:
            if exit_instruction.function == callee.function and exit_instruction.text.strip() == "exit":
                edges.append(
                    {
                        "from": exit_instruction.pc,
                        "to": continuation.pc,
                        "kind": "return",
                        "call_site": instruction.pc,
                    }
                )
    return {
        "schema": "rac-frontier-cfg-v1",
        "interprocedural": True,
        "instructions": [instruction.to_dict() for instruction in values],
        "edges": edges,
    }
