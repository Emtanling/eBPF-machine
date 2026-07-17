"""Small xlated semantics used by the path-correspondence gate."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from tools.frontier.locate_calls import locate_frontier
from tools.frontier.schema import FrontierError, Instruction

_COND_ZERO_RE = re.compile(r"if\s+r1\s+(?P<op>==|!=)\s+0x?0\s+goto\s+pc(?P<off>[+-]\d+)")
_PSEUDO_CALL_RE = re.compile(r"\bcall\s+pc[+-]\d+#(?P<name>[^\s]+)")
_GOTO_RE = re.compile(r"^goto\s+pc(?P<off>[+-]\d+)")


@dataclass(frozen=True)
class SelectorCase:
    case: str
    input_value: int
    branch_name: str
    branch_call: int
    selector_condition_pc: int
    selector_edge: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "case": self.case,
            "input_value": self.input_value,
            "branch_name": self.branch_name,
            "branch_call": self.branch_call,
            "selector_condition_pc": self.selector_condition_pc,
            "selector_edge": self.selector_edge,
        }


def _function_matches(actual: str | None, expected: str) -> bool:
    return bool(actual and (actual == expected or actual.endswith("_" + expected)))


def _within(function: str, instructions: list[Instruction]) -> list[Instruction]:
    body = [item for item in instructions if _function_matches(item.function, function)]
    if not body:
        raise FrontierError(f"xlated dump does not contain function {function}")
    return body


def _target_name(instruction: Instruction) -> str | None:
    match = _PSEUDO_CALL_RE.search(instruction.text)
    if not match:
        return None
    name = match.group("name")
    for suffix in ("select_a", "select_s", "select_branch", "shared_suffix"):
        if name == suffix or name.endswith("_" + suffix):
            return suffix
    return name


def _follow_to_branch_call(start_pc: int, selector_by_pc: dict[int, Instruction]) -> tuple[str, int]:
    seen: set[int] = set()
    pc = start_pc
    while pc not in seen:
        seen.add(pc)
        insn = selector_by_pc.get(pc)
        if insn is None:
            break
        target = _target_name(insn)
        if target in {"select_a", "select_s"}:
            return target, insn.pc
        text = insn.text.strip()
        goto = _GOTO_RE.match(text)
        if goto:
            pc = insn.pc + 1 + int(goto.group("off"))
        else:
            pc = insn.next_pc
    raise FrontierError(f"selector edge from {start_pc} does not reach a branch call")


def selector_cases(instructions: list[Instruction]) -> dict[str, SelectorCase]:
    """Return the xlated-proven mapping from runtime input to branch call."""

    frontier, _details = locate_frontier(instructions)
    selector = _within("select_branch", instructions)
    selector_by_pc = {item.pc: item for item in selector}
    conditions = []
    for item in selector:
        match = _COND_ZERO_RE.search(item.text.strip())
        if match:
            conditions.append((item, match))
    if len(conditions) != 1:
        raise FrontierError(f"expected one simple r1 zero selector condition, found {len(conditions)}")
    condition, match = conditions[0]
    taken_pc = condition.pc + 1 + int(match.group("off"))
    fallthrough_pc = condition.next_pc
    taken_name, taken_call = _follow_to_branch_call(taken_pc, selector_by_pc)
    fallthrough_name, fallthrough_call = _follow_to_branch_call(fallthrough_pc, selector_by_pc)
    expected_calls = set(frontier.branch_calls)
    if {taken_call, fallthrough_call} != expected_calls:
        raise FrontierError("selector case calls do not match located frontier branch calls")

    if match.group("op") == "==":
        zero = (taken_name, taken_call, "taken")
        one = (fallthrough_name, fallthrough_call, "fallthrough")
    else:
        zero = (fallthrough_name, fallthrough_call, "fallthrough")
        one = (taken_name, taken_call, "taken")
    return {
        "a=0": SelectorCase("a=0", 0, zero[0], zero[1], condition.pc, zero[2]),
        "a=1": SelectorCase("a=1", 1, one[0], one[1], condition.pc, one[2]),
    }


def semantics_summary(instructions: list[Instruction]) -> dict[str, Any]:
    frontier, details = locate_frontier(instructions)
    cases = selector_cases(instructions)
    return {
        "schema": "rac-xlated-path-semantics-v1",
        "frontier": frontier.to_dict(),
        "frontier_shape": details,
        "cases": {case: value.to_dict() for case, value in cases.items()},
    }
