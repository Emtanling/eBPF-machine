"""Locate the v0.3.2 frontier from a pinned, globally numbered xlated dump.

The locator intentionally recognizes a narrow, versioned shape.  It does not
infer a source-level order from global instruction numbers: BPF-to-BPF callee
bodies may appear before the caller in an xlated dump.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Iterable

from .schema import Frontier, FrontierError, Instruction


_PC_CALL_RE = re.compile(r"\bcall\s+pc(?P<offset>[+-]\d+)(?:#(?P<name>[^\s]+))?")


def _function_matches(actual: str | None, expected: str) -> bool:
    if actual is None:
        return False
    return actual == expected or actual.endswith("_" + expected)


def _target_name(instruction: Instruction) -> str | None:
    match = _PC_CALL_RE.search(instruction.text)
    return match.group("name") if match and match.group("name") else None


def _is_call_to(instruction: Instruction, expected: str) -> bool:
    target = _target_name(instruction)
    return bool(target and (target == expected or target.endswith("_" + expected)))


def _is_state_sensitive_helper(instruction: Instruction) -> bool:
    """Treat a non-pseudo BPF helper call as the suffix's first state boundary."""

    text = instruction.text.strip()
    return text.startswith("call ") and _PC_CALL_RE.search(text) is None


def _one(values: Iterable[Instruction], description: str) -> Instruction:
    results = list(values)
    if len(results) != 1:
        raise FrontierError(f"expected one {description}, found {len(results)}")
    return results[0]


def _pseudo_call_target(instruction: Instruction) -> int:
    match = _PC_CALL_RE.search(instruction.text)
    if not match:
        raise FrontierError(f"instruction {instruction.pc} is not a pseudo-call")
    return instruction.next_pc + int(match.group("offset"))


def _within(function: str, instructions: list[Instruction]) -> list[Instruction]:
    values = [item for item in instructions if _function_matches(item.function, function)]
    if not values:
        raise FrontierError(f"xlated dump does not contain function {function}")
    return values


def _function_entry(function: str, instructions: list[Instruction]) -> Instruction:
    return min(_within(function, instructions), key=lambda item: item.pc)


def _calls_to(
    caller: list[Instruction], expected: str, instructions: list[Instruction]
) -> list[Instruction]:
    """Resolve calls by their target PC, not an informational symbol suffix."""

    entry = _function_entry(expected, instructions)
    calls: list[Instruction] = []
    for instruction in caller:
        if _PC_CALL_RE.search(instruction.text) is None:
            continue
        if _pseudo_call_target(instruction) != entry.pc:
            continue
        label = _target_name(instruction)
        if label is not None and not (label == expected or label.endswith("_" + expected)):
            raise FrontierError(
                f"pseudo-call {instruction.pc} resolves to {expected} but is labelled {label}"
            )
        calls.append(instruction)
    return calls


def _function_at_pc(pc: int, instructions: list[Instruction]) -> str | None:
    for instruction in instructions:
        if instruction.pc == pc:
            return instruction.function
    return None


def _normalizer_is_plain(function: str, instructions: list[Instruction]) -> None:
    body = _within(function, instructions)
    for instruction in body:
        text = instruction.text.strip()
        if text == "exit":
            continue
        if "goto pc" in text:
            raise FrontierError(f"normalizer {function} must not branch at {instruction.pc}")
        if text.startswith("call "):
            raise FrontierError(f"normalizer {function} must not call helpers or subprograms at {instruction.pc}")


def _verify_common_normalization(
    root: list[Instruction],
    dispatch: Instruction,
    suffix_call: Instruction,
    instructions: list[Instruction],
) -> list[dict[str, object]]:
    """Allow a strict common block between selector return and shared suffix.

    v0.3.3 witness shaping may insert a common noinline register-normalizer
    after `select_branch` returns.  Accept only a single fallthrough root path
    containing plain instructions or plain pseudo-calls with no helpers, no
    branches, and no branch-specific callees.
    """

    if suffix_call.pc == dispatch.next_pc:
        return []
    if suffix_call.pc < dispatch.next_pc:
        raise FrontierError(
            "shared suffix call must follow selector return: "
            f"expected at or after {dispatch.next_pc}, found {suffix_call.pc}"
        )
    root_by_pc = {instruction.pc: instruction for instruction in root}
    all_by_pc = {instruction.pc: instruction for instruction in instructions}
    pc = dispatch.next_pc
    seen: set[int] = set()
    segment: list[dict[str, object]] = []
    while pc != suffix_call.pc:
        if pc in seen:
            raise FrontierError("common normalization segment loops")
        seen.add(pc)
        instruction = root_by_pc.get(pc)
        if instruction is None:
            raise FrontierError(
                "selector return must flow through rac_single common normalization "
                f"before shared suffix; missing root instruction {pc}"
            )
        text = instruction.text.strip()
        if text == "exit" or "goto pc" in text:
            raise FrontierError(f"common normalization segment must be linear at {pc}")
        target_function = None
        if text.startswith("call "):
            if _PC_CALL_RE.search(text) is None:
                raise FrontierError(f"common normalization must not call helper at {pc}")
            target_pc = _pseudo_call_target(instruction)
            target_function = _function_at_pc(target_pc, instructions)
            if target_function is None:
                raise FrontierError(f"common normalization call {pc} has no target function")
            if any(
                _function_matches(target_function, forbidden)
                for forbidden in ("select_branch", "select_a", "select_s", "shared_suffix")
            ):
                raise FrontierError(
                    f"common normalization call {pc} targets non-normalizer {target_function}"
                )
            _normalizer_is_plain(target_function, instructions)
            if target_pc not in all_by_pc:
                raise FrontierError(f"common normalization call {pc} target {target_pc} is absent")
        segment.append({"pc": instruction.pc, "text": instruction.text, "target_function": target_function})
        next_pc = instruction.next_pc
        if next_pc <= instruction.pc:
            raise FrontierError(f"common normalization segment does not advance at {pc}")
        pc = next_pc
    return segment


def _selector_successors(selector: list[Instruction]) -> dict[int, set[int]]:
    pcs = {item.pc for item in selector}
    successors: dict[int, set[int]] = {}
    for item in selector:
        next_pc = item.next_pc
        text = item.text.strip()
        if text == "exit":
            successors[item.pc] = set()
            continue
        jump = re.search(r"\bgoto pc([+-]\d+)", text)
        targets: set[int] = set()
        if jump:
            targets.add(item.pc + 1 + int(jump.group(1)))
            if not text.startswith("goto "):
                targets.add(next_pc)
        else:
            targets.add(next_pc)
        successors[item.pc] = {target for target in targets if target in pcs}
    return successors


def _reachable(start: int, successors: dict[int, set[int]]) -> set[int]:
    reached: set[int] = set()
    queue: deque[int] = deque([start])
    while queue:
        pc = queue.popleft()
        if pc in reached:
            continue
        reached.add(pc)
        queue.extend(successors.get(pc, set()) - reached)
    return reached


def _branch_return_is_unambiguous(
    selector: list[Instruction], branch_calls: tuple[Instruction, Instruction]
) -> int:
    """Require both branch calls to flow to exactly one selector return.

    This is deliberately small and intraprocedural: a BPF-to-BPF call normally
    returns at its next instruction, so a selector's common exit establishes
    that the caller's following instruction is the shared continuation.
    """

    exits = {item.pc for item in selector if item.text.strip() == "exit"}
    if len(exits) != 1:
        raise FrontierError(f"selector must have one return exit, found {len(exits)}")
    exit_pc = next(iter(exits))
    successors = _selector_successors(selector)
    for call in branch_calls:
        start = call.next_pc
        if start not in successors:
            raise FrontierError(f"branch call {call.pc} has no in-function return edge")
        reached = _reachable(start, successors)
        if exit_pc not in reached:
            raise FrontierError(f"branch call {call.pc} cannot reach selector return {exit_pc}")
        other_exits = exits & reached
        if other_exits != {exit_pc}:
            raise FrontierError(f"branch call {call.pc} reaches ambiguous selector exits")
    return exit_pc


def _branch_calls_are_exclusive(
    selector: list[Instruction], branch_a: Instruction, branch_s: Instruction
) -> int:
    """Prove the two branch calls are separated by a selector conditional."""

    successors = _selector_successors(selector)
    a_reaches_s = branch_s.pc in _reachable(branch_a.pc, successors)
    s_reaches_a = branch_a.pc in _reachable(branch_s.pc, successors)
    if a_reaches_s or s_reaches_a:
        raise FrontierError("branch-specific calls are sequentially reachable")
    for instruction in selector:
        text = instruction.text.strip()
        if "goto pc" not in text or text.startswith("goto "):
            continue
        branches = successors[instruction.pc]
        if len(branches) != 2:
            continue
        first, second = (_reachable(pc, successors) for pc in branches)
        first_a, first_s = branch_a.pc in first, branch_s.pc in first
        second_a, second_s = branch_a.pc in second, branch_s.pc in second
        if (first_a and not first_s and second_s and not second_a) or (
            first_s and not first_a and second_a and not second_s
        ):
            return instruction.pc
    raise FrontierError("no selector conditional separates the branch-specific calls")


def locate_frontier(instructions: list[Instruction]) -> tuple[Frontier, dict[str, object]]:
    """Return the narrow canonical pre-suffix frontier or raise FrontierError.

    The accepted execution point is the *pre-call state* of rac_single's unique
    `call shared_suffix`.  This canonical subset proves a common continuation
    without requiring a verifier call stack in the trace event.
    """

    root = _within("rac_single", instructions)
    selector = _within("select_branch", instructions)
    suffix = _within("shared_suffix", instructions)

    dispatch = _one(
        _calls_to(root, "select_branch", instructions),
        "rac_single -> select_branch pseudo-call",
    )
    suffix_call = _one(
        _calls_to(root, "shared_suffix", instructions),
        "rac_single -> shared_suffix pseudo-call",
    )
    common_normalization = _verify_common_normalization(root, dispatch, suffix_call, instructions)
    branch_a = _one(
        _calls_to(selector, "select_a", instructions),
        "select_branch -> select_a pseudo-call",
    )
    branch_s = _one(
        _calls_to(selector, "select_s", instructions),
        "select_branch -> select_s pseudo-call",
    )
    selector_exit = _branch_return_is_unambiguous(selector, (branch_a, branch_s))
    selector_fork = _branch_calls_are_exclusive(selector, branch_a, branch_s)

    suffix_entry = _pseudo_call_target(suffix_call)
    if suffix_entry != _function_entry("shared_suffix", instructions).pc:
        raise FrontierError(
            f"shared suffix pseudo-call {suffix_call.pc} resolves to {suffix_entry}, "
            "which is not the shared_suffix entry"
        )
    sensitive_helpers = [item for item in suffix if _is_state_sensitive_helper(item)]
    if not sensitive_helpers:
        raise FrontierError("shared_suffix has no state-sensitive helper")
    first_sensitive = min(sensitive_helpers, key=lambda item: item.pc)

    frontier = Frontier(
        branch_dispatch_call=dispatch.pc,
        join_insn=suffix_call.pc,
        suffix_entry_insn=suffix_entry,
        first_sensitive_insn=first_sensitive.pc,
        branch_calls=(branch_a.pc, branch_s.pc),
    )
    details: dict[str, object] = {
        "schema": "rac-frontier-shape-v1",
        "rac_single": {
            "select_branch_call": dispatch.pc,
            "shared_suffix_call": suffix_call.pc,
            "common_continuation": suffix_call.pc,
            "common_normalization": common_normalization,
            "post_shared_suffix_return": suffix_call.next_pc,
        },
        "select_branch": {
            "select_a_call": branch_a.pc,
            "select_a_return": branch_a.next_pc,
            "select_s_call": branch_s.pc,
            "select_s_return": branch_s.next_pc,
            "branch_selector_fork": selector_fork,
            "common_return_exit": selector_exit,
        },
        "shared_suffix": {
            "entry": suffix_entry,
            "first_state_sensitive_helper": first_sensitive.pc,
        },
        "canonical_eligible_execution_segment": {
            "start": f"pre({suffix_call.pc})",
            "end": f"pre({suffix_call.pc})",
            "reason": "v1 accepts the caller-side pre-call state after an optional strict common normalizer; callee PCs require a recorded call stack",
        },
    }
    return frontier, details
