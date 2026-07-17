"""Common suffix validation for path correspondence."""
from __future__ import annotations

from typing import Any

from tools.frontier.locate_calls import locate_frontier
from tools.frontier.schema import Instruction


def _function_matches(actual: str | None, expected: str) -> bool:
    return bool(actual and (actual == expected or actual.endswith("_" + expected)))


def common_suffix(instructions: list[Instruction], frontier_event: dict[str, Any]) -> dict[str, Any]:
    frontier, details = locate_frontier(instructions)
    if frontier_event.get("same_remaining_xlated_suffix") is not True:
        raise ValueError("frontier event did not prove same_remaining_xlated_suffix")
    join = frontier.join_insn
    suffix = [item for item in instructions if _function_matches(item.function, "shared_suffix")]
    if not suffix:
        raise ValueError("shared_suffix function missing from xlated dump")
    suffix_entry = min(suffix, key=lambda item: item.pc).pc
    first_sensitive = frontier.first_sensitive_insn
    prefix = [item for item in suffix if suffix_entry <= item.pc <= first_sensitive]
    return {
        "schema": "rac-common-suffix-v1",
        "join_insn": join,
        "suffix_entry_insn": suffix_entry,
        "first_sensitive_insn": first_sensitive,
        "same_remaining_xlated_suffix": True,
        "frontier_segment": details.get("canonical_eligible_execution_segment"),
        "suffix_prefix_until_first_sensitive": [item.to_dict() for item in prefix],
    }
