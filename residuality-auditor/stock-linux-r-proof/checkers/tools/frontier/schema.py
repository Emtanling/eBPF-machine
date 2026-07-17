"""Stable schema helpers for the v0.3.2 frontier gate."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Instruction:
    pc: int
    text: str
    function: str | None
    line_number: int
    slots: int = 1

    @property
    def next_pc(self) -> int:
        """First instruction slot after this BPF instruction."""

        return self.pc + self.slots

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Frontier:
    branch_dispatch_call: int
    join_insn: int
    suffix_entry_insn: int
    first_sensitive_insn: int
    branch_calls: tuple[int, int]

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["branch_calls"] = list(self.branch_calls)
        return value


class FrontierError(ValueError):
    """Raised when raw evidence is incomplete or structurally ambiguous."""
