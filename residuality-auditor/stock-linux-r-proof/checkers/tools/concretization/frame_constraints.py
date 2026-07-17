"""Frame-level local concretization constraints."""
from __future__ import annotations

from typing import Any

from .reg_constraints import check_reg, concrete_for_reg
from .stack_constraints import check_stack_slot, concrete_for_stack_slot


def concrete_for_frame(frame: dict[str, Any]) -> dict[str, Any]:
    regs = frame.get("regs") or []
    slots = frame.get("stack_slots") or []
    return {
        "frameno": frame.get("frameno"),
        "allocated_stack": frame.get("allocated_stack"),
        "registers": [concrete_for_reg(i, reg) for i, reg in enumerate(regs)],
        "stack_slots": [concrete_for_stack_slot(slot) for slot in slots],
    }


def check_frame(concrete: dict[str, Any], frame: dict[str, Any]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    reasons: list[str] = []
    if not frame.get("present"):
        reasons.append("frame is not present")
    checks.append({"field": "frameno", "passed": concrete.get("frameno") == frame.get("frameno")})
    checks.append({"field": "allocated_stack", "passed": concrete.get("allocated_stack") == frame.get("allocated_stack")})
    regs = frame.get("regs") or []
    concrete_regs = concrete.get("registers") or []
    if len(regs) != len(concrete_regs):
        reasons.append("register count mismatch")
    reg_checks = [check_reg(i, concrete_regs[i], regs[i]) for i in range(min(len(regs), len(concrete_regs)))]
    slot_checks = []
    abstract_slots = frame.get("stack_slots") or []
    concrete_slots = concrete.get("stack_slots") or []
    if len(abstract_slots) != len(concrete_slots):
        reasons.append("stack slot count mismatch")
    for i in range(min(len(abstract_slots), len(concrete_slots))):
        slot_checks.append(check_stack_slot(concrete_slots[i], abstract_slots[i]))
    passed = not reasons and all(item["passed"] for item in reg_checks) and all(item["passed"] for item in slot_checks) and all(item.get("passed") for item in checks)
    return {"passed": passed, "checks": checks, "registers": reg_checks, "stack_slots": slot_checks, "reasons": reasons}
