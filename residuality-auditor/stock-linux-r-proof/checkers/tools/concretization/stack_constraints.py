"""Stack-slot local concretization constraints."""
from __future__ import annotations

from typing import Any

from .reg_constraints import check_reg, concrete_for_reg
from .schema import STACK_INVALID, STACK_MISC, STACK_SPILL, STACK_ZERO

SUPPORTED_STACK_TYPES = {STACK_INVALID, STACK_SPILL, STACK_MISC, STACK_ZERO}


def concrete_for_stack_slot(slot: dict[str, Any]) -> dict[str, Any]:
    if not slot.get("initialized"):
        return {"slot": slot.get("slot"), "kind": "uninitialized"}
    value = {"slot": slot.get("slot"), "kind": "initialized", "slot_type": slot.get("slot_type")}
    if STACK_SPILL in set(slot.get("slot_type") or []):
        value["spilled_ptr"] = concrete_for_reg(-1, slot.get("spilled_ptr") or {})
    return value


def check_stack_slot(concrete: dict[str, Any], slot: dict[str, Any]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    reasons: list[str] = []
    slot_types = slot.get("slot_type") or []
    unsupported = sorted({int(t) for t in slot_types if int(t) not in SUPPORTED_STACK_TYPES})
    if unsupported:
        reasons.append(f"unsupported stack slot types {unsupported}")
    checks.append({"field": "initialized", "passed": bool(concrete.get("kind") != "uninitialized") == bool(slot.get("initialized"))})
    checks.append({"field": "slot_type", "passed": concrete.get("slot_type", slot_types) == slot_types, "abstract": slot_types})
    spilled = None
    if STACK_SPILL in set(slot_types):
        spilled = check_reg(-1, concrete.get("spilled_ptr") or {}, slot.get("spilled_ptr") or {})
        checks.append({"field": "spilled_ptr", "passed": spilled["passed"], "detail": spilled})
    passed = not reasons and all(item.get("passed") for item in checks)
    return {"slot": slot.get("slot"), "passed": passed, "checks": checks, "reasons": reasons}
