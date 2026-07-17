"""Register-level local concretization constraints."""
from __future__ import annotations

from typing import Any

from .range_constraints import check_scalar_ranges
from .schema import CONST_PTR_TO_MAP, NOT_INIT, PTR_TO_CTX, PTR_TO_STACK, REG_TYPE_NAMES, SCALAR_VALUE, SUPPORTED_REG_TYPES
from .tnum import choose as choose_tnum
from .tnum import satisfies as tnum_satisfies


def concrete_for_reg(index: int, reg: dict[str, Any]) -> dict[str, Any]:
    typ = int(reg.get("type"))
    if typ == NOT_INIT:
        return {"reg": index, "kind": "uninitialized"}
    if typ == SCALAR_VALUE:
        value = choose_tnum(reg.get("var_off") or {})
        return {"reg": index, "kind": "scalar", "value": value}
    if typ == PTR_TO_STACK:
        return {"reg": index, "kind": "ptr_to_stack", "frame": reg.get("frameno", 0), "offset": reg.get("off", 0)}
    if typ == PTR_TO_CTX:
        return {"reg": index, "kind": "ptr_to_ctx", "offset": reg.get("off", 0)}
    if typ == CONST_PTR_TO_MAP:
        return {"reg": index, "kind": "const_ptr_to_map", "id": reg.get("id", 0), "offset": reg.get("off", 0)}
    return {"reg": index, "kind": "unsupported", "type": typ}


def check_reg(index: int, concrete: dict[str, Any], reg: dict[str, Any]) -> dict[str, Any]:
    typ = int(reg.get("type"))
    checks: list[dict[str, Any]] = []
    reasons: list[str] = []
    if typ not in SUPPORTED_REG_TYPES:
        reasons.append(f"unsupported reg type {typ}")
    expected_name = REG_TYPE_NAMES.get(typ, str(typ))
    checks.append({"field": "type", "passed": not reasons, "abstract": expected_name, "concrete_kind": concrete.get("kind")})
    if typ == NOT_INIT:
        checks.append({"field": "uninitialized", "passed": concrete.get("kind") == "uninitialized"})
    elif typ == SCALAR_VALUE:
        value = int(concrete.get("value", 0))
        tnum = reg.get("var_off") or {}
        checks.append({"field": "var_off", "passed": tnum_satisfies(value, tnum), "concrete": value, "tnum": tnum})
        checks.extend(check_scalar_ranges(value, reg))
    elif typ == PTR_TO_STACK:
        checks.append({"field": "ptr_kind", "passed": concrete.get("kind") == "ptr_to_stack"})
        checks.append({"field": "offset", "passed": concrete.get("offset") == reg.get("off"), "concrete": concrete.get("offset"), "abstract": reg.get("off")})
        checks.append({"field": "var_off", "passed": tnum_satisfies(0, reg.get("var_off") or {}), "tnum": reg.get("var_off")})
    elif typ == PTR_TO_CTX:
        checks.append({"field": "ptr_kind", "passed": concrete.get("kind") == "ptr_to_ctx"})
        checks.append({"field": "offset", "passed": concrete.get("offset") == reg.get("off")})
    elif typ == CONST_PTR_TO_MAP:
        checks.append({"field": "ptr_kind", "passed": concrete.get("kind") == "const_ptr_to_map"})
    passed = not reasons and all(item.get("passed") for item in checks)
    return {"reg": index, "type": expected_name, "passed": passed, "checks": checks, "reasons": reasons}
