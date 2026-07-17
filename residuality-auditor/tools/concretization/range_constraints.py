"""Range checks for concrete scalar representatives."""
from __future__ import annotations

MASK64 = (1 << 64) - 1
SIGN64 = 1 << 63


def s64(value: int) -> int:
    value &= MASK64
    return value - (1 << 64) if value & SIGN64 else value


def check_scalar_ranges(value: int, reg: dict) -> list[dict]:
    value_u = value & MASK64
    value_s = s64(value)
    value32 = value & 0xFFFFFFFF
    value32_s = value32 - (1 << 32) if value32 & (1 << 31) else value32
    checks = [
        {"field": "umin_value", "passed": int(reg.get("umin_value", 0)) <= value_u, "concrete": value_u, "bound": reg.get("umin_value")},
        {"field": "umax_value", "passed": value_u <= int(reg.get("umax_value", MASK64)), "concrete": value_u, "bound": reg.get("umax_value")},
        {"field": "smin_value", "passed": int(reg.get("smin_value", -(1 << 63))) <= value_s, "concrete": value_s, "bound": reg.get("smin_value")},
        {"field": "smax_value", "passed": value_s <= int(reg.get("smax_value", (1 << 63) - 1)), "concrete": value_s, "bound": reg.get("smax_value")},
        {"field": "u32_min_value", "passed": int(reg.get("u32_min_value", 0)) <= value32, "concrete": value32, "bound": reg.get("u32_min_value")},
        {"field": "u32_max_value", "passed": value32 <= int(reg.get("u32_max_value", 0xFFFFFFFF)), "concrete": value32, "bound": reg.get("u32_max_value")},
        {"field": "s32_min_value", "passed": int(reg.get("s32_min_value", -(1 << 31))) <= value32_s, "concrete": value32_s, "bound": reg.get("s32_min_value")},
        {"field": "s32_max_value", "passed": value32_s <= int(reg.get("s32_max_value", (1 << 31) - 1)), "concrete": value32_s, "bound": reg.get("s32_max_value")},
    ]
    return checks
