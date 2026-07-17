"""Tiny tnum helpers for verifier scalar concretization."""
MASK64 = (1 << 64) - 1


def u64(value: int) -> int:
    return int(value) & MASK64


def satisfies(value: int, tnum: dict) -> bool:
    known = u64(tnum.get("value", 0))
    mask = u64(tnum.get("mask", 0))
    return (u64(value) & ~mask & MASK64) == (known & ~mask & MASK64)


def choose(tnum: dict) -> int:
    # The known value is always a valid representative of value + unknown mask.
    return u64(tnum.get("value", 0))
