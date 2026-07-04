#!/usr/bin/env python3
import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path


NORMAL_TRUTH = {(0, 0): 1, (0, 1): 1, (1, 0): 1, (1, 1): 0}
ALL1_TRUTH = {(0, 0): 1, (0, 1): 1, (1, 0): 1, (1, 1): 1}
FIXED_ADDER_CASES = {
    (0, 0),
    (1, 1),
    (0xFFFFFFFF, 1),
    (0x55555555, 0xAAAAAAAA),
    (0xFFFFFFFF, 0xFFFFFFFF),
}


class Audit:
    def __init__(self) -> None:
        self.failures: list[str] = []

    def fail(self, message: str) -> None:
        self.failures.append(message)

    def require(self, condition: bool, message: str) -> None:
        if not condition:
            self.fail(message)


def load_jsonl(path: Path, audit: Audit) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        audit.fail(f"{path.name}: missing")
        return rows

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                audit.fail(f"{path.name}:{line_no}: invalid JSON: {exc}")

    if not rows:
        audit.fail(f"{path.name}: no rows")
    return rows


def common_row_checks(name: str, rows: list[dict], audit: Audit) -> None:
    for idx, row in enumerate(rows, 1):
        audit.require(row.get("passed") is True, f"{name}:{idx}: passed is not true")
        audit.require(row.get("err") == 0, f"{name}:{idx}: err is {row.get('err')}")


def check_nand(name: str, rows: list[dict], truth: dict[tuple[int, int], int],
               audit: Audit, full_suite: bool) -> None:
    common_row_checks(name, rows, audit)
    counts: Counter[tuple[int, int]] = Counter()

    for idx, row in enumerate(rows, 1):
        key = (row.get("a"), row.get("b"))
        if key not in truth:
            audit.fail(f"{name}:{idx}: unexpected input pair {key}")
            continue
        expected = truth[key]
        audit.require(row.get("expected") == expected,
                      f"{name}:{idx}: expected field {row.get('expected')} != {expected}")
        audit.require(row.get("actual") == expected,
                      f"{name}:{idx}: actual field {row.get('actual')} != {expected}")
        counts[key] += 1

    audit.require(set(counts) == set(truth),
                  f"{name}: input coverage {sorted(counts)} != {sorted(truth)}")
    if counts:
        unique_counts = set(counts.values())
        audit.require(len(unique_counts) == 1,
                      f"{name}: per-input repeat counts not uniform: {dict(counts)}")
        if full_suite:
            audit.require(unique_counts == {100},
                          f"{name}: full suite expected 100 repeats per input, got {dict(counts)}")
            audit.require(len(rows) == 400, f"{name}: full suite expected 400 rows, got {len(rows)}")


def check_full_adder(rows: list[dict], audit: Audit, full_suite: bool) -> None:
    common_row_checks("full_adder", rows, audit)
    seen: set[tuple[int, int, int]] = set()

    for idx, row in enumerate(rows, 1):
        key = (row.get("a"), row.get("b"), row.get("cin"))
        if any(bit not in (0, 1) for bit in key):
            audit.fail(f"full_adder:{idx}: unexpected input triple {key}")
            continue
        total = key[0] + key[1] + key[2]
        expected_sum = total & 1
        expected_cout = (total >> 1) & 1
        audit.require(row.get("expected_sum") == expected_sum,
                      f"full_adder:{idx}: expected_sum mismatch")
        audit.require(row.get("expected_cout") == expected_cout,
                      f"full_adder:{idx}: expected_cout mismatch")
        audit.require(row.get("actual_sum") == expected_sum,
                      f"full_adder:{idx}: actual_sum mismatch")
        audit.require(row.get("actual_cout") == expected_cout,
                      f"full_adder:{idx}: actual_cout mismatch")
        seen.add(key)

    expected_seen = {(a, b, c) for a in (0, 1) for b in (0, 1) for c in (0, 1)}
    audit.require(seen == expected_seen,
                  f"full_adder: input coverage {sorted(seen)} != {sorted(expected_seen)}")
    if full_suite:
        audit.require(len(rows) == 8, f"full_adder: full suite expected 8 rows, got {len(rows)}")


def check_adder32(rows: list[dict], audit: Audit, full_suite: bool) -> None:
    common_row_checks("adder32", rows, audit)
    fixed_seen: set[tuple[int, int]] = set()
    kinds = Counter()

    for idx, row in enumerate(rows, 1):
        x = row.get("x")
        y = row.get("y")
        if not isinstance(x, int) or not isinstance(y, int):
            audit.fail(f"adder32:{idx}: non-integer operands")
            continue
        wide = (x & 0xFFFFFFFF) + (y & 0xFFFFFFFF)
        expected = wide & 0xFFFFFFFF
        carry = wide >> 32
        audit.require(row.get("expected") == expected,
                      f"adder32:{idx}: expected {row.get('expected')} != {expected}")
        audit.require(row.get("actual") == expected,
                      f"adder32:{idx}: actual {row.get('actual')} != {expected}")
        audit.require(row.get("expected_carry") == carry,
                      f"adder32:{idx}: expected_carry {row.get('expected_carry')} != {carry}")
        audit.require(row.get("carry_out") == carry,
                      f"adder32:{idx}: carry_out {row.get('carry_out')} != {carry}")
        kind = row.get("kind")
        kinds[kind] += 1
        if kind == "fixed":
            fixed_seen.add((x, y))

    if full_suite:
        audit.require(len(rows) == 1005, f"adder32: full suite expected 1005 rows, got {len(rows)}")
        audit.require(kinds["fixed"] == 5, f"adder32: expected 5 fixed rows, got {kinds['fixed']}")
        audit.require(kinds["random"] == 1000,
                      f"adder32: expected 1000 random rows, got {kinds['random']}")
        audit.require(fixed_seen == FIXED_ADDER_CASES,
                      f"adder32: fixed cases {sorted(fixed_seen)} != {sorted(FIXED_ADDER_CASES)}")


def check_adder_exhaustive(rows: list[dict], audit: Audit) -> None:
    common_row_checks("adder_exhaustive", rows, audit)
    seen: set[tuple[int, int]] = set()

    for idx, row in enumerate(rows, 1):
        x = row.get("x")
        y = row.get("y")
        if not isinstance(x, int) or not isinstance(y, int):
            audit.fail(f"adder_exhaustive:{idx}: non-integer operands")
            continue
        wide = (x & 0xFFFFFFFF) + (y & 0xFFFFFFFF)
        audit.require(row.get("kind") == "exhaustive",
                      f"adder_exhaustive:{idx}: kind != exhaustive")
        audit.require(row.get("actual") == (wide & 0xFFFFFFFF),
                      f"adder_exhaustive:{idx}: actual mismatch")
        audit.require(row.get("carry_out") == (wide >> 32),
                      f"adder_exhaustive:{idx}: carry mismatch")
        seen.add((x, y))

    n = len(rows)
    side = math.isqrt(n)
    audit.require(side * side == n,
                  f"adder_exhaustive: row count {n} is not a perfect square")
    if side * side == n and side > 0:
        audit.require((side & (side - 1)) == 0,
                      f"adder_exhaustive: side {side} is not a power of two")
        expected_pairs = {(a, b) for a in range(side) for b in range(side)}
        audit.require(seen == expected_pairs,
                      "adder_exhaustive: input coverage incomplete")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("results_dir", type=Path)
    parser.add_argument("--full-suite", action="store_true")
    args = parser.parse_args()

    audit = Audit()
    specs = {
        "nand_truth_table.jsonl": ("nand", NORMAL_TRUTH),
        "baseline_nand.jsonl": ("baseline_nand", NORMAL_TRUTH),
        "ablation_cap64.jsonl": ("ablation_cap64", ALL1_TRUTH),
        "ablation_k2_sentinel.jsonl": ("ablation_k2_sentinel", ALL1_TRUTH),
    }

    for filename, (name, truth) in specs.items():
        rows = load_jsonl(args.results_dir / filename, audit)
        if rows:
            check_nand(name, rows, truth, audit, args.full_suite)

    fa_rows = load_jsonl(args.results_dir / "full_adder.jsonl", audit)
    if fa_rows:
        check_full_adder(fa_rows, audit, args.full_suite)

    adder_rows = load_jsonl(args.results_dir / "adder32.jsonl", audit)
    if adder_rows:
        check_adder32(adder_rows, audit, args.full_suite)

    exhaustive_path = args.results_dir / "adder32_exhaustive.jsonl"
    if exhaustive_path.exists():
        ex_rows = load_jsonl(exhaustive_path, audit)
        if ex_rows:
            check_adder_exhaustive(ex_rows, audit)

    if audit.failures:
        for failure in audit.failures:
            print(failure, file=sys.stderr)
        print(f"semantic audit: {len(audit.failures)} failure(s)", file=sys.stderr)
        return 1

    print("semantic audit: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
