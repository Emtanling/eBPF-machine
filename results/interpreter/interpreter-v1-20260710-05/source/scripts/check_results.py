#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def check_file(path: Path) -> tuple[int, int]:
    total = 0
    failed = 0

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"{path}:{line_no}: invalid JSON: {exc}", file=sys.stderr)
                failed += 1
                continue
            if row.get("passed") is not True:
                print(f"{path}:{line_no}: failed row: {row}", file=sys.stderr)
                failed += 1

    print(f"{path}: {total - failed}/{total} passed")
    if total == 0:
        print(f"{path}: no result rows found", file=sys.stderr)
        failed += 1
    return total, failed


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: check_results.py FILE.jsonl [...]", file=sys.stderr)
        return 2

    total = 0
    failed = 0
    for arg in sys.argv[1:]:
        file_total, file_failed = check_file(Path(arg))
        total += file_total
        failed += file_failed

    print(f"TOTAL: {total - failed}/{total} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
