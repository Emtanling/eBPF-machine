#!/usr/bin/env python3
"""Replay the published Stock-R artifact capsule and compare expected results."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile
from typing import Any

from residuality_auditor.reproduction import (
    ReproductionError,
    compare_reproduction_summary,
    normalize_reproduction_result,
    replay_capsule,
    verify_and_extract_capsule,
)


ARTIFACT_DIR = Path(__file__).resolve().parent


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReproductionError(f"JSON_UNREADABLE: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReproductionError(f"JSON_ROOT_NOT_OBJECT: {path}")
    return value


def _write_json(path: Path, document: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ReproductionError(f"JSON_WRITE_FAILED: {path}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive",
        type=Path,
        default=ARTIFACT_DIR / "evidence" / "replay-capsule.tar.xz",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ARTIFACT_DIR / "replay-manifest.json",
    )
    parser.add_argument(
        "--expected",
        type=Path,
        default=ARTIFACT_DIR / "expected-results.json",
    )
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args(argv)

    try:
        expected = _read_json(args.expected)
        with tempfile.TemporaryDirectory(prefix="stock-r-replay-") as temporary:
            extracted = Path(temporary) / "capsule"
            verify_and_extract_capsule(args.archive, _read_json(args.manifest), extracted)
            summary = normalize_reproduction_result(replay_capsule(extracted))
        comparison = compare_reproduction_summary(summary, expected)
        record = {
            "schema": "rac-stock-r-reproduce-run-v1",
            "summary": summary,
            "comparison": comparison,
        }
        if args.json_out is not None:
            _write_json(args.json_out, record)
        print(f"all_expected={str(comparison['all_expected']).lower()}")
        print(f"unexpected_results={summary.get('unexpected_results')}")
        if comparison["mismatches"]:
            print("mismatches=" + ",".join(comparison["mismatches"]))
        return 0 if comparison["all_expected"] else 1
    except ReproductionError as exc:
        record = {
            "schema": "rac-stock-r-reproduce-run-v1",
            "status": "ERROR",
            "error": str(exc),
        }
        if args.json_out is not None:
            try:
                _write_json(args.json_out, record)
            except ReproductionError:
                pass
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
