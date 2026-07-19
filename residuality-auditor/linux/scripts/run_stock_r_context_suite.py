#!/usr/bin/env python3
"""Run every frozen bounded Stock-R context exactly once."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Mapping, Sequence

from residuality_auditor.context_suite import (
    ContextSuiteError,
    compare_case_result,
    load_context_suite,
)


MATRIX_SCHEMA = "rac-stock-r-contextual-matrix-v1"


def _pin_dir_for_run(run_id: str, index: int) -> str:
    digest = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:16]
    return f"/sys/fs/bpf/rac-v2-context-matrix-{index:02d}-{digest}"


def _read_case_result(path: Path) -> Mapping[str, object]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {
            "case_id": "",
            "observed": {
                "stage": "RUNNER",
                "status": "ERROR",
                "reasons": [f"CASE_RESULT_UNREADABLE:{type(exc).__name__}"],
            },
        }
    if not isinstance(document, dict):
        return {
            "case_id": "",
            "observed": {
                "stage": "RUNNER",
                "status": "ERROR",
                "reasons": ["CASE_RESULT_MALFORMED"],
            },
        }
    return document


def _write_json(path: Path, document: Mapping[str, object]) -> None:
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv: Sequence[str] | None = None) -> int:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_bundle", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--suite",
        type=Path,
        default=here.parent / "context-suite-v1.json",
    )
    parser.add_argument(
        "--single-runner",
        type=Path,
        default=here / "run_stock_r_context.sh",
    )
    parser.add_argument("--python", default="python3")
    args = parser.parse_args(argv)

    if not args.base_bundle.is_dir():
        parser.error(f"base Stock-R V2 bundle is not a directory: {args.base_bundle}")
    if not args.single_runner.is_file():
        parser.error(f"single-case runner is not a file: {args.single_runner}")
    if args.output.exists():
        parser.error(f"output path already exists: {args.output}")
    try:
        suite = load_context_suite(args.suite)
    except ContextSuiteError as exc:
        parser.error(str(exc))
    args.output.mkdir(parents=True)

    case_results: list[dict[str, object]] = []
    for index, case in enumerate(suite.cases):
        case_output = args.output / "cases" / f"{index:02d}-{case.case_id}"
        run_id = f"{suite.suite_id}-{index:02d}-{case.case_id}"
        environment = dict(os.environ)
        environment.update(
            {
                "PYTHON": args.python,
                "RAC_CONTEXT_RUN_ID": run_id,
                "RAC_CONTEXT_PIN_DIR": _pin_dir_for_run(run_id, index),
                "RAC_CONTEXT_SUITE": str(args.suite.resolve()),
                "RAC_CONTEXT_CASE_ID": case.case_id,
            }
        )
        started_ns = time.monotonic_ns()
        completed = subprocess.run(
            [str(args.single_runner), str(args.base_bundle), str(case_output)],
            env=environment,
            check=False,
        )
        duration_ns = time.monotonic_ns() - started_ns
        retained = _read_case_result(case_output / "context" / "case-result.json")
        raw_observed = retained.get("observed", {})
        observed = raw_observed if isinstance(raw_observed, Mapping) else {}
        comparison = compare_case_result(case, observed)
        identity_match = retained.get("case_id") == case.case_id
        comparison.update(
            {
                "run_id": run_id,
                "output": str(case_output.relative_to(args.output)),
                "duration_ns": duration_ns,
                "child_exit_status": completed.returncode,
                "retained_case_id_match": identity_match,
            }
        )
        comparison["expected_match"] = bool(
            comparison["expected_match"]
            and identity_match
            and completed.returncode == 0
        )
        case_results.append(comparison)

    unexpected = [
        result["case_id"]
        for result in case_results
        if not result["expected_match"]
    ]
    matrix: dict[str, object] = {
        "schema": MATRIX_SCHEMA,
        "suite_id": suite.suite_id,
        "claim_boundary": suite.claim_boundary,
        "counts": {
            "total": len(case_results),
            "expected": len(case_results) - len(unexpected),
            "unexpected": len(unexpected),
        },
        "case_results": case_results,
        "unexpected_results": unexpected,
        "all_expected": not unexpected,
    }
    _write_json(args.output / "contextual-matrix.json", matrix)
    return 0 if matrix["all_expected"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
