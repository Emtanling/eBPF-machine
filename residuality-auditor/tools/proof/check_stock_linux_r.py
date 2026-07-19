#!/usr/bin/env python3
"""Strict legacy-adapter four-check replay for a frozen stock-Linux tuple."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

FINAL = "STOCK_LINUX_R_ESTABLISHED_FOR_FROZEN_TUPLE"

REQUIRED_RESULTS = {
    "path": "PATH_CORRESPONDENCE_VERIFIED",
    "a0": "SIGMA_A0_IN_DIRECT_GAMMA",
    "a1": "SIGMA_A1_IN_DIRECT_GAMMA",
    "coverage": "BOTH_CASES_IN_OPERATIONAL_PRUNE_CELL",
    "unique": "UNIQUE_SAME_REPORT_CELL",
    "factorization": "REPORT_FACTORIZATION_FAILURE_ESTABLISHED",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"_missing": True, "_path": str(path)}
    except json.JSONDecodeError as exc:
        return {"_invalid_json": str(exc), "_path": str(path)}
    return data if isinstance(data, dict) else {"_invalid_json": "root is not object", "_path": str(path)}


def _write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _ref_check(bundle: Path, report: dict[str, Any]) -> dict[str, Any]:
    refs = report.get("evidence_refs") if isinstance(report.get("evidence_refs"), dict) else {}
    required = [
        "path_correspondence",
        "membership_a0",
        "membership_a1",
        "prune_cell_definition",
        "prune_cell_coverage",
        "session_completeness",
        "membership_matrix",
        "unique_cell",
    ]
    checks = {}
    mismatches = []
    for name in required:
        ref = refs.get(name)
        if not isinstance(ref, dict):
            mismatches.append({"ref": name, "reason": "missing"})
            checks[name] = False
            continue
        rel = ref.get("path")
        if not isinstance(rel, str) or rel.startswith("/") or ".." in Path(rel).parts:
            mismatches.append({"ref": name, "reason": "unsafe path", "path": rel})
            checks[name] = False
            continue
        p = bundle / rel
        if not p.exists():
            mismatches.append({"ref": name, "reason": "file missing", "path": rel})
            checks[name] = False
            continue
        actual = sha256_file(p)
        checks[name] = actual == ref.get("sha256")
        if not checks[name]:
            mismatches.append({"ref": name, "path": rel, "expected": ref.get("sha256"), "actual": actual})
    return {"passed": not mismatches and bool(refs), "checks": checks, "mismatches": mismatches}


def _first_failure(checks: dict[str, Any]) -> str:
    if not checks["evidence_refs"]["passed"]:
        return "EVIDENCE_REFS_NOT_ESTABLISHED"
    if checks["path"].get("result") != REQUIRED_RESULTS["path"]:
        return "PATH_CORRESPONDENCE_NOT_ESTABLISHED"
    if (
        checks["membership_a0"].get("result") != REQUIRED_RESULTS["a0"]
        or checks["membership_a1"].get("result") != REQUIRED_RESULTS["a1"]
        or checks["membership_a0"].get("unsupported_fields_empty") is not True
        or checks["membership_a1"].get("unsupported_fields_empty") is not True
        or checks["membership_a0"].get("field_checks_present") is not True
        or checks["membership_a1"].get("field_checks_present") is not True
        or checks["membership_a0"].get("field_checks_all_pass") is not True
        or checks["membership_a1"].get("field_checks_all_pass") is not True
    ):
        return "DIRECT_MEMBERSHIP_NOT_ESTABLISHED"
    if checks["coverage"].get("result") != REQUIRED_RESULTS["coverage"]:
        return "PRUNE_CELL_COVERAGE_NOT_ESTABLISHED"
    if checks["session"].get("session_complete") is not True or checks["session"].get("result") != "SESSION_CAPTURE_COMPLETE":
        return "SESSION_CAPTURE_INCOMPLETE"
    if checks["unique"].get("result") != REQUIRED_RESULTS["unique"]:
        return "UNIQUE_CELL_NOT_ESTABLISHED"
    if checks["factorization"].get("result") != REQUIRED_RESULTS["factorization"]:
        return "R_NOT_ESTABLISHED"
    if checks["output_witnessed_r_collision"] is not True:
        return "R_NOT_ESTABLISHED"
    return FINAL


def check(bundle: Path, out: Path | None = None) -> dict[str, Any]:
    bundle = bundle.resolve()
    report = _load(bundle / "proof" / "report" / "report-map.json")
    path = _load(bundle / "proof" / "path" / "path-correspondence.json")
    a0 = _load(bundle / "proof" / "concretization" / "membership-a0.json")
    a1 = _load(bundle / "proof" / "concretization" / "membership-a1.json")
    coverage = _load(bundle / "proof" / "report" / "prune-cell-coverage.json")
    session = _load(bundle / "proof" / "report" / "session-completeness.json")
    unique = _load(bundle / "proof" / "report" / "unique-cell-check.json")
    factorization = _load(bundle / "proof" / "factorization" / "factorization.json")
    factor_conditions = factorization.get("conditions") or {}
    checks = {
        "evidence_refs": _ref_check(bundle, report),
        "path": {"result": path.get("result"), "identity_verified": path.get("identity_verified"), "a0": path.get("a0"), "a1": path.get("a1")},
        "membership_a0": {
            "result": a0.get("result"),
            "unsupported_fields": a0.get("unsupported_fields"),
            "unsupported_fields_empty": a0.get("unsupported_fields") == [],
            "field_checks_present": bool(a0.get("field_checks")),
            "field_checks_all_pass": bool(a0.get("field_checks")) and all(item.get("result") == "PASS" for item in a0.get("field_checks", [])),
            "field_check_count": len(a0.get("field_checks", [])) if isinstance(a0.get("field_checks"), list) else 0,
        },
        "membership_a1": {
            "result": a1.get("result"),
            "unsupported_fields": a1.get("unsupported_fields"),
            "unsupported_fields_empty": a1.get("unsupported_fields") == [],
            "field_checks_present": bool(a1.get("field_checks")),
            "field_checks_all_pass": bool(a1.get("field_checks")) and all(item.get("result") == "PASS" for item in a1.get("field_checks", [])),
            "field_check_count": len(a1.get("field_checks", [])) if isinstance(a1.get("field_checks"), list) else 0,
        },
        "coverage": {"result": coverage.get("result"), "checks": coverage.get("checks"), "representative": coverage.get("representative")},
        "session": {"result": session.get("result"), "session_complete": session.get("session_complete"), "ringbuf_lost_events": session.get("ringbuf_lost_events"), "collector_parse_errors": session.get("collector_parse_errors")},
        "unique": {
            "schema": unique.get("schema"),
            "result": unique.get("result"),
            "session_complete": unique.get("session_complete"),
            "verifier_invocation_completed": unique.get("verifier_invocation_completed"),
            "events_lost": unique.get("events_lost"),
            "collector_parse_errors": unique.get("collector_parse_errors"),
            "retained_roots": unique.get("retained_roots"),
            "representatives": unique.get("representatives"),
        },
        "factorization": {"result": factorization.get("result"), "conditions": factor_conditions},
        "output_witnessed_r_collision": factor_conditions.get("auditor_R_output_witnessed") is True or (factorization.get("auditor_summary") or {}).get("R_output_witnessed") is True,
    }
    # Extra strictness from the guide: unique-cell must be the v2/session-aware certificate.
    if checks["unique"].get("schema") != "rac-unique-report-cell-v2":
        checks["unique"]["result"] = "UNIQUE_CELL_NOT_ESTABLISHED"
    if checks["unique"].get("session_complete") is not True:
        checks["unique"]["result"] = "UNIQUE_CELL_NOT_ESTABLISHED"
    if checks["unique"].get("verifier_invocation_completed") is not True:
        checks["unique"]["result"] = "UNIQUE_CELL_NOT_ESTABLISHED"
    if checks["unique"].get("events_lost") != 0:
        checks["unique"]["result"] = "UNIQUE_CELL_NOT_ESTABLISHED"
    if checks["unique"].get("collector_parse_errors") != 0:
        checks["unique"]["result"] = "UNIQUE_CELL_NOT_ESTABLISHED"
    verdict = _first_failure(checks)
    result = {
        "schema": "rac-stock-linux-r-four-checks-v1",
        "result": verdict,
        "passed": verdict == FINAL,
        "required": REQUIRED_RESULTS,
        "checks": checks,
    }
    out = out or bundle / "proof" / "definition2" / "stock-linux-r-check.json"
    _write(out, result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args(argv)
    result = check(args.bundle)
    print(result["result"])
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
