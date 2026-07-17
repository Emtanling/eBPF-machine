#!/usr/bin/env python3
"""Verify a stock-linux-r-proof frozen bundle's checksums and stored final verdict."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

FINAL_VERDICT = "STOCK_LINUX_R_ESTABLISHED_FOR_FROZEN_TUPLE"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_rel(rel: str) -> bool:
    p = Path(rel)
    return bool(rel) and not p.is_absolute() and ".." not in p.parts


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} root must be object")
    return data


def verify_checksums(bundle: Path) -> dict[str, Any]:
    path = bundle / "CHECKSUMS.sha256"
    missing: list[str] = []
    mismatches: list[dict[str, str]] = []
    checked: list[str] = []
    if not path.exists():
        return {"passed": False, "checked": [], "missing": ["CHECKSUMS.sha256"], "mismatches": []}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            expected, rel = line.split(None, 1)
        except ValueError:
            mismatches.append({"file": "CHECKSUMS.sha256", "reason": f"malformed line: {line}"})
            continue
        rel = rel.strip()
        if not _safe_rel(rel):
            mismatches.append({"file": rel, "reason": "unsafe path"})
            continue
        f = bundle / rel
        if not f.exists():
            missing.append(rel)
            continue
        actual = sha256_file(f)
        checked.append(rel)
        if actual != expected:
            mismatches.append({"file": rel, "expected": expected, "actual": actual})
    return {"passed": not missing and not mismatches and bool(checked), "checked": checked, "missing": missing, "mismatches": mismatches}


def verify_manifest(bundle: Path) -> dict[str, Any]:
    manifest = _load_json(bundle / "MANIFEST.json")
    files = manifest.get("files")
    errors: list[str] = []
    checked: list[str] = []
    if manifest.get("schema") != "stock-linux-r-proof-v1":
        errors.append("bad manifest schema")
    if not isinstance(files, dict):
        errors.append("manifest files must be object")
        files = {}
    for rel, entry in files.items():
        if not _safe_rel(rel) or not isinstance(entry, dict):
            errors.append(f"bad manifest entry {rel!r}")
            continue
        path = bundle / rel
        if not path.exists():
            errors.append(f"manifest file missing: {rel}")
            continue
        checked.append(rel)
        if entry.get("sha256") != sha256_file(path):
            errors.append(f"manifest sha mismatch: {rel}")
        if entry.get("size") != path.stat().st_size:
            errors.append(f"manifest size mismatch: {rel}")
    return {"passed": not errors and bool(checked), "errors": errors, "checked": checked, "manifest": manifest}


def verify(bundle: Path) -> dict[str, Any]:
    manifest_result = verify_manifest(bundle)
    checksum_result = verify_checksums(bundle)
    verdict_doc = _load_json(bundle / "proof" / "definition2" / "verdict.json")
    verdict_ok = verdict_doc.get("verdict") == FINAL_VERDICT
    passed = manifest_result["passed"] and checksum_result["passed"] and verdict_ok
    return {
        "schema": "stock-linux-r-frozen-bundle-check-v1",
        "result": "FROZEN_PROOF_BUNDLE_VERIFIED" if passed else "FROZEN_PROOF_BUNDLE_REJECTED",
        "passed": passed,
        "manifest": {k: v for k, v in manifest_result.items() if k != "manifest"},
        "checksums": checksum_result,
        "verdict": verdict_doc.get("verdict"),
        "verdict_ok": verdict_ok,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args(argv)
    result = verify(args.bundle)
    print(result["result"])
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
