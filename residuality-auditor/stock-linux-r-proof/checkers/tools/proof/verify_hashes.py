#!/usr/bin/env python3
"""Hash manifest helpers for frozen RAC evidence bundles."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


REQUIRED_EVIDENCE: dict[str, str] = {
    "events.jsonl": "raw/verifier-events",
    "events.raw.jsonl": "raw/verifier-events",
    "frontier-check.json": "normalized/frontier",
    "object.sha256": "raw/object",
    "program-info.json": "raw/object",
    "program-pin.txt": "raw/object",
    "runtime.json": "raw/runtime",
    "xlated-rac_single.sha256": "raw/xlated",
    "xlated-rac_single.txt": "raw/xlated",
    "proof/states/state-capture-check.json": "normalized/states",
    "proof/states/retained-state.json": "normalized/states",
    "proof/states/current-state.json": "normalized/states",
    "proof/path/path-correspondence.json": "normalized/paths",
    "proof/concretization/joint-coverage.json": "normalized/concretization",
    "proof/concretization/membership-a0.json": "normalized/concretization",
    "proof/concretization/membership-a1.json": "normalized/concretization",
    "proof/subsumption/subsumption-check.json": "normalized/subsumption",
    "proof/subsumption/kernel-source-map.json": "normalized/subsumption",
    "proof/report/prune-cell-definition.json": "normalized/report",
    "proof/report/prune-cell-coverage.json": "normalized/report",
    "proof/report/session-completeness.json": "normalized/report",
    "proof/report/membership-matrix.json": "normalized/report",
    "proof/report/unique-cell-check.json": "normalized/report",
    "proof/report/report-map.json": "normalized/report",
    "proof/factorization/behavioral-quotient.json": "proof/quotient",
    "proof/factorization/beta-map.json": "proof/quotient",
    "proof/factorization/factorization.json": "proof/factorization",
    "proof/factorization/suffix-witness.json": "proof/factorization",
    "proof/definition2/kernel-identity.json": "proof/definition2",
    "proof/definition2/stock-linux-r-check.json": "proof/definition2",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_rel(rel: str) -> bool:
    p = Path(rel)
    return bool(rel) and not p.is_absolute() and ".." not in p.parts


def build_manifest(bundle: Path, *, required: dict[str, str] | None = None) -> dict[str, Any]:
    required = required or REQUIRED_EVIDENCE
    files: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    for rel, role in sorted(required.items()):
        path = bundle / rel
        if not path.exists():
            missing.append(rel)
            continue
        files[rel] = {
            "role": role,
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
        }
    return {
        "schema": "rac-proof-manifest-v1",
        "bundle_name": bundle.name,
        "files": files,
        "required_files": sorted(required),
        "missing_required_files": missing,
    }


def verify_hashes(bundle: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    files = manifest.get("files")
    if not isinstance(files, dict):
        return {
            "schema": "rac-proof-hash-check-v1",
            "result": "HASH_MANIFEST_INVALID",
            "passed": False,
            "checked": [],
            "missing": [],
            "mismatches": [{"manifest": "files must be an object"}],
        }
    checked: list[str] = []
    missing: list[str] = []
    mismatches: list[dict[str, Any]] = []
    for rel, entry in sorted(files.items()):
        if not _safe_rel(rel) or not isinstance(entry, dict):
            mismatches.append({"file": rel, "reason": "unsafe path or malformed entry"})
            continue
        path = bundle / rel
        if not path.exists():
            missing.append(rel)
            continue
        actual_sha = sha256_file(path)
        actual_size = path.stat().st_size
        expected_sha = entry.get("sha256")
        expected_size = entry.get("size")
        checked.append(rel)
        if actual_sha != expected_sha or actual_size != expected_size:
            mismatches.append(
                {
                    "file": rel,
                    "expected_sha256": expected_sha,
                    "actual_sha256": actual_sha,
                    "expected_size": expected_size,
                    "actual_size": actual_size,
                }
            )
    required_missing = [rel for rel in manifest.get("required_files", []) if rel not in files]
    passed = not missing and not mismatches and not required_missing and not manifest.get("missing_required_files")
    return {
        "schema": "rac-proof-hash-check-v1",
        "result": "HASHES_VERIFIED" if passed else "HASH_CHECK_FAILED",
        "passed": passed,
        "checked": checked,
        "missing": missing,
        "required_missing_from_manifest": required_missing,
        "missing_required_files": manifest.get("missing_required_files", []),
        "mismatches": mismatches,
    }


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _embedded_identities(bundle: Path) -> list[tuple[str, dict[str, Any]]]:
    rels = [
        "frontier-check.json",
        "proof/states/state-capture-check.json",
        "proof/path/path-correspondence.json",
        "proof/report/report-map.json",
        "proof/subsumption/kernel-source-map.json",
    ]
    out: list[tuple[str, dict[str, Any]]] = []
    for rel in rels:
        doc = _load_json(bundle / rel)
        if not doc:
            continue
        ident = doc.get("identity") or doc.get("program_identity")
        if isinstance(ident, dict) and isinstance(ident.get("input_sha256"), dict):
            out.append((rel, ident["input_sha256"]))
    return out


def verify_embedded_input_hashes(bundle: Path) -> dict[str, Any]:
    checked: list[dict[str, str]] = []
    missing: list[dict[str, str]] = []
    mismatches: list[dict[str, str]] = []
    conflicts: list[dict[str, Any]] = []
    expected_by_file: dict[str, set[str]] = {}
    for source, mapping in _embedded_identities(bundle):
        for rel, expected in sorted(mapping.items()):
            expected_by_file.setdefault(rel, set()).add(str(expected))
            path = bundle / rel
            if not path.exists():
                missing.append({"source": source, "file": rel})
                continue
            actual = sha256_file(path)
            checked.append({"source": source, "file": rel})
            if actual != expected:
                mismatches.append({"source": source, "file": rel, "expected": str(expected), "actual": actual})
    for rel, values in sorted(expected_by_file.items()):
        if len(values) > 1:
            conflicts.append({"file": rel, "expected_values": sorted(values)})
    passed = not missing and not mismatches and not conflicts and bool(checked)
    return {
        "schema": "rac-embedded-input-hash-check-v1",
        "result": "EMBEDDED_INPUT_HASHES_VERIFIED" if passed else "EMBEDDED_INPUT_HASH_CHECK_FAILED",
        "passed": passed,
        "checked": checked,
        "missing": missing,
        "mismatches": mismatches,
        "conflicts": conflicts,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--write-manifest", action="store_true")
    args = parser.parse_args(argv)
    manifest = build_manifest(args.bundle)
    if args.manifest and args.manifest.exists() and not args.write_manifest:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    elif args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result = verify_hashes(args.bundle, manifest)
    print(result["result"])
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
