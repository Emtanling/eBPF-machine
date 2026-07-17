#!/usr/bin/env python3
"""Validate RAC proof manifests before hash verification."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from tools.proof.verify_hashes import REQUIRED_EVIDENCE, build_manifest


def _safe_rel(rel: str) -> bool:
    p = Path(rel)
    return bool(rel) and not p.is_absolute() and ".." not in p.parts


def validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    if manifest.get("schema") != "rac-proof-manifest-v1":
        errors.append("manifest schema must be rac-proof-manifest-v1")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        errors.append("manifest files must be a non-empty object")
        files = {}
    for rel, entry in files.items():
        if not _safe_rel(str(rel)):
            errors.append(f"manifest contains unsafe relative path {rel!r}")
            continue
        if not isinstance(entry, dict):
            errors.append(f"manifest entry {rel!r} must be an object")
            continue
        sha = entry.get("sha256")
        size = entry.get("size")
        if not isinstance(sha, str) or len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            errors.append(f"manifest entry {rel!r} has invalid sha256")
        if not isinstance(size, int) or size < 0:
            errors.append(f"manifest entry {rel!r} has invalid size")
    required = manifest.get("required_files")
    if not isinstance(required, list):
        errors.append("manifest required_files must be a list")
        required = []
    missing_from_manifest = sorted(set(REQUIRED_EVIDENCE) - set(files))
    if missing_from_manifest:
        errors.append(f"manifest omits required files: {missing_from_manifest}")
    extra_required = sorted(set(required) - set(REQUIRED_EVIDENCE))
    if extra_required:
        warnings.append(f"manifest declares non-standard required files: {extra_required}")
    if manifest.get("missing_required_files"):
        errors.append(f"required files missing when manifest was built: {manifest['missing_required_files']}")
    return {
        "schema": "rac-proof-manifest-validation-v1",
        "result": "MANIFEST_VALID" if not errors else "MANIFEST_INVALID",
        "passed": not errors,
        "errors": errors,
        "warnings": warnings,
        "file_count": len(files),
    }


def load_or_build_manifest(bundle: Path, manifest_path: Path | None = None) -> tuple[dict[str, Any], str]:
    if manifest_path is not None and manifest_path.exists():
        return json.loads(manifest_path.read_text(encoding="utf-8")), "provided"
    manifest = build_manifest(bundle)
    if manifest_path is not None:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest, "generated"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--write-manifest", action="store_true")
    args = parser.parse_args(argv)
    manifest_path = args.manifest if args.manifest or args.write_manifest else None
    if args.write_manifest and manifest_path is None:
        manifest_path = args.bundle / "proof" / "definition2" / "manifest.json"
    manifest, _ = load_or_build_manifest(args.bundle, manifest_path)
    result = validate_manifest(manifest)
    print(result["result"])
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
