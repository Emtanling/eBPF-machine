#!/usr/bin/env python3
"""Create or verify a self-issued SHA-256 integrity manifest for one run."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


SCHEMA = "weirdmachinebpf.interpreter-provenance/v1"
MANIFEST_NAME = "interpreter.provenance.json"
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
EXPECTED_BOUNDS = {
    "abi_version": 1,
    "max_inputs": 64,
    "max_gates": 512,
    "max_wires": 578,
    "max_outputs": 64,
    "gate_op": "NAND",
    "descriptor_format": "WMC1",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def list_files(root: Path) -> list[dict[str, object]]:
    files: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        # Only the run-root manifest is self-referential.  A nested file with
        # the same basename is ordinary evidence and must be bound.
        if not path.is_file() or path == root / MANIFEST_NAME:
            continue
        relative = path.relative_to(root).as_posix()
        files.append({
            "path": relative,
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        })
    return files


def write_manifest(root: Path, run_id: str) -> Path:
    if not RUN_ID_RE.fullmatch(run_id):
        raise ValueError("invalid run id")
    files = list_files(root)
    if not files:
        raise ValueError("refusing to write a provenance manifest for an empty run")
    manifest = {
        "schema": SCHEMA,
        "run_id": run_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "bounds": EXPECTED_BOUNDS,
        "files": files,
    }
    output = root / MANIFEST_NAME
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    os.replace(temporary, output)
    return output


def verify_manifest(root: Path) -> list[str]:
    manifest_path = root / MANIFEST_NAME
    if not manifest_path.is_file():
        return [f"missing {MANIFEST_NAME}"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"invalid manifest: {exc}"]
    failures: list[str] = []
    if manifest.get("schema") != SCHEMA:
        failures.append("wrong provenance schema")
    if not RUN_ID_RE.fullmatch(manifest.get("run_id", "")):
        failures.append("invalid run id")
    elif manifest["run_id"] != root.name:
        failures.append("run id does not match run-root directory name")
    if manifest.get("bounds") != EXPECTED_BOUNDS:
        failures.append("unexpected interpreter bounds")
    expected = manifest.get("files")
    if not isinstance(expected, list):
        return failures + ["manifest files field is not a list"]
    actual = {entry["path"]: entry for entry in list_files(root)}
    recorded: dict[str, dict[str, object]] = {}
    for entry in expected:
        if not isinstance(entry, dict):
            failures.append("manifest contains non-object binding")
            continue
        path = entry.get("path")
        digest = entry.get("sha256")
        size = entry.get("bytes")
        if not isinstance(path, str) or not path or path.startswith("/") or ".." in Path(path).parts:
            failures.append(f"unsafe manifest path: {path!r}")
            continue
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            failures.append(f"invalid digest for {path}")
            continue
        if not isinstance(size, int) or size < 0:
            failures.append(f"invalid byte count for {path}")
            continue
        if path in recorded:
            failures.append(f"duplicate manifest path: {path}")
            continue
        recorded[path] = entry
    for path, entry in recorded.items():
        observed = actual.get(path)
        if observed is None:
            failures.append(f"missing bound file: {path}")
            continue
        if observed["sha256"] != entry["sha256"]:
            failures.append(f"hash mismatch: {path}")
        if observed["bytes"] != entry["bytes"]:
            failures.append(f"size mismatch: {path}")
    unexpected = sorted(set(actual) - set(recorded))
    missing = sorted(set(recorded) - set(actual))
    failures.extend(f"unbound file: {path}" for path in unexpected)
    failures.extend(f"missing recorded file: {path}" for path in missing)
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    write_parser = subcommands.add_parser("write")
    write_parser.add_argument("run_root", type=Path)
    write_parser.add_argument("--run-id", required=True)
    verify_parser = subcommands.add_parser("verify")
    verify_parser.add_argument("run_root", type=Path)
    args = parser.parse_args(argv)
    root = args.run_root.resolve()
    if not root.is_dir():
        print(f"run root does not exist: {root}", file=sys.stderr)
        return 2
    try:
        if args.command == "write":
            print(write_manifest(root, args.run_id))
            return 0
        failures = verify_manifest(root)
    except (OSError, ValueError) as exc:
        print(f"interpreter provenance: {exc}", file=sys.stderr)
        return 2
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print("interpreter provenance: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
