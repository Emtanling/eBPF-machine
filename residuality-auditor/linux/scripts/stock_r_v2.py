#!/usr/bin/env python3
"""Prepare, seal, audit, and manifest a Stock-R V2 experiment bundle."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from residuality_auditor.stock_r_v2 import (  # noqa: E402
    BUILD_CLOSURE_SCHEMA,
    SOURCE_CLOSURE_SCHEMA,
    StockRV2Error,
    audit_bundle,
    canonical_sha256,
    make_history_case_binding_from_events,
    make_must_outcome_proof,
    make_precommit,
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StockRV2Error(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StockRV2Error(f"JSON root must be an object: {path}")
    return value


def _read_jsonl(path: Path) -> list[Any]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise StockRV2Error(f"cannot read JSONL {path}: {exc}") from exc
    rows = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise StockRV2Error(f"invalid JSON at {path}:{number}: {exc}") from exc
    return rows


def _copy_regular_file(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise StockRV2Error(f"source is not a readable regular file: {source}")
    if destination.exists():
        raise StockRV2Error(f"refusing to overwrite bundle file: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def _manifest_entry(path: Path, rel: str) -> dict[str, Any]:
    return {"path": rel, "sha256": _sha256_file(path), "size": path.stat().st_size}


def _validate_manifest(path: Path, schema: str) -> None:
    manifest = _read_json(path)
    if manifest.get("schema") != schema:
        raise StockRV2Error(f"{path} has wrong schema")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise StockRV2Error(f"{path} must contain at least one entry")
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise StockRV2Error(f"{path}: entries[{index}] must be an object")
        rel = entry.get("path")
        digest = entry.get("sha256")
        size = entry.get("size")
        if (
            not isinstance(rel, str)
            or not rel
            or rel.startswith("/")
            or rel in {".", ".."}
            or any(part in {"", ".", ".."} for part in rel.split("/"))
        ):
            raise StockRV2Error(f"{path}: unsafe entry path {rel!r}")
        if rel in seen:
            raise StockRV2Error(f"{path}: duplicate entry {rel}")
        seen.add(rel)
        if not isinstance(digest, str) or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise StockRV2Error(f"{path}: invalid digest for {rel}")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise StockRV2Error(f"{path}: invalid size for {rel}")


def source_closure(args: argparse.Namespace) -> int:
    root = args.output.resolve()
    source_root = args.source_root.resolve()
    manifest_path = root / "build" / "source-manifest.json"
    if manifest_path.exists():
        raise StockRV2Error("source closure manifest already exists; use a new output directory")
    entries = []
    seen: set[str] = set()
    for raw_source in args.source:
        source = raw_source.resolve()
        try:
            rel_path = source.relative_to(source_root)
        except ValueError as exc:
            raise StockRV2Error(f"source is outside --source-root: {source}") from exc
        rel = rel_path.as_posix()
        if rel in seen:
            raise StockRV2Error(f"duplicate source closure entry: {rel}")
        seen.add(rel)
        destination = root / "build" / "source" / rel_path
        _copy_regular_file(source, destination)
        entries.append(_manifest_entry(destination, rel))
    entries.sort(key=lambda entry: entry["path"])
    _atomic_json(manifest_path, {"schema": SOURCE_CLOSURE_SCHEMA, "entries": entries})
    print(_sha256_file(manifest_path))
    return 0


def artifact_closure(args: argparse.Namespace) -> int:
    root = args.output.resolve()
    manifest_path = root / "build" / "artifact-manifest.json"
    if manifest_path.exists():
        raise StockRV2Error("artifact closure manifest already exists; use a new output directory")
    entries = []
    seen: set[str] = set()
    for spec in args.artifact:
        name, separator, raw_path = spec.partition("=")
        if (
            separator != "="
            or not name
            or "/" in name
            or name in {".", ".."}
            or any(part in {"", ".", ".."} for part in name.split("/"))
        ):
            raise StockRV2Error(f"--artifact must have form safe-name=/path, got {spec!r}")
        if name in seen:
            raise StockRV2Error(f"duplicate artifact closure entry: {name}")
        seen.add(name)
        source = Path(raw_path).resolve()
        destination = root / "build" / name
        _copy_regular_file(source, destination)
        entries.append(_manifest_entry(destination, name))
    entries.sort(key=lambda entry: entry["path"])
    _atomic_json(manifest_path, {"schema": BUILD_CLOSURE_SCHEMA, "entries": entries})
    print(_sha256_file(manifest_path))
    return 0


def _static_identity(args: argparse.Namespace) -> dict[str, Any]:
    if args.trials < 4 or args.trials % 2:
        raise StockRV2Error("--trials must be even and at least 4")
    object_path = args.object.resolve()
    btf_path = args.btf.resolve()
    if not object_path.is_file() or not btf_path.is_file():
        raise StockRV2Error("--object and --btf must be readable regular files")
    return {
        "program_name": "rac_v2_single",
        "object_sha256": _sha256_file(object_path),
        "kernel_release": args.kernel_release,
        "btf_sha256": _sha256_file(btf_path),
    }


def prepare(args: argparse.Namespace) -> int:
    root = args.output.resolve()
    query_path = root / "query" / "query.json"
    policy_path = root / "query" / "selection-policy.json"
    precommit_path = root / "query" / "precommit.json"
    if any(path.exists() for path in (query_path, policy_path, precommit_path)):
        raise StockRV2Error("V2 precommit files already exist; use a new output directory")
    identity = _static_identity(args)
    source_manifest = args.source_manifest.resolve()
    artifact_manifest = args.artifact_manifest.resolve()
    if source_manifest != root / "build" / "source-manifest.json":
        raise StockRV2Error("--source-manifest must be OUTPUT/build/source-manifest.json")
    if artifact_manifest != root / "build" / "artifact-manifest.json":
        raise StockRV2Error("--artifact-manifest must be OUTPUT/build/artifact-manifest.json")
    _validate_manifest(source_manifest, SOURCE_CLOSURE_SCHEMA)
    _validate_manifest(artifact_manifest, BUILD_CLOSURE_SCHEMA)
    query = {
        "schema": "rac-stock-r-v2-query-v1",
        "query_id": "stock-r-v2.array-map-shared-suffix",
        "identity": identity,
        "source_closure_sha256": _sha256_file(source_manifest),
        "build_closure_sha256": _sha256_file(artifact_manifest),
        "event_selector": {
            "exact_level": 0,
            "require_distinct_histories": True,
            "require_complete_history": True,
            "require_supported_state": True,
            "uniqueness": "EXACTLY_ONE",
        },
        "trial_plan": {
            "cases": [0, 1],
            "per_case": args.trials // 2,
            "schedule": "ALTERNATING_START_ZERO",
            "observer": "XDP_RETURN_BIT",
        },
    }
    policy = {
        "schema": "rac-stock-r-v2-selection-policy-v1",
        "policy_id": "stock-r-v2.unique-direct-prune",
        "query_digest_sha256": canonical_sha256(query),
        "selector": "EXACTLY_ONE_DIRECT_PRUNE",
        "outcome_free": True,
        "forbidden_input_prefixes": ["runtime.trials", "runtime.outcomes"],
    }
    precommit = make_precommit(query, policy, recorded_at_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC))
    capture_contract = {
        "schema": "rac-stock-r-v2-capture-contract-v1",
        "query_digest_sha256": precommit["query_digest_sha256"],
        "selection_policy_sha256": precommit["selection_policy_sha256"],
        "source_closure_sha256": query["source_closure_sha256"],
        "build_closure_sha256": query["build_closure_sha256"],
        "backend": "fentry+fexit",
        "target_comm": "rac-v2-witness",
        "program_name": identity["program_name"],
        "trial_count": args.trials,
        "outcome_free_selection": True,
    }
    _atomic_json(query_path, query)
    _atomic_json(policy_path, policy)
    _atomic_json(precommit_path, precommit)
    _atomic_json(root / "contract" / "capture-contract.json", capture_contract)
    print(precommit["query_digest_sha256"])
    return 0


def seal_runtime(args: argparse.Namespace) -> int:
    root = args.output.resolve()
    query = _read_json(root / "query" / "query.json")
    runtime_path = root / "raw" / "runtime.json"
    runtime = _read_json(runtime_path)
    xlated_path = args.xlated.resolve()
    if not xlated_path.is_file():
        raise StockRV2Error("--xlated must be a readable regular file")
    identity = runtime.get("identity")
    if not isinstance(identity, dict):
        raise StockRV2Error("runtime.identity must be an object")
    static = query.get("identity")
    if not isinstance(static, dict):
        raise StockRV2Error("query.identity must be an object")
    for field, expected in static.items():
        if identity.get(field) != expected:
            raise StockRV2Error(f"runtime identity conflicts with precommitted {field}")
    identity["xlated_sha256"] = _sha256_file(xlated_path)
    _atomic_json(runtime_path, runtime)
    return 0


def prove_outcomes(args: argparse.Namespace) -> int:
    root = args.output.resolve()
    proof_path = root / "proof" / "must-outcome-proof.json"
    if proof_path.exists():
        raise StockRV2Error("must-outcome proof already exists; use a new output directory")
    proof = make_must_outcome_proof(
        _read_json(root / "query" / "query.json"),
        _read_json(root / "raw" / "runtime.json"),
    )
    _atomic_json(proof_path, proof)
    print(canonical_sha256(proof))
    return 0


def bind_history_case(args: argparse.Namespace) -> int:
    root = args.output.resolve()
    binding_path = root / "proof" / "history-case-binding.json"
    if binding_path.exists():
        raise StockRV2Error("history-case binding already exists; use a new output directory")
    proof = _read_json(root / "proof" / "must-outcome-proof.json")
    binding = make_history_case_binding_from_events(
        _read_json(root / "query" / "query.json"),
        _read_jsonl(root / "raw" / "events.jsonl"),
        _read_json(root / "raw" / "runtime.json"),
        proof,
    )
    _atomic_json(binding_path, binding)
    print(canonical_sha256(binding))
    return 0


def audit(args: argparse.Namespace) -> int:
    root = args.output.resolve()
    report = audit_bundle(root)
    _atomic_json(root / "audit" / "audit.json", report)
    print(report["assessment"]["status"])
    return 0 if report["assessment"]["status"] != "INVALID_EVIDENCE" else 1


def manifest(args: argparse.Namespace) -> int:
    root = args.output.resolve()
    manifest_path = root / "MANIFEST.json"
    checksum_path = root / "CHECKSUMS.sha256"
    excluded = {manifest_path.resolve(), checksum_path.resolve()}
    entries = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.resolve() in excluded:
            continue
        rel = path.relative_to(root).as_posix()
        entries.append({"path": rel, "sha256": _sha256_file(path), "size": path.stat().st_size})
    document = {"schema": "rac-stock-r-v2-manifest-v1", "entries": entries}
    _atomic_json(manifest_path, document)
    checksums = [f"{entry['sha256']}  {entry['path']}" for entry in entries]
    checksums.append(f"{_sha256_file(manifest_path)}  MANIFEST.json")
    checksum_path.write_text("\n".join(checksums) + "\n", encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    source_parser = subparsers.add_parser("source-closure", help="copy and manifest the V2 source closure")
    source_parser.add_argument("output", type=Path)
    source_parser.add_argument("--source-root", required=True, type=Path)
    source_parser.add_argument("--source", required=True, action="append", type=Path)
    source_parser.set_defaults(handler=source_closure)

    artifact_parser = subparsers.add_parser("artifact-closure", help="copy and manifest the V2 build closure")
    artifact_parser.add_argument("output", type=Path)
    artifact_parser.add_argument("--artifact", required=True, action="append")
    artifact_parser.set_defaults(handler=artifact_closure)

    prepare_parser = subparsers.add_parser("prepare", help="write a prospective V2 precommit")
    prepare_parser.add_argument("output", type=Path)
    prepare_parser.add_argument("--object", required=True, type=Path)
    prepare_parser.add_argument("--btf", required=True, type=Path)
    prepare_parser.add_argument("--source-manifest", required=True, type=Path)
    prepare_parser.add_argument("--artifact-manifest", required=True, type=Path)
    prepare_parser.add_argument("--kernel-release", required=True)
    prepare_parser.add_argument("--trials", type=int, default=4)
    prepare_parser.set_defaults(handler=prepare)

    seal_parser = subparsers.add_parser("seal-runtime", help="bind runtime to the pinned xlated dump")
    seal_parser.add_argument("output", type=Path)
    seal_parser.add_argument("--xlated", required=True, type=Path)
    seal_parser.set_defaults(handler=seal_runtime)

    proof_parser = subparsers.add_parser("prove-outcomes", help="write the checked V2 must-outcome proof")
    proof_parser.add_argument("output", type=Path)
    proof_parser.set_defaults(handler=prove_outcomes)

    binding_parser = subparsers.add_parser("bind-history-case", help="write the checked V2 history-case binding")
    binding_parser.add_argument("output", type=Path)
    binding_parser.set_defaults(handler=bind_history_case)

    audit_parser = subparsers.add_parser("audit", help="audit one V2 bundle")
    audit_parser.add_argument("output", type=Path)
    audit_parser.set_defaults(handler=audit)

    manifest_parser = subparsers.add_parser("manifest", help="write a V2 byte manifest")
    manifest_parser.add_argument("output", type=Path)
    manifest_parser.set_defaults(handler=manifest)

    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except StockRV2Error as exc:
        print(f"stock-r-v2: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
