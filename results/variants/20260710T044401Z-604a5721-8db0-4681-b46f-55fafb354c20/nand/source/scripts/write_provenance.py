#!/usr/bin/env python3
"""Write one content-addressed, run-scoped variant provenance manifest."""

import argparse
import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path


SCHEMA = "weirdmachinebpf.provenance/v2"
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
LABELS = ("nand", "ablation_cap64", "ablation_k2_sentinel", "baseline_nand")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_utc_timestamp(value: str) -> str:
    if not value.endswith("Z"):
        raise argparse.ArgumentTypeError("timestamp must end in Z")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid ISO-8601 timestamp: {exc}") from exc
    return value


def binding(results_dir: Path, path: Path) -> dict[str, str]:
    base = results_dir.resolve()
    resolved = path.resolve()
    try:
        rel = resolved.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"bound file must be inside {base}: {resolved}") from exc
    if not resolved.is_file():
        raise FileNotFoundError(f"bound file is missing: {resolved}")
    if resolved.stat().st_size == 0:
        raise ValueError(f"refusing to bind an empty file: {resolved}")
    return {"path": rel.as_posix(), "sha256": sha256_file(resolved)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", type=Path, default=Path("results"))
    parser.add_argument("--label", required=True, choices=LABELS)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--timestamp-utc", required=True, type=parse_utc_timestamp)
    parser.add_argument("--build-flags", required=True)
    parser.add_argument("--bpftool-loadall-exit", required=True, type=int)
    parser.add_argument("--environment", required=True, type=Path)
    parser.add_argument("--bpf-object", required=True, type=Path)
    parser.add_argument("--user-binary", required=True, type=Path)
    parser.add_argument("--verifier-log", required=True, type=Path)
    parser.add_argument("--xlated-dump", required=True, type=Path)
    parser.add_argument("--build-log", required=True, type=Path)
    parser.add_argument(
        "--source", required=True, action="append", nargs=2,
        metavar=("WORKSPACE_PATH", "SNAPSHOT_PATH"),
    )
    parser.add_argument("--result", required=True, action="append", type=Path)
    args = parser.parse_args()

    if not RUN_ID_RE.fullmatch(args.run_id):
        parser.error("run-id must contain only letters, digits, '.', '_' or '-'")
    if args.bpftool_loadall_exit != 0:
        parser.error("refusing to certify a variant that verifier loading rejected")

    results_dir = args.results_dir.resolve()
    results_dir.mkdir(parents=True, exist_ok=True)
    environment_snapshot = json.loads(args.environment.read_text(encoding="utf-8"))
    if not isinstance(environment_snapshot, dict):
        parser.error("environment JSON root must be an object")

    manifest = {
        "schema": SCHEMA,
        "run_id": args.run_id,
        "timestamp_utc": args.timestamp_utc,
        "label": args.label,
        "build_flags": args.build_flags,
        "bpftool_loadall_exit": args.bpftool_loadall_exit,
        "environment": {
            **binding(results_dir, args.environment),
            "snapshot": environment_snapshot,
        },
        "artifacts": {
            "bpf_object": binding(results_dir, args.bpf_object),
            "user_binary": binding(results_dir, args.user_binary),
            "verifier_log": binding(results_dir, args.verifier_log),
            "xlated_dump": binding(results_dir, args.xlated_dump),
            "build_log": binding(results_dir, args.build_log),
        },
        "source_snapshot": [
            {
                "workspace_path": workspace_path,
                **binding(results_dir, Path(snapshot_path)),
            }
            for workspace_path, snapshot_path in args.source
        ],
        "results": [binding(results_dir, path) for path in args.result],
    }

    output = results_dir / f"{args.label}.provenance.json"
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, output)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
