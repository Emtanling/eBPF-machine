#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any


class EnrichEventsError(RuntimeError):
    pass


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _first_token(path: Path) -> str | None:
    text = path.read_text(encoding="utf-8").strip()
    return text.split()[0] if text else None


def _program_info_record(path: Path) -> dict[str, Any]:
    data = _read_json(path)
    if isinstance(data, list):
        if not data:
            raise EnrichEventsError(f"empty program-info JSON: {path}")
        data = data[0]
    if not isinstance(data, dict):
        raise EnrichEventsError(f"program-info JSON is not an object: {path}")
    return data


def load_identity(
    runtime_path: Path,
    program_info_path: Path,
    object_sha_path: Path,
    program_pin_path: Path,
    xlated_sha_path: Path,
) -> dict[str, Any]:
    runtime = _read_json(runtime_path)
    info = _program_info_record(program_info_path)
    pin = program_pin_path.read_text(encoding="utf-8").strip() or runtime.get("program_pin")
    identity = {
        "object_sha256": _first_token(object_sha_path) or runtime.get("object_sha256"),
        "program_id": info.get("id", runtime.get("program_id")),
        "program_tag": info.get("tag", runtime.get("program_tag")),
        "program_pin": pin,
        "xlated_sha256": _first_token(xlated_sha_path) or runtime.get("xlated_sha256"),
    }
    missing = [key for key, value in identity.items() if value in (None, "")]
    if missing:
        raise EnrichEventsError(f"missing identity fields: {', '.join(missing)}")
    identity["program_id"] = int(identity["program_id"])
    return identity


def _merge_identity(event: dict[str, Any], identity: dict[str, Any]) -> None:
    for key, value in identity.items():
        current = event.get(key)
        if current not in (None, "", value):
            raise EnrichEventsError(f"raw event already has conflicting {key}: {current!r} != {value!r}")
        event[key] = value
    event["event_identity_source"] = "run_linux_r_enrichment_v1"


def enrich_events(
    raw_events_path: Path,
    output_events_path: Path,
    runtime_path: Path,
    program_info_path: Path,
    object_sha_path: Path,
    program_pin_path: Path,
    xlated_sha_path: Path,
) -> None:
    identity = load_identity(runtime_path, program_info_path, object_sha_path, program_pin_path, xlated_sha_path)
    output_events_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=output_events_path.name + ".",
        suffix=".tmp",
        dir=str(output_events_path.parent),
        text=True,
    )
    try:
        with raw_events_path.open("r", encoding="utf-8") as src, os.fdopen(fd, "w", encoding="utf-8") as dst:
            for lineno, line in enumerate(src, 1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise EnrichEventsError(f"{raw_events_path}:{lineno}: invalid JSON: {exc}") from exc
                if isinstance(event, dict) and event.get("event") == "prune_hit":
                    _merge_identity(event, identity)
                json.dump(event, dst, sort_keys=False, separators=(",", ":"))
                dst.write("\n")
        os.replace(tmp_name, output_events_path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Bind raw verifier events to the frozen runtime/program identity.")
    parser.add_argument("raw_events", type=Path)
    parser.add_argument("output_events", type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--program-info", required=True, type=Path)
    parser.add_argument("--object-sha", required=True, type=Path)
    parser.add_argument("--program-pin", required=True, type=Path)
    parser.add_argument("--xlated-sha", required=True, type=Path)
    args = parser.parse_args()
    enrich_events(
        args.raw_events,
        args.output_events,
        args.runtime,
        args.program_info,
        args.object_sha,
        args.program_pin,
        args.xlated_sha,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
