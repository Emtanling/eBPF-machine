"""Parse raw/enriched prune-event JSONL with line references."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_jsonl(path: Path) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    errors = 0
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            errors += 1
            continue
        if isinstance(item, dict):
            item["_line"] = line_no
            rows.append(item)
        else:
            errors += 1
    return rows, errors


def raw_event_ref(path: Path, event: dict[str, Any]) -> dict[str, Any]:
    return {"path": path.name, "line": event.get("_line"), "sha256": sha256_file(path)}
