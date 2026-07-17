"""Verify event identity against frozen runtime/program identity."""
from __future__ import annotations

from typing import Any


def verify_identity(event: dict[str, Any], identity: dict[str, Any]) -> dict[str, Any]:
    checks = {
        "program_name": event.get("program_name") == identity.get("program_name"),
        "program_id": event.get("program_id") == identity.get("program_id"),
        "program_tag": event.get("program_tag") == identity.get("program_tag"),
        "program_pin": event.get("program_pin") == identity.get("program_pin"),
        "object_sha256": event.get("object_sha256") == identity.get("object_sha256"),
        "xlated_sha256": event.get("xlated_sha256") == (identity.get("xlated_sha256") or identity.get("recorded_xlated_sha256")),
    }
    return {"schema": "rac-event-identity-check-v1", "passed": all(checks.values()), "checks": checks}
