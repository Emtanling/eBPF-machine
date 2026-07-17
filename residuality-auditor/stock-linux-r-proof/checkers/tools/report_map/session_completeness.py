"""Check verifier capture session completeness for unique-cell claims."""
from __future__ import annotations

from typing import Any


def check_session(rows: list[dict[str, Any]], *, parse_errors: int, join_insn: int, program_name: str, runtime: dict[str, Any]) -> dict[str, Any]:
    metadata = [r for r in rows if r.get("event") == "metadata"]
    complete = [r for r in rows if r.get("event") == "capture_complete"]
    prune_events = [r for r in rows if r.get("event") == "prune_hit"]
    session_id = metadata[0].get("session_id") if metadata else None
    complete_doc = complete[-1] if complete else {}
    event_session_consistent = bool(session_id) and all(e.get("session_id") == session_id for e in prune_events)
    target_program_events = [e for e in prune_events if e.get("program_name") == program_name]
    target_frontier_events = [e for e in target_program_events if int(e.get("visit_insn", -1)) == int(join_insn)]
    runtime_runs = runtime.get("runs") if isinstance(runtime.get("runs"), list) else []
    checks = {
        "metadata_present": bool(metadata),
        "capture_complete_present": bool(complete),
        "session_id_present": bool(session_id),
        "event_session_consistent": event_session_consistent,
        "verifier_invocation_started": bool(runtime_runs),
        "verifier_invocation_completed": len(runtime_runs) >= 2,
        "capture_completed": complete_doc.get("completed") is True,
        "ringbuf_lost_events_zero": int(complete_doc.get("ringbuf_lost_events", -1)) == 0,
        "collector_parse_errors_zero": int(complete_doc.get("collector_parse_errors", parse_errors)) == 0 and parse_errors == 0,
        "target_program_events_present": len(target_program_events) > 0,
        "target_frontier_events_complete": len(target_frontier_events) == 1,
    }
    return {
        "schema": "rac-session-completeness-v1",
        "session_id": session_id,
        "capture_started_ns": metadata[0].get("capture_started_ns") if metadata else None,
        "capture_ended_ns": complete_doc.get("capture_ended_ns"),
        "verifier_invocation_started": checks["verifier_invocation_started"],
        "verifier_invocation_completed": checks["verifier_invocation_completed"],
        "ringbuf_lost_events": int(complete_doc.get("ringbuf_lost_events", -1)),
        "events_lost": int(complete_doc.get("ringbuf_lost_events", -1)),
        "collector_parse_errors": parse_errors + int(complete_doc.get("collector_parse_errors", 0) or 0),
        "target_program_events": len(target_program_events),
        "target_frontier_events": len(target_frontier_events),
        "checks": checks,
        "session_complete": all(checks.values()),
        "result": "SESSION_CAPTURE_COMPLETE" if all(checks.values()) else "SESSION_CAPTURE_INCOMPLETE",
    }
