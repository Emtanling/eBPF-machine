"""Independent finite oracle for synthetic EBRC nonfactor models.

This module intentionally does not import the EBRC checker or proof rules.  It
enumerates the semantic definition directly, providing a small differential
oracle for tests and mutation experiments.
"""
from __future__ import annotations

import json
from typing import Any


class EBRCOracleError(ValueError):
    """A synthetic finite world violates the oracle input contract."""


def _outcome_key(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise EBRCOracleError("oracle outcome is not JSON-encodable") from exc


def enumerate_nonfactor_witnesses(world: Any) -> list[dict[str, Any]]:
    """Enumerate exact two-history witnesses by the semantic definition."""

    if not isinstance(world, dict):
        raise EBRCOracleError("world must be an object")
    histories = world.get("histories")
    observer = world.get("observer")
    if not isinstance(histories, list) or not isinstance(observer, dict):
        raise EBRCOracleError("world requires histories and observer")

    parsed: list[tuple[str, str, Any, Any]] = []
    seen: set[str] = set()
    for item in histories:
        if not isinstance(item, dict):
            raise EBRCOracleError("history must be an object")
        history_id = item.get("history_id")
        report_cell_id = item.get("report_cell_id")
        outcomes = item.get("outcomes")
        if (
            not isinstance(history_id, str)
            or not history_id
            or history_id in seen
            or not isinstance(report_cell_id, str)
            or not report_cell_id
            or not isinstance(outcomes, list)
        ):
            raise EBRCOracleError("history contract invalid")
        seen.add(history_id)
        if len(outcomes) != 1:
            continue
        outcome = outcomes[0]
        key = _outcome_key(outcome)
        observation = observer.get(key, outcome)
        parsed.append((history_id, report_cell_id, outcome, observation))

    witnesses: list[dict[str, Any]] = []
    for left_index, left in enumerate(parsed):
        for right in parsed[left_index + 1 :]:
            if left[1] != right[1] or left[3] == right[3]:
                continue
            witnesses.append(
                {
                    "history_ids": [left[0], right[0]],
                    "outcomes": [left[2], right[2]],
                    "report_cell_id": left[1],
                }
            )
    return witnesses
