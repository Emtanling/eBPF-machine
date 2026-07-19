"""Independent bounded oracle for synthetic CRL worlds."""
from __future__ import annotations

from typing import Any


class EBRCContextOracleError(ValueError):
    """A synthetic CRL oracle input is malformed."""


def contextual_nonfactor_holds(world: dict[str, Any]) -> bool:
    """Evaluate the bounded CRL preservation condition without checker rules."""

    if not isinstance(world, dict):
        raise EBRCContextOracleError("world must be an object")
    if world.get("source_nonfactor") is not True:
        return False
    obligations = world.get("obligations")
    if not isinstance(obligations, dict) or any(value is not True for value in obligations.values()):
        return False
    history_map = world.get("history_map")
    target_histories = world.get("target_histories")
    observer = world.get("observer")
    if not isinstance(history_map, dict) or not isinstance(target_histories, dict) or not isinstance(observer, dict):
        raise EBRCContextOracleError("world requires history_map, target_histories, and observer")
    mapped = []
    for source in world.get("source_histories", []):
        target = history_map.get(source)
        if not isinstance(target, str) or target not in target_histories:
            return False
        outcomes = target_histories[target]
        if not isinstance(outcomes, list) or len(outcomes) != 1:
            return False
        mapped.append(outcomes[0])
    if len(mapped) != 2 or mapped[0] == mapped[1]:
        return False
    observations = [observer.get(str(outcome)) for outcome in mapped]
    return all(observation is not None for observation in observations) and observations[0] != observations[1]


def positive_synthetic_world() -> dict[str, Any]:
    return {
        "source_nonfactor": True,
        "source_histories": ["history.source.0", "history.source.1"],
        "history_map": {
            "history.source.0": "history.target.0",
            "history.source.1": "history.target.1",
        },
        "target_histories": {
            "history.target.0": [0],
            "history.target.1": [1],
        },
        "observer": {"0": "left", "1": "right"},
        "obligations": {
            "source_certificate": True,
            "source_target_scope_distinct_or_identity_marked": True,
            "instruction_correspondence_total_on_witness": True,
            "footprint_effect_disjoint": True,
            "collision_preserved": True,
            "common_suffix_preserved": True,
            "must_outcomes_preserved": True,
            "observer_reflected": True,
            "report_cell_preserved": True,
            "frontier_preserved": True,
            "history_map_total": True,
            "target_conformance_bridge": True,
            "outcome_independent_selection": True,
            "no_target_terminal_verdict": True,
        },
    }
