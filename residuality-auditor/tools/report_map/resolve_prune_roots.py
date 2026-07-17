"""Resolve direct abstract states to final operational prune roots."""
from __future__ import annotations

from typing import Any


def resolve(state_hash: str, graph: dict[str, Any]) -> list[str]:
    outgoing = {edge["current"]: edge["retained"] for edge in graph.get("edges", [])}
    seen = set()
    cur = state_hash
    while cur in outgoing:
        if cur in seen:
            return []
        seen.add(cur)
        cur = outgoing[cur]
    return [cur]
