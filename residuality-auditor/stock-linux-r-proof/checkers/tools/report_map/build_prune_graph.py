"""Build the operational current -> retained prune graph."""
from __future__ import annotations

from typing import Any


def build_graph(prune_edges: list[dict[str, Any]]) -> dict[str, Any]:
    edges = []
    nodes = set()
    for edge in prune_edges:
        current = edge["current_state_hash"]
        retained = edge["retained_state_hash"]
        nodes.add(current)
        nodes.add(retained)
        edges.append({"current": current, "retained": retained})
    current_nodes = {edge["current"] for edge in edges}
    retained_nodes = {edge["retained"] for edge in edges}
    roots = sorted(retained_nodes - current_nodes) or sorted(retained_nodes)
    return {"schema": "rac-prune-graph-v1", "nodes": sorted(nodes), "edges": edges, "retained_roots": roots}
