"""Markdown renderer for report maps."""
from __future__ import annotations

from typing import Any


def render(report: dict[str, Any]) -> str:
    lines = ["# Prune Report Map", "", f"Result: `{report['unique_cell_check']['result']}`", "", "| Sigma | Direct state | Retained representative |", "|---|---|---|"]
    coverage = report["coverage_relation"]["cases"]
    for case in ("a=0", "a=1"):
        item = coverage[case]
        reps = ", ".join(item["retained_representatives"]) or "<none>"
        lines.append(f"| `{case}` | `{item['direct_abstract_role']}:{item['direct_state_hash']}` | `{reps}` |")
    lines.append("")
    lines.append("The map is derived from the frontier prune event, local concretization memberships, and restricted current-to-retained subsumption.")
    return "\n".join(lines) + "\n"
