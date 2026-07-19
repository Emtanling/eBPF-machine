"""Markdown renderer for legacy-adapter Definition 2 proof reports."""
from __future__ import annotations

from typing import Any

from tools.proof.verdict import DEFINITION2_CHECKS


def _fmt(value: bool) -> str:
    return "yes" if value else "no"


def render(report: dict[str, Any]) -> str:
    lines = [
        "# Legacy-Adapter Definition 2 Check for a Frozen Stock-Linux Tuple",
        "",
        f"Verdict: `{report['verdict']}`",
        "",
        "| # | Check | Pass | Evidence |",
        "|---:|---|---|---|",
    ]
    labels = {
        "artifact_accepted": "fixed artifact accepted by verifier",
        "identity_consistent": "object/program/kernel/BTF/config identity consistent",
        "concrete_states_reachable": "two concrete states reachable",
        "context_same": "context same",
        "selected_state_different": "selected state different",
        "same_suffix": "same suffix",
        "suffix_outputs_differ": "same-suffix outputs differ",
        "same_actual_report_cell": "same actual computed report cell",
        "unique_cell_on_chosen_fiber": "unique-cell on chosen fiber",
        "behavioral_quotient_different": "behavioral quotient different",
        "factorization_failure": "factorization failure",
        "stock_linux_four_checks": "four legacy-adapter factorization checks (not real-Linux R certificates)",
        "evidence_hashes_match": "all evidence hashes match",
    }
    for index, name in enumerate(DEFINITION2_CHECKS, start=1):
        item = report["checks"].get(name, {})
        evidence = item.get("evidence", "") if isinstance(item, dict) else ""
        passed = item.get("passed") is True if isinstance(item, dict) else bool(item)
        lines.append(f"| {index} | {labels[name]} | {_fmt(passed)} | {evidence} |")
    reasons = report.get("reasons") or []
    if reasons:
        lines.extend(["", "## Blocking reasons", ""])
        lines.extend(f"- `{reason}`" for reason in reasons)
    lines.extend([
        "",
        "## Scope",
        "",
        "This report replays a legacy adapter on the frozen tuple represented by the supplied evidence bundle only. It is not a verdict about real Linux behavior or a real-Linux R verdict, and it does not establish stable must outcomes, a documented Linux functional-report contract, verifier unsoundness, a vulnerability, W, or a full weird machine.",
    ])
    return "\n".join(lines) + "\n"
