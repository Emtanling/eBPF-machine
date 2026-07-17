from __future__ import annotations

import json
from typing import Any


def _fmt_word(word: list[str] | tuple[str, ...] | None) -> str:
    if not word:
        return "ε"
    return " · ".join(f"`{x}`" for x in word)


def _fmt_bool(value: Any) -> str:
    if value is True:
        return "**yes**"
    if value is False:
        return "**no**"
    return "not assessed"


def render_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines: list[str] = [
        f"# Residuality audit: {result['model']}",
        "",
        "## Claim summary",
        "",
        "| Claim | Result |",
        "|---|---|",
        f"| A — accepted artifact/model flag | {_fmt_bool(summary['A_acceptance'])} |",
        f"| C — output-witnessed same-suffix distinction | {_fmt_bool(summary['C_output_witnessed'])} |",
        f"| P — bounded programmability | {summary['P_status']} |",
        f"| R — unique-cell report criterion assessable | {_fmt_bool(summary['R_assessable'])} |",
        f"| R — report non-factorization | {_fmt_bool(summary['R_non_factorization'])} |",
        f"| R — output-witnessed residual collision | {_fmt_bool(summary['R_output_witnessed'])} |",
        f"| W — policy candidate under supplied certificate | {_fmt_bool(summary['W_candidate'])} |",
        "",
        "## Future-observation quotient",
        "",
        f"Stable classes: **{len(result['behavioral_quotient']['classes'])}** over "
        f"{result['behavioral_quotient']['states']} states and "
        f"{result['behavioral_quotient']['actions']} actions.",
        "",
    ]
    for index, block in enumerate(result["behavioral_quotient"]["classes"]):
        lines.append(f"- Q{index}: {', '.join(f'`{state}`' for state in block)}")

    c = result["C"]
    lines += ["", "## C witness", ""]
    witness = c.get("shortest_output_witness")
    if witness:
        lines += [
            f"Shortest witness: `{witness['left_state']}` vs `{witness['right_state']}` with "
            f"{_fmt_word(witness['word'])}.",
            "",
            f"- Left outputs: `{json.dumps(witness['left_execution']['outputs'], ensure_ascii=False)}`",
            f"- Right outputs: `{json.dumps(witness['right_execution']['outputs'], ensure_ascii=False)}`",
        ]
    else:
        lines.append("No output-witnessed same-suffix distinction was found in the declared context fibers.")

    r = result["R"]
    lines += ["", "## R factorization audit", ""]
    if not r["assessable"]:
        lines.append("R is not assessable because the unique-cell report contract is missing or invalid:")
        for error in r["errors"]:
            lines.append(f"- {error}")
    else:
        lines += [
            f"Report source: `{r['source']}`",
            "",
            f"Behavioral factorization holds: {_fmt_bool(r['factorizes'])}",
            f"Output-witnessed R collision exists: {_fmt_bool(r['output_witnessed_R'])}",
        ]
        if r["output_witnessed_collisions"]:
            first = r["output_witnessed_collisions"][0]
            w = first["witness"]
            lines += [
                "",
                f"First shortest reported collision: cell `{first['cell']}`, states "
                f"`{first['states'][0]}` and `{first['states'][1]}`, suffix {_fmt_word(w['word'])}.",
                f"Left outputs: `{json.dumps(w['left_execution']['outputs'], ensure_ascii=False)}`",
                f"Right outputs: `{json.dumps(w['right_execution']['outputs'], ensure_ascii=False)}`",
            ]
        lines += ["", "### Residuality spectrum", "", "| Depth k | Behavior classes | Max classes in one report cell |", "|---:|---:|---:|"]
        for row in r["residuality_spectrum"]:
            lines.append(
                f"| {row['depth']} | {row['behavior_classes']} | {row['max_classes_in_one_cell']} |"
            )

    gate = result["gate_certificate"]
    lines += ["", "## Gate-basis certificate", ""]
    if not gate["supplied"]:
        lines.append("No gate certificate supplied.")
    else:
        lines += [
            f"Gate: **{gate['name']}**",
            f"Reset verified: {_fmt_bool(gate['reset_verified'])}",
            f"Truth table verified: {_fmt_bool(gate['truth_table_verified'])}",
            "",
            "| Input | Word | Expected | Observed | Pass |",
            "|---|---|---:|---:|---|",
        ]
        for row in gate["rows"]:
            lines.append(
                f"| `{row['input']}` | {_fmt_word(row['word'])} | {row['expected_bit']} | "
                f"{row['observed_bit']} | {_fmt_bool(row['passed'])} |"
            )
        lines += ["", f"> {gate['scope_note']}"]

    lines += ["", "## Scope limits", ""]
    for item in result["limitations"]:
        lines.append(f"- {item}")
    if result.get("notes"):
        lines += ["", "## Model notes", "", result["notes"]]
    return "\n".join(lines) + "\n"
