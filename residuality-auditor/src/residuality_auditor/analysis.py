from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
from itertools import combinations
from typing import Any, Iterable

from .model import Model, canonical_output


@dataclass(frozen=True)
class Execution:
    defined: bool
    final_state: str
    outputs: tuple[Any, ...]
    undefined_action: str | None = None


@dataclass(frozen=True)
class Witness:
    left_state: str
    right_state: str
    word: tuple[str, ...]
    left_execution: Execution
    right_execution: Execution
    distinction: str


def execute(model: Model, start: str, word: Iterable[str]) -> Execution:
    state = start
    outputs: list[Any] = []
    for action in word:
        transition = model.step(state, action)
        if transition is None:
            return Execution(
                defined=False,
                final_state=state,
                outputs=tuple(outputs),
                undefined_action=action,
            )
        outputs.append(transition.output)
        state = transition.next_state
    return Execution(defined=True, final_state=state, outputs=tuple(outputs))


def _partition_index(blocks: list[tuple[str, ...]]) -> dict[str, int]:
    return {state: index for index, block in enumerate(blocks) for state in block}


def refine_once(model: Model, blocks: list[tuple[str, ...]]) -> list[tuple[str, ...]]:
    block_of = _partition_index(blocks)
    groups: dict[tuple[Any, ...], list[str]] = {}
    for state in model.states:
        signature: list[Any] = []
        for action in model.actions:
            transition = model.step(state, action)
            if transition is None:
                signature.append(("undefined",))
            else:
                signature.append(
                    ("defined", canonical_output(transition.output), block_of[transition.next_state])
                )
        groups.setdefault(tuple(signature), []).append(state)
    return sorted((tuple(sorted(group)) for group in groups.values()), key=lambda b: b[0])


def behavioral_partitions(model: Model, max_rounds: int | None = None) -> list[list[tuple[str, ...]]]:
    """Compute depth-0 through stable future-observation partitions.

    Round k corresponds to equivalence for operation words of length at most k.
    The last partition is stable unless max_rounds stops the computation early.
    """

    partitions: list[list[tuple[str, ...]]] = [[tuple(sorted(model.states))]]
    rounds = 0
    while True:
        if max_rounds is not None and rounds >= max_rounds:
            break
        next_blocks = refine_once(model, partitions[-1])
        rounds += 1
        if next_blocks == partitions[-1]:
            break
        partitions.append(next_blocks)
    return partitions


def _distinguishing_witness(
    model: Model, left: str, right: str, *, output_only: bool
) -> Witness | None:
    """Return a shortest same-suffix witness using BFS on the state-pair product."""

    queue: deque[tuple[str, str, tuple[str, ...]]] = deque([(left, right, tuple())])
    visited = {(left, right)}
    while queue:
        s0, s1, prefix = queue.popleft()
        for action in model.actions:
            t0, t1 = model.step(s0, action), model.step(s1, action)
            word = prefix + (action,)
            if t0 is None or t1 is None:
                if not output_only and (t0 is None) != (t1 is None):
                    return Witness(
                        left_state=left,
                        right_state=right,
                        word=word,
                        left_execution=execute(model, left, word),
                        right_execution=execute(model, right, word),
                        distinction="definedness",
                    )
                continue
            if canonical_output(t0.output) != canonical_output(t1.output):
                return Witness(
                    left_state=left,
                    right_state=right,
                    word=word,
                    left_execution=execute(model, left, word),
                    right_execution=execute(model, right, word),
                    distinction="output",
                )
            pair = (t0.next_state, t1.next_state)
            if pair not in visited:
                visited.add(pair)
                queue.append((pair[0], pair[1], word))
    return None


def shortest_witness(model: Model, left: str, right: str) -> Witness | None:
    return _distinguishing_witness(model, left, right, output_only=False)


def shortest_output_witness(model: Model, left: str, right: str) -> Witness | None:
    return _distinguishing_witness(model, left, right, output_only=True)


def _witness_to_dict(witness: Witness | None) -> dict[str, Any] | None:
    if witness is None:
        return None
    return asdict(witness)


def _unique_report_partition(model: Model) -> tuple[bool, list[str], dict[str, str]]:
    if model.report is None:
        return False, ["no report specification supplied"], {}
    errors: list[str] = []
    fiber = set(model.report.fiber_states)
    membership: dict[str, list[str]] = {state: [] for state in fiber}
    for cell, members in model.report.cells.items():
        for state in members:
            if state not in fiber:
                errors.append(f"cell {cell!r} contains {state!r}, which is outside report.fiber_states")
                continue
            membership[state].append(cell)
    for state, labels in membership.items():
        if len(labels) != 1:
            errors.append(f"state {state!r} belongs to {len(labels)} report cells; exactly one is required")
    return not errors, errors, {state: labels[0] for state, labels in membership.items() if len(labels) == 1}


def _analyze_c(model: Model, stable_block_of: dict[str, int]) -> dict[str, Any]:
    fiber_results: list[dict[str, Any]] = []
    best: Witness | None = None
    for name, states in model.context_fibers.items():
        pairs = 0
        output_pairs = 0
        fiber_best: Witness | None = None
        for left, right in combinations(states, 2):
            if stable_block_of[left] == stable_block_of[right]:
                continue
            pairs += 1
            witness = shortest_output_witness(model, left, right)
            if witness is not None:
                output_pairs += 1
                if fiber_best is None or len(witness.word) < len(fiber_best.word):
                    fiber_best = witness
                if best is None or len(witness.word) < len(best.word):
                    best = witness
        fiber_results.append(
            {
                "name": name,
                "states": list(states),
                "behaviorally_distinct_pairs": pairs,
                "output_witnessed_pairs": output_pairs,
                "shortest_output_witness": _witness_to_dict(fiber_best),
            }
        )
    return {
        "established": best is not None,
        "shortest_output_witness": _witness_to_dict(best),
        "fibers": fiber_results,
    }


def _analyze_r(
    model: Model,
    partitions: list[list[tuple[str, ...]]],
    stable_block_of: dict[str, int],
) -> dict[str, Any]:
    valid, errors, report_map = _unique_report_partition(model)
    if not valid:
        return {
            "assessable": False,
            "factorizes": None,
            "non_factorization": None,
            "output_witnessed_R": None,
            "errors": errors,
        }
    assert model.report is not None
    collisions: list[dict[str, Any]] = []
    output_collisions: list[dict[str, Any]] = []
    for cell, members in model.report.cells.items():
        in_fiber = [s for s in members if s in report_map]
        for left, right in combinations(in_fiber, 2):
            if stable_block_of[left] == stable_block_of[right]:
                continue
            witness = shortest_witness(model, left, right)
            output_witness = shortest_output_witness(model, left, right)
            collisions.append(
                {
                    "cell": cell,
                    "states": [left, right],
                    "witness": _witness_to_dict(witness),
                }
            )
            if output_witness is not None:
                output_collisions.append(
                    {
                        "cell": cell,
                        "states": [left, right],
                        "witness": _witness_to_dict(output_witness),
                    }
                )

    collisions.sort(
        key=lambda item: (
            len(item["witness"]["word"]) if item["witness"] is not None else 10**9,
            item["cell"],
            item["states"],
        )
    )
    output_collisions.sort(
        key=lambda item: (
            len(item["witness"]["word"]) if item["witness"] is not None else 10**9,
            item["cell"],
            item["states"],
        )
    )

    spectrum: list[dict[str, Any]] = []
    for depth, blocks in enumerate(partitions):
        block_of = _partition_index(blocks)
        cells: dict[str, int] = {}
        for cell, members in model.report.cells.items():
            relevant = [state for state in members if state in report_map]
            cells[cell] = len({block_of[state] for state in relevant})
        spectrum.append(
            {
                "depth": depth,
                "behavior_classes": len(blocks),
                "classes_per_report_cell": cells,
                "max_classes_in_one_cell": max(cells.values(), default=0),
            }
        )

    return {
        "assessable": True,
        "source": model.report.source,
        "fiber_states": list(model.report.fiber_states),
        "factorizes": not collisions,
        "non_factorization": bool(collisions),
        "output_witnessed_R": bool(output_collisions),
        "collisions": collisions,
        "output_witnessed_collisions": output_collisions,
        "residuality_spectrum": spectrum,
        "errors": [],
    }


def _analyze_gate_certificate(model: Model) -> dict[str, Any]:
    cert = model.gate_certificate
    if cert is None:
        return {
            "supplied": False,
            "reset_verified": None,
            "truth_table_verified": None,
            "basis_evidence": "not assessed",
        }
    reset_failures: list[dict[str, Any]] = []
    for state in cert.admissible_states:
        run = execute(model, state, cert.reset_word)
        if not run.defined or run.final_state != cert.canonical_state:
            reset_failures.append({"start": state, "execution": asdict(run)})

    rows: list[dict[str, Any]] = []
    all_rows_pass = True
    for input_name, word in cert.input_words.items():
        run = execute(model, cert.canonical_state, word)
        observed_bit: str | None = None
        if run.defined and run.outputs:
            observed_bit = cert.output_to_bit.get(canonical_output(run.outputs[-1]))
        expected = cert.expected_bits[input_name]
        passed = run.defined and observed_bit == expected
        all_rows_pass = all_rows_pass and passed
        rows.append(
            {
                "input": input_name,
                "word": list(word),
                "expected_bit": expected,
                "observed_bit": observed_bit,
                "passed": passed,
                "execution": asdict(run),
            }
        )
    reset_ok = not reset_failures
    truth_ok = all_rows_pass
    return {
        "supplied": True,
        "name": cert.name,
        "reset_verified": reset_ok,
        "reset_failures": reset_failures,
        "truth_table_verified": truth_ok,
        "rows": rows,
        "basis_evidence": "verified resettable observed gate basis" if reset_ok and truth_ok else "failed",
        "scope_note": (
            "This checks a finite gate-basis certificate only. It does not discharge the paper's "
            "fixed-interpreter scheduling and frame-preservation obligations for full node P."
        ),
    }


def _analyze_policy(model: Model) -> dict[str, Any]:
    cert = model.policy_certificate
    if cert is None:
        return {"supplied": False, "W_candidate": None, "cases": []}
    cases: list[dict[str, Any]] = []
    any_candidate = False
    for case in cert.cases:
        run = execute(model, case.start_state, case.word)
        effect: str | None
        if not run.defined:
            effect = None
        elif case.effect_from == "final_state":
            effect = run.final_state
        elif run.outputs:
            effect = str(run.outputs[-1])
        else:
            effect = None
        excluded = effect is not None and effect not in cert.allowed_effects
        candidate = (
            run.defined
            and excluded
            and case.linked_to_programmability
            and case.unintended
        )
        any_candidate = any_candidate or candidate
        cases.append(
            {
                "actor": case.actor,
                "word": list(case.word),
                "effect": effect,
                "policy_excluded": excluded,
                "linked_to_programmability": case.linked_to_programmability,
                "unintended": case.unintended,
                "W_candidate": candidate,
                "execution": asdict(run),
            }
        )
    return {
        "supplied": True,
        "allowed_effects": list(cert.allowed_effects),
        "W_candidate": any_candidate,
        "cases": cases,
        "scope_note": (
            "The tool checks the declared finite model and supplied linkage/unintendedness flags; "
            "it does not independently establish a real-world threat model."
        ),
    }


def analyze_model(model: Model, *, spectrum_depth: int | None = None) -> dict[str, Any]:
    if spectrum_depth is not None and spectrum_depth < 0:
        raise ValueError("spectrum_depth must be non-negative")
    # Compute to stability for the full quotient. If a spectrum bound is requested, retain
    # stable analysis and truncate only the displayed spectrum later.
    partitions = behavioral_partitions(model)
    stable_blocks = partitions[-1]
    stable_block_of = _partition_index(stable_blocks)
    c_result = _analyze_c(model, stable_block_of)
    r_result = _analyze_r(model, partitions, stable_block_of)
    if spectrum_depth is not None and r_result.get("assessable"):
        r_result["residuality_spectrum"] = [
            row for row in r_result["residuality_spectrum"] if row["depth"] <= spectrum_depth
        ]
    gate_result = _analyze_gate_certificate(model)
    policy_result = _analyze_policy(model)

    p_status = "not established"
    if gate_result.get("basis_evidence", "").startswith("verified"):
        p_status = "gate basis verified; full P requires separate interpreter obligations"

    return {
        "model": model.name,
        "notes": model.notes,
        "summary": {
            "A_acceptance": model.accepted,
            "C_output_witnessed": c_result["established"],
            "P_status": p_status,
            "R_assessable": r_result["assessable"],
            "R_non_factorization": r_result["non_factorization"],
            "R_output_witnessed": r_result["output_witnessed_R"],
            "W_candidate": policy_result["W_candidate"],
        },
        "behavioral_quotient": {
            "states": len(model.states),
            "actions": len(model.actions),
            "refinement_rounds": len(partitions) - 1,
            "classes": [list(block) for block in stable_blocks],
        },
        "C": c_result,
        "R": r_result,
        "gate_certificate": gate_result,
        "policy_certificate": policy_result,
        "limitations": [
            "Finite deterministic partial Mealy models only.",
            "R is assessable only with an explicit unique-cell report partition on the declared fiber.",
            "A modeled report partition is not evidence about Linux verifier computed cells.",
            "A gate certificate is not a proof of the full fixed-interpreter obligations for node P.",
            "Policy linkage and unintendedness remain declared evidence, not automatically inferred facts.",
        ],
    }
