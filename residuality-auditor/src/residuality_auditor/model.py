from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


class ModelError(ValueError):
    """Raised when a model violates the finite-state input contract."""


@dataclass(frozen=True)
class Transition:
    next_state: str
    output: Any


@dataclass(frozen=True)
class ReportSpec:
    fiber_states: tuple[str, ...]
    cells: Mapping[str, tuple[str, ...]]
    source: str


@dataclass(frozen=True)
class GateCertificate:
    name: str
    canonical_state: str
    admissible_states: tuple[str, ...]
    reset_word: tuple[str, ...]
    input_words: Mapping[str, tuple[str, ...]]
    expected_bits: Mapping[str, str]
    output_to_bit: Mapping[str, str]


@dataclass(frozen=True)
class PolicyCase:
    actor: str
    start_state: str
    word: tuple[str, ...]
    effect_from: str
    linked_to_programmability: bool
    unintended: bool


@dataclass(frozen=True)
class PolicyCertificate:
    allowed_effects: tuple[str, ...]
    cases: tuple[PolicyCase, ...]


@dataclass(frozen=True)
class Model:
    name: str
    accepted: bool
    states: tuple[str, ...]
    actions: tuple[str, ...]
    transitions: Mapping[str, Mapping[str, Transition]]
    context_fibers: Mapping[str, tuple[str, ...]]
    report: ReportSpec | None
    gate_certificate: GateCertificate | None
    policy_certificate: PolicyCertificate | None
    notes: str

    def step(self, state: str, action: str) -> Transition | None:
        return self.transitions.get(state, {}).get(action)


def _require_list_of_strings(value: Any, field: str, *, nonempty: bool = False, unique: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value):
        raise ModelError(f"{field} must be a list of non-empty strings")
    if nonempty and not value:
        raise ModelError(f"{field} must not be empty")
    if unique and len(set(value)) != len(value):
        raise ModelError(f"{field} contains duplicates")
    return tuple(value)


def _canonical_output(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def load_model(path: str | Path) -> Model:
    source_path = Path(path)
    try:
        raw = json.loads(source_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelError(f"cannot read model {source_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ModelError("model root must be a JSON object")

    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ModelError("name must be a non-empty string")
    accepted = raw.get("accepted")
    if not isinstance(accepted, bool):
        raise ModelError("accepted must be boolean")

    states = _require_list_of_strings(raw.get("states"), "states", nonempty=True)
    actions = _require_list_of_strings(raw.get("actions"), "actions", nonempty=True)
    state_set, action_set = set(states), set(actions)

    raw_transitions = raw.get("transitions")
    if not isinstance(raw_transitions, dict):
        raise ModelError("transitions must be an object keyed by state")
    unknown_transition_states = set(raw_transitions) - state_set
    if unknown_transition_states:
        raise ModelError(f"transitions contain unknown states: {sorted(unknown_transition_states)}")

    transitions: dict[str, dict[str, Transition]] = {s: {} for s in states}
    for state, action_map in raw_transitions.items():
        if not isinstance(action_map, dict):
            raise ModelError(f"transitions.{state} must be an object")
        unknown_actions = set(action_map) - action_set
        if unknown_actions:
            raise ModelError(f"transitions.{state} contains unknown actions: {sorted(unknown_actions)}")
        for action, item in action_map.items():
            if not isinstance(item, dict) or "next" not in item or "output" not in item:
                raise ModelError(f"transition {state}/{action} must contain next and output")
            next_state = item["next"]
            if next_state not in state_set:
                raise ModelError(f"transition {state}/{action} targets unknown state {next_state!r}")
            # Ensure output can be compared and serialized deterministically.
            _canonical_output(item["output"])
            transitions[state][action] = Transition(next_state=next_state, output=item["output"])

    context_fibers: dict[str, tuple[str, ...]] = {}
    raw_fibers = raw.get("context_fibers", {"all": list(states)})
    if not isinstance(raw_fibers, dict) or not raw_fibers:
        raise ModelError("context_fibers must be a non-empty object")
    for fiber_name, members in raw_fibers.items():
        if not isinstance(fiber_name, str) or not fiber_name:
            raise ModelError("context fiber names must be non-empty strings")
        parsed = _require_list_of_strings(members, f"context_fibers.{fiber_name}", nonempty=True)
        unknown = set(parsed) - state_set
        if unknown:
            raise ModelError(f"context_fibers.{fiber_name} contains unknown states: {sorted(unknown)}")
        context_fibers[fiber_name] = parsed

    report: ReportSpec | None = None
    raw_report = raw.get("report")
    if raw_report is not None:
        if not isinstance(raw_report, dict):
            raise ModelError("report must be an object")
        fiber_states = _require_list_of_strings(
            raw_report.get("fiber_states"), "report.fiber_states", nonempty=True
        )
        unknown = set(fiber_states) - state_set
        if unknown:
            raise ModelError(f"report.fiber_states contains unknown states: {sorted(unknown)}")
        raw_cells = raw_report.get("cells")
        if not isinstance(raw_cells, dict) or not raw_cells:
            raise ModelError("report.cells must be a non-empty object")
        cells: dict[str, tuple[str, ...]] = {}
        for cell, members in raw_cells.items():
            if not isinstance(cell, str) or not cell:
                raise ModelError("report cell names must be non-empty strings")
            parsed = _require_list_of_strings(members, f"report.cells.{cell}", nonempty=True)
            unknown = set(parsed) - state_set
            if unknown:
                raise ModelError(f"report.cells.{cell} contains unknown states: {sorted(unknown)}")
            cells[cell] = parsed
        source = raw_report.get("source", "unspecified")
        if not isinstance(source, str):
            raise ModelError("report.source must be a string")
        report = ReportSpec(fiber_states=fiber_states, cells=cells, source=source)

    gate_certificate: GateCertificate | None = None
    raw_gate = raw.get("gate_certificate")
    if raw_gate is not None:
        if not isinstance(raw_gate, dict):
            raise ModelError("gate_certificate must be an object")
        gate_name = raw_gate.get("name", "unnamed gate")
        canonical_state = raw_gate.get("canonical_state")
        if canonical_state not in state_set:
            raise ModelError("gate_certificate.canonical_state must name a model state")
        admissible_states = _require_list_of_strings(
            raw_gate.get("admissible_states", list(states)),
            "gate_certificate.admissible_states",
            nonempty=True,
        )
        unknown = set(admissible_states) - state_set
        if unknown:
            raise ModelError(f"gate certificate contains unknown admissible states: {sorted(unknown)}")
        reset_word = _require_list_of_strings(
            raw_gate.get("reset_word"), "gate_certificate.reset_word", nonempty=True
        )
        unknown = set(reset_word) - action_set
        if unknown:
            raise ModelError(f"gate reset word contains unknown actions: {sorted(unknown)}")
        raw_input_words = raw_gate.get("input_words")
        raw_expected = raw_gate.get("expected_bits")
        raw_map = raw_gate.get("output_to_bit")
        if not isinstance(raw_input_words, dict) or not raw_input_words:
            raise ModelError("gate_certificate.input_words must be a non-empty object")
        if not isinstance(raw_expected, dict) or set(raw_expected) != set(raw_input_words):
            raise ModelError("gate_certificate.expected_bits must have the same keys as input_words")
        if not isinstance(raw_map, dict) or not raw_map:
            raise ModelError("gate_certificate.output_to_bit must be a non-empty object")
        input_words: dict[str, tuple[str, ...]] = {}
        expected_bits: dict[str, str] = {}
        for key, word in raw_input_words.items():
            if not isinstance(key, str) or not key:
                raise ModelError("gate input names must be non-empty strings")
            parsed_word = _require_list_of_strings(word, f"gate_certificate.input_words.{key}", unique=False)
            unknown = set(parsed_word) - action_set
            if unknown:
                raise ModelError(f"gate input {key} contains unknown actions: {sorted(unknown)}")
            bit = raw_expected[key]
            if bit not in (0, 1, "0", "1"):
                raise ModelError(f"expected bit for {key} must be 0 or 1")
            input_words[key] = parsed_word
            expected_bits[key] = str(bit)
        output_to_bit = {_canonical_output(k): str(v) for k, v in raw_map.items()}
        if any(v not in ("0", "1") for v in output_to_bit.values()):
            raise ModelError("gate_certificate.output_to_bit values must be 0 or 1")
        gate_certificate = GateCertificate(
            name=str(gate_name),
            canonical_state=canonical_state,
            admissible_states=admissible_states,
            reset_word=reset_word,
            input_words=input_words,
            expected_bits=expected_bits,
            output_to_bit=output_to_bit,
        )

    policy_certificate: PolicyCertificate | None = None
    raw_policy = raw.get("policy_certificate")
    if raw_policy is not None:
        if not isinstance(raw_policy, dict):
            raise ModelError("policy_certificate must be an object")
        allowed = _require_list_of_strings(
            raw_policy.get("allowed_effects", []), "policy_certificate.allowed_effects"
        )
        raw_cases = raw_policy.get("cases")
        if not isinstance(raw_cases, list) or not raw_cases:
            raise ModelError("policy_certificate.cases must be a non-empty list")
        cases: list[PolicyCase] = []
        for index, item in enumerate(raw_cases):
            if not isinstance(item, dict):
                raise ModelError(f"policy case {index} must be an object")
            actor = item.get("actor")
            start_state = item.get("start_state")
            if not isinstance(actor, str) or not actor:
                raise ModelError(f"policy case {index} actor must be non-empty")
            if start_state not in state_set:
                raise ModelError(f"policy case {index} has unknown start_state")
            word = _require_list_of_strings(item.get("word"), f"policy case {index}.word", nonempty=True, unique=False)
            unknown = set(word) - action_set
            if unknown:
                raise ModelError(f"policy case {index} contains unknown actions: {sorted(unknown)}")
            effect_from = item.get("effect_from", "last_output")
            if effect_from not in {"last_output", "final_state"}:
                raise ModelError(f"policy case {index} effect_from must be last_output or final_state")
            linked = item.get("linked_to_programmability")
            unintended = item.get("unintended")
            if not isinstance(linked, bool) or not isinstance(unintended, bool):
                raise ModelError(f"policy case {index} linkage and unintended flags must be booleans")
            cases.append(
                PolicyCase(
                    actor=actor,
                    start_state=start_state,
                    word=word,
                    effect_from=effect_from,
                    linked_to_programmability=linked,
                    unintended=unintended,
                )
            )
        policy_certificate = PolicyCertificate(allowed_effects=allowed, cases=tuple(cases))

    notes = raw.get("notes", "")
    if not isinstance(notes, str):
        raise ModelError("notes must be a string")

    return Model(
        name=name,
        accepted=accepted,
        states=states,
        actions=actions,
        transitions=transitions,
        context_fibers=context_fibers,
        report=report,
        gate_certificate=gate_certificate,
        policy_certificate=policy_certificate,
        notes=notes,
    )


def canonical_output(value: Any) -> str:
    """Return a stable string representation used by the analysis engine."""

    return _canonical_output(value)
