"""Deterministic contracts for the bounded Stock-R contextual suite."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping


SUITE_SCHEMA = "rac-stock-r-context-suite-v1"
SUITE_CLAIM_BOUNDARY = "BOUNDED_CONTEXT_SUITE_ONLY"
CASE_CLAIM_BOUNDARY = "EXACT_TARGET_ONLY"
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CASE_ID = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")
_CLASSIFICATIONS = {"TRANSPARENT", "NONTRANSPARENT"}
_PLACEMENTS = {"POST_SUFFIX", "PRE_SUFFIX"}
_OPERATIONS = {"identity", "xor", "add", "mul_odd"}
_BEHAVIOR_MUTATIONS = {
    "WRITE_SOURCE_FOOTPRINT",
    "CHANGE_RETURN_VALUE",
    "DROP_INSTRUCTION_CORRESPONDENCE",
    "WITHHOLD_TARGET_BRIDGE",
    "ADD_OUTCOME_TRANSFORM_DEPENDENCY",
}
_OBLIGATIONS = {
    "source_certificate",
    "source_target_scope_distinct_or_identity_marked",
    "instruction_correspondence_total_on_witness",
    "footprint_effect_disjoint",
    "collision_preserved",
    "common_suffix_preserved",
    "must_outcomes_preserved",
    "observer_reflected",
    "report_cell_preserved",
    "frontier_preserved",
    "history_map_total",
    "target_conformance_bridge",
    "outcome_independent_selection",
    "no_target_terminal_verdict",
}


class ContextSuiteError(ValueError):
    """The suite document is malformed or requests an unsupported claim."""


@dataclass(frozen=True)
class ContextExpectation:
    stage: str
    status: str
    assessment: str | None
    quantifier: str | None
    evidence_grade: str | None
    reason: str | None


@dataclass(frozen=True)
class ContextFrame:
    map_name: str
    expression: tuple[dict[str, int | str], ...]
    resource: str


@dataclass(frozen=True)
class ContextCase:
    case_id: str
    classification: str
    claim_boundary: str
    placement: str
    frames: tuple[ContextFrame, ...]
    behavior_mutation: str | None
    obligation_overrides: dict[str, bool]
    expected: ContextExpectation


@dataclass(frozen=True)
class ContextSuite:
    schema: str
    suite_id: str
    claim_boundary: str
    max_expression_depth: int
    max_sequence_length: int
    cases: tuple[ContextCase, ...]

    def case(self, case_id: str) -> ContextCase:
        for case in self.cases:
            if case.case_id == case_id:
                return case
        raise ContextSuiteError(f"unknown case_id: {case_id}")

    def to_document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "suite_id": self.suite_id,
            "claim_boundary": self.claim_boundary,
            "bounds": {
                "max_expression_depth": self.max_expression_depth,
                "max_sequence_length": self.max_sequence_length,
            },
            "cases": [_case_to_document(case) for case in self.cases],
        }


@dataclass(frozen=True)
class RenderedContextTarget:
    source_text: str
    metadata: dict[str, object]


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _frame_function_name(case: ContextCase, frame: ContextFrame) -> str:
    if case.behavior_mutation == "WRITE_SOURCE_FOOTPRINT":
        return "context_source_footprint_frame"
    return f"{frame.map_name}_frame"


def _render_expression(operations: tuple[dict[str, int | str], ...]) -> str:
    lines = ["    __u32 framed = observed;"]
    for operation in operations:
        op = operation["op"]
        value = operation["value"]
        if op == "identity":
            continue
        operator = {"xor": "^=", "add": "+=", "mul_odd": "*="}[str(op)]
        lines.append(f"    framed {operator} {value}U;")
    return "\n".join(lines)


def _render_frame_definition(case: ContextCase, frame: ContextFrame) -> str:
    function_name = _frame_function_name(case, frame)
    map_definition = ""
    if case.behavior_mutation != "WRITE_SOURCE_FOOTPRINT":
        map_definition = f'''struct {{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
}} {frame.map_name} SEC(".maps");

'''
    return f'''{map_definition}static __noinline void {function_name}(__u32 observed)
{{
    __u32 key = 0;
{_render_expression(frame.expression)}

    (void)bpf_map_update_elem(&{frame.map_name}, &key, &framed, BPF_ANY);
}}

'''


def render_context_target(
    source_text: str,
    suite: ContextSuite,
    case: ContextCase,
) -> RenderedContextTarget:
    """Render one validated bounded context at the fixed Stock-R V2 anchors."""

    if case not in suite.cases:
        raise ContextSuiteError("case does not belong to the supplied suite")
    if "/* CRL context case:" in source_text:
        raise ContextSuiteError("source already contains a bounded context case")
    map_anchor = "/* Keep the branch-local map writes before the shared lookup suffix. */"
    call_anchor = "    observed = shared_suffix();\n"
    return_anchor = "    return observed;\n"
    for anchor, label in (
        (map_anchor, "map insertion"),
        (call_anchor, "shared suffix"),
        (return_anchor, "return"),
    ):
        if anchor not in source_text:
            raise ContextSuiteError(f"cannot find {label} anchor")

    definitions = "".join(
        _render_frame_definition(case, frame) for frame in case.frames
    )
    definitions = f"/* CRL context case: {case.case_id} */\n" + definitions
    generated = source_text.replace(map_anchor, definitions + map_anchor, 1)
    argument = "branch" if case.placement == "PRE_SUFFIX" else "observed"
    calls = "".join(
        f"    {_frame_function_name(case, frame)}((__u32){argument});\n"
        for frame in case.frames
    )
    if case.placement == "POST_SUFFIX":
        generated = generated.replace(call_anchor, call_anchor + calls, 1)
    else:
        generated = generated.replace(call_anchor, calls + call_anchor, 1)
    if case.behavior_mutation == "CHANGE_RETURN_VALUE":
        generated = generated.replace(return_anchor, "    observed ^= 1;\n" + return_anchor, 1)

    obligations = {name: True for name in sorted(_OBLIGATIONS)}
    obligations.update(case.obligation_overrides)
    correspondence_total = case.behavior_mutation != "DROP_INSTRUCTION_CORRESPONDENCE"
    metadata: dict[str, object] = {
        "schema": "rac-stock-r-context-transform-metadata-v1",
        "suite_id": suite.suite_id,
        "case_id": case.case_id,
        "classification": case.classification,
        "claim_boundary": case.claim_boundary,
        "transform_id": f"context.stock-r-v2.{case.case_id}",
        "primitive": "BOUNDED_CONTEXT_SUITE",
        "source_sha256": _sha256_text(source_text),
        "generated_sha256": _sha256_text(generated),
        "parameters": {
            "placement": case.placement,
            "behavior_mutation": case.behavior_mutation,
            "frames": [
                {
                    "map_name": frame.map_name,
                    "expression": [dict(operation) for operation in frame.expression],
                    "resource": frame.resource,
                }
                for frame in case.frames
            ],
            "retval_preserved": case.behavior_mutation != "CHANGE_RETURN_VALUE",
        },
        "instruction_correspondence": {
            "status": "VERIFIED" if correspondence_total else "INCOMPLETE",
            "total_on_witness": correspondence_total,
            "entries": [
                {"source_insn": 0, "target_insn": 0, "relation": "IDENTITY"},
                {"source_insn": 1, "target_insn": 1, "relation": "FRAMED"},
            ],
        },
        "footprint": {
            "resources": [
                "reg:r1",
                "reg:r2",
                "stack:-8..-1",
                "map:witness.0",
                "frontier:source",
            ]
        },
        "effect": {"writes": [frame.resource for frame in case.frames]},
        "obligations": obligations,
        "obligation_overrides": dict(case.obligation_overrides),
    }
    return RenderedContextTarget(source_text=generated, metadata=metadata)


def compare_case_result(
    case: ContextCase,
    observed: Mapping[str, object],
) -> dict[str, object]:
    """Compare one normalized observation with its frozen exact expectation."""

    expected = asdict(case.expected)
    raw_reasons = observed.get("reasons", [])
    if not isinstance(raw_reasons, list) or any(
        not isinstance(reason, str) for reason in raw_reasons
    ):
        reasons: tuple[str, ...] = ("OBSERVED_REASONS_MALFORMED",)
    else:
        reasons = tuple(sorted(set(raw_reasons)))
    expected_reason = expected["reason"]
    reason_match = expected_reason is None or expected_reason in reasons
    field_match = all(
        expected[name] is None or observed.get(name) == expected[name]
        for name in (
            "stage",
            "status",
            "assessment",
            "quantifier",
            "evidence_grade",
        )
    )
    return {
        "case_id": case.case_id,
        "classification": case.classification,
        "expected": expected,
        "observed": dict(observed),
        "field_match": bool(field_match),
        "reason_match": bool(reason_match),
        "expected_match": bool(field_match and reason_match),
    }


def _case_to_document(case: ContextCase) -> dict[str, object]:
    return {
        "case_id": case.case_id,
        "classification": case.classification,
        "case_claim_boundary": case.claim_boundary,
        "placement": case.placement,
        "frames": [
            {
                "map_name": frame.map_name,
                "resource": frame.resource,
                "expression": [dict(operation) for operation in frame.expression],
            }
            for frame in case.frames
        ],
        "behavior_mutation": case.behavior_mutation,
        "obligation_overrides": dict(sorted(case.obligation_overrides.items())),
        "expected": {
            "stage": case.expected.stage,
            "status": case.expected.status,
            "assessment": case.expected.assessment,
            "quantifier": case.expected.quantifier,
            "evidence_grade": case.expected.evidence_grade,
            "reason": case.expected.reason,
        },
    }


def _object(value: Any, name: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ContextSuiteError(f"{name} must contain exactly {sorted(keys)}")
    return value


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContextSuiteError(f"{name} must be a non-empty string")
    return value


def _integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContextSuiteError(f"{name} must be an integer")
    return value


def _nullable_string(value: Any, name: str) -> str | None:
    if value is None:
        return None
    return _string(value, name)


def _parse_expectation(value: Any, name: str) -> ContextExpectation:
    document = _object(
        value,
        name,
        {"stage", "status", "assessment", "quantifier", "evidence_grade", "reason"},
    )
    return ContextExpectation(
        stage=_string(document["stage"], f"{name}.stage"),
        status=_string(document["status"], f"{name}.status"),
        assessment=_nullable_string(document["assessment"], f"{name}.assessment"),
        quantifier=_nullable_string(document["quantifier"], f"{name}.quantifier"),
        evidence_grade=_nullable_string(
            document["evidence_grade"], f"{name}.evidence_grade"
        ),
        reason=_nullable_string(document["reason"], f"{name}.reason"),
    )


def _parse_frame(
    value: Any,
    name: str,
    *,
    max_expression_depth: int,
) -> ContextFrame:
    document = _object(value, name, {"map_name", "resource", "expression"})
    map_name = _string(document["map_name"], f"{name}.map_name")
    if _IDENTIFIER.fullmatch(map_name) is None:
        raise ContextSuiteError(f"{name}.map_name must be a C identifier")
    resource = _string(document["resource"], f"{name}.resource")
    expression = document["expression"]
    if (
        not isinstance(expression, list)
        or not expression
        or len(expression) > max_expression_depth
    ):
        raise ContextSuiteError(
            f"{name}.expression must have 1..{max_expression_depth} operations"
        )
    operations: list[dict[str, int | str]] = []
    for index, raw_operation in enumerate(expression):
        operation_name = f"{name}.expression[{index}]"
        operation = _object(raw_operation, operation_name, {"op", "value"})
        op = _string(operation["op"], f"{operation_name}.op")
        if op not in _OPERATIONS:
            raise ContextSuiteError(f"{operation_name}.op is unsupported: {op}")
        operand = _integer(operation["value"], f"{operation_name}.value")
        if not 0 <= operand <= 0xFFFFFFFF:
            raise ContextSuiteError(f"{operation_name}.value must fit uint32")
        if op == "identity" and operand != 0:
            raise ContextSuiteError(f"{operation_name}.identity value must be 0")
        if op == "mul_odd" and operand % 2 != 1:
            raise ContextSuiteError(f"{operation_name}.mul_odd value must be odd")
        operations.append({"op": op, "value": operand})
    return ContextFrame(map_name=map_name, expression=tuple(operations), resource=resource)


def _parse_case(
    value: Any,
    name: str,
    *,
    max_expression_depth: int,
    max_sequence_length: int,
) -> ContextCase:
    document = _object(
        value,
        name,
        {
            "case_id",
            "classification",
            "case_claim_boundary",
            "placement",
            "frames",
            "behavior_mutation",
            "obligation_overrides",
            "expected",
        },
    )
    case_id = _string(document["case_id"], f"{name}.case_id")
    if _CASE_ID.fullmatch(case_id) is None:
        raise ContextSuiteError(f"{name}.case_id has an unsafe form")
    classification = _string(document["classification"], f"{name}.classification")
    if classification not in _CLASSIFICATIONS:
        raise ContextSuiteError(f"{name}.classification is unsupported")
    claim_boundary = _string(
        document["case_claim_boundary"], f"{name}.case_claim_boundary"
    )
    if claim_boundary != CASE_CLAIM_BOUNDARY:
        raise ContextSuiteError(
            f"{name}.case_claim_boundary must be {CASE_CLAIM_BOUNDARY}"
        )
    placement = _string(document["placement"], f"{name}.placement")
    if placement not in _PLACEMENTS:
        raise ContextSuiteError(f"{name}.placement is unsupported")
    raw_frames = document["frames"]
    if (
        not isinstance(raw_frames, list)
        or not raw_frames
        or len(raw_frames) > max_sequence_length
    ):
        raise ContextSuiteError(
            f"{name}.frames must have 1..{max_sequence_length} entries"
        )
    frames = tuple(
        _parse_frame(
            raw_frame,
            f"{name}.frames[{index}]",
            max_expression_depth=max_expression_depth,
        )
        for index, raw_frame in enumerate(raw_frames)
    )
    behavior_mutation = document["behavior_mutation"]
    if behavior_mutation is not None:
        behavior_mutation = _string(behavior_mutation, f"{name}.behavior_mutation")
        if behavior_mutation not in _BEHAVIOR_MUTATIONS:
            raise ContextSuiteError(f"{name}.behavior_mutation is unsupported")
    raw_overrides = document["obligation_overrides"]
    if not isinstance(raw_overrides, dict):
        raise ContextSuiteError(f"{name}.obligation_overrides must be an object")
    obligation_overrides: dict[str, bool] = {}
    for obligation, enabled in raw_overrides.items():
        if obligation not in _OBLIGATIONS:
            raise ContextSuiteError(f"{name}.obligation_overrides has unknown key")
        if not isinstance(enabled, bool):
            raise ContextSuiteError(f"{name}.obligation_overrides values must be boolean")
        obligation_overrides[obligation] = enabled
    expected = _parse_expectation(document["expected"], f"{name}.expected")
    if classification == "TRANSPARENT":
        if expected.reason is not None:
            raise ContextSuiteError(f"{name}.expected.reason must be null for transparent cases")
        if (
            expected.stage != "CRL_CHECK"
            or expected.status != "CERTIFIED"
            or expected.assessment != "NONFACTORING"
            or expected.quantifier != "AT"
            or expected.evidence_grade != "TRANSPORTED"
        ):
            raise ContextSuiteError(f"{name}.expected must be an exact transported certificate")
    elif expected.reason is None:
        raise ContextSuiteError(f"{name}.expected.reason is required for negative cases")
    return ContextCase(
        case_id=case_id,
        classification=classification,
        claim_boundary=claim_boundary,
        placement=placement,
        frames=frames,
        behavior_mutation=behavior_mutation,
        obligation_overrides=dict(sorted(obligation_overrides.items())),
        expected=expected,
    )


def parse_context_suite(document: object) -> ContextSuite:
    root = _object(
        document,
        "suite",
        {"schema", "suite_id", "claim_boundary", "bounds", "cases"},
    )
    if root["schema"] != SUITE_SCHEMA:
        raise ContextSuiteError(f"suite.schema must be {SUITE_SCHEMA}")
    suite_id = _string(root["suite_id"], "suite.suite_id")
    claim_boundary = _string(root["claim_boundary"], "suite.claim_boundary")
    if claim_boundary != SUITE_CLAIM_BOUNDARY:
        raise ContextSuiteError(
            f"suite.claim_boundary must be {SUITE_CLAIM_BOUNDARY}"
        )
    bounds = _object(
        root["bounds"],
        "suite.bounds",
        {"max_expression_depth", "max_sequence_length"},
    )
    max_expression_depth = _integer(
        bounds["max_expression_depth"], "suite.bounds.max_expression_depth"
    )
    max_sequence_length = _integer(
        bounds["max_sequence_length"], "suite.bounds.max_sequence_length"
    )
    if max_expression_depth != 2 or max_sequence_length != 2:
        raise ContextSuiteError("suite bounds must remain frozen at depth=2,length=2")
    raw_cases = root["cases"]
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ContextSuiteError("suite.cases must be a non-empty array")
    cases = tuple(
        _parse_case(
            raw_case,
            f"suite.cases[{index}]",
            max_expression_depth=max_expression_depth,
            max_sequence_length=max_sequence_length,
        )
        for index, raw_case in enumerate(raw_cases)
    )
    case_ids = [case.case_id for case in cases]
    if len(set(case_ids)) != len(case_ids):
        raise ContextSuiteError("duplicate case_id in suite")
    return ContextSuite(
        schema=SUITE_SCHEMA,
        suite_id=suite_id,
        claim_boundary=claim_boundary,
        max_expression_depth=max_expression_depth,
        max_sequence_length=max_sequence_length,
        cases=cases,
    )


def load_context_suite(path: Path) -> ContextSuite:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContextSuiteError(f"cannot read context suite {path}: {exc}") from exc
    return parse_context_suite(document)
