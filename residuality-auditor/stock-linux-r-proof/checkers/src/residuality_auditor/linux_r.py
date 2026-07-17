from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


class LinuxRError(ValueError):
    """Raised when Linux extractor evidence violates the declared schema."""


@dataclass(frozen=True)
class PruneSnapshot:
    insn_idx: int
    first_insn_idx: int
    last_insn_idx: int
    curframe: int
    dfs_depth: int
    state_hash: str
    history_hash: str
    history_count: int


@dataclass(frozen=True)
class PruneEvent:
    cell_id: int
    exact_level: int
    visit_insn: int
    old: PruneSnapshot
    current: PruneSnapshot
    tgid: int | None
    source: str
    program_name: str | None


def _read_json(path: str | Path) -> Any:
    p = Path(path)
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LinuxRError(f"cannot read JSON {p}: {exc}") from exc


def _require_dict(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LinuxRError(f"{name} must be an object")
    return value


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise LinuxRError(f"{name} must be a non-empty string")
    return value


def _require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise LinuxRError(f"{name} must be boolean")
    return value


def _require_int(value: Any, name: str) -> int:
    if not isinstance(value, int):
        raise LinuxRError(f"{name} must be an integer")
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _snapshot(raw: Any, name: str) -> PruneSnapshot:
    item = _require_dict(raw, name)
    return PruneSnapshot(
        insn_idx=_require_int(item.get("insn_idx"), f"{name}.insn_idx"),
        first_insn_idx=_require_int(item.get("first_insn_idx", -1), f"{name}.first_insn_idx"),
        last_insn_idx=_require_int(item.get("last_insn_idx", -1), f"{name}.last_insn_idx"),
        curframe=_require_int(item.get("curframe", 0), f"{name}.curframe"),
        dfs_depth=_require_int(item.get("dfs_depth", 0), f"{name}.dfs_depth"),
        state_hash=_require_str(item.get("state_hash"), f"{name}.state_hash"),
        history_hash=_require_str(item.get("history_hash"), f"{name}.history_hash"),
        history_count=_require_int(item.get("history_count", 0), f"{name}.history_count"),
    )


def load_prune_events(path: str | Path) -> tuple[dict[str, Any], list[PruneEvent]]:
    p = Path(path)
    metadata: dict[str, Any] = {}
    events: list[PruneEvent] = []
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise LinuxRError(f"cannot read event stream {p}: {exc}") from exc
    for lineno, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise LinuxRError(f"invalid JSON at {p}:{lineno}: {exc}") from exc
        raw = _require_dict(raw, f"event line {lineno}")
        event_type = raw.get("event")
        if event_type == "metadata":
            metadata.update(raw)
            continue
        if event_type != "prune_hit":
            continue
        events.append(
            PruneEvent(
                cell_id=_require_int(raw.get("cell_id"), f"line {lineno}.cell_id"),
                exact_level=_require_int(raw.get("exact_level", -1), f"line {lineno}.exact_level"),
                visit_insn=_require_int(raw.get("visit_insn"), f"line {lineno}.visit_insn"),
                old=_snapshot(raw.get("old"), f"line {lineno}.old"),
                current=_snapshot(raw.get("current"), f"line {lineno}.current"),
                tgid=raw.get("tgid") if isinstance(raw.get("tgid"), int) else None,
                source=str(raw.get("source", "unknown")),
                program_name=raw.get("program_name") if isinstance(raw.get("program_name"), str) else None,
            )
        )
    if not events:
        raise LinuxRError("event stream contains no prune_hit events")
    return metadata, events


def _normalize_run(raw: Any, index: int) -> dict[str, Any]:
    run = _require_dict(raw, f"runtime.runs[{index}]")
    _require_str(run.get("case"), f"runtime.runs[{index}].case")
    for field in ("selected_state", "context", "suffix", "observation"):
        if field not in run:
            raise LinuxRError(f"runtime.runs[{index}] is missing {field}")
    return run


def load_runtime(path: str | Path) -> dict[str, Any]:
    raw = _require_dict(_read_json(path), "runtime")
    if raw.get("schema") != "rac-linux-runtime-v1":
        raise LinuxRError("runtime.schema must be rac-linux-runtime-v1")
    runs = raw.get("runs")
    if not isinstance(runs, list) or len(runs) < 2:
        raise LinuxRError("runtime.runs must contain at least two executions")
    raw["runs"] = [_normalize_run(run, i) for i, run in enumerate(runs)]
    return raw


def load_contract(path: str | Path) -> dict[str, Any]:
    raw = _require_dict(_read_json(path), "contract")
    if raw.get("schema") != "rac-linux-contract-v1":
        raise LinuxRError("contract.schema must be rac-linux-contract-v1")
    _require_str(raw.get("selected_component"), "contract.selected_component")
    omitted = raw.get("omitted_by_verifier_cell")
    if not isinstance(omitted, list) or not omitted or any(not isinstance(x, str) or not x for x in omitted):
        raise LinuxRError("contract.omitted_by_verifier_cell must be a non-empty string list")
    fields = raw.get("same_context_fields", [])
    if not isinstance(fields, list) or any(not isinstance(x, str) or not x for x in fields):
        raise LinuxRError("contract.same_context_fields must be a string list")
    if "report_contract_in_scope" in raw:
        _require_bool(raw["report_contract_in_scope"], "contract.report_contract_in_scope")
    if "concretization_reviewed" in raw:
        _require_bool(raw["concretization_reviewed"], "contract.concretization_reviewed")
    if "path_correspondence_reviewed" in raw:
        _require_bool(raw["path_correspondence_reviewed"], "contract.path_correspondence_reviewed")
    return raw


def _path_get(value: Any, dotted: str) -> Any:
    cur = value
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            raise LinuxRError(f"context field {dotted!r} is missing")
        cur = cur[part]
    return cur


def _runtime_pairs(runtime: dict[str, Any], context_fields: list[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    runs = runtime["runs"]
    for i, left in enumerate(runs):
        for right in runs[i + 1 :]:
            selected_diff = _canonical(left["selected_state"]) != _canonical(right["selected_state"])
            suffix_same = _canonical(left["suffix"]) == _canonical(right["suffix"])
            observation_diff = _canonical(left["observation"]) != _canonical(right["observation"])
            context_checks: dict[str, bool] = {}
            for field in context_fields:
                context_checks[field] = _canonical(_path_get(left["context"], field)) == _canonical(
                    _path_get(right["context"], field)
                )
            candidates.append(
                {
                    "left_case": left["case"],
                    "right_case": right["case"],
                    "selected_state_differs": selected_diff,
                    "suffix_equal": suffix_same,
                    "observation_differs": observation_diff,
                    "context_equal": all(context_checks.values()),
                    "context_checks": context_checks,
                    "qualifies": selected_diff and suffix_same and observation_diff and all(context_checks.values()),
                }
            )
    return candidates


def _event_candidates(events: Iterable[PruneEvent], contract: dict[str, Any]) -> list[dict[str, Any]]:
    frontier = contract.get("frontier", {})
    if frontier is None:
        frontier = {}
    frontier = _require_dict(frontier, "contract.frontier")
    exact_insn = frontier.get("visit_insn")
    min_insn = frontier.get("min_insn")
    max_insn = frontier.get("max_insn")
    require_histories = bool(contract.get("require_distinct_verifier_histories", True))
    require_same_state_hash = bool(contract.get("require_same_state_hash", False))
    required_program_name = contract.get("program_name")
    if required_program_name is not None:
        required_program_name = _require_str(required_program_name, "contract.program_name")
    result: list[dict[str, Any]] = []
    for event in events:
        in_frontier = True
        if exact_insn is not None:
            in_frontier = event.visit_insn == _require_int(exact_insn, "contract.frontier.visit_insn")
        if min_insn is not None:
            in_frontier = in_frontier and event.visit_insn >= _require_int(min_insn, "contract.frontier.min_insn")
        if max_insn is not None:
            in_frontier = in_frontier and event.visit_insn <= _require_int(max_insn, "contract.frontier.max_insn")
        program_matches = required_program_name is None or event.program_name == required_program_name
        histories_distinct = event.old.history_hash != event.current.history_hash
        state_hash_equal = event.old.state_hash == event.current.state_hash
        qualifies = in_frontier and program_matches
        if require_histories:
            qualifies = qualifies and histories_distinct
        if require_same_state_hash:
            qualifies = qualifies and state_hash_equal
        result.append(
            {
                "cell_id": event.cell_id,
                "visit_insn": event.visit_insn,
                "exact_level": event.exact_level,
                "source": event.source,
                "program_name": event.program_name,
                "program_matches": program_matches,
                "in_declared_frontier": in_frontier,
                "histories_distinct": histories_distinct,
                "state_hash_equal": state_hash_equal,
                "old": event.old.__dict__,
                "current": event.current.__dict__,
                "qualifies": qualifies,
            }
        )
    result.sort(key=lambda x: (not x["qualifies"], x["visit_insn"], x["cell_id"]))
    return result


def analyze_linux_r(events_path: str | Path, runtime_path: str | Path, contract_path: str | Path) -> dict[str, Any]:
    metadata, events = load_prune_events(events_path)
    runtime = load_runtime(runtime_path)
    contract = load_contract(contract_path)

    event_candidates = _event_candidates(events, contract)
    runtime_candidates = _runtime_pairs(runtime, list(contract.get("same_context_fields", [])))
    operational_cell = next((item for item in event_candidates if item["qualifies"]), None)
    runtime_witness = next((item for item in runtime_candidates if item["qualifies"]), None)

    selected_component = contract["selected_component"]
    frontier = contract.get("frontier")
    frontier_declared = isinstance(frontier, dict) and any(
        key in frontier for key in ("visit_insn", "min_insn", "max_insn")
    )
    path_correspondence_reviewed = bool(contract.get("path_correspondence_reviewed", False))
    omitted = selected_component in contract["omitted_by_verifier_cell"] or bool(
        contract.get("selected_component_omission_reviewed", False)
    )
    extractor_identity_ok = True
    expected_kernel = contract.get("kernel_release")
    if expected_kernel is not None:
        extractor_identity_ok = extractor_identity_ok and runtime.get("kernel_release") == expected_kernel
    event_kernel = metadata.get("kernel_release")
    if event_kernel and runtime.get("kernel_release"):
        extractor_identity_ok = extractor_identity_ok and event_kernel == runtime.get("kernel_release")
    expected_tag = contract.get("program_tag")
    if expected_tag is not None:
        extractor_identity_ok = extractor_identity_ok and runtime.get("program_tag") == expected_tag
    event_tag = metadata.get("program_tag")
    if event_tag and runtime.get("program_tag"):
        extractor_identity_ok = extractor_identity_ok and event_tag == runtime.get("program_tag")

    prerequisites = {
        "extractor_events_present": bool(events),
        "extractor_identity_matches_runtime": extractor_identity_ok,
        "frontier_declared": frontier_declared,
        "path_correspondence_reviewed": path_correspondence_reviewed,
        "joint_operational_prune_cell": operational_cell is not None,
        "distinct_verifier_paths": bool(operational_cell and operational_cell["histories_distinct"]),
        "runtime_same_suffix_c_witness": runtime_witness is not None,
        "selected_component_omitted_from_cell_schema": omitted,
        "no_external_interference_declared": bool(contract.get("no_external_interference", False)),
        "serialized_execution_declared": bool(contract.get("serialized_execution", False)),
    }
    candidate = all(prerequisites.values())
    report_scope = bool(contract.get("report_contract_in_scope", False))
    concretization_reviewed = bool(contract.get("concretization_reviewed", False))
    established = candidate and report_scope and concretization_reviewed

    if established:
        verdict = "LINUX_R_ESTABLISHED_UNDER_DECLARED_CONTRACT"
    elif candidate:
        verdict = "LINUX_R_CANDIDATE_REQUIRES_CONCRETIZATION_AND_REPORT_CONTRACT_REVIEW"
    else:
        verdict = "LINUX_R_NOT_ESTABLISHED"

    evidence_digest = hashlib.sha256(
        (_canonical(metadata) + _canonical(runtime) + _canonical(contract) + _canonical(event_candidates)).encode("utf-8")
    ).hexdigest()

    return {
        "schema": "rac-linux-r-analysis-v1",
        "verdict": verdict,
        "summary": {
            "linux_R_candidate": candidate,
            "linux_R_established": established,
            "frontier_declared": frontier_declared,
            "path_correspondence_reviewed": path_correspondence_reviewed,
            "report_contract_in_scope": report_scope,
            "concretization_reviewed": concretization_reviewed,
        },
        "prerequisites": prerequisites,
        "selected_operational_cell": operational_cell,
        "selected_runtime_witness": runtime_witness,
        "event_candidates": event_candidates,
        "runtime_candidates": runtime_candidates,
        "metadata": metadata,
        "runtime_identity": {
            "kernel_release": runtime.get("kernel_release"),
            "program_tag": runtime.get("program_tag"),
            "btf_sha256": runtime.get("btf_sha256"),
            "object_sha256": runtime.get("object_sha256"),
        },
        "contract": contract,
        "evidence_digest_sha256": evidence_digest,
        "limitations": [
            "A successful states_equal/is_state_visited prune is treated as an operational computed cell membership event.",
            "The tool does not infer the verifier's intended functional contract from source code.",
            "The selected runtime component must be explicitly declared omitted from the extracted cell schema.",
            "A program-name match alone is insufficient; the contract must select a bytecode frontier and review its correspondence to the concrete prefixes.",
            "Without reviewed concretization and report-contract scope, the result remains an R candidate, not a final paper claim.",
        ],
    }


def render_linux_r_markdown(result: dict[str, Any]) -> str:
    s = result["summary"]
    p = result["prerequisites"]
    lines = [
        "# Linux R Evidence Report",
        "",
        f"**Verdict:** `{result['verdict']}`",
        "",
        "## Summary",
        "",
        f"- Linux R candidate: **{s['linux_R_candidate']}**",
        f"- Linux R established under declared contract: **{s['linux_R_established']}**",
        f"- Bytecode frontier declared: **{s['frontier_declared']}**",
        f"- Path correspondence reviewed: **{s['path_correspondence_reviewed']}**",
        f"- Report contract in scope: **{s['report_contract_in_scope']}**",
        f"- Concretization reviewed: **{s['concretization_reviewed']}**",
        "",
        "## Required evidence",
        "",
    ]
    for name, value in p.items():
        lines.append(f"- `{name}`: **{value}**")
    cell = result.get("selected_operational_cell")
    if cell:
        lines.extend(
            [
                "",
                "## Selected verifier prune cell",
                "",
                f"- Cell ID: `{cell['cell_id']}`",
                f"- Program name: `{cell.get('program_name')}`",
                f"- Visit instruction: `{cell['visit_insn']}`",
                f"- Equality level: `{cell['exact_level']}`",
                f"- Distinct path histories: **{cell['histories_distinct']}**",
                f"- State fingerprints equal: **{cell['state_hash_equal']}**",
                f"- Old history hash: `{cell['old']['history_hash']}`",
                f"- Current history hash: `{cell['current']['history_hash']}`",
            ]
        )
    witness = result.get("selected_runtime_witness")
    if witness:
        lines.extend(
            [
                "",
                "## Selected runtime witness",
                "",
                f"- Cases: `{witness['left_case']}` vs `{witness['right_case']}`",
                f"- Selected state differs: **{witness['selected_state_differs']}**",
                f"- Same suffix: **{witness['suffix_equal']}**",
                f"- Observation differs: **{witness['observation_differs']}**",
                f"- Context equal: **{witness['context_equal']}**",
            ]
        )
    lines.extend(["", "## Limitations", ""])
    for item in result["limitations"]:
        lines.append(f"- {item}")
    lines.extend(["", f"Evidence digest: `{result['evidence_digest_sha256']}`", ""])
    return "\n".join(lines)
