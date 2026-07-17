from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..analysis import analyze_model, behavioral_partitions, execute, shortest_output_witness
from ..model import Model, ReportSpec, Transition, canonical_output
from ..report import render_markdown


SIGMA_A0 = "sigma-a0"
SIGMA_A1 = "sigma-a1"
ACTION_SHARED_SUFFIX = "shared_suffix_insert_B"
RESULT_ESTABLISHED = "REPORT_FACTORIZATION_FAILURE_ESTABLISHED"
RESULT_REJECTED = "REPORT_FACTORIZATION_FAILURE_REJECTED"


class StockLinuxAdapterError(ValueError):
    """Raised when a Linux evidence bundle is not usable as a stock verifier model."""


def _load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise StockLinuxAdapterError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise StockLinuxAdapterError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise StockLinuxAdapterError(f"{path} must contain a JSON object")
    return data


def _load_json_optional(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return _load_json(path)


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def _runtime_by_case(runtime: dict[str, Any]) -> dict[str, dict[str, Any]]:
    runs = runtime.get("runs")
    if not isinstance(runs, list):
        raise StockLinuxAdapterError("runtime.json must contain a runs list")
    by_case: dict[str, dict[str, Any]] = {}
    for run in runs:
        if not isinstance(run, dict):
            continue
        case = run.get("case")
        if case in {"a=0", "a=1"}:
            if case in by_case:
                raise StockLinuxAdapterError(f"runtime.json contains duplicate run for {case}")
            by_case[case] = run
    missing = sorted({"a=0", "a=1"} - set(by_case))
    if missing:
        raise StockLinuxAdapterError(f"runtime.json is missing runs for {missing}")
    for case, run in by_case.items():
        if not isinstance(run.get("observation"), dict):
            raise StockLinuxAdapterError(f"runtime run {case} must contain an observation object")
    return by_case


def _case_observation(run: dict[str, Any]) -> dict[str, Any]:
    observation = run.get("observation")
    if not isinstance(observation, dict):
        raise StockLinuxAdapterError("runtime observation must be an object")
    return observation


def _same_suffix_descriptor(by_case: dict[str, dict[str, Any]]) -> dict[str, Any]:
    suffixes = {case: run.get("suffix") or {} for case, run in by_case.items()}
    operations = {suffix.get("operation") for suffix in suffixes.values()}
    programs = {suffix.get("program") for suffix in suffixes.values()}
    return {
        "operation": next(iter(operations)) if len(operations) == 1 else None,
        "program": next(iter(programs)) if len(programs) == 1 else None,
        "per_case": suffixes,
        "same_operation": len(operations) == 1 and None not in operations,
        "same_program": len(programs) == 1 and None not in programs,
    }


def _representative_cell(report_map: dict[str, Any]) -> tuple[str, dict[str, list[str]]]:
    unique = report_map.get("unique_cell_check") or {}
    reps = unique.get("representatives") if isinstance(unique, dict) else None
    if not isinstance(reps, dict):
        cert = report_map.get("certificate_results") or {}
        reps = cert.get("representatives") if isinstance(cert, dict) else None
    if not isinstance(reps, dict):
        return "", {}
    normalized: dict[str, list[str]] = {}
    for case in ("a=0", "a=1"):
        raw = reps.get(case)
        normalized[case] = [str(x) for x in raw] if isinstance(raw, list) else []
    if len(normalized["a=0"]) == 1 and normalized["a=0"] == normalized["a=1"]:
        return f"retained:{normalized['a=0'][0]}", normalized
    return "", normalized


def _identity_consistency(path_report: dict[str, Any], report_map: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    path_identity = path_report.get("identity") or {}
    report_identity = report_map.get("identity") or {}
    fields: dict[str, list[Any]] = {}
    for key in ("object_sha256", "program_tag", "program_pin", "program_id", "xlated_sha256"):
        values = []
        for source in (path_identity, report_identity, runtime):
            if isinstance(source, dict) and key in source:
                values.append(source.get(key))
        if values:
            fields[key] = values
    mismatches = {
        key: values for key, values in fields.items() if len({json.dumps(v, sort_keys=True) for v in values}) > 1
    }
    return {"fields": fields, "mismatches": mismatches, "consistent": not mismatches}


def _collect_inputs(bundle: Path) -> dict[str, Any]:
    return {
        "path_report": _load_json(bundle / "proof" / "path" / "path-correspondence.json"),
        "joint_coverage": _load_json_optional(bundle / "proof" / "concretization" / "joint-coverage.json"),
        "membership_a0": _load_json(bundle / "proof" / "concretization" / "membership-a0.json"),
        "membership_a1": _load_json(bundle / "proof" / "concretization" / "membership-a1.json"),
        "coverage": _load_json(bundle / "proof" / "report" / "prune-cell-coverage.json"),
        "session": _load_json(bundle / "proof" / "report" / "session-completeness.json"),
        "subsumption": _load_json_optional(bundle / "proof" / "subsumption" / "subsumption-check.json"),
        "report_map": _load_json(bundle / "proof" / "report" / "report-map.json"),
        "runtime": _load_json(bundle / "runtime.json"),
    }


def _preconditions(docs: dict[str, Any], by_case: dict[str, dict[str, Any]], cell: str, reps: dict[str, list[str]]) -> dict[str, Any]:
    path_report = docs["path_report"]
    joint = docs.get("joint_coverage") or {}
    report_map = docs["report_map"]
    runtime = docs["runtime"]
    coverage = docs.get("coverage") or {}
    session = docs.get("session") or {}
    suffix = _same_suffix_descriptor(by_case)
    identity = _identity_consistency(path_report, report_map, runtime)

    obs_a0 = _case_observation(by_case["a=0"])
    obs_a1 = _case_observation(by_case["a=1"])
    contexts = {case: run.get("context") or {} for case, run in by_case.items()}

    checks = {
        "path_correspondence": path_report.get("result") == "PATH_CORRESPONDENCE_VERIFIED",
        "same_remaining_xlated_suffix": (path_report.get("common_suffix") or {}).get("same_remaining_xlated_suffix") is True,
        "joint_coverage_candidate": joint.get("result") in {None, "JOINT_COVERAGE_CANDIDATE"},
        "membership_a0": docs["membership_a0"].get("result") == "SIGMA_A0_IN_DIRECT_GAMMA",
        "membership_a1": docs["membership_a1"].get("result") == "SIGMA_A1_IN_DIRECT_GAMMA",
        "operational_prune_cell_coverage": coverage.get("result") == "BOTH_CASES_IN_OPERATIONAL_PRUNE_CELL",
        "session_capture_complete": session.get("result") == "SESSION_CAPTURE_COMPLETE" and session.get("ringbuf_lost_events") == 0 and session.get("collector_parse_errors") == 0,
        "unique_same_report_cell": ((report_map.get("unique_cell_check") or {}).get("result") == "UNIQUE_SAME_REPORT_CELL" or (report_map.get("certificate_results") or {}).get("unique_cell") == "UNIQUE_SAME_REPORT_CELL"),
        "same_retained_representative": bool(cell),
        "coverage_representative_matches": bool(cell) and coverage.get("representative") and cell == f"retained:{coverage.get('representative')}",
        "same_suffix_operation": suffix["same_operation"],
        "same_suffix_program": suffix["same_program"],
        "serialized_runtime": all(context.get("serialized") is True for context in contexts.values()),
        "single_artifact_runtime": all(context.get("single_artifact") is True for context in contexts.values()),
        "runtime_observations_differ": canonical_output(obs_a0) != canonical_output(obs_a1),
        "identity_consistent": identity["consistent"],
    }
    reasons = [name for name, passed in checks.items() if not passed]
    return {
        "schema": "rac-stock-linux-preconditions-v1",
        "checks": checks,
        "passed": all(checks.values()),
        "reasons": reasons,
        "representatives": reps,
        "identity": identity,
        "suffix": suffix,
        "runtime_contexts": contexts,
    }


def _build_model(by_case: dict[str, dict[str, Any]], report_cell: str, docs: dict[str, Any]) -> Model:
    transitions = {
        SIGMA_A0: {
            ACTION_SHARED_SUFFIX: Transition(
                next_state=SIGMA_A0,
                output=_case_observation(by_case["a=0"]),
            )
        },
        SIGMA_A1: {
            ACTION_SHARED_SUFFIX: Transition(
                next_state=SIGMA_A1,
                output=_case_observation(by_case["a=1"]),
            )
        },
    }
    identity = docs["path_report"].get("identity") or docs["report_map"].get("identity") or {}
    notes = (
        "Finite stock-Linux adapter model built from one verifier frontier bundle. "
        "The two concrete prefix cases are kept as sigma-a0 and sigma-a1; the only action is the "
        "reviewed common xlated suffix. The report cell is the retained verifier-state representative "
        "established by proof/report/report-map.json."
    )
    if identity.get("object_sha256"):
        notes += f" Object SHA256: {identity['object_sha256']}."
    if identity.get("program_tag"):
        notes += f" Program tag: {identity['program_tag']}."
    return Model(
        name="stock-linux-frontier-factorization",
        accepted=True,
        states=(SIGMA_A0, SIGMA_A1),
        actions=(ACTION_SHARED_SUFFIX,),
        transitions=transitions,
        context_fibers={"stock-linux-frontier": (SIGMA_A0, SIGMA_A1)},
        report=ReportSpec(
            fiber_states=(SIGMA_A0, SIGMA_A1),
            cells={report_cell: (SIGMA_A0, SIGMA_A1)},
            source="Linux verifier retained-state representative from proof/report/report-map.json",
        ),
        gate_certificate=None,
        policy_certificate=None,
        notes=notes,
    )


def _stable_beta(model: Model) -> tuple[dict[str, str], dict[str, Any]]:
    partitions = behavioral_partitions(model)
    stable = partitions[-1]
    beta = {state: f"Q{index}" for index, block in enumerate(stable) for state in block}
    quotient = {
        "schema": "rac-behavioral-quotient-v1",
        "source_algorithm": "residuality_auditor.analysis.behavioral_partitions",
        "states": list(model.states),
        "actions": list(model.actions),
        "refinement_rounds": len(partitions) - 1,
        "classes": [{"class": f"Q{index}", "states": list(block)} for index, block in enumerate(stable)],
        "partitions_by_depth": [
            {"depth": depth, "classes": [list(block) for block in blocks]}
            for depth, blocks in enumerate(partitions)
        ],
    }
    return beta, quotient


def _suffix_witness(model: Model, by_case: dict[str, dict[str, Any]], docs: dict[str, Any]) -> dict[str, Any]:
    witness = shortest_output_witness(model, SIGMA_A0, SIGMA_A1)
    return {
        "schema": "rac-stock-linux-suffix-witness-v1",
        "suffix_word": [ACTION_SHARED_SUFFIX],
        "runtime_suffix": _same_suffix_descriptor(by_case),
        "frontier": docs["path_report"].get("frontier"),
        "common_suffix": docs["path_report"].get("common_suffix"),
        "runtime_observations": {
            "sigma-a0": _case_observation(by_case["a=0"]),
            "sigma-a1": _case_observation(by_case["a=1"]),
        },
        "runtime_selected_states": {
            "sigma-a0": by_case["a=0"].get("selected_state"),
            "sigma-a1": by_case["a=1"].get("selected_state"),
        },
        "model_executions": {
            "sigma-a0": asdict(execute(model, SIGMA_A0, [ACTION_SHARED_SUFFIX])),
            "sigma-a1": asdict(execute(model, SIGMA_A1, [ACTION_SHARED_SUFFIX])),
        },
        "shortest_output_witness": asdict(witness) if witness is not None else None,
    }


def _discipline_doc(bundle: Path, pre: dict[str, Any], docs: dict[str, Any]) -> dict[str, Any]:
    subsumption = docs.get("subsumption") or {}
    return {
        "schema": "rac-stock-linux-discipline-v1",
        "name": "D_stock_linux_frontier_local",
        "bundle": str(bundle),
        "states": {
            "sigma0": SIGMA_A0,
            "sigma1": SIGMA_A1,
            "meaning": "runtime prefix cases at the same verifier frontier before the common suffix",
        },
        "action_alphabet": [ACTION_SHARED_SUFFIX],
        "constraints": [
            "single eBPF object/program identity across verifier and runtime evidence",
            "path correspondence verified from xlated selector semantics and raw verifier histories",
            "both cases share the same remaining xlated suffix from the frontier",
            "local direct concretization memberships place each concrete case in its captured verifier state",
            "operational prune-cell coverage ties sigma-a0 to the retained representative via the observed current-pruned-by-retained edge",
            "report partition is the Linux retained-state representative emitted by is_state_visited pruning",
            "runtime observations are serialized within the supplied single-artifact harness",
        ],
        "frontier": docs["path_report"].get("frontier"),
        "identity": pre["identity"],
        "subsumption_scope": subsumption.get("theorem_scope"),
        "kernel": subsumption.get("kernel") or (docs.get("path_report", {}).get("identity") or {}),
        "preconditions": pre,
        "scope_note": (
            "This discipline is intentionally local to the captured stock-Linux verifier frontier and "
            "the observed common suffix. It is not a global theorem about all verifier states or all programs."
        ),
    }


def _markdown(factorization: dict[str, Any], quotient: dict[str, Any], suffix: dict[str, Any]) -> str:
    conditions = factorization["conditions"]
    lines = [
        "# Stock Linux Behavioral Factorization",
        "",
        f"Result: `{factorization['result']}`",
        "",
        "| Check | Pass |",
        "|---|---|",
        f"| `pi_R(sigma0) = pi_R(sigma1)` | {conditions['pi_R_equal']} |",
        f"| `beta_D(sigma0) != beta_D(sigma1)` | {conditions['beta_D_different']} |",
        f"| `Obs(w, sigma0) != Obs(w, sigma1)` | {conditions['observations_differ']} |",
        f"| old v0.2 R collision checker agrees | {conditions['auditor_R_output_witnessed']} |",
        "",
        f"Suffix word: `{ ' · '.join(suffix['suffix_word']) }`",
        "",
        "## beta map",
        "",
    ]
    for state, klass in factorization["beta_D"].items():
        lines.append(f"- `{state}` -> `{klass}`")
    lines.extend([
        "",
        "## quotient classes",
        "",
    ])
    for item in quotient["classes"]:
        lines.append(f"- `{item['class']}`: " + ", ".join(f"`{state}`" for state in item["states"]))
    if factorization["precondition_reasons"]:
        lines.extend(["", "## Reject reasons", ""])
        lines.extend(f"- `{reason}`" for reason in factorization["precondition_reasons"])
    else:
        lines.extend([
            "",
            "The same Linux report representative covers both concrete prefix cases, but the reviewed common suffix produces different runtime observations.",
        ])
    return "\n".join(lines) + "\n"


def extract_factorization(bundle: Path, out: Path | None = None) -> dict[str, Any]:
    bundle = bundle.resolve()
    docs = _collect_inputs(bundle)
    by_case = _runtime_by_case(docs["runtime"])
    report_cell, reps = _representative_cell(docs["report_map"])
    pre = _preconditions(docs, by_case, report_cell, reps)

    # Keep the finite model build deterministic even when a later precondition rejects;
    # this lets the emitted proof explain which factorization clause failed.
    model = _build_model(by_case, report_cell or "unresolved-retained-representative", docs)
    beta, quotient = _stable_beta(model)
    suffix = _suffix_witness(model, by_case, docs)
    analysis = analyze_model(model)

    pi_R = {SIGMA_A0: report_cell, SIGMA_A1: report_cell} if report_cell else {SIGMA_A0: None, SIGMA_A1: None}
    obs_a0 = _case_observation(by_case["a=0"])
    obs_a1 = _case_observation(by_case["a=1"])
    conditions = {
        "preconditions_passed": pre["passed"],
        "pi_R_equal": bool(report_cell) and pi_R[SIGMA_A0] == pi_R[SIGMA_A1],
        "beta_D_different": beta.get(SIGMA_A0) != beta.get(SIGMA_A1),
        "observations_differ": canonical_output(obs_a0) != canonical_output(obs_a1),
        "auditor_R_non_factorization": analysis["summary"].get("R_non_factorization") is True,
        "auditor_R_output_witnessed": analysis["summary"].get("R_output_witnessed") is True,
    }
    established = all(conditions.values())
    result = RESULT_ESTABLISHED if established else RESULT_REJECTED
    factorization = {
        "schema": "rac-stock-linux-factorization-v1",
        "result": result,
        "sigma": {"sigma0": SIGMA_A0, "sigma1": SIGMA_A1},
        "discipline": "D_stock_linux_frontier_local",
        "pi_R": pi_R,
        "beta_D": beta,
        "observations": {SIGMA_A0: obs_a0, SIGMA_A1: obs_a1},
        "conditions": conditions,
        "precondition_reasons": pre["reasons"],
        "auditor_summary": analysis["summary"],
        "auditor_R": analysis["R"],
        "auditor_C": analysis["C"],
    }
    beta_map = {
        "schema": "rac-stock-linux-beta-map-v1",
        "source_algorithm": "residuality_auditor.analysis.behavioral_partitions",
        "beta_D": beta,
        "pi_R": pi_R,
        "report_cell": report_cell,
        "representatives": reps,
    }
    discipline = _discipline_doc(bundle, pre, docs)

    out = out or bundle / "proof" / "factorization"
    out.mkdir(parents=True, exist_ok=True)
    _write_json(out / "discipline.json", discipline)
    _write_json(out / "behavioral-quotient.json", quotient)
    _write_json(out / "beta-map.json", beta_map)
    _write_json(out / "suffix-witness.json", suffix)
    _write_json(out / "factorization.json", factorization)
    (out / "factorization.md").write_text(_markdown(factorization, quotient, suffix), encoding="utf-8")
    (out / "auditor-analysis.md").write_text(render_markdown(analysis), encoding="utf-8")
    _write_json(out / "auditor-analysis.json", analysis)
    return factorization


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the stock-Linux behavioral quotient/factorization proof from a RAC evidence bundle.")
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    result = extract_factorization(args.bundle, args.out)
    print(result["result"])
    return 0 if result["result"] == RESULT_ESTABLISHED else 1


if __name__ == "__main__":
    raise SystemExit(main())
