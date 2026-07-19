#!/usr/bin/env python3
"""Legacy-adapter Definition 2 checker for a frozen stock-Linux RAC evidence bundle."""
from __future__ import annotations

import argparse
import json
import platform
from pathlib import Path
from typing import Any

from tools.proof.check_stock_linux_r import check as check_stock_linux_r
from tools.proof.render_proof_report import render
from tools.proof.verdict import DEFINITION2_CHECKS, choose_verdict
from tools.proof.verify_hashes import build_manifest, sha256_file, verify_embedded_input_hashes, verify_hashes
from tools.proof.verify_manifest import load_or_build_manifest, validate_manifest


DOCS = {
    "frontier": "frontier-check.json",
    "program_info": "program-info.json",
    "runtime": "runtime.json",
    "state_capture": "proof/states/state-capture-check.json",
    "path": "proof/path/path-correspondence.json",
    "joint": "proof/concretization/joint-coverage.json",
    "membership_a0": "proof/concretization/membership-a0.json",
    "membership_a1": "proof/concretization/membership-a1.json",
    "subsumption": "proof/subsumption/subsumption-check.json",
    "kernel_source": "proof/subsumption/kernel-source-map.json",
    "report_map": "proof/report/report-map.json",
    "factorization": "proof/factorization/factorization.json",
    "beta_map": "proof/factorization/beta-map.json",
    "suffix_witness": "proof/factorization/suffix-witness.json",
    "kernel_identity": "proof/definition2/kernel-identity.json",
    "stock_linux_r": "proof/definition2/stock-linux-r-check.json",
}


class Definition2Error(ValueError):
    pass


def _load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"_missing": True, "_path": str(path)}
    except json.JSONDecodeError as exc:
        return {"_invalid_json": str(exc), "_path": str(path)}
    return data if isinstance(data, dict) else {"_invalid_json": "root is not object", "_path": str(path)}


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _first_token(path: Path) -> str | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    return text.split()[0] if text.split() else None


def _file_identity(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"path": str(path), "available": False}
    return {"path": str(path), "available": True, "size": path.stat().st_size, "sha256": sha256_file(path)}


def ensure_kernel_identity(bundle: Path) -> dict[str, Any]:
    out = bundle / DOCS["kernel_identity"]
    if out.exists():
        return _load_json(out)
    release = platform.release()
    btf = Path("/sys/kernel/btf/vmlinux")
    config = Path("/boot") / f"config-{release}"
    doc = {
        "schema": "rac-kernel-identity-v1",
        "kernel_release": release,
        "host": platform.platform(),
        "btf": _file_identity(btf),
        "config": _file_identity(config),
        "source": "local kernel identity files read without re-running verifier/runtime capture",
    }
    _write_json(out, doc)
    return doc


def _load_docs(bundle: Path) -> dict[str, dict[str, Any]]:
    return {name: _load_json(bundle / rel) for name, rel in DOCS.items()}


def _check(passed: bool, evidence: str, details: Any = None) -> dict[str, Any]:
    return {"passed": bool(passed), "evidence": evidence, "details": details}


def _runs_by_case(runtime: dict[str, Any]) -> dict[str, dict[str, Any]]:
    runs = runtime.get("runs") if isinstance(runtime.get("runs"), list) else []
    return {run.get("case"): run for run in runs if isinstance(run, dict) and run.get("case") in {"a=0", "a=1"}}


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _identity_values(docs: dict[str, dict[str, Any]]) -> dict[str, list[Any]]:
    aliases = {
        "object_sha256": ("object_sha256", "runtime_object_sha256"),
        "program_id": ("program_id", "runtime_program_id"),
        "program_tag": ("program_tag", "runtime_program_tag"),
        "program_pin": ("program_pin", "runtime_program_pin"),
        "xlated_sha256": ("xlated_sha256", "recorded_xlated_sha256", "runtime_xlated_sha256"),
    }
    values: dict[str, list[Any]] = {key: [] for key in aliases}
    sources = []
    for name in ("frontier", "state_capture", "path", "report_map"):
        doc = docs.get(name, {})
        ident = doc.get("identity")
        if isinstance(ident, dict):
            sources.append(ident)
    runtime = docs.get("runtime", {})
    if runtime:
        sources.append(runtime)
    kernel_source = docs.get("kernel_source", {})
    ident = kernel_source.get("program_identity")
    if isinstance(ident, dict):
        sources.append(ident)
    for source in sources:
        for key, names in aliases.items():
            for name in names:
                if name in source:
                    values[key].append(source[name])
    return values


def _identity_check(bundle: Path, docs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    values = _identity_values(docs)
    mismatches = {
        key: vals for key, vals in values.items() if vals and len({_canon(v) for v in vals}) > 1
    }
    missing_fields = [key for key, vals in values.items() if not vals]
    frontier_id = (docs.get("frontier", {}).get("identity") or {}) if isinstance(docs.get("frontier"), dict) else {}
    program = docs.get("program_info", {})
    program_checks = {
        "id_matches": program.get("id") == frontier_id.get("program_id"),
        "tag_matches": program.get("tag") == frontier_id.get("program_tag"),
        "name_matches": program.get("name") == frontier_id.get("program_name"),
    }
    object_file = _first_token(bundle / "object.sha256")
    xlated_file = _first_token(bundle / "xlated-rac_single.sha256")
    file_checks = {
        "object_sha_file_matches": object_file == frontier_id.get("object_sha256"),
        "xlated_sha_file_matches": xlated_file == (frontier_id.get("xlated_sha256") or frontier_id.get("recorded_xlated_sha256")),
    }
    kernel_id = docs.get("kernel_identity", {})
    kernel_source = docs.get("kernel_source", {})
    subsumption_kernel = docs.get("subsumption", {}).get("kernel") or {}
    runtime = docs.get("runtime", {})
    releases = [
        runtime.get("kernel_release"),
        kernel_source.get("kernel_release"),
        subsumption_kernel.get("kernel_release"),
        kernel_id.get("kernel_release"),
    ]
    releases = [x for x in releases if x]
    kernel_checks = {
        "kernel_release_consistent": bool(releases) and len(set(releases)) == 1,
        "btf_identity_present": isinstance(kernel_id.get("btf"), dict) and kernel_id["btf"].get("available") is True and isinstance(kernel_id["btf"].get("sha256"), str),
        "config_identity_present": isinstance(kernel_id.get("config"), dict) and kernel_id["config"].get("available") is True and isinstance(kernel_id["config"].get("sha256"), str),
    }
    passed = not mismatches and not missing_fields and all(program_checks.values()) and all(file_checks.values()) and all(kernel_checks.values())
    return _check(
        passed,
        "frontier/state/path/report/runtime identities plus kernel-identity.json",
        {
            "values": values,
            "mismatches": mismatches,
            "missing_fields": missing_fields,
            "program_checks": program_checks,
            "file_checks": file_checks,
            "kernel_checks": kernel_checks,
            "kernel_releases": releases,
        },
    )


def _hash_check(bundle: Path, out: Path, *, refresh_manifest: bool) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], str]:
    manifest_path = out / "manifest.json"
    if refresh_manifest and manifest_path.exists():
        manifest = build_manifest(bundle)
        source = "refreshed"
        _write_json(manifest_path, manifest)
    else:
        manifest, source = load_or_build_manifest(bundle, manifest_path)
    manifest_validation = validate_manifest(manifest)
    hashes = verify_hashes(bundle, manifest)
    embedded = verify_embedded_input_hashes(bundle)
    combined = {
        "schema": "rac-definition2-hash-gate-v1",
        "result": "EVIDENCE_HASHES_MATCH" if manifest_validation["passed"] and hashes["passed"] and embedded["passed"] else "EVIDENCE_HASH_CHECK_FAILED",
        "passed": manifest_validation["passed"] and hashes["passed"] and embedded["passed"],
        "manifest_source": source,
        "manifest_validation": manifest_validation,
        "manifest_hashes": hashes,
        "embedded_input_hashes": embedded,
    }
    return combined, manifest, manifest_validation, hashes, source


def evaluate(bundle: Path, *, refresh_manifest: bool = False) -> dict[str, Any]:
    bundle = bundle.resolve()
    out = bundle / "proof" / "definition2"
    out.mkdir(parents=True, exist_ok=True)
    ensure_kernel_identity(bundle)
    stock_linux_r = check_stock_linux_r(bundle, out / "stock-linux-r-check.json")
    docs = _load_docs(bundle)
    hash_gate, manifest, manifest_validation, hash_result, manifest_source = _hash_check(bundle, out, refresh_manifest=refresh_manifest)

    frontier = docs["frontier"]
    runtime = docs["runtime"]
    path = docs["path"]
    joint = docs["joint"]
    report_map = docs["report_map"]
    factorization = docs["factorization"]
    beta_map = docs["beta_map"]
    suffix_witness = docs["suffix_witness"]
    by_case = _runs_by_case(runtime)
    run0 = by_case.get("a=0", {})
    run1 = by_case.get("a=1", {})
    obs0 = run0.get("observation")
    obs1 = run1.get("observation")
    context0 = run0.get("context")
    context1 = run1.get("context")
    suffix0 = run0.get("suffix")
    suffix1 = run1.get("suffix")
    selected0 = run0.get("selected_state")
    selected1 = run1.get("selected_state")
    unique = report_map.get("unique_cell_check") or {}
    if not unique:
        cert_results = report_map.get("certificate_results") or {}
        unique = {
            "result": cert_results.get("unique_cell"),
            "representatives": cert_results.get("representatives"),
            "reasons": [],
        }
    reps = unique.get("representatives") or {}
    rep0 = reps.get("a=0") if isinstance(reps, dict) else None
    rep1 = reps.get("a=1") if isinstance(reps, dict) else None
    factor_conditions = factorization.get("conditions") or {}
    beta = beta_map.get("beta_D") if isinstance(beta_map.get("beta_D"), dict) else factorization.get("beta_D", {})

    checks = {
        "artifact_accepted": _check(
            frontier.get("result") == "FRONTIER_ELIGIBLE" and bool(docs["program_info"].get("id")),
            "frontier-check.json result and program-info.json",
            {"frontier_result": frontier.get("result"), "program_id": docs["program_info"].get("id")},
        ),
        "identity_consistent": _identity_check(bundle, docs),
        "concrete_states_reachable": _check(
            docs["membership_a0"].get("result") == "SIGMA_A0_IN_DIRECT_GAMMA"
            and docs["membership_a1"].get("result") == "SIGMA_A1_IN_DIRECT_GAMMA"
            and joint.get("result") == "JOINT_COVERAGE_CANDIDATE",
            "membership-a0/a1.json and joint-coverage.json",
            {
                "membership_a0": docs["membership_a0"].get("result"),
                "membership_a1": docs["membership_a1"].get("result"),
                "joint": joint.get("result"),
            },
        ),
        "context_same": _check(
            context0 is not None and _canon(context0) == _canon(context1) and isinstance(context0, dict) and context0.get("serialized") is True,
            "runtime.json contexts for a=0 and a=1",
            {"a=0": context0, "a=1": context1},
        ),
        "selected_state_different": _check(
            selected0 is not None and selected1 is not None and _canon(selected0) != _canon(selected1)
            and joint.get("selected_masks_differ") is True,
            "runtime selected_state plus joint selected_masks_differ",
            {"a=0": selected0, "a=1": selected1, "selected_masks": joint.get("selected_masks")},
        ),
        "same_suffix": _check(
            (path.get("common_suffix") or {}).get("same_remaining_xlated_suffix") is True
            and suffix0 is not None and _canon(suffix0) == _canon(suffix1)
            and (suffix_witness.get("runtime_suffix") or {}).get("same_operation") is True,
            "path-correspondence common_suffix, runtime suffix, suffix-witness.json",
            {"path_common_suffix": path.get("common_suffix"), "runtime_suffix_a0": suffix0, "runtime_suffix_a1": suffix1},
        ),
        "suffix_outputs_differ": _check(
            obs0 is not None and obs1 is not None and _canon(obs0) != _canon(obs1)
            and factor_conditions.get("observations_differ") is True,
            "runtime observations and factorization conditions",
            {"a=0": obs0, "a=1": obs1},
        ),
        "same_actual_report_cell": _check(
            unique.get("result") == "UNIQUE_SAME_REPORT_CELL"
            and isinstance(rep0, list) and len(rep0) == 1 and rep0 == rep1,
            "report-map unique_cell_check representatives",
            {"unique_result": unique.get("result"), "representatives": reps},
        ),
        "unique_cell_on_chosen_fiber": _check(
            unique.get("result") == "UNIQUE_SAME_REPORT_CELL" and not unique.get("reasons"),
            "proof/report/unique-cell-check result embedded in report-map.json",
            unique,
        ),
        "behavioral_quotient_different": _check(
            factor_conditions.get("beta_D_different") is True
            and isinstance(beta, dict)
            and beta.get("sigma-a0") != beta.get("sigma-a1"),
            "proof/factorization beta-map and factorization conditions",
            {"beta_D": beta, "condition": factor_conditions.get("beta_D_different")},
        ),
        "factorization_failure": _check(
            factorization.get("result") == "REPORT_FACTORIZATION_FAILURE_ESTABLISHED"
            and factor_conditions.get("pi_R_equal") is True
            and factor_conditions.get("observations_differ") is True
            and factor_conditions.get("auditor_R_output_witnessed") is True,
            "proof/factorization/factorization.json",
            {"result": factorization.get("result"), "conditions": factor_conditions},
        ),
        "stock_linux_four_checks": _check(
            stock_linux_r.get("passed") is True,
            "proof/definition2/stock-linux-r-check.json",
            {"result": stock_linux_r.get("result"), "checks": stock_linux_r.get("checks")},
        ),
        "evidence_hashes_match": _check(
            hash_gate["passed"],
            "manifest.json plus embedded input_sha256 fields",
            hash_gate,
        ),
    }
    verdict = choose_verdict(checks)
    reasons = [name for name in DEFINITION2_CHECKS if not checks[name]["passed"]]
    report = {
        "schema": "rac-definition2-integrated-check-v1",
        "verdict": verdict,
        "bundle": str(bundle),
        "checks": checks,
        "reasons": reasons,
        "manifest_source": manifest_source,
        "hash_gate": hash_gate,
    }
    _write_json(out / "manifest.json", manifest)
    _write_json(out / "manifest-validation.json", manifest_validation)
    _write_json(out / "hash-check.json", hash_result)
    _write_json(out / "embedded-input-hash-check.json", hash_gate["embedded_input_hashes"])
    _write_json(out / "definition2-check.json", report)
    _write_json(out / "verdict.json", {"schema": "rac-definition2-verdict-v1", "verdict": verdict, "reasons": reasons})
    (out / "definition2-report.md").write_text(render(report), encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--refresh-manifest", action="store_true")
    args = parser.parse_args(argv)
    report = evaluate(args.bundle, refresh_manifest=args.refresh_manifest)
    print(report["verdict"])
    return 0 if report["verdict"] == "STOCK_LINUX_R_ESTABLISHED_FOR_FROZEN_TUPLE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
