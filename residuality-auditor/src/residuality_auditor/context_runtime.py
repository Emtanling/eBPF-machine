"""Validate target-bound runtime receipts for bounded Stock-R contexts."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence


RUNTIME_SCHEMA = "rac-stock-r-v2-runtime-v1"
VALIDATION_SCHEMA = "rac-stock-r-context-runtime-validation-v1"
_IDENTITY_FIELDS = (
    "program_name",
    "program_id",
    "program_tag",
    "program_load_time",
    "object_sha256",
    "xlated_sha256",
    "kernel_release",
    "btf_sha256",
)
_TRIAL_IDENTITY_FIELDS = tuple(
    field for field in _IDENTITY_FIELDS if field != "xlated_sha256"
)
_RECEIPT_DIGEST_FIELDS = {
    "object": ("object_sha256", "OBJECT_DIGEST_MISMATCH"),
    "btf": ("btf_sha256", "BTF_DIGEST_MISMATCH"),
    "xlated": ("xlated_sha256", "XLATED_DIGEST_MISMATCH"),
}


class ContextRuntimeError(ValueError):
    """A context runtime document or receipt set is malformed."""


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ContextRuntimeError(f"{name} must be an object")
    return value


def _sequence(value: object, name: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise ContextRuntimeError(f"{name} must be an array")
    return value


def _exact_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _identity(value: object, name: str) -> Mapping[str, object]:
    identity = _mapping(value, name)
    missing = [field for field in _IDENTITY_FIELDS if field not in identity]
    if missing:
        raise ContextRuntimeError(f"{name} is missing {', '.join(missing)}")
    for field in ("program_name", "program_tag", "kernel_release"):
        if not isinstance(identity[field], str) or not identity[field]:
            raise ContextRuntimeError(f"{name}.{field} must be a non-empty string")
    for field in ("program_id", "program_load_time"):
        if not _exact_int(identity[field]):
            raise ContextRuntimeError(f"{name}.{field} must be an integer")
    for field in ("object_sha256", "xlated_sha256", "btf_sha256"):
        digest = identity[field]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ContextRuntimeError(f"{name}.{field} must be lowercase SHA-256")
    return identity


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ContextRuntimeError(f"cannot read receipt {path}: {exc}") from exc
    return digest.hexdigest()


def validate_context_runtime(
    runtime_document: object,
    target_identity_document: object,
    receipt_paths: Mapping[str, Path],
) -> dict[str, object]:
    """Validate runtime semantics, identity coherence, and retained receipt bytes."""

    runtime = _mapping(runtime_document, "runtime")
    if runtime.get("schema") != RUNTIME_SCHEMA:
        raise ContextRuntimeError(f"runtime.schema must be {RUNTIME_SCHEMA}")
    runtime_identity = _identity(runtime.get("identity"), "runtime.identity")
    target_identity = _identity(target_identity_document, "target_identity")
    trials = _sequence(runtime.get("trials"), "runtime.trials")
    if set(receipt_paths) != set(_RECEIPT_DIGEST_FIELDS):
        raise ContextRuntimeError("receipt_paths must contain object, btf, and xlated")

    reasons: list[str] = []
    if any(
        runtime_identity[field] != target_identity[field]
        for field in _IDENTITY_FIELDS
    ):
        reasons.append("TARGET_IDENTITY_MISMATCH")

    receipt_digests: dict[str, str] = {}
    for receipt_name, (identity_field, reason) in _RECEIPT_DIGEST_FIELDS.items():
        raw_path = receipt_paths[receipt_name]
        if not isinstance(raw_path, Path):
            raise ContextRuntimeError(f"receipt_paths.{receipt_name} must be a Path")
        actual_digest = _sha256_file(raw_path)
        receipt_digests[receipt_name] = actual_digest
        if actual_digest != target_identity[identity_field]:
            reasons.append(reason)

    if len(trials) < 4 or len(trials) % 2:
        reasons.append("TRIAL_COUNT_INVALID")
    for index, raw_trial in enumerate(trials):
        trial = _mapping(raw_trial, f"runtime.trials[{index}]")
        expected_case = index % 2
        if trial.get("trial_id") != index or not _exact_int(trial.get("trial_id")):
            reasons.append("TRIAL_ID_SEQUENCE_MISMATCH")
        case = trial.get("case")
        if not _exact_int(case) or case not in (0, 1):
            reasons.append("TRIAL_CASE_INVALID")
        if case != expected_case:
            reasons.append("TRIAL_SCHEDULE_MISMATCH")
        if trial.get("test_run_rc") != 0 or trial.get("test_run_errno") != 0:
            reasons.append("TEST_RUN_FAILED")
        if trial.get("map_read_rc") != 0:
            reasons.append("MAP_READ_FAILED")
        if trial.get("trace_read_rc") != 0:
            reasons.append("TRACE_READ_FAILED")
        if trial.get("retval") != case:
            reasons.append("RETVAL_CASE_MISMATCH")
        if trial.get("map_value_after") != case:
            reasons.append("MAP_CASE_MISMATCH")

        trial_identity = _mapping(
            trial.get("program_identity"),
            f"runtime.trials[{index}].program_identity",
        )
        if any(
            trial_identity.get(field) != runtime_identity[field]
            for field in _TRIAL_IDENTITY_FIELDS
        ):
            reasons.append("TRIAL_TARGET_IDENTITY_MISMATCH")

        trace = _mapping(trial.get("trace"), f"runtime.trials[{index}].trace")
        trace_values = (
            trace.get("branch"),
            trace.get("selected_value"),
            trace.get("observed_value"),
        )
        if any(value != case for value in trace_values):
            reasons.append("TRACE_CASE_MISMATCH")
        if (
            trace.get("reset_rc") != 0
            or trace.get("branch_rc") != 0
            or trace.get("trace_errors") != 0
            or trace.get("lookup_missing") is not False
        ):
            reasons.append("TRACE_CAPTURE_INVALID")

    invalid_reasons = sorted(set(reasons))
    return {
        "schema": VALIDATION_SCHEMA,
        "status": "INVALID" if invalid_reasons else "VERIFIED",
        "trial_count": len(trials),
        "invalid_reasons": invalid_reasons,
        "receipt_sha256": dict(sorted(receipt_digests.items())),
    }


def _read_json(path: Path, name: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContextRuntimeError(f"cannot read {name} {path}: {exc}") from exc


def _write_json(path: Path, document: Mapping[str, object]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ContextRuntimeError(f"cannot write validation report {path}: {exc}") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--target-identity", type=Path, required=True)
    parser.add_argument("--object", type=Path, required=True)
    parser.add_argument("--btf", type=Path, required=True)
    parser.add_argument("--xlated", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        result = validate_context_runtime(
            _read_json(args.runtime, "runtime"),
            _read_json(args.target_identity, "target identity"),
            {"object": args.object, "btf": args.btf, "xlated": args.xlated},
        )
        _write_json(args.json_out, result)
    except ContextRuntimeError as exc:
        malformed = {
            "schema": VALIDATION_SCHEMA,
            "status": "MALFORMED",
            "errors": [str(exc)],
        }
        try:
            _write_json(args.json_out, malformed)
        except ContextRuntimeError:
            pass
        return 2
    return 0 if result["status"] == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
