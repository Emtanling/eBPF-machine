#!/usr/bin/env python3
import argparse
import hashlib
import json
import math
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
NORMAL_TRUTH = {(0, 0): 1, (0, 1): 1, (1, 0): 1, (1, 1): 0}
ALL1_TRUTH = {(0, 0): 1, (0, 1): 1, (1, 0): 1, (1, 1): 1}
FIXED_ADDER_CASES = {
    (0, 0),
    (1, 1),
    (0xFFFFFFFF, 1),
    (0x55555555, 0xAAAAAAAA),
    (0xFFFFFFFF, 0xFFFFFFFF),
}
FIXED_ADDER_TRIALS = {
    0: (0, 0),
    1: (1, 1),
    2: (0xFFFFFFFF, 1),
    3: (0x55555555, 0xAAAAAAAA),
    4: (0xFFFFFFFF, 0xFFFFFFFF),
}
PROVENANCE_SCHEMA = "weirdmachinebpf.provenance/v2"
PROVENANCE_RESULTS = {
    "nand": {
        "nand_truth_table.jsonl",
        "full_adder.jsonl",
        "adder32.jsonl",
        "adder32_exhaustive.jsonl",
    },
    "ablation_cap64": {"ablation_cap64.jsonl"},
    "ablation_k2_sentinel": {"ablation_k2_sentinel.jsonl"},
    "baseline_nand": {"baseline_nand.jsonl"},
}
PROVENANCE_BUILD_FLAGS = {
    "nand": "GATE_CAP=2",
    "ablation_cap64": "GATE_CAP=64",
    "ablation_k2_sentinel": "GATE_CAP=2 -DWM_FORCE_SENTINEL_B",
    "baseline_nand": "GATE_CAP=2 -DWM_BASELINE_NAND",
}
ROW_IDENTITIES = {
    "nand": (1, 2),
    "full_adder": (1, 2),
    "adder32": (1, 2),
    "adder_exhaustive": (1, 2),
    "ablation_cap64": (2, 64),
    "ablation_k2_sentinel": (3, 2),
    "baseline_nand": (4, 2),
}
REQUIRED_ARTIFACTS = {
    "bpf_object",
    "user_binary",
    "verifier_log",
    "xlated_dump",
    "build_log",
}
SOURCE_FILES = {
    "Makefile",
    "src/wm.bpf.c",
    "src/wm_user.c",
    "src/wm_common.h",
    "src/vmlinux.h",
    "scripts/run_kernel_suite.sh",
    "scripts/write_provenance.py",
    "scripts/audit_results.py",
    "scripts/capture_system_evidence.sh",
    "scripts/record_env.py",
    "scripts/check_results.py",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def sampled_adder_pairs(count: int = 1000) -> dict[int, tuple[int, int]]:
    state = 0x6D2B79F5

    def next_u32() -> int:
        nonlocal state
        state ^= (state << 13) & 0xFFFFFFFF
        state ^= state >> 17
        state ^= (state << 5) & 0xFFFFFFFF
        state &= 0xFFFFFFFF
        return state

    return {trial: (next_u32(), next_u32()) for trial in range(count)}


SAMPLED_ADDER_PAIRS = sampled_adder_pairs()


class Audit:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.suppressed_failures = 0
        self.negative_second_update_returns: set[int] = set()
        self.reported_observation_schema: set[tuple[str, tuple[str, ...]]] = set()

    def fail(self, message: str) -> None:
        if len(self.failures) < 200:
            self.failures.append(message)
        else:
            self.suppressed_failures += 1

    def require(self, condition: bool, message: str) -> None:
        if not condition:
            self.fail(message)


def load_jsonl(path: Path, audit: Audit) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        audit.fail(f"{path.name}: missing")
        return rows

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                audit.fail(f"{path.name}:{line_no}: invalid JSON: {exc}")
                continue
            if not isinstance(row, dict):
                audit.fail(f"{path.name}:{line_no}: JSON row is not an object")
                continue
            rows.append(row)

    if not rows:
        audit.fail(f"{path.name}: no rows")
    return rows


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_bound_file(results_dir: Path, owner: str, record: object,
                     audit: Audit) -> str | None:
    if not isinstance(record, dict):
        audit.fail(f"{owner}: binding is not an object")
        return None

    rel = record.get("path")
    expected_hash = record.get("sha256")
    if not isinstance(rel, str) or not rel:
        audit.fail(f"{owner}: binding path is missing or invalid")
        return None
    if not isinstance(expected_hash, str) or not SHA256_RE.fullmatch(expected_hash):
        audit.fail(f"{owner}: binding sha256 is not a lowercase 64-hex digest")
        return None

    base = results_dir.resolve()
    candidate = (results_dir / rel).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        audit.fail(f"{owner}: binding path escapes results directory: {rel}")
        return None
    if not candidate.is_file():
        audit.fail(f"{owner}: bound file is missing: {rel}")
        return rel
    audit.require(candidate.stat().st_size > 0,
                  f"{owner}: bound file is empty: {rel}")

    actual_hash = sha256_file(candidate)
    audit.require(
        actual_hash == expected_hash,
        f"{owner}: sha256 mismatch for {rel}: {actual_hash} != {expected_hash}",
    )
    return Path(rel).as_posix()


def load_manifest(path: Path, audit: Audit) -> dict | None:
    if not path.is_file():
        audit.fail(f"{path.name}: missing provenance manifest")
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        audit.fail(f"{path.name}: invalid provenance JSON: {exc}")
        return None
    if not isinstance(data, dict):
        audit.fail(f"{path.name}: provenance root is not an object")
        return None
    if data.get("schema") != PROVENANCE_SCHEMA:
        audit.fail(
            f"{path.name}: provenance schema {data.get('schema')!r} != "
            f"{PROVENANCE_SCHEMA!r}; legacy/unbound results must be rerun"
        )
        return None
    return data


def check_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None


def check_provenance(results_dir: Path, audit: Audit,
                     check_live_environment: bool = False) -> str | None:
    run_ids: set[str] = set()
    env_hashes: set[str] = set()
    object_hashes: dict[str, str] = {}

    for label, expected_results in PROVENANCE_RESULTS.items():
        manifest_name = f"{label}.provenance.json"
        manifest = load_manifest(results_dir / manifest_name, audit)
        if manifest is None:
            continue

        owner = manifest_name
        audit.require(manifest.get("label") == label,
                      f"{owner}: label {manifest.get('label')!r} != {label!r}")
        run_id = manifest.get("run_id")
        if isinstance(run_id, str) and RUN_ID_RE.fullmatch(run_id):
            run_ids.add(run_id)
        else:
            audit.fail(f"{owner}: run_id is missing or invalid")
        audit.require(check_timestamp(manifest.get("timestamp_utc")),
                      f"{owner}: timestamp_utc is not an ISO-8601 UTC timestamp")
        audit.require(manifest.get("build_flags") == PROVENANCE_BUILD_FLAGS[label],
                      f"{owner}: build_flags {manifest.get('build_flags')!r} != "
                      f"{PROVENANCE_BUILD_FLAGS[label]!r}")
        audit.require(manifest.get("bpftool_loadall_exit") == 0,
                      f"{owner}: bpftool_loadall_exit is not 0")

        environment = manifest.get("environment")
        env_path = check_bound_file(results_dir, f"{owner}:environment",
                                    environment, audit)
        audit.require(env_path == "env.json",
                      f"{owner}: environment path {env_path!r} != 'env.json'")
        if isinstance(environment, dict):
            env_hash = environment.get("sha256")
            if isinstance(env_hash, str):
                env_hashes.add(env_hash)
            snapshot = environment.get("snapshot")
            audit.require(isinstance(snapshot, dict),
                          f"{owner}: environment.snapshot is missing or invalid")
            if env_path is not None and isinstance(snapshot, dict):
                for hash_key in (
                    "bpf_object_sha256",
                    "verifier_log_sha256",
                    "feature_probe_sha256",
                    "vmlinux_btf_sha256",
                    "vmlinux_header_sha256",
                ):
                    audit.require(
                        isinstance(snapshot.get(hash_key), str)
                        and SHA256_RE.fullmatch(snapshot[hash_key]) is not None,
                        f"{owner}: environment {hash_key} is not a SHA-256 digest",
                    )
                for hash_key, evidence_name in (
                    ("verifier_log_sha256", "verifier.log"),
                    ("feature_probe_sha256", "feature_probe.txt"),
                ):
                    evidence_path = results_dir / evidence_name
                    audit.require(
                        evidence_path.is_file() and evidence_path.stat().st_size > 0,
                        f"{owner}: environment evidence is missing: {evidence_name}",
                    )
                    if evidence_path.is_file():
                        audit.require(
                            sha256_file(evidence_path) == snapshot.get(hash_key),
                            f"{owner}: environment {hash_key} != {evidence_name}",
                        )
                header_path = WORKSPACE_ROOT / "src" / "vmlinux.h"
                if header_path.is_file():
                    audit.require(
                        sha256_file(header_path)
                        == snapshot.get("vmlinux_header_sha256"),
                        f"{owner}: environment vmlinux header hash != current header",
                    )
                kernel_btf = Path("/sys/kernel/btf/vmlinux")
                if check_live_environment and kernel_btf.is_file():
                    audit.require(
                        sha256_file(kernel_btf)
                        == snapshot.get("vmlinux_btf_sha256"),
                        f"{owner}: environment kernel BTF hash != running kernel BTF",
                    )
                try:
                    actual_snapshot = json.loads(
                        (results_dir / env_path).read_text(encoding="utf-8")
                    )
                except (OSError, json.JSONDecodeError) as exc:
                    audit.fail(f"{owner}: cannot parse bound environment: {exc}")
                else:
                    audit.require(snapshot == actual_snapshot,
                                  f"{owner}: environment.snapshot != bound env JSON")

        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, dict):
            audit.fail(f"{owner}: artifacts is missing or invalid")
        else:
            missing = REQUIRED_ARTIFACTS - set(artifacts)
            audit.require(not missing,
                          f"{owner}: missing artifact bindings {sorted(missing)}")
            artifact_paths: dict[str, str | None] = {}
            for kind in sorted(REQUIRED_ARTIFACTS & set(artifacts)):
                artifact_paths[kind] = check_bound_file(
                    results_dir, f"{owner}:{kind}", artifacts[kind], audit
                )
            if isinstance(run_id, str) and RUN_ID_RE.fullmatch(run_id):
                expected_artifact_paths = {
                    "bpf_object": f"variants/{run_id}/{label}/wm.bpf.o",
                    "user_binary": f"variants/{run_id}/{label}/wm_user",
                    "verifier_log": f"{label}.verifier.log",
                    "xlated_dump": f"{label}.wm_nand.xlated.txt",
                    "build_log": f"{label}.build.log",
                }
                for kind, expected_path in expected_artifact_paths.items():
                    audit.require(
                        artifact_paths.get(kind) == expected_path,
                        f"{owner}: {kind} path {artifact_paths.get(kind)!r} != "
                        f"{expected_path!r}",
                    )
                vlog_path = artifact_paths.get("verifier_log")
                xlated_path = artifact_paths.get("xlated_dump")
                if vlog_path and xlated_path:
                    vlog_bytes = (results_dir / vlog_path).read_bytes()
                    xlated_bytes = (results_dir / xlated_path).read_bytes()
                    vlog_lines = vlog_bytes.splitlines()
                    audit.require(xlated_bytes in vlog_bytes,
                                  f"{owner}: xlated dump is not embedded in verifier log")
                    load_footers = [line for line in vlog_lines
                                    if line.startswith(b"bpftool_loadall_exit=")]
                    dump_footers = [line for line in vlog_lines
                                    if line.startswith(b"bpftool_xlated_dump_exit=")]
                    audit.require(load_footers == [b"bpftool_loadall_exit=0"],
                                  f"{owner}: verifier log lacks one loadall success footer")
                    audit.require(dump_footers == [b"bpftool_xlated_dump_exit=0"],
                                  f"{owner}: verifier log lacks one xlated success footer")
            obj = artifacts.get("bpf_object")
            if isinstance(obj, dict) and isinstance(obj.get("sha256"), str):
                object_hashes[label] = obj["sha256"]
                if label == "nand" and isinstance(environment, dict):
                    snapshot = environment.get("snapshot")
                    if isinstance(snapshot, dict):
                        audit.require(
                            snapshot.get("bpf_object_sha256") == obj["sha256"],
                            f"{owner}: env normal object hash != bound object hash",
                        )

        source_records = manifest.get("source_snapshot")
        observed_sources: set[str] = set()
        if not isinstance(source_records, list):
            audit.fail(f"{owner}: source_snapshot is missing or invalid")
        else:
            for idx, record in enumerate(source_records):
                if not isinstance(record, dict):
                    audit.fail(f"{owner}: source_snapshot[{idx}] is not an object")
                    continue
                workspace_path = record.get("workspace_path")
                if not isinstance(workspace_path, str):
                    audit.fail(f"{owner}: source_snapshot[{idx}] lacks workspace_path")
                    continue
                observed_sources.add(workspace_path)
                snapshot_path = check_bound_file(
                    results_dir, f"{owner}:source_snapshot[{idx}]", record, audit
                )
                expected_snapshot_path = (
                    f"variants/{run_id}/{label}/source/{workspace_path}"
                    if isinstance(run_id, str) else None
                )
                audit.require(snapshot_path == expected_snapshot_path,
                              f"{owner}: source snapshot path mismatch for "
                              f"{workspace_path}")
                current = WORKSPACE_ROOT / workspace_path
                if current.is_file() and snapshot_path is not None:
                    audit.require(
                        sha256_file(current) == sha256_file(results_dir / snapshot_path),
                        f"{owner}: current source differs from run snapshot: "
                        f"{workspace_path}",
                    )
                else:
                    audit.fail(f"{owner}: current source is missing: {workspace_path}")
        audit.require(observed_sources == SOURCE_FILES,
                      f"{owner}: source snapshot set {sorted(observed_sources)} != "
                      f"{sorted(SOURCE_FILES)}")

        records = manifest.get("results")
        observed_results: list[str] = []
        if not isinstance(records, list) or not records:
            audit.fail(f"{owner}: results bindings are missing or invalid")
        else:
            for idx, record in enumerate(records):
                rel = check_bound_file(results_dir, f"{owner}:results[{idx}]",
                                       record, audit)
                if rel is not None:
                    observed_results.append(rel)
        audit.require(
            set(observed_results) == expected_results,
            f"{owner}: bound results {sorted(set(observed_results))} != "
            f"{sorted(expected_results)}",
        )
        audit.require(len(observed_results) == len(set(observed_results)),
                      f"{owner}: duplicate result bindings")

    audit.require(len(run_ids) == 1,
                  f"provenance: manifests do not share one run_id: {sorted(run_ids)}")
    audit.require(len(env_hashes) == 1,
                  "provenance: manifests do not bind the same environment snapshot")
    if len(object_hashes) == len(PROVENANCE_RESULTS):
        audit.require(len(set(object_hashes.values())) == len(object_hashes),
                      "provenance: build variants do not have distinct BPF objects")
    return next(iter(run_ids)) if len(run_ids) == 1 else None


def check_second_update(name: str, idx: int, row: dict, audit: Audit,
                        expected_observed: bool, output_bit: int | None) -> None:
    prefix = f"{name}:{idx}"
    required = {
        "variant_id",
        "gate_cap",
        "second_update_observed",
        "second_update_raw_ret",
        "second_update_errno",
    }
    missing = required - set(row)
    if missing:
        report_key = (name, tuple(sorted(missing)))
        if report_key not in audit.reported_observation_schema:
            audit.reported_observation_schema.add(report_key)
            audit.fail(
                f"{prefix}: missing helper observation fields {sorted(missing)}; "
                "this result set predates raw-return capture and must be rerun"
            )
        return

    observed = row.get("second_update_observed")
    raw_ret = row.get("second_update_raw_ret")
    errno_value = row.get("second_update_errno")
    expected_variant_id, expected_gate_cap = ROW_IDENTITIES[name]
    audit.require(type(row.get("variant_id")) is int and
                  row.get("variant_id") == expected_variant_id,
                  f"{prefix}: variant_id {row.get('variant_id')!r} != "
                  f"{expected_variant_id}")
    audit.require(type(row.get("gate_cap")) is int and
                  row.get("gate_cap") == expected_gate_cap,
                  f"{prefix}: gate_cap {row.get('gate_cap')!r} != "
                  f"{expected_gate_cap}")
    audit.require(observed is expected_observed,
                  f"{prefix}: second_update_observed is {observed!r}, "
                  f"expected {expected_observed}")

    if not expected_observed:
        audit.require(raw_ret is None,
                      f"{prefix}: unobserved second_update_raw_ret must be null")
        audit.require(errno_value is None,
                      f"{prefix}: unobserved second_update_errno must be null")
        return

    if not isinstance(raw_ret, int) or isinstance(raw_ret, bool):
        audit.fail(f"{prefix}: second_update_raw_ret is not a signed integer")
        return
    if not isinstance(errno_value, int) or isinstance(errno_value, bool):
        audit.fail(f"{prefix}: second_update_errno is not an integer")
        return
    audit.require(raw_ret <= 0,
                  f"{prefix}: second_update_raw_ret must be 0 or negative, got {raw_ret}")
    audit.require(-(1 << 63) <= raw_ret,
                  f"{prefix}: second_update_raw_ret is outside signed int64 range")
    expected_errno = -raw_ret if raw_ret < 0 else 0
    audit.require(errno_value == expected_errno,
                  f"{prefix}: second_update_errno {errno_value} != {expected_errno}")
    if raw_ret < 0:
        audit.negative_second_update_returns.add(raw_ret)

    if output_bit is not None:
        if output_bit == 1:
            audit.require(raw_ret == 0,
                          f"{prefix}: output 1 requires second_update_raw_ret == 0, "
                          f"got {raw_ret}")
        elif output_bit == 0:
            audit.require(raw_ret < 0,
                          f"{prefix}: output 0 requires second_update_raw_ret < 0, "
                          f"got {raw_ret}")
        else:
            audit.fail(f"{prefix}: output bit is not Boolean: {output_bit!r}")


def common_row_checks(name: str, rows: list[dict], audit: Audit) -> None:
    for idx, row in enumerate(rows, 1):
        audit.require(row.get("passed") is True, f"{name}:{idx}: passed is not true")
        audit.require(row.get("err") == 0, f"{name}:{idx}: err is {row.get('err')}")


def check_nand(name: str, rows: list[dict], truth: dict[tuple[int, int], int],
               audit: Audit, full_suite: bool,
               expected_observed: bool) -> None:
    common_row_checks(name, rows, audit)
    counts: Counter[tuple[int, int]] = Counter()
    trials: dict[tuple[int, int], set[int]] = {key: set() for key in truth}

    for idx, row in enumerate(rows, 1):
        expected_case = "nand_all1" if name.startswith("ablation_") else "nand"
        audit.require(row.get("case") == expected_case,
                      f"{name}:{idx}: case {row.get('case')!r} != {expected_case!r}")
        a = row.get("a")
        b = row.get("b")
        if type(a) is not int or type(b) is not int:
            audit.fail(f"{name}:{idx}: inputs are not integer bits")
            continue
        key = (a, b)
        if key not in truth:
            audit.fail(f"{name}:{idx}: unexpected input pair {key}")
            continue
        expected = truth[key]
        audit.require(type(row.get("expected")) is int,
                      f"{name}:{idx}: expected is not an integer")
        audit.require(type(row.get("actual")) is int,
                      f"{name}:{idx}: actual is not an integer")
        audit.require(row.get("expected") == expected,
                      f"{name}:{idx}: expected field {row.get('expected')} != {expected}")
        audit.require(row.get("actual") == expected,
                      f"{name}:{idx}: actual field {row.get('actual')} != {expected}")
        check_second_update(name, idx, row, audit, expected_observed,
                            expected if expected_observed else None)
        trial = row.get("trial")
        if not isinstance(trial, int) or isinstance(trial, bool) or trial < 0:
            audit.fail(f"{name}:{idx}: trial is not a nonnegative integer")
        else:
            audit.require(trial not in trials[key],
                          f"{name}:{idx}: duplicate trial {trial} for input {key}")
            trials[key].add(trial)
        counts[key] += 1

    audit.require(set(counts) == set(truth),
                  f"{name}: input coverage {sorted(counts)} != {sorted(truth)}")
    if counts:
        unique_counts = set(counts.values())
        audit.require(len(unique_counts) == 1,
                      f"{name}: per-input repeat counts not uniform: {dict(counts)}")
        for key, count in counts.items():
            audit.require(len(trials[key]) == count,
                          f"{name}: duplicate/missing trial ids for input {key}")
        if full_suite:
            audit.require(unique_counts == {100},
                          f"{name}: full suite expected 100 repeats per input, got {dict(counts)}")
            for key in truth:
                audit.require(trials[key] == set(range(100)),
                              f"{name}: full suite trial coverage for {key} is not 0..99")
            audit.require(len(rows) == 400, f"{name}: full suite expected 400 rows, got {len(rows)}")


def check_full_adder(rows: list[dict], audit: Audit, full_suite: bool) -> None:
    common_row_checks("full_adder", rows, audit)
    seen: set[tuple[int, int, int]] = set()

    for idx, row in enumerate(rows, 1):
        audit.require(row.get("case") == "full_adder",
                      f"full_adder:{idx}: case != full_adder")
        key = (row.get("a"), row.get("b"), row.get("cin"))
        if any(type(bit) is not int or bit not in (0, 1) for bit in key):
            audit.fail(f"full_adder:{idx}: unexpected input triple {key}")
            continue
        total = key[0] + key[1] + key[2]
        expected_sum = total & 1
        expected_cout = (total >> 1) & 1
        audit.require(row.get("expected_sum") == expected_sum,
                      f"full_adder:{idx}: expected_sum mismatch")
        audit.require(row.get("expected_cout") == expected_cout,
                      f"full_adder:{idx}: expected_cout mismatch")
        audit.require(row.get("actual_sum") == expected_sum,
                      f"full_adder:{idx}: actual_sum mismatch")
        audit.require(row.get("actual_cout") == expected_cout,
                      f"full_adder:{idx}: actual_cout mismatch")
        check_second_update("full_adder", idx, row, audit, True, expected_cout)
        seen.add(key)

    expected_seen = {(a, b, c) for a in (0, 1) for b in (0, 1) for c in (0, 1)}
    audit.require(seen == expected_seen,
                  f"full_adder: input coverage {sorted(seen)} != {sorted(expected_seen)}")
    if full_suite:
        audit.require(len(rows) == 8, f"full_adder: full suite expected 8 rows, got {len(rows)}")


def check_adder32(rows: list[dict], audit: Audit, full_suite: bool) -> None:
    common_row_checks("adder32", rows, audit)
    fixed_seen: set[tuple[int, int]] = set()
    fixed_trials: set[int] = set()
    random_trials: set[int] = set()
    kinds = Counter()

    for idx, row in enumerate(rows, 1):
        x = row.get("x")
        y = row.get("y")
        audit.require(row.get("case") == "adder32",
                      f"adder32:{idx}: case != adder32")
        if type(x) is not int or type(y) is not int or not (0 <= x <= 0xFFFFFFFF) \
                or not (0 <= y <= 0xFFFFFFFF):
            audit.fail(f"adder32:{idx}: non-integer operands")
            continue
        wide = (x & 0xFFFFFFFF) + (y & 0xFFFFFFFF)
        expected = wide & 0xFFFFFFFF
        carry = wide >> 32
        audit.require(row.get("expected") == expected,
                      f"adder32:{idx}: expected {row.get('expected')} != {expected}")
        audit.require(row.get("actual") == expected,
                      f"adder32:{idx}: actual {row.get('actual')} != {expected}")
        audit.require(row.get("expected_carry") == carry,
                      f"adder32:{idx}: expected_carry {row.get('expected_carry')} != {carry}")
        audit.require(row.get("carry_out") == carry,
                      f"adder32:{idx}: carry_out {row.get('carry_out')} != {carry}")
        check_second_update("adder32", idx, row, audit, True, carry)
        kind = row.get("kind")
        kinds[kind] += 1
        trial = row.get("trial")
        if not isinstance(trial, int) or isinstance(trial, bool) or trial < 0:
            audit.fail(f"adder32:{idx}: trial is not a nonnegative integer")
            continue
        if kind == "fixed":
            audit.require(trial in FIXED_ADDER_TRIALS,
                          f"adder32:{idx}: unexpected fixed trial {trial}")
            if trial in FIXED_ADDER_TRIALS:
                audit.require((x, y) == FIXED_ADDER_TRIALS[trial],
                              f"adder32:{idx}: fixed trial {trial} operands mismatch")
            audit.require(trial not in fixed_trials,
                          f"adder32:{idx}: duplicate fixed trial {trial}")
            fixed_trials.add(trial)
            fixed_seen.add((x, y))
        elif kind == "random":
            audit.require(trial in SAMPLED_ADDER_PAIRS,
                          f"adder32:{idx}: unexpected random trial {trial}")
            if trial in SAMPLED_ADDER_PAIRS:
                audit.require((x, y) == SAMPLED_ADDER_PAIRS[trial],
                              f"adder32:{idx}: random trial {trial} operands "
                              "do not match deterministic PRNG")
            audit.require(trial not in random_trials,
                          f"adder32:{idx}: duplicate random trial {trial}")
            random_trials.add(trial)
        else:
            audit.fail(f"adder32:{idx}: unexpected kind {kind!r}")

    if full_suite:
        audit.require(len(rows) == 1005, f"adder32: full suite expected 1005 rows, got {len(rows)}")
        audit.require(kinds["fixed"] == 5, f"adder32: expected 5 fixed rows, got {kinds['fixed']}")
        audit.require(kinds["random"] == 1000,
                      f"adder32: expected 1000 random rows, got {kinds['random']}")
        audit.require(fixed_trials == set(range(5)),
                      "adder32: fixed trial coverage is not 0..4")
        audit.require(random_trials == set(range(1000)),
                      "adder32: random trial coverage is not 0..999")
        audit.require(fixed_seen == FIXED_ADDER_CASES,
                      f"adder32: fixed cases {sorted(fixed_seen)} != {sorted(FIXED_ADDER_CASES)}")


def check_adder_exhaustive(rows: list[dict], audit: Audit,
                           full_suite: bool) -> None:
    common_row_checks("adder_exhaustive", rows, audit)
    seen: set[tuple[int, int]] = set()

    for idx, row in enumerate(rows, 1):
        x = row.get("x")
        y = row.get("y")
        audit.require(row.get("case") == "adder32",
                      f"adder_exhaustive:{idx}: case != adder32")
        if type(x) is not int or type(y) is not int or x < 0 or y < 0:
            audit.fail(f"adder_exhaustive:{idx}: non-integer operands")
            continue
        wide = (x & 0xFFFFFFFF) + (y & 0xFFFFFFFF)
        audit.require(row.get("kind") == "exhaustive",
                      f"adder_exhaustive:{idx}: kind != exhaustive")
        audit.require(row.get("actual") == (wide & 0xFFFFFFFF),
                      f"adder_exhaustive:{idx}: actual mismatch")
        audit.require(row.get("expected") == (wide & 0xFFFFFFFF),
                      f"adder_exhaustive:{idx}: expected mismatch")
        audit.require(row.get("carry_out") == (wide >> 32),
                      f"adder_exhaustive:{idx}: carry mismatch")
        audit.require(row.get("expected_carry") == (wide >> 32),
                      f"adder_exhaustive:{idx}: expected_carry mismatch")
        check_second_update("adder_exhaustive", idx, row, audit, True, wide >> 32)
        seen.add((x, y))

    n = len(rows)
    side = math.isqrt(n)
    audit.require(side * side == n,
                  f"adder_exhaustive: row count {n} is not a perfect square")
    if side * side == n and side > 0:
        audit.require((side & (side - 1)) == 0,
                      f"adder_exhaustive: side {side} is not a power of two")
        expected_pairs = {(a, b) for a in range(side) for b in range(side)}
        audit.require(seen == expected_pairs,
                      "adder_exhaustive: input coverage incomplete")
        trials: set[int] = set()
        for idx, row in enumerate(rows, 1):
            x = row.get("x")
            y = row.get("y")
            if not isinstance(x, int) or isinstance(x, bool) or \
                    not isinstance(y, int) or isinstance(y, bool):
                continue
            expected_trial = x * side + y
            trial = row.get("trial")
            audit.require(trial == expected_trial,
                          f"adder_exhaustive:{idx}: trial {trial} != {expected_trial}")
            if isinstance(trial, int) and not isinstance(trial, bool):
                audit.require(trial not in trials,
                              f"adder_exhaustive:{idx}: duplicate trial {trial}")
                trials.add(trial)
        audit.require(trials == set(range(n)),
                      "adder_exhaustive: trial coverage is incomplete")
    if full_suite:
        audit.require(len(rows) == 65536,
                      f"adder_exhaustive: full suite expected 65536 rows, got {len(rows)}")
        audit.require(side == 256,
                      f"adder_exhaustive: full suite expected width 8, got side {side}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("results_dir", type=Path)
    parser.add_argument("--full-suite", action="store_true")
    args = parser.parse_args()

    audit = Audit()
    check_live_environment = (
        args.full_suite
        and args.results_dir.resolve() == (WORKSPACE_ROOT / "results").resolve()
    )
    run_id = check_provenance(
        args.results_dir, audit, check_live_environment=check_live_environment
    )
    specs = {
        "nand_truth_table.jsonl": ("nand", NORMAL_TRUTH, True),
        "baseline_nand.jsonl": ("baseline_nand", NORMAL_TRUTH, False),
        "ablation_cap64.jsonl": ("ablation_cap64", ALL1_TRUTH, True),
        "ablation_k2_sentinel.jsonl": (
            "ablation_k2_sentinel", ALL1_TRUTH, True
        ),
    }

    for filename, (name, truth, expected_observed) in specs.items():
        rows = load_jsonl(args.results_dir / filename, audit)
        if rows:
            check_nand(name, rows, truth, audit, args.full_suite,
                       expected_observed)

    fa_rows = load_jsonl(args.results_dir / "full_adder.jsonl", audit)
    if fa_rows:
        check_full_adder(fa_rows, audit, args.full_suite)

    adder_rows = load_jsonl(args.results_dir / "adder32.jsonl", audit)
    if adder_rows:
        check_adder32(adder_rows, audit, args.full_suite)

    exhaustive_path = args.results_dir / "adder32_exhaustive.jsonl"
    if exhaustive_path.exists():
        ex_rows = load_jsonl(exhaustive_path, audit)
        if ex_rows:
            check_adder_exhaustive(ex_rows, audit, args.full_suite)
    else:
        audit.fail("adder32_exhaustive.jsonl: missing")

    if audit.failures:
        for failure in audit.failures:
            print(failure, file=sys.stderr)
        if audit.suppressed_failures:
            print(
                f"... {audit.suppressed_failures} additional failure(s) suppressed",
                file=sys.stderr,
            )
        total_failures = len(audit.failures) + audit.suppressed_failures
        print(f"semantic audit: {total_failures} failure(s)", file=sys.stderr)
        return 1

    print("semantic audit: ok")
    if audit.negative_second_update_returns:
        returns = sorted(audit.negative_second_update_returns)
        print(
            "helper-return audit: success=0 and at-capacity ret<0; "
            f"observed negative return(s)={returns}, "
            f"errno(s)={sorted(-value for value in returns)}"
        )
    print(f"provenance audit: ok (run_id={run_id})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
