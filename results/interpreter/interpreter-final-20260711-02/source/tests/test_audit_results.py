#!/usr/bin/env python3
import json
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "scripts" / "audit_results.py"
WRITER = ROOT / "scripts" / "write_provenance.py"


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def add_helper_observation(row: dict, raw_ret: int | None,
                           variant_id: int = 1, gate_cap: int = 2) -> dict:
    observed = raw_ret is not None
    row.update(
        {
            "variant_id": variant_id,
            "gate_cap": gate_cap,
            "second_update_observed": observed,
            "second_update_raw_ret": raw_ret,
            "second_update_errno": -raw_ret if raw_ret is not None and raw_ret < 0 else (
                0 if observed else None
            ),
        }
    )
    return row


def sampled_pairs(count: int = 1000) -> list[tuple[int, int]]:
    state = 0x6D2B79F5
    values = []
    for _ in range(count):
        pair = []
        for _ in range(2):
            state ^= (state << 13) & 0xFFFFFFFF
            state ^= state >> 17
            state ^= (state << 5) & 0xFFFFFFFF
            state &= 0xFFFFFFFF
            pair.append(state)
        values.append((pair[0], pair[1]))
    return values


def write_provenance(tmp: Path, label: str, result_names: list[str],
                     run_id: str = "unit-test-run") -> None:
    variant_dir = tmp / "variants" / run_id / label
    variant_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "bpf_object": variant_dir / "wm.bpf.o",
        "user_binary": variant_dir / "wm_user",
        "verifier_log": tmp / f"{label}.verifier.log",
        "xlated_dump": tmp / f"{label}.wm_nand.xlated.txt",
        "build_log": tmp / f"{label}.build.log",
    }
    for kind, path in files.items():
        path.write_bytes(f"{label}:{kind}\n".encode())
    xlated_bytes = files["xlated_dump"].read_bytes()
    files["verifier_log"].write_bytes(
        b"verifier accepted\n" + xlated_bytes +
        b"bpftool_loadall_exit=0\nbpftool_xlated_dump_exit=0\n"
    )

    def record(path: Path) -> dict:
        return {"path": path.relative_to(tmp).as_posix(), "sha256": sha256(path)}

    source_snapshot = []
    source_files = (
        "Makefile", "src/wm.bpf.c", "src/wm_user.c", "src/wm_common.h",
        "src/vmlinux.h",
        "scripts/run_kernel_suite.sh", "scripts/write_provenance.py",
        "scripts/audit_results.py", "scripts/capture_system_evidence.sh",
        "scripts/record_env.py", "scripts/check_results.py",
    )
    for workspace_path in source_files:
        snapshot = variant_dir / "source" / workspace_path
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes((ROOT / workspace_path).read_bytes())
        source_snapshot.append(
            {"workspace_path": workspace_path, **record(snapshot)}
        )

    env = tmp / "env.json"
    if not env.exists():
        generic_verifier = tmp / "verifier.log"
        feature_probe = tmp / "feature_probe.txt"
        generic_verifier.write_text("unit verifier evidence\n", encoding="utf-8")
        feature_probe.write_text("unit feature evidence\n", encoding="utf-8")
        normal_obj = tmp / "variants" / run_id / "nand" / "wm.bpf.o"
        env_snapshot = {
            "uname": "unit-test-kernel",
            "bpf_object_sha256": sha256(normal_obj) if normal_obj.exists() else "0" * 64,
            "verifier_log_sha256": sha256(generic_verifier),
            "feature_probe_sha256": sha256(feature_probe),
            "vmlinux_btf_sha256": "3" * 64,
            "vmlinux_header_sha256": sha256(ROOT / "src" / "vmlinux.h"),
        }
        env.write_text(json.dumps(env_snapshot) + "\n", encoding="utf-8")

    manifest = {
        "schema": "weirdmachinebpf.provenance/v2",
        "run_id": run_id,
        "timestamp_utc": "2026-07-10T00:00:00Z",
        "label": label,
        "build_flags": {
            "nand": "GATE_CAP=2",
            "ablation_cap64": "GATE_CAP=64",
            "ablation_k2_sentinel": "GATE_CAP=2 -DWM_FORCE_SENTINEL_B",
            "baseline_nand": "GATE_CAP=2 -DWM_BASELINE_NAND",
        }[label],
        "bpftool_loadall_exit": 0,
        "environment": {
            **record(env),
            "snapshot": json.loads(env.read_text(encoding="utf-8")),
        },
        "artifacts": {kind: record(path) for kind, path in files.items()},
        "source_snapshot": source_snapshot,
        "results": [record(tmp / name) for name in result_names],
    }
    (tmp / f"{label}.provenance.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )


def run_audit(tmp: Path, full_suite: bool = False) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(AUDIT)]
    if full_suite:
        command.append("--full-suite")
    command.append(str(tmp))
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def minimal_valid_dataset(tmp: Path) -> None:
    nand_rows = []
    all1_rows = []
    for a in (0, 1):
        for b in (0, 1):
            expected = 0 if (a and b) else 1
            nand_rows.append(
                add_helper_observation({
                    "case": "nand",
                    "trial": 0,
                    "a": a,
                    "b": b,
                    "expected": expected,
                    "actual": expected,
                    "err": 0,
                    "passed": True,
                }, -7 if expected == 0 else 0)
            )
            all1_rows.append(
                add_helper_observation({
                    "case": "nand_all1",
                    "trial": 0,
                    "a": a,
                    "b": b,
                    "expected": 1,
                    "actual": 1,
                    "err": 0,
                    "passed": True,
                }, 0)
            )

    fa_rows = []
    for a in (0, 1):
        for b in (0, 1):
            for cin in (0, 1):
                total = a + b + cin
                fa_rows.append(
                    add_helper_observation({
                        "case": "full_adder",
                        "a": a,
                        "b": b,
                        "cin": cin,
                        "expected_sum": total & 1,
                        "expected_cout": (total >> 1) & 1,
                        "actual_sum": total & 1,
                        "actual_cout": (total >> 1) & 1,
                        "err": 0,
                        "passed": True,
                    }, 0 if ((total >> 1) & 1) else -7)
                )

    adder_rows = [
        add_helper_observation({
            "case": "adder32",
            "kind": "fixed",
            "trial": 2,
            "x": 0xFFFFFFFF,
            "y": 1,
            "expected": 0,
            "actual": 0,
            "expected_carry": 1,
            "carry_out": 1,
            "err": 0,
            "passed": True,
        }, 0)
    ]

    exhaustive_rows = []
    for x in (0, 1):
        for y in (0, 1):
            wide = x + y
            carry = wide >> 32
            exhaustive_rows.append(
                add_helper_observation(
                    {
                        "case": "adder32",
                        "kind": "exhaustive",
                        "trial": x * 2 + y,
                        "x": x,
                        "y": y,
                        "expected": wide,
                        "actual": wide,
                        "expected_carry": carry,
                        "carry_out": carry,
                        "err": 0,
                        "passed": True,
                    },
                    0 if carry else -7,
                )
            )

    baseline_rows = []
    for row in nand_rows:
        baseline = dict(row)
        baseline["case"] = "nand"
        add_helper_observation(baseline, None, variant_id=4)
        baseline_rows.append(baseline)

    write_jsonl(tmp / "nand_truth_table.jsonl", nand_rows)
    write_jsonl(tmp / "baseline_nand.jsonl", baseline_rows)
    write_jsonl(
        tmp / "ablation_cap64.jsonl",
        [{**row, "variant_id": 2, "gate_cap": 64} for row in all1_rows],
    )
    write_jsonl(
        tmp / "ablation_k2_sentinel.jsonl",
        [{**row, "variant_id": 3, "gate_cap": 2} for row in all1_rows],
    )
    write_jsonl(tmp / "full_adder.jsonl", fa_rows)
    write_jsonl(tmp / "adder32.jsonl", adder_rows)
    write_jsonl(tmp / "adder32_exhaustive.jsonl", exhaustive_rows)

    write_provenance(
        tmp,
        "nand",
        [
            "nand_truth_table.jsonl",
            "full_adder.jsonl",
            "adder32.jsonl",
            "adder32_exhaustive.jsonl",
        ],
    )
    write_provenance(tmp, "ablation_cap64", ["ablation_cap64.jsonl"])
    write_provenance(tmp, "ablation_k2_sentinel", ["ablation_k2_sentinel.jsonl"])
    write_provenance(tmp, "baseline_nand", ["baseline_nand.jsonl"])


def full_count_dataset_with_small_exhaustive(tmp: Path) -> None:
    minimal_valid_dataset(tmp)

    for filename in (
        "nand_truth_table.jsonl",
        "baseline_nand.jsonl",
        "ablation_cap64.jsonl",
        "ablation_k2_sentinel.jsonl",
    ):
        base_rows = [json.loads(line) for line in
                     (tmp / filename).read_text(encoding="utf-8").splitlines()]
        expanded = []
        for base in base_rows:
            for trial in range(100):
                row = dict(base)
                row["trial"] = trial
                expanded.append(row)
        write_jsonl(tmp / filename, expanded)

    fixed_pairs = [
        (0, 0),
        (1, 1),
        (0xFFFFFFFF, 1),
        (0x55555555, 0xAAAAAAAA),
        (0xFFFFFFFF, 0xFFFFFFFF),
    ]
    adder_rows = []
    for trial, (x, y) in enumerate(fixed_pairs):
        wide = x + y
        carry = wide >> 32
        adder_rows.append(add_helper_observation({
            "case": "adder32", "kind": "fixed", "trial": trial,
            "x": x, "y": y, "expected": wide & 0xFFFFFFFF,
            "actual": wide & 0xFFFFFFFF, "expected_carry": carry,
            "carry_out": carry, "err": 0, "passed": True,
        }, 0 if carry else -7))
    for trial, (x, y) in enumerate(sampled_pairs()):
        wide = x + y
        carry = wide >> 32
        adder_rows.append(add_helper_observation({
            "case": "adder32", "kind": "random", "trial": trial,
            "x": x, "y": y, "expected": wide & 0xFFFFFFFF,
            "actual": wide & 0xFFFFFFFF, "expected_carry": carry,
            "carry_out": carry, "err": 0, "passed": True,
        }, 0 if carry else -7))
    write_jsonl(tmp / "adder32.jsonl", adder_rows)

    write_provenance(
        tmp,
        "nand",
        [
            "nand_truth_table.jsonl", "full_adder.jsonl",
            "adder32.jsonl", "adder32_exhaustive.jsonl",
        ],
    )
    write_provenance(tmp, "ablation_cap64", ["ablation_cap64.jsonl"])
    write_provenance(tmp, "ablation_k2_sentinel", ["ablation_k2_sentinel.jsonl"])
    write_provenance(tmp, "baseline_nand", ["baseline_nand.jsonl"])


def test_audit_accepts_semantically_valid_dataset() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        minimal_valid_dataset(tmp)
        result = run_audit(tmp)
        assert result.returncode == 0, result.stderr + result.stdout
        assert "semantic audit: ok" in result.stdout


def test_audit_rejects_ablation_that_still_behaves_like_nand() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        minimal_valid_dataset(tmp)
        rows = (tmp / "ablation_cap64.jsonl").read_text(encoding="utf-8").splitlines()
        bad = json.loads(rows[-1])
        bad["expected"] = 0
        bad["actual"] = 0
        rows[-1] = json.dumps(bad)
        (tmp / "ablation_cap64.jsonl").write_text("\n".join(rows) + "\n", encoding="utf-8")
        write_provenance(tmp, "ablation_cap64", ["ablation_cap64.jsonl"])

        result = run_audit(tmp)
        assert result.returncode != 0
        assert "ablation_cap64" in result.stderr


def test_audit_rejects_nonnegative_at_capacity_return() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        minimal_valid_dataset(tmp)
        rows = [json.loads(line) for line in
                (tmp / "nand_truth_table.jsonl").read_text(encoding="utf-8").splitlines()]
        at_capacity = next(row for row in rows if row["a"] == 1 and row["b"] == 1)
        at_capacity["second_update_raw_ret"] = 0
        at_capacity["second_update_errno"] = 0
        write_jsonl(tmp / "nand_truth_table.jsonl", rows)
        # Keep provenance internally consistent so this test isolates the raw-return check.
        write_provenance(
            tmp,
            "nand",
            [
                "nand_truth_table.jsonl",
                "full_adder.jsonl",
                "adder32.jsonl",
                "adder32_exhaustive.jsonl",
            ],
        )

        result = run_audit(tmp)
        assert result.returncode != 0
        assert "second_update_raw_ret" in result.stderr


def test_audit_rejects_tampered_result_hash() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        minimal_valid_dataset(tmp)
        with (tmp / "nand_truth_table.jsonl").open("a", encoding="utf-8") as f:
            f.write("\n")

        result = run_audit(tmp)
        assert result.returncode != 0
        assert "sha256 mismatch" in result.stderr


def test_audit_rejects_legacy_unbound_manifest() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        minimal_valid_dataset(tmp)
        (tmp / "nand.provenance.json").write_text(
            json.dumps({"label": "nand", "bpf_object_sha256": "0" * 64}) + "\n",
            encoding="utf-8",
        )

        result = run_audit(tmp)
        assert result.returncode != 0
        assert "provenance schema" in result.stderr


def test_audit_rejects_tampered_variant_object() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        minimal_valid_dataset(tmp)
        obj = tmp / "variants" / "unit-test-run" / "nand" / "wm.bpf.o"
        obj.write_bytes(obj.read_bytes() + b"tampered\n")

        result = run_audit(tmp)
        assert result.returncode != 0
        assert "nand.provenance.json:bpf_object: sha256 mismatch" in result.stderr


def test_audit_rejects_mixed_run_ids() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        minimal_valid_dataset(tmp)
        manifest_path = tmp / "baseline_nand.provenance.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["run_id"] = "different-run"
        manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")

        result = run_audit(tmp)
        assert result.returncode != 0
        assert "do not share one run_id" in result.stderr


def test_provenance_writer_hashes_every_required_file() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        variant = tmp / "variants" / "writer-run" / "nand"
        variant.mkdir(parents=True)
        env = tmp / "env.json"
        obj = variant / "wm.bpf.o"
        user = variant / "wm_user"
        verifier = tmp / "nand.verifier.log"
        xlated = tmp / "nand.wm_nand.xlated.txt"
        build_log = tmp / "nand.build.log"
        result_file = tmp / "nand_truth_table.jsonl"
        for path in (obj, user, xlated, build_log, result_file):
            path.write_text(path.name + "\n", encoding="utf-8")
        verifier.write_bytes(
            b"accepted\n" + xlated.read_bytes() +
            b"bpftool_loadall_exit=0\nbpftool_xlated_dump_exit=0\n"
        )
        env.write_text(json.dumps({"uname": "writer-test"}) + "\n", encoding="utf-8")

        source_args = []
        for workspace_path in (
            "Makefile", "src/wm.bpf.c", "src/wm_user.c", "src/wm_common.h",
            "src/vmlinux.h",
            "scripts/run_kernel_suite.sh", "scripts/write_provenance.py",
            "scripts/audit_results.py", "scripts/capture_system_evidence.sh",
            "scripts/record_env.py", "scripts/check_results.py",
        ):
            snapshot = variant / "source" / workspace_path
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            snapshot.write_bytes((ROOT / workspace_path).read_bytes())
            source_args.extend(["--source", workspace_path, str(snapshot)])

        completed = subprocess.run(
            [
                sys.executable,
                str(WRITER),
                "--results-dir", str(tmp),
                "--label", "nand",
                "--run-id", "writer-run",
                "--timestamp-utc", "2026-07-10T01:02:03Z",
                "--build-flags", "GATE_CAP=2",
                "--bpftool-loadall-exit", "0",
                "--environment", str(env),
                "--bpf-object", str(obj),
                "--user-binary", str(user),
                "--verifier-log", str(verifier),
                "--xlated-dump", str(xlated),
                "--build-log", str(build_log),
                *source_args,
                "--result", str(result_file),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        manifest = json.loads((tmp / "nand.provenance.json").read_text(encoding="utf-8"))
        assert manifest["schema"] == "weirdmachinebpf.provenance/v2"
        assert manifest["run_id"] == "writer-run"
        assert set(manifest["artifacts"]) == {
            "bpf_object", "user_binary", "verifier_log", "xlated_dump",
            "build_log",
        }
        assert len(manifest["source_snapshot"]) == 11
        assert manifest["results"][0]["sha256"] == sha256(result_file)
        assert manifest["environment"]["snapshot"] == {"uname": "writer-test"}


def test_full_suite_rejects_non_8bit_exhaustive_dataset() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        full_count_dataset_with_small_exhaustive(tmp)
        result = run_audit(tmp, full_suite=True)
        assert result.returncode != 0
        assert "full suite expected 65536 rows, got 4" in result.stderr


def test_provenance_writer_rejects_label_path_traversal() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        result = subprocess.run(
            [sys.executable, str(WRITER), "--label", "../escaped"],
            cwd=tmp,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        assert result.returncode != 0
        assert "invalid choice" in result.stderr
        assert not (tmp.parent / "escaped.provenance.json").exists()


def test_audit_rejects_replayed_nand_trials() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        minimal_valid_dataset(tmp)
        path = tmp / "nand_truth_table.jsonl"
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        write_jsonl(path, rows + [dict(row) for row in rows])
        write_provenance(
            tmp, "nand",
            ["nand_truth_table.jsonl", "full_adder.jsonl", "adder32.jsonl",
             "adder32_exhaustive.jsonl"],
        )
        result = run_audit(tmp)
        assert result.returncode != 0
        assert "duplicate trial 0" in result.stderr


def test_audit_rejects_replayed_random_trial() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        minimal_valid_dataset(tmp)
        path = tmp / "adder32.jsonl"
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        random_row = add_helper_observation({
            "case": "adder32", "kind": "random", "trial": 0,
            "x": 0, "y": 0, "expected": 0, "actual": 0,
            "expected_carry": 0, "carry_out": 0, "err": 0, "passed": True,
        }, -7)
        write_jsonl(path, rows + [random_row, dict(random_row)])
        write_provenance(
            tmp, "nand",
            ["nand_truth_table.jsonl", "full_adder.jsonl", "adder32.jsonl",
             "adder32_exhaustive.jsonl"],
        )
        result = run_audit(tmp)
        assert result.returncode != 0
        assert "duplicate random trial 0" in result.stderr


def test_audit_rejects_relabelled_random_operands() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        full_count_dataset_with_small_exhaustive(tmp)
        path = tmp / "adder32.jsonl"
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        for row in rows:
            if row["kind"] == "random":
                row.update({"x": 0, "y": 0, "expected": 0, "actual": 0,
                            "expected_carry": 0, "carry_out": 0})
                add_helper_observation(row, -7)
        write_jsonl(path, rows)
        write_provenance(
            tmp, "nand",
            ["nand_truth_table.jsonl", "full_adder.jsonl", "adder32.jsonl",
             "adder32_exhaustive.jsonl"],
        )
        result = run_audit(tmp)
        assert result.returncode != 0
        assert "do not match deterministic PRNG" in result.stderr


def test_audit_rejects_conflicting_verifier_footer() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        minimal_valid_dataset(tmp)
        verifier = tmp / "nand.verifier.log"
        verifier.write_bytes(
            verifier.read_bytes() + b"bpftool_loadall_exit=1\n"
        )
        manifest_path = tmp / "nand.provenance.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["artifacts"]["verifier_log"]["sha256"] = sha256(verifier)
        manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
        result = run_audit(tmp)
        assert result.returncode != 0
        assert "lacks one loadall success footer" in result.stderr


def test_audit_rejects_environment_object_mismatch() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        minimal_valid_dataset(tmp)
        env = tmp / "env.json"
        snapshot = json.loads(env.read_text(encoding="utf-8"))
        snapshot["bpf_object_sha256"] = "f" * 64
        env.write_text(json.dumps(snapshot) + "\n", encoding="utf-8")
        write_provenance(
            tmp, "nand",
            ["nand_truth_table.jsonl", "full_adder.jsonl", "adder32.jsonl",
             "adder32_exhaustive.jsonl"],
        )
        write_provenance(tmp, "ablation_cap64", ["ablation_cap64.jsonl"])
        write_provenance(
            tmp, "ablation_k2_sentinel", ["ablation_k2_sentinel.jsonl"]
        )
        write_provenance(tmp, "baseline_nand", ["baseline_nand.jsonl"])
        result = run_audit(tmp)
        assert result.returncode != 0
        assert "env normal object hash != bound object hash" in result.stderr


if __name__ == "__main__":
    test_audit_accepts_semantically_valid_dataset()
    test_audit_rejects_ablation_that_still_behaves_like_nand()
    test_audit_rejects_nonnegative_at_capacity_return()
    test_audit_rejects_tampered_result_hash()
    test_audit_rejects_legacy_unbound_manifest()
    test_audit_rejects_tampered_variant_object()
    test_audit_rejects_mixed_run_ids()
    test_provenance_writer_hashes_every_required_file()
    test_full_suite_rejects_non_8bit_exhaustive_dataset()
    test_provenance_writer_rejects_label_path_traversal()
    test_audit_rejects_replayed_nand_trials()
    test_audit_rejects_replayed_random_trial()
    test_audit_rejects_relabelled_random_operands()
    test_audit_rejects_conflicting_verifier_footer()
    test_audit_rejects_environment_object_mismatch()
    print("audit result tests: ok")
