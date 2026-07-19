from __future__ import annotations

import copy
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

from residuality_auditor.reproduction import (
    CapsuleInputs,
    ReproductionError,
    build_replay_capsule,
    compare_reproduction_summary,
    normalize_reproduction_result,
    replay_capsule,
    verify_and_extract_capsule,
    verify_manifested_tree,
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)


def _closure(entries: list[tuple[str, bytes]], schema: str) -> dict[str, object]:
    return {
        "schema": schema,
        "entries": [
            {"path": path, "sha256": _sha256_bytes(value), "size": len(value)}
            for path, value in entries
        ],
    }


def make_capsule_fixture(root: Path) -> CapsuleInputs:
    v2 = root / "v2"
    source_entries = [("linux/witness.c", b"int witness(void) { return 0; }\n")]
    for relative, value in source_entries:
        _write(v2 / "build" / "source" / relative, value)
    source_manifest = _closure(source_entries, "rac-stock-r-v2-source-closure-v1")
    _write_json(v2 / "build" / "source-manifest.json", source_manifest)

    btf = b"tiny common btf\n"
    object_bytes = b"tiny source object\n"
    artifact_entries = [
        ("btf-vmlinux", btf),
        ("rac_v2_witness.bpf.o", object_bytes),
    ]
    for relative, value in artifact_entries:
        _write(v2 / "build" / relative, value)
    artifact_manifest = _closure(
        artifact_entries,
        "rac-stock-r-v2-build-closure-v1",
    )
    _write_json(v2 / "build" / "artifact-manifest.json", artifact_manifest)
    source_manifest_bytes = (v2 / "build" / "source-manifest.json").read_bytes()
    artifact_manifest_bytes = (v2 / "build" / "artifact-manifest.json").read_bytes()
    v2_identity = {
        "program_name": "rac_v2_single",
        "program_id": 77,
        "program_tag": "0123456789abcdef",
        "program_load_time": 1234,
        "object_sha256": _sha256_bytes(object_bytes),
        "xlated_sha256": _sha256_bytes(b"source xlated\n"),
        "kernel_release": "6.17.0-fixture",
        "btf_sha256": _sha256_bytes(btf),
    }
    fixed_json = {
        "query/query.json": {
            "identity": v2_identity,
            "source_closure_sha256": _sha256_bytes(source_manifest_bytes),
            "build_closure_sha256": _sha256_bytes(artifact_manifest_bytes),
        },
        "query/selection-policy.json": {"schema": "fixture-policy"},
        "query/precommit.json": {"schema": "fixture-precommit"},
        "contract/capture-contract.json": {"schema": "fixture-contract"},
        "raw/runtime.json": {"schema": "fixture-runtime", "identity": v2_identity},
        "raw/program-info.json": {"id": 77, "tag": "0123456789abcdef"},
        "proof/must-outcome-proof.json": {"schema": "fixture-must-proof"},
        "proof/history-case-binding.json": {"schema": "fixture-binding"},
    }
    for relative, document in fixed_json.items():
        _write_json(v2 / relative, document)
    _write(v2 / "raw" / "events.jsonl", b'{"event":"fixture"}\n')
    _write(v2 / "raw" / "xlated-rac_v2_single.txt", b"source xlated\n")

    contexts: list[Path] = []
    for index in range(2):
        context = root / f"context-{index}"
        contexts.append(context)
        target_object = f"target object {index}\n".encode()
        target_xlated = f"target xlated {index}\n".encode()
        identity = {
            **v2_identity,
            "program_id": 80 + index,
            "program_tag": f"{index + 1:016x}",
            "object_sha256": _sha256_bytes(target_object),
            "xlated_sha256": _sha256_bytes(target_xlated),
        }
        _write(
            context / "work" / "linux" / "witness" / "rac_v2_witness.bpf.c",
            f"/* generated context {index} */\n".encode(),
        )
        _write(context / "target" / "build" / "rac_v2_contextual.bpf.o", target_object)
        _write(context / "target" / "raw" / "xlated-rac_v2_contextual.txt", target_xlated)
        _write_json(context / "target" / "identity.json", identity)
        _write_json(
            context / "target" / "raw" / "runtime.json",
            {"schema": "fixture-context-runtime", "identity": identity, "trials": []},
        )
        _write_json(
            context / "target" / "raw" / "program-info.json",
            {"id": identity["program_id"], "tag": identity["program_tag"]},
        )
        _write_json(
            context / "target" / "audit" / "runtime-validation.json",
            {"schema": "fixture-validation", "status": "VERIFIED"},
        )
        _write_json(
            context / "context" / "transform-metadata.json",
            {
                "schema": "rac-stock-r-context-transform-metadata-v1",
                "suite_id": "fixture-suite",
                "case_id": f"transparent.fixture-{index}",
                "claim_boundary": "EXACT_TARGET_ONLY",
            },
        )
    return CapsuleInputs(v2_bundle=v2, context_bundles=tuple(contexts))


def _context_runtime(identity: dict[str, object]) -> dict[str, object]:
    trials = []
    for index in range(4):
        case = index % 2
        trials.append(
            {
                "trial_id": index,
                "case": case,
                "test_run_rc": 0,
                "test_run_errno": 0,
                "map_read_rc": 0,
                "trace_read_rc": 0,
                "retval": case,
                "map_value_after": case,
                "program_identity": dict(identity),
                "trace": {
                    "reset_rc": 0,
                    "branch_rc": 0,
                    "trace_errors": 0,
                    "lookup_missing": False,
                    "branch": case,
                    "selected_value": case,
                    "observed_value": case,
                },
            }
        )
    return {
        "schema": "rac-stock-r-v2-runtime-v1",
        "identity": dict(identity),
        "trials": trials,
    }


def make_real_capsule_fixture(root: Path) -> CapsuleInputs:
    from residuality_auditor.stock_r_v2 import (
        make_history_case_binding,
        make_must_outcome_proof,
    )
    from tests.test_stock_r_v2 import _bundle, _events

    v2 = root / "real-v2"
    _bundle(v2)
    query = json.loads((v2 / "query" / "query.json").read_text(encoding="utf-8"))
    runtime = json.loads((v2 / "raw" / "runtime.json").read_text(encoding="utf-8"))
    proof = make_must_outcome_proof(query, runtime)
    binding = make_history_case_binding(query, _events(runtime["identity"])[1], runtime, proof)
    (v2 / "proof").mkdir(parents=True, exist_ok=True)
    _write_json(v2 / "proof" / "must-outcome-proof.json", proof)
    _write_json(v2 / "proof" / "history-case-binding.json", binding)
    v2_query = json.loads((v2 / "query" / "query.json").read_text(encoding="utf-8"))
    v2_identity = v2_query["identity"]

    contexts: list[Path] = []
    for index in range(2):
        context = root / f"real-context-{index}"
        contexts.append(context)
        target_object = f"real target object {index}\n".encode()
        target_xlated = f"real target xlated {index}\n".encode()
        identity = {
            **v2_identity,
            "program_id": 8000 + index,
            "program_tag": f"{index + 10:016x}",
            "program_load_time": 9000 + index,
            "object_sha256": _sha256_bytes(target_object),
            "xlated_sha256": _sha256_bytes(target_xlated),
        }
        _write(
            context / "work" / "linux" / "witness" / "rac_v2_witness.bpf.c",
            f"/* real generated context {index} */\n".encode(),
        )
        _write(context / "target" / "build" / "rac_v2_contextual.bpf.o", target_object)
        _write(context / "target" / "raw" / "xlated-rac_v2_contextual.txt", target_xlated)
        _write_json(context / "target" / "identity.json", identity)
        _write_json(context / "target" / "raw" / "runtime.json", _context_runtime(identity))
        _write_json(
            context / "target" / "raw" / "program-info.json",
            {"id": identity["program_id"], "tag": identity["program_tag"]},
        )
        _write_json(
            context / "target" / "audit" / "runtime-validation.json",
            {
                "schema": "rac-stock-r-context-runtime-validation-v1",
                "status": "VERIFIED",
                "trial_count": 4,
                "invalid_reasons": [],
            },
        )
        _write_json(
            context / "context" / "transform-metadata.json",
            {
                "schema": "rac-stock-r-context-transform-metadata-v1",
                "suite_id": "fixture-real-suite",
                "case_id": f"transparent.real-{index}",
                "variant_id": f"transparent.real-{index}",
                "claim_boundary": "EXACT_TARGET_ONLY",
                "transform_id": f"context.stock-r-v2.real-{index}",
                "primitive": "POST_COLLISION_FRAMED_COMPUTATION",
                "parameters": {"fixture": index},
            },
        )
    return CapsuleInputs(v2_bundle=v2, context_bundles=tuple(contexts))


def _archive_bytes(members: list[tuple[tarfile.TarInfo, bytes]]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for info, value in members:
            archive.addfile(info, io.BytesIO(value) if info.isreg() else None)
    return lzma.compress(raw.getvalue(), format=lzma.FORMAT_XZ, preset=9)


def _regular_info(name: str, value: bytes) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.REGTYPE
    info.size = len(value)
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.mtime = 0
    return info


def _manifest_for_archive(base: dict[str, object], archive_bytes: bytes) -> dict[str, object]:
    manifest = copy.deepcopy(base)
    manifest["archive"]["sha256"] = _sha256_bytes(archive_bytes)
    manifest["archive"]["size"] = len(archive_bytes)
    return manifest


class ReproductionArtifactTests(unittest.TestCase):
    def test_capsule_builder_is_byte_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_capsule_fixture(root)
            first = root / "first.tar.xz"
            second = root / "second.tar.xz"
            first_manifest_path = root / "first-manifest.json"
            second_manifest_path = root / "second-manifest.json"

            first_manifest = build_replay_capsule(inputs, first, first_manifest_path)
            second_manifest = build_replay_capsule(inputs, second, second_manifest_path)

            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first_manifest, second_manifest)
            self.assertEqual(
                first_manifest_path.read_bytes(), second_manifest_path.read_bytes()
            )
            self.assertLessEqual(first.stat().st_size, 25 * 1024 * 1024)

    def test_offline_replay_normalizes_expected_scientific_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "capsule.tar.xz"
            manifest_path = root / "manifest.json"
            inputs = make_real_capsule_fixture(root)
            manifest = build_replay_capsule(inputs, archive, manifest_path)
            extracted = root / "extracted"
            verify_and_extract_capsule(archive, manifest, extracted)

            summary = normalize_reproduction_result(replay_capsule(extracted))

            self.assertEqual(summary["v1"]["status"], "BLOCKED")
            self.assertIn("MUST_OUTCOME_PROOF", summary["v1"]["missing_obligations"])
            self.assertEqual(summary["v2"]["status"], "CERTIFIED")
            self.assertEqual(summary["v2"]["assessment"], "NONFACTORING")
            self.assertEqual(summary["v2"]["scope"], "EXACT_STOCK_R_V2_QUERY")
            self.assertEqual(summary["v2"]["certificate"], manifest["certificates"]["v2"])
            self.assertTrue(summary["hostile"]["v2"]["all_expected"])
            self.assertEqual(summary["hostile"]["v2"]["case_count"], 12)
            self.assertEqual(len(summary["contexts"]), 2)
            self.assertEqual(summary["unexpected_results"], 0)
            for index, context in enumerate(summary["contexts"]):
                self.assertEqual(context["status"], "CERTIFIED")
                self.assertEqual(context["scope"], "EXACT_TARGET_ONLY")
                self.assertEqual(
                    context["certificate"],
                    manifest["certificates"]["contexts"][index],
                )
                self.assertTrue(context["hostile"]["all_expected"])
                self.assertEqual(context["hostile"]["case_count"], 12)

    def test_normalized_summary_rejects_scope_promotion(self) -> None:
        observed = {
            "schema": "rac-stock-r-reproduction-summary-v1",
            "v2": {"scope": "EXACT_STOCK_R_V2_QUERY"},
            "unexpected_results": 0,
        }
        expected = copy.deepcopy(observed)
        expected["v2"]["scope"] = "FORALL"

        comparison = compare_reproduction_summary(observed, expected)

        self.assertFalse(comparison["all_expected"])
        self.assertIn("v2.scope", comparison["mismatches"])

    def test_comparison_rejects_unexpected_observed_promotion(self) -> None:
        expected = {
            "schema": "rac-stock-r-reproduction-summary-v1",
            "v2": {"status": "CERTIFIED"},
            "contexts": [],
            "unexpected_results": 0,
        }
        observed = copy.deepcopy(expected)
        observed["v2"]["quantifier"] = "FORALL"

        comparison = compare_reproduction_summary(observed, expected)

        self.assertFalse(comparison["all_expected"])
        self.assertIn("v2.quantifier", comparison["mismatches"])

    def test_valid_capsule_extracts_to_an_exact_manifested_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "capsule.tar.xz"
            manifest_path = root / "manifest.json"
            manifest = build_replay_capsule(
                make_capsule_fixture(root), archive, manifest_path
            )
            destination = root / "extracted"

            verify_and_extract_capsule(archive, manifest, destination)
            verify_manifested_tree(destination, manifest)

            self.assertTrue((destination / "v2" / "query" / "query.json").is_file())
            self.assertFalse((destination / "contexts" / "0" / "target" / "build" / "btf-vmlinux").exists())

    def test_capsule_manifest_records_checked_source_and_context_certificates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "capsule.tar.xz"
            manifest_path = root / "manifest.json"

            manifest = build_replay_capsule(
                make_real_capsule_fixture(root), archive, manifest_path
            )

            certificates = manifest["certificates"]
            self.assertRegex(certificates["v2"], r"^NONFACTORING@[0-9a-f]{64}$")
            self.assertEqual(len(certificates["contexts"]), 2)
            for certificate in certificates["contexts"]:
                self.assertRegex(certificate, r"^NONFACTORING@[0-9a-f]{64}$")

    def test_build_capsule_cli_writes_manifest_and_reports_certificates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = make_capsule_fixture(root)
            archive = root / "out" / "capsule.tar.xz"
            manifest = root / "out" / "manifest.json"

            completed = subprocess.run(
                [
                    os.environ.get("PYTHON", "python3"),
                    "artifact/build_replay_capsule.py",
                    "--v2-bundle",
                    str(inputs.v2_bundle),
                    "--context-bundle",
                    str(inputs.context_bundles[0]),
                    "--context-bundle",
                    str(inputs.context_bundles[1]),
                    "--archive",
                    str(archive),
                    "--manifest",
                    str(manifest),
                ],
                cwd=Path(__file__).resolve().parents[1],
                env={
                    **os.environ,
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONPATH": "src:.",
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(archive.is_file())
            self.assertTrue(manifest.is_file())
            manifest_document = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertIn(f"archive_sha256={manifest_document['archive']['sha256']}", completed.stdout)
            self.assertIn("v2_certificate=", completed.stdout)
            self.assertIn("context_0_certificate=", completed.stdout)
            self.assertIn("context_1_certificate=", completed.stdout)

    def test_reproduce_cli_help_is_available(self) -> None:
        completed = subprocess.run(
            [
                os.environ.get("PYTHON", "python3"),
                "artifact/reproduce.py",
                "--help",
            ],
            cwd=Path(__file__).resolve().parents[1],
            env={**os.environ, "PYTHONPATH": "src:."},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_public_reproduction_docs_pin_commands_boundary_and_capsule_hash(self) -> None:
        stock_root = Path(__file__).resolve().parents[1]
        repo_root = stock_root.parent
        manifest = json.loads(
            (stock_root / "artifact" / "replay-manifest.json").read_text(
                encoding="utf-8"
            )
        )
        capsule_hash = manifest["archive"]["sha256"]

        for document_path in (
            repo_root / "ARTIFACT.md",
            repo_root / "README.md",
            stock_root / "REPRODUCE.md",
        ):
            document = document_path.read_text(encoding="utf-8")
            self.assertIn("make reproduce-paper", document, str(document_path))
            self.assertIn("make contextual-matrix-live", document, str(document_path))
            self.assertIn("BOUNDED_CONTEXT_SUITE_ONLY", document, str(document_path))
            self.assertIn(capsule_hash, document, str(document_path))

    def test_path_traversal_member_is_rejected_before_extraction(self) -> None:
        self._assert_hostile_member_rejected("../escape", "ARCHIVE_MEMBER_PATH_UNSAFE")

    def test_absolute_member_is_rejected_before_extraction(self) -> None:
        self._assert_hostile_member_rejected("/absolute", "ARCHIVE_MEMBER_PATH_UNSAFE")

    def test_symlink_member_is_rejected_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid_archive = root / "valid.tar.xz"
            manifest = build_replay_capsule(
                make_capsule_fixture(root), valid_archive, root / "manifest.json"
            )
            info = tarfile.TarInfo("v2/query/query.json")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../escape"
            hostile = _archive_bytes([(info, b"")])
            archive = root / "hostile.tar.xz"
            archive.write_bytes(hostile)

            with self.assertRaisesRegex(ReproductionError, "ARCHIVE_MEMBER_TYPE_UNSAFE"):
                verify_and_extract_capsule(
                    archive,
                    _manifest_for_archive(manifest, hostile),
                    root / "extract",
                )

    def test_unmanifested_member_is_rejected(self) -> None:
        self._assert_hostile_member_rejected(
            "extra.txt", "UNMANIFESTED_ARCHIVE_MEMBER"
        )

    def test_member_digest_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid_archive = root / "valid.tar.xz"
            manifest = build_replay_capsule(
                make_capsule_fixture(root), valid_archive, root / "manifest.json"
            )
            entry = manifest["entries"][0]
            path = entry["path"]
            hostile_value = b"x" * int(entry["size"])
            self.assertNotEqual(_sha256_bytes(hostile_value), entry["sha256"])
            hostile = _archive_bytes([(_regular_info(path, hostile_value), hostile_value)])
            archive = root / "hostile.tar.xz"
            archive.write_bytes(hostile)

            with self.assertRaisesRegex(ReproductionError, "ARCHIVE_MEMBER_DIGEST_MISMATCH"):
                verify_and_extract_capsule(
                    archive,
                    _manifest_for_archive(manifest, hostile),
                    root / "extract",
                )

    def _assert_hostile_member_rejected(self, name: str, reason: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid_archive = root / "valid.tar.xz"
            manifest = build_replay_capsule(
                make_capsule_fixture(root), valid_archive, root / "manifest.json"
            )
            value = b"hostile\n"
            hostile = _archive_bytes([(_regular_info(name, value), value)])
            archive = root / "hostile.tar.xz"
            archive.write_bytes(hostile)

            with self.assertRaisesRegex(ReproductionError, reason):
                verify_and_extract_capsule(
                    archive,
                    _manifest_for_archive(manifest, hostile),
                    root / "extract",
                )


if __name__ == "__main__":
    unittest.main()
