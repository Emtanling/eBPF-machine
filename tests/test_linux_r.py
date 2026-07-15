#!/usr/bin/env python3
"""Contract tests for the executable report-relative residual witness.

These tests intentionally separate three questions:

* did ``V_linux_r`` actually compute the frontier report before concrete
  witness enumeration;
* does that report uniquely cover the declared concrete fiber and fail the
  behavioral factorization test; and
* is the persisted evidence reproducible and independently auditable?

The claim under test is deliberately scoped to ``R(V_linux_r, I_hash)``.  A
passing test must never be interpreted as an export of stock Linux-verifier
cells.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from linux_r.audit import audit_bundle
from linux_r.model import (
    ModelError,
    _parse_kernel_oracle,
    build_analysis,
    build_bundle,
    canonical_json_bytes,
    load_program,
)


PROGRAM = ROOT / "linux_r" / "program.json"
BASELINE_STATES = {"frontier:S", "frontier:AS"}
SUFFIX_WORD = ["update-suffix-and-observe"]
CONTROL_PROFILES = (
    "occupancy_tracking",
    "cap64",
    "forced_sentinel",
    "unobserved",
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_canonical(path: Path, value: object) -> None:
    path.write_bytes(canonical_json_bytes(value))


def refresh_report_hash(report: dict) -> None:
    core = {key: value for key, value in report.items() if key != "report_hash"}
    report["report_hash"] = sha256_bytes(canonical_json_bytes(core))


def refresh_derivation_hash(derivation: dict) -> None:
    core = {key: value for key, value in derivation.items()
            if key != "derivation_hash"}
    derivation["derivation_hash"] = sha256_bytes(canonical_json_bytes(core))


def persist_resigned_report(bundle: Path, report: dict) -> None:
    """Persist a self-consistent but potentially dishonest report mutation."""

    refresh_report_hash(report)
    report_path = bundle / "report.json"
    write_canonical(report_path, report)

    analysis_path = bundle / "analysis.json"
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    analysis["report_ref"] = {
        "path": "report.json",
        "report_hash": report["report_hash"],
        "sha256": sha256_bytes(report_path.read_bytes()),
    }
    write_canonical(analysis_path, analysis)
    refresh_manifest(bundle)


def persist_resigned_derivation(bundle: Path, derivation: dict) -> None:
    """Persist a self-consistent forged derivation and all dependent refs."""

    refresh_derivation_hash(derivation)
    derivation_path = bundle / "derivation.json"
    write_canonical(derivation_path, derivation)

    report_path = bundle / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["derivation_ref"]["derivation_hash"] = derivation["derivation_hash"]
    refresh_report_hash(report)
    write_canonical(report_path, report)

    analysis_path = bundle / "analysis.json"
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    analysis["derivation_ref"] = {
        "derivation_hash": derivation["derivation_hash"],
        "path": "derivation.json",
        "sha256": sha256_bytes(derivation_path.read_bytes()),
    }
    analysis["report_ref"] = {
        "path": "report.json",
        "report_hash": report["report_hash"],
        "sha256": sha256_bytes(report_path.read_bytes()),
    }
    write_canonical(analysis_path, analysis)
    refresh_manifest(bundle)


def refresh_manifest(bundle: Path) -> None:
    """Refresh hashes after an intentional semantic mutation.

    This makes the overlap/missing-cell tests stronger than ordinary byte
    tampering: the manifest remains internally valid, so the semantic audit
    must reject the malformed report partition itself.
    """

    path = bundle / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    for name, record in manifest["files"].items():
        candidate = bundle / name
        record["sha256"] = sha256_bytes(candidate.read_bytes())
        record["size"] = candidate.stat().st_size
    core = {key: value for key, value in manifest.items()
            if key != "manifest_hash"}
    manifest["manifest_hash"] = sha256_bytes(canonical_json_bytes(core))
    write_canonical(path, manifest)


def write_kernel_oracle(path: Path, *, trace_valid: bool = True) -> None:
    """Write the minimal fixed-boundary calibration accepted by the model."""

    common = {
        "circuit": "nand",
        "kind": "fixed_boundary",
        "passed": True,
        "program_id": 17,
        "program_tag": "0123456789abcdef",
        "variant_id": 1,
    }
    rows = []
    for ordinal, assignment, actual, raw_return in (
        (0, 2, 1, 0),
        (1, 3, 0, -7),
    ):
        rows.append({
            **common,
            "assignment": assignment,
            "actual": actual,
            "executed": 1,
            "failing_gate": 0xFFFFFFFF,
            "gate_cap": 2,
            "gate_count": 1,
            "gate_error_count": 0,
            "input_count": 2,
            "logical_expected": actual,
            "ordinal": ordinal,
            "record": "run",
            "run_seq": ordinal + 1,
            "status": 0,
            "trace_passed": True,
            "variant_expected": actual,
        })
        rows.append({
            **common,
            "actual": actual,
            "dst": 4,
            "expected": actual,
            "gate": 0,
            "ordinal": ordinal,
            "record": "gate",
            "run_seq": ordinal + 1,
            "second_update_raw_ret": raw_return,
            "src0": 2,
            "src1": 3,
            "trace_valid": trace_valid,
        })
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


class LinuxRModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.program = load_program(PROGRAM)

    def test_baseline_establishes_output_witnessed_nonfactorization(self) -> None:
        analysis = build_analysis(self.program, profile_name="baseline")

        self.assertEqual(analysis["schema"], "linux-r-analysis-v1")
        self.assertEqual(analysis["profile"]["name"], "baseline")
        self.assertTrue(analysis["result"]["adm_pass"])
        self.assertTrue(analysis["result"]["r_established"])
        self.assertFalse(analysis["factorization"]["holds"])
        self.assertEqual(analysis["result"]["scope"], "R(V_linux_r,I_hash)")
        self.assertFalse(
            analysis["result"]["stock_linux_verifier_r_established"],
            "the executable recognizer must not overclaim stock-verifier R",
        )

        witness = analysis["witness"]
        self.assertTrue(witness["definition1_causal"])
        self.assertTrue(witness["same_computed_cell"])
        self.assertTrue(witness["beta_different"])
        self.assertEqual(set(witness["observations"]), {0, 1})
        self.assertEqual(witness["suffix_word"], SUFFIX_WORD)
        self.assertEqual(
            {witness["left_state"], witness["right_state"]},
            BASELINE_STATES,
        )

        collisions = analysis["factorization"]["collisions"]
        self.assertEqual(len(collisions), 1)
        self.assertEqual(collisions[0]["cardinality"], 2)
        self.assertEqual(len(collisions[0]["beta_classes"]), 2)

    def test_report_is_computed_without_posthoc_witness_output(self) -> None:
        analysis = build_analysis(self.program)
        report = analysis["report"]
        derivation = analysis["derivation_provenance"]

        self.assertEqual(
            report["analysis_order"],
            "computed-before-concrete-witness-enumeration",
        )
        self.assertFalse(report["posthoc_output_data_used"])
        self.assertNotIn("computed_trace", report)
        self.assertFalse(
            report["report_interface"]["computed_trace_is_label_set"]
        )
        self.assertGreaterEqual(len(derivation["computed_trace"]), 3)
        self.assertEqual(len(report["report_cells"]), 1)
        self.assertEqual(
            report["report_cells"][0]["operator"],
            "join(forget-exact-occupancy)",
        )
        self.assertEqual(
            report["report_cells"][0]["abstract_state"]["occupancy"]
            ["exact_key_set"],
            "not-tracked",
        )

    def test_domain_returns_and_report_cell_successors_are_sound(self) -> None:
        analysis = build_analysis(self.program)
        validation = analysis["report"]["transfer_validation"]

        # Seven admissible subsets K of {S,A,B} with |K| <= 2, times three
        # update keys, check return containment.  The two concretizations of
        # the actual joined cell additionally check post-state containment.
        self.assertEqual(
            validation["method"],
            "symbolic-transform-plus-exhaustive-concretization",
        )
        self.assertEqual(validation["checked_cases"], 21)
        self.assertEqual(validation["cell_checked_cases"], 2)
        self.assertEqual(validation["violations"], [])
        self.assertTrue(analysis["checks"]["abstract_transfer_sound"])

    def test_epsilon_and_action_exhaust_all_common_word_obligations(self) -> None:
        analysis = build_analysis(self.program)

        self.assertEqual(analysis["common_words"], [[], SUFFIX_WORD])
        self.assertEqual(len(analysis["word_obligations"]), 2)
        obligations = {
            tuple(item["word"]): item for item in analysis["word_obligations"]
        }
        self.assertEqual(set(obligations), {(), tuple(SUFFIX_WORD)})

        epsilon = obligations[()]
        self.assertEqual(epsilon["encoded_word"], [])
        self.assertTrue(epsilon["runtime_included"])
        self.assertTrue(epsilon["observer_compatible"])
        self.assertTrue(epsilon["sound_observation_contract"])
        self.assertTrue(epsilon["common_context"])
        self.assertEqual(len(epsilon["outcomes"]), 2)
        for outcome in epsilon["outcomes"]:
            self.assertTrue(outcome["concrete_defined"])
            self.assertTrue(outcome["discipline_defined"])
            self.assertEqual(outcome["concrete_outputs"], [])
            self.assertEqual(outcome["discipline_outputs"], [])

        action = obligations[tuple(SUFFIX_WORD)]
        self.assertEqual(len(action["encoded_word"]), 1)
        self.assertTrue(action["runtime_included"])
        self.assertTrue(action["observer_compatible"])
        self.assertTrue(action["sound_observation_contract"])
        self.assertTrue(action["common_context"])
        self.assertEqual(
            [outcome["concrete_outputs"] for outcome in action["outcomes"]],
            [[1], [0]],
        )
        self.assertEqual(
            [outcome["discipline_outputs"] for outcome in action["outcomes"]],
            [[1], [0]],
        )
        self.assertTrue(analysis["checks"]["runtime_word_inclusion"])
        self.assertTrue(analysis["checks"]["observation_compatibility"])
        self.assertTrue(analysis["checks"]["observation_contract_sound"])
        self.assertTrue(analysis["checks"]["common_context"])

    def test_computed_cells_form_a_unique_cover_of_the_context_fiber(self) -> None:
        analysis = build_analysis(self.program)
        concrete_ids = {state["state_id"]
                        for state in analysis["concrete_states"]}
        self.assertEqual(concrete_ids, BASELINE_STATES)

        assignments = Counter()
        for item in analysis["coverage"]:
            self.assertIn(item["state_id"], concrete_ids)
            self.assertEqual(len(item["cell_ids"]), 1)
            assignments[item["state_id"]] += len(item["cell_ids"])
        self.assertEqual(assignments, Counter({state: 1 for state in concrete_ids}))
        self.assertTrue(analysis["checks"]["unique_cell_condition"])

        witness_cells = {
            item["cell_ids"][0]
            for item in analysis["coverage"]
            if item["state_id"] in BASELINE_STATES
        }
        self.assertEqual(len(witness_cells), 1)

    def test_report_and_hashes_are_deterministic(self) -> None:
        first = build_analysis(self.program)
        second = build_analysis(load_program(PROGRAM))
        self.assertEqual(canonical_json_bytes(first), canonical_json_bytes(second))

        report = first["report"]
        report_core = {key: value for key, value in report.items()
                       if key != "report_hash"}
        self.assertEqual(
            report["report_hash"],
            sha256_bytes(canonical_json_bytes(report_core)),
        )
        # Canonicalization must be independent of insertion order.
        self.assertEqual(
            canonical_json_bytes({"b": 2, "a": 1}),
            canonical_json_bytes({"a": 1, "b": 2}),
        )

    def test_partition_refinement_finds_the_shortest_distinguishing_word(self) -> None:
        baseline = build_analysis(self.program)
        self.assertEqual(
            baseline["quotient"]["algorithm"],
            "deterministic-mealy-partition-refinement",
        )
        self.assertEqual(
            baseline["quotient"]["shortest_distinguishing_word"],
            SUFFIX_WORD,
        )
        left = baseline["witness"]["left_state"]
        right = baseline["witness"]["right_state"]
        partition = baseline["quotient"]["state_to_block"]
        self.assertNotEqual(partition[left], partition[right])

        refined = build_analysis(self.program, "occupancy_tracking")
        self.assertTrue(refined["factorization"]["holds"])
        self.assertEqual(len(refined["report"]["report_cells"]), 2)
        self.assertFalse(refined["witness"]["same_computed_cell"])

    def test_all_mechanism_and_observer_controls_are_negative_for_r(self) -> None:
        analyses = {
            name: build_analysis(self.program, name)
            for name in CONTROL_PROFILES
        }
        for name, analysis in analyses.items():
            with self.subTest(profile=name):
                self.assertTrue(analysis["result"]["adm_pass"])
                self.assertFalse(analysis["result"]["r_established"])
                self.assertTrue(analysis["factorization"]["holds"])
                self.assertEqual(analysis["factorization"]["collisions"], [])

        # Occupancy tracking refines the report; the other controls erase the
        # behavioral distinction while leaving the joined report in place.
        self.assertFalse(
            analyses["occupancy_tracking"]["witness"]["same_computed_cell"]
        )
        self.assertEqual(analyses["cap64"]["witness"]["observations"], [1, 1])
        self.assertEqual(
            analyses["forced_sentinel"]["witness"]["observations"], [1, 1]
        )
        self.assertEqual(
            analyses["unobserved"]["witness"]["observations"], ["unit", "unit"]
        )


class LinuxRBundleAuditTests(unittest.TestCase):
    def build(self, destination: Path) -> dict:
        return build_bundle(
            PROGRAM,
            destination,
            created_at="2026-07-15T00:00:00Z",
        )

    def test_bundle_is_complete_deterministic_and_auditable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            self.build(first)
            self.build(second)

            required = {
                "program.json", "derivation.json", "report.json",
                "analysis.json", "manifest.json"
            }
            self.assertTrue(required.issubset({path.name for path in first.iterdir()}))
            for name in required:
                self.assertEqual((first / name).read_bytes(),
                                 (second / name).read_bytes())

            result = audit_bundle(first, require_kernel=False)
            self.assertEqual(result["verdict"], "PASS")
            self.assertTrue(result["checks"])
            self.assertTrue(all(result["checks"].values()))
            self.assertTrue((first / "audit.txt").is_file())

            analysis = json.loads((first / "analysis.json").read_text())
            report = json.loads((first / "report.json").read_text())
            self.assertNotIn("report", analysis)
            self.assertEqual(analysis["report_ref"]["path"], "report.json")
            self.assertEqual(
                analysis["report_ref"]["report_hash"], report["report_hash"]
            )
            self.assertEqual(
                analysis["report_ref"]["sha256"],
                sha256_bytes((first / "report.json").read_bytes()),
            )
            self.assertEqual(set(analysis["controls"]), set(CONTROL_PROFILES))
            self.assertTrue(all(
                control["r_established"] is False
                for control in analysis["controls"].values()
            ))

    def test_missing_kernel_calibration_is_rejected_only_when_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            self.build(bundle)
            self.assertEqual(
                audit_bundle(bundle, require_kernel=False)["verdict"], "PASS"
            )
            required = audit_bundle(bundle, require_kernel=True)
            self.assertEqual(required["verdict"], "FAIL")
            self.assertFalse(required["checks"]["kernel_calibration"])

    def test_byte_tampering_is_rejected_by_manifest_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            self.build(bundle)
            analysis_path = bundle / "analysis.json"
            analysis_path.write_bytes(analysis_path.read_bytes() + b" ")

            result = audit_bundle(bundle)
            self.assertEqual(result["verdict"], "FAIL")
            self.assertFalse(result["checks"]["manifest_files"])

    def test_unmanifested_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            self.build(bundle)
            (bundle / "unmanifested").mkdir()

            result = audit_bundle(bundle)
            self.assertEqual(result["verdict"], "FAIL")
            self.assertFalse(result["checks"]["root_entries_regular"])

    def test_overlapping_computed_cells_are_semantically_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            self.build(bundle)
            report_path = bundle / "report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))

            duplicate = copy.deepcopy(report["report_cells"][0])
            duplicate["cell_id"] += "-overlap"
            report["report_cells"].append(duplicate)
            persist_resigned_report(bundle, report)

            result = audit_bundle(bundle)
            self.assertEqual(result["verdict"], "FAIL")
            self.assertFalse(result["checks"]["unique_cell_condition"])

    def test_missing_computed_cell_coverage_is_semantically_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            self.build(bundle)
            report_path = bundle / "report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))

            report["report_cells"] = []
            persist_resigned_report(bundle, report)

            result = audit_bundle(bundle)
            self.assertEqual(result["verdict"], "FAIL")
            self.assertFalse(result["checks"]["unique_cell_condition"])

    def test_resigned_computed_trace_or_metadata_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trace_bundle = root / "computed-trace"
            self.build(trace_bundle)
            derivation = json.loads(
                (trace_bundle / "derivation.json").read_text(encoding="utf-8")
            )
            derivation["computed_trace"][0]["operator"] = "forged-update"
            persist_resigned_derivation(trace_bundle, derivation)
            trace_result = audit_bundle(trace_bundle)
            self.assertEqual(trace_result["verdict"], "FAIL")
            self.assertTrue(trace_result["checks"]["manifest_files"])
            self.assertTrue(trace_result["checks"]["derivation_hash"])
            self.assertFalse(trace_result["checks"]["derivation_exact"])

            domain_bundle = root / "domain-metadata"
            self.build(domain_bundle)
            report = json.loads(
                (domain_bundle / "report.json").read_text(encoding="utf-8")
            )
            report["domain"]["version"] = "forged-domain"
            persist_resigned_report(domain_bundle, report)
            domain_result = audit_bundle(domain_bundle)
            self.assertEqual(domain_result["verdict"], "FAIL")
            self.assertTrue(domain_result["checks"]["manifest_files"])
            self.assertTrue(domain_result["checks"]["report_hash"])
            self.assertFalse(domain_result["checks"]["report_exact"])

    def test_empty_discipline_is_rejected_after_manifest_is_refreshed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            self.build(bundle)
            analysis_path = bundle / "analysis.json"
            analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
            analysis["discipline"] = {}
            write_canonical(analysis_path, analysis)
            refresh_manifest(bundle)

            result = audit_bundle(bundle)
            self.assertEqual(result["verdict"], "FAIL")
            self.assertTrue(result["checks"]["manifest_files"])
            self.assertFalse(result["checks"]["discipline_exact"])

    def test_omitting_epsilon_or_action_obligation_is_rejected(self) -> None:
        omitted_words = ([], SUFFIX_WORD)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, omitted in enumerate(omitted_words):
                with self.subTest(omitted=omitted):
                    bundle = root / f"omitted-{index}"
                    self.build(bundle)
                    analysis_path = bundle / "analysis.json"
                    analysis = json.loads(
                        analysis_path.read_text(encoding="utf-8")
                    )
                    analysis["common_words"] = [
                        word for word in analysis["common_words"]
                        if word != omitted
                    ]
                    analysis["word_obligations"] = [
                        item for item in analysis["word_obligations"]
                        if item["word"] != omitted
                    ]
                    write_canonical(analysis_path, analysis)
                    refresh_manifest(bundle)

                    result = audit_bundle(bundle)
                    self.assertEqual(result["verdict"], "FAIL")
                    self.assertTrue(result["checks"]["manifest_files"])
                    self.assertFalse(
                        result["checks"]["common_word_obligations"]
                    )

    def test_false_kernel_trace_and_fake_executables_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            oracle = root / "kernel_oracle.jsonl"
            write_kernel_oracle(oracle)
            self.assertEqual(_parse_kernel_oracle(oracle)["row_count"], 4)

            write_kernel_oracle(oracle, trace_valid=False)
            with self.assertRaises(ModelError):
                _parse_kernel_oracle(oracle)
            write_kernel_oracle(oracle)

            bpf_object = root / "wm.bpf.o"
            bpf_object.write_bytes(b"\x7fELFunit-test-bpf-object\n")
            descriptor = root / "nand.wmc"
            descriptor.write_bytes(b"WMC1 nand 2 1 5 1\n1 2 3 4\n4\n")
            harness_binary = root / "wm_vm_user"
            harness_binary.write_bytes(b"unit-test-harness\n")
            kernel_stderr = root / "kernel_oracle.stderr"
            kernel_stderr.write_bytes(b"")
            build_log = root / "build.log"
            build_log.write_text(
                "clang -target bpf -DGATE_CAP=2 src/wm.bpf.c\n"
                "cc src/wm_vm_user.c -o wm_vm_user\n",
                encoding="utf-8",
            )
            vmlinux_header = root / "vmlinux.h"
            vmlinux_header.write_text(
                "typedef unsigned int __u32; struct task_struct {};\n",
                encoding="utf-8",
            )
            toolchain_log = root / "toolchain.txt"
            toolchain_log.write_text(
                "UNAME\nCLANG\nCC\nBPFTOOL\nLIBBPF\n", encoding="utf-8"
            )
            bundle = root / "bundle"
            with self.assertRaises(ModelError):
                build_bundle(
                    PROGRAM,
                    bundle,
                    kernel_oracle=oracle,
                    kernel_stderr=kernel_stderr,
                    build_log=build_log,
                    bpf_object=bpf_object,
                    source=ROOT / "src" / "wm.bpf.c",
                    descriptor=descriptor,
                    harness_binary=harness_binary,
                    harness_source=ROOT / "src" / "wm_vm_user.c",
                    common_header=ROOT / "src" / "wm_common.h",
                    makefile=ROOT / "Makefile",
                    vmlinux_header=vmlinux_header,
                    runner=ROOT / "linux_r" / "run_kernel.sh",
                    circuit_spec=ROOT / "circuits" / "nand.json",
                    circuit_compiler=ROOT / "scripts" / "circuit_tool.py",
                    model_source=ROOT / "linux_r" / "model.py",
                    auditor_source=ROOT / "linux_r" / "audit.py",
                    toolchain_log=toolchain_log,
                    created_at="2026-07-15T00:00:00Z",
                )

    def test_failed_audit_never_prints_an_established_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            self.build(bundle)
            analysis_path = bundle / "analysis.json"
            analysis_path.write_bytes(analysis_path.read_bytes() + b" ")

            result = audit_bundle(bundle, write=True)
            self.assertEqual(result["verdict"], "FAIL")
            text = (bundle / "audit.txt").read_text(encoding="utf-8")
            self.assertNotIn("CLAIM: R(V_linux_r,I_hash)=ESTABLISHED", text)
            self.assertIn("VERDICT: FAIL", text)

    def test_malformed_json_returns_fail_instead_of_raising(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            self.build(bundle)
            (bundle / "analysis.json").write_bytes(b"{not-json\n")

            result = audit_bundle(bundle, write=True)
            self.assertEqual(result["verdict"], "FAIL")
            self.assertFalse(result["checks"]["bundle_readable"])
            text = (bundle / "audit.txt").read_text(encoding="utf-8")
            self.assertIn("R(V_linux_r,I_hash)=NOT_ESTABLISHED", text)

    def test_resigned_negative_control_claim_is_independently_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            self.build(bundle)
            analysis_path = bundle / "analysis.json"
            analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
            analysis["controls"]["cap64"]["r_established"] = True
            write_canonical(analysis_path, analysis)
            refresh_manifest(bundle)

            result = audit_bundle(bundle)
            self.assertEqual(result["verdict"], "FAIL")
            self.assertTrue(result["checks"]["manifest_files"])
            self.assertFalse(result["checks"]["negative_controls"])


if __name__ == "__main__":
    unittest.main()
