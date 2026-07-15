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
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from linux_r.audit import audit_bundle
from linux_r.model import (
    build_analysis,
    build_bundle,
    canonical_json_bytes,
    load_program,
)


ROOT = Path(__file__).resolve().parents[1]
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


def refresh_report_hash(analysis: dict) -> None:
    report = analysis["report"]
    core = {key: value for key, value in report.items() if key != "report_hash"}
    report["report_hash"] = sha256_bytes(canonical_json_bytes(core))


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

        self.assertEqual(
            report["analysis_order"],
            "computed-before-concrete-witness-enumeration",
        )
        self.assertFalse(report["posthoc_output_data_used"])
        self.assertGreaterEqual(len(report["computed_trace"]), 3)
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

    def test_abstract_transfer_is_sound_for_entire_finite_domain(self) -> None:
        analysis = build_analysis(self.program)
        validation = analysis["report"]["transfer_validation"]

        # Seven admissible subsets K of {S,A,B} with |K| <= 2, times the
        # three update keys, are all checked rather than sampled.
        self.assertEqual(validation["method"], "exhaustive")
        self.assertEqual(validation["checked_cases"], 21)
        self.assertEqual(validation["violations"], [])
        self.assertTrue(analysis["checks"]["abstract_transfer_sound"])

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

            required = {"program.json", "analysis.json", "manifest.json"}
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

    def test_overlapping_computed_cells_are_semantically_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            self.build(bundle)
            analysis_path = bundle / "analysis.json"
            analysis = json.loads(analysis_path.read_text(encoding="utf-8"))

            duplicate = copy.deepcopy(analysis["report"]["report_cells"][0])
            duplicate["cell_id"] += "-overlap"
            analysis["report"]["report_cells"].append(duplicate)
            refresh_report_hash(analysis)
            write_canonical(analysis_path, analysis)
            refresh_manifest(bundle)

            result = audit_bundle(bundle)
            self.assertEqual(result["verdict"], "FAIL")
            self.assertFalse(result["checks"]["unique_cell_condition"])

    def test_missing_computed_cell_coverage_is_semantically_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            self.build(bundle)
            analysis_path = bundle / "analysis.json"
            analysis = json.loads(analysis_path.read_text(encoding="utf-8"))

            analysis["report"]["report_cells"] = []
            refresh_report_hash(analysis)
            write_canonical(analysis_path, analysis)
            refresh_manifest(bundle)

            result = audit_bundle(bundle)
            self.assertEqual(result["verdict"], "FAIL")
            self.assertFalse(result["checks"]["unique_cell_condition"])


if __name__ == "__main__":
    unittest.main()
