from __future__ import annotations

import copy
from pathlib import Path
import unittest

from residuality_auditor.context_suite import (
    ContextSuiteError,
    compare_case_result,
    load_context_suite,
    parse_context_suite,
    render_context_target,
)


ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "linux" / "context-suite-v1.json"
BASE_SOURCE = ROOT / "linux" / "witness" / "rac_v2_witness.bpf.c"


class ContextSuiteTests(unittest.TestCase):
    def test_negative_reason_must_match_exactly(self) -> None:
        case = load_context_suite(SUITE).case("reject.missing-bridge")
        observed = {
            "stage": "CRL_CHECK",
            "status": "BLOCKED",
            "assessment": "INCONCLUSIVE",
            "quantifier": None,
            "evidence_grade": None,
            "reasons": ["TARGET_CONFORMANCE_BRIDGE"],
        }

        self.assertTrue(compare_case_result(case, observed)["expected_match"])
        observed["reasons"] = ["COMMON_SUFFIX_NOT_PRESERVED"]
        comparison = compare_case_result(case, observed)
        self.assertFalse(comparison["expected_match"])
        self.assertEqual(comparison["reason_match"], False)

    def test_frozen_suite_has_six_positive_and_six_negative_cases(self) -> None:
        suite = load_context_suite(SUITE)

        self.assertEqual(suite.suite_id, "stock-r-v2-crl-bounded-v1")
        self.assertEqual(suite.claim_boundary, "BOUNDED_CONTEXT_SUITE_ONLY")
        self.assertEqual(len(suite.cases), 12)
        self.assertEqual(
            sum(case.classification == "TRANSPARENT" for case in suite.cases),
            6,
        )
        self.assertEqual(
            sum(case.classification == "NONTRANSPARENT" for case in suite.cases),
            6,
        )
        self.assertEqual(len({case.case_id for case in suite.cases}), 12)

    def test_suite_rejects_forall_boundary_and_duplicate_case(self) -> None:
        suite = load_context_suite(SUITE)
        document = suite.to_document()

        promoted = copy.deepcopy(document)
        promoted["claim_boundary"] = "FORALL_CONTEXTS"
        with self.assertRaisesRegex(ContextSuiteError, "claim_boundary"):
            parse_context_suite(promoted)

        duplicate = copy.deepcopy(document)
        duplicate["cases"].append(copy.deepcopy(duplicate["cases"][0]))
        with self.assertRaisesRegex(ContextSuiteError, "duplicate case_id"):
            parse_context_suite(duplicate)

    def test_two_map_generation_is_deterministic_and_distinct(self) -> None:
        suite = load_context_suite(SUITE)
        case = suite.case("transparent.two-map.depth2")
        source = BASE_SOURCE.read_text(encoding="utf-8")

        first = render_context_target(source, suite, case)
        second = render_context_target(source, suite, case)

        self.assertEqual(first.source_text, second.source_text)
        self.assertEqual(first.metadata, second.metadata)
        self.assertIn("ctx_pair_a SEC", first.source_text)
        self.assertIn("ctx_pair_b SEC", first.source_text)
        self.assertIn("ctx_pair_a_frame((__u32)observed);", first.source_text)
        self.assertIn("ctx_pair_b_frame((__u32)observed);", first.source_text)
        self.assertEqual(first.metadata["claim_boundary"], "EXACT_TARGET_ONLY")
        self.assertEqual(
            first.metadata["effect"]["writes"],
            ["map:ctx_pair_a.0", "map:ctx_pair_b.0"],
        )

    def test_footprint_negative_uses_existing_g0_without_redeclaring_it(self) -> None:
        suite = load_context_suite(SUITE)
        case = suite.case("reject.footprint-overlap")
        source = BASE_SOURCE.read_text(encoding="utf-8")

        rendered = render_context_target(source, suite, case)

        self.assertEqual(rendered.source_text.count("} g0 SEC"), 1)
        self.assertIn("bpf_map_update_elem(&g0", rendered.source_text)
        self.assertIn("map:witness.0", rendered.metadata["effect"]["writes"])
        self.assertNotIn(
            "footprint_effect_disjoint", rendered.metadata["obligation_overrides"]
        )


if __name__ == "__main__":
    unittest.main()
