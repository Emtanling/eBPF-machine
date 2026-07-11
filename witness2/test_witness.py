#!/usr/bin/env python3
"""Regression tests for witness2/witness.py."""

import unittest
from pathlib import Path

import witness


class Witness2PrecisionAuditTests(unittest.TestCase):
    def setUp(self):
        self.cases = witness.cases()

    def test_explicit_and_modulo_programs_compute_same_nand(self):
        expected = {(0, 0): 1, (0, 1): 1, (1, 0): 1, (1, 1): 0}
        self.assertEqual(witness.oracle(self.cases["explicit_nand"]), expected)
        self.assertEqual(witness.oracle(self.cases["modulo_nand"]), expected)

    def test_projection_is_nonconstant_control(self):
        self.assertEqual(
            witness.oracle(self.cases["projection"]),
            {(0, 0): 0, (0, 1): 0, (1, 0): 1, (1, 1): 1},
        )

    def test_frama_model_uses_two_explicit_independent_inputs(self):
        source = (Path(__file__).parent / "frama_c" / "nand_mod.c").read_text()
        self.assertEqual(source.count("Frama_C_interval(0, 1)"), 2)
        self.assertNotIn("volatile int input", source)

    def test_global_intervals_are_exact_but_do_not_certify_graphs(self):
        for name, expr in self.cases.items():
            with self.subTest(name=name):
                expected_range = witness.interval_alpha(witness.oracle(expr).values())
                self.assertEqual(witness.global_interval(expr), expected_range)
                certificate = witness.global_range_certificate(expr)
                self.assertTrue(witness.relation_is_sound(certificate, expr))
                self.assertFalse(witness.relation_is_exact(certificate, expr))

    def test_range_only_mod_transfer_discriminates_only_at_mod(self):
        projection = witness.relational_eval(self.cases["projection"], "range")
        explicit = witness.relational_eval(self.cases["explicit_nand"], "range")
        modulo = witness.relational_eval(self.cases["modulo_nand"], "range")

        self.assertTrue(witness.relation_is_exact(projection, self.cases["projection"]))
        self.assertTrue(witness.relation_is_exact(explicit, self.cases["explicit_nand"]))
        self.assertTrue(witness.relation_is_sound(modulo, self.cases["modulo_nand"]))
        self.assertFalse(witness.relation_is_exact(modulo, self.cases["modulo_nand"]))

    def test_congruence_refinement_certifies_all_graphs(self):
        for name, expr in self.cases.items():
            with self.subTest(name=name):
                certificate = witness.relational_eval(expr, "congruence")
                self.assertTrue(witness.relation_is_exact(certificate, expr))

    def test_singleton_input_partition_certifies_all_graphs(self):
        for name, expr in self.cases.items():
            with self.subTest(name=name):
                certificate = witness.partitioned_interval_certificate(expr)
                self.assertTrue(witness.relation_is_exact(certificate, expr))

    def test_completeness_equations_use_actual_reachable_state(self):
        checks = witness.completeness_checks()
        interval = checks["interval_on_actual_value_set"]
        relational = checks["row_relation_on_actual_reachable_state"]

        self.assertEqual(interval["actual_X"], [1, 2, 3])
        self.assertTrue(interval["equal"])
        self.assertFalse(relational["equal"])
        self.assertTrue(relational["lhs_strict_subset_of_rhs"])
        self.assertTrue(relational["refined_rhs_equal_to_lhs"])

    def test_relational_equation_is_constructed_explicitly(self):
        reachable = witness.reachable_acc_relation()
        lhs = witness.relation_alpha(witness.concrete_mod_relation(reachable, 3))
        rhs = witness.mod_range_only_transfer(witness.relation_alpha(reachable), 3)
        refined = witness.mod_congruence_transfer(
            witness.relation_alpha(reachable), 3
        )

        self.assertTrue(witness.relation_subset(lhs, rhs))
        self.assertNotEqual(lhs, rhs)
        self.assertEqual(lhs, refined)

    def test_report_scope_blocks_overclaim(self):
        report = witness.build_report()
        scope = " ".join(report["scope"])
        self.assertIn("not a model", scope)
        self.assertIn("Frama-C", scope)
        self.assertIn("old-input-model", scope)
        self.assertIn("no scalability", scope)
        self.assertTrue(report["same_concrete_nand_function"])


if __name__ == "__main__":
    unittest.main()
