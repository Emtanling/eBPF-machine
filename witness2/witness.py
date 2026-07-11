#!/usr/bin/env python3
"""Mechanized precision audit for the manuscript's numeric control.

This program deliberately separates three questions that the earlier artifact
conflated:

1. Is a *global output value range* exact?
2. Does an analysis certify the *input/output graph* of a function?
3. Does a concrete completeness equation hold on the actually reachable set?

The projection ``a``, explicit ``1 - a*b``, and modulo implementation
``((1+a+b) % 3) != 0`` all have the exact global interval [0, 1].  Consequently,
that interval alone cannot distinguish an ordinary expression from the modulo
implementation and is not evidence of relational opacity.

For a transparent, executable comparison, this file also contains a small
row-indexed relational interpreter.  Its ordinary arithmetic transfers preserve
input rows, while its intentionally range-only MOD transfer forgets the row to
which a residue belongs.  The explicit NAND is certified by that interpreter;
the equivalent modulo NAND is not.  A congruence-aware MOD transfer or singleton
input partitioning restores the exact graph.  This is a result about this toy
transfer only.  It is not a model of, or evidence about, the Linux eBPF verifier.

Run:
    python3 witness2/witness.py
    python3 witness2/witness.py --json
"""

from __future__ import annotations

import argparse
import itertools
import json
from typing import Dict, FrozenSet, Iterable, Mapping, Sequence, Tuple


Expr = tuple
Interval = Tuple[int, int]
Row = Tuple[int, int]
Relation = Dict[Row, FrozenSet[int]]

INPUTS: Tuple[str, str] = ("a", "b")
ROWS: Tuple[Row, ...] = tuple(itertools.product((0, 1), repeat=2))


# ---------------------------------------------------------------------------
# Tiny expression IR.
# ---------------------------------------------------------------------------
def C(k: int) -> Expr:
    return ("const", k)


def V(name: str) -> Expr:
    return ("var", name)


def ADD(x: Expr, y: Expr) -> Expr:
    return ("add", x, y)


def SUB(x: Expr, y: Expr) -> Expr:
    return ("sub", x, y)


def MUL(x: Expr, y: Expr) -> Expr:
    return ("mul", x, y)


def MOD(x: Expr, k: int) -> Expr:
    return ("mod", x, k)


def NE(x: Expr, y: Expr) -> Expr:
    return ("ne", x, y)


def projection(a: Expr, _b: Expr) -> Expr:
    """Nonconstant control that is not NAND."""

    return a


def explicit_nand(a: Expr, b: Expr) -> Expr:
    """NAND expressed without modulo, valid for Boolean inputs."""

    return SUB(C(1), MUL(a, b))


def modulo_nand(a: Expr, b: Expr) -> Expr:
    """The same concrete NAND function, routed through a modulo operation."""

    return NE(MOD(ADD(ADD(C(1), a), b), 3), C(0))


def cases() -> Mapping[str, Expr]:
    a, b = V("a"), V("b")
    return {
        "projection": projection(a, b),
        "explicit_nand": explicit_nand(a, b),
        "modulo_nand": modulo_nand(a, b),
    }


# ---------------------------------------------------------------------------
# Concrete semantics and exhaustive truth tables.
# ---------------------------------------------------------------------------
def concrete_eval(expr: Expr, env: Mapping[str, int]) -> int:
    tag = expr[0]
    if tag == "const":
        return expr[1]
    if tag == "var":
        return env[expr[1]]
    if tag == "add":
        return concrete_eval(expr[1], env) + concrete_eval(expr[2], env)
    if tag == "sub":
        return concrete_eval(expr[1], env) - concrete_eval(expr[2], env)
    if tag == "mul":
        return concrete_eval(expr[1], env) * concrete_eval(expr[2], env)
    if tag == "mod":
        return concrete_eval(expr[1], env) % expr[2]
    if tag == "ne":
        return int(concrete_eval(expr[1], env) != concrete_eval(expr[2], env))
    raise ValueError(f"unknown expression tag: {tag}")


def row_env(row: Row) -> Mapping[str, int]:
    return dict(zip(INPUTS, row))


def oracle(expr: Expr) -> Dict[Row, int]:
    return {row: concrete_eval(expr, row_env(row)) for row in ROWS}


# ---------------------------------------------------------------------------
# Nonrelational interval semantics.
# ---------------------------------------------------------------------------
def interval_alpha(values: Iterable[int]) -> Interval:
    values = tuple(values)
    if not values:
        raise ValueError("interval_alpha requires a nonempty set")
    return min(values), max(values)


def interval_values(interval: Interval) -> FrozenSet[int]:
    lo, hi = interval
    return frozenset(range(lo, hi + 1))


def interval_mod(interval: Interval, modulus: int) -> Interval:
    """Sound interval MOD transfer for nonnegative values and positive modulus."""

    lo, hi = interval
    if lo < 0 or modulus <= 0:
        raise ValueError("this witness uses nonnegative values and positive moduli")
    if hi - lo < modulus and lo // modulus == hi // modulus:
        return lo % modulus, hi % modulus
    return 0, modulus - 1


def intervals_disjoint(left: Interval, right: Interval) -> bool:
    return left[1] < right[0] or right[1] < left[0]


def interval_eval(expr: Expr, env: Mapping[str, Interval]) -> Interval:
    tag = expr[0]
    if tag == "const":
        return expr[1], expr[1]
    if tag == "var":
        return env[expr[1]]
    if tag == "add":
        left, right = interval_eval(expr[1], env), interval_eval(expr[2], env)
        return left[0] + right[0], left[1] + right[1]
    if tag == "sub":
        left, right = interval_eval(expr[1], env), interval_eval(expr[2], env)
        return left[0] - right[1], left[1] - right[0]
    if tag == "mul":
        left, right = interval_eval(expr[1], env), interval_eval(expr[2], env)
        products = (
            left[0] * right[0],
            left[0] * right[1],
            left[1] * right[0],
            left[1] * right[1],
        )
        return min(products), max(products)
    if tag == "mod":
        return interval_mod(interval_eval(expr[1], env), expr[2])
    if tag == "ne":
        left, right = interval_eval(expr[1], env), interval_eval(expr[2], env)
        if intervals_disjoint(left, right):
            return 1, 1
        if left[0] == left[1] == right[0] == right[1]:
            return 0, 0
        return 0, 1
    raise ValueError(f"unknown expression tag: {tag}")


def global_interval(expr: Expr) -> Interval:
    return interval_eval(expr, {name: (0, 1) for name in INPUTS})


def global_range_certificate(expr: Expr) -> Relation:
    """Lift one global value range to every input row.

    This is sound, but a nonconstant function's exact graph cannot be recovered
    from it because it carries no input/output association.
    """

    values = interval_values(global_interval(expr))
    return {row: values for row in ROWS}


def partitioned_interval_certificate(expr: Expr) -> Relation:
    """Run the interval analysis once per singleton input row."""

    result: Relation = {}
    for row in ROWS:
        env = {name: (value, value) for name, value in row_env(row).items()}
        result[row] = interval_values(interval_eval(expr, env))
    return result


# ---------------------------------------------------------------------------
# Row-indexed relational interpreter.
#
# Every value maps an input row to a set of possible runtime values.  Ordinary
# transfers preserve rows.  The "range" MOD policy intentionally joins rows at
# MOD; "congruence" retains exact residues per row.  Both are sound.
# ---------------------------------------------------------------------------
def _rel_const(value: int) -> Relation:
    return {row: frozenset((value,)) for row in ROWS}


def _rel_binary(left: Relation, right: Relation, operation) -> Relation:
    return {
        row: frozenset(operation(x, y) for x in left[row] for y in right[row])
        for row in ROWS
    }


def mod_range_only_transfer(relation: Relation, modulus: int) -> Relation:
    """Sound but row-forgetting MOD transfer used by the toy base analyzer."""

    joined_values = set().union(*(relation[row] for row in ROWS))
    residue_interval = interval_mod(interval_alpha(joined_values), modulus)
    residues = interval_values(residue_interval)
    return {row: residues for row in ROWS}


def relation_alpha(relation: Relation) -> Relation:
    """Identity abstraction over finite row-indexed value sets.

    Naming the abstraction explicitly keeps the completeness equation in the
    report executable instead of relying on an unstated coercion.
    """

    return {row: frozenset(relation[row]) for row in ROWS}


def concrete_mod_relation(relation: Relation, modulus: int) -> Relation:
    """Exact concrete pointwise image of MOD on a finite row relation."""

    return {
        row: frozenset(value % modulus for value in relation[row])
        for row in ROWS
    }


def mod_congruence_transfer(relation: Relation, modulus: int) -> Relation:
    """Row-preserving refinement that tracks residues exactly for this finite input."""

    return concrete_mod_relation(relation, modulus)


def relational_eval(expr: Expr, mod_policy: str) -> Relation:
    tag = expr[0]
    if tag == "const":
        return _rel_const(expr[1])
    if tag == "var":
        index = INPUTS.index(expr[1])
        return {row: frozenset((row[index],)) for row in ROWS}
    if tag == "add":
        return _rel_binary(
            relational_eval(expr[1], mod_policy),
            relational_eval(expr[2], mod_policy),
            lambda x, y: x + y,
        )
    if tag == "sub":
        return _rel_binary(
            relational_eval(expr[1], mod_policy),
            relational_eval(expr[2], mod_policy),
            lambda x, y: x - y,
        )
    if tag == "mul":
        return _rel_binary(
            relational_eval(expr[1], mod_policy),
            relational_eval(expr[2], mod_policy),
            lambda x, y: x * y,
        )
    if tag == "mod":
        operand = relational_eval(expr[1], mod_policy)
        if mod_policy == "range":
            return mod_range_only_transfer(operand, expr[2])
        if mod_policy == "congruence":
            return mod_congruence_transfer(operand, expr[2])
        raise ValueError(f"unknown MOD policy: {mod_policy}")
    if tag == "ne":
        return _rel_binary(
            relational_eval(expr[1], mod_policy),
            relational_eval(expr[2], mod_policy),
            lambda x, y: int(x != y),
        )
    raise ValueError(f"unknown expression tag: {tag}")


def oracle_relation(expr: Expr) -> Relation:
    return {row: frozenset((value,)) for row, value in oracle(expr).items()}


def relation_is_sound(certificate: Relation, expr: Expr) -> bool:
    return all(oracle(expr)[row] in certificate[row] for row in ROWS)


def relation_is_exact(certificate: Relation, expr: Expr) -> bool:
    return certificate == oracle_relation(expr)


def relation_subset(left: Relation, right: Relation) -> bool:
    return all(left[row] <= right[row] for row in ROWS)


def reachable_acc_relation() -> Relation:
    return {
        row: frozenset((1 + row[0] + row[1],))
        for row in ROWS
    }


# ---------------------------------------------------------------------------
# Claim matrix and completeness checks.
# ---------------------------------------------------------------------------
def completeness_checks() -> dict:
    # The actual value set at the modulo program point is {1, 2, 3}.
    actual_values = set().union(*reachable_acc_relation().values())
    interval_lhs = interval_alpha(value % 3 for value in actual_values)
    interval_rhs = interval_mod(interval_alpha(actual_values), 3)

    # In the row-indexed domain alpha_rel is the identity: the domain can
    # represent the exact finite relation.  The range-only implementation of
    # MOD nevertheless forgets the input row and is strictly less precise.
    actual_relation = reachable_acc_relation()
    relation_lhs = relation_alpha(concrete_mod_relation(actual_relation, 3))
    relation_rhs = mod_range_only_transfer(relation_alpha(actual_relation), 3)
    relation_refined_rhs = mod_congruence_transfer(
        relation_alpha(actual_relation), 3
    )

    return {
        "interval_on_actual_value_set": {
            "actual_X": sorted(actual_values),
            "lhs_alpha_of_concrete_mod_X": list(interval_lhs),
            "rhs_interval_mod_of_alpha_X": list(interval_rhs),
            "equal": interval_lhs == interval_rhs,
            "interpretation": (
                "No interval-completeness violation occurs for MOD on the "
                "actually reachable value set."
            ),
        },
        "row_relation_on_actual_reachable_state": {
            "alpha_rel": "identity over finite row-indexed value sets",
            "lhs_alpha_rel_of_concrete_mod_R": relation_json(relation_lhs),
            "rhs_range_only_mod_of_alpha_rel_R": relation_json(relation_rhs),
            "lhs_strict_subset_of_rhs": (
                relation_subset(relation_lhs, relation_rhs)
                and relation_lhs != relation_rhs
            ),
            "equal": relation_lhs == relation_rhs,
            "refined_rhs_equal_to_lhs": relation_refined_rhs == relation_lhs,
            "interpretation": (
                "Strict inequality is caused by this toy analyzer's "
                "row-forgetting range-only MOD transfer, not by the ordinary "
                "interval value abstraction and not by Linux eBPF."
            ),
        },
    }


def relation_json(relation: Relation) -> list:
    return [
        {"input": list(row), "values": sorted(relation[row])}
        for row in ROWS
    ]


def build_report() -> dict:
    expressions = cases()
    tables = {name: oracle(expr) for name, expr in expressions.items()}
    same_nand = tables["explicit_nand"] == tables["modulo_nand"]

    matrix = {}
    for name, expr in expressions.items():
        exact_range = interval_alpha(oracle(expr).values())
        inferred_range = global_interval(expr)
        global_cert = global_range_certificate(expr)
        toy_range_cert = relational_eval(expr, "range")
        congruence_cert = relational_eval(expr, "congruence")
        partition_cert = partitioned_interval_certificate(expr)

        assert relation_is_sound(global_cert, expr)
        assert relation_is_sound(toy_range_cert, expr)
        assert relation_is_sound(congruence_cert, expr)
        assert relation_is_sound(partition_cert, expr)

        matrix[name] = {
            "truth_table": [
                {"input": list(row), "output": tables[name][row]}
                for row in ROWS
            ],
            "nonconstant": len(set(tables[name].values())) > 1,
            "exact_global_value_range": list(exact_range),
            "interval_global_value_range": list(inferred_range),
            "global_value_range_exact": inferred_range == exact_range,
            "global_range_certifies_graph": relation_is_exact(global_cert, expr),
            "toy_row_relation_range_mod_certifies_graph": relation_is_exact(
                toy_range_cert, expr
            ),
            "congruence_refined_relation_certifies_graph": relation_is_exact(
                congruence_cert, expr
            ),
            "singleton_input_partition_certifies_graph": relation_is_exact(
                partition_cert, expr
            ),
        }

    report = {
        "schema": "witness2-precision-audit-v2",
        "same_concrete_nand_function": same_nand,
        "claim_matrix": matrix,
        "completeness": completeness_checks(),
        "scope": [
            "A full Boolean output range is exact for every nonconstant Boolean function; it does not by itself establish relational opacity.",
            "The strict completeness inequality is specific to the toy row-forgetting MOD transfer implemented here.",
            "The result is not a model of, and supplies no system-independence evidence about, the Linux eBPF verifier.",
            "The archived old-input-model Frama-C log reports global value ranges only; it is not a run of the corrected two-input source and does not validate this report's relational claims.",
            "The exact residue and singleton-partition repairs enumerate four Boolean input rows; they establish no scalability or circuit-composition theorem.",
        ],
    }

    # These are the empirical invariants whose failure must make the script fail.
    assert same_nand
    assert all(row["global_value_range_exact"] for row in matrix.values())
    assert not any(row["global_range_certifies_graph"] for row in matrix.values())
    assert matrix["projection"]["toy_row_relation_range_mod_certifies_graph"]
    assert matrix["explicit_nand"]["toy_row_relation_range_mod_certifies_graph"]
    assert not matrix["modulo_nand"]["toy_row_relation_range_mod_certifies_graph"]
    assert all(
        row["congruence_refined_relation_certifies_graph"]
        for row in matrix.values()
    )
    assert all(
        row["singleton_input_partition_certifies_graph"]
        for row in matrix.values()
    )
    assert report["completeness"]["interval_on_actual_value_set"]["equal"]
    assert report["completeness"]["row_relation_on_actual_reachable_state"][
        "lhs_strict_subset_of_rhs"
    ]
    return report


def format_table(table: Sequence[Sequence[str]], widths: Sequence[int]) -> str:
    return "\n".join(
        "  ".join(str(value).ljust(width) for value, width in zip(row, widths))
        for row in table
    )


def print_text(report: dict) -> None:
    print("PRECISION CONTROL — VALUE RANGE VS RELATIONAL CERTIFICATION")
    print("=" * 72)
    print(f"Equivalent concrete NAND implementations: {report['same_concrete_nand_function']}")
    print()

    header = (
        "case",
        "range exact",
        "global graph",
        "toy range-MOD graph",
        "refined graph",
        "partition graph",
    )
    rows = [header]
    for name, facts in report["claim_matrix"].items():
        rows.append(
            (
                name,
                str(facts["global_value_range_exact"]),
                str(facts["global_range_certifies_graph"]),
                str(facts["toy_row_relation_range_mod_certifies_graph"]),
                str(facts["congruence_refined_relation_certifies_graph"]),
                str(facts["singleton_input_partition_certifies_graph"]),
            )
        )
    print("CLAIM MATRIX")
    print(format_table(rows, (16, 12, 13, 20, 13, 15)))
    print()

    interval = report["completeness"]["interval_on_actual_value_set"]
    relational = report["completeness"]["row_relation_on_actual_reachable_state"]
    print("COMPLETENESS CHECKS ON ACTUAL REACHABLE STATES")
    print(
        "  interval values: alpha(mod(X)) = "
        f"{interval['lhs_alpha_of_concrete_mod_X']}; "
        "mod#(alpha(X)) = "
        f"{interval['rhs_interval_mod_of_alpha_X']}; equal={interval['equal']}"
    )
    print(
        "  toy row relation: exact MOD result is a strict subset of the "
        "range-only MOD result: "
        f"{relational['lhs_strict_subset_of_rhs']}"
    )
    print(
        "  congruence-aware refinement restores equality: "
        f"{relational['refined_rhs_equal_to_lhs']}"
    )
    print()

    print("INTERPRETATION")
    for item in report["scope"]:
        print(f"  - {item}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--json", action="store_true", help="emit the machine-readable report"
    )
    args = parser.parse_args()
    report = build_report()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_text(report)


if __name__ == "__main__":
    main()
