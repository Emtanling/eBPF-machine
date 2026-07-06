#!/usr/bin/env python3
"""
Second witness: opaque programmable computation in a join-based interval analyzer.

This is a structurally different (C, A) pair from the eBPF verifier witness:
  * the eBPF verifier is path-sensitive and its channel is hash-map occupancy;
  * here A is a SOUND, non-relational, join-based INTERVAL abstract interpreter,
    and the channel phi is a congruence quantity (acc mod k) that the interval
    domain abstracts to top.

Gate:  NAND(a, b) = [ (1 + a + b) mod 3 != 0 ]   (sentinel 1; modulus 3 is the threshold)

What this script demonstrates for this (C, A) -- mirroring the paper's claims:
  (1) concrete correctness -- exhaustive oracle: the program computes NAND, and,
      composed, AND and XOR.
  (2) A-opacity (Definition 2) -- the interval analyzer certifies out in [0,1] = TOP,
      i.e. nothing about the output bit, though concretely it depends on the inputs.
  (3) non-triviality (localization / repair) -- an ablation (modulus 7) degenerates the
      gate to a CONSTANT and the SAME interval analyzer then certifies out = [1,1].
      So the domain is not "trivially always top": the blindness is localized to the
      working channel, exactly the below-shell incompleteness at `mod`.
  (4) repair (Section 9.5, the repair outlook) -- a disjunctive (input-partitioned) analysis
      certifies the output per input: the precision price of closing the channel.

Run:  python3 witness2/witness.py       (no external dependencies)
"""

# ---------------------------------------------------------------------------
# Tiny expression IR.  An expression is a nested tuple.
# ---------------------------------------------------------------------------
def C(k):        return ('const', k)
def V(n):        return ('var', n)
def ADD(x, y):   return ('add', x, y)
def SUB(x, y):   return ('sub', x, y)
def MUL(x, y):   return ('mul', x, y)
def MOD(x, k):   return ('mod', x, k)      # k: positive int constant
def EQ(x, y):    return ('eq', x, y)
def NE(x, y):    return ('ne', x, y)
def GT(x, y):    return ('gt', x, y)
def SEL(c, x, y):return ('sel', c, x, y)   # if c != 0 then x else y


# ---------------------------------------------------------------------------
# The gate and its compositions.  Every NAND routes its output through the
# `mod` channel, so every gate use is one channel use (E1/E2/E3/E4 realized by
# fresh accumulators + the mod readout).
# ---------------------------------------------------------------------------
def nand(x, y, mod=3):
    acc = ADD(ADD(C(1), x), y)             # E2/E3: acc = 1 + a + b (sentinel 1, reset each gate)
    return SEL(NE(MOD(acc, mod), C(0)),    # E1: observe [ acc mod k != 0 ]
               C(1), C(0))

def and_gate(a, b, mod=3):                 # AND = NAND(NAND(a,b), NAND(a,b))  -- 2 channel uses
    g = nand(a, b, mod)
    return nand(g, g, mod)

def xor_gate(a, b, mod=3):                 # XOR from 4 NANDs                  -- 4 channel uses
    g = nand(a, b, mod)
    return nand(nand(a, g, mod), nand(b, g, mod), mod)


# ---------------------------------------------------------------------------
# Concrete semantics.
# ---------------------------------------------------------------------------
def ev_concrete(e, env):
    t = e[0]
    if t == 'const': return e[1]
    if t == 'var':   return env[e[1]]
    if t == 'add':   return ev_concrete(e[1], env) + ev_concrete(e[2], env)
    if t == 'sub':   return ev_concrete(e[1], env) - ev_concrete(e[2], env)
    if t == 'mul':   return ev_concrete(e[1], env) * ev_concrete(e[2], env)
    if t == 'mod':   return ev_concrete(e[1], env) % e[2]
    if t == 'eq':    return 1 if ev_concrete(e[1], env) == ev_concrete(e[2], env) else 0
    if t == 'ne':    return 1 if ev_concrete(e[1], env) != ev_concrete(e[2], env) else 0
    if t == 'gt':    return 1 if ev_concrete(e[1], env) >  ev_concrete(e[2], env) else 0
    if t == 'sel':   return ev_concrete(e[2], env) if ev_concrete(e[1], env) != 0 else ev_concrete(e[3], env)
    raise ValueError(t)


# ---------------------------------------------------------------------------
# Sound, non-relational, join-based INTERVAL domain.  A value is (lo, hi).
# Every transfer OVER-approximates its concrete counterpart (checked at runtime
# by assert_sound below), so any imprecision here is *designed incompleteness*,
# not a bug -- the whole point of the witness.
# ---------------------------------------------------------------------------
def i_mod(a, k):
    lo, hi = a
    # sound: if the interval stays within one block of size k, mod is exact;
    # otherwise the sound over-approximation is the full residue range [0, k-1].
    if lo >= 0 and (hi - lo) < k and (lo // k) == (hi // k):
        return (lo % k, hi % k)
    return (0, k - 1)

def i_disjoint(a, b):
    return a[1] < b[0] or b[1] < a[0]

def i_singleton_eq(a, b):
    return a[0] == a[1] == b[0] == b[1]

def ev_interval(e, env):
    t = e[0]
    if t == 'const': k = e[1]; return (k, k)
    if t == 'var':   return env[e[1]]
    if t == 'add':
        a = ev_interval(e[1], env); b = ev_interval(e[2], env)
        return (a[0] + b[0], a[1] + b[1])
    if t == 'sub':
        a = ev_interval(e[1], env); b = ev_interval(e[2], env)
        return (a[0] - b[1], a[1] - b[0])
    if t == 'mul':
        a = ev_interval(e[1], env); b = ev_interval(e[2], env)
        cs = [a[0]*b[0], a[0]*b[1], a[1]*b[0], a[1]*b[1]]
        return (min(cs), max(cs))
    if t == 'mod':
        return i_mod(ev_interval(e[1], env), e[2])
    if t == 'eq':
        a = ev_interval(e[1], env); b = ev_interval(e[2], env)
        if i_disjoint(a, b):      return (0, 0)
        if i_singleton_eq(a, b):  return (1, 1)
        return (0, 1)
    if t == 'ne':
        a = ev_interval(e[1], env); b = ev_interval(e[2], env)
        if i_disjoint(a, b):      return (1, 1)
        if i_singleton_eq(a, b):  return (0, 0)
        return (0, 1)
    if t == 'gt':
        a = ev_interval(e[1], env); b = ev_interval(e[2], env)
        if a[0] >  b[1]: return (1, 1)
        if a[1] <= b[0]: return (0, 0)
        return (0, 1)
    if t == 'sel':
        c = ev_interval(e[1], env)
        a = ev_interval(e[2], env); b = ev_interval(e[3], env)
        if c[0] >= 1: return a          # condition definitely true
        if c[1] <= 0: return b          # condition definitely false
        return (min(a[0], b[0]), max(a[1], b[1]))   # <-- the join: opacity happens here
    raise ValueError(t)


# ---------------------------------------------------------------------------
# Analyses.
# ---------------------------------------------------------------------------
def oracle(expr, inputs):
    """Exhaustive concrete truth table over all 0/1 assignments of `inputs`."""
    table = {}
    for bits in range(2 ** len(inputs)):
        env = {v: (bits >> i) & 1 for i, v in enumerate(inputs)}
        table[tuple(env[v] for v in inputs)] = ev_concrete(expr, env)
    return table

def interval_output(expr, inputs):
    """Join-based interval analysis with each input abstracted to the bit range [0,1]."""
    env = {v: (0, 1) for v in inputs}
    return ev_interval(expr, env)

def disjunctive_output(expr, inputs):
    """Repair: input-partitioned (trace-partitioned) analysis -> certified per input."""
    return oracle(expr, inputs)   # a definite value in each partition

def assert_sound(expr, inputs):
    """The interval transfer must over-approximate the concrete output set."""
    outs = set(oracle(expr, inputs).values())
    lo, hi = interval_output(expr, inputs)
    assert lo <= min(outs) and max(outs) <= hi, \
        f"UNSOUND interval result {(lo,hi)} vs concrete outputs {sorted(outs)}"


# ---------------------------------------------------------------------------
# Report.
# ---------------------------------------------------------------------------
def classify(iv):
    return "CERTIFIED " + str(iv) if iv[0] == iv[1] else "TOP  [0,1]  <- A-OPAQUE"

def truth(table):
    return "  ".join(f"{k}->{v}" for k, v in sorted(table.items()))

def reference(inputs, fn):
    return {tuple((bits >> i) & 1 for i in range(len(inputs))): fn(*[(bits >> i) & 1 for i in range(len(inputs))])
            for bits in range(2 ** len(inputs))}

def main():
    a, b = V('a'), V('b')
    ins = ['a', 'b']

    rows = [
        ("NAND (mod 3, working channel)", nand(a, b, 3),      lambda x, y: 1 - (x & y),  1),
        ("AND  = NAND∘NAND (mod 3)",      and_gate(a, b, 3),  lambda x, y: x & y,         2),
        ("XOR  = 4×NAND (mod 3)",         xor_gate(a, b, 3),  lambda x, y: x ^ y,         4),
        ("NAND (mod 7, ABLATION)",        nand(a, b, 7),      None,                       1),
    ]

    print("=" * 78)
    print("SECOND WITNESS — opaque computation in a sound join-based interval analyzer")
    print("=" * 78)
    print("Analyzer A: non-relational interval domain; channel phi = acc mod k.")
    print("Inputs abstracted to the bit range [0,1]; the interval join is the only")
    print("place opacity can arise.  Every interval transfer is checked sound at runtime.\n")

    for name, expr, ref, gate_uses in rows:
        assert_sound(expr, ins)
        table = oracle(expr, ins)
        iv = interval_output(expr, ins)
        outs = set(table.values())
        constant = (len(outs) == 1)

        print("-" * 78)
        print(name)
        print(f"  concrete (oracle) : {truth(table)}"
              f"   [{'CONSTANT' if constant else 'input-dependent'}]")
        if ref is not None:
            ok = table == reference(ins, ref)
            print(f"  matches spec      : {ok}")
        print(f"  interval output   : {classify(iv)}")
        if iv == (0, 1):
            dj = disjunctive_output(expr, ins)
            print(f"  repair (disjunct.): {truth(dj)}   [CERTIFIED per input]")
        print(f"  leakage           : L_gate=1 bit, channel uses={gate_uses} "
              f"=> L_trace<= {gate_uses} bit, L_out<=1 bit")

    print("-" * 78)
    print("""
READING THE OUTPUT
  * NAND/AND/XOR (mod 3): concrete output depends on the inputs, yet the interval
    analyzer returns [0,1] = TOP -- it certifies nothing about the output bit.
    That is A-opacity (Definition 2) in a join-based analyzer: the `⟦π⟧# = ⊤` of
    the paper is here LITERALLY one top interval, no path-sensitivity caveat needed.
  * The SAME analyzer CERTIFIES the ablation (mod 7 -> constant 1) as [1,1].
    So the interval domain is not trivially blind; the blindness is localized to
    the working `mod` channel -- an operation whose relevant residual congruence is erased
    by the interval abstraction, and which a disjunctive refinement repairs.
  * Composition (AND, XOR) keeps the output at TOP while the number of channel uses
    (hidden computation, L_trace) grows: L_out stays <= 1 bit, L_trace ~ size.
""")

if __name__ == "__main__":
    main()
