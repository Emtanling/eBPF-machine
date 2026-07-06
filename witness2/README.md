# Second witness — opaque computation in a join-based interval analyzer

This is the empirical down-payment for the boundary-condition theorem (paper §9): a
**second, structurally different** `(C, A)` pair that reproduces the same phenomenon as
the eBPF witness. If the phenomenon appears here too, it tracks *sound-but-incomplete
abstraction*, not an eBPF quirk.

`python3 witness.py` — no dependencies. It runs today and prints the table in one screen.

## Why this pair, and how it differs from the eBPF witness

| | eBPF witness (paper §6) | This second witness |
|---|---|---|
| Analyzer `A` | in-kernel verifier — **path-sensitive** | interval abstract interpreter — **join-based, non-relational** |
| Channel `φ` | hash-map **occupancy** `c(G)` | a **congruence** quantity `acc mod k` |
| `⟦π⟧# = ⊤` | join *over explored paths* (certified output abstraction, Def. 2) | **literally one `⊤` interval** — no path-sensitivity caveat |
| Substrate | kernel maps + helper return codes | pure integer arithmetic |

The two share nothing at the systems level, which is the point. What they share is the
*abstract* structure of the paper's abstraction-gap outlook.

## The gate

```
NAND(a, b) = [ (1 + a + b) mod 3 != 0 ]
```

The sentinel `1` and modulus `3` play the roles of the eBPF sentinel and `max_entries`.
`acc = 1 + a + b ∈ {1,2,3}`; `acc mod 3 ∈ {1,2,0}`; the readout `[·≠0]` gives `1,1,1,0` =
NAND. `AND` and `XOR` are built by composing NAND gates (2 and 4 channel uses).

## Relating this pair to the paper's abstraction-gap outlook

- **(α) erased residual state / incomplete operation.** The interval domain is
  backward-incomplete for `mod`: `acc ∈ [1,3] ⇒ acc mod 3` is soundly abstracted to
  `[0,2]`, and the readout joins to `[0,1] = ⊤`. `φ` = the residue class, unrepresented by
  intervals.
- **(Π) expressibility E1–E4.** E1 = branch on `[acc mod 3 ≠ 0]`; E2 = `acc = 1+a+b`
  (input-driven); E3 = fresh `acc` (sentinel `1`) per gate; E4 = independent accumulators,
  used by `and_gate` / `xor_gate`.
- **(R) robust functional completeness.** Deterministic evaluation, no uncontrolled input
  `u`, so the gate is robustly realized (the same degenerate corner as the eBPF offline
  run); NAND is functionally complete.

## What the script proves

1. **Concrete correctness** — exhaustive oracle: NAND, and composed AND and XOR, match
   spec (`matches spec: True`).
2. **A-opacity (Definition 2)** — the interval analyzer returns `[0,1] = ⊤` for the output
   of every mod-3 gate: it certifies nothing about the output bit though it depends on the
   inputs.
3. **Non-triviality (localization / repair)** — the ablation `mod 7` degenerates the gate to
   the constant `1`, and the **same** interval analyzer then certifies `[1,1]`. So the
   domain is *not* trivially always-`⊤`; the blindness is localized to the working `mod`
   channel. (This is the interval analogue of the eBPF `GATE_CAP=64` ablation.)
4. **Repair = precision price** — a disjunctive / input-partitioned
   analysis certifies the output per input. Closing the channel costs the analyzer exactly
   this added precision (tracking the channel variable's value set), not free.
5. **Leakage composition pattern** — AND and XOR keep the output at `⊤` (`L_out ≤ 1` bit)
   while the number of channel uses grows (`L_trace ≈ 1, 2, 4` bits): the analysis is blind
   to `Θ(circuit size)` bits of computation, not to one.

Every interval transfer is checked to over-approximate the concrete output set at runtime
(`assert_sound`), so the analyzer is genuinely **sound** — the imprecision is designed
incompleteness, not a bug. That is what makes this a witness rather than a broken analyzer.

## Independent analyzer reproduction

The interval interpreter here is written for this repository so the witness is
self-contained and exhaustively checkable. The same construction is also fed to
Frama-C EVA, an independent production value analysis. That run is confirmed in
`frama_c/RESULTS.md`: the working mod-3 gate has output `{0; 1} = ⊤`, while the
mod-7 ablation narrows to `{1}` with zero alarms. This upgrades the evidence
from "our interpreter is blind" to "an independent sound analyzer we did not
write exhibits the same localized blindness."

IKOS / Crab remains an optional third target: the same C/LLVM shape can be
analyzed with the interval domain of the Crab library, the numeric-domain family
that PREVAIL builds on. That would sharpen the contrast further, but the paper's
second-witness claim is already backed by the self-contained analyzer and the
captured Frama-C EVA result.
