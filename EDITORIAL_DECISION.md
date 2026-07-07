# Editorial Decision Letter

**Manuscript:** Opaque Programmable Computation / the eBPF Opacity Theorem
(`ARTIFACT.md` A.1–A.10, `results/abstraction_gap_witness.md`, `results/exploitable_gap.md`;
full drafted version in `PAPER_DRAFT.md`).
**Simulated venue tier:** SAS / CSF (full) · LangSec-SPW (short).
**Decision:** **Major Revision** — the *result* is acceptable and worth publishing; the
*manuscript as originally written* (the `ARTIFACT.md` appendices) is not yet a submittable
paper. Most manuscript-level blockers are already resolved in `PAPER_DRAFT.md`; the remaining
gap is the substance of goal #1.

## Verdict in one line

可以 — 内容达到可发表水准，但需 Major Revision。The contribution is novel, the artifact is
above the bar for the field, and the honest scoping is a credibility asset. It cannot be
*accepted as-is* because (a) the original manuscript has no related work / bibliography and
(b) one theory step (the `⊤`-opacity claim under a path-sensitive analyzer) was under-specified.
Both are fixable and (a),(b) are addressed in `PAPER_DRAFT.md`.

## Scores (peer-review rubric)

| Dimension (weight) | Score | Basis |
|---|---|---|
| Originality (20%) | 82 | Novel angle: opacity as *designed incompleteness*; first verifier-accepted, non-CVE witness. Capped because the high-level thesis overlaps Vanegue 2014 [8] — the delta is formalization+witness, which must be stated. |
| Methodological rigor (25%) | 78 | Exhaustive truth tables, ablations that collapse the gate, per-variant object-hash provenance, independent audit oracle — genuinely strong. Dinged for single kernel/arch and under-explained `-E2BIG`/prealloc mechanism. |
| Evidence sufficiency (25%) | 70 | Airtight for the eBPF instance; the *theorem's generality* still rests on one instance; the `⟦π⟧#=⊤` claim needed the analysis-model fix before the evidence supported it. |
| Argument coherence (15%) | 72 | The "so what" answer (payload = invisibility, not expressiveness) is correct but was buried; "biconditional" over-claims; time-multiplexing step unstated. Improved in `PAPER_DRAFT.md`. |
| Writing quality (15%) | 80 | Precise, honest register; excellent "Not claimed" discipline. Structural hole: no related-work section, no references. |
| **Weighted total** | **≈76 / 100** | Solid Major Revision, leaning acceptable. Above reject, below accept. |

## Blocking issues (must resolve before Accept)

1. **[Blocker] No related work / bibliography** in the original manuscript. Resolved in
   `PAPER_DRAFT.md` §8. Situate against Bratus [5], Vanegue 2014 [8] (closest — state the
   delta), Dullien 2020 [9], Paykin 2019 [10]; the completeness line [2],[3]; eBPF
   formalization [12],[13].
2. **[Blocker / DA CRITICAL] Pin the analysis model** for A-opacity. `⟦π⟧#=⊤` is not literally
   true under the path-sensitive verifier (it forks and knows the output per path). Resolved in
   `PAPER_DRAFT.md` §4 via the *certified output abstraction* (join-over-paths). Keep that.
3. **[Major] State the time-multiplexing construction** for "arbitrary circuits" from a bounded
   number of gate maps. Resolved in `PAPER_DRAFT.md` §5.

## Non-blocking but expected

- Mechanism precision (map type / prealloc / single-CPU / kernel source for `-E2BIG`).
- Second environment (x86-64 + a second kernel) to defuse the single-instance threat.
- Downgrade "biconditional" → "characterization" (the ⇒ direction is near-definitional).

## What raises the score toward Accept — and it is goal #1

The score is capped by *evidence sufficiency* and *originality*, and the single change that
lifts both is executing goal #1 rather than adding another eBPF variant:

- **Recast the hypothesis in completeness theory** [2],[3] so the paper contributes a
  *boundary-condition theorem*, not a second instance. The α-side condition (a `⊤`-channel
  exists) becomes "α is incomplete for a Π-reachable operation" — a characterizable class, not
  an instance.
- **The exploitability half now has a formal home too.** Goal #1 asks "when is the gap
  *necessarily exploitable*." The **robust reachability** framework (Girol–Farinier–Bardin,
  CAV 2021; Sellami–Girol–Bardin, POPL 2024) formalizes precisely a condition an adversary can
  trigger *regardless of uncontrolled inputs* — the right formal notion for E1/E2 "necessarily
  exploitable." Pairing completeness (channel exists) with robust reachability (channel is
  reliably drivable) gives a two-sided characterization: α-incompleteness supplies necessity of
  the channel; robust reachability supplies necessity of exploitability.
- **Second witness in a join-based analyzer** (interval/tnum) is the near-term empirical
  down-payment: it makes opacity literally a `⊤` cell, instantiates completeness-incompleteness
  directly, and shows the phenomenon tracks *sound-but-incomplete abstraction*, not eBPF.

Doing this moves the paper from "≈76, strong instance" toward "clear accept, framework
result." That is the durable, citable contribution — the framework, not the construction.
