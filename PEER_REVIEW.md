# Peer Review — "Residual Semantic Languages and the eBPF Weird-Machine Witness"

Simulated multi-perspective review (academic-paper-reviewer, full mode). Reviewed
materials: `ARTIFACT.md` (Claims + Appendix A.1–A.10), `results/abstraction_gap_witness.md`,
`results/exploitable_gap.md`, `README.md`, `ETHICS.md`. Read-only: this is a separate
document; the manuscript was not modified.

**Revision status, 2026-07-07:** this remains the original simulated review record. The current
`PAPER_DRAFT.md` addresses the listed blockers by adding related work/references, defining
A-opacity through certified input-output relations rather than a path-sensitive `⊤` cell, and
restating the theorem as a program-family result. **LangSec-target update:** the draft now leads
with the recognizer/runtime language-boundary claim, adds Figure 1, and treats the theorem as a
sufficient condition for residual weird machines inside a recognized safety language. Use the issue
list below as historical review context and a re-review checklist, not as the current state of the
manuscript.

---

## Phase 0 — Field analysis

- **Primary field:** systems security / language-theoretic security (weird machines, LangSec).
- **Secondary field:** programming languages — abstract interpretation, soundness vs.
  completeness of static analysis.
- **Paradigm:** constructive artifact + conditional theorem with artifact instantiation.
- **Maturity:** *artifact* is strong and near-publishable; *theory wrapper* (A.9/A.10) is
  early-stage and currently un-situated.
- **Realistic venue as-written:** LangSec/SPW workshop, or WOOT-class. **Venue the theory
  targets:** SAS / CSF / a PL venue — reachable only after the revisions below.

---

## Headline verdict: **MAJOR REVISION**

The core idea is genuinely novel in one specific, defensible way: it recasts the
weird-machine phenomenon as **incompleteness of a sound static analysis**, makes it a
**machine-checkable proposition** (A.9), and lifts it to a **conditional theorem** (A.10)
with the eBPF hypotheses instantiated by a reproducible artifact. The engineering artifact
(exhaustive truth tables, ablations, per-variant object-hash provenance, independent audit
oracle) is above the bar for its field.

At review time, three issues blocked acceptance *as a theory paper*:

1. **No related work, no bibliography.** For a paper asserting a *theorem about weird
   machines*, omitting the closest prior art is disqualifying. (Blocker.)
2. **The opacity claim `⟦π_f⟧# = ⊤` is under-specified w.r.t. the analysis model** —
   path-sensitive verifier vs. join-based abstract interpreter. The generalization you want
   (goal #1) hinges on fixing exactly this. (Devil's Advocate CRITICAL.)
3. **"Arbitrary Boolean circuits" relies on an unstated time-multiplexing argument** over
   only 9 gate-maps.

Devil's Advocate raised a CRITICAL issue, so per the review protocol the decision cannot be
Accept. It is, however, a *fixable* Major Revision — none of the three is a defect in the
result, only in how it is stated and situated.

---

## Reviewer 1 — Methodology & reproducibility (systems)

**Strengths.**
- Exhaustive coverage where it counts: NAND 400/400, full adder 8/8, 8-bit adder
  65536/65536. These are genuine proofs for those functions, not sampled.
- **Ablation design is textbook-good causal attribution.** `GATE_CAP=64` and
  `WM_FORCE_SENTINEL_B` each collapse the gate to a constant; the baseline builds the same
  truth table with legible ALU logic. This isolates the mechanism (capacity saturation)
  cleanly — reviewers rarely see this discipline in security artifacts.
- Provenance binding (four distinct object hashes → four result sets) and an **independent
  audit oracle** (`audit_results.py` recomputes expected tables rather than trusting the
  harness `passed` flag) are strong reproducibility practice.

**Concerns.**
- **M1 (mechanism precision — the −E2BIG story).** The claim that the second input-conditioned fresh-key update
  returns a negative errno exactly at `max_entries` depends on map type. For
  `BPF_MAP_TYPE_HASH` with prealloc, the kernel reserves per-CPU *extra elements*; the
  effective capacity can exceed `max_entries` and be allocation/CPU-order sensitive. State
  explicitly: (a) prealloc vs. `BPF_F_NO_PREALLOC`, (b) that runs are single-CPU offline
  `BPF_PROG_TEST_RUN`, (c) the kernel source path for the `−E2BIG` return
  (`kernel/bpf/hashtab.c`). Your `ablation_cap64` result is good evidence the threshold
  behaves as claimed *on your box*, but the mechanism narrative in A.4 is currently
  under-explained for a reader who knows htab internals.
- **M2 (single environment).** All evidence is one kernel (6.17.0 aarch64). htab internals
  and verifier behavior drift across versions/arches. At minimum flag kernel-version
  sensitivity; ideally re-run on x86-64 + a second LTS kernel and diff the verifier log.
- **M3 (adder32 labeling).** `adder` is 1005 fixed cases, *not* exhaustive — you already say
  so honestly (A.5). Keep the exhaustive 8-bit as the ceiling claim; don't let "32-bit adder"
  in the README read as exhaustive.

**Rigor score: 7/10** (artifact) — the *evidence* is strong; the *theory* claims outrun the
single-instance evidence, which is a positioning problem, not a data problem.

---

## Reviewer 2 — Domain (weird machines / LangSec literature)

**The paper has no related-work section and cites nothing.** For a paper staking a *theorem*
about weird machines this is the single largest defect. Required engagement, with the exact
delta you should claim over each:

- **Vanegue (2014), "The Weird Machines in Proof-Carrying Code," SPW/LangSec.** *The closest
  prior art, and currently uncited.* He already states your thesis informally: weird machines
  as "shadow execution arising in programs when their proofs do not sufficiently capture and
  disallow the execution of untrusted computations," with a taxonomy over policy / memory
  model / machine abstraction / formal system, and the line "any used abstraction is the
  opportunity for an attacker to introduce uncaptured computations." **Your contribution over
  Vanegue is precisely that you make it (a) machine-checkable (A.9) and (b) a conditional
  theorem with an artifact-instantiated basis (A.10).** Cite him and sharpen that delta — it
  *strengthens* your novelty claim. Omit him and a domain reviewer rejects on prior art.
- **Dullien (2020), "Weird Machines, Exploitability, and Provable Unexploitability," IEEE
  TETC 8(2).** The foundational finite-state/transducer model. Your "opacity" is a *different
  property* than his "exploitability": opacity = a sound analysis's blind spot; exploitability
  = reachability of an attacker goal state. Relate the two explicitly — it's a clean way to
  position "opaque programmable computation" as orthogonal to his axis.
- **Paykin, Mertens, Tullsen, Maurer, Razet, Bakst, Moore (2019), "Weird Machines as Insecure
  Compilation," arXiv:1911.00157 (Galois).** Weird machine = target behaviors unreachable by
  any source-level context; a compiler has no exploits iff it satisfies Robust Hyperproperty
  Preservation. Theirs is **source-vs-target** abstraction; yours is
  **concrete-vs-abstract-domain** (static analysis). Distinct and complementary — cite it to
  stake your lane rather than let a reviewer assume overlap.
- **Bangert, Bratus, Shapiro, Smith (2013), "The Page-Fault Weird Machine," WOOT** and
  **Shapiro, Bratus, Smith (2013), "Weird Machines in ELF," WOOT.** Both realize
  *Turing-complete* weird machines in a checker/loader substrate. Position your
  bounded/combinational, *deliberately not Turing-complete* scope against theirs — it makes
  your termination-check argument a feature, not a limitation.
- **Bratus, Locasto, Patterson, Sassaman, Shubina (2011), "Exploit Programming," USENIX
  ;login:.** Origin of the weird-machine framing; one-line grounding cite.
- **eBPF-specific formalization (you *rely* on this and cite none of it):**
  - **Gershuni et al. (2019), "Simple and Precise Static Analysis of Untrusted Linux Kernel
    Extensions" (PREVAIL), PLDI** — an abstract-interpretation eBPF verifier. Directly
    relevant to your "second sound verifier" plan.
  - **Vishwanathan, Shachnai, Narayana, Nagarakatte (2022), "Sound, Precise, and Fast Abstract
    Interpretation with Tristate Numbers," CGO** — the *formal spec + soundness proof of the
    tnum domain* you invoke in A.9. You describe the scalar lattice as "a tnum refined by
    interval bounds"; cite the paper that formalizes it.
  - MOAT (Lu et al., arXiv:2301.13421) as complementary BPF hardening work: it isolates accepted BPF programs, while this paper studies residual semantics inside accepted programs.

**Domain contribution:** real, but **currently un-situated and therefore unverifiable by a
reviewer.** With the six citations above and the deltas made explicit, the contribution
becomes legible and, I think, defensible.

---

## Reviewer 3 — Cross-disciplinary perspective (abstract interpretation)

**This is your biggest missed opportunity and the answer to goal #1.** The phenomenon you
witness is, in the precise technical sense, **incompleteness of a sound abstract
interpretation** — a 25-year-old theory with exactly the machinery you need to turn "another
instance" into a theorem.

- **Giacobazzi, Ranzato, Scozzari (2000), "Making Abstract Interpretations Complete," JACM
  47(2).** An abstraction α is *complete* for a concrete operation f iff `α∘f = α∘f∘γ∘α`.
  An **abstractly unresolved readout channel at `op` is definitionally a point where α is incomplete for `op`** relative to
  the concrete component φ: your (g1) says the concrete transfer depends on φ, your (g2) says
  α collapses it — that is exactly the failure of the completeness equation at that point.
  GRS give constructive *complete-shell / complete-core* characterizations of which domains
  are (in)complete for a given operation — i.e., a ready-made handle on *"which class of sound
  abstractions admits the channel."*
- **Bruni, Giacobazzi, Gori, Ranzato (2021), "A Logic for Locally Complete Abstract
  Interpretations," LICS (Distinguished Paper).** *Local* completeness ties (in)completeness
  to specific inputs / program fragments and gives a proof system unifying correctness and
  incorrectness. **This is literally your "boundary conditions" calculus** — LCL is how you
  state, per fragment, whether α is complete or admits a constructible abstractly unresolved readout channel.
- **Bruni et al. (2022), "Partial (In)Completeness in Abstract Interpretation," POPL /
  PACMPL** and the **SAS 2023 "measuring incompleteness"** follow-ups — quantify *how much* an
  abstractly unresolved readout channel leaks, which is the natural refinement of a binary "exploitable/not."

**Scope discipline.** Outlook #2 (weird machines in the neural-semantic layer) is a genuinely
interesting bet but a *separate paper*; keep it to one paragraph so it doesn't dilute the
abstract-interpretation contribution this paper can actually own.

---

## Devil's Advocate

**Strongest counter-argument.** *"You reimplemented NAND with hash maps. The verifier already
accepts explicit-logic NAND (A.8), so you added no expressiveness; you moved a known
computation into map metadata and then observed that a domain which doesn't track map
metadata doesn't track it. The 'theorem' is a restatement of the definitional fact that a
sound-but-incomplete analysis is incomplete."* — Your §0 pre-empts this and answers it
correctly (the payload is *invisibility to sound analysis*, not expressiveness). But that
answer is buried; it must be the **headline of the abstract**, or every skim reader lands on
the counter-argument and stops.

**Issue list.**
- **DA-1 (CRITICAL — theory).** `⟦π_f⟧# = ⊤` is not obviously true under a *path-sensitive*
  analysis. Your own A.9 log shows the verifier **forks** at `if r6 == 0`, and on each
  successor `r6` is *known* (`R6=0` on one edge). So along each explored path the output bit
  is a known constant — not ⊤. Opacity holds only in the sense that the **set of reachable
  outputs is {0,1} independent of any input relation the analysis can express** — a statement
  about the *join / reachable-value set*, not a single ⊤ cell. For a join-based interpreter
  (intervals, tnum-with-join) the ⊤-cell statement is literally true; for the path-sensitive
  eBPF verifier it must be restated. As written, Theorem 5's opacity invariant assumes the
  join-based reading while the eBPF instance (A.9) is path-sensitive. **Fix:** define
  A-opacity in terms of the analysis's *certified output abstraction* (the join over reachable
  paths / the analysis's post-condition), and show both models satisfy it. This is also what
  makes goal #1 tractable — the incompleteness framing is cleanest for join-based α.
- **DA-2 (MAJOR).** "Arbitrary Boolean circuits from G0..G8" is not shown. An 8-bit ripple
  adder is ~70+ NAND gates; you have 9 gate-maps. The construction is necessarily
  **time-multiplexed** — evaluate gates in topological order, store wire bits on `TAPE`, reset
  maps (E3) between evaluations. That's correct and is *exactly why you're bounded /
  combinational* — but it is unstated, and "E4: independent maps G0..G8" reads as if 9 gates
  were the ceiling. State the time-multiplexing explicitly; it also tightens the
  not-Turing-complete argument (wire count is statically bounded per program).
- **DA-3 (MAJOR).** Novelty vs. Vanegue 2014 (see Reviewer 2). Non-negotiable citation.
- **DA-4 (MINOR).** The "biconditional" (Corollary 6) over-claims. The ⇒ direction ("if the
  output depends on inputs it must be observed and input-driven") is near-definitional; the ⇐
  is Theorem 5. Consider downgrading "biconditional" → "characterization" to avoid a sharp
  reader pulling on the thin ⇒ direction.
- **DA-5 (MINOR).** E3/E4 necessity is "construction-relative" (you say so). Good — but then
  don't let Corollary 6 imply they're intrinsic; keep the honest hedge adjacent to the
  headline claim, not only in the "Honest scope" paragraph.

**Non-defect observations.** The ablation design, provenance binding, and the explicit "Not
claimed" section are credibility assets — the honesty is doing real work for you. Keep them.

---

## Editorial decision & revision roadmap

**Decision: Major Revision.** Novel, publishable core; over-reaching and un-situated theory
wrapper. Priority order:

1. **[Blocker] Add related work + bibliography.** Situate against Vanegue 2014, Dullien 2020,
   Paykin 2019, Bangert 2013 / Shapiro 2013, Bratus 2011; and the eBPF formalization line
   (Gershuni 2019, Vishwanathan 2022). Make the delta over Vanegue 2014 explicit.
2. **[Blocker / DA-1] Pin the analysis model** in the definition of A-opacity. Give the
   join-based statement as primary; note the path-sensitive verifier realizes it via
   reachable-set = {0,1}.
3. **[DA-2] State the time-multiplexing construction** for arbitrary circuits.
4. **[Elevation] Reframe A.9/A.10 in completeness-of-AI terms** (GRS 2000; LCL LICS 2021).
   This is the single change that converts "another instance" → "citable theory."
5. **[M1] Tighten mechanism precision:** map type, prealloc, single-CPU, kernel source ref.
6. **[Generalization] Make the second witness a *join-based* interval/tnum analyzer** (not
   only an exotic runtime). It simultaneously proves system-independence, makes opacity
   literally a ⊤-cell (kills DA-1), and instantiates GRS incompleteness directly — one move,
   three problems.

---

## On goal #1 — turning the Residual-Language Weird Machine Theorem into a theorem with boundary conditions

The durable, citable version is a **completeness-theoretic** theorem, with eBPF as the
artifact-instantiated instance and the *framework* as the contribution:

**Definition (constructible abstractly unresolved readout channel).** For toolkit Π and sound abstraction α, α admits a
constructible abstractly unresolved readout channel iff ∃ `op ∈ Π` and concrete component φ such that α is **incomplete**
for `op` at φ in the GRS sense (`α∘⟦op⟧ ⊐ α∘⟦op⟧∘γ∘α` there). *(This subsumes your Def. 1.)*

**Necessity (which α necessarily admit one).** Any sound α that fails to be forward-complete
for some input-controllable `op ∈ Π` admits a constructible abstractly unresolved readout channel. **Completeness is the
exact boundary:** complete-for-Π ⇒ no channel; incomplete-at-a-reachable-op ⇒ channel. GRS's
complete-shell/core constructions characterize the boundary constructively.

**Exploitability is a condition on Π, not on α.** E1 (observability) and E2 (input-control)
are *expressibility* properties of the toolkit around the incomplete op; E3/E4 are
construction ingredients. So the clean statement is: *for the class of sound-but-op-incomplete
abstractions, any Π that can observe and input-drive the incomplete op yields programmable
opacity; if the induced gate is functionally complete, E3/E4 give arbitrary **bounded**
circuits.* **Local Completeness Logic supplies the per-fragment "boundary conditions"
calculus** you asked for.

**Best near-term down-payment.** Your §6 lists WASM `table.grow` / JVM collection size as
second witnesses. Prefer instead (or first) a **join-based interval/tnum static analyzer** as
the second witness, because it is the *bridge from instance to theorem*: it proves
system-independence, makes `⟦π_f⟧# = ⊤` literally a top cell (resolving DA-1), and is a direct
instantiation of GRS incompleteness. The exotic-runtime witnesses are better as *breadth*
evidence after the theorem is stated in completeness terms.

Net: the theorem you want already lives inside a mature theory. Citing into it (rather than
re-deriving it under weird-machine vocabulary) is what moves this from "a clever eBPF
construction" to "a framework result other people cite."

---

### Key references to add (verify final metadata before submission)

- Cousot & Cousot (1977). Abstract Interpretation. POPL.
- Giacobazzi, Ranzato, Scozzari (2000). Making Abstract Interpretations Complete. JACM 47(2), 361–416.
- Bruni, Giacobazzi, Gori, Ranzato (2021). A Logic for Locally Complete Abstract Interpretations. LICS (Distinguished Paper).
- Bruni, Giacobazzi, Gori, Ranzato (2022). Partial (In)Completeness in Abstract Interpretation. POPL / PACMPL 6.
- Bratus, Locasto, Patterson, Sassaman, Shubina (2011). Exploit Programming. USENIX ;login:.
- Bangert, Bratus, Shapiro, Smith (2013). The Page-Fault Weird Machine. USENIX WOOT.
- Shapiro, Bratus, Smith (2013). "Weird Machines" in ELF. USENIX WOOT.
- Vanegue (2014). The Weird Machines in Proof-Carrying Code. IEEE SPW/LangSec. DOI 10.1109/SPW.2014.37.
- Dullien (2020). Weird Machines, Exploitability, and Provable Unexploitability. IEEE TETC 8(2), 391–403. DOI 10.1109/TETC.2017.2785299.
- Paykin, Mertens, Tullsen, Maurer, Razet, Bakst, Moore (2019). Weird Machines as Insecure Compilation. arXiv:1911.00157.
- Vanegue (2022). Adversarial Logic. SAS, LNCS 13790. DOI 10.1007/978-3-031-22308-2_19.
- Gershuni et al. (2019). Simple and Precise Static Analysis of Untrusted Linux Kernel Extensions (PREVAIL). PLDI.
- Vishwanathan, Shachnai, Narayana, Nagarakatte (2022). Sound, Precise, and Fast Abstract Interpretation with Tristate Numbers. CGO. arXiv:2105.05398.
