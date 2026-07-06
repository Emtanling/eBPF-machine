# Opaque Programmable Computation: Weird Machines from the Designed Incompleteness of Sound Verifiers

# Abstract

A *weird machine* is usually presented as the computational residue of a bug: a malformed input, parser differential, memory corruption, or metadata quirk drives an implementation into an unintended state space that an attacker can program. This paper studies a different source of weird computation: the designed incompleteness of sound program verifiers. We do not claim that eBPF can compute; ordinary eBPF bytecode is already computationally expressive. Instead, we show that computation can be relocated into concrete residual state that an abstract-interpretation verifier erases. If that erased state remains controllable, observable, resettable, and composable by accepted programs, and if the induced operation realizes a functionally complete gate, then it is sufficient to obtain verifier-opaque programmable computation.

We formalize this phenomenon as a `⊤`-channel: a program-visible operation whose concrete result depends on a residual state component outside the abstraction, while the verifier's abstract transfer maps the result to top. We then state a conditional Opacity Theorem: an exploitable `⊤`-channel whose induced gate is functionally complete can compute arbitrary bounded Boolean circuits while the verifier's certified output abstraction expresses no input-output relation for the computed function. The theorem is a sufficiency result, not a universal claim that every abstraction gap yields a weird machine.

We give, to our knowledge, the first verifier-success, non-CVE, memory-safe constructive witness in a production eBPF verifier setting. The witness realizes NAND entirely through eBPF hash-map occupancy and helper return metadata: map occupancy is not represented in the verifier abstraction, yet a capacity-probing insert exposes a threshold bit through its return code. The program is accepted by the in-kernel verifier, performs no memory corruption or verifier bypass, and composes the gate into finite arithmetic circuits. Ablations remove capacity saturation and collapse the gate to a constant; a baseline computes the same truth table with explicit bytecode logic; and independent audits re-derive the outputs. We further include a second, structurally different witness in a join-based interval analyzer and Frama-C EVA, as empirical evidence that the phenomenon tracks sound-but-incomplete abstraction rather than an eBPF quirk. The broader goal — a structural theorem characterizing which abstractions necessarily admit exploitable channels — remains an outlook, not a claim completed by this paper.

**Keywords:** weird machines, abstract interpretation, completeness, sound verification, eBPF, language-theoretic security, opaque computation.

---

# 1. Introduction

The eBPF verifier is one of the most consequential program analyzers deployed today: it
gates untrusted code into the Linux kernel on billions of machines, and it does so by
abstract interpretation — it simulates the program over an abstract domain and rejects
anything it cannot prove safe [12], [13]. Its guarantee is *soundness for safety*: an
accepted program does not read or write out of bounds, does not loop forever, and does not
dereference an invalid pointer. What the verifier does *not* promise is equally important and
far less discussed: it says nothing about *what the accepted program computes*. That silence
is not an accident or an oversight. It is the designed incompleteness of a sound abstraction —
the price every sound, terminating analyzer pays for decidability [1], [2].

This paper is about what lives in that silence. We show, constructively and with a
machine-checkable witness, that residual state erased by a sound verifier can become a
*weird machine* when the accepted toolkit can control, observe, reset, and compose it: a
programmable computational artifact whose input-to-output behavior the analysis cannot see. The construction uses no bug. The program
is accepted. Nothing is corrupted. The entire computation lives in a concrete quantity —
the occupancy of a bounded hash map — that the verifier's abstract domain does not represent
and, being sound, is not obliged to represent.

## 1.1 The gap is not a bug

The weird-machine literature, from its origin in language-theoretic security [5] through its
formal treatments [9], [10], has almost always assumed a defect: a parser differential, a
memory-corrupting input, a malformed metadata table [6], [7]. The "weird" instructions are
unintended state transitions unlocked by that defect. Our phenomenon is different in kind.
The verifier is *correct*. There is no unsound step, no accepted-but-unsafe program, no CVE.
The computation is invisible not because the analyzer is wrong but because it is sound and
therefore incomplete: it abstracts away the state that carries the computation, exactly as
its design intends.

This distinction matters for defense. A weird machine born of a bug is closed by fixing the
bug. A weird machine born of *sound incompleteness* cannot be closed without changing what the
abstraction tracks — and any such change trades decidability, precision, or performance. The
gap is structural.

## 1.2 Two independent conditions: on the abstraction, and on the toolkit

Prior informal statements of this idea — most directly Vanegue's observation that "any used
abstraction is the opportunity for an attacker to introduce uncaptured computations" [8] —
conflate two conditions that we hold apart, because separating them is what makes the result a
theorem rather than a slogan:

- A **condition on the abstraction** α: there is a program-expressible operation `op` and a
  concrete state component φ such that the concrete effect of `op` depends on φ while α erases
  φ. In the language of abstract interpretation, α is *incomplete* for `op` at φ [2]. This
  produces what we call a **`⊤`-channel**: a program-visible location that `op` sets to a
  non-constant function of φ, but that the abstract transfer sets to top.

- A **condition on the toolkit** Π (the accepted instruction/primitive set): the `⊤`-channel
  is **observable** (its value can be branched into a program bit), **input-controllable**
  (inputs can steer φ so the readout realizes a chosen Boolean dependence), **resettable**
  (φ can be restored, making the channel a pure re-evaluable gate), and **composable**
  (independent instances exist, so one gate can drive another).

The abstraction condition determines *whether the channel exists*; the toolkit conditions
determine *whether it is programmable*. Given both, plus functional completeness of the
induced gate, the accepted program computes arbitrary bounded Boolean circuits whose entire
input-to-output dependence is invisible to the analysis (Section 5).

## 1.3 Contributions

1. **A semantic sufficient condition for verifier-opaque weird machines.** We define a
   `⊤`-channel as a program-visible operation whose concrete return depends on state erased by
   the abstraction, while the verifier maps the return to top. We then separate the
   abstraction-side condition (the erased residual state influences a reachable operation) from
   the toolkit-side conditions (observability, input-control, resettability, and composability).
   This gives a precise sufficiency theorem for *opaque programmable computation* without
   claiming that every abstraction gap is exploitable.

2. **A verifier-success, non-CVE eBPF witness.** We construct a NAND gate in eBPF map/helper
   runtime metadata, not in ordinary ALU bytecode. Hash-map occupancy is absent from the verifier
   abstraction, yet helper return codes expose a capacity threshold that accepted programs can
   branch on. The result is accepted by the Linux verifier, memory-safe, bounded, and not a
   verifier bypass.

3. **A machine-checkable abstraction-gap witness.** We connect the construction to the verifier's
   own trace: the capacity-probing helper return is held as `scalar()`/`⊤`, and the verifier
   forks at the output branch. The concrete map occupancy separates truth-table cases that the
   abstract state quotients into a top value.

4. **Evidence that the phenomenon is not merely an eBPF quirk.** In addition to the eBPF witness,
   we include a second join-based interval-analysis witness, checked by a self-contained analyzer
   and Frama-C EVA. This is empirical support for the abstraction-gap thesis, not a completed
   general theorem.

5. **A research program from instances to boundary conditions.** We identify the next theoretical
   target: characterize the classes of sound abstractions `α` for which a program-constructible
   `⊤`-channel necessarily arises, and the toolkit conditions under which such a channel is
   necessarily exploitable. We frame this in the language of completeness for abstract
   interpretation, but leave the full structural theorem as future work.

Scope matters. This paper does not claim that eBPF is Turing-complete, that the verifier is
unsound, that a CVE exists, or that every abstraction gap yields a weird machine. The claim is a
conditional one: erased residual state plus the right program operations is sufficient for
bounded verifier-opaque programmability.

---

# 2. Background

## 2.1 Abstract interpretation, soundness, and completeness

An abstract interpreter approximates a concrete semantics `⟦·⟧ : Σ → Σ` by an abstract
semantics `⟦·⟧# : 𝒜 → 𝒜` connected to the concrete world by a Galois connection
`(α : ℘(Σ) → 𝒜, γ : 𝒜 → ℘(Σ))` [1]. **Soundness** requires each abstract transfer to
over-approximate its concrete counterpart: `α ∘ ⟦op⟧ ⊑ ⟦op⟧# ∘ α`. Soundness alone is cheap;
the top element `⊤` (with `γ(⊤) = Σ`) is a sound abstraction of everything and certifies
nothing.

**Completeness** is the property that the abstraction loses *no* information at an operation
relative to what it can already express: α is (backward-)complete for `op` when
`α ∘ ⟦op⟧ = α ∘ ⟦op⟧ ∘ γ ∘ α` [2]. Giacobazzi, Ranzato, and Scozzari showed that
completeness is a property of the *abstraction and the operation together*, and gave
constructive characterizations (the complete shell and core) of the domains that are complete
for a given semantics [2]. Bruni, Giacobazzi, Gori, and Ranzato later localized the notion:
*local completeness* holds for particular inputs or program fragments, and supports a proof
system that reasons simultaneously about correctness and incorrectness [3]. Incompleteness is
not a defect to be removed at will — for a sound, terminating analyzer over an undecidable
property it is unavoidable — but it *is* precisely characterizable, and that is what we
exploit.

The reading we need is simple: **a `⊤`-channel is a witness of incompleteness.** If `op`'s
concrete effect depends on a component φ that α discards, then at that point
`α ∘ ⟦op⟧ ⊐ α ∘ ⟦op⟧ ∘ γ ∘ α`, and the abstract result is `⊤` where the concrete result is
informative. The rest of the paper studies when such a witness is *program-constructible* and
*programmable*.

## 2.2 The eBPF verifier as an abstract interpreter

The Linux eBPF verifier statically checks untrusted bytecode before it runs in the kernel
[12]. It performs a symbolic pass that tracks, per register and stack slot, an abstract value:
a *tristate number* (tnum, a known-bits abstraction) refined by signed and unsigned interval
bounds [13]. Its abstract domain represents pointer types, map-value regions, and scalar
ranges, and it explores program paths to prove memory safety and bounded termination.
Vishwanathan et al. formally specified and proved sound the tnum domain now used in the kernel
[13]; Gershuni et al. built an abstract-interpretation-based verifier (PREVAIL) with an
explicitly chosen numeric domain [12]. In all these treatments the verifier is *sound for
safety*: it may reject safe programs, but it does not accept unsafe ones.

Crucially for us, the verifier's abstract domain represents each map's *identity* and *static*
attributes — type, key and value size, `max_entries` — but has **no component for a map's
dynamic occupancy**, the number of live entries. Occupancy is a concrete quantity the analysis
discards. That is the φ we will use.

We distinguish our *abstraction gap* from the well-known eBPF *language–verifier gap* [12],
[14], which describes correct programs that the verifier *rejects* because the compiler and
verifier disagree — a usability problem about false rejections. Our gap is the opposite
direction: an *accepted* program whose semantics the sound verifier cannot see.

## 2.3 Weird machines

The weird-machine framing originates with Bratus and colleagues, who recast exploitation as
programming an unintended machine whose instructions are the target's unexpected state
transitions [5]. Constructive demonstrations followed in exotic substrates — the x86
page-fault handler [6], ELF loader metadata [7], DWARF unwinding — typically establishing
Turing-completeness of an unintended interpreter. On the formal side, Dullien modeled a weird
machine as a finite-state transducer emerging after a state corruption and studied
exploitability and provable unexploitability [9]; Paykin et al. characterized weird machines
as insecure compilation, where an exploit is a target-level behavior no source context can
produce, tied to robust hyperproperty preservation [10]; and Vanegue examined weird machines
in proof-carrying code, observing informally that any abstraction the proof system uses is an
opportunity for uncaptured computation [8], and later gave an under-approximate adversarial
logic for exploitability [11]. Section 8 positions our result precisely against each.

---

# 3. The ⊤-channel: incompleteness made program-visible

We fix a concrete system `C = (Σ, →, In, Out)` with a toolkit Π of constructible operations
(for eBPF, the verifier-accepted instruction set plus map primitives), and a sound abstraction
`A = (𝒜, α, γ, {⟦·⟧#})` that certifies a property `P` (memory safety, bounded termination) and
has top `⊤`.

> **Definition 1 (⊤-channel).** A pair `(op, φ)`, with `op ∈ Π` a constructible operation and
> φ a concrete-state component, is a *⊤-channel* if
> - **(g1)** the concrete transfer of `op` writes a program-visible location `r` with a value
>   that is a *non-constant* function of φ; and
> - **(g2)** the abstract transfer sets `r := ⊤`, and α is constant in φ (φ is unrepresented
>   in 𝒜).

Definition 1 is exactly a witness of α's incompleteness for `op`: by (g1) the concrete result
depends on φ, by (g2) α forgets φ, so `α∘⟦op⟧ ⊐ α∘⟦op⟧∘γ∘α` at any two states differing only
in φ. This is the **condition on the abstraction**. It says nothing yet about programmability;
a `⊤`-channel can exist and be useless if the toolkit cannot observe or drive it (Section 5).

**The eBPF instance.** Let φ be the occupancy `c(G)` of a preallocated, non-LRU hash map `G`
with `max_entries = k`. The map-insert helper `bpf_map_update_elem(G, key, val, BPF_ANY)` for
a fresh key returns `0` and increments `c(G)` when `c(G) < k`, and returns `-E2BIG` leaving
`c(G)` unchanged when `c(G) = k`. So the returned value in register `r0` satisfies
`[r0 = 0] ⇔ c(G) < k` — a non-constant function of occupancy (g1). The helper's return
prototype is `RET_INTEGER`, which the scalar domain models as the top scalar `⊤ = scalar()`;
and 𝒜 has no occupancy component, so α is constant in `c(G)` (g2). The pair
`(op = insert, φ = c(G))` is a `⊤`-channel.

We formalize (g2) as a proposition about the verifier's own transfer function.

> **Proposition 1 (occupancy is quotiented to ⊤).** Let `σ0, σ1` be two pre-states of the
> insert that differ only in `c(G)` — one below capacity, one at capacity. Then (i) their
> abstract images coincide, `α(σ0) = α(σ1)`; (ii) the concrete transfer separates them,
> `⟦op⟧(σ0)(r0) = 0 ≠ -E2BIG = ⟦op⟧(σ1)(r0)`; and (iii) the abstract transfer collapses both,
> `⟦op⟧#(α(σ0))(r0) = ⟦op⟧#(α(σ1))(r0) = ⊤`. Hence `⟦op⟧#` is non-injective on the classes
> that `⟦op⟧` separates: the single bit `[r0 = 0]` that distinguishes the concrete outcomes is
> mapped into one `⊤` cell.

*Proof.* (i) holds because α is constant in `c(G)`; (ii) is the concrete insert semantics with
the chosen occupancies; (iii) is the constant abstract transfer for `RET_INTEGER`. Combining,
`α(σ0)=α(σ1)` forces equal abstract outputs while the concrete outputs disagree on `r0`. ∎

Proposition 1 is machine-checkable against the verifier's trace (Section 6.3): at the branch
that reads `r0`, the verifier reports `r0` as an unbounded scalar and explores both
successors.

---

# 4. A-opacity, pinned to the analysis model

The payload of a `⊤`-channel is not new expressiveness — the verifier already accepts explicit
NAND written with ordinary arithmetic (Section 6.2). The payload is *computation the sound
analysis cannot see*. We name the property precisely, and we are deliberate about *which*
abstract quantity must be `⊤`, because the answer differs between a join-based analyzer and a
path-sensitive one, and a loose statement would be false for the latter.

Let `⟦π⟧#_out` denote the analysis's **certified output abstraction** of program π: the
abstract value the analysis certifies for π's output cell over all reachable executions. For a
**join-based** analyzer that maintains one abstract state per program point,
`⟦π⟧#_out` is literally the value in the output cell at the exit point. For a **path-sensitive**
analyzer (such as the eBPF verifier) that explores paths separately, we define
`⟦π⟧#_out := ⨆_{paths p} out#(p)`, the join over the path-final abstract outputs — i.e. what the
analysis has proved about the output *taking all explored paths together*.

> **Definition 2 (A-opacity).** A program π is *A-opaque* if its concrete output is a
> non-constant function of its inputs, yet `⟦π⟧#_out = ⊤`: the analysis certifies nothing about
> the output value.

Under this definition both analyzer shapes are covered by one statement. For a join-based
interval or tnum analyzer, the output cell is `⊤` outright. For the path-sensitive eBPF
verifier, along each explored path the output bit is a *known* constant (the verifier resolves
`r6` to `0` on one branch and to an unknown non-zero on the other), but the join over paths is
the unknown bit `{0,1}` — and, crucially, this join is `⊤` *independently of any relation the
analysis can express between the inputs and the output*. That last clause is the real content:
A-opacity says the analysis cannot prove `output = f(inputs)` for any non-trivial `f`, because
the reachable output set is all of `{0,1}` at the abstract level regardless of the inputs.

This is the fix to the most dangerous soft spot in a naive account. Writing "`⟦π_f⟧# = ⊤`"
without saying *which* abstraction is `⊤` invites the objection that a path-sensitive verifier
"knows" the output on each path. Definition 2 answers it: opacity is a property of the
*certified* (join-over-paths) output abstraction, which is `⊤` in both models.

> **Proposition 2 (a bare gap is necessary for opacity).** If π is A-opaque then its output
> derivation contains a `⊤`-channel.

*Proof.* The certified output is `⊤` while the concrete output depends on the input. By
soundness each abstract transfer over-approximates its concrete one, so somewhere on the
derivation a transfer produced `⊤` in a cell whose concrete value still depended on the input —
that transfer and that component are a `⊤`-channel. ∎

Proposition 2 is the α-side necessity: no opacity without incompleteness. It does not yet give
programmability, which needs the toolkit.

---

# 5. Exploitability and the Opacity Theorem

A `⊤`-channel becomes a *gate* only if the toolkit can operate it. The following four
conditions are properties of Π — the accepted operations around `op` — not of the abstraction.

> **Definition 3 (exploitable gap).** A `⊤`-channel `(op, φ)` is *exploitable* over `C` if Π
> also provides:
> - **(E1) Observability** — `r` can be branched on, so its `⊤`-value becomes a definite
>   program bit feeding later computation.
> - **(E2) Input-control** — ops apply *input-conditioned* transitions to φ, so the observed
>   predicate realizes a chosen non-trivial Boolean dependence on inputs.
> - **(E3) Resettability** — an op restores φ to a known value, making the channel a *pure*
>   function re-evaluable per invocation.
> - **(E4) Composability** — arbitrarily many mutually non-interfering instances `(opₖ, φₖ)`
>   are allocatable, so one instance's output (E1) can drive another's input (E2).

> **Definition 4 (induced gate).** Under (E1)–(E4) the *gate* of the exploitable gap is the
> Boolean function `g(x₁,…,xₙ)` obtained by resetting φ, applying the input-conditioned
> transitions, and observing the readout.

> **Theorem 1 (Opacity Theorem).** Suppose `(C, A)` admits an exploitable gap whose induced
> gate `g` is functionally complete together with the freely available represented operations
> (negation, constants, wiring). Then for every Boolean function `f : {0,1}ⁿ → {0,1}` there is
> a program `π_f ∈ Π` such that (1) `π_f` computes `f`, and (2) `π_f` is A-opaque: its whole
> input-to-output dependence factors through `⊤`-channel operations, so `⟦π_f⟧#_out = ⊤`.

*Proof.* Functional completeness of `g` yields a circuit for `f`. Realize the circuit by
**time-multiplexing** a bounded set of physical gate instances: evaluate the circuit's gates
in topological order; for each gate, reset its instance (E3), apply the input-conditioned
transitions from the wire values (E2), observe the readout (E1), and store the resulting bit
to a wire cell; reuse instances across gates and use independent instances only where two
gates are live simultaneously (E4). A statically bounded number of instances and wire cells
suffices for any fixed circuit. For opacity, maintain the invariant "every wire cell is
`⊤`-derived": the base case is Definition 1(g2); (E2) feeds a `⊤`-derived bit forward as a
`⊤`-derived input, so by induction on circuit depth the certified output abstraction is `⊤`.
Correctness (1) is the gate truth table lifted along the circuit; opacity (2) is the invariant.
∎

Two consequences of the construction are worth stating. First, because the circuit is realized
by time-multiplexing a *statically bounded* number of instances and wire cells, the result is
**combinational and bounded, not Turing-complete**: unbounded opaque memory would require a
resettable store the verifier's termination check forbids. Second, the number of physical gate
instances need not equal the number of gates in the circuit — a point that a reader who counts
"nine maps" in the eBPF witness (Section 6) must not mistake for a nine-gate ceiling.

**Scope of the theorem.** Theorem 1 is a sufficiency theorem for a precise sub-notion of
"weird machine": bounded, verifier-opaque programmable computation. Proposition 2 gives a weak
necessity statement for opacity itself — some abstractly erased, program-visible dependence must
appear in the output derivation — but the full E1–E4 package is a construction discipline, not an
intrinsic characterization of all weird machines. In particular, E3 and E4 are the conditions we
use to upgrade one opaque gate into arbitrary bounded circuits; we do not claim that every weird
machine must have resettable, composable gate instances. This distinction is what keeps the result
from becoming the overbroad slogan "gap implies weird machine." Section 9 returns to the harder,
open problem of structural boundary conditions.

---

# 6. The eBPF witness

We discharge every clause of Definition 3 and Theorem 1 in a program the in-kernel verifier
accepts. The program is a `SEC("syscall")` eBPF program run offline via
`bpf_prog_test_run_opts()`; it uses only legal helper calls and bounded loops; it performs no
out-of-bounds access, no verifier bypass, and no privilege escalation beyond the `CAP_BPF`
required to load any eBPF program.

## 6.1 The capacity-saturation NAND

The gate uses one hash map `G` with `max_entries = 2`, preloaded with a sentinel entry.
Encoding inputs `a, b ∈ {0,1}`, the construction inserts, for each input, a key selected
*branchlessly* by `key = base + delta · bit`, then probes capacity with a third insert. With
the sentinel occupying one slot, the map is full exactly when both inputs contributed a
distinct new key — i.e. when `a = b = 1`. The third insert therefore returns `-E2BIG` iff
`a ∧ b`, and the output bit is `[r0 = 0] = ¬(a ∧ b) = NAND(a, b)`. Formally the gate is
`g(a,b) = ¬[ 1 + a + b > 2 ]`, the sentinel supplying the `1` and `max_entries = 2` the
threshold. NAND is functionally complete, satisfying the hypothesis of Theorem 1.

The post-verifier (xlated) instruction stream confirms that **no instruction combines `a` and
`b` arithmetically**: the inputs appear only in the branchless key selection that decides
*which* key each insert targets, and the stored truth value is decided solely by a single
`if r6 == 0` on the third insert's return code (repository Appendix A.7). The computation is in
the map metadata, not in the bytecode.

## 6.2 Contrast: an explicit-logic baseline the verifier accepts identically

A baseline variant computes the same truth table with ordinary arithmetic: two comparisons
negate the inputs and an `OR` combines them into `¬a ∨ ¬b = ¬(a∧b)` by De Morgan. This
baseline is *also* verifier-accepted and produces an identical 400/400 truth table, but its
NAND is legible in the bytecode (repository Appendix A.8). The verifier sees two safe, bounded
programs with identical I/O; only the baseline's logic is visible to it. This is the point of
the paper in one comparison: the gap is not about *what* can be computed but about *what the
sound analysis can see*.

## 6.3 Discharging the clauses

| Clause | eBPF realization | Evidence |
|---|---|---|
| `C`, `A` | BPF machine; in-kernel verifier (sound abstract interp.) | `results/verifier.log`, `env.json` |
| `⊤`-channel (g1,g2) | φ = occupancy `c(G)`; `op` = insert; `r0 := ⊤` | Prop. 1; verifier log insn 78/79 |
| E1 observability | `if r6 == 0` decides the output bit | xlated insn 122 |
| E2 input-control | `key = base + delta·bit` ⇒ φ = `1+a+b`; readout `[φ>2]` | xlated insn 66–68 / 79–81 |
| E3 resettability | `bpf_map_delete_elem` restores `c(G)` | xlated insn 44 / 49 / 54 |
| E4 composability | independent maps `G0..G8`; time-multiplexed | `full_adder.jsonl` |
| gate `g` = NAND (complete) | 32-bit adder checked over all 8-bit operand pairs | `adder32_exhaustive.jsonl` |
| opacity | verifier forks at output branch; both truth values reachable | verifier log 104 (both successors) |

The machine-checkable heart is the last row. Verbatim from the verifier log, the third insert
returns a top scalar, that scalar flows into the output register, and at the output branch the
verifier cannot resolve the guard and explores both successors — so both truth values are
abstractly reachable regardless of the inputs. That is Proposition 1 and Definition 2 realized
in the verifier's own trace.

---

# 7. Evaluation

**Exhaustiveness.** The NAND gate is verified exhaustively over its truth table (400/400
including repetitions of the four input combinations), and a full adder built from the gate is
exhaustive (8/8). The file `adder32_exhaustive.jsonl` checks the 32-bit adder over every pair of
8-bit operands (65536/65536), validating the low 32-bit sum on that complete subdomain; it is not
a proof over the full 32-bit input space. Full-width 32-bit addition is checked on 1005 fixed
cases (five corner cases plus 1000 fixed-seed random pairs) and is reported as sampled, not
exhaustive.

**Mechanism attribution by ablation.** Two ablations isolate the cause. Raising the capacity to
`GATE_CAP = 64` removes saturation and collapses NAND to the constant 1 (400/400). Forcing the
second input to reuse the sentinel key (`WM_FORCE_SENTINEL_B`) removes the distinct-key
insertion and likewise collapses the gate. Each ablation compiles to a *distinct* object, and
every result set is bound to the exact binary that produced it by an object hash recorded in a
per-variant provenance file. The four variants — weird machine, two ablations, and the explicit
baseline — are all verifier-accepted (`loadall_exit = 0`).

**Independent audit.** An oracle re-derives every expected truth table and sum independently of
the harness's own pass flag, and asserts full input coverage; the aggregate re-check reports
68149/68149 and a passing semantic audit. All artifacts are regenerated by a single command and
re-checked by another.

**Second witness — an independent, join-based analyzer.** To test whether the phenomenon tracks
sound-but-incomplete abstraction rather than an eBPF idiosyncrasy, we reproduce it in a
structurally different `(C, A)`: a numeric program whose gate is `NAND(a,b) = [(1+a+b) mod 3 ≠ 0]`,
analyzed by a **sound, non-relational, join-based interval domain**. The channel `φ` is now the
congruence `acc mod 3` — unrepresented by intervals — in place of hash-map occupancy. We run it
through two independent realizations of that domain: a self-contained reference interval
interpreter (exhaustive over the inputs, with every abstract transfer checked at runtime to
over-approximate the concrete output), and **Frama-C's EVA value analysis, v25.0 — a production
analyzer we did not write** [18]. Both agree. For the working gate the analyzer's certified value
for the output is the full Boolean range `{0,1} = ⊤`: it proves nothing about the output bit
though it depends on the inputs (A-opacity, Definition 2). Because the domain is join-based, this
`⊤` is a *single top value* — `⟦π⟧#_out = ⊤` holds literally, with none of the path-sensitivity
qualification the eBPF verifier needs. Crucially, the **same** analyzer certifies the modulus-7
ablation as the singleton `{1}` (the gate degenerates to a constant): the blindness is *localized*
to the incomplete `mod` operation, not a blanket weakness, showing that the blindness is localized to the abstract domain's treatment of `mod`, not to the whole analysis. EVA reports `acc ∈ {1,2,3}` and raises zero alarms, so the
result is not an artifact of imprecision elsewhere. Composed gates (AND, XOR) keep the output at
`⊤` while the number of channel uses grows, and an input-partitioned (disjunctive) refinement
certifies the output per input — the same channel-composition and precision-repair pattern observed in a real tool.

| | analyzer | style | channel `φ` | certified output |
|---|---|---|---|---|
| eBPF witness (§6) | Linux verifier | path-sensitive | map occupancy | `⊤` (join over paths) |
| second witness | interval domain / Frama-C EVA | **join-based** | `acc mod 3` | `out ∈ {0,1} = ⊤` |

Two structurally different sound analyzers thus exhibit the same opacity pattern — the
system-independence the abstraction-gap thesis predicts. The full
construction, the runnable reference analyzer, and the verbatim EVA log are in the artifact.

**Threats to validity.** The eBPF evidence is from one kernel (6.17.0, aarch64). Hash-map internals
and verifier behavior can drift across kernel versions and architectures; in particular, the
`-E2BIG`-at-capacity mechanism should be confirmed against the exact map type (preallocated,
non-LRU) and single-CPU offline execution, since preallocated hash maps reserve per-CPU spare
elements that can perturb the capacity threshold under concurrency. The exhaustive truth tables
establish that the mechanism holds as described on the tested configuration; portability across
eBPF kernels and architectures remains future work. The demand for a second, structurally
different analyzer is discharged by the join-based witness above.

---

# 8. Related work

**Weird machines: informal and constructive.** Bratus et al. introduced the weird-machine frame
as a way to see exploitation as programming an unintended machine [5]; constructive
demonstrations established Turing-complete computation in unintended substrates such as the
page-fault handler [6] and ELF metadata [7]. These works answer *what can be computed* in a
substrate not meant to compute, typically after or around a defect. Our witness differs on two
axes: the substrate is a *verifier-accepted* program with no defect, and the property we
establish is not Turing-completeness but *invisibility to a sound analysis* of a bounded
computation.

**Other substrates and later variants.** Subsequent work broadens the catalog of weird-machine
substrates and patterns. Bratus et al. describe recurring weird-machine patterns across systems
[19], while Anantharaman et al. use *mismorphism* to name the semantic mismatch at the heart of
the phenomenon [20]. More recent systems work moves the hidden machine into microarchitectural
state: Evtyushkin et al. show computation with timing and microarchitectural state [21], and
Wang et al. study weird machines in transient execution [22]. Levy and Maldonado use the weird
machine lens for attack-surface measurement [23]. These papers reinforce that hidden or
under-specified state is a recurring substrate; our contribution is to isolate the analogous
substrate in a verifier abstraction and to give a verifier-success, non-CVE construction.

**Weird machines: formal.** Dullien models a weird machine as a transducer that emerges after a
state corruption and formalizes *exploitability* — reachability of an attacker goal state — and
its negation, provable unexploitability [9]. Our property is orthogonal: *opacity* is about what
a sound analysis can see, not about reaching a goal state, and our machine presupposes no
corruption. Paykin et al. cast weird machines as *insecure compilation*: an exploit is a
target-context behavior no source context can produce, and a compiler is exploit-free iff it
preserves robust hyperproperties [10]. The abstraction they invoke is the *source language's*;
ours is the *analyzer's abstract domain*. Both are "computation that violates an abstraction,"
but the abstraction is a different mathematical object, and ours requires no compiler pair.

**The closest prior art.** Vanegue's study of weird machines in proof-carrying code is the
nearest antecedent: it observes, informally and taxonomically, that when a proof system's
abstraction fails to capture untrusted computation a "shadow execution" arises, and names the
machine abstraction as one such opportunity [8]. We regard our contribution as the
formalization of exactly this observation: we turn "any used abstraction is an opportunity for
uncaptured computation" into (i) a machine-checkable proposition about the analyzer's transfer
function (Prop. 1), (ii) a conditional theorem with the α-side and Π-side conditions separated
(Thm. 1), and (iii) a discharged instance in a production verifier (Section 6). Vanegue's later
adversarial logic gives an under-approximate proof system for exploitability [11]; it is
complementary to ours, which concerns the *sound over-approximate* analysis's blind spot rather
than the discovery of true attack paths.

**Completeness in abstract interpretation.** Our reframing rests on the theory of completeness:
Giacobazzi, Ranzato, and Scozzari characterize when an abstraction is complete for an operation
and construct the complete shell and core [2]; Bruni et al. localize completeness to fragments
and build a logic that reasons about correctness and incorrectness together [3], with follow-up
work quantifying partial incompleteness [4]. To our knowledge, no prior work connects the
weird-machine phenomenon to this theory constructively. Doing so is what lets us state the
open problem of Section 9 in an established language.

**eBPF verification.** The eBPF verifier and its abstract domains have been formalized and, in
part, proved sound: PREVAIL uses abstract interpretation with a chosen numeric domain [12], and
the tnum domain used in the kernel has a machine-checked soundness proof [13]. This line is
about proving the verifier *correct*. Our result is compatible with and depends on that
correctness: the verifier is sound, and the weird machine lives in its *designed
incompleteness*, not in any unsound step.

---

# 9. Outlook: from witnesses to a structural theorem

The Opacity Theorem in Section 5 is already a theorem, but it is conditional: it assumes an
*exploitable gap*. In this paper that hypothesis is established constructively, first in eBPF and
then in a structurally different interval-analysis witness. The foundational target is stronger:
turn the statement "an abstraction-layer gap yields a programmable weird machine" into a theorem
with explicit boundary conditions. We do **not** claim to have completed that step here.

The open problem has two halves.

## 9.1 Which abstractions necessarily admit a channel?

The abstraction-side question is naturally a completeness question. In the terminology of
abstract interpretation, a `⊤`-channel appears when an operation's concrete result depends on a
state component that the abstraction `α` quotients away. This resembles failure of completeness:
`α` is sound for the safety property it certifies, but incomplete for the operation whose result
is later observed by the program. The mature theory of complete shells, complete cores, and local
completeness [2], [3], [4], [17] is therefore the right mathematical setting for the next step.

A plausible theorem would characterize a class of sound abstractions and toolkits such that:

1. `α` erases a concrete residual component `φ`;
2. some program-constructible operation `op` has an output whose concrete value is non-constant
   across an `α`-fiber varying only in `φ`;
3. the abstract transfer for `op` must over-approximate those concrete outcomes by a top or
   top-like value at a program-visible location; and
4. the program can route that location into later computation.

The eBPF map-occupancy witness instantiates this shape with `φ = c(G)` and `op =
bpf_map_update_elem`; the interval witness instantiates it with a congruence component erased by
intervals. What remains is to state the class of abstractions for which this implication is not
just observed by instance but guaranteed by the structure of `α` and `op`.

## 9.2 When is the channel exploitable?

A bare channel is not yet a weird machine. It becomes programmable only when the toolkit can
observe it, drive it with inputs, reset the underlying state, and compose independent uses. In a
closed offline experiment, such as `BPF_PROG_TEST_RUN` with private maps, uncontrolled state is
minimal; in a live system, scheduling, concurrency, shared maps, allocator state, or unrelated
writers can perturb the residual component. A future theorem therefore needs a reliability
condition, not merely reachability.

Robust reachability [15], [16] is a promising language for this half of the problem: it asks
whether a controlled choice reaches the desired branch for all uncontrolled choices. For this
paper we use the simpler, empirical discipline: isolate the channel, reset it before each gate,
use private instances for composition, and validate the truth table exhaustively on the relevant
finite domains. A full exploitability theorem would connect E1--E4 to a robust-reachability
condition over the controlled/uncontrolled split of the host system.

## 9.3 Why the second witness matters

The second witness is a down-payment on generality. It is deliberately unlike the eBPF witness:
its analyzer is join-based rather than path-sensitive, its residual state is a congruence rather
than map occupancy, and its substrate is numeric arithmetic rather than kernel helper metadata.
Yet the same pattern appears: the concrete program computes through state that the sound
abstraction does not represent, and the certified output abstraction is top. This supports the
hypothesis that the phenomenon tracks sound-but-incomplete abstraction, not an eBPF-specific
quirk.

Still, two witnesses are not a structural theorem. The durable contribution we target next is a
framework in which one can read off, from `(α, Π)`, whether a program-constructible `⊤`-channel
must arise and whether it is necessarily exploitable. The present paper supplies the formal
vocabulary, the conditional theorem, and the first production-verifier witness; the complete
boundary characterization remains future work.

# 10. Limitations

The eBPF evidence is from one kernel and architecture, so portability across kernel versions,
map implementations, and architectures remains to be established. Section 7 supplies a second
analyzer witness, including Frama-C EVA, but that witness is empirical support rather than a
complete structural characterization of all sound abstractions. The Opacity Theorem characterizes
a precise sub-notion, opaque *programmable* computation, not weird machines in general; E3 and E4
are construction conditions for bounded circuits, not claimed necessary features of every weird
machine. The result is deliberately bounded and combinational, not Turing-complete. Finally, the
boundary-condition theorem sketched in Section 9 remains future work: deciding when an arbitrary
`(α, Π)` pair necessarily admits an exploitable `⊤`-channel is a richer problem than this paper
solves.

# 11. Conclusion

Weird machines are usually paid for with a bug. We showed they can also be paid for with
soundness: a verifier that is correct about safety and, by design, silent about semantics hosts
a programmable computation it cannot see, with no vulnerability involved. The condition splits
cleanly into incompleteness of the abstraction and expressibility of the toolkit, and when the
induced gate is functionally complete the invisible computation extends to arbitrary bounded
circuits. Our eBPF witness makes this concrete and machine-checkable in a production verifier,
and the completeness-theoretic framing turns the phenomenon from a single instance into a
boundary-condition research program that other sound analyzers can be tested against. The gap is not a
bug to be fixed; it is the shape of soundness itself, and it is programmable.

---

## Ethics and disclosure

**Ethics.** All experiments run in an isolated local VM. The artifact attaches no program to a
live network path, targets no third-party system, and attempts no privilege escalation, memory
corruption, or verifier bypass. It uses legal helper calls and bounded execution to study the
gap between verifier-level abstractions and runtime map-metadata transitions. The work is
defensive in orientation: it characterizes a structural blind spot of sound verifiers so that
analyzer designers can reason about it.

**Data availability.** All code, build variants, per-variant provenance, verifier logs, xlated
disassembly, and exhaustive result datasets are in the accompanying repository and are
regenerated by a single command.

**AI-usage disclosure.** This draft was prepared with the assistance of an AI writing pipeline
for structuring, drafting, and literature positioning; all technical claims, the artifact, and
the formal statements originate with the authors, and all citations were checked to correspond
to real works. Final bibliographic metadata should be verified against the publisher records
before submission.

**Conflicts of interest.** None declared.

---

## References

[1] P. Cousot and R. Cousot, "Abstract interpretation: a unified lattice model for static
analysis of programs by construction or approximation of fixpoints," in *POPL*, 1977.

[2] R. Giacobazzi, F. Ranzato, and F. Scozzari, "Making abstract interpretations complete,"
*Journal of the ACM*, vol. 47, no. 2, pp. 361–416, 2000.

[3] R. Bruni, R. Giacobazzi, R. Gori, and F. Ranzato, "A logic for locally complete abstract
interpretations," in *LICS*, 2021 (Distinguished Paper).

[4] R. Bruni, R. Giacobazzi, R. Gori, and F. Ranzato, "Partial (in)completeness in abstract
interpretation: limiting the imprecision in program analysis," *Proc. ACM Program. Lang.*, vol. 6,
no. POPL, 2022.

[5] S. Bratus, M. E. Locasto, M. L. Patterson, L. Sassaman, and A. Shubina, "Exploit
programming: from buffer overflows to weird machines and theory of computation," *USENIX
;login:*, 2011.

[6] J. Bangert, S. Bratus, R. Shapiro, and S. W. Smith, "The page-fault weird machine: lessons
in instruction-less computation," in *USENIX WOOT*, 2013.

[7] R. Shapiro, S. Bratus, and S. W. Smith, "'Weird machines' in ELF: a spotlight on the
underappreciated metadata," in *USENIX WOOT*, 2013.

[8] J. Vanegue, "The weird machines in proof-carrying code," in *IEEE Security and Privacy
Workshops (LangSec)*, 2014, doi:10.1109/SPW.2014.37.

[9] T. Dullien, "Weird machines, exploitability, and provable unexploitability," *IEEE
Transactions on Emerging Topics in Computing*, vol. 8, no. 2, pp. 391–403, 2020,
doi:10.1109/TETC.2017.2785299.

[10] J. Paykin, E. Mertens, M. Tullsen, L. Maurer, B. Razet, A. Bakst, and S. Moore, "Weird
machines as insecure compilation," *arXiv:1911.00157*, 2019.

[11] J. Vanegue, "Adversarial logic," in *Static Analysis Symposium (SAS)*, LNCS 13790, 2022,
doi:10.1007/978-3-031-22308-2_19.

[12] E. Gershuni et al., "Simple and precise static analysis of untrusted Linux kernel
extensions," in *PLDI*, 2019.

[13] H. Vishwanathan, M. Shachnai, S. Narayana, and S. Nagarakatte, "Sound, precise, and fast
abstract interpretation with tristate numbers," in *CGO*, 2022, arXiv:2105.05398.

[14] (Survey) "The eBPF runtime in the Linux kernel," *arXiv:2410.00026*, 2024.

[15] G. Girol, B. Farinier, and S. Bardin, "Not all bugs are created equal, but robust
reachability can tell the difference," in *CAV*, 2021.

[16] Y. Sellami, G. Girol, and S. Bardin, "Inference of robust reachability constraints," *Proc.
ACM Program. Lang.*, vol. 8, no. POPL, pp. 2731–2760, 2024.

[17] M. Campion, C. Urban, M. Dalla Preda, and R. Giacobazzi, "A formal framework to measure the
incompleteness of abstract interpretations," in *SAS*, LNCS 14284, pp. 114–138, 2023,
doi:10.1007/978-3-031-44245-2_7.



[18] F. Kirchner, N. Kosmatov, V. Prevosto, J. Signoles, and B. Yakobowski, "Frama-C: A software
analysis perspective," *Formal Aspects of Computing*, vol. 27, no. 3, pp. 573–609, 2015. (EVA
value-analysis plug-in.)

[19] S. Bratus et al., "'Weird machine' patterns," in *Software Engineering for Resilient
Systems*, LNCS 8166, 2014, doi:10.1007/978-3-319-04447-7_13.

[20] P. Anantharaman et al., "Mismorphism: The heart of the weird machine," in *Foundations and
Practice of Security*, LNCS 12056, 2020, doi:10.1007/978-3-030-57043-9_11.

[21] D. Evtyushkin et al., "Computing with time: microarchitectural weird machines," in *ASPLOS
Workshop on Hardware and Architectural Support for Security and Privacy*, 2021,
doi:10.1145/3445814.3446729.

[22] P.-L. Wang, F. Brown, and R. S. Wahby, "The ghost is the machine: Weird machines in
transient execution," in *IEEE Security and Privacy Workshops*, 2023,
doi:10.1109/SPW59333.2023.00029.

[23] M. L. Levy and F. Maldonado, "Attack surface measurement: A weird machines perspective,"
in *Cyber Security Experimentation and Test Workshop*, 2024, doi:10.1145/3655693.3655705.
