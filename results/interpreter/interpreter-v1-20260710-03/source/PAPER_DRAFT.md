# After Acceptance: A Bounded Residual-Circuit Interpreter at a Verifier–Runtime Boundary

# Abstract

Language-theoretic security (LangSec) asks whether a boundary recognizes the language that
downstream machinery actually interprets. LangSec has long observed that input validation and
program verification have the same interpreter-shaped structure. Building on that established
observation, we study its post-acceptance consequences at a program-verifier boundary. A verifier
recognizes an artifact language `L_V`, but an accepted artifact can induce an ordinary language
`W_run(P)` of documented, stateful runtime operations. Relative to a declared observation contract
`K_res` (projection, observer, dependency slice, and environment discipline), we retain the words
whose observations causally depend on the residual projection in a *recognizer-relative residual
language* `L_res(V,I;K_res)` and record their concrete input/output distinctions in a residual observation
relation. These objects are not unrecognized program artifacts and are not set differences from
`L_V`; they are downstream languages induced by accepted artifacts.

The formal model separates safety recognition, computed report coverage, semantic precision, and
standard abstract-interpretation completeness. It also separates two explanations for a boundary
gap. A defect-induced gap depends on an implementation violating its declared contract. A
*contract-shape-induced* gap, by contrast, uses only behavior permitted by the declared concrete
semantics and safety contract while a selected report fails to factor a program-visible
observation. This classification is relative to a fixed contract and report interface: refining
that interface or restricting the runtime may remove the gap. Soundness or incompleteness alone
does not force a residual machine; forgotten state may be unreachable, dead, unobservable, or
uncontrollable. We therefore prove sufficient, resource-bounded realization conditions rather
than a universal necessity claim. A separate conditional certificate-opacity theorem requires a
defined report vocabulary, sound extractors, graph expressibility, and a persistent alternate
model through the complete schedule. A residual transducer is classified as a weird machine only
after an intended policy and threat model exclude its attacker-controlled behavior.

The source-snapshotted Linux/aarch64 run
`results/interpreter/interpreter-v1-20260710-02/` passed its independent semantic audit and
self-issued SHA-256 integrity check. It records 37,507 JSONL rows: 25,464 per-gate traces,
12,035 successful run records, and eight malformed-core controls. A fixed eBPF artifact `P_U`
implements NAND by saturating one dedicated two-entry hash map and branching on the second
update's success predicate. A host parser translates a textual WMC1 bundle into
normalized core-gate, input, and control map cells; `P_U` reads those cells, not textual WMC1,
and host code projects selected outputs only after a successful status. Under mutual exclusion
over the complete shared map set, the interpreter serially reuses the residual gate. The recorded
suite covers named-circuit truth tables, a fixed-seed random corpus, a 512-gate chain, a zero-gate
boundary, serial alternating-invocation regression, and mechanism controls. The
capacity-dependent helper behavior supplies the key nonlinearity; ordinary bytecode still
performs descriptor dispatch, routing, and storage. The Linux verifier log is used only as a
local scalar-unresolved observation under an explicit diagnostic interpretation, not as a
machine-extracted joined report cell. This is not proof that all sound-but-incomplete recognizers
host such a machine. The interval-analysis experiment is only a precision control. The work does
not claim a Linux verifier bug, an artifact-parametric eBPF compiler, unbounded universality or
Turing completeness, whole-program Linux certificate opacity, privilege escalation, or a
demonstrated security-policy violation.

**Keywords:** language-theoretic security, residual languages, program verification, recognition
contracts, policy-relative weird-machine classification, abstract interpretation, eBPF.

---

# 1. Introduction

Language-theoretic security (LangSec) treats security boundaries as language boundaries: an
input processor should recognize a well-defined language before downstream computation acts on
it [24]-[27]. LangSec already observes that software processing input is an interpreter, that
input data acts as its program, and that input validation is therefore structurally analogous to
program verification. Our novelty claim is not that analogy. We ask the next operational
question at a program-verifier boundary: after a verifier recognizes an artifact language, what
tagged operation language does the concrete runtime still interpret on behalf of accepted
artifacts?

This paper studies that question under an explicit safety-soundness assumption. Safe recognition
is not full semantic certification. A verifier may certify memory safety, bounded execution, and
well-typed helper use while omitting concrete runtime state that accepted programs can observe,
reset, and compose. When documented operations expose such state, they can form a program-visible
residual transducer without any verifier implementation defect. We call the resulting gap
*contract-shape-induced* relative to the declared safety and report contract. The qualifier is
important: a richer report, a restricted runtime, or a different boundary contract can remove
the gap. Calling the transducer a *weird machine* requires a further policy judgment; ordinary
use of an API that the verifier never promised to summarize is not itself a security violation.

For each accepted artifact `P`, our central concrete objects are a **residual word language**
`W_res(P;K_res)` and a **residual observation relation** `R_res(P;K_res)`. Their tagged union defines the
boundary-level residual language
`L_res(V,I;K_res) = { (P,ell,w) | P in L_V and w in W_res^ell(P;K_res) }`, where
`K_res` fixes the residual projection, observer, dependency slice, and environment discipline.
We write `L_res(V,I)` only after fixing that contract. This dependent typing matters:
`L_V` contains program artifacts, `W_res(P;K_res)` contains runtime operation words, and `R_res(P;K_res)`
contains execution tuples. `L_res(V,I)` does not mean `Sem(I) \ L_V`, because those sets do not
share a carrier. A verifier-local uncertainty tag is added only when a computed report cell
jointly covers a causal pair and its post-report cannot decide the readout. This report-precision
fact does not by itself establish standard abstract-interpretation incompleteness.

This reframing also limits the role of eBPF. The production Linux verifier gates bytecode into the
kernel with a path-sensitive abstract analysis. PREVAIL is a separate verified analyzer, not a
proof of the production verifier, and the tnum work proves properties of an important abstract
domain rather than end-to-end soundness of a particular Linux release [12], [13]. Accordingly,
our formal safety result is conditional on a stated soundness premise. The artifact itself shows
that the submitted programs are accepted and bounded and that dynamic hash-map occupancy affects
a helper return. The retained verifier log supplies a local scalar-return observation, not a
defined `Report_V` cell or an extractor proof that the concrete executions are jointly covered.
It does not use that observation to make a universal soundness claim about Linux.

## 1.1 Defect-induced and contract-shape-induced gaps

A conventional weird machine is often presented as the residue of a defect: a malformed input,
parser differential, memory-corrupting input, or metadata quirk drives an implementation into an
unintended state space [5]-[7], [9], [10]. That is a *defect-induced* explanation when the
implementation departs from its declared recognition or runtime contract. A
*contract-shape-induced* explanation instead holds the documented runtime semantics and declared
safety property fixed, then asks whether the selected report factors every program-visible
observation that accepted code can drive. Map occupancy, capacity failure, and helper return
codes are documented eBPF semantics, so our witness uses the second explanation.

The term is descriptive: it denotes report-relative non-factorization under documented semantics,
not breach of the declared safety contract.

This terminology attributes a gap relative to a boundary contract; it does not make the gap
immutable. Tracking occupancy, using a relational certificate, or forbidding the stateful helper
would change the relevant shape. We therefore use a two-stage classification. A *residual
transducer* is a technical property of accepted executions. A *recognizer-relative weird
machine* additionally requires a declared intended policy `M`, threat model `T`, actor control,
and a security-relevant behavior excluded by `M`. The offline artifact supplies the first stage,
not the second.

## 1.2 From residual languages to programmable machines

An abstraction gap alone is not enough. A sound recognizer may reject some safe programs yet
fully characterize every accepted program; an abstract domain may also forget only unreachable,
dead, unobservable, or uncontrollable state. None of these cases hosts a residual machine.
Vanegue identifies shadow computation outside a proof-carrying-code abstraction [8], Paykin et
al. make the source/target policy boundary explicit through insecure compilation [10], and Palmer
et al. reconstruct stateful operation languages at low-level interfaces [32]. Building on those
observations, we make the verifier/runtime carriers and the following operational obligations
explicit rather than claiming priority for the general input-as-program analogy:

- A **recognizer-side condition**: a concrete operation depends on suffix-relevant runtime state,
  two corresponding executions are covered by one analyzer-computed frontier, and the computed
  report cannot decide the program-visible readout predicate. This marks a residual observation
  as verifier-unresolved; it does not equate a joined state with singleton abstraction.

- A **toolkit-side condition**: accepted operations can control, observe, reset, and compose the
  residual state so that it behaves as a reusable transducer basis.

Given both sides, an accepted uniform dispatcher, and functional completeness of the induced gate,
a fixed accepted interpreter can realize an independently declared bounded *host-configuration*
domain at runtime. This is data-parametric realization: the verifier accepts the interpreter once,
whereas the circuit is host-supplied map configuration, not another member of `L_V` or a runtime
word by itself. It does not quantify beyond the stated input, wire, and gate bounds, nor does it
establish an artifact-parametric compiler that emits a separate accepted BPF object per circuit.
Global report opacity needs more: a precise report vocabulary, a sound extractor, graph
expressibility, and a persistent alternate model through the complete schedule. Local branch
uncertainty alone is insufficient because relational composition can eliminate local spurious
alternatives.

## 1.3 Contributions

1. **A LangSec model of verifier-runtime boundaries.** We define the tagged residual language
   `L_res(V,I;K_res)`, artifact-indexed word languages, and causally isolated observation relations,
   keeping their carriers distinct from the artifact language `L_V`.

2. **A defect/shape distinction with explicit limits.** We classify a residual observation as
   contract-shape-induced only relative to documented runtime semantics and a fixed recognition
   contract. We give counterexamples to the blanket claim that soundness or incompleteness alone
   forces a weird machine.

3. **Operational sufficiency, not unqualified necessity.** We identify the recognizer-side and
   toolkit-side conditions under which a residual language yields a reusable gate, define bounded
   data-parametric realization for one accepted interpreter and an independently declared circuit
   language, and state the additional policy condition for a recognizer-relative weird machine. A
   separate theorem identifies the whole-program evidence needed for certificate opacity.

4. **A production-verifier eBPF witness.** We implement `P_U`, a bounded residual-circuit
   interpreter using map occupancy and helper success/failure. Its WMC1 encoder, independent
   oracle, fail-closed core-map checks, per-gate helper traces, randomized DAG corpus, boundary
   chain, and mechanism-removing ablations are regenerated from one source snapshot and checked
   by a self-issued SHA-256 integrity manifest. The witness does not depend on a verifier bug,
   corruption, or privilege escalation.

5. **A precision taxonomy.** We separate verifier-unresolved observations, relational
   certificate opacity, and standard abstract-interpretation completeness [2]-[4], [17]. The
   Linux artifact provides paired-run and local-log evidence relevant to the first only under the
   explicitly stated `Report_log` interpretation; the second is conditional; the third is claimed
   only when a concrete strict-inequality witness is shown.

Scope matters. This paper does not claim that eBPF is newly computationally expressive, that the
production Linux verifier has an end-to-end machine-checked soundness proof, that a CVE exists,
or that every sound-but-incomplete recognizer necessarily hosts a weird machine. The empirical
claim is configuration- and report-specific. The realization theorem ranges only over one accepted
interpreter and a declared bounded host-to-map configuration ABI; it is not an acceptance theorem
for a family of generated BPF artifacts. The global certificate result is not asserted for Linux
without a report-theory extractor and persistent-alternative check. Section 9 formulates a
qualified shape-theorem conjecture schema as future work and explains why complete shells and
Rice-style undecidability cannot, by themselves, supply the missing operational premises.

# 2. From LangSec Recognition to Verifier–Runtime Boundaries

## 2.1 Language boundaries and recognizers

LangSec views insecurity as a failure to recognize the language actually consumed by a system:
input processors should accept a precise language, reject inputs outside it, and ensure later
computation operates only on recognized structure [24]-[26]. We use *recognizer* broadly. A
recognizer may be a parser for a file format, a validator for a protocol message, or a verifier
for program artifacts. In each case, it defines an accepted language and a boundary between what
has been recognized and what downstream machinery may still interpret.

For program verifiers, the recognized language is property-specific. A verifier can soundly
recognize a safety language without recognizing every semantic distinction the concrete runtime
will later interpret. This paper studies exactly that case: safety recognition succeeds, while
accepted execution exposes a residual operation-word interface outside the selected report.

## 2.2 Abstract interpretation, soundness, and completeness

An abstract interpreter approximates a concrete transition system over states `Σ`. For an
operation `op`, write its collecting concrete transformer as `T_op : P(Σ) -> P(Σ)` and its
abstract transformer as `T#_op : A -> A`, connected by a Galois connection
`(α : P(Σ) -> A, γ : A -> P(Σ))` [1]. **Transfer soundness** requires each abstract transfer to
over-approximate its concrete counterpart:

`α(T_op(X)) <= T#_op(α(X))` for all `X subseteq Σ`.

This equation concerns the abstract transfer, not the whole verifier's acceptance judgment.
Safety soundness is a separate property: for a declared concrete trace property `Safe`, it is the
implication `V(P)=accept => Tr_I(P) subseteq Safe`. Both properties are explicit assumptions in
Section 3. We do not infer either from the fact that a program loaded successfully.

A second distinction is equally important. The best abstraction `α({σ})` of a singleton is not
the analyzer-computed state `a#_ell` at a control frontier. The latter can be a join that covers
many concrete states: `Reach_I(P,ell) subseteq γ(a#_ell)`. Concrete values 0 and 1 may therefore
have distinct singleton abstractions while both belong to the concretization of the same computed
state. Our definitions use computed coverage, not singleton equality.

**Completeness** asks whether the abstraction loses no information relevant to an operation:

`α(T_op(X)) = α(T_op(γ(α(X))))` for all `X subseteq Σ` [2].

Giacobazzi, Ranzato, and Scozzari showed that completeness is a property of the abstraction and
the operation together, and gave constructive characterizations of complete shells and cores [2].
Later work localized and quantified incompleteness [3], [4], [17]. An analyzer's inability to
decide a predicate does not imply that this equation fails: the one-element nonempty abstraction
can be complete for a total transformer while deciding no nonconstant predicate. We therefore use
*unresolved* for report-level uncertainty and reserve *incomplete* for a demonstrated strict
inequality in the completeness equation.

## 2.3 The eBPF verifier as a safety recognizer

The Linux eBPF verifier statically checks bytecode before it runs in the kernel. It symbolically
tracks registers and stack slots, including pointer types, scalar bounds, map-value regions, and
known-bit information. PREVAIL applies abstract interpretation to a separate eBPF analyzer and
proves properties of that analyzer [12]. The tnum work establishes soundness and precision
results for tristate-number operations used in eBPF analysis [13]. Neither reference is an
end-to-end proof of the production verifier in the exact kernel build used here.

In the model, `L_V` is the set of artifacts accepted by this verifier, and the declared safety
property covers memory accesses, termination under the verifier's control-flow rules, and helper
typing. Treating acceptance as sound for that property is a premise, not an empirical conclusion.
The concrete execution semantics include JIT or interpreter execution, helpers, and map
implementations. The saved Linux verifier log is not promoted here to a formal `Report_V`: at the
selected branch it records a helper return as a scalar but supplies neither a declared relational
occupancy component nor an extractor to computed abstract cells. Occupancy is concrete runtime
state observed through helper success or failure. Section 6 uses the log only through an explicit,
conditional local `Report_log` interpretation.

We distinguish this abstraction gap from the eBPF language-verifier gap [12], [14], where valid
programs are rejected because language, compiler, and verifier expectations do not align. Our
gap goes in the opposite direction: the program is accepted, but the recognizer has not captured
all program-visible concrete semantics.

## 2.4 Weird machines

The weird-machine framing originates with Bratus and colleagues, who recast exploitation as
programming an unintended machine whose instructions are the target's unexpected state
transitions [5]. Constructive demonstrations exposed unintended computation in substrates such
as page-fault handling [6] and ELF metadata [7]. Formal accounts model weird machines as
state-transition systems or as target-level behaviors not expressible at the source level [9],
[10]. Vanegue's proof-carrying-code work is the closest antecedent to our setting: it observes
that abstractions used by proof systems can leave untrusted computation outside the proof model
[8], and later gives an under-approximate adversarial logic for exploitability [11].

Our technical contribution is a recognizer-relative account of residual transducers. We connect
it to weird machines only when a separate intended-semantic policy excludes the resulting
attacker-controlled behavior. This boundary prevents the definition from classifying every
ordinary stateful API call as a weird machine.

---

# 3. Recognized Artifacts and Residual Observations

The semantic core is the triple `(V,I,α)`: `V` accepts program artifacts, `I` is the
concrete execution semantics (including any JIT, runtime, helper, and stateful service), and
`α` maps concrete state sets into an abstract domain. Theorems need the contract around that
triple, so we make it explicit as `K=(Safe,A,Report)`. `Safe` is a concrete trace property, `A` is
the family of abstract domains used at analysis frontiers, and `Report` contains the analyzer-
computed states. An abstraction/concretization pair `(α,γ)` relates concrete sets and
abstract elements. It does not identify a computed join with the best abstraction of any concrete
singleton.


**Figure 1. Recognizer-visible language and runtime-interpreted residual language.**

```text
program artifact P
      |
      |  V accepts
      v
recognized safety language L_V
      |
      |  concrete execution semantics I runs accepted P
      v
concrete reachable states ---------------- coverage ---------------> computed Report_V(P)
      |
      | runtime words w in W_run(P); retain causal residual words
      v
program-visible observations o
      |
      | same suffix context, residual state changed, output changed
      v
residual observation relation R_res(P;K_res)  -->  finite residual transducer
```

Figure 1 separates the carriers. `L_V` contains artifacts, `W_res(P;K_res)` contains operation
words, and `R_res(P;K_res)` contains concrete observation tuples. A report-opacity claim additionally requires
one computed report cell to cover the relevant executions. A weird-machine classification
requires a further intended-policy condition defined in Section 5.

> **Definition 1 (recognized safety boundary).** Let `V` be a verifier or recognizer over program
> artifacts `Σ_P*`. Its accepted artifact language is
>
> `L_V = { P in Σ_P* | V(P) = accept }`.
>
> Let `Tr_I(P)` be the concrete traces of `P`, and let `Safe` be a set of traces. The boundary is
> *safety-sound for Safe* when
>
> `forall P in L_V. Tr_I(P) subseteq Safe`.
>
> Safety soundness is a premise of the theorems below. It is distinct from both transfer
> soundness and empirical acceptance of a particular artifact.

> **Definition 2 (computed abstract coverage).** For `P in L_V` and control frontier `ell`, let
> `Reach_I(P,ell)` be the reachable concrete states at `ell`. The analyzer report is a finite set
> `Report_V(P,ell) subseteq A_ell` of *computed* abstract cells. It has frontier coverage when
>
> `Reach_I(P,ell) subseteq union { γ_ell(a#) | a# in Report_V(P,ell) }`.
>
> A concrete pair is *jointly covered* at `ell` when some single `a# in Report_V(P,ell)` covers
> both states. For an operation `op` at that cell, transfer soundness means
>
> `T_op(Reach_I(P,ell) intersect γ_ell(a#)) subseteq γ_ell(T#_op(a#))`.
>
> Joint coverage does not assert `α({σ0})=α({σ1})`; those singleton abstractions may be distinct.
> This definition models joined and path-partitioned analyzers without inventing a pointwise
> abstract trace that the implementation never computed.

> **Definition 3 (runtime words, residual words, and causal observation relation).** For
> `P in L_V`, let `Sigma_op(P)` be a finite alphabet of program-controllable runtime operations
> and let `W_run^ell(P) subseteq Sigma_op(P)^*` be the ordinary operation words enabled from
> frontier `ell` by accepted code. Write `W_run(P)=union_ell W_run^ell(P)`. Calling all of
> `W_run` residual would merely rename trace semantics; the residual subset is defined by causal
> dependence below.
>
> Fix a *residual-observation contract*
> `K_res=(rho_obs,Obs,Slice,Env)`: `rho_obs` is the selected causal residual-state projection,
> `Obs` fixes the program-visible observation trace, `Slice` supplies the conservative semantic
> read-dependency used for `ctx_w`, and `Env` fixes or records relevant nondeterministic and
> environmental choices. For a word `w`, let `ctx_w(σ)` project all concrete state
> read by `w` or its observer, except `rho_obs(σ)`; dead registers and fields not consulted by the suffix
> are excluded. The execution environment and nondeterministic schedule, if any, are included in
> `ctx_w`. The dependency set must be fixed from the semantics or a conservative program slice
> before comparing outcomes; an artifact claim must audit it against source and translated data
> flow rather than delete inconvenient variables after observing the result. Write
> `σ0 =_w^ctx σ1` when these projections agree. For
> `⟦w⟧_I(σ)=(τ,o,σ')`, where `o=Obs(τ)`, define
>
> `R_res^ell(P;K_res) = { (w,c,r0,r1,o0,o1) | exists σ0,σ1 in Reach_I(P,ell):`
>
> `w in W_run^ell(P), ctx_w(σ0)=ctx_w(σ1)=c, rho_obs(σ_i)=r_i, r0!=r1,`
>
> `⟦w⟧_I(σ_i)=(τ_i,o_i,σ_i'), and o0!=o1 }`.
>
> Holding `ctx_w` fixed makes the observation difference residual-causal for the chosen suffix:
> an unrelated explicit input or hidden environment variable cannot supply the differing output.
> `R_res(P;K_res) = { (ell,w,c,r0,r1,o0,o1) |`
> `(w,c,r0,r1,o0,o1) in R_res^ell(P;K_res) }` is a frontier-tagged observation relation, not a language of artifacts and
> not a subset of `L_V`.
>
> Define `W_res^ell(P;K_res)` as the projection of `R_res^ell(P;K_res)` onto its word component,
> and define `W_res(P;K_res)=union_ell W_res^ell(P;K_res)`. Thus an ordinary runtime word enters the residual language
> only when two suffix-context-equal executions give it different observations because their
> selected residual projections differ. Definition 5 later adds the distinct report-unresolved
> obligation; not every causal residual word is opaque to the recognizer.
>
> The boundary-level *recognizer-relative residual language* is the dependent union
>
> `L_res(V,I;K_res) = { (P,ell,w) | P in L_V and w in W_res^ell(P;K_res) }`.
>
> The artifact tag `P` and frontier tag `ell` are part of each word's type: operations enabled by
> one accepted artifact or frontier need not be enabled by another. This is a dependent tagged
> word family. With fixed prefix-free encodings of artifacts, frontiers, and operation symbols,
> its image is an ordinary formal language over a fixed finite encoding alphabet. We use the
> dependent notation to keep the types visible. `L_res(V,I;K_res)` is not a set difference between
> concrete semantics and `L_V`; the two have different carriers. Once `K_res` is fixed, we suppress
> it in `R_res`, `W_res`, and `L_res`.

> **Definition 4 (behavioral residual quotient and transducer).** Fix a *deterministic* execution
> discipline `D` with residual-state carrier `S_D` and a discipline-state projection
> `s_D : Σ -> S_D`: any environment choice or schedule relevant
> to an operation is fixed by `D` or included in the concrete state, so each state/symbol pair has
> at most one successor and output. The projection is `D`-adequate: all concrete components needed
> to determine those residual successors and outputs are included in `s_D` or fixed by the common
> non-residual context. Its word discipline is continuation-closed: whenever a prefix
> `u` reaches a residual state, every suffix `v` admitted there is represented by `uv`. The
> observer for a word records its complete output trace. For
> `r,r' in S_D`,
> define
>
> `r ~_D r' iff for every w allowed by D, w has the same definedness and observation from r and r'`.
>
> This future-observation equivalence is independent of `α`. Continuation closure makes it a right
> congruence: after a common defined prefix `u`, any distinguishing suffix `v` would also
> distinguish the original states through `uv`. If the
> quotient `Q_D = S_D / ~_D` is finite, concrete execution induces a partial Mealy transducer
> `T_D=(Q_D,Σ_D,Γ_D,δ_D,λ_D,q0)`, where `q0` is the equivalence class of a fixed initial
> residual state. The transition and output functions are well-defined because
> `~_D` preserves definedness, output, and successor equivalence. The residual transformations
> induced by words form a partial transformation monoid when identity and composition are defined.
>
> The quotient states need not be equivalence classes of the verifier abstraction. Report opacity
> is the separate fact that two behaviorally distinct classes have reachable representatives
> jointly covered by a computed abstract cell whose report does not decide their different output.

The definitions deliberately separate acceptance, concrete residual behavior, and report
precision. `V` decides membership in `L_V`; `I` gives the residual words their semantics; and
`Report_V` determines whether the particular analyzer distinguishes those executions.

> **Proposition 1 (factorization excludes verifier-unresolved residual observations).** Suppose
> that for every frontier cell `a#` and enabled word `w` there is a function `h_w` such that every
> reachable `σ in γ(a#)` has observation `h_w(a#)`, and that computed abstract transitions preserve
> this factorization along prefixes of `w`. Then no two jointly covered, suffix-context-equal
> executions can produce different observations without the report distinguishing them.

*Proof.* Factorization gives equal reported observations for any jointly covered pair at one
step. Congruence preserves that equality along a word. Thus a residual observation pair may still
exist concretely, but it cannot also be verifier-unresolved under the stated report. ∎

The defensive meaning is LangSec-shaped: the target is not to eliminate abstraction, but to state
which program-visible semantic relations a boundary intends to certify and then test that report
against those relations.

> **Proposition 2 (behavioral factorization on a context fiber).** Fix `P`, frontier `ell`, and a
> deterministic discipline `D`. Let `F subseteq Reach_I(P,ell)` be a reachable fiber whose states
> agree on every non-residual context component read by any continuation admitted by `D`. Let
> `W_D(F)` be those continuations, and assume `W_D(F) subseteq W_run^ell(P)` and that every word in
> `W_D(F)` is total on `F`. Define
> `beta_D(σ)=[s_D(σ)]_D in Q_D` and, for every computed report cell `a#`, define
> `F_a = F intersect gamma_ell(a#)`. Also write `σ approx_D σ'` when
> `s_D(σ) ~_D s_D(σ')`. The report has no cell-level behavioral collision on `F` if
> and only if
>
> `forall a# in Report_V(P,ell). | beta_D(F_a) | <= 1`.
>
> Equivalently, on every nonempty `F_a`, `beta_D` factors through the cell label: there is a value
> `h(a#)` such that `beta_D(σ)=h(a#)` for every `σ in F_a`. If the report cells form a partition
> represented by a unique report map `pi_R : F -> Report_V(P,ell)`, this is equivalent to
> `ker(pi_R) subseteq approx_D`, or `beta_D = h compose pi_R` on `F`.

*Proof.* A cell has no behavioral collision exactly when all residual representatives it covers
belong to one future-observation class. This is the displayed cardinality condition and defines
`h` on every nonempty cell. Under a unique report map, saying that equal reports imply future-
observation equivalence is precisely `ker(pi_R) subseteq approx_D`, which is equivalent to the stated
factorization. ∎

> **Corollary 1 (finite report-capacity collision).** Under Proposition 2's unique-report
> hypothesis, if `F` reaches more behavioral quotient classes than the report has nonempty cells,
> then some computed cell covers two behaviorally inequivalent states.

The corollary is only a collision result. Future-observation inequivalence supplies some
distinguishing continuation and therefore a tuple in `R_res` under the enabled-word, common-context, and totality
hypotheses. It does **not** by itself establish Definition 5: the analyzer may split the pair on a
prefix, or a final post-cell may decide the readout. Those are separate checked obligations.

---

# 4. Verifier-Unresolved Readouts and Certificate Opacity

A residual observation becomes verifier-unresolved when concrete executions are jointly covered
by an analyzer-computed frontier and its post-report cannot decide the readout. This is a
report-precision property. Standard abstract-interpretation completeness is kept separate.

> **Definition 5 (verifier-unresolved residual readout).** Let `op` be a constructible operation,
> `rho_obs` the causal residual-state projection fixed by `K_res`, and `ψ` a predicate over the
> program-visible readout written by `op`. The triple `(op,rho_obs,ψ)` is verifier-unresolved at `(P,ell,a#)` if:
>
> 1. `a# in Report_V(P,ell)` jointly covers reachable `σ0,σ1`;
> 2. `σ0 =_op^ctx σ1`, `rho_obs(σ0)!=rho_obs(σ1)`, and the concrete readouts `r0,r1` satisfy
>    `ψ(r0)!=ψ(r1)`; and
> 3. the computed post-cell `b#=T#_op(a#)` does not decide `ψ`, where `b#` decides `ψ` exactly
>    when `ψ` is constant over every concrete readout in the readout projection of `γ(b#)`.
>
> This definition refers to a computed cell and its sound transfer. It neither requires nor
> implies equality of `α({σ0})` and `α({σ1})`.

Relative to a declared boundary contract `K=(Safe,A,Report)` and observation contract `K_res`, such a readout is
*contract-shape-induced* when the paired executions follow the documented concrete semantics and
their traces satisfy `Safe`, and the collision arises because `Report` fails the behavioral factorization criterion,
not because `V` or `I` violates the declared boundary specification `(V,I,K,K_res)`. This is a relational classification, not an immutable
property of the implementation: refining `Report`, strengthening `A`, or restricting `I` changes
the boundary specification and can eliminate the collision.

> **Lemma 1 (sound coverage preserves both outcomes).** Under transfer soundness, a computed
> post-cell covering two states that satisfy conditions 1–2 of Definition 5 cannot decide `ψ`.

*Proof.* The two concrete post-states belong to the concrete image of
`Reach_I(P,ell) intersect γ(a#)`. Transfer soundness places both in `γ(T#_op(a#))`. Since their
readouts give opposite values of `ψ`, `ψ` is not constant over the post-cell's readout
concretization. ∎

An unresolved readout is not automatically a standard completeness counterexample. To claim
incompleteness for `(α,T_op)`, one must exhibit a concrete set `X` for which
`α(T_op(X)) != α(T_op(γ(α(X))))`, or invoke an equivalent established criterion. Throughout the
artifact, `top` means only “the computed report does not decide the stated predicate” unless the
lattice element is explicitly identified.

**The eBPF instance.** Let `rho_obs` include the key set and occupancy `c(G)` of a preallocated,
non-LRU hash map `G` with `max_entries = k`. The witness relies on the following deterministic
capacity predicate: `CAP(k)` says that a fresh-key update succeeds and increments `c(G)` exactly
when `c(G) < k`, and otherwise fails without changing `c(G)`. For this eBPF helper instance,
`RET_eBPF` states that success returns `0` and an error return is negative; the gate observes only
the zero/nonzero predicate `ψ(r)=[r==0]`.

The retained Linux verifier log is not itself `Report_V`. We write `Report_log` only for a
diagnostic interpretation of its local scalar-return text and branch exploration. `Report_log`
does not supply an abstract-cell extractor, a concretization map, a proof that two concrete runs
are jointly covered, or local transfer soundness. Consequently, the following proposition is a
general conditional statement. Applying it to Linux would additionally require a declared
`Report_log -> (a#,T#_op(a#))` interpretation and proofs of its local coverage and transfer-
soundness premises.

> **Proposition 3 (conditional occupancy readout).** Assume a map implementation satisfying
> `CAP(k)` and `RET_eBPF`, and transfer soundness for the computed cell below. Let `σ0,σ1` be reachable
> at one fresh-insert frontier, jointly covered by a
> computed cell `a#`, and equal under `ctx_op`. The inserted key and all suffix-read helper
> arguments therefore agree; dead values need not agree. Suppose the key is fresh in both states,
> one residual map has capacity and the other is full. Then `(op,rho_obs,[r==0])` is a
> verifier-unresolved residual readout.

*Proof.* Under `CAP(k)` and `RET_eBPF`, the stated capacity difference is sufficient for zero and
negative concrete readouts; no claim that it is the only component of `rho_obs` is needed. Joint
coverage and transfer soundness then invoke Lemma 1. No equality of singleton abstractions is
needed. ∎

The configuration recorded in `results/env.json` empirically instantiates `CAP(2)` for the
dedicated map and reset discipline. The semantic claim uses only success versus failure, although
the eBPF instance sharpens failure to a negative raw return. The regeneration path records the raw
second-helper return so that version-specific errno statements can be audited, but neither
Proposition 3 nor the NAND proof assumes a particular errno number.

Local uncertainty and whole-program certification are different objects.

> **Definition 6 (typed report vocabulary, certificate theory, and Q-opacity).** A report
> vocabulary `Q` assigns to each finite typed variable context `U` a formula set `Form_Q(U)` and
> a valuation semantics `Mod_Q^U(q) subseteq Val(U)`. It is closed under conjunction in one
> context, capture-avoiding variable renaming, compatible natural join, and existential
> projection. For a finite theory `Γ subseteq Form_Q(U)`, write
> `Mod_Q^U(Γ)=intersection_{q in Γ} Mod_Q^U(q)`, with
> `Mod_Q^U(emptyset)=Val(U)`. Define
> `Γ models_Q q` iff `Mod_Q^U(Γ) subseteq Mod_Q^U(q)`, and
> `q models_Q Γ` iff `Mod_Q^U(q) subseteq Mod_Q^U(Γ)`.
>
> For finite input domain `D`, output domain `O`, and interface context
> `U_io={x:D,y:O}`, a deterministic program `π` has graph
> `G_π={(x,f_π(x)) | x in D} subseteq Val(U_io)`. The graph is *Q-expressible* when some
> `Graph_Q(f_π) in Form_Q(U_io)` denotes exactly `G_π`.
>
> A fixed extractor `Extract_Q` maps the complete analyzer report for `π` to one finite theory
> `Γ_Q(π) subseteq Form_Q(U_io)`. It is sound when
> `G_π subseteq Mod_Q^U_io(Γ_Q(π))`. The theory, rather than each formula in
> isolation, is the certificate: `Γ_Q(π) models_Q q` uses their conjunction. A program is
> *Q-certificate-opaque* when (i) `f_π` is nonconstant, (ii) `Graph_Q(f_π)` exists, and
> (iii) `Γ_Q(π) not-models_Q Graph_Q(f_π)`.

The expressibility requirement prevents a deliberately weak vocabulary from making opacity
vacuous, and theory-level entailment prevents two individually weak facts from being ignored when
their conjunction proves the graph. `Extract_Q` must also define input/output scope, path joins,
variable renaming, and projection. Syntactic visibility of an explicit baseline is not a
certificate under this definition. A baseline comparison requires the same frontiers, vocabulary,
and extractor for both programs.

> **Remark 1 (local uncertainty does not imply Q-opacity).** Definition 5 does not imply
> Definition 6. Later branches or relational summaries can recover a function, and composition
> can eliminate spurious local pairs. Section 5 therefore uses an explicit persistent-alternative
> condition for its conditional global result. The present eBPF artifact provides only a local
> scalar-return `Report_log` observation; it does not establish Definition 5, implement a
> machine-checked `Extract_Q` for the Linux verifier, or claim whole-program Q-certificate-opacity.

A finite counterexample makes the composition point concrete. Let
`A={0,1}`, `B={0,1,2,3}`, and `C={0,1}`; let `f1` map 0 to 0 and 1 to
1, and let `f2` map 0 to 0, 1 to 1, 2 to 0, and 3 to 0. The sound local
over-approximations
`R1=graph(f1) union {(0,2)}` and
`R2=graph(f2) union {(3,1)}` are both strict and locally non-functional.
Nevertheless, `R2 compose R1={(0,0),(1,1)}`, the exact identity graph:
the first relation's extra value is merged by `f2`, while the second
relation's extra pair lies outside the first relation's range. Local opacity
therefore has no general monotone-composition law.

---

# 5. Bounded Data-Parametric Realization and Conditional Global Opacity

A residual readout is programmable only when accepted code provides one uniform gate
implementation and one accepted artifact can consume a complete, independently bounded circuit
description. The quantifiers, runtime-language carrier, and resource boundary are explicit below.

> **Definition 7 (uniform residual gate basis; E1--E3).** A basis for an `m`-input Boolean gate consists
> of a witness artifact `P_G in L_V`, designated fragments `(reset,G,observe)` within `P_G`, and
> a residual transducer discipline `D` satisfying:
>
> Fix a reset equivalence class `q0=[r_reset]_D subseteq S_D`.
>
> - **(E1) Residual basis and observability:** at an internal frontier `ell_r`, there exist
>   `σ0,σ1 in Reach_I(P_G,ell_r)` with `[s_D(σ0)]_D != [s_D(σ1)]_D`, and the same pair witnesses
>   an output-relevant suffix `v in W_res^ell_r(P_G)`. For the resulting program-visible readout `o`,
>   `observe` branches on or stores `ψ(o)` as one program bit.
> - **(E2) Uniform input control:** one accepted dispatcher `G`, not an external oracle, reads the
>   runtime wire vector `x in {0,1}^m` and selects a complete gate word `u(x) in W_run(P_G)`. For every `x`, every
>   admissible concrete state `σ` with `s_D(σ) in q0`, and every environment admitted by `D`, the
>   execution is defined, terminates, and produces the same bit `g(x)`. Thus `G` is total and
>   deterministic and the induced gate `g` is well-defined.
> - **(E3) Reset:** from every admissible concrete state `σ`, `reset` returns `σ'` with
>   `s_D(σ') in q0` and removes prior-gate dependence except for explicit wire cells.
>
> For a later opacity claim, input dispatch and output storage are included in the analyzed gate;
> one may not hide an explicit computation of `g` in the dispatcher.

> **Definition 8 (E4-D: bounded data-parametric composition).** Fix independent bounds
> `M=64` primary inputs and `N=512` NAND gates. Let `D_{M,N}` be the language of canonical,
> topologically ordered *core* descriptor tuples
> `d=(m,n,(s_i^0,s_i^1)_{0<=i<n})` satisfying `0<=m<=M`, `0<=n<=N`, and, for every gate `i` and
> operand `b`, `0<=s_i^b<2+m+i`. Write `m(d)=m` and `n(d)=n`. Wire cells `0,1` contain constants
> `0,1`; primary inputs occupy `2,...,2+m-1`; gate `i` writes the canonical destination
> `2+m+i`. Hence every descriptor has exactly `2+m+n<=578` live wire cells.
>
> A textual WMC1 bundle is a **host-side serialization**, not a kernel word: its parser returns a
> core descriptor `d` and, optionally, a host output projection `pi`. The output list is not part
> of `d` and is not consumed by `P_U`. Let `Conf_U` be the set of map configurations over
> `CIRCUIT`, `WIRES`, and `VM_CONTROL` admitted by the core ABI. The encoding
> `Enc_U(d,x) in Conf_U` normalizes `d` into `CIRCUIT`, writes the Boolean input vector `x` into
> `WIRES`, and writes the control record into `VM_CONTROL`; let
> `Valid_U={Enc_U(d,x) | d in D_{M,N}, x in {0,1}^{m(d)}}`. Thus `d` denotes a mathematical core
> descriptor and `Enc_U(d,x)` denotes the concrete configuration delivered to the kernel.
>
> Let `Eval(d,x)` be the complete live wire vector initialized with the two constants and `x`, then
> extended in descriptor order by `nu[2+m+i]=g(nu[s_i^0],nu[s_i^1])`. Let
> `Status_U={OK} union Err`. For a physical map configuration `c`, write
> `PhysRun_U(c)=(s,k,mu)` for the final status `s`, number `k` of completed gate iterations, and
> physical map state `mu`. Its **status-masked observable result** is
>
> `Run_U(c)=(s,WireObs(mu))` if `s=OK`, and `Run_U(c)=(s,bottom)` if `s in Err`.
>
> On `OK`, `WireObs(mu)` denotes only the complete live canonical wire vector for the valid
> configuration; it is not a claim about unrelated map cells. On error, `bottom` is the only
> semantic wire observation even if old physical `WIRES` or `VM_TRACE` entries remain in maps.
> The host may apply `pi` only to a successful `WireObs(mu)`.
>
> A fixed artifact `P_U` discharges **E4-D** for `D_{M,N}` when:
>
> 1. `P_U in L_V` independently of the host configuration;
> 2. for every `d in D_{M,N}` and `x in {0,1}^{m(d)}`, invocation from `Enc_U(d,x)` executes
>    exactly the iterations `i=0,...,n(d)-1`, in order and without per-gate intervention by an
>    external oracle, and finishes with `PhysRun_U(Enc_U(d,x))=(OK,n(d),mu)` and
>    `Run_U(Enc_U(d,x))=(OK,Eval(d,x))`;
> 3. the execution discipline externally enforces one global critical section over the entire
>    invocation and every shared map read or written by it, including `TAPE`, `CIRCUIT`, `WIRES`,
>    `VM_CONTROL`, `VM_TRACE`, and the gate map. It excludes another `P_U` invocation and every
>    external map writer, so the encoded descriptor, inputs, and gate state are mutually isolated
>    for the whole run;
> 4. on a valid configuration, iteration `i` checks canonical form, reads exactly its two
>    designated source wires, invokes the embedded uniform residual gate, writes only `2+m+i` and
>    declared audit cells, and preserves earlier wire cells; and
> 5. at most `N` iterations execute, and any malformed core-ABI control or descriptor configuration
>    that reaches `P_U` finishes with an explicit `s in Err`, `k<=N`, and the masked result
>    `(s,bottom)`, rather than a functional output.
>
> `D_{M,N}` is fixed in the source snapshot independently of this run's load outcome. It indexes
> valid host configurations through `Enc_U`; neither `d` nor textual WMC1 is a member of
> `L_V`, `W_run(P_U)`, or automatically of `L_res`. The internal operation schedule
> `Sched_U(d,x)` induced after `Enc_U(d,x)` is the relevant member of `W_run(P_U)`; only causally
> compared internal suffixes may enter `W_res`.

`E4-D` differs from an **artifact-parametric** condition `E4-A`, in which a compiler emits a
distinct accepted program `compile_B(C)` for each circuit. This paper does not establish `E4-A`:
E4-D requires acceptance of one fixed interpreter, not each descriptor. The distinction prevents
a carrier error while retaining `E4-A` as a future macro-closure question.

Definitions 5, 7, and 8 address different questions: Lemma 1 explains one computed frontier,
while E1--E3 and E4-D make the same concrete mechanism observable, uniformly controllable,
resettable, and data-parametrically composable. The conditions remove the following nearby
counterexamples:

| Missing condition | Counterexample | Consequence |
|---|---|---|
| program-visible readout | hidden state differs but no accepted code can observe it | no residual language witness |
| uniform input-control | an external oracle chooses a different constant word for each input | no single runtime gate program |
| reset | the channel can be consumed only once | no reusable gate basis |
| data-parametric interpreter | an isolated gate exists but no accepted artifact consumes a complete descriptor | no hosted circuit language |
| functional completeness | the residual gate is only a projection or constant | not a universal Boolean basis |
| persistent alternative | local spurious pairs disappear under composition | no global opacity conclusion |

> **Lemma 2 (gate embedding and frame preservation).** Under the E4-D discipline, including
> mutual exclusion of the whole invocation across every shared map in its footprint, projection of
> one interpreter iteration onto its dedicated gate map, two source bits, and helper readout has
> the same transition/output semantics as Definition 7's uniform gate. The iteration modifies
> neither the descriptor nor any previously defined wire cell, except for its canonical destination
> and declared audit/error cells.

*Proof sketch.* The implementation copies descriptor fields and source bits before helper calls,
uses a dedicated gate map, deletes `S,A,B` before every invocation, and writes only the canonical
destination after a successful gate setup. Canonical destinations exclude source/destination
aliasing. The global critical section excludes an interleaving reset, descriptor update, wire
update, trace update, or gate-map update by another `P_U` invocation or host writer; the compiler
barrier in the implementation is not a concurrency lock. ∎

> **Lemma 3 (descriptor-prefix simulation).** For `d in D_{M,N}` and Boolean input `x`, after
> the first `t` successful interpreter iterations, every cell below `2+m+t` equals the
> corresponding cell of `Eval(d,x)`, and the descriptor, primary inputs, and unrelated declared
> frame are unchanged.

*Proof.* By induction on `t`. The descriptor bound makes both sources of gate `t` earlier cells;
Lemma 2 and the gate correctness of Definition 7 supply `g` at the canonical destination, while
the frame clause preserves the induction hypothesis. ∎

> **Theorem 1 (bounded data-parametric residual-circuit realization).** Assume the boundary is
> safety-sound for `Safe`, `P_U in L_V`, the embedded basis satisfies E1--E3 and computes `g`, and
> `P_U` discharges E4-D under its stated discipline. Then, for every `d in D_{M,N}` and input
> `x`, `Run_U(Enc_U(d,x))=(OK,Eval(d,x))` after exactly `n(d)` gate iterations. Every such trace
> satisfies `Safe` under the safety-soundness premise.

*Proof.* Lemma 3 at `t=n(d)` gives functional correctness and termination; E4-D gives the single
artifact acceptance fact; Definition 1 supplies the conditional safety conclusion. ∎

If `g` is NAND, every Boolean circuit whose canonical NAND description fits `D_{64,512}` is
realized by the fixed interpreter. This is not an unbounded claim and does not imply that a Linux
verifier accepts a separately generated BPF artifact for every finite circuit.

> **Definition 9 (persistent-alternative certificate).** Fix `d` and write `P_{U,d}` for `P_U`
> executed from the frozen normalized configuration `Enc_U(d,x)` under the E4-D discipline.
> Alongside the
> interface extractor `Extract_Q` of Definition 6, fix a local extractor `Extract_Q^loc` over the
> same complete report and vocabulary. It produces formulas for each designated gate frontier and
> exact formulas for explicit copy/fan-out operations in their typed variable contexts. After
> consistent variable renaming and compatible natural joins, let `U_C` be the complete typed
> context of primary inputs `x`, internal wires `z`, and final output `y`, and let
> `K_C in Form_Q(U_C)` be their conjunction over those variables. Let
> `Loc_C=exists z.K_C in Form_Q(U_io)`. Let `Γ_Q(P_{U,d}) subseteq Form_Q(U_io)` be the extracted
> whole-program theory, and let `f_d` be the selected nonconstant output function of `Eval(d,.)`.
> A *persistent-alternative certificate* consists of:
>
> 1. a pair `(x,y')` with `y'!=f_d(x)` satisfying `Loc_C`; and
> 2. a checked dominance obligation `Loc_C models_Q Γ_Q(P_{U,d})`, meaning every pair admitted by
>    the composed local summaries is also admitted by the whole-program report theory.
>
> The typed closure conditions of Definition 6 make each operation above well-defined. Local gate
> uncertainty is not enough: the first obligation
> fails when composition eliminates all wrong alternatives, and the second fails when a global
> analyzer relation is stronger than the composed local summaries.

> **Theorem 2 (conditional Q-certificate opacity).** Under Theorem 1 for fixed `d`, let
> `Eval(d,.)` compute a nonconstant function, let its graph be Q-expressible, and let `Extract_Q`
> be sound. If a valid persistent-alternative certificate exists for `P_{U,d}`, then `P_{U,d}` is
> Q-certificate-opaque for that function.

*Proof.* The persistent pair `(x,y')` is a model of `Loc_C`. Dominance makes it a model of the
whole-program theory `Γ_Q(P_{U,d})`. Because `y'!=f_d(x)`, it is not a model of the target graph.
Therefore the extracted theory does not entail that graph, and all clauses of Definition 6 hold. ∎

The theorem deliberately excludes constant circuits and does not derive global opacity from local
imprecision. It is a verification obligation, not a claim that composition can only propagate
imprecision. The eBPF artifact does not yet provide `Extract_Q`, `K_C`, or a persistent-alternative
certificate, so it does not instantiate Theorem 2.

> **Definition 10 (recognizer-relative weird machine).** Relative to an intended semantic or
> security policy `M` and threat model `T`, an accepted artifact operates a recognizer-relative
> weird machine only when (i) it realizes a controllable residual transducer under Definition 7,
> (ii) an actor in `T` can drive it, and (iii) the resulting security-relevant behavior is excluded
> by `M` rather than merely omitted from a property-specific analyzer report.

Definition 10 makes the classification deployment-relative. The offline eBPF construction has no
victim policy or security-relevant effect and is therefore reported only as a residual-transducer
construction with a local scalar-return `Report_log` observation, not as a demonstrated exploit,
weird machine, or formal Definition 5 instantiation.

# 6. The eBPF witness

We instantiate the uniform residual NAND gate of Definition 7 in `P_U = wm_circuit`, a fixed
`SEC("syscall")` eBPF artifact. A host parser converts textual WMC1 into a normalized core gate
array plus input and control map cells; the kernel program reads those maps, checks the E4-D core
shape, invokes the same dedicated `G0` capacity gate for every descriptor iteration, stores
canonical wire cells, and records one helper-return trace per gate. The output-list projection is
host-side and is applied only after `status=OK`. The recorded fresh run checks acceptance of this
one artifact; neither textual WMC1 nor a descriptor is a separately verified BPF program. Under
the stated whole-map-set mutual-exclusion discipline, the source construction is intended to
discharge the artifact side of Theorem 1 for `D_{64,512}`. Its safety conclusion remains
conditional on Definition 1, and the proof is a mathematical prefix induction over the declared
descriptor semantics rather than a claim that finite tests enumerate all descriptors.

We do not discharge Theorem 2: the current Linux report artifact has no formally specified
`Extract_Q` or persistent-alternative certificate. The explicit-logic baseline is therefore a
mechanism and bytecode-structure control, not a same-vocabulary proof of global certificate
opacity. The programs run offline via `bpf_prog_test_run_opts()`; they use only legal helper
calls and bounded loops; they perform no out-of-bounds access and no verifier bypass. All
experiments run in a local VM under a privileged configuration sufficient for the exact kernel
version and program type used by the artifact. We do not claim unprivileged loadability,
attachability, privilege escalation, or deployment in a live kernel path.

**Artifact interface note.** We use `BPF_PROG_TYPE_SYSCALL` because the artifact requires
map-update helper traces without attaching a program to a live kernel hook. On the tested kernel,
this program type is accepted by the verifier and executed through `bpf_prog_test_run_opts()`;
the artifact records the exact program type, helper set, kernel version, and verifier logs. The
construction is not tied to syscall attachment semantics at the level of concrete gate behavior,
but acceptance and resource limits remain specific to the recorded program type and kernel build.

## 6.1 The residual gate language

The witness is a finite-state residual transducer over hash-map occupancy. The gate uses one
`BPF_MAP_TYPE_HASH` map `G` with `max_entries = 2`. The map is non-LRU and, as defined in the
artifact, has no `BPF_F_NO_PREALLOC` flag; it therefore uses the ordinary preallocated hash-map
configuration relied on by the deterministic capacity-saturation witness. The keys `S`, `A`,
and `B` are distinct, and the maps are dedicated to offline `SEC("syscall")` runs via
`bpf_prog_test_run_opts()`; that allocation fact is not a concurrency guarantee and is paired
with the external whole-map-set exclusion discipline.

The mechanism is capacity saturation, not allocation failure as an attacker primitive. In the
tested dedicated, preallocated, non-LRU configuration, a fresh-key update succeeds below
`max_entries` and fails once both slots are live, without eviction. The gate depends only on the
zero/nonzero success predicate. The regeneration harness records the raw second-helper return for
auditing, but the proof does not assign a portable errno to the failure. Section 7 treats
kernel-version and architecture portability as a threat to validity.

Under deterministic discipline `D_G` (dedicated map, mutual exclusion across the complete shared
map set for the whole invocation, fixed flags, successful reset, and the fixed gate schedule
below), a finite concrete carrier is represented by pairs
`(phase,K)`, where `phase` records reset/sentinel/first-input/second-input completion and `K` is
the live key set. Phase is retained because equal key sets reached at different positions can
admit different continuations. The reachable product is finite, so its future-observation
quotient from Definition 4 is finite; we do not claim that the quotient has exactly four classes.
Formally, the discipline projection is `s_D(σ)=(phase(σ),K(σ))`. It is distinct from the
causal projection `rho_obs` in Definition 3, which includes the key set/occupancy needed to isolate
the helper-return difference but need not carry the control phase.

The residual-observation contract is instantiated as follows:

| `K_res` component | eBPF instantiation |
|---|---|
| `rho_obs` | dedicated gate-map key set and logical occupancy |
| `Obs` | complete suffix output trace, including the second update's zero/nonzero return predicate |
| `Slice` | source-level suffix read-dependencies audited against the bound translated-bytecode data flow |
| `Env` | dedicated preallocated non-LRU map; whole-invocation mutual exclusion across every shared map and host writer; fixed flags/program type; and the kernel/architecture captured in the interpreter run's `environment.txt` |
For compactness, the following table projects away phase and lists the key-set effects exercised
by the gate. The alphabet is

`Σ_G = { reset, insS, updS, insA, insB }`.

`reset` deletes the sentinel and input keys `S`, `A`, and `B`; `insS` inserts the sentinel key
`S`; `updS` updates the existing sentinel and therefore does not increase occupancy; `insA` and
`insB` insert fresh input keys. Each gate starts from the invariant occupancy `{S}` after
`reset . insS`. The output alphabet is `{ ε, 1, 0 }`, where `1` means helper success
(`ret == 0`), `0` means helper failure (`ret < 0` in this eBPF instance), and `ε` is an ignored
normalization output. The partial transition/output table needed by the gate is:

| Key set | Input | Next key set | Output |
|---|---|---|---|
| any admissible `K` | `reset` | `empty` | `ε` |
| `empty` | `insS` | `{S}` | `ε` |
| `{S}` | `updS` | `{S}` | `1` |
| `{S}` | `insA` | `{S,A}` | `1` |
| `{S}` | `insB` | `{S,B}` | `1` |
| `{S,A}` | `updS` | `{S,A}` | `1` |
| `{S,A}` | `insA` | `{S,A}` | `1` |
| `{S,A}` | `insB` | `{S,A}` | `0` |
| `{S,B}` | `updS` | `{S,B}` | `1` |
| `{S,B}` | `insB` | `{S,B}` | `1` |
| `{S,B}` | `insA` | `{S,B}` | `0` |

Combined with the deterministic phase progression, the table defines every transition used by
the reset-normalized gate schedule. It is a presentation of the concrete finite machine, not a
minimal-quotient proof. For input bits `a,b in {0,1}`, the complete runtime gate word is

`w_ab = reset . insS . op_a . op_b`, where `op_0 = updS` and `op_1` is the corresponding fresh
insert (`insA` for the first input, `insB` for the second). The output symbol is the predicate
`out = [ret == 0]` over the return code of the **second input operation** `op_b`, not a third
probe. At gate exit, the output is determined only by success or non-success of that second
input operation. This matches the artifact's `GATE_CAP=2` implementation and avoids the
off-by-one ambiguity of a sentinel-plus-third-probe variant.

| a | b | runtime gate word | second input result | output |
|---|---|---|---|---|
| 0 | 0 | `reset insS updS updS` | success | 1 |
| 0 | 1 | `reset insS updS insB` | success | 1 |
| 1 | 0 | `reset insS insA updS` | success | 1 |
| 1 | 1 | `reset insS insA insB` | failure (`ret < 0`; raw return recorded by regeneration) | 0 |

Because its reset prefix erases incoming residual differences, the complete `w_ab` need not itself
belong to `W_res`. The causal residual word is the common second-operation suffix at the frontier
after the first input operation: for example, `insB` distinguishes the rank-1 and rank-2 states
reached by `(a,b)=(0,1)` and `(1,1)` under the same suffix context. E2 governs the complete word in
`W_run`; E1 identifies this internal `W_res` suffix.

> **Proposition 4 (saturating-rank NAND basis).** Let a residual resource have capacity `k>=2` and
> let reset prepare rank `k-1` with an existing sentinel name `s`. Let `A` and `B` be distinct
> names fresh after reset. Existing-name update succeeds without changing rank; fresh-name update
> succeeds and increments rank below `k`, and fails without changing rank at `k`. For input
> `(a,b)`, a uniform dispatcher first updates `s` if `a=0` and `A` if `a=1`, then updates `s` if
> `b=0` and `B` if `b=1`. If the output is the second update's success predicate, the result is
> `NAND(a,b)`.

*Proof.* If `a=0`, the first update preserves rank `k-1`, so either second operation succeeds. If
`a=1`, the first update raises rank to `k`; the second operation still succeeds for `b=0` because
it updates existing `s`, but fails for `b=1` because `B` is fresh. The four outputs are therefore
`1,1,1,0`. ∎

The eBPF instance sets `k=2`. Thus the uniform dispatcher implements `NAND(a,b)`. The bytecode
uses `a` and `b` to select an existing or fresh key, while capacity-dependent helper success
supplies the truth table's key nonlinearity. Bytecode still performs dispatch, reset, routing, and
output storage. `wm_circuit` embeds this gate in a fixed bounded loop: each descriptor gate has
canonical sources and destination, and the same `G0` map is reset and reused sequentially. NAND
is functionally complete algebraically, so the host encoder can form a valid `Enc_U(d,x)` map
configuration for every canonical NAND DAG that fits `D_{64,512}`. The runtime word is the
resulting `Sched_U(d,x)`, not `d` itself. This does not establish `E4-A` for a compiler that
generates a new verifier-accepted BPF artifact per circuit. The explicit-logic baseline in the
next subsection controls for the truth table and verifier acceptance, but it is not a Definition 6
certificate comparison because no common `Extract_Q` is available.

## 6.2 Contrast: an explicit-logic baseline the verifier accepts identically

A baseline variant computes the same truth table with ordinary arithmetic: two comparisons
negate the inputs and an `OR` combines them into `¬a ∨ ¬b = ¬(a∧b)` by De Morgan. This
baseline is also verifier-accepted and produces an identical 400/400 truth table; its NAND
expression is syntactically present in translated bytecode (repository Appendix A.8). The
comparison shows that the residual variant does not gain extensional Boolean expressiveness and
that both mechanisms pass the same acceptance gate. It does not show that the production verifier
certifies the baseline's complete map-mediated input/output graph. Establishing that contrast in
Definition 6 requires a common report-theory extractor.

## 6.3 Discharging the clauses

| Clause | eBPF realization | Evidence |
|---|---|---|
| recognized boundary | in-kernel verifier; concrete eBPF/JIT plus map/helper runtime; exact environment | `interpreter-v1-20260710-02` verifier log and environment record |
| causal residual relation | same second-insert suffix context; residual key set/occupancy differs; success bit differs | source, xlated data flow, and paired-run records in the audited run |
| local `Report_log` observation | the log locally presents the helper return as a scalar and explores both return-branch successors; paired runs record `0` and `<0` | verifier log plus raw-return records; **not** an extractor for `a#`, `gamma`, or `T#_op` |
| E1 residual basis and observability | after the first input, the common second-update suffix distinguishes rank-1/rank-2 classes; the saved return's zero-test decides the bit | bound xlated data flow; no copied instruction number |
| E2 uniform dispatcher | one accepted fragment reads both runtime inputs and selects `updS` versus the corresponding fresh insert | xlated input-select and helper-call blocks |
| E3 resettability | delete `S,A,B`, then insert `S`; gate restarts in canonical class `{S}` / occupancy 1 | bound xlated delete/insert blocks; no copied instruction number |
| E4-D fixed interpreter | one fixed `wm_circuit` reads normalized core-gate, input, and control maps; it validates canonical SSA and dispatches every gate through `G0`; host code separately parses WMC1 and projects selected output wires | source snapshot and `interpreter-v1-20260710-02` object/audit |
| descriptor-prefix/frame invariants | canonical destinations exclude aliases; invalid ABI/count/op/destination/forward-reference controls receive an error status and a masked output | source snapshot and eight-case negative-suite audit |
| bounded circuit configuration domain | the host WMC1 encoder plus independent oracle drive named circuits, a fixed-seed random corpus, zero-gate, and 512-gate boundary descriptors | regenerated descriptors/corpus and interpreter JSONL audit |
| serial reuse regression | one loaded harness alternates descriptors serially; it is not a concurrency test and does not establish the mutual-exclusion premise | 10,000-run stress JSONL audit |
| gate `g` = NAND | successful normal per-gate traces are checked against `output=[raw_return=0]`; cap64 and sentinel controls are checked as mechanism-removing controls | normal/control JSONL audit |
| Definition 5 / Proposition 3 for Linux | not yet instantiated: it would require a declared `Report_log`-to-cell interpretation plus local joint-coverage and transfer-soundness proofs | explicit limitation in Sections 4--5 |
| global Q-opacity | not claimed: no `Extract_Q` or persistent-alternative certificate | limitation in Sections 4-5 |

The representative full-adder composition uses the standard nine-NAND schedule:

`n1 = NAND(a,b)`

`n2 = NAND(a,n1)`

`n3 = NAND(b,n1)`

`x = NAND(n2,n3)`

`n4 = NAND(x,cin)`

`n5 = NAND(x,n4)`

`n6 = NAND(cin,n4)`

`sum = NAND(n5,n6)`

`carry = NAND(n1,n4)`

The host WMC1 encoder parses this schedule into nine normalized core NAND records, writes them to
the map ABI, and may retain a host-side output projection. Intermediate values use the canonical
SSA wire cells and the interpreter resets and reuses `G0` once per record. The same accepted
`P_U` also executes the other encoded configurations in the corpus; neither the BPF object nor its
verifier-visible control-flow shape changes when the host configuration changes. This is E4-D, not
the unproved artifact-parametric `compile_B` condition E4-A.

For the causal readout witness, compare concrete inputs `(a,b)=(0,1)` and
`(1,1)` immediately before the second input-conditioned update. Both suffixes
use the same key `B`, value, map identity, flags, program point, and observer.
The first execution has key set `{S}`; the second has `{S,A}`. The earlier
input `a` is no longer read by the suffix, so it is excluded from
`ctx_op`; its only suffix-relevant effect is already contained in the
residual key-set/occupancy projection. The two concrete returns are success and
failure, respectively.

The serialized verifier log is machine-checkable as a file, but the inference drawn from it is
local and diagnostic. It records a scalar helper return flowing into the output branch and both
branch successors; paired runs and xlated data flow respectively supply the observed `0`/negative
outcomes and the proposed `ctx_op` slice. This is an empirical `Report_log` observation, not a
machine-proven joined abstract cell. It does not establish `a#`, `gamma(a#)`, `T#_op`, joint
coverage, or transfer soundness. If a future extractor gives the log a `Report_log ->
(a#,T#_op(a#))` interpretation and proves those local premises, Proposition 3 would then support
a Definition 5 instantiation. It does not, without a report extractor, instantiate Definition 6
or Theorem 2.

## 6.4 `P_U`: the bounded host-to-map circuit ABI

`wm_circuit` is a single `SEC("syscall")` program with four additional maps: `CIRCUIT` stores
normalized core gate records `(op,src0,src1,dst)`; `WIRES` stores constants, inputs, and
canonical SSA cells; `VM_CONTROL` supplies the core-ABI version and bounds; and `VM_TRACE` stores
the raw second helper return, output bit, and validity flag for every executed gate. Textual WMC1
is parsed outside the kernel; its optional output list is a host projection and is never read by
the BPF program. The fixed v1 core domain is `0<=m<=64`, `0<=n<=512`, and `2+m+n<=578`. The code
uses `bpf_loop(n, ...)`, copies each gate record and its source bits before helpers run, resets
`G0`, and re-looks up the destination after the helper sequence. A malformed ABI, input count,
gate count, wire count, opcode, destination, or forward reference produces an explicit non-`OK`
status and the status-masked semantic result `(status,bottom)`; this does not claim that old
physical map contents have been erased.

The artifact's interpreter theorem is deliberately modest. The verifier acceptance fact required
by Theorem 1 is `P_U in L_V` once for the recorded object; the fresh run records that empirical
acceptance, and it is not `d in L_V` for every
descriptor. The runtime schedule `Sched_U(d,x)`, not `d` or textual WMC1 itself, belongs to
`W_run(P_U)`. Only a causally compared internal gate suffix, such as the second fresh-key update,
belongs to the residual word language under `K_res`. The proof obligation for every valid
configuration is Lemmas 2--3 plus whole-invocation mutual exclusion across the entire shared map
set; finite tests are regression evidence, not a replacement for that induction or an enumeration
of `D_{64,512}`.

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
the regeneration manifest binds each result set to its BPF object, user-space runner, verifier
log, xlated dump, run identifier, environment record, and dataset hashes. The audit checks those
bindings before semantic oracles. The four variants — residual gate, two ablations, and the
explicit baseline — are all verifier-accepted (`loadall_exit = 0`) in the recorded run.

**Independent audit.** An oracle re-derives every expected truth table and sum independently of
the harness's own pass flag, and asserts full input coverage; the aggregate re-check reports
68149/68149 and a passing semantic audit. The aggregate consists of 400 NAND trials, 8 full-adder
trials, 65536 exhaustive 8-bit operand-pair trials for the 32-bit adder harness, 1005 full-width
sampled 32-bit cases, and 1200 ablation/baseline truth-table checks. The eBPF datasets and bound
variant evidence are regenerated by one command and re-checked by
another; the Frama-C control has its own recorded command and log.

**Bounded interpreter evaluation.** The source-snapshotted run
`interpreter-v1-20260710-02` rebuilt the fixed interpreter, regenerated WMC1 descriptors from
symbolic circuit descriptions, and passed both `interpreter audit: ok` and `interpreter
provenance: ok`. It contains 37,507 JSONL rows: 25,464 per-gate records, 12,035 successful
run records, and eight malformed-core controls. The normal named corpus contributes 39 exhaustive
runs and 166 gate traces; the fixed-seed 100-DAG corpus contributes 1,876 exhaustive runs and
23,776 traces; the deep boundary contributes two 512-gate runs and 1,024 traces; the zero-gate
descriptor contributes one run; the serial alternation contributes exactly 10,000 runs; and each
of the three controls contributes 39 runs and 166 traces.

The audit independently decodes every WMC1 descriptor, recomputes complete wire vectors and
projected outputs, regenerates the fixed-seed corpus byte-for-byte, checks all 512 boundary-gate
traces and all eight negative cases, and requires each JSONL file's runtime BPF program tag to
match the tag captured from its preserved variant object. The suite covers normal,
capacity-control, sentinel-control, and explicit-baseline variants. Each named circuit exhausts
its own finite input set, but the corpus and boundary tests remain regression evidence only: they
do not enumerate the descriptor domain `D_{64,512}`. In particular, the alternating-invocation
regression is not a concurrent stress test and cannot establish the whole-map-set
mutual-exclusion premise of E4-D.

The run includes per-gate raw-return traces, host-run records, an independent oracle audit, and a
self-issued SHA-256 integrity manifest over the source snapshot and generated artifacts. The
manifest detects accidental divergence of files within that recorded run; it is not a signature or
an independent attestation against a writer who can replace the entire manifest and its contents.

**Precision control — separating value ranges from relational certificates.** The numeric case compares
a projection, explicit arithmetic NAND <code>1-a*b</code>, and the extensionally equal expression
<code>[(1+a+b) mod 3 != 0]</code>. The self-contained toy interval analyzer reports the global
Boolean range <code>{0,1}</code> for all three nonconstant cases. That range is exact and therefore
does not distinguish ordinary arithmetic from the modulo implementation or certify any of their
input/output graphs. The separate Frama-C EVA source [18] contains only modulo NAND and a different
mod-7 control; it records <code>{0,1}</code> for modulo NAND, while the mod-7 program yields
<code>{1}</code> only because it computes a different, constant function; it is retained as a
value-range control, not a same-semantics ablation.

The self-contained audit also makes the relational precision choice explicit. It indexes abstract
values by the four Boolean input rows. Ordinary arithmetic transfers preserve those rows, whereas
an intentionally range-only, row-forgetting <code>MOD</code> transfer assigns every possible
residue to every row. Under that toy transfer the explicit NAND graph is certified and the
equivalent modulo NAND graph is not; a congruence-aware <code>MOD</code> transfer or singleton
input partition restores both graphs. On the actual row relation, the range-only transfer gives a
strict over-approximation, while the refined transfer gives equality. This is an operator-specific
result about the artifact's declared toy transfer, not about Frama-C or Linux.

For the reachable accumulator value set <code>X={1,2,3}</code>, the standard non-relational
interval completeness check for modulo still gives equality: direct collection and interval
closure both map to <code>[0,2]</code>. The artifact therefore reports two different facts without
conflating them: global value-range abstraction is exact for this case, while the deliberately
row-forgetting relational transfer loses input/residue association. Neither fact supplies an
independent residual-transducer or Linux system-independence result.

| | analyzer | style | residual candidate `rho_obs` | certified output |
|---|---|---|---|---|
| eBPF witness (§6) | Linux verifier | path-sensitive | map key set/occupancy | local scalar-return `Report_log` observation only; no formal `Report_V` certificate claim |
| toy value-range control | self-contained interval analyzer | join-based, non-relational; three programs | none isolated by this experiment | exact output range `{0,1}`; input/output graph not certified by ranges alone |
| Frama-C range control | EVA | join-based, non-relational; modulo NAND plus mod-7 only | none isolated by this experiment | `{0,1}` for modulo NAND and `{1}` for the different control; graph not certified |
| relational precision audit | self-contained row-indexed toy analyzer | relation-preserving except for declared range-only `MOD` | input/residue association | explicit NAND graph certified; equal modulo NAND graph recovered only after refinement |

The numeric control is not an independent residual-transducer witness, a system-independence
argument, or an eBPF-style exploitability proof. Its role is methodological: it prevents a
full-range output from being misread as proof of standard incompleteness or of a particular hidden
state cause. Frama-C 25.0-beta (Manganese) was rerun on the corrected two-independent-input source
on the VM recorded in `results/env.json`; `eva_slevel0.current.log` reports `{0,1}` for modulo
NAND, `{1}` for the different mod-7 control, and zero alarms. The unchanged historical log is
retained separately. Neither log is evidence for the row-indexed relational toy transfer.

**Strongest alternative interpretation.** The eBPF program uses normal bytecode to select normal,
documented helper operations. The verifier promises a safety property, not a complete input/output
function, so leaving the helper return unknown can be exactly correct for its intended contract.
We agree: the artifact is not evidence of verifier failure, unexpected Boolean expressiveness, or
a LangSec vulnerability. Its evidentiary role is narrower. It shows that post-acceptance runtime
words can have a causal, reusable finite transducer semantics and records a local observation that
would be relevant to a report-factorization test once a report extractor exists. It makes explicit
the extra compiler, certificate, reliability, and policy obligations needed before that observation
becomes a weird-machine security claim.

**Threats to validity.** The eBPF evidence is from the one kernel build and architecture recorded
in `results/env.json`. Hash-map internals and verifier behavior can drift. The tested discipline
requires a dedicated, preallocated, non-LRU gate map and mutual exclusion across the *entire*
shared map set for the whole invocation. Per-CPU spare elements in this implementation support
replacement paths; the more direct threats to this experiment are any concurrent invocation or
host writer, key reuse, reset failure, map-type changes, and version-dependent helper semantics.
Raw return capture audits the tested build but does not create a cross-version errno guarantee.
Truth tables establish the mechanism only for the recorded configuration and cannot enumerate
`D_{64,512}`. The numeric control does not satisfy a demand for an independent residual-transducer
witness.

---

# 8. Related work

**Language-theoretic security and low-level interfaces.** LangSec already treats input-handling
software as an interpreter and input validation as structurally continuous with program
verification [24]-[27]. We therefore do not claim to extend LangSec from parsers to verifiers.
Palmer, Rogers, and Adams further model low-level interfaces as effective languages of buffers,
calls, flags, object references, and state-dependent operations, reconstructing accepted traces
and implementation/specification divergences through object-centric tracing [32]. Their operation-
stream view is close to `W_run`. Our distinct boundary is property-specific program-artifact
acceptance followed by runtime interpretation: we type-separate `L_V`, causal `W_res(P;K_res)`,
observation tuples, and report claims; require joint coverage by an analyzer-computed cell; and
separate resource-bounded programmability from policy-relative weird-machine classification.

**Weird machines: informal and constructive.** Bratus et al. introduced the weird-machine frame
as a way to see exploitation as programming an unintended machine [5]; constructive
demonstrations exposed unintended computation in substrates such as the page-fault handler [6]
and ELF metadata [7]. These works ask what can be computed in a substrate not meant to compute,
typically after or around a defect. Our artifact instead uses documented helper semantics in an
accepted program. It therefore establishes a residual transducer, while the weird-machine label
is conditional on the intended policy and threat model in Definition 10.

**Other substrates and later variants.** Subsequent work broadens the catalog of weird-machine
substrates and patterns. Bratus et al. describe recurring weird-machine patterns across systems
[19], while Anantharaman et al. use *mismorphism* to name the semantic mismatch at the heart of
the phenomenon [20]. More recent systems work moves the hidden machine into microarchitectural
state: Evtyushkin et al. show computation with timing and microarchitectural state [21], and
Wang et al. study weird machines in transient execution [22]. Levy and Maldonado use the weird
machine lens for attack-surface measurement [23]. These papers reinforce that hidden or
under-specified state is a recurring substrate; our contribution is to isolate a typed residual
word interface and its analyzer-computed coverage at a program-verification boundary.

**Weird machines as insecure compilation.** Paykin et al. cast weird machines as insecure
compilation: an exploit is a target-context behavior no source context can produce, and a
compiler is exploit-free iff it preserves robust hyperproperties [10]. Their boundary is source
language versus target language; ours is an accepted-artifact analysis report versus concrete
runtime behavior. Their policy comparison also motivates Definition 10: a weird-machine claim
needs an intended semantic boundary, not merely analyzer imprecision.

**A particularly close antecedent.** Vanegue's study of weird machines in proof-carrying code
observes that when a proof system's abstraction fails to capture
untrusted computation, a shadow execution can arise, and the machine abstraction becomes one
such opportunity [8]. We regard our contribution as a LangSec-style formalization of this
observation: residual word semantics and computed report coverage make the boundary testable, and
the resource-bounded theorem states when a uniform residual gate composes. Vanegue's later
adversarial logic gives an under-approximate proof system for exploitability [11]; it is
complementary to ours, which concerns report non-factorization under a sound over-approximation rather
than the discovery of true attack paths.

**Completeness and relational security analyses.** The precision taxonomy uses the theory of completeness:
Giacobazzi, Ranzato, and Scozzari characterize when an abstraction is complete for an operation
and construct the complete shell and core [2]; Bruni et al. localize completeness to fragments
and build a logic that reasons about correctness and incorrectness together [3], with follow-up
work quantifying partial incompleteness [4]. We do not equate an unresolved predicate with failure
of their completeness equation. Abstract Non-Interference formalizes information-flow properties
relative to observer abstractions [29]; abstract-interpretation accounts of opacity analyze what
an observer can infer [30]; and hypercollecting semantics lifts static analysis to sets of sets for
information-flow hyperproperties [31]. Our Q-certificate definition is narrower: it asks whether a
particular analyzer report theory entails a finite program graph. A full comparison or reusable
hyperproperty analyzer remains future work.

**eBPF verification.** eBPF is our witness, not the theoretical source of the paper. PREVAIL is a
separate abstract interpreter with its own soundness argument [12]. Tristate-number work proves
properties of the tnum domain and operations used in eBPF analyses [13]. These results do not
amount to an end-to-end proof of the production verifier in the artifact's kernel build, which is
why Theorem 1 takes safety soundness as an assumption. Systems such as MOAT isolate potentially
malicious BPF programs using Intel MPK [28]. That line is complementary: MOAT hardens execution after verifier acceptance,
whereas our question is which stateful runtime distinctions remain outside a selected analyzer
report after acceptance.

# 9. Outlook: Toward a LangSec Shape Theorem

The long-term goal is a theorem about the *shape* of a declared recognizer/runtime boundary, not
a theorem that every incomplete recognizer is defective. Section 5 gives a bounded sufficiency
direction once E1--E3, E4-D, and, for a weird-machine classification, `(M,T)` are supplied. The
eBPF source construction targets E4-D for one fixed interpreter and `D_{64,512}`; its fresh
execution evidence is recorded in `interpreter-v1-20260710-02`. It does not establish artifact-
parametric macro closure E4-A, a complete verifier report theory, or a policy violation. The
conditional opacity theorem additionally requires a report-theory extractor and persistent-
alternative certificate, neither of which is discharged for Linux.

## 9.1 Why sound-but-incomplete does not imply a weird machine

The unrestricted necessity claim is false. The following superficially plausible arrows all fail:

`safety soundness plus rejected safe artifacts`
`↛ report-relative residual observation`
`↛ uniformly controllable residual basis`
`↛ resettable, budget-composable transducer`
`↛ behavior excluded by intended policy M under threat model T`.

Simple countermodels witness each break. A recognizer may accept only `skip` and reject another
safe constant program; it is sound and acceptance-incomplete, but its accepted language has no
residual operations. An abstract domain may forget reachable hidden state while every accepted
continuation has one constant visible output. A destructive readout may expose one residual bit
but provide no reset, so it is not a reusable basis. Finally, a documented NAND accelerator can
be programmable while explicitly allowed by `M`, so it is not a weird machine. Standard abstract-
interpretation incompleteness, acceptance incompleteness, report uncertainty, residual
programmability, and policy violation must therefore remain separate predicates.

For a strict standard-completeness countermodel, take concrete states `{0,1,2}`, partition blocks
`B0={0,1}` and `B1={2}`, and transformer `f(0)=0`, `f(1)=f(2)=2`. For `X={0}`,
`α(f(X))={B0}` but `α(f(γ(α(X))))={B0,B1}`. Thus the completeness equality is
strict. If every program-visible observation is nevertheless the constant `0`, then `R_res` is
empty for that observer. Even genuine transformer incompleteness therefore does not supply a
residual observation.

## 9.2 Open Problem 1: a SIRP conjecture schema

The local resource algebra is not conjectural: Proposition 4 proves NAND once rank-`k-1` reset,
freshness, and the existing/fresh update laws are supplied. What remains open is whether a useful,
independently characterized class of *shape-local recognizer families* preserves that local gate
and its report collision under capture-avoiding resource-name renaming and disjoint macro composition.

Consider a budget-indexed family `(V_B,I,α_B,K_B)` with these local premises: (i) one
saturating-rank gate macro and the wire operations are individually accepted; (ii) the resource
semantics and bit-to-existing/fresh encoding satisfy Proposition 4; (iii) at the isolated second-
update frontier, reachable rank-`k-1` and rank-`k` states share the suffix context and one computed
cell; and (iv) the analyzer's resource summaries and transfers are invariant under fresh-name
renaming and separable across disjoint resource instances. These premises do **not** assume that
arbitrary macro compositions are accepted.

Call a gate invocation *active* when two reachable primary-input valuations lead, immediately
before its second update, to the rank-`k-1` and rank-`k` states with the same suffix context. Let
the verifier budget range over `B in N^d`, with componentwise order; fixed vectors
`b0,bg,bw in N^d` represent setup, one gate macro, and one wire operation.

The terms *shape-local*, *separable*, and *report embedding* do not yet have a complete semantic
definition in this paper. Accordingly, the following is deliberately a conjecture schema/open
problem, not a well-formed theorem claimed as a result.

> **Conjecture Schema 1 (Shape-Induced Residual Programmability, SIRP macro-closure).** After
> defining a semantic class that satisfies the four local premises above, determine whether every
> family in that class admits fixed resource vectors `b0,bg,bw` and a capture-avoiding fresh-name renaming construction
> such that substituting `n` disjoint gate macros and `r` explicit copy/fan-out operations into an
> acyclic Boolean wiring skeleton preserves acceptance whenever
> `b0+n bg+r bw <=_componentwise B`. Moreover,
> the isolated jointly covered behavioral pair embeds into the computed report at every active
> gate instance. If Lemma 2's routing correctness and concrete residual-noninterference hypotheses
> also hold, Proposition 4 and schedule induction then yield an accepted residual NAND
> implementation for each such skeleton, and every active gate retains a cell-level behavioral-
> factorization collision.

The nontrivial content is the macro-closure and report-embedding claim; neither is hidden in the
premises. A context-sensitive analyzer may use surrounding paths or earlier wires to split the
local pair, and verifier analysis cost need not be additive. A proof must therefore define
“shape-local” as a semantic class, derive both closure properties, and then show that a production
verifier family belongs to it. The present paper proves none of those steps and does not claim that
the fixed Linux artifact instantiates the conjecture.

The conjecture concerns budgeted residual transducers only, not a weird machine, whole-program
certificate opacity, or standard abstract-interpretation incompleteness. If proved, its result
would be contract-shape-induced for implementations conforming to that report shape; patching an
accidental defect would not remove it, whereas refining `α_B` or `Report`, or restricting `I`,
changes the contract and can. The current `CAP(2)` construction supplies one local gate witness
and a bounded data-parametric interpreter, not the conjectured artifact-family closure or a
policy violation.

## 9.3 What complete shells and Rice can—and cannot—add

Complete-shell theory [2] can characterize, in the stated abstract-domain order, the most abstract
complete refinement of an abstraction
for a specified family of transformers. Applied observer-relatively, it may identify the semantic
distinctions a report must add to make `beta_D` factor through the report. The required shell may
be too large or noncomputable, however, and completeness for selected transformers does not create
accepted control, observation, reset, routing, or an attacker-relevant policy violation. The first
research step is therefore to relate Proposition 2's behavioral quotient to a shell parameterized
by the allowed continuation and observer family, then prove a lower bound on the report refinement
needed to separate the relevant quotient classes.

Rice's theorem rules out a total decider for a nontrivial extensional property over an appropriate
Turing-complete semantics [33]. It does not apply directly to the fixed, resource-bounded eBPF
experiments in this paper. Even in a Turing-complete setting it would establish an undecidability
boundary, not that false negatives create accepted residual state, not that the state is observable
or resettable, and not that a policy is violated. The missing bridge is constructive: derive a
reachable behavioral collision, then an E1--E3/E4-D toolkit, from an explicitly stated family of report
shapes and runtime algebras.

A proof program therefore has four stages: (i) define an observer-relative complete shell for the
continuation family; (ii) prove a finite-report or resource lower bound that forces a behavioral
collision under the shape hypotheses; (iii) construct uniform macros and a verified budgeted
compiler; and (iv) add robust reachability plus `(M,T)` to obtain a genuine weird-machine theorem.

## 9.4 From a residual transducer to an exploitable weird machine

In a closed offline experiment, such as `BPF_PROG_TEST_RUN` with a dedicated gate map and an
externally enforced global critical section, uncontrolled state is reduced; in a live system,
scheduling, concurrency, shared maps, allocator state, or unrelated writers can perturb the
residual component. A future exploitability theorem needs reliability, not merely reachability,
and an intended-policy criterion, not merely report uncertainty.

Robust reachability [15], [16] is a promising language for this half of the problem: it asks
whether a controlled choice reaches the desired branch for all uncontrolled choices. A full
theorem would connect E1--E3/E4-D to a robust-reachability condition over the controlled/uncontrolled
split of the host system and then show violation of `M` under `T`. Until then, even a successful
fresh interpreter run would be only bounded residual-transducer evidence under its stated
premises, not a weird-machine security result.

## 9.5 Why the numeric control remains useful

The numeric case is useful because it demonstrates a common evidentiary mistake. A join-based
analysis can return the full Boolean range while being exact about that range, and the same report
can arise for explicit NAND, modulo NAND, and a projection. Such output is insufficient to locate
the cause of missing relational certification. This negative result motivated Definition 6's
expressibility and common-extractor requirements.

A genuine independent witness would need a specified relational vocabulary, an explicit
implementation whose graph that vocabulary certifies, a residual implementation of the same
concrete function that it does not certify, and a precision refinement that restores the graph.
Until such evidence exists, generality rests on the formal conditional statements, not on counting
the numeric control as a second system instance.

# 10. Limitations

The eBPF evidence is from one kernel build and architecture, so portability remains unestablished.
The numeric case is a methodological control, not a second residual-transducer witness. Safety
soundness of the production verifier is assumed rather than proved end to end. The Linux log is a
local scalar-return observation, not a formal `Report_V` or proof of a jointly covered cell; a
Definition 5/Proposition 3 instantiation would require the declared `Report_log` interpretation
and local coverage and transfer-soundness proofs described in Section 6. Theorem 1 covers one
fixed interpreter under its explicit acceptance premise and the `D_{64,512}` host-configuration
domain; it is not a theorem that every descriptor is verifier-recognized, nor an E4-A macro-
closure theorem for generated BPF artifacts. Theorem 2 is conditional on an extractor and
persistent-alternative certificate that the artifact does not supply. Whole-invocation mutual exclusion across the
entire shared map set is essential: another invocation or any host writer is outside the theorem
and experiments. The audited `interpreter-v1-20260710-02` result is finite regression evidence,
not a universal enumeration. Named-circuit tests, bounded random corpora, and a deep boundary case are not an
enumeration of `D_{64,512}`. Open Problem 1's macro-closure is unresolved, and the unrestricted
sound-but-incomplete necessity claim is false. The work is bounded and combinational, not
Turing-complete. Finally, no intended deployment policy or attacker-relevant effect is
demonstrated, so Definition 10's weird-machine classification is not claimed for the offline
experiment.

# 11. Conclusion

LangSec teaches that acceptance is meaningful only relative to a recognized language and property.
At a program-verifier boundary, acceptance need not be semantic closure: an artifact in `L_V` may
still drive runtime words in `W_run(P)`, some of which enter the causal residual language
`W_res(P;K_res)`. On its stated context fiber, Proposition 2 gives the exact observer-relative
test: the selected report has no cell-level collision exactly when future behavior factors through
its computed cells. A report-relative non-factorization arising under documented semantics and
that fixed report shape is contract-shape-induced; it is not an implementation bug,
although changing the abstraction, report, or runtime contract can remove it.

The eBPF construction targets this residual-transducer layer through a dedicated map's key-
set/occupancy and helper success predicate, including a NAND truth table and one fixed interpreter.
Under the explicit `P_U in L_V` premise, it consumes the bounded host-to-map circuit ABI. The
descriptor `d` is not a runtime word: `Enc_U(d,x)` is the map configuration and `Sched_U(d,x)` is
the resulting runtime schedule.
The construction does not witness a four-state minimal quotient, artifact-parametric compiler
closure, global Linux certificate opacity, or a policy violation. E1--E3 plus E4-D and the frame
discipline are sufficient for bounded data-parametric realization; certificate opacity needs a
persistent alternate model; and weird-machine status additionally needs `(M,T)`. Soundness or
incompleteness alone supplies none of these bridges. Conjecture Schema 1 states the narrower
structural question worth pursuing with observer-relative complete shells, resource lower bounds,
and robust reachability. That layered result—not the false universal slogan—is the paper's LangSec
claim.

---

## Ethics and disclosure

**Ethics.** All experiments run in an isolated local VM. The artifact attaches no program to a
live network path, targets no third-party system, and attempts no privilege escalation, memory
corruption, or verifier bypass. It uses legal helper calls and bounded execution to study the
gap between verifier-level abstractions and runtime map-metadata transitions. The work is
defensive in orientation: it characterizes a precision boundary in one verifier report so that
analyzer designers can state and test which semantic relations their boundary intends to certify.

**Data availability.** All code, build variants, verifier logs, xlated disassembly, raw-return
records, and result datasets are in the accompanying repository. The regeneration suite emits a
self-issued SHA-256 integrity manifest and the audit validates its file hashes before interpreting
the recorded semantic results; this is an accidental-drift check, not a signed provenance claim.

**Submission disclosure note.** If the target venue requires AI-use reporting, disclose in the
submission metadata or cover letter that an AI writing pipeline assisted with structuring,
drafting, and literature positioning. The authors remain responsible for all technical claims,
the artifact, the formal statements, and final bibliographic verification.

**Conflicts of interest.** None declared.

---

## References

[1] P. Cousot and R. Cousot, "Abstract interpretation: a unified lattice model for static
analysis of programs by construction or approximation of fixpoints," in *Proceedings of the 4th
ACM SIGACT-SIGPLAN Symposium on Principles of Programming Languages (POPL '77)*, pp. 238-252,
1977, doi:10.1145/512950.512973.

[2] R. Giacobazzi, F. Ranzato, and F. Scozzari, "Making abstract interpretations complete,"
*Journal of the ACM*, vol. 47, no. 2, pp. 361-416, 2000, doi:10.1145/333979.333989.

[3] R. Bruni, R. Giacobazzi, R. Gori, and F. Ranzato, "A logic for locally complete abstract
interpretations," in *2021 36th Annual ACM/IEEE Symposium on Logic in Computer Science (LICS)*,
pp. 1-13, 2021, doi:10.1109/LICS52264.2021.9470608.

[4] M. Campion, M. Dalla Preda, and R. Giacobazzi, "Partial (in)completeness in abstract
interpretation: limiting the imprecision in program analysis," *Proceedings of the ACM on
Programming Languages*, vol. 6, no. POPL, pp. 1-31, 2022, doi:10.1145/3498721.

[5] S. Bratus, M. E. Locasto, M. L. Patterson, L. Sassaman, and A. Shubina, "Exploit
programming: from buffer overflows to weird machines and theory of computation," *USENIX
;login:*, vol. 36, no. 6, pp. 13-21, 2011.

[6] J. Bangert, S. Bratus, R. Shapiro, and S. W. Smith, "The Page-Fault Weird Machine: Lessons
in Instruction-less Computation," in *7th USENIX Workshop on Offensive Technologies (WOOT 13)*,
Washington, DC, USA, Aug. 2013.

[7] R. Shapiro, S. Bratus, and S. W. Smith, "'Weird Machines' in ELF: A Spotlight on the
Underappreciated Metadata," in *7th USENIX Workshop on Offensive Technologies (WOOT 13)*,
Washington, DC, USA, Aug. 2013.

[8] J. Vanegue, "The Weird Machines in Proof-Carrying Code," in *2014 IEEE Security and Privacy
Workshops*, pp. 209-213, 2014, doi:10.1109/SPW.2014.37.

[9] T. Dullien, "Weird machines, exploitability, and provable unexploitability," *IEEE
Transactions on Emerging Topics in Computing*, vol. 8, no. 2, pp. 391-403, 2020,
doi:10.1109/TETC.2017.2785299.

[10] J. Paykin, E. Mertens, M. Tullsen, L. Maurer, B. Razet, A. Bakst, and S. Moore, "Weird
Machines as Insecure Compilation," arXiv:1911.00157, 2019.

[11] J. Vanegue, "Adversarial Logic," in *Static Analysis*, LNCS 13790, pp. 422-448, Springer,
2022, doi:10.1007/978-3-031-22308-2_19.

[12] E. Gershuni, N. Amit, A. Gurfinkel, N. Narodytska, J. A. Navas, N. Rinetzky, L. Ryzhyk, and
M. Sagiv, "Simple and precise static analysis of untrusted Linux kernel extensions," in
*Proceedings of the 40th ACM SIGPLAN Conference on Programming Language Design and
Implementation (PLDI '19)*, pp. 1069-1084, 2019, doi:10.1145/3314221.3314590.

[13] H. Vishwanathan, M. Shachnai, S. Narayana, and S. Nagarakatte, "Sound, precise, and fast
abstract interpretation with tristate numbers," in *2022 IEEE/ACM International Symposium on
Code Generation and Optimization (CGO)*, pp. 254-265, 2022, doi:10.1109/CGO53902.2022.9741267.

[14] J. Jia, R. Qin, M. Craun, E. Lukiyanov, A. Bansal, M. V. Le, H. Franke, H. Jamjoom,
T. Xu, and D. Williams, "Safe and usable kernel extensions with Rex," arXiv:2502.18832, 2025.

[15] G. Girol, B. Farinier, and S. Bardin, "Not All Bugs Are Created Equal, But Robust
Reachability Can Tell the Difference," in *Computer Aided Verification (CAV 2021)*, pp. 669-693,
2021, doi:10.1007/978-3-030-81685-8_32.

[16] Y. Sellami, G. Girol, F. Recoules, D. Couroussé, and S. Bardin, "Inference of Robust
Reachability Constraints," *Proceedings of the ACM on Programming Languages*, vol. 8, no. POPL,
pp. 2731-2760, 2024, doi:10.1145/3632933.

[17] M. Campion, C. Urban, M. Dalla Preda, and R. Giacobazzi, "A Formal Framework to Measure the
Incompleteness of Abstract Interpretations," in *Static Analysis*, LNCS 14284, pp. 114-138,
Springer, 2023, doi:10.1007/978-3-031-44245-2_7.

[18] F. Kirchner, N. Kosmatov, V. Prevosto, J. Signoles, and B. Yakobowski, "Frama-C: A software
analysis perspective," *Formal Aspects of Computing*, vol. 27, no. 3, pp. 573-609, 2015,
doi:10.1007/s00165-014-0326-7.

[19] S. Bratus, J. Bangert, A. Gabrovsky, A. Shubina, M. E. Locasto, and D. Bilar, "'Weird
Machine' Patterns," in *Cyberpatterns*, C. Blackwell and H. Zhu, Eds., pp. 157-171, Springer,
2014, doi:10.1007/978-3-319-04447-7_13.

[20] P. Anantharaman, V. Kothari, J. P. Brady, I. R. Jenkins, S. Ali, M. C. Millian, R. Koppel,
J. Blythe, S. Bratus, and S. W. Smith, "Mismorphism: The Heart of the Weird Machine," in
*Security Protocols XXVII*, LNCS 12287, pp. 113-124, Springer, 2020,
doi:10.1007/978-3-030-57043-9_11.

[21] D. Evtyushkin, T. Benjamin, J. Elwell, J. A. Eitel, A. Sapello, and A. Ghosh, "Computing
with time: microarchitectural weird machines," in *Proceedings of the 26th ACM International
Conference on Architectural Support for Programming Languages and Operating Systems (ASPLOS
'21)*, pp. 758-772, 2021, doi:10.1145/3445814.3446729.

[22] P.-L. Wang, F. Brown, and R. S. Wahby, "The ghost is the machine: Weird machines in
transient execution," in *2023 IEEE Security and Privacy Workshops (SPW)*, pp. 264-272, 2023,
doi:10.1109/SPW59333.2023.00029.

[23] M. Levy and F. Maldonado, "Attack Surface Measurement: A Weird Machines Perspective," in
*European Interdisciplinary Cybersecurity Conference (EICC 2024)*, pp. 90-94, 2024,
doi:10.1145/3655693.3655705.

[24] L. Sassaman, M. L. Patterson, S. Bratus, and M. E. Locasto, "Security Applications of
Formal Language Theory," *IEEE Systems Journal*, vol. 7, no. 3, pp. 489-500, 2013,
doi:10.1109/JSYST.2012.2222000.

[25] F. Momot, S. Bratus, S. M. Hallberg, and M. L. Patterson, "The Seven Turrets of Babel: A
Taxonomy of LangSec Errors and How to Expunge Them," in *2016 IEEE Cybersecurity Development
(SecDev)*, pp. 45-52, 2016, doi:10.1109/SecDev.2016.019.

[26] L. Sassaman, M. L. Patterson, and S. Bratus, "A Patch for Postel's Robustness Principle,"
*IEEE Security & Privacy*, vol. 10, no. 2, pp. 87-91, 2012, doi:10.1109/MSP.2012.31.

[27] S. Ali, P. Anantharaman, Z. Lucas, and S. W. Smith, "What We Have Here Is Failure to
Validate: Summer of LangSec," *IEEE Security & Privacy*, vol. 19, no. 3, pp. 17-23, 2021,
doi:10.1109/MSEC.2021.3059167.

[28] H. Lu, S. Wang, Y. Wu, W. He, and F. Zhang, "MOAT: Towards Safe BPF Kernel Extension,"
in *33rd USENIX Security Symposium (USENIX Security 24)*, pp. 1153-1170, 2024,
https://www.usenix.org/conference/usenixsecurity24/presentation/lu-hongyi.

[29] R. Giacobazzi and I. Mastroeni, "Abstract non-interference: parameterizing
non-interference by abstract interpretation," in *Proceedings of the 31st ACM SIGPLAN-SIGACT
Symposium on Principles of Programming Languages (POPL '04)*, pp. 186-197, 2004,
doi:10.1145/982962.964017.

[30] I. Mastroeni and M. Pasqua, "Verifying opacity by abstract interpretation," in
*Proceedings of the 37th ACM/SIGAPP Symposium on Applied Computing (SAC '22)*, pp. 1817-1826,
2022, doi:10.1145/3477314.3507119.

[31] M. Assaf, D. A. Naumann, J. Signoles, E. Totel, and F. Tronel, "Hypercollecting semantics
and its application to static analysis of information flow," in *Proceedings of the 44th ACM
SIGPLAN Symposium on Principles of Programming Languages (POPL '17)*, pp. 874-887, 2017,
doi:10.1145/3009837.3009889.

[32] I. Palmer, E. Rogers, and R. Adams, "Object-centric Tracing for Language-Theoretic Security
in Low-Level Interfaces," in *Twelfth Workshop on Language-Theoretic Security (LangSec), IEEE
Security and Privacy Workshops*, 2026,
https://langsec.org/spw26/papers/palmer-object-tracing.pdf.

[33] H. G. Rice, "Classes of recursively enumerable sets and their decision problems,"
*Transactions of the American Mathematical Society*, vol. 74, no. 2, pp. 358-366, 1953,
doi:10.2307/1990888.
