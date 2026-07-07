# Residual Semantic Languages: Weird Machines Inside Recognized Safety Languages

# Abstract

Language-theoretic security treats security boundaries as language boundaries: a recognizer
accepts a language, and downstream computation should act only on recognized structure. This
paper extends that lens from parsers and protocol processors to program verifiers. A verifier can
soundly recognize a *safety language* while the concrete runtime still interprets a
program-visible *residual semantic language*. Acceptance closes the safety boundary, but it need
not close the semantic boundary consumed by the runtime.

We formalize this recognizer/interpreter mismatch for sound verifiers. Let `V` recognize a safety
language `L_V`, let `I` be the concrete interpreter for accepted programs, and let `α` denote the
state and trace abstractions through which `V` observes behavior. The residual semantic language
of an accepted program is a frontier-local, observation-labeled relation over residual words: the
runtime can distinguish the words, but the recognizer's trace abstraction identifies them. Our
main result is a LangSec-style sufficient condition split into two claims. First, if the accepted
toolkit inside `L_V` supplies a controllable, observable, resettable, composable, and
functionally complete residual transducer basis, then for every finite Boolean circuit `C` there
is an accepted bounded program instance `P_C in L_V` whose concrete execution computes `C`.
Second, under an additional local gate-opacity condition excluding recognizer-visible shadow logic, the
recognizer cannot certify the corresponding input-output graph.

This is not a vulnerability report; it is a recognizer-boundary witness in eBPF. The Linux eBPF
verifier recognizes memory-safe, bounded, helper-safe bytecode; the
concrete map/helper runtime also interprets dynamic map occupancy, a state component absent from
the verifier abstraction. We show that map occupancy and helper return symbols form a finite-state
residual transducer implementing NAND. The witness is verifier-accepted, memory-safe, bounded,
and does not rely on any known verifier unsoundness, memory corruption, or privilege-escalation
bug. Ablations and an explicit-logic baseline show that the computation is carried by residual
runtime semantics rather than ordinary bytecode logic. A second interval-analysis witness supports
the claim that the phenomenon tracks sound-but-incomplete recognition rather than an eBPF quirk.

**Keywords:** language-theoretic security, recognizers, residual semantic languages, weird
machines, abstract interpretation, completeness, eBPF, verifier-opaque computation.

---

# 1. Introduction

Language-theoretic security (LangSec) treats security boundaries as language boundaries: an
input processor should recognize a well-defined language before any downstream computation acts
on it [24], [25]. The familiar examples are parsers, protocol processors, and file-format
validators, where insecurity appears when later machinery consumes structure the recognizer did
not precisely accept. Program verification has the same shape. A verifier recognizes a language
of acceptable program artifacts, rejects artifacts outside that language, and then hands accepted
artifacts to a concrete interpreter. The crucial LangSec question is therefore not only *what does
the verifier accept?* but also *what language does the runtime still interpret after acceptance?*

This paper answers that question for sound program verifiers. We argue that safe recognition is
not semantic recognition. A verifier may soundly recognize a safety language--for example,
programs that do not access memory out of bounds, do not loop forever, and call helpers with
well-typed arguments--while still erasing concrete runtime state that accepted programs can
observe, reset, and compose. When that erased state forms a program-visible transducer, the
accepted language contains a hidden interpreter: a weird machine inside the recognized safety
language, relative to the recognizer's abstraction.

Our central object is the **residual semantic language**. Given a recognizer `V`, an accepted
program `P`, a concrete interpreter `I`, and the recognizer abstraction `α`, the residual semantic
language `L_res(P, α)` is an observation-labeled relation over residual operation words: the
runtime and program can distinguish observations that the trace abstraction `α_T` identifies. In
LangSec terms, the recognizer has accepted a safety language while leaving an additional semantic
sublanguage inside accepted inputs. In abstract-interpretation terms, this is an incompleteness
witness whose outputs remain program-visible.

This reframing changes the role of eBPF in the paper. eBPF is not the theoretical source of the
result; it is the witness. The Linux eBPF verifier is one of the most consequential deployed
program recognizers: it gates untrusted bytecode into the kernel by abstract interpretation and
rejects anything it cannot prove safe [12], [13]. Its guarantee is *soundness for safety*.
What it does not promise is complete recognition of all program-visible semantics. Dynamic hash
map occupancy is one such residual state component: the verifier tracks map identity and static
attributes, but not the number of live entries. The concrete map/helper runtime does interpret
that number, and helper return codes expose it to accepted programs.

## 1.1 Safe recognition is not semantic recognition

A conventional weird machine is often presented as the residue of a defect: a malformed input,
parser differential, memory-corrupting input, or metadata quirk drives an implementation into an
unintended state space that an attacker can program [5]-[7], [9], [10]. Our phenomenon is
different. The recognizer is not unsound. The program is accepted. Nothing is corrupted. The
computation lives in a concrete residual state component that the recognizer deliberately does
not model because that component is irrelevant to the safety property being recognized.

This distinction matters for defense. A weird machine born of a parser bug or memory-corruption
bug is closed by fixing that bug. A weird machine born of residual semantics is closed only by
changing the recognized language or the abstraction through which program-visible semantics are
recognized. In LangSec terms, the boundary is not merely syntactic validity versus invalidity;
it is the boundary between the recognizer-visible language and the runtime-interpreted residual
language.

## 1.2 From abstraction gaps to residual languages

An abstraction gap alone is not enough. Prior informal statements of this idea--most directly
Vanegue's proof-carrying-code account of abstractions that leave untrusted computation outside
the proof model [8]--identify the opportunity, but not the operational conditions that turn the
opportunity into a programmable machine. We separate two sides:

- A **recognizer-side condition**: a concrete operation depends on runtime state that `α` erases,
  and its program-visible result is mapped to an abstract value or trace summary that cannot
  decide the readout predicate. This is the residual semantic language.

- A **toolkit-side condition**: accepted operations can control, observe, reset, and compose the
  residual state so that it behaves as a reusable transducer basis.

Given both sides, plus functional completeness of the induced gate, the accepted language contains
a family of bounded program instances realizing arbitrary finite Boolean circuits. If, in
addition, the residual schedule is gate-opaque--that is, no recognizer-visible shadow computation
certifies the same local gate relation--then the recognizer's certified abstraction does not
entail the corresponding input-output graph.

## 1.3 Contributions

1. **Residual semantic languages.** We define residual semantic languages as runtime-interpreted
   behavior that is collapsed by a recognizer's abstraction but remains program-visible inside
   accepted inputs.

2. **A LangSec-style sufficient condition.** We state a recognizer-boundary theorem pair: a
   controllable, observable, resettable, and composable residual transducer basis inside an
   accepted language realizes finite Boolean circuits; with an additional local gate-opacity condition
   excluding recognizer-visible shadow logic, those circuits remain opaque to the recognizer's
   certified input-output relations.

3. **An eBPF recognizer/interpreter witness.** We instantiate the theorem in eBPF, treating the
   verifier as a recognizer for a safety language and the map/helper runtime as a concrete
   interpreter. The construction is verifier-accepted, memory-safe, bounded, and does not
   rely on any known verifier unsoundness, memory corruption, or privilege-escalation bug.

4. **A residual gate-language artifact.** We implement a finite-state residual gate language
   using map occupancy and helper return symbols, validate the NAND truth table and bounded
   composition, and provide ablations showing that the computation is carried by residual
   runtime semantics rather than explicit bytecode logic.

5. **A bridge to abstract-interpretation completeness.** We connect the LangSec residual-language
   view to completeness for abstract interpretation [2]-[4], [17], framing the next theoretical
   step as a boundary theorem for which abstractions necessarily admit program-visible residual
   languages.

Scope matters. This paper does not claim that eBPF is newly computationally expressive, that the
verifier is unsound, that a CVE exists, or that every abstraction gap yields a weird machine. The
claim is conditional: an accepted safety language whose toolkit contains a controllable,
observable, resettable, composable, and functionally complete residual basis contains a family of
bounded program instances; under the additional local gate-opacity condition, those instances are
verifier-opaque for the computed relation.

# 2. Background: Recognizers, Weird Machines, and Abstract Semantics

## 2.1 Language boundaries and recognizers

LangSec views insecurity as a failure to recognize the language actually consumed by a system:
input processors should accept a precise language, reject inputs outside it, and ensure later
computation operates only on recognized structure [24]-[26]. We use *recognizer* broadly. A
recognizer may be a parser for a file format, a validator for a protocol message, or a verifier
for program artifacts. In each case, it defines an accepted language and a boundary between what
has been recognized and what downstream machinery may still interpret.

For program verifiers, the recognized language is property-specific. A verifier can soundly
recognize a safety language without recognizing every semantic distinction the concrete runtime
will later interpret. This paper studies exactly that case: safety recognition succeeds, but a
program-visible residual semantic language remains.

## 2.2 Abstract interpretation, soundness, and completeness

An abstract interpreter approximates a concrete transition system over states `Σ`. For an
operation `op`, write its collecting concrete transformer as `T_op : P(Σ) -> P(Σ)` and its
abstract transformer as `T#_op : A -> A`, connected by a Galois connection
`(α : P(Σ) -> A, γ : A -> P(Σ))` [1]. **Soundness** requires each abstract transfer to
over-approximate its concrete counterpart:

`α(T_op(X)) <= T#_op(α(X))` for all `X subseteq Σ`.

For individual states we write `σ0 ≡_α σ1` as shorthand for `α({σ0}) = α({σ1})`. For finite
traces, `α_T` denotes the pointwise/event-level lift of the state abstraction to trace summaries;
when the lifted domain is clear from context, we write `α` for the appropriate state or trace
abstraction. Soundness alone is cheap: a very coarse abstract value can be sound while certifying
no precise semantic relation.

**Completeness** asks whether the abstraction loses no information relevant to an operation:

`α(T_op(X)) = α(T_op(γ(α(X))))` for all `X subseteq Σ` [2].

Giacobazzi, Ranzato, and Scozzari showed that completeness is a property of the abstraction and
the operation together, and gave constructive characterizations of complete shells and cores [2].
Later work localized and quantified incompleteness [3], [4], [17]. We use this theory as the
mathematical account of why a recognizer can be sound for a safety language while incomplete for
program-visible semantics.

## 2.3 The eBPF verifier as a safety recognizer

The Linux eBPF verifier statically checks untrusted bytecode before it runs in the kernel [12].
It performs a symbolic pass over registers and stack slots, tracking pointer types, scalar
ranges, map-value regions, and a tristate-number known-bits abstraction refined by intervals
[13]. Prior eBPF verification work formalizes the verifier and its domains as sound safety
analyses: they may reject safe programs, but they should not accept unsafe ones [12], [13].

In the language of this paper, the verifier recognizes a safety language `L_V`: accepted eBPF
program artifacts that satisfy the verifier's memory-safety, bounded-control-flow, and helper-use
rules. The concrete interpreter is the Linux eBPF runtime plus helper and map implementations.
The verifier abstraction represents each map's identity and static attributes--type, key/value
size, and `max_entries`--but has no component for dynamic hash-map occupancy. Occupancy is a
concrete runtime state interpreted by helpers and observable through return symbols, but it is
not part of the recognizer-visible language.

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

Our contribution is a recognizer-theoretic sufficient condition: a weird machine arises when an
accepted language contains a program-visible residual semantic language with a reusable
transducer basis.

---

# 3. Residual Semantic Languages

We model a recognizer boundary by a tuple `(V, I, α)`: `V` is the recognizer, `I` is the concrete
interpreter for accepted artifacts, and `α` is the abstraction family through which `V` observes
or summarizes concrete behavior. We use `α` for state abstractions and `α_T` for their trace-level
lifts when the distinction matters.


**Figure 1. Recognizer-visible language and runtime-interpreted residual language.**

```text
program artifact P
      |
      |  V accepts
      v
recognized safety language L_V
      |
      |  concrete interpreter I executes accepted P
      v
concrete traces Tr_I(P) -------------------- α_T --------------------> Tr_α(P)
      |
      | residual words w in Σ_res(P)^*
      v
program-visible observations o
      |
      | same abstract trace, different concrete observations
      v
residual semantic language L_res(P, α)  -->  residual transducer / weird machine
```

Figure 1 is the LangSec boundary shift studied here. The recognizer accepts `P` into the safety
language `L_V`, but the concrete interpreter may still consume residual operation words whose
observations are collapsed by `α_T`. A residual weird machine exists only when that collapsed
residual language is also controllable, observable, resettable, and composable by accepted
programs.

> **Definition 1 (recognizer language).** Let `V` be a verifier or recognizer over program
> artifacts `Σ_P*`. The language accepted by `V` is
>
> `L_V = { P in Σ_P* | V(P) = accept }`.
>
> We call `L_V` the safety language recognized by `V` when acceptance certifies a safety
> property such as memory safety, bounded control flow, or well-typed helper use.

> **Definition 2 (concrete and abstract trace languages).** For `P in L_V`, let `Tr_I(P)` be
> the set of concrete traces generated by executing `P` under interpreter `I`. The abstract
> trace language visible to the recognizer is
>
> `Tr_α(P) = { α_T(τ) | τ in Tr_I(P) }`.
>
> For a finite state trace `τ = <σ0, ..., σn>`, we use the pointwise lift
> `α_T(τ) = <α_S(σ0), ..., α_S(σn)>`. If traces also carry recognized instruction or event
> labels, `α_T` preserves those labels and applies `α_S` to the state components. This is the
> formal sense in which two concrete traces can be abstract-trace equivalent.

> **Definition 3 (frontier-local residual semantic language).** For `P in L_V`, let
> `Σ_res(P)` be the alphabet of accepted, program-controllable residual operations available
> inside `P`. At a recognized frontier, write a concrete state as `σ = (pc, x, r, η)`, where
> `pc` is the program point, `x = X(σ)` is the program-visible explicit state, `r` is the
> residual runtime component erased by the recognizer abstraction, and `η` is other recognized
> state. Let `K(σ)` be the recognizer-visible abstraction of the explicit state and other
> recognized facts at that frontier. The corresponding recognized frontier fiber is
>
> `F_{pc,a,κ} = { σ in Reach(P) | pc(σ)=pc, α_S(σ)=a, K(σ)=κ }`.
>
> Concrete program-visible explicit states may differ inside `F_{pc,a,κ}` unless they are
> recognized by `K`.
>
> For a residual word `w in Σ_res(P)^*` and an admissible concrete pre-state `σ`, write
> `⟦w⟧_I(σ) = (τ, o, σ')` for the finite concrete trace segment, program-visible observation, and
> post-state produced by interpreter `I`. The residual semantic language under `α`, local to
> recognized frontier `(pc,a,κ)`, is the observation-labeled ambiguity relation
>
> `R_res^{pc,a,κ}(P, α) = { (w, x0, x1, o0, o1) | exists σ0, σ1 in F_{pc,a,κ}. X(σ_i)=x_i, ⟦w⟧_I(σ_i) = (τ_i, o_i, σ_i'), α_T(τ0) = α_T(τ1), and o0 != o1 }`.
>
> The global residual language `L_res(P, α)` is the union of these frontier-local relations over
> reachable frontiers. We keep the word *language* because the relation is generated by words over
> the residual alphabet; formally, it is an observation-labeled relation on recognizer-collapsed
> residual executions, not a claim that arbitrary unrelated states may be compared.

> **Definition 4 (residual transducer and residual monoid).** A residual transducer is a
> finite-state Mealy transducer `T_res = (Q, Σ_in, Γ_out, δ, λ, q0)` defined at a frontier fiber.
> Its states `Q` are quotient classes of residual runtime states erased by `α`; its input symbols
> `Σ_in` are accepted program-controllable operations; its output symbols `Γ_out` are
> program-visible effects; and its transition/output functions `δ` and `λ` are interpreted by the
> concrete runtime rather than precisely represented in `Tr_α(P)`. The quotient is required to be
> well-defined for the chosen residual alphabet: if two concrete residual states are in the same
> class, then every accepted residual symbol is either undefined for both or produces the same
> output symbol and successor quotient class. This is the congruence condition that lets `δ` and
> `λ` descend to `Q`. In this paper the condition is obtained only under the reset-normalized gate
> discipline and restricted input alphabet introduced in Definition 7. The reset class `q0` is the
> canonical class reached by the accepted reset sequence. When accepted residual words compose
> without leaving the frontier discipline, the induced partial transformations
> `{ δ_w : Q ⇀ Q | w in Σ_in^* }` form a partial transformation semigroup under composition where
> defined. When the identity residual word is included and composition is closed for the schedule
> discipline under discussion, we call it the residual partial transformation monoid.

The definitions deliberately separate acceptance from interpretation. `V` decides membership in
`L_V`; `I` still interprets concrete state while executing `P`; and `α` determines which of those
concrete distinctions are recognized.

> **Proposition 1 (no residual weird machine under semantic recognition).** If every
> program-visible concrete effect factors through `α`, and `α`-equivalence is a congruence for all
> program-controllable transitions, then no `α`-residual semantic language is available to the
> program. Consequently, relative to the given residual alphabet, frontiers, and accepted toolkit,
> `L_V` contains no weird machine of the residual-language kind defined here.

*Proof sketch.* If all program-visible effects factor through `α`, then any two concrete states
with the same abstract image produce the same program-visible result under every accepted
transition. Congruence preserves this equivalence under sequencing. Hence no residual words can
produce observations distinguished by the runtime and the program while the recognizer collapses
the corresponding trace. Without such a residual word pair, no residual transducer can be
constructed. ∎

The defensive meaning is LangSec-shaped: the target is not to eliminate abstraction, but to
ensure that all program-visible semantics relevant to downstream computation have been
recognized.

---

# 4. Residual Channels and A-Opacity

A residual semantic language becomes operational when a concrete operation exposes an abstractly
erased state component to the program. This is the point where the LangSec recognizer view and
abstract-interpretation incompleteness meet.

> **Definition 5 (abstractly unresolved readout channel).** A triple `(op, φ, ψ)`, with `op` a
> constructible operation, `φ` a concrete-state component, and `ψ` a predicate over the
> program-visible readout `r` written by `op`, is an *abstractly unresolved readout channel* if
> there exist reachable pre-states `σ0, σ1` for `op` at the same program point and under the same
> recognized frontier `(pc,a,κ)` such that (g1) the recognizer identifies the relevant pre-state and
> trace prefix, `σ0 ≡_α σ1` and equal `α_T` prefixes, while `φ` differs; (g2) the concrete transfer
> writes readouts `r0, r1` with `ψ(r0) != ψ(r1)`; and (g3) the abstract transfer cannot decide `ψ`
> at `r`, either because both truth values remain abstractly possible or because the abstract
> state records no relation sufficient to prove either side.

An abstractly unresolved readout channel is a witness of incompleteness for `op`: concrete
execution distinguishes reachable states that the recognizer abstraction identifies, and that
distinction remains program-visible. In residual-language terms, it supplies an output symbol for
`L_res(P, α)`. When this paper later says that a value is `top`, that is shorthand for an abstract
readout too coarse to decide the concrete predicate `ψ`; it need not be the greatest element of an
implementation lattice.

**The eBPF instance.** Let `φ` be the occupancy `c(G)` of a preallocated, non-LRU hash map `G` with
`max_entries = k`. The witness relies on the following deterministic capacity predicate:
`CAP(k)` says that a fresh-key update succeeds and increments `c(G)` exactly when `c(G) < k`, and
otherwise fails without changing `c(G)`. The readout predicate is `ψ(r) = [r == 0]`. Thus `ψ` is a
non-constant function of occupancy under `CAP(k)`. The verifier's helper prototype is an integer
return, represented as an unconstrained scalar, and the verifier abstraction has no occupancy
component. Thus map update exposes a residual state bit while the recognizer collapses the
predicate that reads that bit.

> **Proposition 2 (conditional occupancy readout).** Assume a map implementation satisfying
> `CAP(k)`. Let `σ0, σ1` be two reachable pre-states of a fresh insert at the same program point
> and recognized frontier. The registers, stack facts, static map attributes, and key argument
> agree; the inserted key is fresh in both states; one state has capacity remaining and the other
> is at capacity. The concrete map contents and key set may differ, but only in dynamic map
> components erased by the verifier abstraction. Then (i) `σ0 ≡_α σ1`; (ii) the concrete transfer
> separates them, returning `0` in one case and a negative error code in the other; and (iii) the
> verifier abstraction leaves the readout predicate `ψ(r) = [r == 0]` undecided. Hence the
> concrete distinction is a residual output symbol.

*Proof.* Item (i) follows because dynamic occupancy and key-set contents are absent from the
verifier abstraction used at this helper boundary; item (ii) follows from `CAP(k)` for a fresh key
below capacity versus at capacity; item (iii) follows from the verifier's integer helper-return
abstraction. The concrete predicate exposed by the return code is therefore interpreted by `I` and
the program, but not recognized by `α`. ∎

Our tested Linux 6.17.0/aarch64, preallocated non-LRU hash-map configuration instantiates
`CAP(2)` for the artifact, with at-capacity failure observed as `-E2BIG`. Section 7 treats
portability of that instantiation as a threat to validity; the proposition above is intentionally
conditional on the capacity semantics rather than a universal Linux-kernel claim.

We name the resulting blindness at program outputs.

> **Definition 6 (A-opacity relative to a relation vocabulary).** Let `π` be an accepted program
> with finite input domain `D` and concrete input-output function `f_π : D -> O`. Let `Q` be the
> class of input-output relations expressible in the recognizer's abstract report language, such
> as intervals, equalities, branch facts, range facts, or finite Boolean relations over tracked
> variables. Let `Cert^Q_α(π)` be the relations in `Q` entailed by the recognizer's final abstract
> trace summaries over the input and output variables. Program `π` is *A-opaque* for `f_π`
> relative to `(α,Q)` if `f_π` is non-constant and no certified relation
> `R# in Cert^Q_α(π)` entails the graph `{(x, f_π(x)) | x in D}`. For a join-based analyzer this
> may appear as a literal full-range value at the exit; for a path-sensitive analyzer, the
> relevant object is the union or join of path-final summaries together with the absence of any
> recognized relation, expressible in `Q`, between inputs and the chosen path.

For the Linux verifier witness, `Q` consists of relations expressible in the verifier's
scalar/range/branch summaries over the relevant input and output cells. The verifier does not
expose a functional graph certificate for map-occupancy-dependent helper returns, so the claim is
not that an external verifier could never infer the function; it is that the recognizer's own
report language does not certify it.

> **Remark 1 (where opacity loses precision).** A-opacity is not caused by any arbitrary
> abstraction gap. The lost distinction must be program-visible: along the output derivation,
> some concrete dependency that affects the final value is erased by the recognizer and later
> read through an abstractly unresolved readout channel. This remark only locates the precision
> loss; the weird-machine claim requires the stronger toolkit conditions below.

---

# 5. Residual-Language Weird Machine Theorems

For LangSec purposes, the theorem pair below is a recognizer-boundary sufficient condition, not a full
classification of all abstract interpreters. A residual channel is not yet a weird machine. It
becomes programmable only when the accepted toolkit can operate it as a transducer while staying
inside the recognized safety language.

> **Definition 7 (exploitable residual basis).** A residual transducer basis inside `L_V` is
> exploitable when the accepted toolkit provides:
> - **(E1) Observability**: the residual readout predicate `ψ` can be branched on or stored as a
>   program bit.
> - **(E2) Input-control**: for each gate input vector `x`, there exists an accepted setup
>   sequence `u_x` that selects the intended residual transitions and produces the corresponding
>   concrete `ψ` readout.
> - **(E3) Resettability**: an accepted reset sequence returns the residual component to a known
>   canonical equivalence class and leaves no hidden state depending on the prior gate evaluation
>   except explicit wire cells.
> - **(E4) Composability**: for each finite circuit, the accepted toolkit either allocates enough
>   independent residual instances or schedules resettable instances with explicit wire values,
>   including the ordinary store, copy, and fan-out operations needed to route those wires, while
>   all operations remain in `L_V`.

> **Definition 8 (induced residual gate).** Under E1-E4, the induced gate is the Boolean function
> obtained by resetting the residual state, applying the input-selected accepted sequence, and
> observing the residual readout predicate `ψ`. At this construction level, the program-visible
> explicit state `x` of Definition 3 is specialized to circuit wire cells and gate input/output
> cells; Definition 3 itself does not assume that all program-visible explicit state has this form.

> **Lemma 1 (frontier-local readout ambiguity).** If `(op, φ, ψ)` is an abstractly unresolved
> readout channel with witnesses reachable at the same program point and under the same recognized
> frontier `(pc,a,κ)`, then a branch or stored bit derived only from `ψ(r)` has both truth values
> in the abstract successor set at that frontier, unless a prior recognized relation already
> decides `ψ`.

*Proof sketch.* By Definition 5, there are same-frontier reachable states with the same abstract
view but opposite concrete values of `ψ`. Soundness requires the abstract post-state for that
frontier to include both concrete executions, while the abstraction records no relation that
decides `ψ`. Any accepted branch or store derived only from `ψ(r)` must therefore preserve both
abstract possibilities. The claim is frontier-local: it does not assert that every individual
concrete execution reaches both outcomes. ∎

The conditions above are not ornamental. Each removes a nearby counterexample:

| Missing condition | Counterexample | Consequence |
|---|---|---|
| program-visible readout | hidden state differs but no accepted code can observe it | no residual language witness |
| input-control | output depends only on uncontrolled environment noise | not a programmable machine |
| reset | the channel can be consumed only once | no reusable gate basis |
| composition | an isolated gate exists but cannot route wires | no circuit family |
| functional completeness | the residual gate is only a projection or constant | no arbitrary finite circuits |
| gate-opacity | explicit bytecode separately proves the same output relation | computes, but not A-opaque |

> **Lemma 2 (accepted schedules realize circuit semantics).** Let `S_C` be an accepted finite
> schedule for a circuit `C`. Assume each residual gate invocation realizes the induced gate
> under the explicit wire values supplied to that invocation, resets satisfy E3, and E4 supplies
> storage, copying, fan-out, and either fresh or resettable residual instances. Then the concrete
> wire valuation after each scheduled gate equals the corresponding circuit valuation.

*Proof sketch.* Induct over the circuit schedule. The base case is the single induced gate in
Definition 8. For the inductive step, E3 removes hidden residual carry-over between gate
evaluations except for explicit wire cells, and E4 supplies accepted routing from existing wire
values to the next gate invocation. The next residual readout is therefore evaluated with exactly
the circuit inputs scheduled for that gate, and the stored output wire agrees with the Boolean
gate semantics. ∎

> **Theorem 1 (residual realization theorem).** Let `V` recognize a safety language `L_V`, let
> `I` be the concrete interpreter for programs accepted by `V`, let `α` be the recognizer
> abstraction, and let `Π` be an accepted toolkit closed under finite schedules inside `L_V`.
> If `Π` contains an exploitable residual transducer basis whose induced gate is functionally
> complete, then for every finite Boolean circuit `C` there exists an accepted bounded program
> instance `P_C in L_V` such that `I(P_C)` computes `C`.

*Proof sketch.* Functional completeness yields a finite gate-level circuit for `C`. Construct
`P_C` by realizing each gate with the accepted residual basis: reset a residual transducer
instance (E3), apply the input-selected sequence for the current wire vector (E2), observe or
store the readout predicate (E1), and write the result into accepted wire cells. E4 supplies the
fresh or resettable residual instances and wire routing needed to sequence the gates without
leaving `L_V`. Lemma 2 gives the gate-by-gate correctness invariant, so the concrete interpreter
computes `C`. ∎

> **Definition 9 (local gate-opacity).** A residual gate invocation is locally gate-opaque
> relative to `(α,Q)` when: (i) its exported output cell is assigned only from the predicate
> `ψ(r)` over the residual readout; (ii) no relation in `Q` certified at that gate frontier
> entails the gate output as a function of the gate's concrete input wires; and (iii) no
> recognizer-visible instruction in the same gate invocation computes a Boolean expression
> equivalent to the induced gate and writes it to the exported output cell.

> **Theorem 2 (residual opacity theorem).** Under the hypotheses of Theorem 1, additionally
> assume that each residual gate invocation is locally gate-opaque relative to `(α,Q)`, each
> residual readout satisfies Lemma 1 at the recognized frontier for its gate invocation, and `Q`
> is closed under the relational composition and projection operations used to route explicit
> program-visible state. Assume further that every global certificate in `Cert^Q_α(P_C)` is
> bounded by relational composition of the certified local gate summaries and explicit state-copy
> summaries; equivalently, the recognizer does not synthesize a global functional relation that is
> absent from all local certificates. Then the constructed program `P_C` is A-opaque for `C`
> relative to `(α,Q)`. Hence the accepted language `L_V` contains a residual-language weird
> machine relative to `(α,Q)`.

*Proof sketch.* Lemma 1 supplies frontier-local abstract ambiguity for each residual readout: at
the recognized frontier, the abstraction cannot decide the readout predicate that becomes the
gate output. Local gate-opacity rules out the counterexample where ordinary bytecode inside a
gate computes and exports the same Boolean relation in recognizer-visible form. By induction over
the same schedule as Theorem 1, explicit wires carry the concrete circuit values, but every
nontrivial gate output is introduced through an unresolved residual readout rather than through a
relation in `Q` certified at that gate. Because `Q` is closed under the relevant relational
composition operations and global certificates are bounded by the composition of local summaries,
the abstract summary can only propagate the imprecision already present in those local gate
relations; it cannot introduce a missing functional gate relation. The final certified summaries
therefore do not entail the graph of `C` in `Q`, so Definition 6 gives A-opacity relative to
`(α,Q)`. ∎

The theorem pair is bounded and conditional. It does not claim Turing-completeness, an exploit,
or a bug, and it is not a complete abstract-interpretation boundary theorem. The realization
theorem says when a residual language is programmable; the opacity theorem adds the extra
recognizer-side condition needed to keep that computation outside the certified input-output
relations expressible in `Q`.

# 6. The eBPF witness

We instantiate the Definition 7 hypotheses for an eBPF NAND basis, demonstrate the Theorem 1
program-family construction on finite adders accepted by the in-kernel verifier, and discharge
the Theorem 2 local gate-opacity condition by contrasting the residual witness with an explicit-logic
baseline. The programs are
`SEC("syscall")` eBPF programs run offline via `bpf_prog_test_run_opts()`; they use only legal
helper calls and bounded loops; they perform no out-of-bounds access and no verifier bypass. All
experiments run in a local VM under a privileged configuration sufficient for the exact kernel
version and program type used by the artifact. We do not claim unprivileged loadability,
attachability, privilege escalation, or deployment in a live kernel path. The general
program-family claim follows from the construction in Section 5; the artifact validates the eBPF
basis and representative finite compositions.

**Artifact interface note.** We use `BPF_PROG_TYPE_SYSCALL` because the artifact requires
map-update helper traces without attaching a program to a live kernel hook. On the tested kernel,
this program type is accepted by the verifier and executed through `bpf_prog_test_run_opts()`;
the artifact records the exact program type, helper set, kernel version, and verifier logs. The
construction is not tied to syscall attachment semantics: the theorem depends only on accepted
helper traces and private map semantics.

## 6.1 The residual gate language

The witness is a finite-state residual transducer over hash-map occupancy. The gate uses one
`BPF_MAP_TYPE_HASH` map `G` with `max_entries = 2`. The map is non-LRU and, as defined in the
artifact, has no `BPF_F_NO_PREALLOC` flag; it therefore uses the ordinary preallocated hash-map
configuration relied on by the deterministic capacity-saturation witness. The keys `S`, `A`,
and `B` are distinct, and the maps are private to offline `SEC("syscall")` runs via
`bpf_prog_test_run_opts()`.

The mechanism is capacity saturation, not allocation failure as an attacker primitive. The tested
preallocated, non-LRU hash-map configuration instantiates `CAP(2)`: a fresh-key update succeeds
while live occupancy is below `max_entries`; once the live-entry count reaches `max_entries`, the
same helper returns a negative error (observed as `-E2BIG`) rather than evicting an entry. The
offline private map and reset discipline make this threshold deterministic for the artifact;
Section 7 treats kernel-version and architecture portability as a threat to validity.

The residual quotient states are the key-set classes reachable under the reset-normalized gate
discipline:

`Q_G = { q_empty, q_S, q_SA, q_SB }`,

representing `empty`, `{S}`, `{S,A}`, and `{S,B}`. The alphabet is

`Σ_G = { reset, insS, updS, insA, insB }`.

`reset` deletes the sentinel and input keys `S`, `A`, and `B`; `insS` inserts the sentinel key
`S`; `updS` updates the existing sentinel and therefore does not increase occupancy; `insA` and
`insB` insert fresh input keys. Each gate starts from the invariant occupancy `{S}` after
`reset . insS`. The output alphabet is `{ ε, 1, 0 }`, where `1` means helper success
(`ret == 0`), `0` means helper failure (`ret != 0`), and `ε` is an ignored normalization output.
The partial transition/output table needed by the gate is:

| State | Input | Next state | Output |
|---|---|---|---|
| any | `reset` | `q_empty` | `ε` |
| `q_empty` | `insS` | `q_S` | `ε` |
| `q_S` | `updS` | `q_S` | `1` |
| `q_S` | `insA` | `q_SA` | `1` |
| `q_S` | `insB` | `q_SB` | `1` |
| `q_SA` | `updS` | `q_SA` | `1` |
| `q_SA` | `insA` | `q_SA` | `1` |
| `q_SA` | `insB` | `q_SA` | `0` |
| `q_SB` | `updS` | `q_SB` | `1` |
| `q_SB` | `insB` | `q_SB` | `1` |
| `q_SB` | `insA` | `q_SB` | `0` |

Rows not reachable under the reset-normalized gate schedule are outside the partial transducer
used in the proof. For input bits `a,b in {0,1}`, the residual word is

`w_ab = reset . insS . op_a . op_b`, where `op_0 = updS` and `op_1` is the corresponding fresh
insert (`insA` for the first input, `insB` for the second). The output symbol is the predicate
`out = [ret == 0]` over the return code of the **second input operation** `op_b`, not a third
probe. At gate exit, the output is determined only by success or non-success of that second
input operation. This matches the artifact's `GATE_CAP=2` implementation and avoids the
off-by-one ambiguity of a sentinel-plus-third-probe variant.

| a | b | residual word | second input result | output |
|---|---|---|---|---|
| 0 | 0 | `reset insS updS updS` | success | 1 |
| 0 | 1 | `reset insS updS insB` | success | 1 |
| 1 | 0 | `reset insS insA updS` | success | 1 |
| 1 | 1 | `reset insS insA insB` | failure (negative errno; observed `-E2BIG`) | 0 |

Thus the residual transducer implements `NAND(a,b)`. The accepted bytecode does not combine
`a` and `b` arithmetically to compute this truth table. The inputs are used only to select
whether an operation targets the existing sentinel key or a fresh key; the truth value is the
helper return symbol produced by the concrete map/runtime interpreter. Since NAND is
functionally complete, the residual gate satisfies the functional-completeness hypothesis of
Theorem 1. The explicit-logic baseline in the next subsection is excluded by the local gate-opacity
condition of Theorem 2: its truth table is recognizer-visible ordinary bytecode logic rather than
an output derived only from the residual readout.

## 6.2 Contrast: an explicit-logic baseline the verifier accepts identically

A baseline variant computes the same truth table with ordinary arithmetic: two comparisons
negate the inputs and an `OR` combines them into `¬a ∨ ¬b = ¬(a∧b)` by De Morgan. This
baseline is *also* verifier-accepted and produces an identical 400/400 truth table, but its
NAND is legible in the bytecode (repository Appendix A.8). The verifier sees two safe, bounded
programs with identical I/O; only the baseline's logic is visible to it. This is the point of
the paper in one comparison: the gap is not about *what* can be computed but about *what the
recognizer abstraction can recognize*.

## 6.3 Discharging the clauses

| Clause | eBPF realization | Evidence |
|---|---|---|
| `(V, I, α)` | eBPF verifier; concrete map/helper runtime; verifier abstraction | `results/nand.verifier.log`, `env.json` |
| residual channel (g1-g3) | φ = occupancy `c(G)`; `op` = update/insert; `ψ(ret) = [ret == 0]` abstractly unresolved at the same verifier frontier | Prop. 2; verifier log insn 78/79 |
| E1 observability | `if r6 == 0` decides the output bit | xlated insn 122 |
| E2 input-control | input bits select `updS` versus fresh-key insert; `op_b` return is the readout | xlated insn 66-68 / 79-81 |
| E3 resettability | delete `S,A,B`, then insert `S`; gate restarts in canonical class `{S}` / occupancy 1 | xlated insn 44 / 49 / 54 |
| E4 composability | maps `G0..G8` plus explicit wire cells on `TAPE`; resettable schedules support finite circuits | `full_adder.jsonl` |
| gate `g` = NAND (complete) | NAND truth table exhaustive; finite adders demonstrate representative compositions | `nand_truth_table.jsonl`, `adder32_exhaustive.jsonl` |
| opacity | verifier cannot resolve `ret == 0`; both path-final output values remain reachable without a certified input-output graph | verifier log 104 (both successors) |

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

Each line is one reset-normalized residual-gate invocation, with intermediate values stored in
explicit wire cells and routed to later invocations by the accepted ordinary store/copy
operations required by E4.

The machine-checkable heart is the last row. Verbatim from the verifier log, the helper return
for the input-conditioned map operation flows as an unconstrained scalar into the output branch;
the verifier cannot resolve the predicate `ret == 0` and explores both successors. This realizes
Proposition 2 at the helper boundary and Definition 6 relative to the verifier relation
vocabulary `Q`: the concrete output is input-dependent, but the certified summaries do not entail
the NAND input-output graph in `Q`.

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
68149/68149 and a passing semantic audit. The aggregate consists of 400 NAND trials, 8 full-adder
trials, 65536 exhaustive 8-bit operand-pair trials for the 32-bit adder harness, 1005 full-width
sampled 32-bit cases, and 1200 ablation/baseline truth-table checks. All artifacts are
regenerated by a single command and re-checked by another.

**Second witness — an independent, join-based analyzer.** To test whether the phenomenon tracks
sound-but-incomplete abstraction rather than an eBPF idiosyncrasy, we reproduce it in a
structurally different `(C, A)`: a numeric program whose gate is `NAND(a,b) = [(1+a+b) mod 3 ≠ 0]`,
analyzed by a **sound, non-relational, join-based interval domain**. The residual component is
the congruence `acc mod 3`, which intervals do not represent. A self-contained reference analyzer
and Frama-C EVA v25.0 [18] both certify the working gate's output as `{0,1} = top`, while the
modulus-7 ablation is certified as the singleton `{1}`. Thus the imprecision is localized to the
erased congruence component rather than to the whole analysis. The artifact contains the
exhaustive reference run, EVA command line, logs, composed-gate checks, and the input-partitioned
refinement that repairs the precision loss.

| | analyzer | style | channel `φ` | certified output |
|---|---|---|---|---|
| eBPF witness (§6) | Linux verifier | path-sensitive | map occupancy | unresolved predicate; both path-final outputs reachable |
| second witness | interval domain / Frama-C EVA | **join-based** | `acc mod 3` | `out ∈ {0,1} = ⊤` |

Two structurally different sound analyzers thus exhibit the same recognizer-side opacity pattern,
which is the limited system-independence claim needed for the LangSec framing. The interval witness
is not a second eBPF-style exploitability proof; it is evidence that residual opacity follows from
sound-but-incomplete recognition rather than from one kernel substrate. The full construction, the
runnable reference analyzer, and the verbatim EVA log are in the artifact.

**Threats to validity.** The eBPF evidence is from one kernel (6.17.0, aarch64). Hash-map internals
and verifier behavior can drift across kernel versions and architectures; in particular, the
`-E2BIG`-at-capacity mechanism should be confirmed against the exact map type (preallocated,
non-LRU) and single-CPU offline execution, since preallocated hash maps reserve per-CPU spare
elements that can perturb the capacity threshold under concurrency. The exhaustive truth tables
establish that the mechanism holds as described on the tested configuration; portability across
eBPF kernels and architectures remains future work. The demand for a second, structurally
different analyzer is satisfied by the join-based witness above.

---

# 8. Related work

**Language-theoretic security.** LangSec argues that security failures often arise when a
system does not precisely recognize the language it consumes, or when later computation acts on
structure that has not been fully recognized [24]-[27]. The usual setting is parsing: input
languages, recognizers, parser differentials, Postel-style ambiguity, and the complexity of the
notional input-accepting automaton. Our work extends this lens from parsers to safety
recognizers. The analogue of the parser/interpreter split is the verifier/runtime split: a program
verifier can correctly recognize a safety language while the concrete runtime still interprets and
exposes a residual semantic language inside accepted programs.

**Weird machines: informal and constructive.** Bratus et al. introduced the weird-machine frame
as a way to see exploitation as programming an unintended machine [5]; constructive
demonstrations exposed unintended computation in substrates such as the page-fault handler [6]
and ELF metadata [7]. These works answer what can be computed in a substrate not meant to
compute, typically after or around a defect. Our witness differs on two axes: the substrate is an
accepted program with no recognizer failure, and the property we establish is not
Turing-completeness but residual-language opacity inside a recognized safety language.

**Other substrates and later variants.** Subsequent work broadens the catalog of weird-machine
substrates and patterns. Bratus et al. describe recurring weird-machine patterns across systems
[19], while Anantharaman et al. use *mismorphism* to name the semantic mismatch at the heart of
the phenomenon [20]. More recent systems work moves the hidden machine into microarchitectural
state: Evtyushkin et al. show computation with timing and microarchitectural state [21], and
Wang et al. study weird machines in transient execution [22]. Levy and Maldonado use the weird
machine lens for attack-surface measurement [23]. These papers reinforce that hidden or
under-specified state is a recurring substrate; our contribution is to isolate the analogous
substrate as a residual language left inside a recognizer's accepted language.

**Weird machines as insecure compilation.** Paykin et al. cast weird machines as insecure
compilation: an exploit is a target-context behavior no source context can produce, and a
compiler is exploit-free iff it preserves robust hyperproperties [10]. Our account is
orthogonal. Their boundary is source language versus target language; ours is recognizer-visible
language versus runtime-interpreted residual language. Both are computation that violates an
abstraction, but the abstraction is a different object.

**The closest prior art.** Vanegue's study of weird machines in proof-carrying code is the
nearest antecedent: it observes that when a proof system's abstraction fails to capture
untrusted computation, a shadow execution can arise, and the machine abstraction becomes one
such opportunity [8]. We regard our contribution as a LangSec-style formalization of this
observation: residual semantic languages make the abstraction gap a language object, and the
residual transducer theorem states when that language becomes programmable. Vanegue's later
adversarial logic gives an under-approximate proof system for exploitability [11]; it is
complementary to ours, which concerns the sound over-approximate recognizer's blind spot rather
than the discovery of true attack paths.

**Completeness in abstract interpretation.** Our reframing rests on the theory of completeness:
Giacobazzi, Ranzato, and Scozzari characterize when an abstraction is complete for an operation
and construct the complete shell and core [2]; Bruni et al. localize completeness to fragments
and build a logic that reasons about correctness and incorrectness together [3], with follow-up
work quantifying partial incompleteness [4]. Abstract interpretation explains how recognizers
soundly approximate concrete semantics for chosen properties. Our question is language-theoretic
and security-specific: when does erased concrete behavior still constitute a program-visible
language?

**eBPF verification.** eBPF is our witness, not the theoretical source of the paper. The eBPF
verifier and its abstract domains have been formalized and, in part, proved sound: PREVAIL uses
abstract interpretation with a chosen numeric domain [12], and the tnum domain used in the
kernel has a machine-checked soundness proof [13]. This line is about proving the verifier
correct for safety. Our result is compatible with and depends on that correctness: the verifier
recognizes a safety language, and the weird machine lives in residual semantics left after that
recognition succeeds. Systems such as MOAT isolate potentially malicious BPF programs using
Intel MPK [28]. That line is complementary: MOAT hardens execution after verifier acceptance,
whereas our question is what residual semantic language remains interpreted yet unrecognized
inside accepted programs.

# 9. Outlook: from witnesses to a structural theorem

The Residual-Language Weird Machine theorem pair in Section 5 is conditional: it assumes an
exploitable residual transducer basis inside an accepted language, and opacity additionally
requires gate-opacity rather than recognizer-visible shadow logic. In this paper those hypotheses
are instantiated constructively in eBPF; the structurally different interval-analysis witness
supports the recognizer-side claim that the pattern tracks sound-but-incomplete abstraction. The
foundational target is stronger: characterize when a sound recognizer necessarily leaves a
program-visible residual semantic language, and when that language is necessarily exploitable. We
do **not** claim to have completed that step here.

The open problem has two halves.

## 9.1 Which recognizer abstractions necessarily admit residual languages?

The recognizer-side question is naturally a completeness question. In abstract-interpretation
terms, a residual semantic language appears when an operation's concrete result depends on a
state component that `α` quotients away, yet the result remains visible to the accepted program.
That is a failure of completeness for a program-visible operation: `α` is sound for the safety
property it certifies, but incomplete for the semantic distinction later interpreted by the
runtime. The mature theory of complete shells, complete cores, local completeness, and measured
incompleteness [2], [3], [4], [17] is therefore the right mathematical setting for the next
step.

A plausible theorem would characterize a class of recognizers, abstractions, and concrete
interpreters such that:

1. `α` erases a concrete residual component `φ`;
2. some accepted operation `op` has a program-visible output whose concrete value is
   non-constant across an `α`-fiber varying only in `φ`;
3. the abstract transfer for `op` must over-approximate those concrete outcomes by an abstract
   value that cannot decide the readout predicate `ψ`; and
4. accepted operations can route that value into later computation.

The eBPF map-occupancy witness instantiates this shape with `φ = c(G)` and `op =
bpf_map_update_elem`; the interval witness instantiates it with a congruence component erased by
intervals. What remains is to state the class of abstractions for which this implication is not
just observed by instance but guaranteed by the structure of `α`, `op`, and the accepted toolkit.

## 9.2 When is the residual language exploitable?

A residual language is not yet a weird machine. It becomes programmable only when the toolkit can
observe it, drive it with inputs, reset the underlying state, and compose independent uses. In a
closed offline experiment, such as `BPF_PROG_TEST_RUN` with private maps, uncontrolled state is
minimal; in a live system, scheduling, concurrency, shared maps, allocator state, or unrelated
writers can perturb the residual component. A future theorem therefore needs a reliability
condition, not merely reachability.

Robust reachability [15], [16] is a promising language for this half of the problem: it asks
whether a controlled choice reaches the desired branch for all uncontrolled choices. For this
paper we use the simpler, empirical discipline: isolate the residual transducer, reset it before
each gate, use private instances for composition, and validate the truth table exhaustively on
the relevant finite domains. A full exploitability theorem would connect E1--E4 to a
robust-reachability condition over the controlled/uncontrolled split of the host system.

## 9.3 Why the second witness matters

The second witness is a down-payment on generality. It is deliberately unlike the eBPF witness:
its analyzer is join-based rather than path-sensitive, its residual state is a congruence rather
than map occupancy, and its substrate is numeric arithmetic rather than kernel helper metadata.
Yet the same pattern appears: the concrete program computes through state that the sound
recognizer abstraction does not represent, and the certified output abstraction is the full
Boolean range (a literal join-top result for the interval witness). This supports the hypothesis
that the phenomenon tracks sound-but-incomplete recognition, not an eBPF-specific quirk.

Still, two witnesses are not a structural theorem. The durable contribution we target next is a
framework in which one can read off, from `(V, I, α, Π)`, whether a recognizer leaves a
program-visible residual semantic language and whether the accepted toolkit can operate it as a
transducer. The present paper supplies the formal vocabulary, the conditional theorem, and a
production-verifier witness; the complete boundary characterization remains future work.

# 10. Limitations

The eBPF evidence is from one kernel and architecture, so portability across kernel versions,
map implementations, and architectures remains to be established. Section 7 supplies a second
analyzer witness, including Frama-C EVA, but that witness is empirical support rather than a
complete structural characterization of all sound recognizers. The Residual-Language Weird
Machine theorem pair characterizes a precise sub-notion--bounded programmable computation plus
recognizer opacity under gate-opacity--not weird machines in general. E3 and E4 are construction conditions for bounded
circuits, not claimed necessary features of every weird machine. The result is deliberately
bounded and combinational, not Turing-complete. Finally, the boundary-condition theorem sketched
in Section 9 remains future work: deciding when an arbitrary `(V, I, α, Π)` tuple necessarily
admits an exploitable residual semantic language is richer than this paper solves.

# 11. Conclusion

LangSec teaches that security boundaries are language boundaries. This paper shows that the
same lesson applies to sound program verifiers: recognizing a safety language does not by itself
recognize every semantic language interpreted by the concrete runtime. A verifier can be correct
about safety while accepted programs still operate a residual semantic language that the
recognizer abstraction collapses.

We formalized that residual language, stated a residual-language weird-machine theorem pair, and
instantiated its hypotheses in eBPF with verifier-accepted, memory-safe, bounded witnesses that do
not rely on any known verifier unsoundness, memory corruption, or privilege-escalation bug. The
witness implements NAND as a residual finite-state transducer over map occupancy and helper
return symbols, then composes it into representative bounded circuits following the program-family
construction. The result is not that eBPF has a trick; it is that safe recognition is not semantic
recognition. When residual semantics are controllable, observable, resettable, composable, and
expressive enough to supply a reusable transducer basis, they form a weird machine inside the
accepted language; when the schedule is locally gate-opaque, that computation is hidden from the
recognizer's certified relations in the chosen vocabulary `Q`.

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
T. Xu, and D. Williams, "Safe and usable kernel extensions with Rax," arXiv:2502.18832, 2025.

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
arXiv:2301.13421v3, 2024.
