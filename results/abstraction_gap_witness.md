# Formal Witness — the verifier quotients hash-map occupancy to ⊤

This note turns the informal claim "the eBPF verifier does not model the state
that carries the weird machine's computation" into a precise, machine-checkable
proposition about the verifier's abstract semantics, and grounds it in the exact
abstract-domain facts recorded in `results/nand.verifier.log`. It is the formal
bridge between the concrete PoC (Appendix A.4/A.7) and the abstraction-gap
thesis: it exhibits, at one program point, a transfer function whose concrete
output depends on state that the abstraction collapses to ⊤.

## 1. Notation

- Concrete states `σ ∈ Σ` include, for each hash map `M`, its live-entry count
  (occupancy) `c(σ, M)` with `0 ≤ c(σ, M) ≤ max_entries(M)`.
- The verifier is a sound-for-safety abstract interpreter with abstract domain
  `𝒜` (per-register/stack types: pointers, `map_value`, and scalars). Its scalar
  lattice is a tnum (known-bits) refined by signed/unsigned interval bounds; its
  top element is `⊤ = scalar()` (unknown bits, full range). Write `α : Σ → 𝒜`
  and `γ : 𝒜 → ℘(Σ)` for the abstraction/concretization pair modelling the
  analysis; soundness means `σ ∈ γ(α(σ))` and each transfer over-approximates.
- Crucially, `𝒜` represents each map's *identity* and *static* attributes
  (type, key/value size, `max_entries`) but has **no component for the dynamic
  occupancy `c(σ, M)`**. Hence `α` is constant in `c`: if `σ0, σ1` differ only in
  `c(·, M)`, then `α(σ0) = α(σ1)`.

## 2. The map-update transfer — concrete vs abstract

Consider the instruction `r0 := bpf_map_update_elem(M, k, v, BPF_ANY)` with a key
`k` not currently present in `M` (a fresh key). The kernel's concrete transfer
`T` is:

    T(σ)(r0) = 0                         and  c ↦ c+1     if c(σ, M) < max_entries(M)
    T(σ)(r0) = -E2BIG (= -7)             and  c unchanged  if c(σ, M) = max_entries(M)

So the concrete post-value of `r0` is a **non-constant function of occupancy**:
`[T(σ)(r0) = 0] ⇔ c(σ, M) < max_entries(M)`.

The verifier's abstract transfer `T#` for the same instruction is fixed by the
helper's return prototype `bpf_map_update_elem.ret_type = RET_INTEGER`, which the
scalar domain models as the top scalar:

    T#(a)(r0) = ⊤ = scalar()             for every abstract state a, independent of a.

## 3. Proposition (occupancy is quotiented to ⊤)

> Let `σ0, σ1 ∈ Σ` be two pre-states of the third gate insert that are identical
> except `c(σ0, G0) = max_entries − 1` and `c(σ1, G0) = max_entries` (so the fresh-key
> insert succeeds from `σ0` and fails from `σ1`). Then
>
> 1. **α agrees:** `α(σ0) = α(σ1)` — occupancy is unrepresented in `𝒜` (§1).
> 2. **T separates:** `T(σ0)(r0) = 0 ≠ -E2BIG = T(σ1)(r0)` — the concrete post-states
>    differ in exactly the bit `[r0 = 0]`.
> 3. **T# collapses:** `T#(α(σ0))(r0) = T#(α(σ1))(r0) = scalar() = ⊤`.
>
> Therefore `T#` is **non-injective on the classes that `T` separates**: the one
> bit `[r0 = 0]` that distinguishes the two concrete outcomes is mapped by the
> abstraction into a single ⊤ cell.

*Proof.* (1) is §1's constancy of `α` in `c`. (2) is the definition of `T` in §2
with the chosen occupancies. (3) is the definition of `T#` in §2, which is a
constant function returning ⊤. Combining, `α(σ0)=α(σ1)` forces
`T#(α(σ0))=T#(α(σ1))`, while `T(σ0)` and `T(σ1)` disagree on `r0`. ∎

## 4. Corollary — the gate output is abstraction-unrepresentable

The NAND gate writes `out = [r0₃ = 0]` to `TAPE[IDX_NAND_OUT]`, where `r0₃` is the
return of the **third** insert. By the Proposition, `out` is a total function of
`c(G0)` at that insert, and that argument is ⊤ in `𝒜`. Hence **no sound
strengthening of the reachable abstract state can predict `out` without extending
`𝒜` with a map-occupancy component.** The verifier's own search confirms it: at
the output branch it cannot resolve the guard and must fork, so *both* truth
values are abstractly reachable (see the two out-edges in §5).

## 5. Empirical witness — verbatim from `results/nand.verifier.log`

Within `wm_nand` (verifier trace, lines 529–739), the three gate inserts and the
output decision appear as follows. Every `bpf_map_update_elem` return is the top
scalar; the third one flows into the output register `r6`, which the verifier
then cannot resolve:

```
 50: (85) call bpf_map_update_elem#2   ; R0=scalar()                       # insert 1 (sentinel S)
 64: (85) call bpf_map_update_elem#2   ; R0_w=scalar()                     # insert 2 (key from A)
 78: (85) call bpf_map_update_elem#2   ; R0=scalar()                       # insert 3 (key from B) — capacity probe
 79: (bf) r6 = r0                       ; R0=scalar(id=3) R6_w=scalar(id=3) # output reg = ⊤ (no bounds)
104: (15) if r6 == 0x0 goto pc+1        ; R6=scalar(id=3,umin=1)           # output decision over ⊤ — verifier forks
```

Both successors of the output branch are explored (occupancy could not decide it):

```
from 104 to 106: R0=scalar() R1_w=1 R6=0    R7=scalar(umin=1) …            # r6 == 0 branch  ⇒ out = 1
        …        R0=scalar() …     R6=scalar(id=3) …                        # r6 != 0 branch  ⇒ out = 0
```

`R0=scalar()` / `R6=scalar(id=3)` printed with no `smin/smax/var_off` is the top
scalar: unknown bits, full range. The gate's truth value is therefore carried by
a register the abstraction holds at ⊤ from insert until the branch.

Instruction-number correspondence to the xlated listing (Appendix A.7), which is
renumbered post-verification:

| role | verifier insn (this log) | xlated insn (A.7) |
|---|---|---|
| 3rd insert (capacity probe) | 78 | 90 |
| capture output register `r6 = r0` | 79 | 91 |
| output decision `if r6 == 0` | 104 | 122 |
| store `out` to `TAPE[IDX_NAND_OUT]` | 114 | 132 |

## 6. What this licenses

The Proposition makes "abstraction-layer gap" precise *at this point* as: **a
program point whose concrete transfer output is a non-constant function of a
concrete-state component that `α` maps to a single ⊤ cell.** This is an
existence witness (∃), not a universal theorem — but it is now a machine-checkable
one, and it is sound-for-safety by construction: the verifier remains correct
about everything it *claims* (memory safety, bounded termination); the gap lies
entirely in semantics it never claims. That is the designed incompleteness of a
sound abstraction, not a bug.

The witness also isolates what makes the ⊤-bit *programmable*, i.e. the extra
conditions beyond "a gap exists":

- **observable** — the ⊤-bit is returned in a register (`r0`) and branched on;
- **resettable** — `bpf_map_delete_elem` restores `c(G0)`, so the gate is a pure
  function re-evaluable per call;
- **composable** — independent maps `G0..G8` compose gates without interference.

An *observable, resettable, composable* ⊤-bit supports a functionally complete
gate (NAND), hence arbitrary Boolean circuits (Appendix A.5: exhaustive 8-bit
adder, 65536/65536). Necessity ("every weird machine has such a gap") and general
sufficiency ("every such gap is programmable") remain separate theoretical claims
this witness motivates but does not discharge.
