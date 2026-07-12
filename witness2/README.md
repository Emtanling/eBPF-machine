# Precision control: value ranges versus relational certification

This directory is a mechanized **precision-control experiment**. It replaces the
earlier claim that an output interval `{0,1}` localized a modulo-specific
abstraction gap. That claim was not justified: `{0,1}` is the exact global output
range of every nonconstant Boolean function, including a projection, explicit
NAND, and modulo-based NAND.

The experiment now asks three separate questions:

1. Is the inferred global output value range exact?
2. Does the abstract result certify the complete input/output graph?
3. Does a stated completeness equation hold on the actually reachable set?

It is a self-contained toy abstract interpreter, **not** a model of the Linux
eBPF verifier and **not** evidence that the eBPF phenomenon is system-independent.

## Reproduce

From the repository root:

```sh
bash witness2/run.sh
```

This runs ten Python regression tests, performs a host-compiler syntax check
of the current Frama-C C model, and writes deterministic reports to:

- `witness2/out/witness.txt`
- `witness2/out/witness.json`
- `witness2/out/SHA256SUMS`

The script has no third-party Python dependencies.

## Programs under comparison

For Boolean inputs `a,b ∈ {0,1}`:

```text
projection(a,b)    = a
explicit_nand(a,b) = 1 - a*b
modulo_nand(a,b)   = ((1+a+b) mod 3 != 0)
```

The last two programs compute the same NAND truth table:

```text
(0,0) -> 1   (0,1) -> 1   (1,0) -> 1   (1,1) -> 0
```

The projection is a nonconstant control; it is not claimed to compute NAND.

## Claim matrix

The executable report verifies the following matrix:

| program | global interval is exact | global range certifies I/O graph | toy row relation with range-only `MOD` | congruence-aware refinement | singleton input partition |
|---|---:|---:|---:|---:|---:|
| projection | yes | no | certifies | certifies | certifies |
| explicit NAND | yes | no | certifies | certifies | certifies |
| modulo NAND | yes | no | **does not certify** | certifies | certifies |

### Reading the columns

- **Global interval.** All three programs yield `[0,1]`, and `[0,1]` is their
  exact global output range. The range is therefore sound and value-range
  complete, but it contains no association between a particular input and its
  output. It cannot certify any of the three nonconstant I/O graphs.
- **Toy row relation with range-only `MOD`.** Values are indexed by the four
  input rows. Ordinary arithmetic transfers preserve those rows, so the
  projection and explicit NAND are certified. The deliberately imprecise
  `MOD` transfer joins all rows, computes a residue range, and assigns that
  range to every row. It remains sound but cannot certify modulo NAND.
- **Congruence-aware refinement.** Keeping residues per input row restores the
  exact modulo-NAND graph. This implementation is finite row enumeration, not a
  claim about a scalable production congruence domain.
- **Singleton input partition.** Running the interval transfer separately for
  all four inputs also certifies every graph. This is a generic finite-domain
  repair, not evidence that a production analyzer implements it.

## Completeness equations on the actual reachable state

The modulo operand reaches the concrete value set

```text
X = {1,2,3}.
```

For the ordinary interval abstraction `α_iv` and the implemented interval
`MOD` transfer:

```text
α_iv({x mod 3 | x ∈ X}) = [0,2]
MOD#(α_iv(X))           = [0,2].
```

The two sides are **equal**. The artifact therefore does not call this an
interval-completeness violation.

For the row-indexed relation at the same program point, let

```text
R = {(00,1), (01,2), (10,2), (11,3)}.
```

Here `α_rel` is explicitly the identity over finite row-indexed value sets, so
the row-indexed domain can represent the exact relation. Its exact concrete
`MOD` image is

```text
{(00,{1}), (01,{2}), (10,{2}), (11,{0})}.
```

The toy range-only `MOD#` instead returns `{0,1,2}` for every row. Thus

```text
α_rel(MOD(R)) ⊊ MOD#_range(α_rel(R)).
```

This strict inequality is an executable witness of **transfer imprecision in
this toy row-forgetting `MOD` implementation**. It must not be generalized to
the ordinary interval value abstraction, Frama-C EVA, or Linux eBPF. The
congruence-aware row-preserving transfer restores equality on this finite state.

## Soundness checks

Every reported certificate is checked against the exhaustive concrete oracle:
the concrete output for each input row must belong to the reported set. Exact
certification additionally requires that every row contain exactly its one
oracle output. The test suite fails if either equivalent NAND implementation
changes, if a certificate becomes unsound, or if any matrix entry changes.

## Frama-C material

`frama_c/out/eva_slevel0.log` is a preserved, verbatim historical run of the
previous one-`volatile` input model. It shows that EVA inferred `{0,1}` for
modulo NAND and `{1}` for a different, constant mod-7 program. These are global
value-range facts about that old run only:

- `{0,1}` is the exact output range of modulo NAND;
- the mod-7 program computes a different constant function;
- the log does not compare modulo NAND with an equivalent explicit NAND;
- the log contains no row-indexed I/O certificate;
- it therefore does not establish modulo-specific incompleteness, relational
  opacity, or cross-system generality.

The Frama-C result is not used to support any relational claim in
`out/witness.json`.

The current C source uses two independent `Frama_C_interval(0,1)` calls. The
recorded VM rerun produced `frama_c/out/eva_slevel0.current.log`: modulo NAND
is `{0;1}`, the different constant mod-7 control is `{1}`, and EVA reports zero
alarms. `frama_c/out/current.provenance.json` binds that log to the current
source, runner, checker, tool version, and a self-contained environment record.

## Residual limitations

- The input space contains four Boolean rows and is exhaustively enumerated.
- The repairs establish no scaling bound or local-to-global circuit theorem.
- The strict inequality diagnoses a deliberately imprecise transfer in this
  reference analyzer, not an unavoidable limitation of interval analysis.
- No production analyzer in this directory has been configured to certify an
  explicit I/O relation for the same-semantics pair.
