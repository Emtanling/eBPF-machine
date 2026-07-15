# `linux_r`: executable report-relative residual witness

`linux_r` is a small report-producing recognizer plus a finite interpreter for
the ordinary, non-evicting Linux `BPF_MAP_TYPE_HASH` update cases used by the
artifact's NAND gate.  Its precise result is:

```text
R(V_linux_r, I_hash) = established
R(stock Linux verifier, I_Linux) = not established
```

The second line is an essential scope boundary.  `V_linux_r` computes and
serializes its own abstract cells; the experiment does not relabel verifier
logs, BTF, or translated bytecode as stock-kernel abstract states.

## Recognizer and runtime

The fixed program is [`program.json`](program.json).  The concrete service
state is `(phase, K)`, where `K` is a subset of `{S,A,B}`.  For a valid
`BPF_ANY` update in a non-evicting HASH map:

1. updating an existing key succeeds without changing `K`;
2. inserting a fresh key below `max_entries` succeeds and adds the key;
3. inserting a fresh key at capacity fails and preserves `K`.

The baseline recognizer validates the static map/operation contract, explores
both values of the first selector, and then applies an actual join at
`after-first-update-before-second`.  Its emitted cell retains the fixed
context and sound must/may/size invariants but deliberately does not retain the
exact key set.  Its declared concretization therefore contains both reachable
states `K={S}` and `K={S,A}`.

The common suffix updates fresh key `B` and observes whether the return is
successful.  It produces `1` from `{S}` and `0` from `{S,A}`.  Exact finite
Mealy partition refinement places the two states in different
future-observation classes, while the emitted report places both in one unique
cell.  Therefore no `h` can satisfy `beta_D = h o pi_R` on this fiber.

## Evidence-generation order

1. `V_linux_r` runs from the symbolic program and writes the computed report.
   Concrete witness outputs are not an input to this step.
2. `I_hash` enumerates the finite context fiber and suffix traces.
3. The generator computes the discipline and quotient, then persists the
   bundle and a SHA-256 manifest.
4. A separate checker rereads the immutable report and independently
   recomputes reachability, gamma membership, unique coverage, the quotient,
   and factorization verdict.
5. On Linux, the existing `wm_circuit` eBPF artifact is loaded and run for
   assignments `(a,b)=(0,1)` and `(1,1)`.  These traces calibrate `I_hash` and
   bind the evidence to one accepted program tag and object hash.  Exact errno
   identity is deliberately outside the contract.

The report also records a 21-case exhaustive abstract-transfer check over all
`K subseteq {S,A,B}` with `|K|<=2` and each update key.  Four negative controls
must not establish R:

- `occupancy_tracking`: exact cells separate the two occupancies;
- `cap64`: both suffix updates succeed;
- `forced_sentinel`: both paths update an existing sentinel;
- `unobserved`: the return distinction is erased by the observer.

## Run and verify on Linux

```bash
make linux-r
make verify-linux-r
```

The recorded bundle is `results/linux_r/linux-r-v1/`.  A successful audit ends
with:

```text
ADM_PASS: PASS
SAME_COMPUTED_CELL_PASS: PASS
BETA_DIFFERENT_PASS: PASS
NON_FACTORIZATION_PASS: PASS
VERDICT: PASS
```

Unit tests also mutate hashes, remove coverage, and introduce overlapping
cells to ensure the checker rejects malformed evidence:

```bash
python3 -m unittest tests.test_linux_r -v
```
