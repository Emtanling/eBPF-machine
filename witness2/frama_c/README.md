# Frama-C EVA port — third-party reproduction of the second witness

Runs the **same construction** as `witness2/witness.py` through an independent,
production, sound abstract interpreter (Frama-C's EVA value analysis). This is what
upgrades the second witness from "our own interpreter is blind" to "an independent sound
analyzer we did not write is blind" — the third-party backing for the paper's
system-independence claim (paper §7 and §9).

Best run on **Ubuntu** (this repo's eBPF witness is Linux-only anyway, so the whole
artifact reproduces on one OS).

## Run

```sh
sudo apt-get update && sudo apt-get install -y frama-c-base   # Ubuntu 24.04
bash run.sh                                              # captures out/*.log
```

## Result — CONFIRMED (Frama-C 25.0-beta, see RESULTS.md + out/eva_slevel0.log)

`frama-c -eva -eva-slevel 0 nand_mod.c` printed, at the `Frama_C_show_each` points:

| readout | EVA inferred value | meaning |
|---|---|---|
| `Frama_C_show_each_NAND_out`     | **`{0; 1}`** (full Boolean range) | **TOP → A-opaque**: EVA certifies nothing about the output bit |
| `Frama_C_show_each_ABLATION_out` | **`{1}`** (singleton)             | **certified**: the same analyzer *does* prove the degenerate gate |

with `acc ∈ {1;2;3}` in both gates and **0 alarms**. The contrast is the witness: a real,
sound analyzer is blind to the working `mod`-channel gate (output = the full Boolean range)
yet certifies the ablation (modulus 7, constant 1). That the blindness is *localized to the
working channel* — not a blanket weakness — is exactly the abstraction-gap outlook (below the complete shell at
`mod`) and the non-triviality point.

## The `slevel` knob = the repair outlook

EVA's `-eva-slevel N` controls how many states it keeps separate before joining. At
`slevel 0` it is join-based and blind (result above). Raising it asks EVA to keep more
states separate — a disjunctive/trace-partitioned refinement — which is the *precision
price* the repair outlook (§9) predicts for seeing through the channel. The repository's
self-contained `witness.py` demonstrates the same repair pattern by input partitioning.

## Optional: IKOS (interval domain, join-based) via Docker

```sh
docker run --rm -v "$PWD":/w ikosverif/ikos ikos /w/nand_mod.c
# inspect the interval invariant inferred for `out` (ikos-view or -d);
# expect the working channel's out invariant to be [0,1], the ablation's to be [1,1].
```

IKOS builds on the same numeric-domain family (Crab) that PREVAIL uses for eBPF, which
sharpens the contrast: the *path-sensitive* eBPF verifier and a *join-based* Crab/interval
analysis, structurally different, exhibit the same opacity.

## Honest status

The Frama-C EVA reproduction is complete for the working channel and ablation; see
`RESULTS.md` and `out/eva_slevel0.log`. IKOS remains optional follow-up evidence, not a
requirement for the current paper claim.
