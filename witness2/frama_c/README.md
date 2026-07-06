# Frama-C EVA port — third-party reproduction of the second witness

Runs the **same construction** as `witness2/witness.py` through an independent,
production, sound abstract interpreter (Frama-C's EVA value analysis). This is what
upgrades the second witness from "our own interpreter is blind" to "an independent sound
analyzer we did not write is blind" — the third-party backing for the paper's
system-independence claim (§9.6).

Best run on **Ubuntu** (this repo's eBPF witness is Linux-only anyway, so the whole
artifact reproduces on one OS).

## Run

```sh
sudo apt-get update && sudo apt-get install -y frama-c   # Ubuntu one-liner
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

## The `slevel` knob = the repair of the repair outlook

EVA's `-eva-slevel N` controls how many states it keeps separate before joining. At
`slevel 0` it is join-based and blind (result above). Raising it (`run.sh` step 2) makes
EVA case-split the inputs — a disjunctive/trace-partitioned refinement — which is precisely
the *precision price* the repair outlook (§9) predicts for seeing through the channel. Same
tool, one flag, both sides of the boundary: opacity at `slevel 0`, repair as `slevel` grows.

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

The C source, commands, and expected numbers are fixed here; the captured tool output is
the one step that needs a machine with Frama-C (or the IKOS image) installed. Once
`out/eva_slevel0.log` shows `NAND_out ∈ {0;1}` and `ABLATION_out ∈ {1}`, cite it as the
independent-analyzer witness alongside the eBPF verifier.
