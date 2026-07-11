# Frama-C EVA: global value-range observation

This directory contains a C rendering of modulo NAND for Frama-C EVA. Its scope
is deliberately narrow: it records **global value ranges**, not input/output
relations.

The source and current-run provenance classify this experiment as a numeric
precision control. Any source change requires a new Frama-C run and provenance
manifest before the evidence can be treated as bound again.

## Current input model

The current `nand_mod.c` obtains the two Boolean inputs independently:

```c
int a = Frama_C_interval(0, 1);
int b = Frama_C_interval(0, 1);
```

`__fc_builtin.h` is Frama-C's installed builtin header. Separate calls make the
intended four-row Boolean input space explicit; the model no longer relies on
two reads of one `volatile` object. The interface and example use are documented
in the [Frama-C 25.0 Manganese EVA manual](https://frama-c.com/download/eva-manual-25.0-Manganese.pdf).

## Reproduce the current model

On a system with Frama-C installed:

```sh
bash run.sh
```

Run the eBPF suite first so `results/env.json` and
`results/nand.provenance.json` identify the environment/run to which this
control is attached.

The script runs:

```sh
frama-c -eva -eva-slevel 0 nand_mod.c
```

and writes `out/eva_slevel0.current.log`. It also requires both independent
input ranges and the zero-alarm summary, then writes and re-verifies
`out/current.provenance.json`. That manifest binds the C source, runner,
provenance checker, current log, version record, environment snapshot, and eBPF
run ID by SHA-256. It deliberately does not overwrite the archived
`out/eva_slevel0.log`. Like the eBPF manifests, it is a self-issued consistency
record, not an external signature.

The corrected model was rerun on the recorded artifact VM with Frama-C
25.0-beta (Manganese). The current log reports `NAND_out: {0; 1}` and
`ABLATION_out: {1}`, with zero alarms. Its SHA-256 is
`6d496d5685ced6d0d0a33bc4e7ff6b67648b6bc0d3250a970dd6dfc203611176`.

## Historical log boundary

`out/eva_slevel0.log` is an unchanged historical run from Frama-C 25.0-beta
(Manganese). Its source used one `volatile int input` and assigned both `a` and
`b` from separate reads of that object. The log's locators
`nand_mod.c:41`/`:44` refer to that **old source revision**. The corrected source
happens to place the display calls on the same line numbers, but that coincidence
does not bind the historical log to the new source contents.

Therefore the historical log is not proof that the corrected independent-input
model runs or produces the same abstract values. That evidence is supplied only
by the separately generated `out/eva_slevel0.current.log`; the historical file
remains unchanged rather than being relabeled.

The historical run reported `{0;1}` for modulo NAND, `{1}` for the different
constant mod-7 control, `acc ∈ {1;2;3}`, and zero alarms. These observations are
retained only as provenance for the old model.

## Local syntax-only check

Without Frama-C, the C source can be parsed by a host compiler using an isolated
declaration stub:

```sh
bash syntax_check.sh
```

The stub is under `static_check/`; Frama-C's normal run does not add that path
and therefore uses its own `__fc_builtin.h`. Passing this syntax check does not
execute EVA and does not validate Frama-C-specific semantics.

## What a `{0,1}` result would and would not establish

`{0,1}` is the exact value range of every nonconstant Boolean function. An
ordinary projection and explicit NAND have the same global range. Consequently,
even a successful corrected-model rerun would establish only the reported
global value range. It would not establish:

- a modulo-specific loss relative to equivalent explicit NAND;
- failure of a completeness equation on the actual reachable value set;
- failure to certify an input/output graph under a relational query;
- relational opacity, a weird-machine interpretation, or cross-system
  generality.

The mod-7 observation is not a same-semantics ablation: it changes NAND into a
constant function. The relational comparison in `../witness.py` is a separate,
explicitly toy experiment; no Frama-C log supports its relational claims.
