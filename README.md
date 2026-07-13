# After Acceptance: eBPF Post-Acceptance Calibration Artifact

This repository contains the paper, implementation, tests, and one canonical
evidence bundle for the bounded eBPF interpreter described in:

- `PAPER_REPORT.tex` — canonical IEEE/arXiv source;
- `output/pdf/PAPER_REPORT.pdf` — canonical compiled paper; and
- `PAPER_REPORT.md` — readable semantic mirror, not an arXiv submission source.

A complete Simplified Chinese reading edition is also provided:

- `PAPER_REPORT_ZH.md` — Chinese manuscript;
- `PAPER_REPORT_ZH.tex` — standalone CTeX source; and
- `output/pdf/PAPER_REPORT_ZH.pdf` — compiled Chinese paper.

The English TeX/PDF pair is the only submission-normative version. The Chinese
edition is a claim-synchronized reading aid rather than a line-for-line
translation and does not replace the English source. If wording differs, the
canonical English TeX controls.

The accompanying repository is
<https://github.com/Emtanling/eBPF-machine>.

## Claim boundary

The artifact records acceptance (**A**), gives a conditional same-suffix causal
state witness (**C**) under the paper's declared map-service/no-interference
contract, and supports bounded programmability (**P**) under additional
source-to-object, reset, frame, environment, and serialization premises. It
does **not** establish Linux report non-factorization (**R**) or a policy/threat
obligation (**W**).

There is no verifier bypass, privilege escalation, memory-corruption,
unprivileged-loadability, concurrency, or Turing-completeness claim.

## Repository layout

- `src/` — eBPF programs and userspace harnesses. `src/vmlinux.h` is generated.
- `circuits/*.json` — source specifications for the bounded WMC1 circuit domain.
- `scripts/` — descriptor tools, experiment runners, auditors, and provenance
  writers.
- `tests/` — logic, parser, audit, provenance, and source-guard tests.
- `results/interpreter/interpreter-final-20260711-02/` — the only versioned
  canonical run, including descriptors, JSONL evidence, four preserved
  variants, verifier logs, a then-current source/manuscript snapshot, semantic
  audit, and integrity manifest. The final manuscript postdates the run and is
  not covered by that manifest.
- `witness2/` — a small optional precision-control experiment; it is not a
  second Linux opacity witness.

Historical runs, root-level result copies, build products, generated WMC1 files,
and internal review drafts are intentionally not versioned.

## Requirements

- Linux with BTF at `/sys/kernel/btf/vmlinux`;
- privileges sufficient to load `SEC("syscall")` eBPF programs;
- kernel 5.17 or newer for `BPF_PROG_TYPE_SYSCALL` and `bpf_loop()`;
- `clang`, `bpftool`, `libbpf`, `pkg-config`, `libelf`, `zlib`, Python 3, and a C
  compiler.

The recorded witness uses preallocated, non-LRU `BPF_MAP_TYPE_HASH` gate maps
and `BPF_ANY` updates. Correct interpreter use requires one globally serialized
critical section around configuration, invocation, and readback of the shared
map set.

## Build and test

```sh
make test
make
make circuits
```

These commands regenerate `src/vmlinux.h`, `build/`, and textual WMC1
descriptors as needed. Those generated files are ignored by Git.

Compile the Chinese reading edition with XeLaTeX:

```sh
xelatex -interaction=nonstopmode -halt-on-error \
  -output-directory=output/pdf PAPER_REPORT_ZH.tex
xelatex -interaction=nonstopmode -halt-on-error \
  -output-directory=output/pdf PAPER_REPORT_ZH.tex
```

This requires `texlive-xetex`, `texlive-lang-chinese`, and a CJK font such as
`Noto Serif CJK SC`.

## Verify the canonical evidence

```sh
make verify
```

This is an alias for verifying
`results/interpreter/interpreter-final-20260711-02/`. The separate semantic
auditor checks the preserved descriptors, named and random circuits, both
boundary descriptors, gate traces, negative controls, and captured program
tags. The provenance verifier checks every file against the bundle's self-issued
SHA-256 manifest.

The canonical run contains 38,533 JSONL rows:

- 26,488 per-gate records;
- 12,037 successful run records; and
- 8 fail-closed negative-control records.

It covers 100 fixed-seed random DAGs, a 512-gate chain, a joint
64-input/512-gate/578-wire boundary, a zero-gate descriptor, 10,000 serial
alternating invocations, and capacity-64, forced-sentinel, and explicit-logic
controls. These are regression and mechanism-attribution evidence, not an
enumeration of all valid descriptors or a concurrency proof.

The manifest detects accidental changes, missing files, and unbound additions.
It is not a signature, timestamp authority, independent reproduction, or
protection against a party able to replace the complete bundle and manifest.

## Regenerate experiments

Generate a fresh bounded-interpreter run in an isolated root-capable VM:

```sh
make interpreter-data
make verify-interpreter INTERPRETER_RUN=results/interpreter/<run-id>
```

Generate the additional gate/full-adder/adder regression suite:

```sh
make data
```

Fresh runs are deliberately ignored by Git. Publish a new run only after
auditing it and deliberately replacing the canonical evidence bundle.

## Optional precision control

```sh
make verify-witness2
make verify-framac
```

The first command runs a self-contained range-versus-relation model. The second
requires Frama-C EVA. Their scope and limitations are documented under
`witness2/`; neither result establishes a Linux verifier report collision.

See `ARTIFACT.md` for the exact evidence and interpretation boundary and
`ETHICS.md` for the safety statement.
