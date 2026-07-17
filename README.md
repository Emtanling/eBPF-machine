# After Acceptance: eBPF calibration and reproduction artifact

This is the minimal public evidence and reproduction artifact for *After
Acceptance: A Claim Graph for Residual Languages and Weird-Machine Claims,
Calibrated on eBPF*.

## Canonical paper

| Artifact | Path |
|---|---|
| English submission source | `PAPER_REPORT.tex` |
| English paper | `output/pdf/PAPER_REPORT.pdf` |
| English readable mirror | `PAPER_REPORT.md` |
| Chinese reading source | `PAPER_REPORT_ZH.tex` / `PAPER_REPORT_ZH.md` |
| Chinese reading PDF | `output/pdf/PAPER_REPORT_ZH.pdf` |

The English TeX/PDF pair is submission-normative. The Chinese edition is a
claim-synchronized reading aid.

## Evidence boundary

The repository keeps three separate carriers. They must not be combined into a
single certificate.

| Carrier | Established evidence | Frozen path |
|---|---|---|
| `wm_circuit` interpreter | A; conditional C; bounded P under the paper's premises | `results/interpreter/interpreter-final-20260711-02/` |
| Auxiliary finite report instance | R for its custom report only | `results/linux_r/linux-r-v1/` |
| stock-Linux `rac_single` tuple | retrospective, trace-local R for the author-declared operational prune-report | `residuality-auditor/stock-linux-r-proof/` |

No carrier establishes W, a policy-level weird machine, verifier unsoundness,
a vulnerability, privilege escalation, memory corruption, or a general Linux
functional-report failure.

## Minimal repository layout

- `src/`, `scripts/`, `tests/`, `circuits/` — interpreter implementation,
  generation/audit tools, tests, and the nine source circuit specifications.
- `results/interpreter/interpreter-final-20260711-02/` — self-contained
  interpreter evidence, including source snapshot, descriptors, JSONL records,
  verifier/runtime logs, variants, audit output, and integrity manifest.
- `results/linux_r/linux-r-v1/` — self-contained auxiliary R certificate,
  checker, model, four-row kernel calibration, logs, and manifest.
- `residuality-auditor/stock-linux-r-proof/` — frozen stock-Linux capture,
  normalized certificates, proof outputs, checker sources, tests, checksums, and
  manifest.
- `residuality-auditor/linux/` — source-only fexit/kprobe collectors, BPF
  tracers, witness, state schema, preflight checks, and live-capture pipeline.
- `residuality-auditor/src/`, `tools/`, `tests/`, `examples/`, and
  `pyproject.toml` — active analysis package, certificate
  construction/checking tools, finite-model controls, and regression tests used
  by the stock-Linux experiment.
- `ARTIFACT.md` and `ETHICS.md` — interpretation, provenance, and safety limits.

Historical drafts, internal reviews, duplicate PDFs, build directories, and
intermediate experiment outputs not used by the paper are intentionally absent.

## Verify all frozen evidence

Run all three evidence checks:

```sh
make verify
```

Equivalent commands are:

```sh
make verify-interpreter
make verify-aux-r
make verify-stock-r
```

The stock-Linux check must print:

```text
FROZEN_PROOF_BUNDLE_VERIFIED
```

The evidence is author-generated and author-reviewed. Checksums detect drift
and mix-ups; they are not signatures, external timestamps, or independent
reproduction.

## Build and test the interpreter

Requirements: Linux with BTF at `/sys/kernel/btf/vmlinux`, `clang`, `bpftool`,
`libbpf`, `pkg-config`, `libelf`, `zlib`, Python 3, and a C compiler. Loading the
recorded program requires suitable privileges.

```sh
make test
make
make circuits
```

Generated build files, `src/vmlinux.h`, and generated WMC1 descriptors are
ignored by Git.

## Build and test the stock-Linux reproduction code

Requirements: Linux with kernel BTF, `clang`, `bpftool`, `libbpf`, `pkg-config`,
`libelf`, `zlib`, Python 3, and a C compiler.

```sh
make stock-r-preflight
make stock-r-build
make test-stock-r-tools
```

The first two commands inspect prerequisites and compile the fexit/kprobe
collectors and `rac_single` witness. They do not attach probes. The test command
exercises the active normalization, report, path, state, subsumption, and proof
logic. `make verify-stock-r` remains the immutable, offline certificate check.

To perform a fresh native capture on an isolated Linux machine, follow
`residuality-auditor/REPRODUCE.md`. The live command requires elevated BPF
privileges, attaches tracing programs, loads and pins the witness temporarily,
and produces a new tuple-specific output directory. A new run is not the frozen
V1.0 tuple and must not replace its evidence without new manifests and a new
version.

## Rebuild the papers

English:

```sh
pdflatex -interaction=nonstopmode -halt-on-error \
  -output-directory=output/pdf PAPER_REPORT.tex
pdflatex -interaction=nonstopmode -halt-on-error \
  -output-directory=output/pdf PAPER_REPORT.tex
```

Chinese:

```sh
xelatex -interaction=nonstopmode -halt-on-error \
  -output-directory=output/pdf PAPER_REPORT_ZH.tex
xelatex -interaction=nonstopmode -halt-on-error \
  -output-directory=output/pdf PAPER_REPORT_ZH.tex
```

The Chinese build requires CTeX and a CJK font such as Noto Serif CJK SC.

## Version and provenance

`V1.0` is the immutable public evidence snapshot cited by the paper. The
current `main` branch additionally publishes the source-only stock-Linux native
capture and certificate-construction toolchain; it does not alter any frozen
V1.0 evidence byte. Earlier interpreter and auxiliary evidence remain
addressable at commits
`4309069a` and `f665b1a`. The stock-Linux frozen payload is published directly
under `residuality-auditor/stock-linux-r-proof/`; changing any frozen byte
requires a new version, updated checksums, and renewed verification.

See `ARTIFACT.md` for the exact claim/evidence mapping and `ETHICS.md` for the
isolation and safety statement.
