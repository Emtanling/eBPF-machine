# After Acceptance: eBPF calibration artifact V1.0

This is the minimal public artifact for *After Acceptance: A Claim Graph for
Residual Languages and Weird-Machine Claims, Calibrated on eBPF*.

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
- `residuality-auditor/tools/proof/check_frozen_bundle.py` — standard-library
  verifier for the frozen stock-Linux bundle.
- `ARTIFACT.md` and `ETHICS.md` — interpretation, provenance, and safety limits.

Historical drafts, internal reviews, duplicate PDFs, build directories, and
experiments not used by the paper are intentionally absent from V1.0.

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

`V1.0` is the public tagged snapshot corresponding to this repository layout.
Earlier interpreter and auxiliary evidence remain addressable at commits
`4309069a` and `f665b1a`. The stock-Linux frozen payload is published directly
under `residuality-auditor/stock-linux-r-proof/`; changing any frozen byte
requires a new version, updated checksums, and renewed verification.

See `ARTIFACT.md` for the exact claim/evidence mapping and `ETHICS.md` for the
isolation and safety statement.
