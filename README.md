# After Acceptance: eBPF calibration and reproduction artifact

This is the minimal public evidence and reproduction artifact for *After
Acceptance: A Claim Graph for Residual Languages and Weird-Machine Claims,
Calibrated on eBPF*.

## Canonical paper

| Artifact | Path |
|---|---|
| English public manuscript source | `PAPER_REPORT.tex` |
| Rendered English PDF | `output/pdf/PAPER_REPORT.pdf` |
| English readable mirror | `PAPER_REPORT.md` |
| Chinese reading source | `PAPER_REPORT_ZH.tex` / `PAPER_REPORT_ZH.md` |
| Chinese reading PDF | `output/pdf/PAPER_REPORT_ZH.pdf` |

The English source is the canonical **public technical-report** manuscript;
it is not a double-blind CSF submission.  The tracked PDFs must be regenerated
after any source change. They were freshly rendered from the corrected sources
on 2026-07-20; their source hashes, renderer versions, page counts, and visual
review are recorded in [`output/pdf/BUILD-INFO.md`](output/pdf/BUILD-INFO.md).
The public source also contains author identity, repository links, and an
AI-assistance disclosure, so a future venue submission needs a separately
reviewed anonymous build rather than a rename of this PDF.
The Chinese edition is a claim-synchronized reading aid, not a submission
artifact.

## Evidence boundary

The repository keeps five separate carriers. They must not be combined into a
single certificate.

| Carrier | Established evidence | Evidence path |
|---|---|---|
| `wm_circuit` interpreter | A; conditional C; bounded P under the paper's premises | `results/interpreter/interpreter-final-20260711-02/` |
| Auxiliary finite report instance | R for its custom report only | `results/linux_r/linux-r-v1/` |
| stock-Linux `rac_single` tuple | one frozen prune event and two samples; legacy adapter factorization result only; current exact real-system query is `UNKNOWN` | `residuality-auditor/stock-linux-r-proof/` |
| prospective Stock-R V2 `rac_v2` tuple | one fresh exact operational `NONFACTORING` result under a checked must-outcome proof and history-case binding; generic EBRC result `CERTIFIED` only at that exact scope | `residuality-auditor/artifact/` replay capsule |
| Stock-R contextual target pilot | two generated nontrivial VM targets with separate target-bound `TRANSPORTED` CRL certificates derived from the exact V2 source certificate; bounded suite matrix is `BOUNDED_CONTEXT_SUITE_ONLY` | `residuality-auditor/artifact/evidence/contextual-matrix-live-20260720-03.json` |

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
- `residuality-auditor/src/residuality_auditor/ebrc*.py` and
  `residuality-auditor/schemas/ebrc-*.schema.json` — generic exact-claim EBRC
  checker, V1/V2 adapters, finite oracle, hostile mutation matrix, and public
  claim/graph/proof contracts.
- `ARTIFACT.md` and `ETHICS.md` — interpretation, provenance, and safety limits.

Historical drafts, internal reviews, build directories, and intermediate
experiment outputs not used by the paper are intentionally absent from the
repository root.  Frozen evidence bundles deliberately retain the historical
source snapshots needed to reproduce their own runs; those snapshots are not
the current manuscript.  Likewise, a rendered PDF is not current merely
because it is tracked: use `output/pdf/BUILD-INFO.md`, `ARTIFACT.md`, and the
replay commands below before treating it as a release artifact.

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

`FROZEN_PROOF_BUNDLE_VERIFIED` verifies the frozen bytes and replayability of
the legacy checker. It is not the current evidence-bounded verdict for the
real stock-Linux query. The active boundary is: V1 records one frozen prune
event and two samples, but its exact operational-prune query remains `UNKNOWN`
because no must-outcome proof is established.

## Replay the release-grade Stock-R capsule

The public Stock-R V2/CRL replay capsule is
`residuality-auditor/artifact/evidence/replay-capsule.tar.xz`.

```text
sha256 = 3df6b96e3dded26e9f876db8f607278bc0a65a6df31b297cb6bd3043f44151f7
size = 2,208,232 bytes
members = 58
```

Install the declared Python test dependencies once, then run offline replay:

```sh
python3 -m pip install -e './residuality-auditor[test]'
make reproduce-paper
```

Expected output:

```text
all_expected=true
unexpected_results=0
```

The command safely verifies and extracts the capsule, recompiles V1/V2/CRL
certificates through the current checkers, reruns the hostile matrices, and
compares the normalized result to `residuality-auditor/artifact/expected-results.json`.
It is a no-network-after-install replay of retained evidence, not a fresh
privileged experiment.

To rerun the bounded VM context matrix instead, use a supported Linux VM and a
fresh output directory:

```sh
make contextual-matrix-live \
  STOCK_R_V2_BUNDLE=residuality-auditor/output/stock-r-v2-u3-live-20260719-01 \
  CONTEXT_MATRIX_OUT=residuality-auditor/output/contextual-matrix-live-YYYYMMDD-NN
```

The published matrix is `BOUNDED_CONTEXT_SUITE_ONLY`: 12 fixed cases, six
transparent certified targets and six fail-closed negative targets. It does
not establish a `FORALL` context theorem, arbitrary eBPF transport, general
Linux R, compiler correctness, vulnerability, P, W, or policy-level
weird-machine status.

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
python3 -m pip install -e './residuality-auditor[test]'
make stock-r-preflight
make stock-r-build
make test-ebrc
make test-stock-r-tools
```

Run the install command once from the repository root in the Python environment
that will execute the tests. The Make target checks for its declared
`jsonschema` and `rfc8785` dependencies and fails with an install hint if they
are absent; it never installs packages or accesses the network itself.

The first two commands inspect prerequisites and compile the fexit/kprobe
collectors and `rac_single` witness. They do not attach probes. The test commands
exercise the active normalization, report, path, state, subsumption, legacy
proof logic, generic EBRC exact-claim controls, hostile mutation matrix, and the
U1 evidence-contract regression. The current VM suite reports
`make test-stock-r-tools` with 172 tests OK,
`make test-ebrc-context-runner` with 8 tests OK, and `make reproduce-paper`
with `all_expected=true`/`unexpected_results=0`. The V1 regression classifies
the V1 exact operational-prune query as `UNKNOWN`, because V1 does not establish
stable must outcomes. `make verify-stock-r` remains an immutable, offline
legacy-bundle check.

The Python wheel installs the three U1 and three EBRC U4 contract schemas below
`sysconfig.get_path('data')/share/residuality-auditor/schemas`. U1 supplies the
versioned JSON Schemas and test-side cross-document checks; U4 adds an
executable checker for its finite exact-claim fragment. Source-specific V1/V2
adapters remain in the trust path for interpreting original bundle bytes. The
source distribution is intentionally package-only: it
contains the Python package and schemas, not the repository's reproduction
tools or test suite. Use a Git checkout for full testing and reproduction.

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
