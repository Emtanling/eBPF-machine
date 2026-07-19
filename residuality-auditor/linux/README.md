# Linux R Extractor and Correlator

This directory upgrades Residuality Auditor from a finite-model checker to a
Linux verifier evidence pipeline. It instruments the verifier's actual state
pruning decision, records a controlled runtime same-suffix witness, and
correlates the two without treating printed verifier logs as computed cells.

## What is treated as a Linux computed cell?

For this tool, one **operational prune cell event** is observed when:

1. Linux `states_equal(env, old, current, exact)` returns true; and
2. the enclosing `is_state_visited(env, insn_idx)` returns `1`, meaning the
   current path was pruned as already covered.

The tracer stores the successful old/current pair, equality level, program
name, instruction frontier, state summary fingerprints, and jump-history
fingerprints. The successful kernel comparison—not the fingerprints—is the
membership evidence. Fingerprints support identity and path-difference checks.

## Capture-stage analyzer labels

The command produces one of three verdicts:

- `LINUX_R_NOT_ESTABLISHED`: at least one required evidence item is missing.
- `LINUX_R_CANDIDATE_REQUIRES_CONCRETIZATION_AND_REPORT_CONTRACT_REVIEW`:
  a real prune pair and runtime same-suffix divergence were correlated, but the
  analyzer/report contract has not been justified.
- `LINUX_R_ESTABLISHED_UNDER_DECLARED_CONTRACT`: all mechanical evidence is
  present and the supplied contract explicitly marks both the concretization
  and report-contract arguments as reviewed.

The last verdict is conditional on the supplied human-reviewed contract. It is
a legacy capture-stage label, not the final integrated Definition 2 verdict.
The tool cannot infer what Linux intended its verifier state to certify; the
frontier, path, state, concretization, report-map, uniqueness, subsumption, and
hash-bound proof gates described in `../REPRODUCE.md` remain separate.

## Included components

- `tracer/rac_tracer_fexit.bpf.c`: preferred BTF fexit backend.
- `tracer/rac_tracer_kprobe.bpf.c`: kprobe/kretprobe fallback.
- `tracer/rac_collect_*.c`: JSONL ring-buffer collectors.
- `witness/rac_witness.bpf.c`: controlled two-entry hash-map prefix/suffix.
- `witness/rac_witness.c`: runs both concrete prefixes, snapshots map keys,
  executes one common suffix, and writes runtime JSON.
- `scripts/run_linux_r.sh`: complete capture and correlation workflow.
- `fixtures/`: offline schema fixtures used by tests.

## Target and privileges

The tracer depends on verifier-internal functions and structures. It is
therefore **kernel-version-bound**, not a stable Linux UAPI. The preferred
backend requires BTF function IDs for `states_equal` and `is_state_visited`.
The fallback requires visible kprobe symbols. Loading tracing programs and the
witness normally requires root or appropriate BPF capabilities.

The original paper artifact used Ubuntu 24.04.3, Linux 6.17.0-35-generic,
aarch64, clang 18, bpftool 7.7, and libbpf 1.7. This package is prepared for
that family but generates `vmlinux.h` from the machine on which it is built.

## Dependencies

Ubuntu/Debian example:

```bash
sudo apt install clang llvm bpftool libbpf-dev libelf-dev zlib1g-dev \
  build-essential pkg-config python3
```

From the top-level `eBPF-machine` checkout, run the non-attaching preflight and
build targets:

```bash
make stock-r-preflight
make stock-r-build
make stock-r-v2-build
make test-stock-r-v2-local
make test-stock-r-tools
make test-stock-r-v2
```

Equivalently, from `eBPF-machine/residuality-auditor/`:

```bash
./linux/scripts/preflight.sh
make -C linux all
```

To build only the prospective Stock-R V2 tracer and witness:

```bash
make -C linux v2
```

## Live capture

From `eBPF-machine/residuality-auditor/`:

```bash
RAC_BACKEND=fexit ./linux/scripts/run_linux_r.sh output/linux-live
```

Use the fallback when fexit attachment is unavailable:

```bash
RAC_BACKEND=kprobe ./linux/scripts/run_linux_r.sh output/linux-live
```

Generated evidence:

```text
output/linux-live/
├── events.raw.jsonl
├── events.jsonl
├── runtime.json
├── object.sha256
├── program-info.json
├── program-pin.txt
├── xlated-rac_single.txt
├── xlated-rac_single.sha256
├── contract.json
├── analysis.json
├── analysis.md
└── prune-screen.tsv
```

The exact program remains pinned after collection so its kernel identity and
translated bytecode can be inspected. Run the explicit cleanup command printed
by the script after that inspection.

## Prospective Stock-R V2 capture

V2 uses a new invocation-scoped fentry/fexit tracer and array-map witness. It
does not mutate `stock-linux-r-proof/`, and repeated samples remain separate
from the checked must-outcome proof and the exact history-case binding.

```bash
./linux/scripts/run_stock_r_v2.sh output/stock-r-v2-$(date -u +%Y%m%dT%H%M%SZ)
```

The runner writes a self-contained bundle under the chosen output directory:

```text
output/stock-r-v2-.../
├── query/
├── contract/
├── raw/
├── build/
├── proof/must-outcome-proof.json
├── proof/history-case-binding.json
├── audit/audit.json
├── MANIFEST.json
└── CHECKSUMS.sha256
```

A V2 bundle without a checked proof remains `assessment.status = UNKNOWN` with
`outcome_eligibility.status = NOT_ESTABLISHED`. A checked proof without
`proof/history-case-binding.json` also remains `UNKNOWN`: the proof cases have
not yet been mechanically joined to the selected operational-prune histories.
The current runner writes both the V2-local proof and binding; when both pass
all structural gates, the auditor may report `assessment.status = NONFACTORING`
with `outcome_eligibility.method =
MUST_OUTCOME_PROOF_WITH_HISTORY_CASE_BINDING`, `assessment.scope =
EXACT_STOCK_R_V2_QUERY`, and `assessment.certificate =
NONFACTORING@<exact-scope-digest>`. See
`../../docs/design/stock-r-v2-experiment.md`.

The automatically generated contract deliberately leaves the bytecode
frontier, path correspondence, report-contract scope, and concretization
review unset. The first live run is therefore an evidence inventory, not an R
candidate. Select the relevant translated instruction frontier before asking
the correlator for a candidate verdict.

## Stock-R contextual target pilot

After a complete Stock-R V2 bundle has passed the exact EBRC checker, the
contextual pilot can generate one nontrivial target variant and derive a
target-bound CRL certificate:

```bash
PYTHON=/path/to/venv/bin/python \
  bash linux/scripts/run_stock_r_context.sh \
  output/stock-r-v2-YYYYMMDDTHHMMSSZ \
  output/stock-r-context-YYYYMMDDTHHMMSSZ
```

The runner builds a temporary transformed witness, loads it, dumps the target
translated bytecode, validates the target runtime bridge, derives the
`TRANSPORTED` EBRC certificate, runs the contextual hostile matrix, records
checksums, and removes the temporary bpffs pin before exit. This pilot
establishes only the generated exact target instance; it does not establish a
`FORALL` or general Linux claim.

## Reviewing the contract

For capture-stage diagnostics, after independently documenting the
verifier/report contract and the concretization relation, regenerate the
contract with explicit flags:

```bash
python3 linux/scripts/make_contract.py \
  output/linux-live/runtime.json \
  output/linux-live/contract-reviewed.json \
  --visit-insn 31 \
  --review-path-correspondence \
  --review-report-contract \
  --review-concretization
```

Then rerun:

```bash
PYTHONPATH=src python3 -m residuality_auditor.cli linux-r \
  output/linux-live/events.jsonl \
  output/linux-live/runtime.json \
  output/linux-live/contract-reviewed.json \
  --json-out output/linux-live/analysis-reviewed.json \
  --md-out output/linux-live/analysis-reviewed.md
```

Replace `31` with the verified translated-instruction frontier from your own
capture/disassembly. Do not enable these flags merely to obtain a stronger
label, and do not substitute this diagnostic for the normalized proof gates.
The written paper must explain why the selected component lies within the
intended report scope and why the concrete runtime executions belong to the
extracted cell.

## Witness semantics

The included witness uses a dedicated non-LRU hash map of capacity two.

- Prefix `a=0`: reset to `{S}`, then update existing `S`.
- Prefix `a=1`: reset to `{S}`, then insert fresh `A`, giving `{S,A}`.
- Common suffix: insert fresh `B`.

The suffix succeeds from `{S}` and fails from `{S,A}`. The user-space runner
serializes the executions and snapshots the concrete map key set before the
suffix. The verifier tracer independently records whether the prefix paths are
operationally pruned together.

## Important non-claims

- Similar state hashes are not treated as a computed cell.
- Similar verifier log lines are not treated as a computed cell.
- Runtime divergence without a successful prune event is only C, not R.
- A successful prune plus divergence is still not a policy-level W claim.
- The map-content example may expose intentional verifier abstraction rather
  than a verifier defect; report-contract review decides whether R is the
  appropriate paper-level interpretation.

## v0.3 single-artifact witness

The v0.2 witness placed branch-specific helper arguments at a common helper
call.  The emitted bytecode therefore joined while `r2` and `r4` still differed,
so stock Linux did not prune the two `rac_prefix` paths together.

The v0.3 witness replaces `rac_prefix`/`rac_suffix` with one program,
`rac_single`:

```text
branch a=1 -> BPF-to-BPF select_a() call --\
                                             -> post-call join -> shared_suffix()
branch a=0 -> BPF-to-BPF select_s() call --/
```

The branch-local helper arguments live in separate subprogram frames.  An
`audit` array map records the concrete G0 key set immediately before the shared
suffix, allowing user space to retain the runtime C witness after the complete
single-program execution.  The audit map does not steer the suffix.

After every build, inspect `output/linux-live/object-disassembly.txt`.  The
required shape is two distinct branch-specific pseudo-calls followed by one
shared post-call continuation.  Reject a build that again tail-merges the two
map-update calls before their arguments have been normalized.

Screen live events with:

```bash
./linux/scripts/screen_prunes.sh output/linux-live/events.jsonl rac_single
```

A useful next-stage event must have `histories_distinct=true`.  The default
contract still leaves the frontier and review fields unset; do not enable them
until the selected instruction is shown to be the post-call join leading to the
shared suffix.
