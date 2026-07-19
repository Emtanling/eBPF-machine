# Reproduce the stock-Linux capture

This guide separates six operations that should not be conflated:

1. verify the immutable published trace certificate;
2. rebuild and test the capture/analysis code;
3. execute a fresh privileged capture on a particular Linux kernel tuple;
4. replay the public Stock-R V2/CRL capsule without rerunning the VM;
5. derive guarded contextual target certificates from an already certified
   exact Stock-R V2 source bundle; and
6. review, check, and freeze a new tuple-specific proof bundle.

## 1. Verify the published certificate

From this directory:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. \
  python3 -m tools.proof.check_frozen_bundle stock-linux-r-proof
```

The expected final line is:

```text
FROZEN_PROOF_BUNDLE_VERIFIED
```

This is an offline integrity and evidence-gate check. It does not load a BPF
program or claim independent reproduction.

## 2. Rebuild and test the complete source path

Use a Linux machine with kernel BTF at `/sys/kernel/btf/vmlinux`, `clang`,
`bpftool`, `libbpf`, `pkg-config`, `libelf`, `zlib`, Python 3, GNU Make, and a C
compiler. From the repository root:

```sh
make stock-r-preflight
make stock-r-build
make test-stock-r-tools
```

The build produces ignored files under `residuality-auditor/linux/build/`.
Neither the preflight nor build target attaches probes or loads the witness.

## 3. Run a fresh native capture

Use an isolated VM. The runner invokes `sudo`, attaches a kernel tracing
collector, loads the XDP witness, and temporarily pins the loaded witness under
bpffs. Review `linux/scripts/run_linux_r.sh` and `linux/README.md` before running
it.

From this directory, prefer fexit:

```sh
RAC_BACKEND=fexit ./linux/scripts/run_linux_r.sh output/linux-live
```

If preflight reports that the required fexit/BTF attachment is unavailable, use
the kprobe fallback:

```sh
RAC_BACKEND=kprobe ./linux/scripts/run_linux_r.sh output/linux-live-kprobe
```

Use a new output directory for every run. The runner records raw events,
environment and loaded-program metadata, object and translated-bytecode
digests, enriched events, a report contract, analyzer output, and prune-screen
results. Follow the cleanup instructions printed by the runner for any pinned
object left for inspection.

## 3b. Run the prospective Stock-R V2 experiment

V2 is a separate fail-closed experiment path. It precommits an outcome-free
query, source closure, build closure, and selection policy before tracer
attachment, witness load, or runtime observation. It then audits direct
verifier-prune capture, runtime trials, a V2-local must-outcome proof, and the
history-case binding that joins the selected prune histories to the proof
cases. Repeated samples alone are never promoted to must outcomes.

From this directory on a supported Linux host:

```sh
./linux/scripts/run_stock_r_v2.sh output/stock-r-v2-$(date -u +%Y%m%dT%H%M%SZ)
```

Without a checked proof, the expected positive structural shape is still an
epistemic `UNKNOWN`:

```text
operational_prune.status = OPERATIONAL_PRUNE_OBSERVED
runtime_replication.status = REPLICATION_OBSERVED
outcome_eligibility.status = NOT_ESTABLISHED
assessment.status = UNKNOWN
```

The current runner writes `proof/must-outcome-proof.json` and
`proof/history-case-binding.json` after sealing the translated bytecode. A
checked must-outcome proof without the binding remains `UNKNOWN`; it proves only
the named witness cases, not that the selected operational prune is the same
history/case pair. If the proof, binding, and every structural gate pass, the
proof-bound exact V2 result is:

```text
operational_prune.status = OPERATIONAL_PRUNE_OBSERVED
runtime_replication.status = REPLICATION_OBSERVED
outcome_eligibility.status = ESTABLISHED
outcome_eligibility.method = MUST_OUTCOME_PROOF_WITH_HISTORY_CASE_BINDING
assessment.status = NONFACTORING
assessment.scope = EXACT_STOCK_R_V2_QUERY
assessment.certificate = NONFACTORING@<exact-scope-digest>
```

If the tracer cannot attach, the event is ambiguous, the bundle is incomplete,
or the identity receipts do not match, V2 must report `INVALID_EVIDENCE` or
`OPERATIONAL_PRUNE_NOT_OBSERVED`; do not reinterpret that as a Stock-R result.
The claim boundary is exact-only: the V2 result is not a Linux functional
report, cross-kernel claim, vulnerability, P, W, or weird-machine result.

## 3b-release. Replay the public Stock-R V2/CRL capsule

The release artifact contains a deterministic capsule and normalized replay
oracle under `artifact/`. After installing `jsonschema` and `rfc8785` once, the
offline replay should require no network access:

```sh
python3 -m pip install -e './residuality-auditor[test]'
make reproduce-paper
```

Expected output:

```text
all_expected=true
unexpected_results=0
```

The capsule hash is:

```text
3df6b96e3dded26e9f876db8f607278bc0a65a6df31b297cb6bd3043f44151f7
```

`artifact/replay-manifest.json` records 58 members and an archive size of
2,208,232 bytes. The replay re-extracts the capsule safely, recompiles the
current V1/V2/CRL certificates through the current checkers, verifies V1 as
`BLOCKED/INCONCLUSIVE`, verifies V2 as exact `CERTIFIED/NONFACTORING`, verifies
two selected CRL target certificates, and reruns the V2 and contextual hostile
matrices. It does not use committed terminal JSON as a proof premise.

The retained live matrix summary is
`artifact/evidence/contextual-matrix-live-20260720-03.json`. It used
`BOUNDED_CONTEXT_SUITE_ONLY` and reports 12 expected results: six certified
transparent contexts and six fail-closed negative contexts. To rerun that
privileged matrix on a supported VM, use a fresh output directory:

```sh
make contextual-matrix-live \
  STOCK_R_V2_BUNDLE=residuality-auditor/output/stock-r-v2-u3-live-20260719-01 \
  CONTEXT_MATRIX_OUT=residuality-auditor/output/contextual-matrix-live-YYYYMMDD-NN
```

Offline replay is a release-grade reproducibility check for the retained
artifact bytes. The privileged matrix is a fresh VM execution. Neither is a
`FORALL` context theorem, arbitrary eBPF transport result, general Linux R
claim, compiler-correctness proof, vulnerability, P, W, or policy-level
weird-machine claim.

## 3c. Compile and check the generic exact EBRC certificate

After a source-specific adapter has validated a retained bundle, the U4
checker compiles it to a versioned claim, evidence graph, and proof DAG and
authorizes only the strongest exact claim derivable from those documents. From
this directory, check a complete V2 bundle with:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -m residuality_auditor.cli ebrc stock-r-v2 \
  output/stock-r-v2-YYYYMMDDTHHMMSSZ \
  --compiled-out output/ebrc-v2-compiled \
  --json-out output/ebrc-v2-result.json
```

The expected full-proof result is `CERTIFIED/NONFACTORING` with quantifier
`AT`, report authority `OPERATIONAL_OBSERVATION`, and evidence grade
`OUTCOME_FREE_PRECOMMITTED`. Check the immutable V1 bundle with:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -m residuality_auditor.cli ebrc stock-linux-v1 \
  stock-linux-r-proof \
  --compiled-out output/ebrc-v1-compiled \
  --json-out output/ebrc-v1-result.json
```

The expected V1 result is `BLOCKED/INCONCLUSIVE`; its strongest claim profile
contains `MAY_OUTCOME` and `REPORT_COLLISION`, not `NONFACTORING`. The V1
adapter deliberately ignores the frozen legacy terminal verdict.

The generic checker validates graph structure, payload digests, ordering,
outcome-to-selector dependency, proof-DAG references, and the finite U4 proof
rules. The source-specific adapters still validate and interpret the original
bundle bytes and proof calculus. This boundary is not a source-to-bytecode
compiler-correctness proof, typed scope transport, a finite-family cover, or a
general Linux R result.

Run the fixed hostile matrix against the compiled positive control with:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -m residuality_auditor.cli ebrc-mutations \
  output/ebrc-v2-compiled \
  --json-out output/ebrc-hostile-mutation-matrix.json
```

The command first requires a `CERTIFIED` baseline. Its expected summary is
five `BLOCKED` forbidden lifts and seven `INVALID_GRAPH` proof-wide or
integrity/dependency mutations, with `all_expected = true`.

## 3d. Check the synthetic CRL contextual transport rule

Contextual Residual Lifting (CRL) is a guarded U5 extension of the generic EBRC
checker. It does not add a `FORALL` EBRC rule. It derives only an exact
target-bound `NONFACTORING` claim with evidence grade `TRANSPORTED` when a
source certificate, context transform, transport proof, instruction
correspondence, footprint/effect contract, history map, observer/report/suffix
preservation, target-conformance bridge, and outcome-independent selection are
all present.

Generate and check the synthetic nontrivial control with:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -m residuality_auditor.cli ebrc-context \
  --compiled-out output/crl-u5-synthetic/positive/compiled \
  --json-out output/crl-u5-synthetic/positive/result.json
```

The expected result is `CERTIFIED/NONFACTORING` with quantifier `AT`, report
authority `OPERATIONAL_OBSERVATION`, and evidence grade `TRANSPORTED`.

Generate the identity control and the runtime-only blocked near-miss with:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -m residuality_auditor.cli ebrc-context --identity \
  --compiled-out output/crl-u5-synthetic/identity/compiled \
  --json-out output/crl-u5-synthetic/identity/result.json

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -m residuality_auditor.cli ebrc-context --runtime-only-blocked \
  --compiled-out output/crl-u5-synthetic/runtime-only-blocked/compiled \
  --json-out output/crl-u5-synthetic/runtime-only-blocked/result.json
```

The identity control may certify but is marked trivial. The runtime-only
near-miss must be `BLOCKED/INCONCLUSIVE` with
`TARGET_CONFORMANCE_BRIDGE` missing and no derived target proof trace.

Run the CRL hostile matrix with:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -m residuality_auditor.cli ebrc-context-mutations \
  output/crl-u5-synthetic/positive/compiled \
  --json-out output/crl-u5-synthetic/context-hostile-matrix.json
```

The expected matrix has `all_expected = true` and rejects proof-wide
quantifier/report promotion, missing bridge, footprint interference, incomplete
history maps, outcome-dependent transform selection, target-verdict circularity,
and stale transform bindings. The retained VM run described in this workspace
is under `output/crl-u5-synthetic-20260719-01/`.

## 3e. Run the Stock-R contextual VM target pilot

The synthetic U5 checker can be exercised against a real VM target generated
from a certified exact Stock-R V2 source bundle. The runner creates a temporary
Linux build tree, transforms `rac_v2_witness.bpf.c` by adding a restricted
post-collision framed computation, compiles and loads that target on the stock
VM, dumps the target translated bytecode, validates the target runtime contract,
and derives a target-bound `TRANSPORTED` CRL certificate from the source EBRC
certificate.

From this directory on the VM, after producing or selecting a complete V2
bundle:

```sh
PYTHON=/path/to/venv/bin/python \
  bash linux/scripts/run_stock_r_context.sh \
  output/stock-r-v2-YYYYMMDDTHHMMSSZ \
  output/stock-r-context-YYYYMMDDTHHMMSSZ
```

The expected successful shape is:

```text
context/result.json:
  status = CERTIFIED
  assessment = NONFACTORING
  quantifier = AT
  evidence_grade = TRANSPORTED

target/audit/runtime-validation.json:
  status = VERIFIED
  invalid_reasons = []

context/hostile-matrix.json:
  all_expected = true
```

The target translated-bytecode digest must differ from the source V2 digest,
and the temporary bpffs pin under `/sys/fs/bpf/rac-v2-context-*` must be removed
before exit. The public retained matrix/capsule selection in this workspace is:

```text
artifact/evidence/contextual-matrix-live-20260720-03.json
artifact/evidence/replay-capsule.tar.xz
```

The retained matrix selects `transparent.xor.depth1` with target certificate
`NONFACTORING@23b72c129e12520df1b05580f4ab74582f49b4e4f442db3e05e207a7deffc1e2`
and `transparent.add-mul.depth2` with target certificate
`NONFACTORING@1d19c14f69a186648acaeee58c57c68faf7b9719a51b2e870e53bafb81efc663`.
They establish two concrete nontrivial contextual target instances from a
12-case bounded contextual suite on that VM.
They are not a `FORALL` claim, a general Linux result, arbitrary eBPF context
transport, compiler correctness, verifier unsoundness, a vulnerability, P, W,
or weird-machine status.

## 4. Review and freeze a new legacy-adapter bundle

The live runner intentionally stops at a fail-closed evidence inventory. It
does not turn a prune event into R by setting a flag. The source packages under
`tools/frontier/`, `tools/path/`, `tools/state_v2/`,
`tools/concretization/`, `tools/report_map/`, `tools/subsumption/`, and
`tools/proof/` contain the normalization and independent evidence gates. The
published `stock-linux-r-proof/normalized/` and `proof/` trees show the required
versioned schemas for the frozen tuple.

After producing those proof objects for a **new** reviewed bundle, run the
integrated checker from this directory:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -m tools.proof.check_definition2 /path/to/reviewed-bundle \
  --refresh-manifest
```

A complete passing legacy-adapter bundle may emit
`STOCK_LINUX_R_ESTABLISHED_FOR_FROZEN_TUPLE`. That historical identifier means
only that the adapter's encoded gates pass on the retained files; it is not a
real-Linux R verdict. Freeze that new bundle to a new directory and version
with:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -m tools.proof.freeze_bundle \
  /path/to/reviewed-bundle /path/to/new-stock-linux-r-proof
```

Do not run `--refresh-manifest` against the published
`stock-linux-r-proof/`; verify it with the offline command in step 1 instead.

## Interpretation boundary

A fresh result is bound to its own kernel release, configuration, BTF, compiled
object, loaded-program identity, and translated bytecode. It is not identical
to the V1.0 frozen tuple merely because the sources are the same. Review and
freeze a new run separately; never copy it over `stock-linux-r-proof/` without
new manifests, checksums, and a new version.

The experiment supports one observed operational-prune edge and two samples for
its declared tuple. A legacy adapter may construct a finite-model factorization
result from them, but a real-Linux positive R claim additionally requires the
evidence-model outcome-eligibility and prospective-contract requirements. V1
does not meet them: its exact query is `UNKNOWN`. It does not establish a
general Linux functional-report failure, verifier unsoundness, a vulnerability,
privilege escalation, P, W, or a policy-level weird machine.
