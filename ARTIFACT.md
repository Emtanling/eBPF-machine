# Artifact Notes

Repository: <https://github.com/Emtanling/eBPF-machine>

Interpreter evidence snapshot: commit
[`4309069a`](https://github.com/Emtanling/eBPF-machine/tree/4309069a1f94d642d5c1402eb710e089c85059b1)

Canonical evidence bundle:
`results/interpreter/interpreter-final-20260711-02/`

Auxiliary report-instance evidence snapshot: commit
[`f665b1a`](https://github.com/Emtanling/eBPF-machine/tree/f665b1a2f9a772ee9b2c08a73d116ea283aa5efb)

Auxiliary report-instance evidence bundle:
`results/linux_r/linux-r-v1/`

Frozen stock-Linux V1 evidence bundle (legacy-adapter output; current semantic
query `UNKNOWN`):
`residuality-auditor/stock-linux-r-proof/`

Public stock-Linux evidence snapshot:
[`V1.0`](https://github.com/Emtanling/eBPF-machine/tree/V1.0/residuality-auditor/stock-linux-r-proof)

Prepublication complete Residuality Auditor archive SHA-256:
`5fd0a2812c8c8db2fe5508440934817c1cf9293ba0c5df31317e8b38d94a90ec`

The prepublication archive hash records the full development package used to
prepare the evidence. The V1.0 tag publishes the frozen proof directory, its raw
and normalized evidence, proof records, manifests, and the minimal offline
checker. Current `main` additionally publishes the source-only native capture,
normalization, certificate-construction, and regression-test toolchain under
`residuality-auditor/`, including the finite-model positive and negative
controls consumed by its tests; generated builds, historical intermediate
outputs, and local caches remain excluded. Any frozen evidence change requires
a new tag and new checksums. The published bundle emits
`FROZEN_PROOF_BUNDLE_VERIFIED`.

## Scope

The paper's claim graph separates:

- **A — acceptance:** one fixed eBPF artifact is accepted;
- **C — causal state distinction:** the same suffix exposes different
  observations from two selected runtime states;
- **P — bounded programmability:** accepted code controls, observes, resets,
  and composes the gate under explicit implementation premises;
- **R — report-relative residual:** two witnesses occupy one actual computed
  report cell but different future-observation classes; and
- **W — policy/threat obligation:** an admitted actor can drive a
  policy-excluded effect.

The `wm_circuit` interpreter case records A, gives a conditional C witness under
the declared map-service/no-interference contract, and supports P under
additional source-to-object, helper, reset, frame, environment, and
serialization premises. It does not provide an interpreter-frontier
computed-cell extractor or deployment policy and therefore establishes neither
R nor W for that carrier.

A completed real local stock-Linux experiment on the separate verifier-accepted
XDP object `rac_single` has a frozen operational-prune evidence bundle. Its
kernel capture is primary evidence of one prune event and two same-suffix
samples; the integrated and frozen-bundle checkers replay a **legacy adapter**
that embeds those samples in a deterministic two-state model. Under the current
evidence-bounded contract, the exact real-system operational-prune query is
`UNKNOWN`: V1 does not establish stable must outcomes. The auxiliary finite
report tuple under `results/linux_r/` independently establishes R for its
custom report. The stock-Linux observations do not establish R, P, or W and
are not combined with `wm_circuit`.

## Implementation boundary

`wm_circuit` is one fixed verifier-accepted `SEC("syscall")` eBPF program. The
host parses strict WMC1 text and normalizes its executable core into maps; the
verifier accepts the eBPF artifact, not each descriptor.

The v1 descriptor domain has:

- at most 64 primary inputs;
- at most 512 NAND gates;
- constants in wires 0 and 1;
- canonical gate destination `2 + input_count + gate_index`; and
- at most 578 live wire cells.

The program revalidates ABI, count, opcode, canonical-destination, and
forward-reference conditions before or during interpretation. A nonzero status
masks the semantic wire result. Physical stale map cells are not treated as an
output.

Correctness requires globally serialized, mutually exclusive use of `TAPE`,
`CIRCUIT`, `WIRES`, `VM_CONTROL`, `VM_TRACE`, and `G0` throughout setup,
invocation, and readback. The supplied runner is serial; the eBPF program does
not implement a concurrency lock.

## Capacity gate

`G0` is a dedicated preallocated, non-LRU `BPF_MAP_TYPE_HASH` map with logical
capacity two. Reset leaves one sentinel entry. Input zero updates the sentinel;
input one selects a fresh input-specific key. The second update succeeds for
`00`, `01`, and `10`, and fails for `11`; the predicate `ret == 0` therefore
implements NAND. The argument uses only success versus a negative return, not a
portable errno value.

The concrete C witness compares inputs `(0,1)` and `(1,1)` immediately before
the second fresh-key update. The suffix, key, value, map identity and static
attributes, flags, program point, observer, kernel, object, schedule, and
no-interference environment are fixed. The selected component is the complete
helper-relevant dynamic state of `G0`, including occupancy and map-local
bucket/preallocated-element/free-list metadata; the occupied-key set is only a
derived proof projection. All suffix-read components outside that selected map
state are fixed. The suffix observations are success and failure under the
declared map-service contract.

## Frozen stock-Linux V1 evidence (superseded semantic interpretation)

The stock-Linux bundle comes from a completed local experiment using the XDP
program `rac_single` on Linux `6.17.0-35-generic`. The manifest binds the kernel
release, BTF/config hashes, object SHA-256, program id/tag/pin, and
translated-bytecode SHA-256. At translated instruction 41, the capture records
a successful exact-level-0 `states_equal` check followed by an
`is_state_visited` prune. Reviewed path correspondence binds the `a=0` and
`a=1` histories to one remaining suffix, and the two samples record program
success bits 1 and 0.

The frozen adapter makes a stronger historical claim by copying those samples
into a deterministic two-state/one-action model and emitting:

```text
STOCK_LINUX_R_ESTABLISHED_FOR_FROZEN_TUPLE
```

That string is retained as an immutable legacy-artifact result. It does **not**
establish that the sampled outcomes are real Linux must outcomes. The U1
evidence-contract regression imports only V1 identity/runtime/prune premises,
excludes the legacy factorization and verdict outputs, and classifies the exact
operational-prune query as `UNKNOWN`; a broader-runs query is also `UNKNOWN`,
and a Linux-functional-report query is `OUT_OF_SCOPE`. Therefore this artifact
must not be described as an R certificate or as a proof of real Linux report
non-factorization.

The retained V1 bytes remain valuable for provenance and for testing the
fail-closed reassessment. The active boundary is intentionally narrow: V1 is
legacy-adapter provenance, not a current semantic R verdict for real Linux.

Verify the frozen package from the Residuality Auditor checkout:

```sh
PYTHONPATH=. python3 -m tools.proof.check_frozen_bundle \
  stock-linux-r-proof
```

Expected output is `FROZEN_PROOF_BUNDLE_VERIFIED`. This verifies the immutable
legacy package, not a current semantic R verdict. It is author-generated and
author-reviewed provenance for one frozen kernel/object tuple, not an
independent reproduction or a frequency/generalization study.

## Prospective Stock-R V2 and generic EBRC U4

V2 is a separate accepted `rac_v2` witness and exact query; it does not modify
or supersede the immutable V1 bytes. Its runner precommits an outcome-free
query and selection policy, captures one qualifying operational prune, repeats
both runtime cases, checks a V2-local must-outcome proof, and checks a
history-case binding that joins the selected histories to proof cases 0/1 at
one frontier, report cell, observer, suffix, and exact scope.

One fresh privileged run on stock Ubuntu kernel `6.17.0-35-generic` reports:

```text
outcome_eligibility.status = ESTABLISHED
outcome_eligibility.method = MUST_OUTCOME_PROOF_WITH_HISTORY_CASE_BINDING
assessment.status = NONFACTORING
assessment.scope = EXACT_STOCK_R_V2_QUERY
assessment.certificate = NONFACTORING@1d5f86d80494575c23f539248614105559dd15380c580d0d2388c24941b6d255
```

The U4 layer compiles source-validated V1/V2 evidence to a typed claim,
evidence graph, and proof DAG. Its generic checker ignores stored terminal
verdict labels: V1 becomes `BLOCKED/INCONCLUSIVE`, while the complete V2
control becomes exact `CERTIFIED/NONFACTORING`. A hostile matrix blocks five
unsupported claim lifts and rejects seven proof-wide or integrity/dependency
attacks. The focused EBRC suite passes 11 tests, the context-runner suite passes
8 tests, and the complete Stock-R suite currently passes 172 tests after the
replay additions.

The public replay capsule now contains the retained V2 source bundle and two
selected contextual target bundles. It is stored at:

```text
residuality-auditor/artifact/evidence/replay-capsule.tar.xz
sha256 = 3df6b96e3dded26e9f876db8f607278bc0a65a6df31b297cb6bd3043f44151f7
size = 2,208,232 bytes
members = 58
```

Run the release-grade offline replay with:

```sh
python3 -m pip install -e './residuality-auditor[test]'
make reproduce-paper
```

Expected output is `all_expected=true` and `unexpected_results=0`. The replay
verifies the capsule hash and manifest, safely extracts only manifested regular
files, recompiles the V1/V2/CRL certificates with the current checkers, reruns
the V2 and contextual hostile matrices, and compares the normalized summary to
`residuality-auditor/artifact/expected-results.json`. After dependency
installation, the replay requires no network access and does not run privileged
BPF code.

To rerun the bounded contextual VM matrix, use a supported Linux VM, the
retained V2 source bundle, and a fresh output directory:

```sh
make contextual-matrix-live \
  STOCK_R_V2_BUNDLE=residuality-auditor/output/stock-r-v2-u3-live-20260719-01 \
  CONTEXT_MATRIX_OUT=residuality-auditor/output/contextual-matrix-live-YYYYMMDD-NN
```

The published matrix summary is
`residuality-auditor/artifact/evidence/contextual-matrix-live-20260720-03.json`.
It uses `BOUNDED_CONTEXT_SUITE_ONLY` and reports 12 expected cases: six
certified transparent targets and six fail-closed hostile or
missing-obligation targets. These artifacts establish no Linux-specified
functional report, cross-kernel transport, family-wide claim,
source-to-bytecode correctness, vulnerability, general Linux R, or new
foundational theorem.

## Contextual Residual Lifting U5/U6

CRL is a guarded transport layer over the exact V2 source certificate.  Its
abstract proof obligations and hostile countermodels are encoded directly in
the CRL checker, schemas, tests, and retained matrix. The executable checker
requires a `DERIVED_CONTEXTUAL` chain that binds the source claim digest,
transform digest, and target claim digest before it can emit a target
`TRANSPORTED` certificate.

The two contextual target bundles selected for the replay capsule are:

```text
transparent.xor.depth1
transparent.add-mul.depth2
```

They derive:

```text
status = CERTIFIED
assessment = NONFACTORING
evidence_grade = TRANSPORTED
derivation_kind = DERIVED_CONTEXTUAL
certificate = NONFACTORING@23b72c129e12520df1b05580f4ab74582f49b4e4f442db3e05e207a7deffc1e2
certificate = NONFACTORING@1d19c14f69a186648acaeee58c57c68faf7b9719a51b2e870e53bafb81efc663
```

Both target translated-bytecode digests differ from the source V2 digest and
from each other, each runtime bridge is `VERIFIED` for four trials, and each
contextual hostile matrix reports `all_expected = true` with three blocked
unsupported claims and nine invalid graphs. These are generated target-bound
transport instances. They are
not a `FORALL` context theorem, compiler-correctness proof, Linux functional
report, verifier unsoundness result, vulnerability, P, W, or weird-machine
claim.

## Verify the auxiliary R certificate

Rerun the separately implemented, author-run checker on the archived auxiliary
bundle:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 \
  results/linux_r/linux-r-v1/linux_r_audit.py \
  results/linux_r/linux-r-v1 --require-kernel
```

The expected audit establishes `R(M_linux_r_aux_v1)` while explicitly leaving
`R(stock Linux verifier,I_Linux)` unestablished for that auxiliary carrier. Its
four VM-oracle rows calibrate only two service outcomes. Parser/CLI regression
tests are secondary and do not replace this checker or the archived bundle.

## Verify the preserved run

```sh
make verify-interpreter
```

Equivalent explicit command:

```sh
make verify-interpreter \
  INTERPRETER_RUN=results/interpreter/interpreter-final-20260711-02
```

The semantic auditor independently reconstructs descriptor and circuit
semantics, regenerates the fixed-seed corpus and both boundary descriptors,
checks gate traces and negative controls, and matches each runtime program tag
to the preserved variant. The provenance verifier checks the bundle against its
self-issued SHA-256 manifest.

Run every published evidence checker with:

```sh
make verify
```

This invokes the interpreter verifier, the auxiliary R verifier, and the
frozen stock-Linux legacy-bundle verifier.

Expected canonical totals:

| Evidence row | Count |
|---|---:|
| per-gate records | 26,488 |
| successful run records | 12,037 |
| fail-closed negative controls | 8 |
| **total JSONL rows** | **38,533** |

Coverage includes:

- nine named circuits with exhaustive inputs;
- 100 fixed-seed random DAGs;
- a 512-gate deep boundary;
- a joint 64-input/512-gate/578-wire boundary;
- a zero-gate descriptor;
- 10,000 successive serial invocations; and
- capacity-64, forced-sentinel, and explicit-logic controls.

Finite testing is regression evidence for the implementation and its proof
premises. It is not an empirical proof over every descriptor in the bounded
domain.

## Bundle inventory

The canonical directory contains:

- `environment.txt` and `feature_probe.txt`;
- named descriptors, generated corpus, and boundary descriptors;
- `interpreter_*.jsonl` execution records;
- four preserved variants with objects, harnesses, verifier logs, translated
  bytecode, and loaded-program metadata;
- `source/`, the then-current selected source/manuscript snapshot used by the
  run (not the later final manuscript);
- `interpreter_audit.txt`; and
- `interpreter.provenance.json`.

Historical runs, root-level result copies, old variant archives, and build
products are intentionally excluded from the public tree. They are reproducible
with the scripts but are not additional independent evidence.

## Regeneration

In an isolated Linux VM with the required BPF privileges and toolchain:

```sh
make test
make
make circuits
make interpreter-data
make verify-interpreter INTERPRETER_RUN=results/interpreter/<run-id>
```

`scripts/run_interpreter_suite.sh` snapshots selected source, builds normal,
capacity-64, sentinel, and explicit variants, generates the named/random/boundary
descriptors, runs the datasets serially, audits the results, and writes the
manifest.

Fresh result directories are ignored by Git. Replacing the canonical run is a
deliberate publication action, not a side effect of ordinary testing.

### Regenerate a stock-Linux capture

First perform a non-attaching prerequisite check, compile both tracing backends,
and run the active regression suite:

```sh
make stock-r-preflight
make stock-r-build
make test-stock-r-tools
```

Then, on an isolated Linux VM with suitable BPF privileges, follow
`residuality-auditor/REPRODUCE.md`. The preferred live backend is fexit, with a
kprobe fallback for kernels where the required BTF tracing attachment is not
available. The live runner captures raw events and tuple metadata, enriches the
events, emits an initial fail-closed contract/analysis, and screens candidate
prunes. The separate frontier, path, state, concretization, report-map,
subsumption, and proof tools consume the reviewed material needed to construct
and check a normalized proof bundle.

A fresh execution produces a new kernel/config/BTF/object tuple. Successful
compilation and offline tests establish tool availability, not repetition of
the published run; a fresh trace establishes only its new tuple and does not
silently replace `stock-linux-r-proof/`.

## Integrity and provenance boundary

The manifest binds every non-manifest file in the canonical run and rejects
changed, missing, duplicate, or newly unbound files. It supports reproducibility
and anti-mix-up checks only. It is not content-addressed storage, a signature,
an external timestamp, an authorship proof, or protection against coordinated
replacement of the complete bundle and manifest.

The captured loaded-program tags bind result rows to the preserved variants in
this run. Source-to-object correspondence beyond the captured build and manual
translated-code inspection remains an explicit premise; there is no
machine-checked eBPF-semantics proof.

## Not claimed

The artifact does not claim verifier bypass, unsound acceptance, privilege
escalation, memory corruption, production-data-path deployment, concurrent
safety, artifact-parametric compilation, or report non-factorization for
`wm_circuit` or for any real Linux kernel/object tuple, including the frozen
`rac_single` case. It also does not claim P or W for the R carrier, a
policy-level weird machine, or unbounded universality.
