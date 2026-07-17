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

Frozen stock-Linux R evidence bundle:
`residuality-auditor/stock-linux-r-proof/`

Public stock-Linux evidence snapshot:
[`V1.0`](https://github.com/Emtanling/eBPF-machine/tree/V1.0/residuality-auditor/stock-linux-r-proof)

Prepublication complete Residuality Auditor archive SHA-256:
`5fd0a2812c8c8db2fe5508440934817c1cf9293ba0c5df31317e8b38d94a90ec`

The prepublication archive hash records the full development package used to
prepare the evidence. V1.0 publishes the frozen proof directory, its raw and
normalized evidence, proof records, manifests, and the minimal offline checker
directly rather than duplicating that archive in the repository. Any evidence
change requires a new tag and new checksums. The published bundle emits
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
XDP object `rac_single` has a frozen operational prune-report evidence bundle.
Its kernel capture is primary evidence; the integrated and frozen-bundle
checkers are offline validation layers. For the exact kernel/config/BTF/object/
translated-bytecode tuple, the evidence supports R only after the paper embeds
the two captured histories in an explicitly finite, phase-tagged, one-step
execution carrier and observation contract. Those choices were finalized
retrospectively, so the result is a trace-local certificate for an author-declared
analysis projection, not a general or Linux-specified functional-report claim. The
auxiliary finite report tuple under `results/linux_r/` independently establishes
R for its custom report. Neither R carrier establishes P or W, and neither is
combined with `wm_circuit`.

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

## Frozen stock-Linux R carrier

The stock-Linux result comes from a completed local experiment using a different
accepted artifact from the interpreter: the XDP program `rac_single` on Linux
`6.17.0-35-generic`. The manifest binds the kernel release, BTF/config hashes,
object SHA-256, program id/tag/pin, and translated-bytecode SHA-256.

The paper does not take the carrier's execution relation to be all possible
Linux executions. It defines `I_K` by restricting the two captured serialized
histories at the selected frontier and adding phase tags; this terminal-state
relation is manuscript-defined, not the bundle adapter's self-loop model. Its
sole macro-action executes the reviewed common suffix, and the two terminal
states have no outgoing action. This gives only the empty word and the one-step
suffix in the common future language.

At translated instruction 41, an fexit capture records a successful
exact-level-0 `states_equal` check followed by an `is_state_visited` prune. The
operational report cell is the retained-state representative reached by that
directed prune edge; `states_equal` is not treated as a symmetric equivalence
over complete concrete states. Reviewed path correspondence maps the `a=0` and
`a=1` histories to the same caller-side frontier and remaining suffix. Normalized
membership checks associate two constructed concretization witnesses, whose
recorded key-set projections are `{S}` and `{S,A}`, with the current and retained
captured verifier states and assign both to the unique representative
`516c47f044cc3fc3`.

The same translated suffix attempts a fresh-`B` insertion. Its recorded
program-level success bits are 1 and 0---not raw helper returns---so the two
concrete states occupy different finite
future-observation classes while the operational report map assigns them to the
same representative. The integrated evidence checker reports:

```text
STOCK_LINUX_R_ESTABLISHED_FOR_FROZEN_TUPLE
```

This string denotes passage of the bundle's tuple-specific evidence gates. It
does not certify a Linux-documented complete functional report or a theorem over
the full Linux execution space.

The raw capture-stage analyzer remains fail-closed and says R is not yet
established because frontier, report-contract, path, and concretization review
are not raw-event facts. Its evidence verdict is emitted only after the
normalized path, direct-membership, operational-report, session-completeness,
uniqueness, factorization, and hash gates pass.

The executable checker does not independently type-check the paper's `I_K`,
`D_K`, and `K_obs^K` wrapper or prove observation soundness for the full Linux
execution space. The formal R conclusion combines the checked evidence with the
paper's explicitly finite one-step construction; it is not a general Linux
semantics theorem. The checker compares the seven context fields declared in
the runtime contract. The manuscript instead selects the complete
helper-relevant dynamic G0 state (with key sets only as derived projections),
reviews the caller call/return path at translated PCs 41--44 and the
`shared_suffix` callee at PCs 107--122, and fixes helper/service choices in its
environment. The bundled adapter uses self-loops
only to recompute its stable quotient; the manuscript consumes the identical
depth-one split and does not treat repeated suffix execution as captured
evidence.

Verify the frozen package from the Residuality Auditor checkout:

```sh
PYTHONPATH=. python3 -m tools.proof.check_frozen_bundle \
  stock-linux-r-proof
```

Expected output is `FROZEN_PROOF_BUNDLE_VERIFIED`. This is author-generated and
author-reviewed evidence for one purpose-built existence witness on a real
frozen kernel/object tuple, not an independent reproduction or a
frequency/generalization study.

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

This invokes the interpreter, auxiliary R, and frozen stock-Linux R verifiers.

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
safety, artifact-parametric compilation, report non-factorization for
`wm_circuit` or any kernel/object tuple beyond the frozen `rac_single` case, P
or W for the R carrier, a policy-level weird machine, or unbounded universality.
