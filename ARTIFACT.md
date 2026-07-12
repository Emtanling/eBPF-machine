# Artifact Notes

Repository: <https://github.com/Emtanling/eBPF-machine>

Canonical evidence bundle:
`results/interpreter/interpreter-final-20260711-02/`

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

The Linux case establishes A and C and supports P under the stated
source-to-object, helper, reset, frame, environment, and serialization premises.
It does not provide a Linux computed-cell extractor or deployment policy and
therefore establishes neither R nor W.

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
no-interference environment are fixed. Only the selected occupied-key set
differs, and the suffix observations are success and failure.

## Verify the preserved run

```sh
make verify
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
- `source/`, the selected source snapshot used by the run;
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

## Optional precision control

`witness2/` contains a small range-versus-relation experiment and an optional
Frama-C EVA model:

```sh
make verify-witness2
make verify-framac
```

The Boolean output range `[0,1]` is exact for every nonconstant Boolean
function, so it is not by itself evidence of relational opacity or a second
Linux witness. The directory is retained only as a precision control.

## Not claimed

The artifact does not claim verifier bypass, unsound acceptance, privilege
escalation, memory corruption, live-hook deployment, concurrent safety,
artifact-parametric compilation, Linux report non-factorization, a policy-level
weird machine, or unbounded universality.
