# `linux_r`: executable report-relative residual witness

`linux_r` is a small report-producing recognizer plus a finite interpreter for
the ordinary, non-evicting Linux `BPF_MAP_TYPE_HASH` update cases used by the
artifact's NAND gate.  Its precise result is:

```text
R(M_linux_r_aux_v1) = established
R(V_linux_r, I_hash) = established  [shorthand for that fixed tuple]
R(stock Linux verifier, I_Linux) = not established
```

The stock-Linux line is an essential scope boundary.  `V_linux_r` computes and
serializes its own abstract cells; the experiment does not relabel verifier
logs, BTF, or translated bytecode as stock-kernel abstract states.

## Claim and evidence boundary

The established claim is strictly relative to the recognizer and service
semantics named above.  In particular:

- `report.json` is the actual report produced by `V_linux_r`; its cells are not
  claimed to be cells of the stock Linux verifier;
- `I_hash` is the documented, restricted HASH-map update discipline exercised
  by this artifact, not a model of every Linux map implementation, scheduling
  behavior, or helper context;
- the kernel run is a calibration of that restricted service semantics and an
  acceptance observation for one concrete eBPF object.  It does not expose a
  stock-verifier concretization map, prove that two concrete states occupy one
  stock-verifier cell, or establish `R(V_Linux, I_Linux)` for the stock
  verifier.

Here `M_linux_r_aux_v1` fixes `V_linux_r`, `I_hash`, the program, frontier,
discipline, fiber, observation contract, and report instance.  Consequently,
a successful bundle establishes `R(M_linux_r_aux_v1)` only; the shorter
`R(V_linux_r, I_hash)` notation is an artifact-local alias.  Kernel logs, BTF,
translated instructions,
program tags, and `bpf_prog_info` metadata, when retained, are calibration or
provenance evidence; none is treated as the missing stock-verifier report-cell
interface.

## Recognizer and runtime

The fixed program is [`program.json`](program.json).  The concrete service
state is `(phase, K)`, where `K` is a subset of `{S,A,B}`.  For a valid
`BPF_ANY` update in a non-evicting HASH map:

1. updating an existing key succeeds without changing `K`;
2. inserting a fresh key below `max_entries` succeeds and adds the key;
3. inserting a fresh key at capacity fails and preserves `K`.

The baseline recognizer validates the static map/operation contract, explores
both values of the first selector, and then applies an actual join at
`after-first-update-before-second`.  Its emitted cell retains the fixed
context and sound must/may/size invariants but deliberately does not retain the
exact key set.  Its declared concretization therefore contains both reachable
states `K={S}` and `K={S,A}`.

The common suffix updates fresh key `B` and observes whether the return is
successful.  It produces `1` from `{S}` and `0` from `{S,A}`.  Exact finite
Mealy partition refinement places the two states in different
future-observation classes, while the emitted report places both in one unique
cell.  Therefore no `h` can satisfy `beta_D = h o pi_R` on this fiber.

## Evidence-generation order

1. `V_linux_r` runs from the symbolic program and writes `derivation.json`
   plus `report.json`.  The former records worklist provenance; only
   `report.json["report_cells"]` is the report-label interface.  Concrete
   witness outputs are not an input to this phase.
2. The generator closes and hashes the persisted report.  The witness phase
   receives only that closed report, enumerates the finite `I_hash` context
   fiber and suffix traces, and writes `analysis.json` with a `report_ref`.
   It has no report-producer API through which to revise the cells.
3. The generator persists the remaining bundle and a SHA-256 manifest.
4. A separate checker rereads `report.json` and independently recomputes
   reachability, gamma membership, unique coverage, the quotient, and the
   factorization verdict.
5. On Linux, the existing `wm_circuit` eBPF artifact is loaded and run for
   assignments `(a,b)=(0,1)` and `(1,1)`.  These traces calibrate `I_hash` and
   record one program tag together with the archived object/harness hashes.
   This is a calibration snapshot, not an independently signed attestation
   that the JSON rows originated from those binaries.  Exact errno identity is
   deliberately outside the contract.

The hashes are **self-recorded integrity bindings**, not signatures or an
independent commitment.  They allow the auditor to detect byte changes and
cross-file mismatches within a supplied bundle, but by themselves do not prove
authorship, wall-clock ordering, prior publication, or that the generator did
not create a different self-consistent bundle.  The two-phase program
structure, the separate audit implementation, deterministic regeneration of
the formal JSON for a fixed program/profile, and
external archival or version-control history provide those distinct kinds of
evidence.  Here, a "closed report" therefore means closed to the
witness-construction API and hash-checked within one run, not cryptographically
immutable in an adversarial sense.

The report records 21 domain/action return-class containment checks over all
`K subseteq {S,A,B}` with `|K|<=2` and each update key, plus two
report-cell successor-containment checks.  All must have zero violations.
Four negative controls must not establish R:

- `occupancy_tracking`: exact cells separate the two occupancies;
- `cap64`: both suffix updates succeed;
- `forced_sentinel`: both paths update an existing sentinel;
- `unobserved`: the return distinction is erased by the observer.

## Run and verify on Linux

```bash
make linux-r
make verify-linux-r
```

The recorded bundle is `results/linux_r/linux-r-v1/`.  A successful audit ends
with:

```text
ADM_PASS: PASS
SAME_COMPUTED_CELL_PASS: PASS
BETA_DIFFERENT_PASS: PASS
NON_FACTORIZATION_PASS: PASS
VERDICT: PASS
```

Unit tests also mutate hashes, remove coverage, and introduce overlapping
cells to ensure the checker rejects malformed evidence:

```bash
python3 -m unittest tests.test_linux_r -v
```

## Bundle closure and runner contract

For a kernel-calibrated archival bundle, the runner supplies a bounded
calibration snapshot.  Source/build inputs map to stable bundle names as follows:

```text
input                                      bundle file
circuits/nand.wmc                          nand.wmc
$WORK/build/wm_vm_user                     wm_vm_user
src/wm_vm_user.c                           wm_vm_user.c
src/wm_common.h                            wm_common.h
src/wm.bpf.c                               wm.bpf.c
$WORK/build/wm.bpf.o                       wm.bpf.o
Makefile                                   Makefile
src/vmlinux.h                              vmlinux.h
linux_r/run_kernel.sh                      run_kernel.sh
circuits/nand.json                         nand.json
scripts/circuit_tool.py                    circuit_tool.py
linux_r/model.py                           linux_r_model.py
linux_r/audit.py                           linux_r_audit.py
$WORK/toolchain.txt                        toolchain.txt
$WORK/kernel_oracle.jsonl                  kernel_oracle.jsonl
$WORK/kernel_oracle.stderr                 kernel_oracle.stderr
$WORK/build.log                            build.log
```

`program.json`, `derivation.json`, `report.json`, `analysis.json`, and
`manifest.json` are the model/report evidence generated from those inputs.
Every archived input must appear in the manifest with its path, byte size,
POSIX mode, and SHA-256 digest; the audit
must reject missing, extra, or changed files.

The model CLI exposes and `run_kernel.sh` passes the following discoverable
artifact arguments in addition to the oracle, log, BPF object, and BPF source:

```text
--descriptor circuits/nand.wmc
--harness-binary $WORK/build/wm_vm_user
--harness-source src/wm_vm_user.c
--common-header src/wm_common.h
--makefile Makefile
--vmlinux-header src/vmlinux.h
--runner linux_r/run_kernel.sh
--circuit-spec circuits/nand.json
--circuit-compiler scripts/circuit_tool.py
--model-source linux_r/model.py
--auditor-source linux_r/audit.py
--toolchain-log $WORK/toolchain.txt
```

When `--kernel-oracle` is present, generation rejects an incomplete artifact
set.  It validates the descriptor and source/build contract, copies all bound
inputs before manifest construction, and records their SHA-256 bindings.  The
independent `--require-kernel` audit then requires the calibration and its
artifact bindings.  It also parses the ELF64 section tables, rejects a
non-`EM_BPF` object or a non-Linux harness executable, checks the harness
architecture against the recorded host, and requires executable modes on the
archived harness and runner.  The snapshot still
depends on an external kernel, compiler, libbpf, and system libraries, and its
self-issued hashes do not prove execution provenance; it is therefore not a
hermetic or independently attested build closure.  This snapshot strengthens
reproducibility but does not change the claim boundary from
`R(M_linux_r_aux_v1)` to a claim about stock-verifier report cells.
