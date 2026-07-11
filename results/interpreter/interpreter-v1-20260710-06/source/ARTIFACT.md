# Artifact Notes

## Target

- Program type: `BPF_PROG_TYPE_SYSCALL` via `SEC("syscall")`
- Execution: offline `bpf_prog_test_run_opts()`
- Maps:
  - `TAPE`: array map for input/output bits, setup/loop-error count, and the raw
    second-update helper observation
  - `G0..G8`: non-LRU `BPF_MAP_TYPE_HASH` maps used as NAND gate capacity state
  - `CIRCUIT`: WMC1 gate descriptors `(op,src0,src1,dst)` consumed by `wm_circuit`
  - `WIRES`: constants, primary inputs, and canonical SSA wire cells
  - `VM_CONTROL`: WMC1 version, input/gate/wire counts, and fail-closed status
  - `VM_TRACE`: one raw helper-return/output record for every interpreted gate
- Gate helper discipline: gate updates use `BPF_ANY`; gate maps omit
  `BPF_F_NO_PREALLOC`; the proof uses the success predicate `ret == 0`, not a
  kernel-stable errno value. The maps are ordinary `BPF_MAP_TYPE_HASH`, not
  per-CPU hash maps. Internal per-CPU allocation caches/spares do not change
  the logical `max_entries` capacity used by the experiment.

## Bounded Runtime Circuit Interpreter

`wm_circuit` is a fixed verifier-accepted `SEC("syscall")` eBPF program. It
does not receive generated BPF code or textual WMC1 input. The host parses
strict WMC1 text, validates the container-level fields, and normalizes its
*core gate descriptor* into `CIRCUIT`, `VM_CONTROL`, and input cells in
`WIRES`. The program consumes that core map configuration and serially reuses
`G0` for every NAND record. The independent v1 core language has:

- `0 <= input_count <= 64`;
- `0 <= gate_count <= 512`;
- constants in wires 0 and 1, inputs beginning at wire 2, and canonical
  destination `2 + input_count + gate_index`; and
- at most 578 live wire cells.

The eBPF program revalidates the normalized core execution shape in the
kernel. Before its loop, it writes the two constant cells and preserves the
host-installed primary-input cells; each successful iteration then writes only
its canonical destination.
Unsupported ABI, out-of-bound count, noncanonical destination, unsupported
operation, or forward reference produces a nonzero status rather than an output
claim. The textual WMC1 output list is parsed and range-checked by the host;
the eBPF program neither consumes nor validates it. The host projects selected
cells from the complete wire vector only after an OK status. A failing status
masks the observable wire result, so residual physical map contents after an
error are not an output claim.

Correctness requires a **globally serializable, mutually exclusive** use of
the entire shared map set (`TAPE`, `CIRCUIT`, `WIRES`, `VM_CONTROL`,
`VM_TRACE`, and `G0`) across descriptor/input installation, one invocation, and
status/trace/wire readback. “No concurrent writer during an invocation” is too
weak: a concurrent reader or a writer during setup/readback can observe or
create a mixed configuration. The supplied harness invokes this sequence
serially; it does not provide a synchronization implementation.

## Claims and Scope

**LangSec terminology.** `L_V` contains accepted program artifacts. `W_run(P)`
contains ordinary post-acceptance runtime operation words; only words with a
causally isolated residual-state-dependent observation under the declared
`K_res` enter `W_res(P;K_res)` and `L_res(V,I;K_res)`. Report uncertainty is a further obligation. “Contract-shape-
induced” is always relative to the declared safety/abstraction/report contract:
it excludes an implementation deviation from that contract, but a refined
report or restricted runtime can remove the gap.

**Directly established:**

- The capacity-dependent gate realizes NAND; the normal `(1,1)` row records a
  negative second-update return and the other inputs record zero.
- The recorded objects are accepted by the in-kernel verifier. The captured
  log supplies only a local empirical observation: a scalar return at the
  recorded helper frontier and both successors of its zero-test explored.
- One fixed accepted interpreter, reset discipline, and explicit canonical
  wires implement the WMC1 descriptor language; named circuits, random DAGs,
  a 512-gate chain, and a joint 64-input/512-gate/578-wire descriptor are
  runtime descriptions executed by the same object.
- Two BPF-produced variant fields (`variant_id`, `gate_cap`) identify the
  interventions; schema-v2 provenance binds source/build snapshots (including
  generated `vmlinux.h`), exact externally loaded objects, harnesses, logs,
  dumps, environment/kernel-BTF digest, and results.
- `witness2/` is a precision-control experiment only; its exact `[0,1]`
  Boolean range does not establish modulo-specific loss or system independence.

**Conditional formal scope:**

- Bounded data-parametric realization applies to one accepted interpreter
  `P_U` and the independently declared WMC1 descriptor language `D_{64,512}`
  under a safety-sound boundary, a uniform/total/deterministic gate basis,
  correct reset, frame preservation, and globally serializable mutually
  exclusive use of the entire shared map set through setup, invocation, and
  readback.
- The repository does **not** establish artifact-parametric compilation
  (`E4-A`): it does not prove that a separate generated BPF object is accepted
  for every circuit. The normalized descriptor is part of the initial map
  configuration `Enc_U(d,x)`; the induced execution schedule, not the
  descriptor text, is a word in `W_run(P_U)`. Neither is a member of `L_V` or
  automatically of `L_res`.
- Conditional Q-certificate opacity additionally requires one fixed sound
  `Extract_Q`, graph expressibility for a nonconstant target, and a checked
  persistent-alternative certificate through the complete schedule.
- This Linux artifact supplies no such extractor or persistent certificate and
  therefore does **not** instantiate the global opacity theorem.
- The verifier log is not itself a `Report_log`, `γ` relation, or transfer
  proof. Any use of it to instantiate Definition 5 or Proposition 3 is
  conditional on an explicit report interpretation plus local
  transfer-soundness and coverage arguments, none of which this artifact
  supplies.
- A recognizer-relative weird machine additionally needs an intended policy,
  threat model, actor control, and excluded security-relevant effect. This
  offline privileged artifact has none and is described as a
  **residual transducer with a local empirical scalar-return/zero-test
  verifier-log observation**, not as a demonstrated weird machine or a
  Definition-5 verifier-unresolved witness.

**Not claimed:** verifier bypass, vulnerability, privilege escalation, memory
corruption, unprivileged loadability, live-hook deployment, Turing completeness,
unbounded circuit realization, artifact-parametric BPF acceptance, standard
abstract-interpretation incompleteness, or whole-program Q-opacity.

## Expected Results

- `nand`: 400/400, exhaustive over the truth table `00,01,10,11 -> 1,1,1,0`
- `fa`: 8/8, exhaustive over all full-adder inputs
- `adder`: 1005/1005 (5 fixed corner cases + 1000 fixed-seed random 32-bit pairs)
- `adder-exhaustive 8`: 65536/65536, exhaustive over all 8-bit operand pairs
- `GATE_CAP=64` ablation: NAND degenerates to all-1 (400/400)
- `WM_FORCE_SENTINEL_B` ablation: NAND degenerates to all-1 (400/400)
- `WM_BASELINE_NAND` baseline: explicit bytecode NAND passes the normal truth table (400/400)
- Normal NAND raw helper return: `0` for inputs `00`, `01`, `10`; negative for
  input `11`. The exact negative errno is run evidence, not a portable premise.
- Both ablations record raw return `0`; the explicit baseline records
  `second_update_observed=false` and null raw-return fields.
- `make verify` aggregate: 68149/68149, `semantic audit: ok` (400 NAND + 8
  full-adder + 65536 exhaustive 8-bit adder-harness cases + 1005 sampled
  full-width cases + 1200 ablation/baseline truth-table checks)
- `make interpreter-data`: a fresh `results/interpreter/<run-id>/` with a
  passing `interpreter audit: ok` and `interpreter provenance: ok`. The recorded
  `interpreter-v1-20260710-04` run has 38,533 JSONL rows: 26,488 per-gate
  records, 12,037 successful runs, and eight fail-closed malformed-control
  records. It includes 100 fixed-seed random DAGs, a 512-gate chain, a joint
  64-input/512-gate/578-wire boundary, a zero-gate descriptor, 10,000 **serial**
  alternating invocations, and three mechanism variants. Its audit recompiles
  named/boundary sources and regenerates the corpus byte-for-byte, then
  cross-checks runtime BPF program tags against each captured variant. The
  alternating sequence checks reset/no-observed-state-contamination under one
  harness; it is not a concurrent-access test.

## Evidence Files

`scripts/run_kernel_suite.sh` produces:

- `results/env.json`
- `results/verifier.log`
- `results/feature_probe.txt`
- `results/nand_truth_table.jsonl`
- `results/full_adder.jsonl`
- `results/adder32.jsonl`
- `results/ablation_cap64.jsonl`
- `results/ablation_k2_sentinel.jsonl`
- `results/baseline_nand.jsonl`
- `results/audit_summary.txt`
- `results/check_summary.txt`
- `results/*.stderr`
- `results/<variant>.provenance.json` (schema-v2 run ID, timestamp,
  environment, build flags, and SHA-256 bindings for the declared per-variant
  objects, sources, logs, dumps, and result files)
- `results/variants/<run_id>/<variant>/wm.bpf.o` and `wm_user` (preserved exact
  object and userspace harness exercised for that variant)
- `results/<variant>.verifier.log` (per-variant verifier acceptance)
- `results/<variant>.wm_nand.xlated.txt` (verifier-processed eBPF bytecode;
  this is not JIT-native machine code)
- `results/adder32_exhaustive.jsonl` (exhaustive 8-bit adder, 65536 cases)
- `results/abstraction_gap_witness.md` (evidence note: concrete occupancy readout
  plus a local scalar-return/zero-test verifier-log observation; not a formal
  abstract-cell witness)
- `results/exploitable_gap.md` (legacy filename; corrected resource-bounded scope mapping)
- `witness2/README.md` and `witness2/witness.py` (self-contained precision control)
- `witness2/frama_c/RESULTS.md`,
  `witness2/frama_c/out/eva_slevel0.current.log`, and
  `witness2/frama_c/out/current.provenance.json` (corrected-model Frama-C EVA
  global-range evidence); `eva_slevel0.log` is retained only as a historical
  old-input-model log

`scripts/run_interpreter_suite.sh` produces one fresh
`results/interpreter/<run-id>/` directory containing:

- `variants/{normal,cap64,sentinel,baseline}/` with the exact BPF object,
  `wm_vm_user` binary, build log, verifier log, `wm_circuit` xlated dump, and
  program metadata for each variant;
- `descriptors/`, `corpus/`, and the generated 512-gate and joint
  64-input/512-gate/578-wire boundary sources and descriptors;
- normal, cap64, sentinel, baseline, random, boundary, zero-gate, negative,
  and stress JSONL datasets;
- `interpreter_audit.txt`, produced by `scripts/audit_interpreter.py`; and
- `interpreter.provenance.json`, produced and rechecked by
  `scripts/write_interpreter_provenance.py`, which SHA-256-binds every other
  file in the run directory. This is a self-issued integrity manifest: it
  detects missing, changed, duplicate, or unbound files relative to the
  manifest, but it is not content-addressed storage, a signature, or proof
  against a party able to rewrite and reissue the entire directory.

## Appendix A: Reproducibility and Audit Evidence

This appendix records the machine-checkable evidence emitted by
`scripts/run_kernel_suite.sh` for the run reported in the paper. All eBPF run
artefacts in A.1–A.10 are regenerated by `make data` and re-checked by
`make verify`. The A.11 precision control uses `make verify-witness2` and
`make verify-framac` separately.

Index: A.1 environment · A.2 per-variant provenance · A.3 verifier
acceptance · A.4 output = helper return · A.5 coverage & audit · A.6
one-command repro · A.7 residual-gate xlated · A.8 baseline xlated
(contrast) · A.9 local verifier witness · A.10 bounded formal scope · A.11
bounded interpreter run · A.12 precision-control experiment.

### A.1 Environment (`results/env.json`)

The authoritative host, kernel, architecture, toolchain, BTF availability, and
system-evidence hashes are machine-recorded in `results/env.json`. Each
schema-v2 provenance manifest embeds that JSON snapshot and binds the file by
SHA-256, so environment text in this document cannot silently drift from the
run. Regenerate the suite before reporting a different kernel or toolchain.

### A.2 Per-variant provenance binding

For every build variant, `scripts/run_kernel_suite.sh` creates a fresh run ID,
refuses to overwrite an existing run directory, preserves the exact BPF object
and userspace harness under `results/variants/<run_id>/<variant>/`, executes
that preserved harness, and only then writes
`results/<variant>.provenance.json`. The schema-v2 manifest includes:

- run ID, UTC timestamp, label, build flags, and verifier-load exit status;
- a hash-bound `env.json` plus the embedded parsed environment snapshot;
- SHA-256 bindings for the preserved BPF object, executed userspace binary,
  build log, source snapshot, verifier log, and xlated dump; and
- SHA-256 bindings for every JSONL result produced by that binary. The normal
  manifest binds NAND, full-adder, sampled 32-bit, and exhaustive 8-bit results;
  each ablation/baseline manifest binds its corresponding truth table.

`scripts/audit_results.py` recomputes every digest, rejects path escapes or
missing files, requires all four manifests to share one run ID and environment,
requires distinct variant objects, and rejects the legacy schema. Full hashes
inside the manifests are authoritative; this document intentionally does not
copy transient digest values. These checks provide content integrity,
source/result drift detection, and anti-mix-up evidence; they are self-issued
hashes, not signatures against a malicious party able to rewrite and reissue
the entire run.

### A.3 Verifier acceptance for every variant

All variants — including the ablations and the explicit-bytecode baseline — are
accepted by the in-kernel verifier: `bpftool_loadall_exit = 0` in every
`provenance.json`, with the full acceptance trace kept in
`results/<variant>.verifier.log`. The verifier reasons about memory safety and
bounded execution for this program. The artifact's narrower observed fact is
that the recorded log prints a scalar helper return and visits both successors
of the relevant zero-test (see A.4 and A.9). This is a local empirical log
observation, not a reconstructed abstract-state semantics, and it does not
infer an end-to-end functional proof from loader acceptance.

### A.4 The output is a helper return value, not computed logic

`results/<variant>.wm_nand.xlated.txt` holds the verifier-processed xlated eBPF
instruction stream of `wm_nand`; it is **not** a dump of architecture-specific
JIT-native machine code. For the normal variant it shows that inputs select
keys branchlessly, the second input-conditioned hash update returns the value
tested by `ret == 0`, that raw return is copied to the TAPE evidence slot, and
the same predicate becomes `IDX_NAND_OUT`. Instruction numbers and map IDs are
build-specific, so the bound run file—not a copied excerpt—is authoritative.

The JSONL provides the matching runtime observation on every row:

| input / variant | `second_update_observed` | raw return requirement | output |
|---|---:|---:|---:|
| normal `00`, `01`, `10` | true | `0` | 1 |
| normal `11` (fresh key at capacity) | true | `< 0` | 0 |
| capacity/sentinel ablations | true | `0` | 1 |
| explicit-logic baseline | false | `null` | normal NAND |

`second_update_errno` is derived as `-raw_ret` for negative returns and zero on
success. The exact number (for example `E2BIG` on a particular run) is reported
only from the new raw-return evidence. Neither source comments nor the audit
hard-code it as a stable cross-kernel contract. The portable premise is
success `0` versus a negative at-capacity failure. Although the default
preallocated hash implementation may use internal per-CPU freelists or spare
elements, the map here is an ordinary non-LRU `BPF_MAP_TYPE_HASH`; those
allocator details do not make it a per-CPU map or extend logical
`max_entries`.

### A.5 Coverage and independent audit

- `nand` 400/400 and `full_adder` 8/8 provide **complete finite-domain
  coverage** of their truth tables (with repeated NAND trials).
- `adder32` covers 5 fixed corner cases + 1000 pairs from a specified xorshift32
  sequence; the Python auditor independently regenerates both operands for each
  trial ID.
- `adder32_exhaustive` covers **all 65536 8-bit operand pairs (65536/65536)**;
  `scripts/audit_results.py` re-derives every expected sum/carry independently
  and asserts full input coverage (`check_adder_exhaustive`).
- Aggregate re-check: `make verify` reports **68149/68149 passed** and
  `semantic audit: ok`: 400 NAND trials, 8 full-adder trials, 65536 exhaustive
  8-bit adder-harness cases, 1005 sampled full-width cases, and 1200
  ablation/baseline truth-table checks.

The audit is an independent oracle: `audit_results.py` recomputes the expected
truth tables / sums rather than trusting the harness's own `passed` flag. It
also checks every raw helper observation, including `0` on success and `< 0`
for normal NAND input `(1,1)`, verifies errno/raw-return consistency, and
recomputes every schema-v2 provenance digest. Historical JSONL without these
fields and legacy manifests fail explicitly and must be regenerated; they are
never upgraded by copying old values into the new schema.

### A.6 One-command reproduction

```sh
make data     # regenerate all results/ (build, run, ablations, provenance, audit)
make verify   # re-check every results/*.jsonl and re-run the semantic audit
```

### A.7 Run-bound xlated evidence for normal `wm_nand`

The authoritative instruction stream is
`results/nand.wm_nand.xlated.txt`, whose digest is in
`results/nand.provenance.json`. It is regenerated from the preserved normal
object and therefore changes when instrumentation or the compiler changes.
Reviewers should establish the following data flow in that file rather than
relying on stale instruction numbers:

1. `a` and `b` are masked to bits and used only in branchless arithmetic that
   selects sentinel versus distinct keys.
2. The gate performs sentinel setup, the first input-conditioned update, then
   the second input-conditioned update.
3. The second update's signed return is preserved in
   `TAPE[SECOND_UPDATE_RAW_IDX]` and its validity flag is set.
4. `IDX_NAND_OUT` is the predicate that the same return equals zero.
5. `results/nand_truth_table.jsonl` records return zero for the three
   non-capacity cases and a negative value for `(1,1)`.

The corresponding verifier trace is hash-bound as
`results/nand.verifier.log`. Its relevant evidentiary claim is local: after
the second hash update, the return is scalar and both successors of the
zero-test are explored. `xlated` denotes eBPF bytecode after verifier/kernel
rewrites; use a separate `bpftool prog dump jited` capture if native JIT
machine code is ever needed. This artifact makes no claim based on such a JIT
dump.

### A.8 Run-bound explicit-logic baseline contrast

The authoritative baseline stream is
`results/baseline_nand.wm_nand.xlated.txt`, bound together with the preserved
baseline object, executed harness, verifier log, and
`baseline_nand.jsonl` in `baseline_nand.provenance.json`. It should show:

- no gate-map capacity probe;
- explicit Boolean/branch operations that combine the input bits into NAND;
- the same 400/400 truth table; and
- `second_update_observed=false` with null raw-return/errno fields, because
  this build has no second capacity-probe helper whose return could be
  recorded.

This is a controlled implementation contrast, not evidence that verifier
acceptance certifies either program's complete input/output graph. Because
compiler versions, map IDs, and instrumentation alter instruction numbering,
the manifest-bound generated files are authoritative and no fixed instruction
listing or old object hash is copied into this document.

### A.9 Empirical verifier-log observation — scalar return and both zero-test successors

The detailed evidence note is `results/abstraction_gap_witness.md`. For the
ordinary, non-LRU `BPF_MAP_TYPE_HASH` configuration captured in
`results/env.json`, the concrete one-gate runs establish the narrow contract
actually used by NAND: the second update returns `0` when its selected key can
be updated/inserted and a negative value when input `(1,1)` attempts a fresh
key at logical capacity. The JSONL records the exact signed return and derived
errno; only the zero/negative distinction is treated as portable.

The manifest-bound verifier log establishes a separate local empirical fact:
after the second hash update, it prints a scalar return representation and
shows both successors of the `ret == 0` test being explored. Review the call,
saved return, and zero-test in `results/nand.verifier.log`; instruction numbers
are deliberately not copied here because the raw-return instrumentation changes
them.

This text does **not** reconstruct the verifier's report carrier, a concretization
`γ`, or a sound transfer relation from the log. It therefore does not prove that
two individual concrete states share an abstract element, and an unresolved
predicate alone does not prove the standard abstract-interpretation
completeness equation fails. Definition 5 and Proposition 3 could be applied
only conditionally after defining `Report_log` and proving the needed local
transfer-soundness and coverage facts. The direct artifact claim is narrower:
the accepted program's runtime capacity predicate determines the bit, while the
recorded local log observation does not decide that predicate.

### A.10 Bounded data-parametric and policy-relative scope

The formal development is in `PAPER_DRAFT.md`; the artifact mapping is in
`results/exploitable_gap.md`.

The concrete gate basis satisfies observability, one uniform/total/deterministic
runtime dispatcher, and reset. `wm_circuit` adds E4-D: one accepted artifact
consumes a normalized core descriptor/map configuration, checks canonical SSA
form, and serially reuses the gate through a fixed `bpf_loop`. WMC1 text and
its output list are host-side parsing/projection objects, not BPF input words.
The induced reset-normalized complete gate schedule is a word in `W_run(P_U)`;
the causal `W_res` witness is the common second-update suffix at the internal
frontier after the first input operation.

Theorem 1 therefore ranges over `d in D_{64,512}` and every input configuration
`Enc_U(d,x)` under a globally serializable/mutually exclusive shared-map
discipline. Its acceptance premise is `P_U in L_V`, once; it is not a statement
that each `d` is in `L_V`. The run validates named circuits, random DAGs, a
declared 512-gate boundary, a joint 64-input/512-gate/578-wire boundary,
malformed controls, and repeated **serial** descriptor changes. It provides regression evidence for the declared bounded
domain, not an enumeration of all descriptors or a concurrent-access proof. It
does not establish a general artifact-parametric compiler `compile_B(C)` or
acceptance of a distinct BPF artifact for every circuit.

Theorem 2 is a separate conditional Q-certificate result about an open
input-parametric interface for fixed `d`, not one frozen `Enc_U(d,x)` run. It
requires a fixed sound report extractor, an expressible nonconstant graph,
composed local formulas, a persistent wrong-output model, and a checked
dominance obligation against the whole-program report. The Linux evidence has
no machine-checked extractor or persistent-alternative certificate, so no
global Q-opacity claim is made.

Finally, a residual transducer is not automatically a weird machine. That label
requires an intended semantic/security policy and threat model under which an
actor drives security-relevant behavior excluded by the policy. The offline
test-run construction lacks that deployment context and is classified only as
a residual transducer with a local empirical scalar-return/zero-test verifier-log
observation; it does not instantiate Definition 5.

### A.11 Bounded interpreter run

Run `make interpreter-data` to regenerate the data-parametric artifact. The
script builds four distinct objects (normal residual, cap64, sentinel, and
explicit baseline), preserves them beneath one fresh run directory, and uses
the preserved `wm_vm_user` binary for each corresponding result. `wm_vm_user`
loads a chosen object once, then serially installs normalized core descriptor
maps between invocations. The textual WMC1 file is parsed by the host; the
kernel sees only the resulting control, gate, and input map cells. The harness
does not overlap setup, invocation, or readback across clients.

The normal run checks all inputs for each named descriptor and each generated
random DAG with at most six inputs. It separately checks the 512-gate deep
chain, a joint 64-input/512-gate/578-wire descriptor (with all-zero and
all-one 64-bit inputs), a zero-gate constant descriptor, eight malformed map
controls, and 10,000 serial alternating invocations. For the named, random,
boundary, and control datasets that emit per-gate rows, `VM_TRACE` makes every
successful gate's raw second update visible; for the residual build the auditor
requires `output == [raw_return == 0]`, while the explicit baseline requires
no such helper trace. The stress dataset deliberately suppresses per-gate rows
and is audited at the run/status/output level only. The two mechanism-removing
variants require every emitted gate to become one and require at least one
final-output divergence from the logical-NAND oracle.

The run-level audit checks the JSONL graph, per-gate trace completeness where
gate rows are emitted, same-program-ID discipline within each batch, negative
statuses, canonical run sequences, and normal/control oracle relations. The
stress sequence is a serial reset and state-contamination regression test; it
is not a concurrency test. The
self-issued SHA-256 integrity manifest then hashes every source snapshot,
descriptor, corpus member, object, binary, verifier log, translated bytecode
dump, result, and audit file. It detects missing, changed, duplicate, or
subsequently added unbound files relative to the manifest, but cannot establish
authorship or resist a complete rewrite and reissue by its creator.

### A.12 Precision-control experiment

`witness2/` compares three Boolean programs over all four input rows:
projection, explicit NAND, and extensionally equal modulo NAND. Their global
output interval is exactly `[0,1]` in every case, so a global value range
certifies none of their nonconstant input/output graphs.

The toy row-indexed analyzer then isolates a specific implementation choice.
Row-preserving arithmetic certifies projection and explicit NAND. Its
deliberately row-forgetting range-only `MOD` transfer is a strict sound
over-approximation for modulo NAND and fails to certify that graph. A
row-preserving congruence refinement and singleton input partition both repair
the finite example. This is an executable witness about that toy transfer only,
not ordinary interval completeness, Frama-C EVA, Linux, or system independence.

The preserved `frama_c/out/eva_slevel0.log` belongs to an older one-volatile
input model and supports only historical global-range facts. The corrected C
model uses two independent `Frama_C_interval(0,1)` calls and was rerun with
Frama-C 25.0-beta (Manganese) on the recorded VM. The separate
`eva_slevel0.current.log` reports modulo NAND `{0;1}`, the different constant
mod-7 control `{1}`, and zero alarms. `current.provenance.json` binds the
current source, runner/checker, log, version, `env.json`, and certified eBPF
run ID. These remain global value-range facts, not evidence for the toy
relational transfer.
