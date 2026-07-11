# After Acceptance: eBPF Residual-Language Artifact

This artifact implements the capacity-saturation NAND construction described in
the paper draft, plus a numeric precision-control experiment. It is intended for an
isolated Linux VM with root access and BTF enabled.

## What this establishes

Full scope is in `ARTIFACT.md`. The direct result is a
**residual-transducer artifact with a local empirical scalar-return/zero-test
verifier-log observation**, not a demonstrated weird machine or a Definition-5
verifier-unresolved witness:

- The normal capacity gate realizes NAND (400/400 with unique trial IDs); the
  BPF program records the second update's signed raw return on every row.
- The captured in-kernel verifier log is treated only as a **local empirical
  scalar-unresolved observation**: at the recorded helper frontier it prints a
  scalar return and explores both successors of the zero-test. It is not, by
  itself, a reconstructed abstract report or a proof about all concrete states.
- A fixed accepted program `wm_circuit` implements a bounded data-parametric
  residual-circuit interpreter: host-parsed WMC1 text is normalized into a
  core descriptor/map configuration selecting canonical NAND DAGs while the
  verifier-visible BPF object remains unchanged.
- The declared v1 domain has at most 64 primary inputs, 512 NAND gates, and
  578 live wire cells. `P_U` consumes only the normalized core gate records
  and controls in maps; the textual WMC1 container and its output list are
  host-side input/projection machinery, not words in `W_run(P_U)` and not a
  family of verifier-recognized BPF artifacts.
- The interpreter revalidates ABI/count/opcode/canonical-destination/forward-
  reference conditions for that core configuration, records a raw
  helper-return trace for each executed gate, and reuses one reset-normalized
  residual gate map. A nonzero status masks the observable wire result; stale
  physical map cells are not treated as an output.
- Correctness requires one globally serializable, mutually exclusive use of
  the entire shared map set during configuration, invocation, and readback.
  The harness supplies serial invocations; it does not implement or test a
  concurrent synchronization protocol.
- This realizes bounded **E4-D** data-parametric composition. It does not
  establish **E4-A**: an artifact-parametric compiler that emits and proves
  acceptance of a distinct BPF object for every circuit.
- Whole-program Q-certificate opacity is **not established**: the artifact has
  no fixed `Extract_Q`, composed report theory, or persistent-alternative
  certificate, so it does not instantiate the conditional opacity theorem.
- Likewise, the log observation does not by itself instantiate Definition 5
  or Proposition 3. Such an instantiation would additionally require an
  explicit `Report_log` interpretation and a justified local
  transfer-soundness/coverage argument; neither is claimed for this artifact.
- Weird-machine classification is **not established**: that additionally
  requires an intended policy, threat model, actor control, and excluded
  security-relevant effect. The offline privileged test has no such victim
  policy or effect.

There is no verifier bypass, privilege escalation, memory corruption,
unbounded universality/Turing-completeness, or unprivileged-loadability claim.

## Requirements

- Isolated Linux VM with privileges sufficient to load `SEC("syscall")` eBPF
  programs and BTF at `/sys/kernel/btf/vmlinux`.
- Kernel >= 5.17 for `SEC("syscall")` programs and `bpf_loop()`.
- `clang`, `bpftool`, `libbpf`, and `pkg-config` on the build host.
- Captured feature detection lands in `results/feature_probe.txt`.
- The witness assumes non-LRU `BPF_MAP_TYPE_HASH` gate maps, no
  `BPF_F_NO_PREALLOC`, and `BPF_ANY` helper updates. These are ordinary hash
  maps, not `BPF_MAP_TYPE_PERCPU_HASH`; kernel-internal per-CPU allocator
  freelists/spares are an implementation detail and do not enlarge the map's
  logical `max_entries`. Exact object and harness hashes, build flags, run ID,
  timestamp, environment, kernel-BTF/generated-header digests, logs, xlated
  dump, and result hashes are recorded in per-variant provenance files.

## Build

```sh
make test
make
```

## Run

```sh
sudo ./build/wm_user nand 100
sudo ./build/wm_user fa
sudo ./build/wm_user adder 1000
sudo ./build/wm_user adder-exhaustive 8
```

## Bounded Interpreter

Build WMC1 descriptors and run named circuits through the fixed interpreter:

```sh
make circuits
sudo ./build/wm_vm_user batch circuits/const_one.wmc circuits/nand.wmc \
  circuits/xor.wmc circuits/full_adder.wmc
sudo ./build/wm_vm_user negative
```

`scripts/circuit_tool.py` is an independent symbolic-NAND encoder and Boolean
oracle. It serializes a JSON DAG into strict WMC1 text; it does not generate
eBPF. `wm_vm_user` loads the BPF object once, changes descriptors only between
invocations, and emits JSONL run and per-gate records. The interpreter consumes
only the normalized WMC1 core gate sequence and controls; the host validates
the textual output projection and, only after an OK status, reads the
corresponding cells from the complete wire vector.

Run the complete reproducible interpreter experiment in an isolated
root-capable VM:

```sh
make interpreter-data
```

This creates a fresh directory under `results/interpreter/<run-id>/` containing
source and descriptor snapshots, four preserved variant objects/binaries,
verifier logs, xlated `wm_circuit` bytecode, normal/random/boundary/negative/
stress JSONL, the independent audit, and a self-issued SHA-256 integrity
manifest. The manifest detects changes, omissions, and extra unbound files
relative to its own contents; it is not a signature or tamper-proof record
against a writer who can replace the entire bundle and manifest. Verify an
existing run with:

```sh
make verify-interpreter INTERPRETER_RUN=results/interpreter/<run-id>
```

The recorded run `interpreter-v1-20260710-04` passed its independent audit and
integrity check: 38,533 rows comprising 26,488 per-gate records, 12,037
successful run records, and eight fail-closed negative controls. It covers 100
fixed-seed random DAGs, a 512-gate boundary chain, a joint 64-input/512-gate/
578-wire boundary (including wire 577), a zero-gate descriptor, 10,000
alternating invocations, and `GATE_CAP=64`, sentinel, and explicit-logic
controls. The audit recompiles named/boundary sources byte-for-byte, regenerates
the corpus, and requires each runtime BPF program tag to match the captured
preserved variant.
The alternation is serial state-reset/regression evidence, not a concurrency
experiment or proof of synchronization.

## Full Dataset

```sh
./scripts/run_kernel_suite.sh
```

The suite records JSONL outputs under `results/` for the normal NAND/full-adder
/32-bit-adder runs and for three ablations:

- `GATE_CAP=64`: capacity saturation disappears, NAND becomes all-1.
- `WM_FORCE_SENTINEL_B`: the second input reuses sentinel, NAND becomes all-1.
- `WM_BASELINE_NAND`: ordinary explicit eBPF NAND baseline.

It also emits per-variant provenance (`<variant>.provenance.json`), a
per-variant verifier log, xlated eBPF bytecode for `wm_nand`, preserved variant
objects/harnesses under `results/variants/<run_id>/`, and an exhaustive 8-bit
adder dataset. Here `xlated` means the verifier-processed eBPF instruction
stream; it is not a JIT-native machine-code dump.

Every JSONL row now records `second_update_observed`, the signed
`second_update_raw_ret`, and its derived positive `second_update_errno`. For the
normal one-gate NAND, successful probes must record return `0`, while input
`(1,1)` must record a negative at-capacity return. The portable claim is this
zero/negative distinction; the exact errno is reported as an observation of the
recorded run, not assumed to be stable across kernels. The explicit-bytecode
baseline records `observed=false` and JSON `null` values because it has no such
helper call.

Provenance schema v2 binds the BPF object, the userspace binary actually
executed, verifier log, xlated dump, environment snapshot, and every associated
JSONL result by SHA-256 under one run ID. The semantic auditor recomputes the
results and verifies all bindings. These are consistency and anti-mix-up
checks, not a signature or proof of who generated the run. It intentionally
rejects the older unbound
schema and result rows without raw-return capture; regenerate them with the full
suite rather than relabeling historical data. Re-check the eBPF evidence with
`make verify`
(68149/68149: 400 NAND + 8 full-adder + 65536 exhaustive 8-bit adder-harness
cases + 1005 sampled full-width cases + 1200 ablation/baseline truth-table
checks, `semantic audit: ok`). Evidence files, the formal analysis
(A.9 local verifier witness, A.10 corrected formal scope), and the precision-control experiment
are catalogued in `ARTIFACT.md`.

This is not a verifier bypass, privilege escalation, or memory-corruption exploit.
It uses verifier-accepted bounded programs and offline `BPF_PROG_TEST_RUN`.

## Precision Control

The legacy-named `witness2/` directory provides a join-based interval-analyzer
experiment. `python3 witness2/witness.py` compares projection, explicit NAND,
and modulo NAND in the self-contained toy analyzer. The separate
`bash witness2/frama_c/run.sh` model contains only modulo NAND and the different
mod-7 control; it does not rerun the three-program comparison. The `[0,1]`
range is exact for the working nonconstant Boolean function and also arises for
explicit NAND/projection in the toy analyzer, so this experiment is **not** evidence by
itself of modulo-specific precision loss or system-independence. On Ubuntu
24.04, install Frama-C with
`sudo apt-get install -y frama-c-base`. The captured EVA result is in
`witness2/frama_c/RESULTS.md`.

Optional checks:

```sh
make verify-witness2
make verify-framac
```

## LangSec Claim and Research Boundaries

The paper distinguishes the accepted artifact language `L_V`, ordinary runtime
word language `W_run(P)`, causal residual language `W_res(P;K_res)`, concrete
observation relation `R_res(P;K_res)`, and analyzer-report claims. A gap is called
contract-shape-induced only relative to a fixed safety/abstraction/report
contract; changing that contract can remove it. Soundness or incompleteness
alone does not imply programmability.

The next formal step is an observer-relative complete-shell construction and a
machine-checked report extractor. The next systems step is E4-A: an
artifact-parametric compiler with a characterized accepted-artifact domain.
Neither is supplied here; the supplied interpreter instead discharges bounded
E4-D for its WMC1 runtime language.

The 2026-07-10 strict revision trace is in
`REVISION_RESPONSE_2026-07-10.md`; the post-regeneration independent decision
and integrity audit are in `RE_REVIEW_2026-07-10.md`.
The subsequent LangSec thesis correction, countermodels, and evidence-boundary
changes are recorded in `LANGSEC_REVISION_2026-07-10.md`; the independent
post-revision formal/evidence decision is in `LANGSEC_RE_REVIEW_2026-07-10.md`.
Those four review records predate the runtime interpreter and are retained as
historical records only. The current implementation boundary is stated in
`INTERPRETER_IMPLEMENTATION_2026-07-10.md`.

The separate interval/Frama-C experiment is a precision control, not a second
opacity witness. Any future weird-machine claim must additionally name the
intended policy, threat model, actor capability, and security-relevant behavior
that the policy excludes.
