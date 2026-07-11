# Bounded Interpreter Implementation Record — 2026-07-10

This is the current implementation-boundary record for the bounded
data-parametric realization. It supersedes the earlier fixed-schedule/no-E4
implementation statements in the 2026-07-10 review records **only for E4-D**.
It does not upgrade their historical gate-only evidence, establish E4-A,
construct a verifier report extractor, or demonstrate a policy-relative weird
machine.

## 1. What the fixed eBPF artifact consumes

`P_U = wm_circuit` is one fixed `SEC("syscall")` eBPF object. It never parses a
textual file. The host-side `wm_vm_user` parser reads a strict WMC1 container,
validates the textual header and output-list bounds, and normalizes the
executable core into maps:

- `VM_CONTROL`: ABI version and input/gate/wire counts;
- `CIRCUIT`: canonical core records `(op,src0,src1,dst)`;
- `WIRES`: constants and primary-input cells; and
- `VM_TRACE`: per-gate evidence written by the program.

The core domain is bounded by 64 inputs, 512 NAND gates, and 578 wire cells.
The kernel checks the core ABI/count/opcode/canonical-destination/forward-
reference shape again before and during interpretation. The WMC1 textual name
and output list are not kernel inputs. The host performs the output projection
from the complete wire vector only when the reported status is OK.

Before the loop, `P_U` itself writes `WIRES[0]=0` and `WIRES[1]=1` and leaves
the host-installed primary-input cells intact; this is the constant/input base
frame for the descriptor-prefix argument. Each successful iteration then writes
only its canonical destination cell.

Formally, the normalized map state is the initial configuration
`Enc_U(d,x)`, not a word in `W_run(P_U)`. The execution schedule induced by
that configuration, `Sched_U(d,x)`, is the relevant runtime word. A nonzero
status makes the observable result `(status, wires)` equal to `(status, ⊥)`;
the implementation does not claim that old physical `WIRES` or `VM_TRACE`
cells were cleared on failure.

## 2. Execution discipline and E4-D scope

One `bpf_loop` iteration executes one descriptor record through the same
reset-normalized capacity gate `G0`, records the raw helper return and derived
bit, and writes the canonical destination wire. This realizes the bounded
data-parametric condition **E4-D**: one accepted object interprets the declared
bounded core language without a verifier-visible BPF control-flow change per
descriptor.

The required discipline is stronger than “no concurrent writer during the BPF
call.” A client must serialize the *whole* shared-map transaction:

1. install `Enc_U(d,x)`;
2. invoke `P_U` once; and
3. read status, trace, and (on success) output wires.

All invocations sharing `TAPE`, `CIRCUIT`, `WIRES`, `VM_CONTROL`, `VM_TRACE`,
or `G0` must be globally serializable/mutually exclusive across those three
steps, and no nonparticipating host may read or write those maps during the
transaction. The supplied runner and suite issue these operations serially;
they do not implement locking and do not establish a concurrent safety property.

This is not **E4-A**. No compiler is claimed to generate a distinct BPF object
and prove verifier acceptance for every circuit. The proof obligation for the
bounded core language is a mathematical prefix induction under the stated gate,
reset, frame, safety, and serialization assumptions. Tests provide regression
evidence, not a finite enumeration of every descriptor in the domain.

## 3. Evidence and negative boundaries

`scripts/run_interpreter_suite.sh` snapshots the implementation, builds each
variant from that snapshot, generates descriptors from JSON sources, and runs
named circuits, a fixed-seed corpus, a 512-gate boundary chain, a joint
64-input/512-gate/578-wire boundary descriptor, malformed-core controls, and
an alternating 10,000-invocation sequence. The latter is a
**serial reset/state-contamination regression**, not a race, linearizability,
or synchronization test.

`scripts/audit_interpreter.py` is a separately implemented author-run auditor
that recomputes descriptor wire values
and checks run rows, gate traces, expected negative status/executed-count
behavior, descriptor/corpus coverage, and control variants. It also recompiles
the named JSON sources and deterministically regenerates both boundary
descriptors byte-for-byte. A successful audit therefore supports the recorded
bounded execution relation, subject to the environment and serialization
assumptions; it does not prove properties of unrecorded kernels, concurrent
callers, or arbitrary descriptors beyond the mathematical premises.

The report-bound source-snapshotted run
`results/interpreter/interpreter-final-20260711-02/` passed both the semantic
audit and integrity-manifest verification. Its 38,533 JSONL rows comprise
26,488 gate traces, 12,037 successful runs, and eight negative controls. The
audit recompiles named sources, regenerates both boundary descriptors and the
100-circuit fixed-seed corpus byte-for-byte, and checks each runtime JSONL
program tag against the tag captured from the preserved normal, cap64,
sentinel, or baseline BPF variant. These are
reproducibility and execution-binding checks for this recorded environment;
they are not a concurrency test or a proof over all admissible descriptors.

## 4. Verifier-log evidence is deliberately local

The verifier log is used only for an empirical local observation at the
instrumented helper frontier: it displays a scalar return representation and
both successors of the `ret == 0` branch. The artifact does not infer a full
`Report_log`, a concretization `γ`, a joined-cell witness containing specified
concrete executions, or a transfer-soundness theorem from those lines.

Consequently, any application of Definition 5 or Proposition 3 is conditional
on separately defining `Report_log` and proving the necessary local
transfer-soundness and coverage facts. The current artifact does not discharge
those extra premises and does not claim global Q-certificate opacity.

## 5. Integrity manifest boundary

Each interpreter run contains a **self-issued SHA-256 integrity manifest**.
It binds every non-manifest file in that run directory and the declared bounds;
verification detects changed, missing, duplicate, or newly unbound files
relative to the manifest. It is not content-addressed storage, a signature, a
timestamp authority, or protection against a party who can replace all files
and issue a matching new manifest. It supports reproducibility and anti-mix-up
checks, not external provenance or authorship claims.

## 6. Relationship to historical reviews

`REVISION_RESPONSE_2026-07-10.md`, `RE_REVIEW_2026-07-10.md`,
The revision notes and independent review records document the earlier
gate-only revision
state. Their statements that no E4 implementation/compiler existed, or that
only hand-written schedules were executed, are historical pre-`P_U` statements.
Their limits on E4-A, report extraction, whole-program opacity, and
policy/threat-model-based weird-machine classification remain current.
