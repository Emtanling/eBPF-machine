# Artifact Notes

## Target

- Program type: `BPF_PROG_TYPE_SYSCALL` via `SEC("syscall")`
- Execution: offline `bpf_prog_test_run_opts()`
- Maps:
  - `TAPE`: array map for input/output bits and error count
  - `G0..G8`: non-LRU `BPF_MAP_TYPE_HASH` maps used as NAND gate capacity state
- Gate helper discipline: gate updates use `BPF_ANY`; gate maps omit
  `BPF_F_NO_PREALLOC`; the proof uses the success predicate `ret == 0`, not a
  kernel-stable errno value.

## Claims and Scope

What this artifact establishes, at honest strength for a LangSec submission (full development in
Appendix A.9 / A.10, the residual-theorem note in `results/exploitable_gap.md`, and the second witness in
`witness2/`). The artifact is a recognizer-boundary witness: it shows residual semantics inside a
recognized safety language, not a verifier bypass or vulnerability report.

**Proven (deductive or exhaustive):**

- The capacity-saturation gate realizes NAND — exhaustive truth table
  (400/400), and by disassembly the output is `out = [ret == 0]` over the
  second input-conditioned map update, with no ALU/compare combining the inputs
  (Appendix A.7).
- Built from that gate: an exhaustive full adder (8/8) and an exhaustive
  8-bit adder (65536/65536). NAND is functionally complete, so arbitrary
  Boolean circuits are realizable; the exhaustive ceiling reached here is the
  8-bit adder.
- Mechanism attribution: ablations collapse the gate to a constant when the
  capacity (`GATE_CAP=2`) or the distinct-key insertion is removed, and an
  independent occupancy model matches exhaustively.
- Every variant is accepted by the in-kernel verifier (`loadall_exit=0`): the
  weird-machine program is a verifier-accepted, bounded, memory-safe program.
- The abstraction gap as a machine-checkable proposition: the verifier holds
  the final input-conditioned update return as an unconstrained scalar and
  forks at the output branch, so `ψ(ret) = [ret == 0]` is abstractly unresolved
  with respect to map occupancy (Appendix A.9).
- A second, structurally different witness in `witness2/` reproduces the same
  opacity pattern in a join-based interval analyzer and in Frama-C EVA: the
  working mod-3 gate is certified as `{0; 1} = ⊤`, while the mod-7 ablation is
  certified as `{1}`. This is empirical support for system-independence, not a
  completed structural theorem.

**Proven conditionally (theorem plus artifact instantiation):**

- Definition of an exploitable residual readout basis and the
  **Residual-Language Weird Machine theorem pair**: a LangSec-style sufficient
  condition under which a recognized safety language still contains a
  runtime-interpreted residual machine. With a functionally-complete gate, the
  realization theorem yields, for every finite Boolean circuit, an accepted
  bounded program instance. The separate opacity theorem requires local
  gate-opacity relative to the recognizer relation vocabulary `Q`: the exported
  gate output must be derived only from the unresolved residual readout, with no
  recognizer-visible shadow computation in the gate that already proves the same
  local relation. The PoC instantiates the eBPF basis, contrasts it with an
  explicit-logic baseline, and validates representative finite compositions
  (Appendix A.10 §5).

**Not claimed:**

- Not a universal "gap ⇒ weird machine" theorem; the biconditional is scoped
  to *opaque programmable computation*, a precise sub-notion.
- Not Turing-complete (bounded, combinational — the verifier's termination
  check forbids unbounded opaque memory).
- Not a vulnerability: no verifier bypass, privilege escalation, or memory
  corruption. Experiments run only in an isolated VM with privileges sufficient
  for the tested program type; no unprivileged loadability or live-kernel
  deployment is claimed.
- Not a completed structural theorem over all sound abstractions. The
  `witness2/` interval/Frama-C result is a second aligned witness and
  empirical support for the thesis, not a proof that every abstraction gap is
  exploitable.

## Expected Results

- `nand`: 400/400, exhaustive over the truth table `00,01,10,11 -> 1,1,1,0`
- `fa`: 8/8, exhaustive over all full-adder inputs
- `adder`: 1005/1005 (5 fixed corner cases + 1000 fixed-seed random 32-bit pairs)
- `adder-exhaustive 8`: 65536/65536, exhaustive over all 8-bit operand pairs
- `GATE_CAP=64` ablation: NAND degenerates to all-1 (400/400)
- `WM_FORCE_SENTINEL_B` ablation: NAND degenerates to all-1 (400/400)
- `WM_BASELINE_NAND` baseline: explicit bytecode NAND passes the normal truth table (400/400)
- `make verify` aggregate: 68149/68149, `semantic audit: ok` (400 NAND + 8
  full-adder + 65536 exhaustive 8-bit adder-harness cases + 1005 sampled
  full-width cases + 1200 ablation/baseline truth-table checks)

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
- `results/<variant>.provenance.json` (per-variant object hash + build flags)
- `results/<variant>.verifier.log` (per-variant verifier acceptance)
- `results/<variant>.wm_nand.xlated.txt` (xlated proof: output = helper return)
- `results/adder32_exhaustive.jsonl` (exhaustive 8-bit adder, 65536 cases)
- `results/xlated_compare.html` (self-contained A.7/A.8 side-by-side, no external assets)
- `results/abstraction_gap_witness.md` (formal witness: occupancy yields an abstractly unresolved readout)
- `results/exploitable_gap.md` (legacy filename; residual readout basis + residual-language theorem)
- `witness2/README.md` and `witness2/witness.py` (self-contained interval witness)
- `witness2/frama_c/RESULTS.md` and `witness2/frama_c/out/eva_slevel0.log`
  (Frama-C EVA reproduction of the second witness)

## Appendix A: Reproducibility and Audit Evidence

This appendix records the machine-checkable evidence emitted by
`scripts/run_kernel_suite.sh` for the run reported in the paper. All artefacts
below are regenerated by `make data` and re-checked by `make verify`.

Index: A.1 environment · A.2 per-variant provenance · A.3 verifier
acceptance · A.4 output = helper return · A.5 coverage & audit · A.6
one-command repro · A.7 weird-machine xlated · A.8 baseline xlated
(contrast) · A.9 residual-readout witness · A.10 residual-language theorem
& opacity theorem · A.11 second witness.

### A.1 Environment (`results/env.json`)

- Host: `Linux 6.17.0-19-generic #19~24.04.2-Ubuntu`, `aarch64` (isolated VM).
- Toolchain: `clang 18.1.3`, `bpftool v7.7.0` (libbpf v1.7), runtime `libbpf 1.3.0`.
- BTF: `/sys/kernel/btf/vmlinux` present (`btf_vmlinux_exists: true`).
- `env.json` additionally pins the sha256 of the normal build's bpf object, the
  verifier log, and the feature probe.

### A.2 Per-variant provenance binding

Each result set is bound to the exact binary that produced it. For every build
variant `scripts/run_kernel_suite.sh` writes `results/<variant>.provenance.json`
holding the object hash, the build flags, the per-variant verifier log hash, and
the loader exit code. The four variants compile to four **distinct** objects, so
a result file cannot be silently attributed to the wrong binary:

| Variant | Build flags | `bpf_object_sha256` (abbrev.) | loadall |
|---|---|---|---|
| `nand` (weird machine) | `GATE_CAP=2` | `57b95a81…8f39e602` | 0 |
| `ablation_cap64` | `GATE_CAP=64` | `376258bf…d8b3fd0c` | 0 |
| `ablation_k2_sentinel` | `GATE_CAP=2 -DWM_FORCE_SENTINEL_B` | `88011208…5137d464` | 0 |
| `baseline_nand` | `GATE_CAP=2 -DWM_BASELINE_NAND` | `cb848a70…379642c6` | 0 |

Full 64-hex digests (authoritative; also inside each `provenance.json`):

- `nand`                 = `57b95a811d0897af3e6347ede44b5868910d1a3f11d28ec323a26fad8f39e602`
- `ablation_cap64`       = `376258bf4ebd7564c477440028b6eb475284c60403de28b7b9ae86b3d8b3fd0c`
- `ablation_k2_sentinel` = `88011208894b6fa49467cce9cf15427bb5734505d721dd6abd1281cb5137d464`
- `baseline_nand`        = `cb848a70a8ddbca7c63a3c0043205970d58146216e6ad1443dad6cf0379642c6`

### A.3 Verifier acceptance for every variant

All variants — including the ablations and the explicit-bytecode baseline — are
accepted by the in-kernel verifier: `bpftool_loadall_exit = 0` in every
`provenance.json`, with the full acceptance trace kept in
`results/<variant>.verifier.log`. The verifier reasons about memory safety and
bounded execution only; it does not model the NAND semantics (see A.4).

### A.4 The output is a helper return value, not computed logic

`results/<variant>.wm_nand.xlated.txt` holds the post-verifier (xlated)
instruction stream of `wm_nand`. The capacity-saturation NAND writes an output
bit that is **exactly `ret == 0` for the second input-conditioned map update**; no instruction
combines the inputs `a,b` arithmetically. Annotated excerpt (normal `nand`
variant):

```
 62: (85) call htab_map_update_elem   ; insert sentinel S            -> r0
 63: (bf) r7 = r0                      ; r7  = r0        (setup guard)
 76: (85) call htab_map_update_elem   ; insert key1 (selected by A)  -> r0
 83: (4f) r7 |= r0                     ; r7 |= r0        (err = r0 || r1)
 90: (85) call htab_map_update_elem   ; insert key2 (selected by B)  -> r0   <-- capacity probe
 91: (bf) r6 = r0                      ; r6 = final input update return code
 92: (15) if r7 == 0x0 goto pc+26      ; err_bump() only if a setup insert failed
        ...
122: (15) if r6 == 0x0 goto pc+1       ; output bit = (r6 == 0) == (r2 == 0)
132: (85) call array_map_update_elem  ; TAPE[IDX_NAND_OUT] = output bit
```

Reading the trace: the inputs appear only in the branchless key selection
(`key = base + delta*bit`) that decides *which* key each insert targets; the
truth value stored at instruction 132 is decided solely by `if r6 == 0`, where
`r6` is the return of the second input-conditioned `htab_map_update_elem`. The kernel returns
a negative errno (observed as `-E2BIG`) for that update when the preallocated, non-LRU hash map of
`max_entries = GATE_CAP = 2` is already full — i.e. only when both inputs are 1.
This is the abstraction gap: the semantics live in runtime map metadata that the
verifier does not track.

### A.5 Coverage and independent audit

- `nand` 400/400 and `full_adder` 8/8 are **exhaustive** over their truth
  tables (genuine proofs for those functions).
- `adder32` covers 5 fixed corner cases + 1000 fixed-seed random 32-bit pairs.
- `adder32_exhaustive` covers **all 65536 8-bit operand pairs (65536/65536)**;
  `scripts/audit_results.py` re-derives every expected sum/carry independently
  and asserts full input coverage (`check_adder_exhaustive`).
- Aggregate re-check: `make verify` reports **68149/68149 passed** and
  `semantic audit: ok`: 400 NAND trials, 8 full-adder trials, 65536 exhaustive
  8-bit adder-harness cases, 1005 sampled full-width cases, and 1200
  ablation/baseline truth-table checks.

The audit is an independent oracle: `audit_results.py` recomputes the expected
truth tables / sums itself rather than trusting the harness's own `passed` flag.

### A.6 One-command reproduction

```sh
make data     # regenerate all results/ (build, run, ablations, provenance, audit)
make verify   # re-check every results/*.jsonl and re-run the semantic audit
```

### A.7 Full xlated disassembly of `wm_nand` (normal variant)

Verbatim `bpftool prog dump xlated` for the `nand` object (`57b95a81…8f39e602`),
as captured in `results/nand.wm_nand.xlated.txt`. Two things to note:

- **Branchless key selection** at 66–68 and 79–81 computes
  `key = base + delta * input_bit` (a subtract / multiply / add on the input bit
  in `r8`, resp. `r9`); the inputs never enter a comparison that yields the
  output.
- The **output bit** is decided only at 122 by `if r6 == 0`, where `r6` is the
  return predicate `ret == 0` of the second input-conditioned `htab_map_update_elem`
  (instr 90). It is stored to `TAPE[IDX_NAND_OUT]` at 132.

```text
int wm_nand(void * ctx):
; int wm_nand(void *ctx)
   0: (b7) r9 = 0
   1: (63) *(u32 *)(r10 -8) = r9
   2: (bf) r2 = r10
;
   3: (07) r2 += -8
; __u64 *p = bpf_map_lookup_elem(&TAPE, &idx);
   4: (18) r1 = map[id:600]
   6: (07) r1 += 264
   7: (61) r0 = *(u32 *)(r2 +0)
   8: (35) if r0 >= 0x100 goto pc+3
   9: (67) r0 <<= 3
  10: (0f) r0 += r1
  11: (05) goto pc+1
  12: (b7) r0 = 0
  13: (b7) r8 = 0
; return p ? (*p & 1ull) : 0;
  14: (15) if r0 == 0x0 goto pc+2
; return p ? (*p & 1ull) : 0;
  15: (79) r8 = *(u64 *)(r0 +0)
; __u64 out = NAND_GATE(G0, a, b);
  16: (57) r8 &= 1
  17: (b7) r6 = 1
  18: (63) *(u32 *)(r10 -8) = r6
  19: (bf) r2 = r10
;
  20: (07) r2 += -8
; __u64 *p = bpf_map_lookup_elem(&TAPE, &idx);
  21: (18) r1 = map[id:600]
  23: (07) r1 += 264
  24: (61) r0 = *(u32 *)(r2 +0)
  25: (35) if r0 >= 0x100 goto pc+3
  26: (67) r0 <<= 3
  27: (0f) r0 += r1
  28: (05) goto pc+1
  29: (b7) r0 = 0
; return p ? (*p & 1ull) : 0;
  30: (15) if r0 == 0x0 goto pc+2
; return p ? (*p & 1ull) : 0;
  31: (79) r9 = *(u64 *)(r0 +0)
; __u64 out = NAND_GATE(G0, a, b);
  32: (57) r9 &= 1
  33: (b7) r1 = 0
  34: (63) *(u32 *)(r10 -16) = r1
  35: (63) *(u32 *)(r10 -20) = r6
  36: (b7) r1 = 2
  37: (63) *(u32 *)(r10 -24) = r1
  38: (7b) *(u64 *)(r10 -32) = r6
  39: (bf) r7 = r10
;
  40: (07) r7 += -16
; __u64 out = NAND_GATE(G0, a, b);
  41: (18) r1 = map[id:599]
  43: (bf) r2 = r7
  44: (85) call htab_map_delete_elem#404256
  45: (bf) r2 = r10
;
  46: (07) r2 += -20
; __u64 out = NAND_GATE(G0, a, b);
  47: (18) r1 = map[id:599]
  49: (85) call htab_map_delete_elem#404256
  50: (bf) r2 = r10
;
  51: (07) r2 += -24
; __u64 out = NAND_GATE(G0, a, b);
  52: (18) r1 = map[id:599]
  54: (85) call htab_map_delete_elem#404256
  55: (bf) r6 = r10
;
  56: (07) r6 += -32
; __u64 out = NAND_GATE(G0, a, b);
  57: (18) r1 = map[id:599]
  59: (bf) r2 = r7
  60: (bf) r3 = r6
  61: (b7) r4 = 1
  62: (85) call htab_map_update_elem#409384
  63: (bf) r7 = r0
  64: (61) r1 = *(u32 *)(r10 -16)
  65: (61) r2 = *(u32 *)(r10 -20)
  66: (1f) r2 -= r1
  67: (2f) r2 *= r8
  68: (0f) r2 += r1
  69: (63) *(u32 *)(r10 -36) = r2
  70: (bf) r2 = r10
;
  71: (07) r2 += -36
; __u64 out = NAND_GATE(G0, a, b);
  72: (18) r1 = map[id:599]
  74: (bf) r3 = r6
  75: (b7) r4 = 0
  76: (85) call htab_map_update_elem#409384
  77: (61) r1 = *(u32 *)(r10 -16)
  78: (61) r2 = *(u32 *)(r10 -24)
  79: (1f) r2 -= r1
  80: (2f) r2 *= r9
  81: (0f) r2 += r1
  82: (63) *(u32 *)(r10 -40) = r2
; __u64 out = NAND_GATE(G0, a, b);
  83: (4f) r7 |= r0
  84: (bf) r2 = r10
;
  85: (07) r2 += -40
; __u64 out = NAND_GATE(G0, a, b);
  86: (18) r1 = map[id:599]
  88: (bf) r3 = r6
  89: (b7) r4 = 0
  90: (85) call htab_map_update_elem#409384
  91: (bf) r6 = r0
; __u64 out = NAND_GATE(G0, a, b);
  92: (15) if r7 == 0x0 goto pc+26
  93: (b7) r1 = 161
; __u32 idx = ERR_IDX;
  94: (63) *(u32 *)(r10 -12) = r1
  95: (bf) r2 = r10
;
  96: (07) r2 += -12
; __u64 *p = bpf_map_lookup_elem(&TAPE, &idx);
  97: (18) r1 = map[id:600]
  99: (07) r1 += 264
 100: (61) r0 = *(u32 *)(r2 +0)
 101: (35) if r0 >= 0x100 goto pc+3
 102: (67) r0 <<= 3
 103: (0f) r0 += r1
 104: (05) goto pc+1
 105: (b7) r0 = 0
 106: (b7) r1 = 1
; __u64 v = (p ? *p : 0) + 1;
 107: (15) if r0 == 0x0 goto pc+2
; __u64 v = (p ? *p : 0) + 1;
 108: (79) r1 = *(u64 *)(r0 +0)
; __u64 v = (p ? *p : 0) + 1;
 109: (07) r1 += 1
; __u64 v = (p ? *p : 0) + 1;
 110: (7b) *(u64 *)(r10 -8) = r1
 111: (bf) r2 = r10
 112: (07) r2 += -12
 113: (bf) r3 = r10
 114: (07) r3 += -8
; bpf_map_update_elem(&TAPE, &idx, &v, BPF_ANY);
 115: (18) r1 = map[id:600]
 117: (b7) r4 = 0
 118: (85) call array_map_update_elem#428432
 119: (b7) r1 = 2
 120: (63) *(u32 *)(r10 -32) = r1
 121: (b7) r1 = 1
; __u64 out = NAND_GATE(G0, a, b);
 122: (15) if r6 == 0x0 goto pc+1
 123: (b7) r1 = 0
; v &= 1ull;
 124: (7b) *(u64 *)(r10 -8) = r1
 125: (bf) r2 = r10
;
 126: (07) r2 += -32
 127: (bf) r3 = r10
 128: (07) r3 += -8
; bpf_map_update_elem(&TAPE, &idx, &v, BPF_ANY);
 129: (18) r1 = map[id:600]
 131: (b7) r4 = 0
 132: (85) call array_map_update_elem#428432
; return 0;
 133: (b7) r0 = 0
 134: (95) exit
```

### A.8 Full xlated disassembly of `wm_nand` (baseline variant) — side-by-side contrast

Verbatim `bpftool prog dump xlated` for the `baseline_nand` object
(`cb848a70…379642c6`, built with `-DWM_BASELINE_NAND`), from
`results/baseline_nand.wm_nand.xlated.txt`. This variant computes the **same**
truth table (400/400) and is **equally verifier-accepted**, but its NAND is
ordinary explicit logic — and that logic is visible in the instruction stream:

- 18: `if r1 == 0x0 …` turns input `a` into `!a` (in `r6`).
- 35: `if r1 == 0x0 …` turns input `b` into `!b` (in `r7`).
- 39: `r6 |= r7` is the OR that **combines the two inputs**: `!a | !b`, i.e.
  `!(a & b)` by De Morgan — the NAND, computed by ALU/compare.
- 40–41: mask and store the result to `TAPE[IDX_NAND_OUT]`.

There is **no `htab_map_update_elem`, no gate map, and no capacity probe** here:
every map reference is a `TAPE` array lookup/store. Compare with A.7, where the
output is `if r6 == 0` on a hash-map insert's return code and no instruction ever
combines `a` and `b`.

Side-by-side summary:

| | A.7 weird machine (`57b95a81…`) | A.8 baseline (`cb848a70…`) |
|---|---|---|
| `wm_nand` xlated length | 135 insns | 52 insns |
| hash-map (`htab_*`) calls | 3 update calls + 3 deletes per gate | 0 |
| where the output comes from | `if r6 == 0` on the final input-conditioned helper return | `r6 \|= r7` → `!a \| !b` (instr 39) |
| inputs combined by an ALU/compare? | no | yes (18, 35, 39) |
| verifier accepts | yes (`loadall_exit=0`) | yes (`loadall_exit=0`) |
| NAND truth table | 400/400 | 400/400 |

The punchline: the verifier sees two safe, bounded programs with identical I/O
behaviour. Only the baseline's NAND is legible in its bytecode; the weird
machine's NAND lives in runtime map metadata the verifier does not model.

```text
int wm_nand(void * ctx):
; int wm_nand(void *ctx)
   0: (b7) r1 = 0
   1: (63) *(u32 *)(r10 -16) = r1
   2: (bf) r2 = r10
;
   3: (07) r2 += -16
; __u64 *p = bpf_map_lookup_elem(&TAPE, &idx);
   4: (18) r1 = map[id:535]
   6: (07) r1 += 264
   7: (61) r0 = *(u32 *)(r2 +0)
   8: (35) if r0 >= 0x100 goto pc+3
   9: (67) r0 <<= 3
  10: (0f) r0 += r1
  11: (05) goto pc+1
  12: (b7) r0 = 0
  13: (b7) r7 = 1
  14: (b7) r6 = 1
; return p ? (*p & 1ull) : 0;
  15: (15) if r0 == 0x0 goto pc+4
; return p ? (*p & 1ull) : 0;
  16: (79) r1 = *(u64 *)(r0 +0)
; return p ? (*p & 1ull) : 0;
  17: (57) r1 &= 1
; __u64 out = NAND_GATE(G0, a, b);
  18: (15) if r1 == 0x0 goto pc+1
  19: (b7) r6 = 0
  20: (63) *(u32 *)(r10 -16) = r7
  21: (bf) r2 = r10
;
  22: (07) r2 += -16
; __u64 *p = bpf_map_lookup_elem(&TAPE, &idx);
  23: (18) r1 = map[id:535]
  25: (07) r1 += 264
  26: (61) r0 = *(u32 *)(r2 +0)
  27: (35) if r0 >= 0x100 goto pc+3
  28: (67) r0 <<= 3
  29: (0f) r0 += r1
  30: (05) goto pc+1
  31: (b7) r0 = 0
; return p ? (*p & 1ull) : 0;
  32: (15) if r0 == 0x0 goto pc+4
; return p ? (*p & 1ull) : 0;
  33: (79) r1 = *(u64 *)(r0 +0)
; return p ? (*p & 1ull) : 0;
  34: (57) r1 &= 1
; __u64 out = NAND_GATE(G0, a, b);
  35: (15) if r1 == 0x0 goto pc+1
  36: (b7) r7 = 0
  37: (b7) r1 = 2
  38: (63) *(u32 *)(r10 -4) = r1
  39: (4f) r6 |= r7
  40: (57) r6 &= 1
; v &= 1ull;
  41: (7b) *(u64 *)(r10 -16) = r6
  42: (bf) r2 = r10
;
  43: (07) r2 += -4
  44: (bf) r3 = r10
  45: (07) r3 += -16
; bpf_map_update_elem(&TAPE, &idx, &v, BPF_ANY);
  46: (18) r1 = map[id:535]
  48: (b7) r4 = 0
  49: (85) call array_map_update_elem#428432
; return 0;
  50: (b7) r0 = 0
  51: (95) exit
```

### A.9 Formal witness — occupancy yields an abstractly unresolved readout

The full derivation is in `results/abstraction_gap_witness.md`; the essence:

the verifier's abstract domain represents each map's identity and static
attributes (`max_entries`, key/value size) but not its dynamic occupancy `c(M)`.
The helper return prototype is `RET_INTEGER`, which the verifier records as an
unconstrained scalar. Yet under deterministic capacity semantics `CAP(k)`, the
concrete readout predicate `ψ(ret) = [ret == 0]` for a fresh-key update depends
on occupancy: it is true below capacity and false when the map is full. The
tested Linux 6.17.0/aarch64, preallocated non-LRU hash-map configuration
instantiates `CAP(2)` for this artifact; the negative errno was observed as
`-E2BIG` on that configuration.

**Proposition.** Assuming `CAP(k)`, for two reachable pre-states differing only
in dynamic map components erased by the verifier abstraction, one below capacity
and one at capacity, the abstract images coincide, the concrete readout
predicate differs, and the abstract transfer cannot decide the predicate. Thus
map occupancy yields an abstractly unresolved readout channel. The verifier
confirms this by forking at the output branch: both truth values are abstractly
reachable.

Verbatim from `results/nand.verifier.log` (`wm_nand`, insns as loaded):

```text
 78: (85) call bpf_map_update_elem#2   ; R0=scalar()                       # second input update, readout source
 79: (bf) r6 = r0                       ; R0=scalar(id=3) R6_w=scalar(id=3) # readout register
104: (15) if r6 == 0x0 goto pc+1        ; R6=scalar(id=3,umin=1)           # predicate unresolved; verifier forks
from 104 to 106: ... R6=0 ...                                              # both successors explored
```

Correspondence to A.7 (post-verification renumbering): verifier insns 78 / 104 /
114 are xlated insns 90 / 122 / 132. This states the residual readout as a
machine-checkable property of the verifier's own abstract semantics, and remains
sound-for-safety: the gap is in semantics the verifier never claims, i.e. the
designed incompleteness of a sound abstraction.

### A.10 Residual readout basis and theorem

Full development in `results/exploitable_gap.md`; the essence:

a bare unresolved readout is not yet programmable. The payload is not extra
expressiveness — the verifier accepts explicit-logic NAND (A.8) — but computation
whose input-output relation a sound analysis cannot certify.

**Definition.** A residual readout basis is exploitable when the accepted toolkit
provides: **(E1)** observability, the readout predicate can be branched into a
program bit; **(E2)** input-control, accepted operations can select residual
transitions as a function of program inputs; **(E3)** resettability, the residual
component returns to a known canonical class with no hidden carry-over except
explicit wire cells; and **(E4)** composability, finite circuits can be scheduled
with independent or resettable instances.

**Residual-Language Weird Machine theorem pair.** This is a LangSec-style
sufficient condition split into two claims. The realization theorem says that if
such a basis has a functionally complete induced gate, then for every finite
Boolean circuit there is an accepted bounded program instance. The opacity
theorem adds local gate-opacity relative to `(α,Q)`: the output relation is not
certified when exported gate outputs are derived only from unresolved residual
readouts, no local gate certificate in `Q` entails the gate relation, and no
recognizer-visible shadow logic in the gate writes an equivalent Boolean result.

**The eBPF PoC instantiates the hypothesis clauses** (`exploitable_gap.md` §5):
`φ` = occupancy `c(G0)`; `ψ(ret)=[ret==0]`; E1 = `if r6==0`; E2 = inputs select
sentinel update versus fresh-key update; E3 = delete `S,A,B` and reinsert `S`,
placing the gate in canonical class `{S}`; E4 = `G0..G8` plus explicit wire
values on `TAPE`; gate = NAND, validated through the exhaustive 8-bit adder.
`witness2/` instantiates the same opacity pattern for a join-based interval
analyzer and Frama-C EVA. Honest scope: bounded Boolean circuits, not
Turing-complete opacity or a fully general theorem for every sound abstraction.
### A.11 Second witness — interval analyzer and Frama-C EVA

`witness2/` provides an independent `(C, A)` pair with no eBPF maps, helper
returns, or verifier path sensitivity. The gate is:

```text
NAND(a, b) = [ (1 + a + b) mod 3 != 0 ]
```

The concrete channel `φ` is the congruence `acc mod 3`, which the interval
domain does not represent. The self-contained analyzer in `witness2/witness.py`
checks every concrete transfer for sound over-approximation and exhaustively
confirms NAND plus composed AND/XOR behavior. Its abstract output for the
working gate is `[0,1] = ⊤`, while the mod-7 ablation is `[1,1]`.

`witness2/frama_c/` runs the same construction through Frama-C EVA. The captured
log (`out/eva_slevel0.log`) reports `Frama_C_show_each_NAND_out: {0; 1}`,
`Frama_C_show_each_ABLATION_out: {1}`, `acc ∈ {1; 2; 3}`, and zero alarms. This
independent analyzer result supports the paper's system-independence argument:
the same opacity pattern appears in a join-based interval domain, not only in
the path-sensitive eBPF verifier.
