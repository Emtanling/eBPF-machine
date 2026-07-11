#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "wm_common.h"

char LICENSE[] SEC("license") = "GPL";

#define ONE 1ull

#ifndef GATE_CAP
#define GATE_CAP 2
#endif

#if defined(WM_BASELINE_NAND)
#define WM_VARIANT_ID 4
#elif defined(WM_FORCE_SENTINEL_B)
#define WM_VARIANT_ID 3
#elif GATE_CAP == 64
#define WM_VARIANT_ID 2
#else
#define WM_VARIANT_ID 1
#endif

#define barrier() asm volatile("" ::: "memory")

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TAPE_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} TAPE SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, VM_MAX_GATES);
    __type(key, __u32);
    __type(value, struct wm_gate_desc);
} CIRCUIT SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, VM_MAX_WIRES);
    __type(key, __u32);
    __type(value, __u64);
} WIRES SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct wm_vm_control);
} VM_CONTROL SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, VM_MAX_GATES);
    __type(key, __u32);
    __type(value, struct wm_gate_trace);
} VM_TRACE SEC(".maps");

#define DECL_GATE(name)                       \
struct {                                      \
    __uint(type, BPF_MAP_TYPE_HASH);          \
    __uint(max_entries, GATE_CAP);            \
    __type(key, __u32);                       \
    __type(value, __u64);                     \
} name SEC(".maps")

DECL_GATE(G0);
DECL_GATE(G1);
DECL_GATE(G2);
DECL_GATE(G3);
DECL_GATE(G4);
DECL_GATE(G5);
DECL_GATE(G6);
DECL_GATE(G7);
DECL_GATE(G8);

static __always_inline __u64 tape_read(__u32 idx)
{
    __u64 *p = bpf_map_lookup_elem(&TAPE, &idx);
    return p ? (*p & 1ull) : 0;
}

static __always_inline void tape_write(__u32 idx, __u64 v)
{
    v &= 1ull;
    bpf_map_update_elem(&TAPE, &idx, &v, BPF_ANY);
}

static __always_inline void tape_write_raw(__u32 idx, __u64 v)
{
    bpf_map_update_elem(&TAPE, &idx, &v, BPF_ANY);
}

static __always_inline void reset_second_update_observation(void)
{
    tape_write_raw(SECOND_UPDATE_RAW_IDX, 0);
    tape_write_raw(SECOND_UPDATE_VALID_IDX, 0);
}

static __always_inline void record_build_identity(void)
{
    tape_write_raw(VARIANT_ID_IDX, WM_VARIANT_ID);
    tape_write_raw(GATE_CAP_OBS_IDX, GATE_CAP);
}

static __always_inline void record_second_update(long ret)
{
    /* Preserve all 64 return bits; userspace decodes them as signed int64. */
    tape_write_raw(SECOND_UPDATE_RAW_IDX, (__u64)ret);
    tape_write_raw(SECOND_UPDATE_VALID_IDX, 1);
}

static __always_inline void err_bump(void)
{
    __u32 idx = ERR_IDX;
    __u64 *p = bpf_map_lookup_elem(&TAPE, &idx);
    __u64 v = (p ? *p : 0) + 1;
    bpf_map_update_elem(&TAPE, &idx, &v, BPF_ANY);
}

#ifdef WM_BASELINE_NAND
#define NAND_GATE_OBS(MAP, A, B, RAW_OUT, VALID_OUT, SETUP_OK_OUT) ({ \
    (RAW_OUT) = 0;                                                    \
    (VALID_OUT) = 0;                                                  \
    (SETUP_OK_OUT) = 1;                                               \
    (__u64)(!(((A) & 1ull) && ((B) & 1ull)));                         \
})
#else
/*
 * Capacity-saturation NAND. The output truth value is NOT produced by any
 * ALU/compare on A,B: the inputs only select which key is written, and that
 * selection is branchless (key = base + delta * bit). The result bit is the
 * return predicate (r2 == 0) of the second input-conditioned update, after
 * sentinel setup and the first input update. Determinism rests on
 * BPF_MAP_TYPE_HASH being non-evicting (not LRU): a new key on a full map of
 * max_entries = GATE_CAP = 2 fails. Default preallocation is retained for the
 * tested configuration. Kernel-internal per-CPU allocator caches/spares do not
 * turn this ordinary HASH into a PERCPU_HASH or increase its logical
 * max_entries. The portable contract used here is ret < 0 on the at-capacity
 * fresh-key update; the suite records the exact observed errno instead of
 * assuming that it is kernel-stable.
 */
#define NAND_GATE_OBS(MAP, A, B, RAW_OUT, VALID_OUT, SETUP_OK_OUT) ({ \
    __u32 ks = K_S, ka = K_A, kb = K_B;                              \
    __u64 one = ONE;                                                 \
    bpf_map_delete_elem(&(MAP), &ks);                                \
    bpf_map_delete_elem(&(MAP), &ka);                                \
    bpf_map_delete_elem(&(MAP), &kb);                                \
    barrier();                                                       \
    long r0 = bpf_map_update_elem(&(MAP), &ks, &one, BPF_NOEXIST);   \
    barrier();                                                       \
    __u32 k1 = ks + (ka - ks) * (__u32)((A) & 1ull);                               \
    long r1 = bpf_map_update_elem(&(MAP), &k1, &one, BPF_ANY);       \
    barrier();                                                       \
    __u32 k2 = ks + (kb - ks) * (__u32)((B) & 1ull);                               \
    long r2 = bpf_map_update_elem(&(MAP), &k2, &one, BPF_ANY);       \
    barrier();                                                       \
    record_second_update(r2);                                       \
    (RAW_OUT) = r2;                                                   \
    (VALID_OUT) = 1;                                                 \
    (SETUP_OK_OUT) = (r0 == 0 && r1 == 0);                           \
    if (r0 || r1)                                                    \
        err_bump();                                                  \
    (__u64)(r2 == 0);                                                \
})
#endif

#ifdef WM_FORCE_SENTINEL_B
#undef NAND_GATE_OBS
#define NAND_GATE_OBS(MAP, A, B, RAW_OUT, VALID_OUT, SETUP_OK_OUT) ({ \
    __u32 ks = K_S, ka = K_A;                                        \
    __u64 one = ONE;                                                 \
    bpf_map_delete_elem(&(MAP), &ks);                                \
    bpf_map_delete_elem(&(MAP), &ka);                                \
    __u32 kb_del = K_B;                                              \
    bpf_map_delete_elem(&(MAP), &kb_del);                            \
    barrier();                                                       \
    long r0 = bpf_map_update_elem(&(MAP), &ks, &one, BPF_NOEXIST);   \
    barrier();                                                       \
    __u32 k1 = ks + (ka - ks) * (__u32)((A) & 1ull);                               \
    long r1 = bpf_map_update_elem(&(MAP), &k1, &one, BPF_ANY);       \
    barrier();                                                       \
    long r2 = bpf_map_update_elem(&(MAP), &ks, &one, BPF_ANY);       \
    barrier();                                                       \
    record_second_update(r2);                                       \
    (RAW_OUT) = r2;                                                   \
    (VALID_OUT) = 1;                                                 \
    (SETUP_OK_OUT) = (r0 == 0 && r1 == 0);                           \
    if (r0 || r1)                                                    \
        err_bump();                                                  \
    (__u64)(r2 == 0);                                                \
})
#endif

#define NAND_GATE(MAP, A, B) ({                                      \
    long __wm_raw = 0;                                               \
    __u32 __wm_valid = 0;                                            \
    __u32 __wm_setup_ok = 0;                                         \
    __u64 __wm_out = NAND_GATE_OBS(MAP, A, B, __wm_raw,              \
                                    __wm_valid, __wm_setup_ok);       \
    __wm_out;                                                        \
})

struct vm_run_ctx {
    __u32 input_count;
    __u32 gate_count;
    __u32 wire_count;
    __u32 status;
    __u32 executed;
    __u32 failing_gate;
};

static __always_inline long vm_fail(struct vm_run_ctx *ctx, __u32 status,
                                    __u32 gate)
{
    if (ctx->status == VM_STATUS_OK) {
        ctx->status = status;
        ctx->failing_gate = gate;
    }
    return 1;
}

static long circuit_step_cb(__u32 i, void *data)
{
    struct vm_run_ctx *ctx = data;
    __u32 gate_key = i;
    struct wm_gate_desc *gate_ptr;
    struct wm_gate_desc gate;
    __u32 expected_dst;
    __u64 *src_ptr;
    __u64 a, b, out;
    long raw = 0;
    __u32 valid = 0;
    __u32 setup_ok = 0;
    struct wm_gate_trace trace = {};

    if (i >= ctx->gate_count)
        return 1;

    gate_ptr = bpf_map_lookup_elem(&CIRCUIT, &gate_key);
    if (!gate_ptr)
        return vm_fail(ctx, VM_STATUS_BAD_DESCRIPTOR, i);
    gate = *gate_ptr;

    expected_dst = VM_INPUT_BASE + ctx->input_count + i;
    if (gate.op != VM_OP_NAND || gate.dst != expected_dst ||
        gate.src0 >= gate.dst || gate.src1 >= gate.dst ||
        gate.dst >= ctx->wire_count || gate.dst >= VM_MAX_WIRES)
        return vm_fail(ctx, VM_STATUS_BAD_DESCRIPTOR, i);

    src_ptr = bpf_map_lookup_elem(&WIRES, &gate.src0);
    if (!src_ptr)
        return vm_fail(ctx, VM_STATUS_BAD_WIRE, i);
    a = *src_ptr & 1ull;

    src_ptr = bpf_map_lookup_elem(&WIRES, &gate.src1);
    if (!src_ptr)
        return vm_fail(ctx, VM_STATUS_BAD_WIRE, i);
    b = *src_ptr & 1ull;

    out = NAND_GATE_OBS(G0, a, b, raw, valid, setup_ok);
    if (!setup_ok)
        return vm_fail(ctx, VM_STATUS_GATE_SETUP, i);
    if (valid && raw > 0)
        return vm_fail(ctx, VM_STATUS_GATE_RETURN, i);

    if (bpf_map_update_elem(&WIRES, &gate.dst, &out, BPF_ANY))
        return vm_fail(ctx, VM_STATUS_BAD_WIRE, i);

    trace.second_update_raw_ret = raw;
    trace.output = (__u32)(out & 1ull);
    trace.valid = valid;
    if (bpf_map_update_elem(&VM_TRACE, &gate_key, &trace, BPF_ANY))
        return vm_fail(ctx, VM_STATUS_TRACE_WRITE, i);

    ctx->executed++;
    return 0;
}

SEC("syscall")
int wm_circuit(void *ctx)
{
    (void)ctx;
    __u32 key = 0;
    struct wm_vm_control *control_ptr;
    struct wm_vm_control control;
    struct vm_run_ctx run = {};
    __u64 zero = 0;
    __u64 one = 1;
    long loop_ret = 0;

    record_build_identity();
    reset_second_update_observation();
    tape_write_raw(ERR_IDX, 0);

    control_ptr = bpf_map_lookup_elem(&VM_CONTROL, &key);
    if (!control_ptr)
        return 0;
    control = *control_ptr;
    control.status = VM_STATUS_OK;
    control.executed = 0;
    control.failing_gate = VM_NO_FAILING_GATE;

    if (control.abi_version != VM_ABI_VERSION) {
        control.status = VM_STATUS_BAD_ABI;
        goto done;
    }
    if (control.input_count > VM_MAX_INPUTS) {
        control.status = VM_STATUS_BAD_INPUT_COUNT;
        goto done;
    }
    if (control.gate_count > VM_MAX_GATES) {
        control.status = VM_STATUS_BAD_GATE_COUNT;
        goto done;
    }
    if (control.wire_count !=
            VM_INPUT_BASE + control.input_count + control.gate_count ||
        control.wire_count > VM_MAX_WIRES) {
        control.status = VM_STATUS_BAD_WIRE_COUNT;
        goto done;
    }

    if (bpf_map_update_elem(&WIRES, &key, &zero, BPF_ANY)) {
        control.status = VM_STATUS_BAD_WIRE;
        goto done;
    }
    key = VM_CONST_ONE;
    if (bpf_map_update_elem(&WIRES, &key, &one, BPF_ANY)) {
        control.status = VM_STATUS_BAD_WIRE;
        goto done;
    }

    run.input_count = control.input_count;
    run.gate_count = control.gate_count;
    run.wire_count = control.wire_count;
    run.status = VM_STATUS_OK;
    run.executed = 0;
    run.failing_gate = VM_NO_FAILING_GATE;

    loop_ret = bpf_loop(control.gate_count, circuit_step_cb, &run, 0);
    control.status = run.status;
    control.executed = run.executed;
    control.failing_gate = run.failing_gate;
    if (control.status == VM_STATUS_OK &&
        (loop_ret != control.gate_count ||
         control.executed != control.gate_count))
        control.status = VM_STATUS_LOOP;

done:
    key = 0;
    bpf_map_update_elem(&VM_CONTROL, &key, &control, BPF_ANY);
    return 0;
}

SEC("syscall")
int wm_nand(void *ctx)
{
    (void)ctx;
    record_build_identity();
    reset_second_update_observation();
    __u64 a = tape_read(IDX_A);
    __u64 b = tape_read(IDX_B);
    __u64 out = NAND_GATE(G0, a, b);
    tape_write(IDX_NAND_OUT, out);
    return 0;
}

static __always_inline void full_adder(__u64 a, __u64 b, __u64 cin,
                                       __u64 *sum, __u64 *cout)
{
    __u64 d   = NAND_GATE(G0, a, b);
    __u64 e   = NAND_GATE(G1, a, d);
    __u64 f   = NAND_GATE(G2, b, d);
    __u64 xab = NAND_GATE(G3, e, f);
    __u64 g   = NAND_GATE(G4, xab, cin);
    __u64 h   = NAND_GATE(G5, xab, g);
    __u64 i   = NAND_GATE(G6, cin, g);
    *sum  = NAND_GATE(G7, h, i);
    *cout = NAND_GATE(G8, d, g);
}

SEC("syscall")
int wm_fa(void *ctx)
{
    (void)ctx;
    record_build_identity();
    reset_second_update_observation();
    __u64 a = tape_read(IDX_A);
    __u64 b = tape_read(IDX_B);
    __u64 cin = tape_read(IDX_CIN);
    __u64 sum = 0;
    __u64 cout = 0;

    full_adder(a, b, cin, &sum, &cout);
    tape_write(IDX_SUM_OUT, sum);
    tape_write(IDX_COUT_OUT, cout);
    return 0;
}

static long step_cb(__u32 i, void *data)
{
    (void)data;
    if (i >= WORDLEN)
        return 1;

    __u64 xi = tape_read(X_BASE + i);
    __u64 yi = tape_read(Y_BASE + i);
    __u64 cin = tape_read(CARRY_IDX);
    __u64 sum = 0;
    __u64 cout = 0;

    full_adder(xi, yi, cin, &sum, &cout);
    tape_write(S_BASE + i, sum);
    tape_write(CARRY_IDX, cout);
    return 0;
}

SEC("syscall")
int wm_adder32(void *ctx)
{
    (void)ctx;
    __u64 zero = 0;
    __u32 ci = CARRY_IDX;
    __u32 ei = ERR_IDX;

    bpf_map_update_elem(&TAPE, &ci, &zero, BPF_ANY);
    bpf_map_update_elem(&TAPE, &ei, &zero, BPF_ANY);
    record_build_identity();
    reset_second_update_observation();
    long loop_ret = bpf_loop(WORDLEN, step_cb, 0, 0);
    if (loop_ret != WORDLEN)
        err_bump();
    return 0;
}
