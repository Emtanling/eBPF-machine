#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "wm_common.h"

char LICENSE[] SEC("license") = "GPL";

#define ONE 1ull

#ifndef GATE_CAP
#define GATE_CAP 2
#endif

#define barrier() asm volatile("" ::: "memory")

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TAPE_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} TAPE SEC(".maps");

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

static __always_inline void err_bump(void)
{
    __u32 idx = ERR_IDX;
    __u64 *p = bpf_map_lookup_elem(&TAPE, &idx);
    __u64 v = (p ? *p : 0) + 1;
    bpf_map_update_elem(&TAPE, &idx, &v, BPF_ANY);
}

#ifdef WM_BASELINE_NAND
#define NAND_GATE(MAP, A, B) ((__u64)(!(((A) & 1ull) && ((B) & 1ull))))
#else
/*
 * Capacity-saturation NAND. The output truth value is NOT produced by any
 * ALU/compare on A,B: the inputs only select which key is written, and that
 * selection is branchless (key = base + delta * bit). The result bit is the
 * return predicate (r2 == 0) of the second input-conditioned update, after
 * sentinel setup and the first input update. Determinism rests on
 * BPF_MAP_TYPE_HASH being preallocated (no BPF_F_NO_PREALLOC) and non-evicting
 * (not LRU): a new key on a full map of max_entries = GATE_CAP = 2
 * deterministically fails, observed as -E2BIG on the tested kernel.
 */
#define NAND_GATE(MAP, A, B) ({                                      \
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
    if (r0 || r1)                                                    \
        err_bump();                                                  \
    (__u64)(r2 == 0);                                                \
})
#endif

#ifdef WM_FORCE_SENTINEL_B
#undef NAND_GATE
#define NAND_GATE(MAP, A, B) ({                                      \
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
    if (r0 || r1)                                                    \
        err_bump();                                                  \
    (__u64)(r2 == 0);                                                \
})
#endif

SEC("syscall")
int wm_nand(void *ctx)
{
    (void)ctx;
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
    bpf_loop(WORDLEN, step_cb, 0, 0);
    return 0;
}
