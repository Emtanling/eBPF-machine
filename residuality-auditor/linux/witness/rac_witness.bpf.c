// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define KEY_S 0
#define KEY_A 1
#define KEY_B 2
#define AUDIT_SLOT 0

#define MASK_S (1U << KEY_S)
#define MASK_A (1U << KEY_A)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} g0 SEC(".maps");

/*
 * Evidence-only map. Each branch records the concrete G0 key set immediately
 * before the shared suffix. It does not steer the suffix.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} audit SEC(".maps");

/* Keep branch-local helper arguments in separate BPF-to-BPF call frames. */
static __noinline long select_a(void)
{
    __u32 ka = KEY_A, one = 1, slot = AUDIT_SLOT;
    __u32 mask = MASK_S | MASK_A;

    (void)bpf_map_update_elem(&g0, &ka, &one, BPF_NOEXIST);
    (void)bpf_map_update_elem(&audit, &slot, &mask, BPF_ANY);
    return 0;
}

static __noinline long select_s(void)
{
    __u32 s = KEY_S, one = 1, slot = AUDIT_SLOT;
    __u32 mask = MASK_S;

    (void)bpf_map_update_elem(&g0, &s, &one, BPF_EXIST);
    (void)bpf_map_update_elem(&audit, &slot, &mask, BPF_ANY);
    return 0;
}

static __noinline long select_branch(__u8 a)
{
    long rc;

    if (a)
        rc = select_a();
    else
        rc = select_s();
    return rc;
}

static __noinline long normalize_join(void)
{
    volatile __u32 scrub0 = 0;
    volatile __u32 scrub1 = 0;
    volatile __u32 scrub2 = 0;
    volatile __u32 scrub3 = 0;

    return scrub0 + scrub1 + scrub2 + scrub3;
}

static __noinline int shared_suffix(void)
{
    __u32 kb = KEY_B, one = 1;
    long rc;

    rc = bpf_map_update_elem(&g0, &kb, &one, BPF_NOEXIST);
    return rc == 0 ? 1 : 0;
}

SEC("xdp")
int rac_single(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 s = KEY_S, ka = KEY_A, kb = KEY_B, one = 1;
    long rc;
    __u8 branch_key;

    if (data + 1 > data_end)
        return 0;
    branch_key = *(__u8 *)data & 1;

    bpf_map_delete_elem(&g0, &s);
    bpf_map_delete_elem(&g0, &ka);
    bpf_map_delete_elem(&g0, &kb);
    rc = bpf_map_update_elem(&g0, &s, &one, BPF_NOEXIST);
    if (rc)
        return 0;

    (void)select_branch(branch_key);
    (void)normalize_join();

    /* Branch-specific call -> packet/stack-normalized post-call join -> shared suffix. */
    return shared_suffix();
}

char LICENSE[] SEC("license") = "GPL";
