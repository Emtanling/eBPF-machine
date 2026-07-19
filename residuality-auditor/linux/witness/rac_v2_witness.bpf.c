// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "rac_v2_witness.h"

#define RAC_V2_STATE_SLOT 0
#define RAC_V2_AUDIT_SLOT 0

/*
 * The V2 state carrier is a preallocated array, not a capacity-sensitive hash
 * map.  Its contents are still intentionally outside the verifier's scalar
 * path state, while update/lookup avoid the allocation pressure of the V1
 * hash-map witness.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} g0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rac_v2_trace);
} audit SEC(".maps");

/* Keep the branch-local map writes before the shared lookup suffix. */
static __noinline int select_branch(__u8 branch)
{
    __u32 key = RAC_V2_STATE_SLOT;
    __u32 value;

    if (branch) {
        value = 1;
        return (int)bpf_map_update_elem(&g0, &key, &value, BPF_ANY);
    }
    value = 0;
    return (int)bpf_map_update_elem(&g0, &key, &value, BPF_ANY);
}

/* The common suffix observes the value written by the branch-local prefix. */
static __noinline int shared_suffix(void)
{
    __u32 key = RAC_V2_STATE_SLOT;
    __u32 *value = bpf_map_lookup_elem(&g0, &key);

    if (!value)
        return 2;
    return (int)(*value & 1U);
}

SEC("xdp")
int rac_v2_single(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 audit_key = RAC_V2_AUDIT_SLOT;
    struct rac_v2_trace trace = {};
    __u8 branch;
    int branch_rc;
    int observed;

    if (data + 1 > data_end)
        return 3;
    branch = *(__u8 *)data & 1U;
    trace.branch = branch;

    branch_rc = select_branch(branch);
    trace.branch_rc = branch_rc;
    observed = shared_suffix();
    trace.lookup_missing = observed == 2;
    trace.selected_value = observed;
    trace.observed_value = observed;
    if (branch_rc) {
        trace.trace_errors |= RAC_V2_TRACE_BRANCH_FAILED;
        observed = 3;
    }
    if (observed == 2)
        trace.trace_errors |= RAC_V2_TRACE_LOOKUP_MISSING;
    bpf_map_update_elem(&audit, &audit_key, &trace, BPF_ANY);
    return observed;
}

char LICENSE[] SEC("license") = "GPL";
