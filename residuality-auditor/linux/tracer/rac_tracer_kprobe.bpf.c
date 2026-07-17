// SPDX-License-Identifier: GPL-2.0-only
#include "rac_tracer_common.bpf.h"
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct rac_prune_event);
} equal_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, int);
} visit_args_map SEC(".maps");

SEC("kprobe/states_equal")
int BPF_KPROBE(rac_states_equal_entry,
               struct bpf_verifier_env *env,
               struct bpf_verifier_state *old,
               struct bpf_verifier_state *current,
               enum exact_level exact)
{
    __u64 key = bpf_get_current_pid_tgid();
    __u32 zero = 0;
    struct rac_prune_event *pending;

    if (selected_task()) {
        pending = bpf_map_lookup_elem(&pending_scratch, &zero);
        if (!pending)
            return 0;
        fill_pending(env, old, current, exact, pending);
        bpf_map_update_elem(&equal_args_map, &key, pending, BPF_ANY);
    }
    return 0;
}

SEC("kretprobe/states_equal")
int BPF_KRETPROBE(rac_states_equal_return, long ret)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct rac_prune_event *captured = bpf_map_lookup_elem(&equal_args_map, &key);
    if (ret && captured)
        bpf_map_update_elem(&pending_equal, &key, captured, BPF_ANY);
    bpf_map_delete_elem(&equal_args_map, &key);
    return 0;
}

SEC("kprobe/is_state_visited")
int BPF_KPROBE(rac_is_state_visited_entry, struct bpf_verifier_env *env, int insn_idx)
{
    __u64 key = bpf_get_current_pid_tgid();
    if (selected_task())
        bpf_map_update_elem(&visit_args_map, &key, &insn_idx, BPF_ANY);
    return 0;
}

SEC("kretprobe/is_state_visited")
int BPF_KRETPROBE(rac_is_state_visited_return, long ret)
{
    __u64 key = bpf_get_current_pid_tgid();
    int *insn_idx = bpf_map_lookup_elem(&visit_args_map, &key);
    if (insn_idx)
        emit_prune(*insn_idx, ret);
    bpf_map_delete_elem(&visit_args_map, &key);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
