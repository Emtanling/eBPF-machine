// SPDX-License-Identifier: GPL-2.0-only
#include "rac_tracer_common.bpf.h"
#include <bpf/bpf_tracing.h>

SEC("fexit/states_equal")
int BPF_PROG(rac_states_equal_exit,
             struct bpf_verifier_env *env,
             struct bpf_verifier_state *old,
             struct bpf_verifier_state *current,
             enum exact_level exact,
             bool ret)
{
    if (ret)
        remember_equal(env, old, current, (int)exact);
    return 0;
}

SEC("fexit/is_state_visited")
int BPF_PROG(rac_is_state_visited_exit,
             struct bpf_verifier_env *env,
             int insn_idx,
             int ret)
{
    emit_prune(insn_idx, ret);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
