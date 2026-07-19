// SPDX-License-Identifier: GPL-2.0-only
#include "rac_v2_tracer_common.bpf.h"
#include <bpf/bpf_tracing.h>

SEC("fentry/is_state_visited")
int BPF_PROG(rac_v2_is_state_visited_enter,
             struct bpf_verifier_env *env,
             int insn_idx)
{
    rac_v2_visit_enter(env, insn_idx);
    return 0;
}

SEC("fexit/states_equal")
int BPF_PROG(rac_v2_states_equal_exit,
             struct bpf_verifier_env *env,
             struct bpf_verifier_state *old,
             struct bpf_verifier_state *current,
             enum exact_level exact,
             bool ret)
{
    rac_v2_equal_exit(env, old, current, (int)exact, ret);
    return 0;
}

SEC("fexit/is_state_visited")
int BPF_PROG(rac_v2_is_state_visited_exit,
             struct bpf_verifier_env *env,
             int insn_idx,
             int ret)
{
    rac_v2_visit_exit(env, insn_idx, ret);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
