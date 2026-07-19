/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RAC_V2_TRACER_COMMON_BPF_H
#define RAC_V2_TRACER_COMMON_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "../include/rac_v2_events.h"
#include "verifier_state_v2.h"

#ifndef MAX_CALL_FRAMES
#define MAX_CALL_FRAMES 16
#endif
#ifndef MAX_BPF_REG
#define MAX_BPF_REG 11
#endif

enum rac_v2_sequence_slot {
    RAC_V2_EVENT_SEQUENCE = 0,
    RAC_V2_EQUALITY_SEQUENCE = 1,
    RAC_V2_VISIT_SEQUENCE = 2,
    RAC_V2_INVOCATION_TOKEN = 3,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rac_v2_config);
} rac_v2_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct rac_v2_visit_context);
} rac_v2_active_visits SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rac_v2_visit_context);
} rac_v2_visit_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} rac_v2_sequence_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rac_v2_stats);
} rac_v2_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rac_v2_events SEC(".maps");

static __always_inline __u64 rac_v2_mix64(__u64 h, __u64 v)
{
    h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    return h;
}

static __always_inline bool rac_v2_comm_matches(const char actual[RAC_COMM_LEN],
                                                 const char expected[RAC_COMM_LEN])
{
#pragma unroll
    for (int i = 0; i < RAC_COMM_LEN; i++) {
        if (expected[i] == '\0')
            return true;
        if (actual[i] != expected[i])
            return false;
    }
    return true;
}

static __always_inline bool rac_v2_selected_task(void)
{
    __u32 zero = 0;
    struct rac_v2_config *cfg = bpf_map_lookup_elem(&rac_v2_config_map, &zero);
    char comm[RAC_COMM_LEN] = {};
    __u64 pid_tgid;

    if (!cfg)
        return false;
    pid_tgid = bpf_get_current_pid_tgid();
    if (cfg->target_tgid && (__u32)(pid_tgid >> 32) != cfg->target_tgid)
        return false;
    if (cfg->target_comm[0]) {
        bpf_get_current_comm(comm, sizeof(comm));
        if (!rac_v2_comm_matches(comm, cfg->target_comm))
            return false;
    }
    return true;
}

static __always_inline struct rac_v2_stats *rac_v2_stats(void)
{
    __u32 zero = 0;

    return bpf_map_lookup_elem(&rac_v2_stats_map, &zero);
}

static __always_inline void rac_v2_count_unmatched_equal(void)
{
    struct rac_v2_stats *stats = rac_v2_stats();

    if (stats)
        __sync_fetch_and_add(&stats->unmatched_equal_events, 1);
}

static __always_inline void rac_v2_count_ambiguous_visit(void)
{
    struct rac_v2_stats *stats = rac_v2_stats();

    if (stats)
        __sync_fetch_and_add(&stats->ambiguous_visit_events, 1);
}

static __always_inline void rac_v2_count_dangling_visit(void)
{
    struct rac_v2_stats *stats = rac_v2_stats();

    if (stats)
        __sync_fetch_and_add(&stats->dangling_visit_contexts, 1);
}

static __always_inline void rac_v2_count_map_failure(void)
{
    struct rac_v2_stats *stats = rac_v2_stats();

    if (stats)
        __sync_fetch_and_add(&stats->tracer_map_update_failures, 1);
}

static __always_inline __u64 rac_v2_next_sequence(__u32 slot)
{
    __u64 *sequence = bpf_map_lookup_elem(&rac_v2_sequence_map, &slot);

    return sequence ? __sync_fetch_and_add(sequence, 1) + 1 : 0;
}

static __always_inline __u64 rac_v2_hash_reg(const struct bpf_reg_state *reg, __u64 h)
{
    struct bpf_reg_state value = {};

    if (!reg)
        return rac_v2_mix64(h, 0xdead0001ULL);
    bpf_core_read(&value, sizeof(value), reg);
    h = rac_v2_mix64(h, value.type);
    h = rac_v2_mix64(h, value.id);
    h = rac_v2_mix64(h, (__u32)value.off);
    h = rac_v2_mix64(h, value.var_off.value);
    h = rac_v2_mix64(h, value.var_off.mask);
    h = rac_v2_mix64(h, value.smin_value);
    h = rac_v2_mix64(h, value.smax_value);
    h = rac_v2_mix64(h, value.umin_value);
    h = rac_v2_mix64(h, value.umax_value);
    h = rac_v2_mix64(h, value.live);
    h = rac_v2_mix64(h, value.precise);
    return h;
}

static __always_inline __u64 rac_v2_hash_current_frame(const struct bpf_verifier_state *state,
                                                        __u32 curframe, __u64 h)
{
    struct bpf_func_state *frame = NULL;

    if (!state || curframe >= MAX_CALL_FRAMES)
        return rac_v2_mix64(h, 0xdead0002ULL);
    bpf_core_read(&frame, sizeof(frame), &state->frame[curframe]);
    if (!frame)
        return rac_v2_mix64(h, 0xdead0003ULL);
#pragma unroll
    for (int i = 0; i < MAX_BPF_REG; i++)
        h = rac_v2_hash_reg(&frame->regs[i], h);
    h = rac_v2_mix64(h, BPF_CORE_READ(frame, callsite));
    h = rac_v2_mix64(h, BPF_CORE_READ(frame, allocated_stack));
    return h;
}

static __always_inline __u64 rac_v2_hash_history(const struct bpf_verifier_state *state,
                                                  __u32 count)
{
    struct bpf_jmp_history_entry *history = NULL;
    __u64 h = 0xcbf29ce484222325ULL;

    if (!state || !count)
        return h;
    bpf_core_read(&history, sizeof(history), &state->jmp_history);
    if (!history)
        return rac_v2_mix64(h, 0xdead0004ULL);
#pragma unroll
    for (int i = 0; i < RAC_MAX_HISTORY; i++) {
        struct bpf_jmp_history_entry entry = {};

        if ((__u32)i >= count)
            break;
        bpf_probe_read_kernel(&entry, sizeof(entry), &history[i]);
        h = rac_v2_mix64(h, entry.idx);
        h = rac_v2_mix64(h, entry.prev_idx);
        h = rac_v2_mix64(h, entry.flags);
        h = rac_v2_mix64(h, entry.linked_regs);
    }
    return h;
}

static __always_inline void rac_v2_copy_history(const struct bpf_verifier_state *state,
                                                 struct rac_snapshot *out, __u32 count)
{
    struct bpf_jmp_history_entry *history = NULL;

    out->history_captured_count = 0;
    if (!state || !count)
        return;
    bpf_core_read(&history, sizeof(history), &state->jmp_history);
    if (!history)
        return;
#pragma unroll
    for (int i = 0; i < RAC_MAX_HISTORY; i++) {
        struct bpf_jmp_history_entry entry = {};

        if ((__u32)i >= count)
            break;
        bpf_probe_read_kernel(&entry, sizeof(entry), &history[i]);
        out->history_entries[i].insn_idx = entry.idx;
        out->history_entries[i].prev_insn_idx = entry.prev_idx;
        out->history_entries[i].flags = entry.flags;
        out->history_entries[i].linked_regs = entry.linked_regs;
        out->history_captured_count = i + 1;
    }
}

static __always_inline void rac_v2_take_snapshot(const struct bpf_verifier_state *state,
                                                  struct rac_snapshot *out)
{
    __u32 curframe = 0;
    __u32 history_count = 0;
    __u64 h = 0x84222325cbf29ce4ULL;

    out->insn_idx = 0;
    out->first_insn_idx = -1;
    out->last_insn_idx = -1;
    out->curframe = 0;
    out->dfs_depth = 0;
    out->state_hash = 0;
    out->history_hash = 0;
    out->history_count = 0;
    out->history_total_count = 0;
    out->history_captured_count = 0;
    out->history_truncated = 0;
    rac_init_state_v2(&out->state_v2);
    if (!state)
        return;
    out->insn_idx = BPF_CORE_READ(state, insn_idx);
    out->first_insn_idx = BPF_CORE_READ(state, first_insn_idx);
    out->last_insn_idx = BPF_CORE_READ(state, last_insn_idx);
    curframe = BPF_CORE_READ(state, curframe);
    history_count = BPF_CORE_READ(state, jmp_history_cnt);
    out->curframe = curframe;
    out->history_count = history_count;
    out->history_total_count = history_count;
    out->history_truncated = history_count > RAC_MAX_HISTORY;
    out->dfs_depth = BPF_CORE_READ(state, dfs_depth);
    h = rac_v2_mix64(h, out->insn_idx);
    h = rac_v2_mix64(h, curframe);
    h = rac_v2_mix64(h, BPF_CORE_READ(state, speculative));
    h = rac_v2_mix64(h, BPF_CORE_READ(state, branches));
    h = rac_v2_mix64(h, BPF_CORE_READ(state, may_goto_depth));
    h = rac_v2_hash_current_frame(state, curframe, h);
    out->state_hash = h;
    history_count = history_count > RAC_MAX_HISTORY ? RAC_MAX_HISTORY : history_count;
    out->history_hash = rac_v2_hash_history(state, history_count);
    rac_v2_copy_history(state, out, history_count);
    rac_capture_state_v2(state, &out->state_v2);
}

static __always_inline bool rac_v2_read_program_identity(struct bpf_verifier_env *env,
                                                          __u64 *load_time,
                                                          char (*program_name)[RAC_COMM_LEN],
                                                          __u8 (*program_tag)[RAC_V2_PROGRAM_TAG_LEN])
{
    struct bpf_prog *prog = NULL;
    struct bpf_prog_aux *aux = NULL;

#pragma unroll
    for (int i = 0; i < RAC_COMM_LEN; i++)
        (*program_name)[i] = 0;
#pragma unroll
    for (int i = 0; i < RAC_V2_PROGRAM_TAG_LEN; i++)
        (*program_tag)[i] = 0;
    *load_time = 0;
    if (!env)
        return false;
    prog = BPF_CORE_READ(env, prog);
    if (!prog)
        return false;
    aux = BPF_CORE_READ(prog, aux);
    if (!aux)
        return false;
    *load_time = BPF_CORE_READ(aux, load_time);
    BPF_CORE_READ_STR_INTO(program_name, aux, name);
    BPF_CORE_READ_INTO(program_tag, prog, tag);
    return *load_time != 0;
}

static __always_inline bool rac_v2_context_matches_env(struct bpf_verifier_env *env,
                                                        const struct rac_v2_visit_context *context)
{
    __u64 load_time = 0;
    char program_name[RAC_COMM_LEN] = {};
    __u8 program_tag[RAC_V2_PROGRAM_TAG_LEN] = {};

    if (!context || !rac_v2_read_program_identity(env, &load_time, &program_name, &program_tag))
        return false;
    if (load_time != context->program_load_time)
        return false;
#pragma unroll
    for (int i = 0; i < RAC_COMM_LEN; i++) {
        if (program_name[i] != context->program_name[i])
            return false;
    }
#pragma unroll
    for (int i = 0; i < RAC_V2_PROGRAM_TAG_LEN; i++) {
        if (program_tag[i] != context->program_tag[i])
            return false;
    }
    return true;
}

static __always_inline void rac_v2_visit_enter(struct bpf_verifier_env *env, int insn_idx)
{
    __u64 key = bpf_get_current_pid_tgid();
    __u32 zero = 0;
    struct rac_v2_visit_context *existing;
    struct rac_v2_visit_context *scratch;

    if (!rac_v2_selected_task())
        return;
    existing = bpf_map_lookup_elem(&rac_v2_active_visits, &key);
    if (existing) {
        existing->nested_or_ambiguous = 1;
        rac_v2_count_ambiguous_visit();
        return;
    }
    scratch = bpf_map_lookup_elem(&rac_v2_visit_scratch, &zero);
    if (!scratch) {
        rac_v2_count_map_failure();
        return;
    }
    /*
     * A verifier_env pointer is BPF pointer-tainted and must never enter a
     * map or ring buffer.  The active (pid_tgid, invocation-token) context,
     * together with fentry/fexit nesting rejection, is the admissible
     * invocation scope for this experiment.
     */
    scratch->invocation_token = rac_v2_next_sequence(RAC_V2_INVOCATION_TOKEN);
    scratch->visit_sequence = rac_v2_next_sequence(RAC_V2_VISIT_SEQUENCE);
    scratch->equality_sequence = 0;
    scratch->visit_insn = insn_idx;
    scratch->exact_level = -1;
    scratch->equality_success_count = 0;
    scratch->nested_or_ambiguous = 0;
    if (!rac_v2_read_program_identity(env, &scratch->program_load_time,
                                      &scratch->program_name, &scratch->program_tag)) {
        rac_v2_count_map_failure();
        return;
    }
    if (bpf_map_update_elem(&rac_v2_active_visits, &key, scratch, BPF_ANY))
        rac_v2_count_map_failure();
}

static __always_inline void rac_v2_equal_exit(struct bpf_verifier_env *env,
                                               struct bpf_verifier_state *old,
                                               struct bpf_verifier_state *current,
                                               int exact_level, bool equal)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct rac_v2_visit_context *context;

    if (!equal || !rac_v2_selected_task())
        return;
    context = bpf_map_lookup_elem(&rac_v2_active_visits, &key);
    if (!context || !rac_v2_context_matches_env(env, context)) {
        rac_v2_count_unmatched_equal();
        return;
    }
    context->equality_success_count++;
    if (context->equality_success_count != 1) {
        if (!context->nested_or_ambiguous) {
            context->nested_or_ambiguous = 1;
            rac_v2_count_ambiguous_visit();
        }
        return;
    }
    context->equality_sequence = rac_v2_next_sequence(RAC_V2_EQUALITY_SEQUENCE);
    context->exact_level = exact_level;
    rac_v2_take_snapshot(old, &context->old);
    rac_v2_take_snapshot(current, &context->current);
}

static __always_inline void rac_v2_visit_exit(struct bpf_verifier_env *env, int insn_idx, long ret)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct rac_v2_visit_context *context;
    struct rac_v2_prune_event *event;
    struct rac_v2_stats *stats;

    if (!rac_v2_selected_task())
        return;
    context = bpf_map_lookup_elem(&rac_v2_active_visits, &key);
    if (!context)
        return;
    if (context->visit_insn != insn_idx || !rac_v2_context_matches_env(env, context)) {
        rac_v2_count_dangling_visit();
        bpf_map_delete_elem(&rac_v2_active_visits, &key);
        return;
    }
    if (ret == 1 && context->equality_success_count == 1 && !context->nested_or_ambiguous) {
        event = bpf_ringbuf_reserve(&rac_v2_events, sizeof(*event), 0);
        if (!event) {
            stats = rac_v2_stats();
            if (stats)
                __sync_fetch_and_add(&stats->ringbuf_lost_events, 1);
        } else {
            event->sequence = rac_v2_next_sequence(RAC_V2_EVENT_SEQUENCE);
            event->equality_sequence = context->equality_sequence;
            event->visit_sequence = context->visit_sequence;
            event->invocation_token = context->invocation_token;
            event->program_load_time = context->program_load_time;
            event->states_equal_success_count = context->equality_success_count;
            event->visit_insn = context->visit_insn;
            event->exact_level = context->exact_level;
            bpf_get_current_comm(event->comm, sizeof(event->comm));
#pragma unroll
            for (int i = 0; i < RAC_COMM_LEN; i++)
                event->program_name[i] = context->program_name[i];
#pragma unroll
            for (int i = 0; i < RAC_V2_PROGRAM_TAG_LEN; i++)
                event->program_tag[i] = context->program_tag[i];
            if (bpf_probe_read_kernel(&event->old, sizeof(event->old), &context->old) ||
                bpf_probe_read_kernel(&event->current, sizeof(event->current), &context->current)) {
                bpf_ringbuf_discard(event, 0);
                rac_v2_count_map_failure();
                bpf_map_delete_elem(&rac_v2_active_visits, &key);
                return;
            }
            bpf_ringbuf_submit(event, 0);
            stats = rac_v2_stats();
            if (stats)
                __sync_fetch_and_add(&stats->events_emitted, 1);
        }
    } else if (ret == 1 && context->equality_success_count) {
        rac_v2_count_ambiguous_visit();
    }
    bpf_map_delete_elem(&rac_v2_active_visits, &key);
}

#endif
