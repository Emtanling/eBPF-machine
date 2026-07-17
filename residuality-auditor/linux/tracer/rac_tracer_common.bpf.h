/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RAC_TRACER_COMMON_BPF_H
#define RAC_TRACER_COMMON_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "../include/rac_events.h"
#include "verifier_state_v2.h"

/* Source-level macros are not preserved in generated vmlinux.h. */
#ifndef MAX_CALL_FRAMES
#define MAX_CALL_FRAMES 16
#endif
#ifndef MAX_BPF_REG
#define MAX_BPF_REG 11
#endif

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rac_config);
} rac_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct rac_prune_event);
} pending_equal SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rac_prune_event);
} pending_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sequence_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} lost_events_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline __u64 mix64(__u64 h, __u64 v)
{
    h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    return h;
}

static __always_inline bool comm_matches(const char actual[RAC_COMM_LEN],
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

static __always_inline bool selected_task(void)
{
    __u32 zero = 0;
    struct rac_config *cfg = bpf_map_lookup_elem(&rac_config_map, &zero);
    char comm[RAC_COMM_LEN] = {};
    __u64 pid_tgid;

    if (!cfg)
        return false;
    pid_tgid = bpf_get_current_pid_tgid();
    if (cfg->target_tgid && (__u32)(pid_tgid >> 32) != cfg->target_tgid)
        return false;
    if (cfg->target_comm[0]) {
        bpf_get_current_comm(comm, sizeof(comm));
        if (!comm_matches(comm, cfg->target_comm))
            return false;
    }
    return true;
}

static __always_inline __u64 hash_reg(const struct bpf_reg_state *reg, __u64 h)
{
    struct bpf_reg_state r = {};

    if (!reg)
        return mix64(h, 0xdead0001ULL);
    bpf_core_read(&r, sizeof(r), reg);
    h = mix64(h, r.type);
    h = mix64(h, r.id);
    h = mix64(h, (__u32)r.off);
    h = mix64(h, r.var_off.value);
    h = mix64(h, r.var_off.mask);
    h = mix64(h, r.smin_value);
    h = mix64(h, r.smax_value);
    h = mix64(h, r.umin_value);
    h = mix64(h, r.umax_value);
    h = mix64(h, r.live);
    h = mix64(h, r.precise);
    return h;
}

static __always_inline __u64 hash_current_frame(const struct bpf_verifier_state *state,
                                                 __u32 curframe, __u64 h)
{
    struct bpf_func_state *frame = NULL;

    if (!state || curframe >= MAX_CALL_FRAMES)
        return mix64(h, 0xdead0002ULL);
    bpf_core_read(&frame, sizeof(frame), &state->frame[curframe]);
    if (!frame)
        return mix64(h, 0xdead0003ULL);
#pragma unroll
    for (int i = 0; i < MAX_BPF_REG; i++)
        h = hash_reg(&frame->regs[i], h);
    h = mix64(h, BPF_CORE_READ(frame, callsite));
    h = mix64(h, BPF_CORE_READ(frame, allocated_stack));
    return h;
}

static __always_inline __u64 hash_history(const struct bpf_verifier_state *state,
                                          __u32 count)
{
    struct bpf_jmp_history_entry *history = NULL;
    __u64 h = 0xcbf29ce484222325ULL;

    if (!state || !count)
        return h;
    bpf_core_read(&history, sizeof(history), &state->jmp_history);
    if (!history)
        return mix64(h, 0xdead0004ULL);
#pragma unroll
    for (int i = 0; i < RAC_MAX_HISTORY; i++) {
        struct bpf_jmp_history_entry entry = {};
        if ((__u32)i >= count)
            break;
        bpf_probe_read_kernel(&entry, sizeof(entry), &history[i]);
        h = mix64(h, entry.idx);
        h = mix64(h, entry.prev_idx);
        h = mix64(h, entry.flags);
        h = mix64(h, entry.linked_regs);
    }
    return h;
}

static __always_inline void copy_history(const struct bpf_verifier_state *state,
                                           struct rac_snapshot *out,
                                           __u32 count)
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

static __always_inline void take_snapshot(const struct bpf_verifier_state *state,
                                          struct rac_snapshot *out)
{
    __u32 curframe = 0, history_count = 0;
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
    h = mix64(h, out->insn_idx);
    h = mix64(h, curframe);
    h = mix64(h, BPF_CORE_READ(state, speculative));
    h = mix64(h, BPF_CORE_READ(state, branches));
    h = mix64(h, BPF_CORE_READ(state, may_goto_depth));
    h = hash_current_frame(state, curframe, h);
    out->state_hash = h;
    history_count = history_count > RAC_MAX_HISTORY ? RAC_MAX_HISTORY : history_count;
    out->history_hash = hash_history(state, history_count);
    copy_history(state, out, history_count);
    rac_capture_state_v2(state, &out->state_v2);
}

static __always_inline void fill_pending(struct bpf_verifier_env *env,
                                        struct bpf_verifier_state *old,
                                        struct bpf_verifier_state *current,
                                        int exact_level,
                                        struct rac_prune_event *value)
{
    value->sequence = 0;
    value->observed_at_ns = bpf_ktime_get_ns();
    value->pid_tgid = 0;
    value->tgid = 0;
    value->pid = 0;
    value->visit_insn = 0;
    value->exact_level = exact_level;
#pragma unroll
    for (int i = 0; i < RAC_COMM_LEN; i++)
        value->program_name[i] = 0;
    if (env) {
        struct bpf_prog *prog = BPF_CORE_READ(env, prog);
        struct bpf_prog_aux *aux = prog ? BPF_CORE_READ(prog, aux) : NULL;
        if (aux)
            BPF_CORE_READ_STR_INTO(&value->program_name, aux, name);
    }
    take_snapshot(old, &value->old);
    take_snapshot(current, &value->current);
}

static __always_inline void remember_equal(struct bpf_verifier_env *env,
                                           struct bpf_verifier_state *old,
                                           struct bpf_verifier_state *current,
                                           int exact_level)
{
    __u64 key = bpf_get_current_pid_tgid();
    __u32 zero = 0;
    struct rac_prune_event *value;

    if (!selected_task())
        return;
    value = bpf_map_lookup_elem(&pending_scratch, &zero);
    if (!value)
        return;
    fill_pending(env, old, current, exact_level, value);
    bpf_map_update_elem(&pending_equal, &key, value, BPF_ANY);
}

static __always_inline void emit_prune(int visit_insn, long ret)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct rac_prune_event *pending;
    __u32 zero = 0;
    __u64 *seq;

    if (ret != 1 || !selected_task()) {
        bpf_map_delete_elem(&pending_equal, &key);
        return;
    }
    pending = bpf_map_lookup_elem(&pending_equal, &key);
    if (!pending)
        return;
    pending->sequence = 0;
    seq = bpf_map_lookup_elem(&sequence_map, &zero);
    if (seq)
        pending->sequence = __sync_fetch_and_add(seq, 1) + 1;
    pending->pid_tgid = key;
    pending->tgid = key >> 32;
    pending->pid = (__u32)key;
    pending->visit_insn = visit_insn;
    bpf_get_current_comm(pending->comm, sizeof(pending->comm));
    if (bpf_ringbuf_output(&events, pending, sizeof(*pending), 0)) {
        __u64 *lost = bpf_map_lookup_elem(&lost_events_map, &zero);
        if (lost)
            __sync_fetch_and_add(lost, 1);
    }
    bpf_map_delete_elem(&pending_equal, &key);
}

#endif
