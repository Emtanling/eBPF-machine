/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RAC_VERIFIER_STATE_V2_H
#define RAC_VERIFIER_STATE_V2_H

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include "../include/rac_events.h"

static __always_inline void rac_copy_reg_v2(const struct bpf_reg_state *reg,
                                            struct rac_reg_v2 *out,
                                            __u64 *unsupported)
{
    struct bpf_reg_state r = {};
    __s32 type;

    out->type = -1;
    out->off = 0;
    out->var_off_value = 0;
    out->var_off_mask = 0;
    out->smin_value = 0;
    out->smax_value = 0;
    out->umin_value = 0;
    out->umax_value = 0;
    out->s32_min_value = 0;
    out->s32_max_value = 0;
    out->u32_min_value = 0;
    out->u32_max_value = 0;
    out->id = 0;
    out->ref_obj_id = 0;
    out->frameno = 0;
    out->subreg_def = 0;
    out->live = 0;
    out->precise = 0;
    out->raw1 = 0;
    out->raw2 = 0;
    out->parent_present = 0;
    out->reserved = 0;
    if (!reg)
        return;

    bpf_core_read(&r, sizeof(r), reg);
    type = r.type;
    out->type = type;
    out->off = r.off;
    out->var_off_value = r.var_off.value;
    out->var_off_mask = r.var_off.mask;
    out->smin_value = r.smin_value;
    out->smax_value = r.smax_value;
    out->umin_value = r.umin_value;
    out->umax_value = r.umax_value;
    out->s32_min_value = r.s32_min_value;
    out->s32_max_value = r.s32_max_value;
    out->u32_min_value = r.u32_min_value;
    out->u32_max_value = r.u32_max_value;
    out->id = r.id;
    out->ref_obj_id = r.ref_obj_id;
    out->frameno = r.frameno;
    out->subreg_def = r.subreg_def;
    out->live = r.live;
    out->precise = r.precise;
    out->raw1 = r.raw.raw1;
    out->raw2 = r.raw.raw2;
    out->parent_present = r.parent ? 1 : 0;

    if (r.ref_obj_id)
        *unsupported |= RAC_STATE_V2_UNSUPPORTED_REFS;
    if (type == CONST_PTR_TO_DYNPTR)
        *unsupported |= RAC_STATE_V2_UNSUPPORTED_DYNPTR;
    if (type == PTR_TO_PACKET || type == PTR_TO_PACKET_META || type == PTR_TO_PACKET_END)
        *unsupported |= RAC_STATE_V2_UNSUPPORTED_PACKET_RANGE;
    if (type == PTR_TO_SOCKET || type == PTR_TO_SOCKET_OR_NULL ||
        type == PTR_TO_SOCK_COMMON || type == PTR_TO_SOCK_COMMON_OR_NULL ||
        type == PTR_TO_TCP_SOCK || type == PTR_TO_TCP_SOCK_OR_NULL)
        *unsupported |= RAC_STATE_V2_UNSUPPORTED_SOCKET_REF;
}

static __always_inline void rac_copy_stack_slot_v2(struct bpf_stack_state *stack,
                                                   __u32 slot,
                                                   struct rac_stack_slot_v2 *out,
                                                   __u64 *unsupported)
{
    struct bpf_stack_state ss = {};
    __u32 initialized = 0;

    out->slot = slot;
    out->initialized = 0;
    out->reserved = 0;
#pragma unroll
    for (int i = 0; i < 8; i++)
        out->slot_type[i] = 0;
    rac_copy_reg_v2(NULL, &out->spilled_ptr, unsupported);
    if (!stack)
        return;

    bpf_probe_read_kernel(&ss, sizeof(ss), &stack[slot]);
#pragma unroll
    for (int i = 0; i < 8; i++) {
        out->slot_type[i] = ss.slot_type[i];
        if (ss.slot_type[i] != STACK_INVALID)
            initialized = 1;
        if (ss.slot_type[i] == STACK_DYNPTR)
            *unsupported |= RAC_STATE_V2_UNSUPPORTED_DYNPTR;
        if (ss.slot_type[i] == STACK_ITER)
            *unsupported |= RAC_STATE_V2_UNSUPPORTED_ITERATOR;
    }
    out->initialized = initialized;
    rac_copy_reg_v2(&ss.spilled_ptr, &out->spilled_ptr, unsupported);
}

static __always_inline void rac_copy_frame_v2(struct bpf_func_state *frame,
                                              struct rac_frame_v2 *out,
                                              __u64 *unsupported)
{
    struct bpf_stack_state *stack = NULL;
    int allocated_stack = 0;
    __u32 stack_slots = 0;
    __u32 captured_slots = 0;
    __u32 nonzero_slots = 0;

    out->present = 0;
    out->frameno = 0;
    out->callsite = 0;
    out->subprogno = 0;
    out->async_entry_cnt = 0;
    out->callback_ret_min = 0;
    out->callback_ret_max = 0;
    out->in_callback_fn = 0;
    out->in_async_callback_fn = 0;
    out->in_exception_callback_fn = 0;
    out->callback_depth = 0;
    out->allocated_stack = 0;
    out->stack_slot_count = 0;
    out->stack_nonzero_slot_count = 0;
    out->stack_truncated = 0;
    out->reserved = 0;
#pragma unroll
    for (int i = 0; i < RAC_MAX_REGS; i++)
        rac_copy_reg_v2(NULL, &out->regs[i], unsupported);

    if (!frame)
        return;

    out->present = 1;
    out->frameno = BPF_CORE_READ(frame, frameno);
    out->callsite = BPF_CORE_READ(frame, callsite);
    out->subprogno = BPF_CORE_READ(frame, subprogno);
    out->async_entry_cnt = BPF_CORE_READ(frame, async_entry_cnt);
    out->callback_ret_min = BPF_CORE_READ(frame, callback_ret_range.minval);
    out->callback_ret_max = BPF_CORE_READ(frame, callback_ret_range.maxval);
    out->in_callback_fn = BPF_CORE_READ(frame, in_callback_fn) ? 1 : 0;
    out->in_async_callback_fn = BPF_CORE_READ(frame, in_async_callback_fn) ? 1 : 0;
    out->in_exception_callback_fn = BPF_CORE_READ(frame, in_exception_callback_fn) ? 1 : 0;
    out->callback_depth = BPF_CORE_READ(frame, callback_depth);
    allocated_stack = BPF_CORE_READ(frame, allocated_stack);
    out->allocated_stack = allocated_stack;

    if (out->async_entry_cnt || out->in_callback_fn || out->in_async_callback_fn ||
        out->in_exception_callback_fn || out->callback_depth)
        *unsupported |= RAC_STATE_V2_UNSUPPORTED_CALLBACK;

    if (allocated_stack > 0)
        stack_slots = ((__u32)allocated_stack + 7) >> 3;
    captured_slots = stack_slots;
    if (captured_slots > RAC_STATE_V2_MAX_STACK_SLOTS) {
        captured_slots = RAC_STATE_V2_MAX_STACK_SLOTS;
        out->stack_truncated = 1;
        *unsupported |= RAC_STATE_V2_UNSUPPORTED_STACK_TRUNCATED;
    }
    out->stack_slot_count = captured_slots;
    stack = BPF_CORE_READ(frame, stack);

#pragma unroll
    for (int i = 0; i < RAC_MAX_REGS; i++)
        rac_copy_reg_v2(&frame->regs[i], &out->regs[i], unsupported);

    for (int i = 0; i < RAC_STATE_V2_MAX_STACK_SLOTS; i++) {
        if ((__u32)i >= captured_slots)
            break;
        rac_copy_stack_slot_v2(stack, i, &out->stack_slots[i], unsupported);
        if (out->stack_slots[i].initialized)
            nonzero_slots++;
    }
    out->stack_nonzero_slot_count = nonzero_slots;
}

static __always_inline void rac_init_state_v2(struct rac_state_v2 *out)
{
    out->schema_version = RAC_STATE_V2_SCHEMA_VERSION;
    out->valid = 0;
    out->unsupported_mask = 0;
    out->insn_idx = 0;
    out->first_insn_idx = -1;
    out->last_insn_idx = -1;
    out->curframe = 0;
    out->dfs_depth = 0;
    out->branches = 0;
    out->acquired_refs = 0;
    out->active_locks = 0;
    out->active_preempt_locks = 0;
    out->active_irq_id = 0;
    out->active_lock_id = 0;
    out->active_rcu_lock = 0;
    out->speculative = 0;
    out->in_sleepable = 0;
    out->callback_unroll_depth = 0;
    out->may_goto_depth = 0;
    out->parent_present = 0;
    out->equal_state_present = 0;
    out->refs_present = 0;
    out->frame_count = 0;
    out->captured_frame_count = 0;
    out->max_supported_frames = RAC_STATE_V2_MAX_FRAMES;
    out->max_supported_stack_slots = RAC_STATE_V2_MAX_STACK_SLOTS;
    rac_copy_frame_v2(NULL, &out->frame0, &out->unsupported_mask);
}

static __always_inline void rac_capture_state_v2(const struct bpf_verifier_state *state,
                                                 struct rac_state_v2 *out)
{
    struct bpf_func_state *frame0 = NULL;
    struct bpf_verifier_state *parent = NULL;
    struct bpf_verifier_state *equal_state = NULL;
    struct bpf_reference_state *refs = NULL;
    __u32 curframe = 0;
    __u32 acquired_refs = 0;
    __u32 active_locks = 0;
    __u32 active_preempt_locks = 0;
    __u32 active_irq_id = 0;
    __u32 active_lock_id = 0;
    __u32 callback_unroll_depth = 0;
    __u32 may_goto_depth = 0;

    rac_init_state_v2(out);
    if (!state)
        return;

    out->valid = 1;
    out->insn_idx = BPF_CORE_READ(state, insn_idx);
    out->first_insn_idx = BPF_CORE_READ(state, first_insn_idx);
    out->last_insn_idx = BPF_CORE_READ(state, last_insn_idx);
    curframe = BPF_CORE_READ(state, curframe);
    out->curframe = curframe;
    out->dfs_depth = BPF_CORE_READ(state, dfs_depth);
    out->branches = BPF_CORE_READ(state, branches);
    acquired_refs = BPF_CORE_READ(state, acquired_refs);
    active_locks = BPF_CORE_READ(state, active_locks);
    active_preempt_locks = BPF_CORE_READ(state, active_preempt_locks);
    active_irq_id = BPF_CORE_READ(state, active_irq_id);
    active_lock_id = BPF_CORE_READ(state, active_lock_id);
    out->acquired_refs = acquired_refs;
    out->active_locks = active_locks;
    out->active_preempt_locks = active_preempt_locks;
    out->active_irq_id = active_irq_id;
    out->active_lock_id = active_lock_id;
    out->active_rcu_lock = BPF_CORE_READ(state, active_rcu_lock) ? 1 : 0;
    out->speculative = BPF_CORE_READ(state, speculative) ? 1 : 0;
    out->in_sleepable = BPF_CORE_READ(state, in_sleepable) ? 1 : 0;
    callback_unroll_depth = BPF_CORE_READ(state, callback_unroll_depth);
    may_goto_depth = BPF_CORE_READ(state, may_goto_depth);
    out->callback_unroll_depth = callback_unroll_depth;
    out->may_goto_depth = may_goto_depth;
    bpf_core_read(&parent, sizeof(parent), &state->parent);
    bpf_core_read(&equal_state, sizeof(equal_state), &state->equal_state);
    bpf_core_read(&refs, sizeof(refs), &state->refs);
    out->parent_present = parent ? 1 : 0;
    out->equal_state_present = equal_state ? 1 : 0;
    out->refs_present = refs ? 1 : 0;
    out->frame_count = curframe + 1;
    out->captured_frame_count = 1;

    if (curframe != 0)
        out->unsupported_mask |= RAC_STATE_V2_UNSUPPORTED_MULTI_FRAME;
    if (acquired_refs)
        out->unsupported_mask |= RAC_STATE_V2_UNSUPPORTED_REFS;
    if (active_locks || active_preempt_locks || active_irq_id || active_lock_id)
        out->unsupported_mask |= RAC_STATE_V2_UNSUPPORTED_LOCKS;
    if (out->active_rcu_lock || out->in_sleepable)
        out->unsupported_mask |= RAC_STATE_V2_UNSUPPORTED_SLEEPABLE_OR_RCU;
    if (callback_unroll_depth)
        out->unsupported_mask |= RAC_STATE_V2_UNSUPPORTED_CALLBACK;

    bpf_core_read(&frame0, sizeof(frame0), &state->frame[0]);
    rac_copy_frame_v2(frame0, &out->frame0, &out->unsupported_mask);
}

#endif
