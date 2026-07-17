// SPDX-License-Identifier: MIT
/* Shared JSON printers for RAC verifier-state evidence. */

static void print_history_entries(FILE *out, const struct rac_snapshot *s)
{
    __u32 count = s->history_captured_count;

    if (count > RAC_MAX_HISTORY)
        count = RAC_MAX_HISTORY;
    fputc('[', out);
    for (__u32 i = 0; i < count; i++) {
        const struct rac_history_entry *h = &s->history_entries[i];

        fprintf(out,
                "%s{\"insn_idx\":%d,\"idx\":%d,\"prev_insn_idx\":%d,"
                "\"prev_idx\":%d,\"flags\":%u,\"linked_regs\":%llu}",
                i ? "," : "", h->insn_idx, h->insn_idx,
                h->prev_insn_idx, h->prev_insn_idx, h->flags,
                (unsigned long long)h->linked_regs);
    }
    fputc(']', out);
}

static void print_reg_v2(FILE *out, const struct rac_reg_v2 *r)
{
    fprintf(out,
            "{\"type\":%d,\"off\":%d,\"var_off\":{\"value\":%llu,\"mask\":%llu},"
            "\"smin_value\":%lld,\"smax_value\":%lld,"
            "\"umin_value\":%llu,\"umax_value\":%llu,"
            "\"s32_min_value\":%d,\"s32_max_value\":%d,"
            "\"u32_min_value\":%u,\"u32_max_value\":%u,"
            "\"id\":%u,\"ref_obj_id\":%u,\"frameno\":%u,"
            "\"subreg_def\":%d,\"live\":%u,\"precise\":%s,"
            "\"raw\":{\"raw1\":%llu,\"raw2\":%llu},"
            "\"parent_present\":%s}",
            r->type, r->off,
            (unsigned long long)r->var_off_value,
            (unsigned long long)r->var_off_mask,
            (long long)r->smin_value, (long long)r->smax_value,
            (unsigned long long)r->umin_value, (unsigned long long)r->umax_value,
            r->s32_min_value, r->s32_max_value,
            r->u32_min_value, r->u32_max_value,
            r->id, r->ref_obj_id, r->frameno,
            r->subreg_def, r->live, r->precise ? "true" : "false",
            (unsigned long long)r->raw1, (unsigned long long)r->raw2,
            r->parent_present ? "true" : "false");
}

static void print_stack_slot_v2(FILE *out, const struct rac_stack_slot_v2 *slot)
{
    fprintf(out, "{\"slot\":%u,\"initialized\":%s,\"slot_type\":[",
            slot->slot, slot->initialized ? "true" : "false");
    for (int i = 0; i < 8; i++)
        fprintf(out, "%s%u", i ? "," : "", slot->slot_type[i]);
    fprintf(out, "],\"spilled_ptr\":");
    print_reg_v2(out, &slot->spilled_ptr);
    fputc('}', out);
}

static void print_frame_v2(FILE *out, const struct rac_frame_v2 *f)
{
    __u32 stack_count = f->stack_slot_count;

    if (stack_count > RAC_STATE_V2_MAX_STACK_SLOTS)
        stack_count = RAC_STATE_V2_MAX_STACK_SLOTS;
    fprintf(out,
            "{\"present\":%s,\"frameno\":%u,\"callsite\":%d,"
            "\"subprogno\":%u,\"async_entry_cnt\":%u,"
            "\"callback_ret_range\":{\"min\":%d,\"max\":%d},"
            "\"in_callback_fn\":%s,\"in_async_callback_fn\":%s,"
            "\"in_exception_callback_fn\":%s,\"callback_depth\":%u,"
            "\"allocated_stack\":%d,\"stack_slot_count\":%u,"
            "\"stack_nonzero_slot_count\":%u,\"stack_truncated\":%s,"
            "\"regs\":[",
            f->present ? "true" : "false", f->frameno, f->callsite,
            f->subprogno, f->async_entry_cnt,
            f->callback_ret_min, f->callback_ret_max,
            f->in_callback_fn ? "true" : "false",
            f->in_async_callback_fn ? "true" : "false",
            f->in_exception_callback_fn ? "true" : "false",
            f->callback_depth, f->allocated_stack, stack_count,
            f->stack_nonzero_slot_count, f->stack_truncated ? "true" : "false");
    for (int i = 0; i < RAC_MAX_REGS; i++) {
        if (i)
            fputc(',', out);
        print_reg_v2(out, &f->regs[i]);
    }
    fprintf(out, "],\"stack_slots\":[");
    for (__u32 i = 0; i < stack_count; i++) {
        if (i)
            fputc(',', out);
        print_stack_slot_v2(out, &f->stack_slots[i]);
    }
    fprintf(out, "]}");
}

static void print_state_v2(FILE *out, const struct rac_state_v2 *s)
{
    fprintf(out,
            "{\"schema\":\"rac-verifier-state-v2\","
            "\"schema_version\":%u,\"valid\":%s,"
            "\"unsupported_mask\":%llu,\"unsupported_mask_hex\":\"0x%llx\","
            "\"insn_idx\":%d,\"first_insn_idx\":%d,\"last_insn_idx\":%d,"
            "\"curframe\":%u,\"dfs_depth\":%u,\"branches\":%u,"
            "\"acquired_refs\":%u,\"active_locks\":%u,"
            "\"active_preempt_locks\":%u,\"active_irq_id\":%u,"
            "\"active_lock_id\":%u,\"active_rcu_lock\":%s,"
            "\"speculative\":%s,\"in_sleepable\":%s,"
            "\"callback_unroll_depth\":%u,\"may_goto_depth\":%u,"
            "\"parent_present\":%s,\"equal_state_present\":%s,"
            "\"refs_present\":%s,\"frame_count\":%u,"
            "\"captured_frame_count\":%u,\"limits\":{"
            "\"max_supported_frames\":%u,\"max_supported_stack_slots\":%u},"
            "\"frames\":[",
            s->schema_version, s->valid ? "true" : "false",
            (unsigned long long)s->unsupported_mask,
            (unsigned long long)s->unsupported_mask,
            s->insn_idx, s->first_insn_idx, s->last_insn_idx,
            s->curframe, s->dfs_depth, s->branches,
            s->acquired_refs, s->active_locks, s->active_preempt_locks,
            s->active_irq_id, s->active_lock_id,
            s->active_rcu_lock ? "true" : "false",
            s->speculative ? "true" : "false",
            s->in_sleepable ? "true" : "false",
            s->callback_unroll_depth, s->may_goto_depth,
            s->parent_present ? "true" : "false",
            s->equal_state_present ? "true" : "false",
            s->refs_present ? "true" : "false",
            s->frame_count, s->captured_frame_count,
            s->max_supported_frames, s->max_supported_stack_slots);
    if (s->captured_frame_count > 0)
        print_frame_v2(out, &s->frame0);
    fprintf(out, "]}");
}

static void print_snapshot(FILE *out, const struct rac_snapshot *s)
{
    fprintf(out,
            "{\"insn_idx\":%d,\"first_insn_idx\":%d,\"last_insn_idx\":%d,"
            "\"curframe\":%u,\"dfs_depth\":%u,\"state_hash\":\"%016llx\","
            "\"history_hash\":\"%016llx\",\"history_count\":%u,"
            "\"history_total_count\":%u,\"history_captured_count\":%u,"
            "\"history_truncated\":%s,\"history_entries\":",
            s->insn_idx, s->first_insn_idx, s->last_insn_idx,
            s->curframe, s->dfs_depth,
            (unsigned long long)s->state_hash,
            (unsigned long long)s->history_hash,
            s->history_count, s->history_total_count,
            s->history_captured_count,
            s->history_truncated ? "true" : "false");
    print_history_entries(out, s);
    fprintf(out, ",\"state_v2\":");
    print_state_v2(out, &s->state_v2);
    fputc('}', out);
}
