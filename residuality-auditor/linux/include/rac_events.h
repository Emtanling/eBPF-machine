/* SPDX-License-Identifier: MIT */
#ifndef RAC_EVENTS_H
#define RAC_EVENTS_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define RAC_COMM_LEN 16
#define RAC_MAX_HISTORY 40
#define RAC_MAX_REGS 11
#define RAC_STATE_V2_SCHEMA_VERSION 1
#define RAC_STATE_V2_MAX_FRAMES 1
#define RAC_STATE_V2_MAX_STACK_SLOTS 32

#define RAC_STATE_V2_UNSUPPORTED_MULTI_FRAME        (1ULL << 0)
#define RAC_STATE_V2_UNSUPPORTED_REFS               (1ULL << 1)
#define RAC_STATE_V2_UNSUPPORTED_LOCKS              (1ULL << 2)
#define RAC_STATE_V2_UNSUPPORTED_CALLBACK           (1ULL << 3)
#define RAC_STATE_V2_UNSUPPORTED_STACK_TRUNCATED    (1ULL << 4)
#define RAC_STATE_V2_UNSUPPORTED_DYNPTR             (1ULL << 5)
#define RAC_STATE_V2_UNSUPPORTED_ITERATOR           (1ULL << 6)
#define RAC_STATE_V2_UNSUPPORTED_SOCKET_REF         (1ULL << 7)
#define RAC_STATE_V2_UNSUPPORTED_PACKET_RANGE       (1ULL << 8)
#define RAC_STATE_V2_UNSUPPORTED_SLEEPABLE_OR_RCU   (1ULL << 9)
#define RAC_STATE_V2_UNSUPPORTED_REG_PARENT         (1ULL << 10)

struct rac_history_entry {
    __s32 insn_idx;
    __s32 prev_insn_idx;
    __u32 flags;
    __u32 reserved;
    __u64 linked_regs;
};

struct rac_reg_v2 {
    __s32 type;
    __s32 off;
    __u64 var_off_value;
    __u64 var_off_mask;
    __s64 smin_value;
    __s64 smax_value;
    __u64 umin_value;
    __u64 umax_value;
    __s32 s32_min_value;
    __s32 s32_max_value;
    __u32 u32_min_value;
    __u32 u32_max_value;
    __u32 id;
    __u32 ref_obj_id;
    __u32 frameno;
    __s32 subreg_def;
    __u32 live;
    __u32 precise;
    __u64 raw1;
    __u64 raw2;
    __u32 parent_present;
    __u32 reserved;
};

struct rac_stack_slot_v2 {
    __u32 slot;
    __u32 initialized;
    __u8 slot_type[8];
    __u32 reserved;
    struct rac_reg_v2 spilled_ptr;
};

struct rac_frame_v2 {
    __u32 present;
    __u32 frameno;
    __s32 callsite;
    __u32 subprogno;
    __u32 async_entry_cnt;
    __s32 callback_ret_min;
    __s32 callback_ret_max;
    __u32 in_callback_fn;
    __u32 in_async_callback_fn;
    __u32 in_exception_callback_fn;
    __u32 callback_depth;
    __s32 allocated_stack;
    __u32 stack_slot_count;
    __u32 stack_nonzero_slot_count;
    __u32 stack_truncated;
    __u32 reserved;
    struct rac_reg_v2 regs[RAC_MAX_REGS];
    struct rac_stack_slot_v2 stack_slots[RAC_STATE_V2_MAX_STACK_SLOTS];
};

struct rac_state_v2 {
    __u32 schema_version;
    __u32 valid;
    __u64 unsupported_mask;
    __s32 insn_idx;
    __s32 first_insn_idx;
    __s32 last_insn_idx;
    __u32 curframe;
    __u32 dfs_depth;
    __u32 branches;
    __u32 acquired_refs;
    __u32 active_locks;
    __u32 active_preempt_locks;
    __u32 active_irq_id;
    __u32 active_lock_id;
    __u32 active_rcu_lock;
    __u32 speculative;
    __u32 in_sleepable;
    __u32 callback_unroll_depth;
    __u32 may_goto_depth;
    __u32 parent_present;
    __u32 equal_state_present;
    __u32 refs_present;
    __u32 frame_count;
    __u32 captured_frame_count;
    __u32 max_supported_frames;
    __u32 max_supported_stack_slots;
    struct rac_frame_v2 frame0;
};

struct rac_config {
    __u32 target_tgid;       /* 0 = any tgid */
    char target_comm[RAC_COMM_LEN]; /* empty = any comm */
};

struct rac_snapshot {
    __s32 insn_idx;
    __s32 first_insn_idx;
    __s32 last_insn_idx;
    __u32 curframe;
    __u32 dfs_depth;
    __u64 state_hash;
    __u64 history_hash;
    __u32 history_count;
    __u32 history_total_count;
    __u32 history_captured_count;
    __u32 history_truncated;
    struct rac_history_entry history_entries[RAC_MAX_HISTORY];
    struct rac_state_v2 state_v2;
};

struct rac_pending {
    __u64 observed_at_ns;
    __s32 exact_level;
    __u32 reserved;
    char program_name[RAC_COMM_LEN];
    struct rac_snapshot old;
    struct rac_snapshot current;
};

struct rac_prune_event {
    __u64 sequence;
    __u64 observed_at_ns;
    __u64 pid_tgid;
    __u32 tgid;
    __u32 pid;
    __s32 visit_insn;
    __s32 exact_level;
    char comm[RAC_COMM_LEN];
    char program_name[RAC_COMM_LEN];
    struct rac_snapshot old;
    struct rac_snapshot current;
};

#endif
