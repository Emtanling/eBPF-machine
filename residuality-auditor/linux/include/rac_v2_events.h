/* SPDX-License-Identifier: MIT */
#ifndef RAC_V2_EVENTS_H
#define RAC_V2_EVENTS_H

#include "rac_events.h"

#define RAC_V2_PROGRAM_TAG_LEN 8

struct rac_v2_config {
    __u32 target_tgid; /* 0 = match by comm only */
    char target_comm[RAC_COMM_LEN];
};

/* One active is_state_visited() invocation per target task is admissible. */
struct rac_v2_visit_context {
    /* Monotonic non-pointer token; never expose a verifier_env address. */
    __u64 invocation_token;
    __u64 visit_sequence;
    __u64 equality_sequence;
    __s32 visit_insn;
    __s32 exact_level;
    __u32 equality_success_count;
    __u32 nested_or_ambiguous;
    /* aux->load_time is assigned before bpf_check() and is a safe scalar. */
    __u64 program_load_time;
    __u8 program_tag[RAC_V2_PROGRAM_TAG_LEN];
    char program_name[RAC_COMM_LEN];
    struct rac_snapshot old;
    struct rac_snapshot current;
};

struct rac_v2_prune_event {
    __u64 sequence;
    __u64 equality_sequence;
    __u64 visit_sequence;
    __u64 invocation_token;
    __u64 program_load_time;
    __u32 states_equal_success_count;
    __s32 visit_insn;
    __s32 exact_level;
    char comm[RAC_COMM_LEN];
    __u8 program_tag[RAC_V2_PROGRAM_TAG_LEN];
    char program_name[RAC_COMM_LEN];
    struct rac_snapshot old;
    struct rac_snapshot current;
};

struct rac_v2_stats {
    __u64 events_emitted;
    __u64 ringbuf_lost_events;
    __u64 unmatched_equal_events;
    __u64 ambiguous_visit_events;
    __u64 dangling_visit_contexts;
    __u64 tracer_map_update_failures;
};

#endif
