/* SPDX-License-Identifier: MIT */
#ifndef RAC_V2_WITNESS_H
#define RAC_V2_WITNESS_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define RAC_V2_TRACE_RESET_FAILED  (1U << 0)
#define RAC_V2_TRACE_BRANCH_FAILED (1U << 1)
#define RAC_V2_TRACE_LOOKUP_MISSING (1U << 2)

/* The same fixed-layout value is read by the BPF program and its user runner. */
struct rac_v2_trace {
    __u32 branch;
    __s32 reset_rc;
    __s32 branch_rc;
    __u32 lookup_missing;
    __u32 selected_value;
    __u32 observed_value;
    __u32 trace_errors;
};

#endif
