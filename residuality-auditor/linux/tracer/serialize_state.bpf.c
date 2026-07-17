/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * The verifier-state V2 serializer is header-only on purpose: fexit and
 * kprobe tracer programs are compiled as separate BPF objects and need the
 * same inlined CO-RE field reads.  This file is kept as the named source
 * anchor for the v0.4.0 serializer described in ROADMAP.md.
 */
#include "verifier_state_v2.h"
