// SPDX-License-Identifier: MIT
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../include/rac_v2_events.h"
#include "rac_v2_tracer_fentry.skel.h"

static volatile sig_atomic_t stop;
static unsigned long long events_seen;
static unsigned long long collector_parse_errors;
static unsigned long long sequence_gaps;
static unsigned long long next_sequence = 1;
static char session_id[96];
static unsigned long long capture_started_ns;
static unsigned long long capture_attached_ns;

static void print_hex_tag(FILE *out, const unsigned char tag[RAC_V2_PROGRAM_TAG_LEN])
{
    for (int i = 0; i < RAC_V2_PROGRAM_TAG_LEN; i++)
        fprintf(out, "%02x", tag[i]);
}

static unsigned long long monotonic_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
}

static void init_session_id(void)
{
    capture_started_ns = monotonic_ns();
    snprintf(session_id, sizeof(session_id), "rac-v2-fentry-%ld-%llu",
             (long)getpid(), capture_started_ns);
}

static void on_signal(int signo)
{
    (void)signo;
    stop = 1;
}

#include "state_collector.c"

static int drain_ring_buffer(struct ring_buffer *ring_buffer)
{
    int empty_polls = 0;

    while (empty_polls < 3) {
        int rc = ring_buffer__poll(ring_buffer, 0);

        if (rc == -EINTR)
            continue;
        if (rc < 0)
            return rc;
        if (rc == 0)
            empty_polls++;
        else
            empty_polls = 0;
    }
    return 0;
}

static unsigned long long count_map_entries(int map_fd)
{
    __u64 key = 0;
    __u64 next_key = 0;
    __u64 *previous = NULL;
    unsigned long long count = 0;

    while (!bpf_map_get_next_key(map_fd, previous, &next_key)) {
        count++;
        key = next_key;
        previous = &key;
        if (count > 1024)
            break;
    }
    return count;
}

static int on_event(void *ctx, void *data, size_t size)
{
    const struct rac_v2_prune_event *event = data;
    FILE *out = ctx;

    if (size != sizeof(*event)) {
        collector_parse_errors++;
        return 0;
    }
    events_seen++;
    if (event->sequence != next_sequence) {
        sequence_gaps++;
        next_sequence = event->sequence + 1;
    } else {
        next_sequence++;
    }
    fprintf(out,
        "{\"event\":\"prune_hit\",\"source\":\"fentry/fexit invocation-scoped states_equal/is_state_visited\","
        "\"session_id\":\"%s\",\"sequence\":%llu,"
        "\"equality_sequence\":%llu,\"visit_sequence\":%llu,"
        "\"invocation_token\":%llu,\"program_load_time\":%llu,"
        "\"states_equal_success_count\":%u,\"program_tag\":\"",
        session_id, (unsigned long long)event->sequence,
        (unsigned long long)event->equality_sequence,
        (unsigned long long)event->visit_sequence,
        (unsigned long long)event->invocation_token,
        (unsigned long long)event->program_load_time,
        event->states_equal_success_count);
    print_hex_tag(out, event->program_tag);
    fprintf(out, "\",\"program_name\":\"%.*s\",", RAC_COMM_LEN, event->program_name);
    fprintf(out, "\"visit_insn\":%d,\"exact_level\":%d,\"old\":",
            event->visit_insn, event->exact_level);
    print_snapshot(out, &event->old);
    fputs(",\"current\":", out);
    print_snapshot(out, &event->current);
    fputs("}\n", out);
    fflush(out);
    return 0;
}

static void usage(const char *program)
{
    fprintf(stderr, "Usage: %s [-o events.jsonl] [-c target-comm] [-p tgid] [-d seconds]\n", program);
}

int main(int argc, char **argv)
{
    const char *output_path = "events.jsonl";
    const char *target_comm = "rac-v2-witness";
    unsigned int target_tgid = 0;
    int duration = 20;
    int opt;
    int err = 1;
    FILE *output = NULL;
    struct rac_v2_tracer_fentry_bpf *skel = NULL;
    struct ring_buffer *ring_buffer = NULL;
    struct rac_v2_config config = {};
    struct rac_v2_stats stats = {};
    struct utsname uts = {};
    unsigned long long active_visit_contexts = 0;
    __u32 key = 0;

    while ((opt = getopt(argc, argv, "o:c:p:d:h")) != -1) {
        switch (opt) {
        case 'o': output_path = optarg; break;
        case 'c': target_comm = optarg; break;
        case 'p': target_tgid = (unsigned int)strtoul(optarg, NULL, 10); break;
        case 'd': duration = atoi(optarg); break;
        default: usage(argv[0]); return opt == 'h' ? 0 : 2;
        }
    }
    init_session_id();
    output = fopen(output_path, "w");
    if (!output) {
        fprintf(stderr, "open %s: %s\n", output_path, strerror(errno));
        return 1;
    }
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = rac_v2_tracer_fentry_bpf__open();
    if (!skel) {
        fprintf(stderr, "open V2 tracer skeleton failed\n");
        goto out;
    }
    if (rac_v2_tracer_fentry_bpf__load(skel)) {
        fprintf(stderr, "load V2 fentry tracer failed\n");
        goto out;
    }
    config.target_tgid = target_tgid;
    snprintf(config.target_comm, sizeof(config.target_comm), "%s", target_comm);
    if (bpf_map_update_elem(bpf_map__fd(skel->maps.rac_v2_config_map), &key, &config, BPF_ANY)) {
        fprintf(stderr, "configure V2 tracer: %s\n", strerror(errno));
        goto out;
    }
    if (rac_v2_tracer_fentry_bpf__attach(skel)) {
        fprintf(stderr, "attach V2 fentry tracer failed; required BTF functions are unavailable\n");
        goto out;
    }
    ring_buffer = ring_buffer__new(bpf_map__fd(skel->maps.rac_v2_events), on_event, output, NULL);
    if (!ring_buffer) {
        fprintf(stderr, "ring_buffer__new failed\n");
        goto out;
    }
    capture_attached_ns = monotonic_ns();
    uname(&uts);
    fprintf(output,
            "{\"event\":\"metadata\",\"schema\":\"rac-stock-r-v2-event-stream-v1\","
            "\"session_id\":\"%s\",\"capture_started_ns\":%llu,\"capture_attached_ns\":%llu,"
            "\"backend\":\"fentry+fexit\",\"kernel_release\":\"%s\","
            "\"target_comm\":\"%s\",\"target_tgid\":%u}\n",
            session_id, capture_started_ns, capture_attached_ns, uts.release, target_comm, target_tgid);
    fflush(output);

    for (int elapsed = 0; !stop && (duration <= 0 || elapsed < duration * 5); elapsed++) {
        int rc = ring_buffer__poll(ring_buffer, 200);

        if (rc == -EINTR)
            continue;
        if (rc < 0) {
            fprintf(stderr, "ring buffer poll: %d\n", rc);
            goto out;
        }
    }
    if (ring_buffer) {
        int drain_rc = drain_ring_buffer(ring_buffer);

        if (drain_rc < 0) {
            fprintf(stderr, "ring buffer drain: %d\n", drain_rc);
            collector_parse_errors++;
            goto out;
        }
    }
    err = 0;
out:
    if (skel) {
        int stats_fd = bpf_map__fd(skel->maps.rac_v2_stats_map);
        int active_fd = bpf_map__fd(skel->maps.rac_v2_active_visits);

        if (stats_fd >= 0 && bpf_map_lookup_elem(stats_fd, &key, &stats))
            collector_parse_errors++;
        if (active_fd >= 0)
            active_visit_contexts = count_map_entries(active_fd);
    }
    if (output) {
        unsigned long long ended_ns = monotonic_ns();

        fprintf(output,
                "{\"event\":\"capture_complete\",\"schema\":\"rac-stock-r-v2-session-v1\","
                "\"session_id\":\"%s\",\"capture_started_ns\":%llu,"
                "\"capture_ended_ns\":%llu,\"completed\":%s,"
                "\"events_seen\":%llu,\"tracer_events_emitted\":%llu,"
                "\"ringbuf_lost_events\":%llu,\"collector_parse_errors\":%llu,"
                "\"unmatched_equal_events\":%llu,\"ambiguous_visit_events\":%llu,"
                "\"dangling_visit_contexts\":%llu,\"tracer_map_update_failures\":%llu,"
                "\"active_visit_contexts\":%llu,\"sequence_gaps\":%llu}\n",
                session_id, capture_started_ns, ended_ns, err == 0 ? "true" : "false",
                events_seen, (unsigned long long)stats.events_emitted,
                (unsigned long long)stats.ringbuf_lost_events, collector_parse_errors,
                (unsigned long long)stats.unmatched_equal_events,
                (unsigned long long)stats.ambiguous_visit_events,
                (unsigned long long)stats.dangling_visit_contexts,
                (unsigned long long)stats.tracer_map_update_failures,
                active_visit_contexts, sequence_gaps);
        fflush(output);
        fclose(output);
    }
    ring_buffer__free(ring_buffer);
    rac_v2_tracer_fentry_bpf__destroy(skel);
    return err;
}
