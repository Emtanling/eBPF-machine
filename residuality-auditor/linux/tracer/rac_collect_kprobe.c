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

#include "../include/rac_events.h"
#include "rac_tracer_kprobe.skel.h"

static volatile sig_atomic_t stop;
static FILE *output;

static unsigned long long events_seen;
static char session_id[96];
static unsigned long long capture_started_ns;

static unsigned long long monotonic_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
}

static void init_session_id(const char *backend)
{
    capture_started_ns = monotonic_ns();
    snprintf(session_id, sizeof(session_id), "rac-%s-%ld-%llu", backend,
             (long)getpid(), capture_started_ns);
}

static unsigned long long read_lost_events(int map_fd)
{
    __u32 key = 0;
    __u64 lost = 0;

    if (map_fd >= 0 && !bpf_map_lookup_elem(map_fd, &key, &lost))
        return (unsigned long long)lost;
    return 0;
}


static void on_signal(int signo)
{
    (void)signo;
    stop = 1;
}

#include "state_collector.c"

static int on_event(void *ctx, void *data, size_t size)
{
    const struct rac_prune_event *e = data;
    FILE *out = ctx;

    if (size < sizeof(*e))
        return 0;
    events_seen++;
    fprintf(out,
        "{\"event\":\"prune_hit\",\"source\":\"kprobe+ kretprobe states_equal/is_state_visited\","
        "\"session_id\":\"%s\",\"sequence\":%llu,"
        "\"observed_at_ns\":%llu,\"collector_observed_at_ns\":%llu,"
        "\"states_equal_success\":true,\"is_state_visited_prune\":true,"
        "\"cell_id\":%llu,\"tgid\":%u,\"pid\":%u,"
        "\"comm\":\"%.*s\",\"program_name\":\"%.*s\","
        "\"visit_insn\":%d,\"exact_level\":%d,\"old\":",
        session_id, (unsigned long long)e->sequence,
        (unsigned long long)e->observed_at_ns, monotonic_ns(),
        (unsigned long long)e->sequence, e->tgid, e->pid,
        RAC_COMM_LEN, e->comm, RAC_COMM_LEN, e->program_name,
        e->visit_insn, e->exact_level);
    print_snapshot(out, &e->old);
    fprintf(out, ",\"current\":");
    print_snapshot(out, &e->current);
    fprintf(out, "}\n");
    fflush(out);
    return 0;
}
static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-o events.jsonl] [-c target-comm] [-p tgid] [-d seconds]\n", prog);
}

int main(int argc, char **argv)
{
    const char *output_path = "events.jsonl";
    const char *target_comm = "rac-witness";
    unsigned int target_tgid = 0;
    int duration = 20;
    int opt, err = 1;
    struct rac_tracer_kprobe_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    struct rac_config cfg = {};
    struct utsname uts = {};
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
    init_session_id("kprobe");
    output = fopen(output_path, "w");
    if (!output) {
        fprintf(stderr, "open %s: %s\n", output_path, strerror(errno));
        return 1;
    }
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = rac_tracer_kprobe_bpf__open();
    if (!skel) {
        fprintf(stderr, "open tracer skeleton failed\n");
        goto out;
    }
    if (rac_tracer_kprobe_bpf__load(skel)) {
        fprintf(stderr, "load kprobe tracer failed\n");
        goto out;
    }
    cfg.target_tgid = target_tgid;
    snprintf(cfg.target_comm, sizeof(cfg.target_comm), "%s", target_comm);
    if (bpf_map_update_elem(bpf_map__fd(skel->maps.rac_config_map), &key, &cfg, BPF_ANY)) {
        fprintf(stderr, "configure tracer: %s\n", strerror(errno));
        goto out;
    }
    if (rac_tracer_kprobe_bpf__attach(skel)) {
        fprintf(stderr, "attach kprobe tracer failed; check CONFIG_KPROBES and symbol visibility\n");
        goto out;
    }
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), on_event, output, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new failed\n");
        goto out;
    }
    uname(&uts);
    fprintf(output,
            "{\"event\":\"metadata\",\"schema\":\"rac-linux-prune-v1\","
            "\"session_id\":\"%s\",\"capture_started_ns\":%llu,"
            "\"backend\":\"kprobe\",\"kernel_release\":\"%s\","
            "\"target_comm\":\"%s\",\"target_tgid\":%u}\n",
            session_id, capture_started_ns, uts.release, target_comm, target_tgid);
    fflush(output);

    for (int elapsed = 0; !stop && (duration <= 0 || elapsed < duration * 5); elapsed++) {
        int rc = ring_buffer__poll(rb, 200);
        if (rc == -EINTR)
            continue;
        if (rc < 0) {
            fprintf(stderr, "ring buffer poll: %d\n", rc);
            goto out;
        }
    }
    err = 0;
out:
    if (output) {
        int lost_fd = -1;
        unsigned long long capture_ended_ns = monotonic_ns();
        if (skel)
            lost_fd = bpf_map__fd(skel->maps.lost_events_map);
        fprintf(output,
                "{\"event\":\"capture_complete\",\"schema\":\"rac-linux-prune-session-v1\","
                "\"session_id\":\"%s\",\"capture_started_ns\":%llu,"
                "\"capture_ended_ns\":%llu,\"ringbuf_lost_events\":%llu,"
                "\"collector_parse_errors\":0,\"events_seen\":%llu,"
                "\"completed\":%s}\n",
                session_id, capture_started_ns, capture_ended_ns,
                read_lost_events(lost_fd), events_seen, err == 0 ? "true" : "false");
        fflush(output);
    }
    ring_buffer__free(rb);
    rac_tracer_kprobe_bpf__destroy(skel);
    if (output)
        fclose(output);
    return err;
}
