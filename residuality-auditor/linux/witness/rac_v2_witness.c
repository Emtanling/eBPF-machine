// SPDX-License-Identifier: MIT
#include <errno.h>
#include <getopt.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "rac_v2_witness.h"
#include "rac_v2_witness.skel.h"

#define RAC_V2_AUDIT_SLOT 0

struct trial_record {
    unsigned int trial_id;
    unsigned int case_value;
    int test_run_rc;
    int test_run_errno;
    __u32 retval;
    __u32 map_value_after;
    int map_read_rc;
    struct rac_v2_trace trace;
    int trace_read_rc;
};

static unsigned long long monotonic_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
}

static int run_prog(int fd, unsigned char byte, __u32 *retval, int *saved_errno)
{
    unsigned char input[64] = {};
    unsigned char out[64] = {};
    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in = input,
        .data_size_in = sizeof(input),
        .data_out = out,
        .data_size_out = sizeof(out),
        .repeat = 1,
    );
    int rc;

    input[0] = byte;
    errno = 0;
    rc = bpf_prog_test_run_opts(fd, &opts);
    *saved_errno = rc ? errno : 0;
    if (!rc)
        *retval = opts.retval;
    return rc;
}

static int map_value(int map_fd, __u32 *value)
{
    __u32 key = 0;

    if (bpf_map_lookup_elem(map_fd, &key, value))
        return -errno;
    return 0;
}

static int trace_value(int map_fd, struct rac_v2_trace *trace)
{
    __u32 key = RAC_V2_AUDIT_SLOT;

    if (bpf_map_lookup_elem(map_fd, &key, trace))
        return -errno;
    return 0;
}

static void print_json_string(FILE *out, const char *value)
{
    const unsigned char *cursor = (const unsigned char *)(value ? value : "");

    fputc('"', out);
    for (; *cursor; cursor++) {
        if (*cursor == '"' || *cursor == '\\')
            fprintf(out, "\\%c", *cursor);
        else if (*cursor < 0x20)
            fprintf(out, "\\u%04x", *cursor);
        else
            fputc(*cursor, out);
    }
    fputc('"', out);
}

static void print_tag(FILE *out, const unsigned char tag[BPF_TAG_SIZE])
{
    for (int i = 0; i < BPF_TAG_SIZE; i++)
        fprintf(out, "%02x", tag[i]);
}

static void print_identity(FILE *out, const struct utsname *uts,
                           const struct bpf_prog_info *info,
                           const char *object_sha, const char *btf_sha,
                           const char *xlated_sha)
{
    fputs("{\"program_name\":\"rac_v2_single\",\"program_id\":", out);
    fprintf(out, "%u,\"program_tag\":\"", info->id);
    print_tag(out, info->tag);
    fprintf(out, "\",\"program_load_time\":%llu", (unsigned long long)info->load_time);
    fputs(",\"object_sha256\":", out);
    print_json_string(out, object_sha);
    fputs(",\"xlated_sha256\":", out);
    print_json_string(out, xlated_sha);
    fputs(",\"kernel_release\":", out);
    print_json_string(out, uts->release);
    fputs(",\"btf_sha256\":", out);
    print_json_string(out, btf_sha);
    fputc('}', out);
}

static void print_trial(FILE *out, const struct trial_record *record,
                        const struct utsname *uts, const struct bpf_prog_info *info,
                        const char *object_sha, const char *btf_sha)
{
    fprintf(out,
        "{\"trial_id\":%u,\"case\":%u,\"test_run_rc\":%d,"
        "\"test_run_errno\":%d,\"retval\":%u,\"map_value_after\":%u,"
        "\"map_read_rc\":%d,\"trace_read_rc\":%d,\"program_identity\":",
        record->trial_id, record->case_value, record->test_run_rc,
        record->test_run_errno, record->retval, record->map_value_after,
        record->map_read_rc, record->trace_read_rc);
    print_identity(out, uts, info, object_sha, btf_sha, "");
    fprintf(out,
        ",\"trace\":{\"branch\":%u,\"reset_rc\":%d,\"branch_rc\":%d,"
        "\"lookup_missing\":%s,\"selected_value\":%u,"
        "\"observed_value\":%u,\"trace_errors\":%u}}",
        record->trace.branch, record->trace.reset_rc, record->trace.branch_rc,
        record->trace.lookup_missing ? "true" : "false",
        record->trace.selected_value, record->trace.observed_value,
        record->trace.trace_errors);
}

static void usage(const char *program)
{
    fprintf(stderr, "Usage: %s [-o runtime.json] [-n even-trial-count]\n", program);
}

int main(int argc, char **argv)
{
    const char *output_path = "runtime.json";
    const char *pin_path = getenv("RAC_V2_PIN_PATH");
    const char *object_sha = getenv("RAC_V2_OBJECT_SHA256");
    const char *btf_sha = getenv("RAC_V2_BTF_SHA256");
    struct rac_v2_witness_bpf *skel = NULL;
    struct bpf_prog_info info = {};
    struct utsname uts = {};
    struct trial_record *trials = NULL;
    FILE *output = NULL;
    __u32 info_len = sizeof(info);
    unsigned int trial_count = 4;
    unsigned long long started_ns;
    unsigned long long ended_ns;
    unsigned long long load_started_ns = 0;
    unsigned long long load_completed_ns = 0;
    int prog_fd, state_fd, audit_fd;
    int opt;
    int err = 1;

    while ((opt = getopt(argc, argv, "o:n:h")) != -1) {
        switch (opt) {
        case 'o': output_path = optarg; break;
        case 'n':
            trial_count = (unsigned int)strtoul(optarg, NULL, 10);
            break;
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 2;
        }
    }
    if (trial_count < 4 || trial_count % 2) {
        fprintf(stderr, "trial count must be even and at least 4\n");
        return 2;
    }
    if (!object_sha || strlen(object_sha) != 64 || !btf_sha || strlen(btf_sha) != 64) {
        fprintf(stderr, "RAC_V2_OBJECT_SHA256 and RAC_V2_BTF_SHA256 must be set\n");
        return 2;
    }

    prctl(PR_SET_NAME, "rac-v2-witness", 0, 0, 0);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    load_started_ns = monotonic_ns();
    skel = rac_v2_witness_bpf__open_and_load();
    load_completed_ns = monotonic_ns();
    if (!skel) {
        fprintf(stderr, "load V2 witness object failed\n");
        goto out;
    }
    prog_fd = bpf_program__fd(skel->progs.rac_v2_single);
    state_fd = bpf_map__fd(skel->maps.g0);
    audit_fd = bpf_map__fd(skel->maps.audit);
    if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len)) {
        fprintf(stderr, "program info: %s\n", strerror(errno));
        goto out;
    }
    if (pin_path && *pin_path) {
        if (bpf_obj_pin(prog_fd, pin_path)) {
            fprintf(stderr, "pin program at %s: %s\n", pin_path, strerror(errno));
            goto out;
        }
    }

    trials = calloc(trial_count, sizeof(*trials));
    if (!trials) {
        fprintf(stderr, "allocate trials: %s\n", strerror(errno));
        goto out;
    }
    uname(&uts);
    started_ns = monotonic_ns();
    err = 0;
    for (unsigned int index = 0; index < trial_count; index++) {
        struct trial_record *record = &trials[index];

        record->trial_id = index;
        record->case_value = index % 2;
        record->map_value_after = UINT32_MAX;
        record->test_run_rc = run_prog(prog_fd, (unsigned char)record->case_value,
                                       &record->retval, &record->test_run_errno);
        if (record->test_run_rc)
            err = 1;
        record->map_read_rc = map_value(state_fd, &record->map_value_after);
        if (record->map_read_rc)
            err = 1;
        record->trace_read_rc = trace_value(audit_fd, &record->trace);
        if (record->trace_read_rc)
            err = 1;
    }
    ended_ns = monotonic_ns();
    output = fopen(output_path, "w");
    if (!output) {
        fprintf(stderr, "open %s: %s\n", output_path, strerror(errno));
        err = 1;
        goto out;
    }
    fputs("{\n  \"schema\": \"rac-stock-r-v2-runtime-v1\",\n  \"program_load_started_ns\": ", output);
    fprintf(output,
            "%llu,\n  \"program_load_completed_ns\": %llu,\n  \"runtime_started_ns\": %llu,"
            "\n  \"runtime_ended_ns\": %llu,\n  \"identity\": ",
            load_started_ns, load_completed_ns, started_ns, ended_ns);
    print_identity(output, &uts, &info, object_sha, btf_sha, "");
    fputs(",\n  \"trials\": [\n", output);
    for (unsigned int index = 0; index < trial_count; index++) {
        fputs("    ", output);
        print_trial(output, &trials[index], &uts, &info, object_sha, btf_sha);
        fputs(index + 1 == trial_count ? "\n" : ",\n", output);
    }
    fputs("  ]\n}\n", output);
out:
    if (output)
        fclose(output);
    free(trials);
    rac_v2_witness_bpf__destroy(skel);
    return err;
}
