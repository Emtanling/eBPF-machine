// SPDX-License-Identifier: MIT
#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "rac_witness.skel.h"

#define AUDIT_SLOT 0

static int run_prog(int fd, unsigned char byte, __u32 *retval)
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
    rc = bpf_prog_test_run_opts(fd, &opts);
    if (rc)
        return -errno;
    *retval = opts.retval;
    return 0;
}

static unsigned int key_mask(int map_fd)
{
    __u32 key, next;
    unsigned int mask = 0;
    int rc = bpf_map_get_next_key(map_fd, NULL, &next);
    while (!rc) {
        key = next;
        if (key < 32)
            mask |= 1U << key;
        rc = bpf_map_get_next_key(map_fd, &key, &next);
    }
    return mask;
}

static int audit_mask(int map_fd, unsigned int *mask)
{
    __u32 key = AUDIT_SLOT, value = 0;

    if (bpf_map_lookup_elem(map_fd, &key, &value))
        return -errno;
    *mask = value;
    return 0;
}

static void print_state(FILE *out, unsigned int mask)
{
    int first = 1;
    fputc('[', out);
    if (mask & (1U << 0)) { fprintf(out, "\"S\""); first = 0; }
    if (mask & (1U << 1)) { fprintf(out, "%s\"A\"", first ? "" : ","); first = 0; }
    if (mask & (1U << 2)) { fprintf(out, "%s\"B\"", first ? "" : ","); }
    fputc(']', out);
}

static void print_tag(FILE *out, const unsigned char tag[BPF_TAG_SIZE])
{
    for (int i = 0; i < BPF_TAG_SIZE; i++)
        fprintf(out, "%02x", tag[i]);
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "runtime.json";
    const char *pin_path = getenv("RAC_PIN_PATH");
    struct rac_witness_bpf *skel = NULL;
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info), retval = 0;
    struct utsname uts = {};
    FILE *out = NULL;
    int prog_fd, g0_fd, audit_fd, err = 1;
    unsigned int selected_states[2] = {};
    unsigned int final_states[2] = {};
    unsigned int observations[2] = {};

    prctl(PR_SET_NAME, "rac-witness", 0, 0, 0);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    skel = rac_witness_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "load witness object failed\n");
        return 1;
    }

    prog_fd = bpf_program__fd(skel->progs.rac_single);
    g0_fd = bpf_map__fd(skel->maps.g0);
    audit_fd = bpf_map__fd(skel->maps.audit);
    if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len)) {
        fprintf(stderr, "program info: %s\n", strerror(errno));
        goto out;
    }

    /* Keep the exact verified program alive after skeleton destruction so
     * bpftool can dump the kernel-linked xlated instruction stream that
     * corresponds to the captured verifier events.
     */
    if (pin_path && *pin_path) {
        if (unlink(pin_path) && errno != ENOENT) {
            fprintf(stderr, "remove stale pin %s: %s\n",
                pin_path, strerror(errno));
            goto out;
        }
        if (bpf_obj_pin(prog_fd, pin_path)) {
            fprintf(stderr, "pin program at %s: %s\n",
                pin_path, strerror(errno));
            goto out;
        }
    }

    for (unsigned int a = 0; a < 2; a++) {
        if (run_prog(prog_fd, (unsigned char)a, &retval)) {
            fprintf(stderr, "single-artifact test run %u failed\n", a);
            goto out;
        }
        if (audit_mask(audit_fd, &selected_states[a])) {
            fprintf(stderr, "read audit state %u failed: %s\n", a, strerror(errno));
            goto out;
        }
        final_states[a] = key_mask(g0_fd);
        observations[a] = retval ? 1 : 0;
    }

    out = fopen(path, "w");
    if (!out) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        goto out;
    }
    uname(&uts);
    fprintf(out, "{\n  \"schema\": \"rac-linux-runtime-v1\",\n");
    fprintf(out, "  \"kernel_release\": \"%s\",\n  \"program_tag\": \"", uts.release);
    print_tag(out, info.tag);
    fprintf(out, "\",\n  \"program_id\": %u,\n", info.id);
    if (pin_path && *pin_path)
        fprintf(out, "  \"program_pin\": \"%s\",\n", pin_path);
    else
        fprintf(out, "  \"program_pin\": null,\n");
    fprintf(out, "  \"runs\": [\n");
    for (unsigned int a = 0; a < 2; a++) {
        fprintf(out, "    {\n      \"case\": \"a=%u\",\n      \"selected_state\": ", a);
        print_state(out, selected_states[a]);
        fprintf(out, ",\n      \"final_state\": ");
        print_state(out, final_states[a]);
        fprintf(out,
            ",\n      \"context\": {\"map_type\": \"BPF_MAP_TYPE_HASH\","
            "\"max_entries\": 2, \"map_flags\": 0, \"serialized\": true,"
            "\"single_artifact\": true, \"prefix_program\": \"rac_single\","
            "\"suffix_program\": \"rac_single\"},\n"
            "      \"suffix\": {\"program\": \"rac_single\","
            " \"operation\": \"shared post-join insert of fresh key B\"},\n"
            "      \"observation\": {\"success\": %s, \"retval\": %u}\n    }%s\n",
            observations[a] ? "true" : "false", observations[a], a == 0 ? "," : "");
    }
    fprintf(out, "  ]\n}\n");
    fclose(out);
    out = NULL;
    err = 0;
out:
    if (out)
        fclose(out);
    rac_witness_bpf__destroy(skel);
    return err;
}
