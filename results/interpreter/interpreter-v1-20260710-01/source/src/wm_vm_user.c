#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "src/wm_common.h"

struct circuit_image {
    char name[64];
    uint32_t input_count;
    uint32_t gate_count;
    uint32_t wire_count;
    uint32_t output_count;
    struct wm_gate_desc gates[VM_MAX_GATES];
    uint32_t outputs[VM_MAX_OUTPUTS];
};

static int circuit_fd = -1;
static int wires_fd = -1;
static int control_fd = -1;
static int trace_fd = -1;
static int tape_fd = -1;
static int circuit_prog_fd = -1;
static uint32_t program_id;
static uint32_t next_run_seq = 1;
static int emit_gate_rows = 1;

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt,
                           va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

static void bump_memlock_rlimit(void)
{
    struct rlimit r = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &r) && errno != EPERM)
        fprintf(stderr, "setrlimit(RLIMIT_MEMLOCK) failed: %s\n",
                strerror(errno));
}

static int map_fd_by_name(struct bpf_object *obj, const char *name)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, name);
    int fd = map ? bpf_map__fd(map) : -1;

    if (fd < 0)
        fprintf(stderr, "map %s not found or not loaded\n", name);
    return fd;
}

static int program_fd_by_name(struct bpf_object *obj, const char *name)
{
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, name);
    int fd = prog ? bpf_program__fd(prog) : -1;

    if (fd < 0)
        fprintf(stderr, "program %s not found or not loaded\n", name);
    return fd;
}

static int map_set(int fd, uint32_t key, const void *value, const char *name)
{
    if (bpf_map_update_elem(fd, &key, value, BPF_ANY)) {
        fprintf(stderr, "update %s[%u] failed: %s\n",
                name, key, strerror(errno));
        return 1;
    }
    return 0;
}

static int map_get(int fd, uint32_t key, void *value, const char *name)
{
    if (bpf_map_lookup_elem(fd, &key, value)) {
        fprintf(stderr, "lookup %s[%u] failed: %s\n",
                name, key, strerror(errno));
        return 1;
    }
    return 0;
}

static int run_program(void)
{
    LIBBPF_OPTS(bpf_test_run_opts, opts);
    int err = bpf_prog_test_run_opts(circuit_prog_fd, &opts);

    if (err) {
        int code = err < 0 ? -err : errno;
        fprintf(stderr, "bpf_prog_test_run_opts failed: err=%d (%s)\n",
                err, strerror(code));
        return 1;
    }
    return 0;
}

static int valid_name(const char *name)
{
    if (!name[0])
        return 0;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.'))
            return 0;
    }
    return 1;
}

static int validate_image(const struct circuit_image *image, const char *path)
{
    if (!valid_name(image->name)) {
        fprintf(stderr, "%s: invalid circuit name\n", path);
        return 1;
    }
    if (image->input_count > VM_MAX_INPUTS ||
        image->gate_count > VM_MAX_GATES ||
        image->output_count == 0 ||
        image->output_count > VM_MAX_OUTPUTS) {
        fprintf(stderr, "%s: counts exceed WMC1 bounds\n", path);
        return 1;
    }
    if (image->wire_count !=
            VM_INPUT_BASE + image->input_count + image->gate_count ||
        image->wire_count > VM_MAX_WIRES) {
        fprintf(stderr, "%s: non-canonical wire_count=%u\n",
                path, image->wire_count);
        return 1;
    }

    for (uint32_t i = 0; i < image->gate_count; i++) {
        const struct wm_gate_desc *gate = &image->gates[i];
        uint32_t expected_dst = VM_INPUT_BASE + image->input_count + i;
        if (gate->op != VM_OP_NAND || gate->dst != expected_dst ||
            gate->src0 >= gate->dst || gate->src1 >= gate->dst) {
            fprintf(stderr, "%s: invalid canonical gate %u\n", path, i);
            return 1;
        }
    }
    for (uint32_t i = 0; i < image->output_count; i++) {
        if (image->outputs[i] >= image->wire_count) {
            fprintf(stderr, "%s: output %u references wire %u >= %u\n",
                    path, i, image->outputs[i], image->wire_count);
            return 1;
        }
    }
    return 0;
}

static int read_image(const char *path, struct circuit_image *image)
{
    FILE *f = fopen(path, "r");
    char magic[8] = {};
    int ch;

    if (!f) {
        fprintf(stderr, "open %s failed: %s\n", path, strerror(errno));
        return 1;
    }
    memset(image, 0, sizeof(*image));
    if (fscanf(f, "%7s %63s %u %u %u %u", magic, image->name,
               &image->input_count, &image->gate_count,
               &image->wire_count, &image->output_count) != 6 ||
        strcmp(magic, "WMC1")) {
        fprintf(stderr, "%s: malformed WMC1 header\n", path);
        fclose(f);
        return 1;
    }
    if (image->gate_count > VM_MAX_GATES ||
        image->output_count > VM_MAX_OUTPUTS) {
        fprintf(stderr, "%s: declared arrays exceed parser bounds\n", path);
        fclose(f);
        return 1;
    }
    for (uint32_t i = 0; i < image->gate_count; i++) {
        struct wm_gate_desc *gate = &image->gates[i];
        if (fscanf(f, "%u %u %u %u", &gate->op, &gate->src0,
                   &gate->src1, &gate->dst) != 4) {
            fprintf(stderr, "%s: malformed gate %u\n", path, i);
            fclose(f);
            return 1;
        }
    }
    for (uint32_t i = 0; i < image->output_count; i++) {
        if (fscanf(f, "%u", &image->outputs[i]) != 1) {
            fprintf(stderr, "%s: malformed output %u\n", path, i);
            fclose(f);
            return 1;
        }
    }
    while ((ch = fgetc(f)) != EOF) {
        if (!isspace((unsigned char)ch)) {
            fprintf(stderr, "%s: trailing non-whitespace data\n", path);
            fclose(f);
            return 1;
        }
    }
    if (ferror(f)) {
        fprintf(stderr, "read %s failed\n", path);
        fclose(f);
        return 1;
    }
    fclose(f);
    return validate_image(image, path);
}

static int load_descriptor(const struct circuit_image *image)
{
    for (uint32_t i = 0; i < image->gate_count; i++) {
        if (map_set(circuit_fd, i, &image->gates[i], "CIRCUIT"))
            return 1;
    }
    return 0;
}

static void evaluate(const struct circuit_image *image, uint64_t assignment,
                     uint32_t variant_id, uint64_t wires[VM_MAX_WIRES])
{
    memset(wires, 0, sizeof(uint64_t) * VM_MAX_WIRES);
    wires[VM_CONST_ZERO] = 0;
    wires[VM_CONST_ONE] = 1;
    for (uint32_t i = 0; i < image->input_count; i++)
        wires[VM_INPUT_BASE + i] = (assignment >> i) & 1u;

    for (uint32_t i = 0; i < image->gate_count; i++) {
        const struct wm_gate_desc *gate = &image->gates[i];
        uint64_t a = wires[gate->src0] & 1u;
        uint64_t b = wires[gate->src1] & 1u;
        if (variant_id == 2 || variant_id == 3)
            wires[gate->dst] = 1;
        else
            wires[gate->dst] = !(a && b);
    }
}

static uint64_t pack_outputs(const struct circuit_image *image,
                             const uint64_t wires[VM_MAX_WIRES])
{
    uint64_t packed = 0;
    for (uint32_t i = 0; i < image->output_count; i++)
        packed |= (wires[image->outputs[i]] & 1u) << i;
    return packed;
}

static int run_one(const struct circuit_image *image, uint64_t assignment,
                   const char *kind, uint32_t ordinal)
{
    struct wm_vm_control control = {
        .abi_version = VM_ABI_VERSION,
        .input_count = image->input_count,
        .gate_count = image->gate_count,
        .wire_count = image->wire_count,
        .status = VM_STATUS_OK,
        .executed = 0,
        .failing_gate = VM_NO_FAILING_GATE,
        .run_seq = next_run_seq++,
    };
    uint64_t standard_wires[VM_MAX_WIRES];
    uint64_t expected_wires[VM_MAX_WIRES];
    uint64_t actual_wires[VM_MAX_WIRES] = {};
    uint64_t variant_id64 = 0;
    uint64_t gate_cap = 0;
    uint64_t err_count = 0;
    uint32_t key = 0;
    int failed = 0;
    int trace_failed = 0;

    if (load_descriptor(image))
        return 1;
    for (uint32_t i = 0; i < image->input_count; i++) {
        uint64_t bit = (assignment >> i) & 1u;
        if (map_set(wires_fd, VM_INPUT_BASE + i, &bit, "WIRES"))
            return 1;
    }
    if (map_set(control_fd, 0, &control, "VM_CONTROL") || run_program())
        return 1;
    if (map_get(control_fd, 0, &control, "VM_CONTROL") ||
        map_get(tape_fd, VARIANT_ID_IDX, &variant_id64, "TAPE") ||
        map_get(tape_fd, GATE_CAP_OBS_IDX, &gate_cap, "TAPE") ||
        map_get(tape_fd, ERR_IDX, &err_count, "TAPE"))
        return 1;

    uint32_t variant_id = (uint32_t)variant_id64;
    evaluate(image, assignment, 1, standard_wires);
    evaluate(image, assignment, variant_id, expected_wires);

    for (uint32_t i = 0; i < image->wire_count; i++) {
        if (map_get(wires_fd, i, &actual_wires[i], "WIRES"))
            return 1;
        actual_wires[i] &= 1u;
    }

    for (uint32_t i = 0; i < image->gate_count; i++) {
        struct wm_gate_trace trace = {};
        const struct wm_gate_desc *gate = &image->gates[i];
        int trace_ok;

        if (map_get(trace_fd, i, &trace, "VM_TRACE"))
            return 1;
        if (variant_id == 4) {
            trace_ok = trace.valid == 0 &&
                       trace.output == expected_wires[gate->dst];
        } else {
            trace_ok = trace.valid == 1 &&
                       trace.second_update_raw_ret <= 0 &&
                       trace.output ==
                           (uint32_t)(trace.second_update_raw_ret == 0) &&
                       trace.output == expected_wires[gate->dst];
        }
        trace_ok = trace_ok &&
                   actual_wires[gate->dst] == expected_wires[gate->dst];
        if (!trace_ok)
            trace_failed = 1;
        if (emit_gate_rows) {
            printf("{\"record\":\"gate\",\"circuit\":\"%s\","
                   "\"kind\":\"%s\",\"ordinal\":%u,\"run_seq\":%u,"
                   "\"program_id\":%u,\"gate\":%u,\"src0\":%u,"
                   "\"src1\":%u,\"dst\":%u,\"variant_id\":%u,"
                   "\"second_update_raw_ret\":%lld,\"trace_valid\":%s,"
                   "\"expected\":%llu,\"actual\":%u,\"passed\":%s}\n",
                   image->name, kind, ordinal, control.run_seq, program_id,
                   i, gate->src0, gate->src1, gate->dst, variant_id,
                   trace.second_update_raw_ret,
                   trace.valid ? "true" : "false",
                   (unsigned long long)expected_wires[gate->dst],
                   trace.output, trace_ok ? "true" : "false");
        }
    }

    uint64_t logical_expected = pack_outputs(image, standard_wires);
    uint64_t expected = pack_outputs(image, expected_wires);
    uint64_t actual = pack_outputs(image, actual_wires);
    failed = control.status != VM_STATUS_OK ||
             control.executed != image->gate_count ||
             control.failing_gate != VM_NO_FAILING_GATE ||
             err_count != 0 || expected != actual || trace_failed ||
             !((variant_id == 1 && gate_cap == 2) ||
               (variant_id == 2 && gate_cap == 64) ||
               (variant_id == 3 && gate_cap == 2) ||
               (variant_id == 4 && gate_cap == 2));

    printf("{\"record\":\"run\",\"circuit\":\"%s\","
           "\"kind\":\"%s\",\"ordinal\":%u,\"run_seq\":%u,"
           "\"program_id\":%u,\"input_count\":%u,\"gate_count\":%u,"
           "\"assignment\":%llu,\"variant_id\":%u,\"gate_cap\":%llu,"
           "\"logical_expected\":%llu,\"variant_expected\":%llu,"
           "\"actual\":%llu,\"status\":%u,\"executed\":%u,"
           "\"failing_gate\":%u,\"gate_error_count\":%llu,"
           "\"trace_passed\":%s,\"passed\":%s}\n",
           image->name, kind, ordinal, control.run_seq, program_id,
           image->input_count, image->gate_count,
           (unsigned long long)assignment, variant_id,
           (unsigned long long)gate_cap,
           (unsigned long long)logical_expected,
           (unsigned long long)expected,
           (unsigned long long)actual, control.status, control.executed,
           control.failing_gate, (unsigned long long)err_count,
           trace_failed ? "false" : "true", failed ? "false" : "true");
    (void)key;
    return failed;
}

static uint64_t next_random(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static int run_truth_table(const struct circuit_image *image, uint32_t ordinal,
                           int repeats)
{
    uint64_t state = 0x9e3779b97f4a7c15ULL ^ ordinal;
    uint64_t cases = image->input_count <= 12
        ? (1ULL << image->input_count) : 1024;
    int failures = 0;

    for (int rep = 0; rep < repeats; rep++) {
        for (uint64_t i = 0; i < cases; i++) {
            uint64_t assignment = image->input_count <= 12
                ? i : next_random(&state);
            if (image->input_count < 64)
                assignment &= (1ULL << image->input_count) - 1;
            failures += run_one(image, assignment,
                                image->input_count <= 12
                                    ? "exhaustive" : "fixed_seed_random",
                                ordinal);
        }
    }
    return failures;
}

static int negative_case(const char *name, struct wm_vm_control control,
                         const struct wm_gate_desc *gate,
                         uint32_t expected_status,
                         uint32_t expected_failing_gate)
{
    int failed;

    control.status = VM_STATUS_OK;
    control.executed = 0;
    control.failing_gate = VM_NO_FAILING_GATE;
    control.run_seq = next_run_seq++;
    if (gate && map_set(circuit_fd, 0, gate, "CIRCUIT"))
        return 1;
    if (map_set(control_fd, 0, &control, "VM_CONTROL") || run_program() ||
        map_get(control_fd, 0, &control, "VM_CONTROL"))
        return 1;
    failed = control.status != expected_status ||
             control.failing_gate != expected_failing_gate;
    printf("{\"record\":\"negative\",\"case\":\"%s\","
           "\"run_seq\":%u,\"program_id\":%u,\"expected_status\":%u,"
           "\"actual_status\":%u,\"expected_failing_gate\":%u,"
           "\"actual_failing_gate\":%u,\"passed\":%s}\n",
           name, control.run_seq, program_id, expected_status, control.status,
           expected_failing_gate, control.failing_gate,
           failed ? "false" : "true");
    return failed;
}

static int run_negative_suite(void)
{
    struct wm_vm_control base = {
        .abi_version = VM_ABI_VERSION,
        .input_count = 2,
        .gate_count = 1,
        .wire_count = 5,
    };
    struct wm_gate_desc gate = {
        .op = VM_OP_NAND,
        .src0 = 2,
        .src1 = 3,
        .dst = 4,
    };
    int failures = 0;
    struct wm_vm_control c;
    struct wm_gate_desc g;

    c = base;
    c.abi_version++;
    failures += negative_case("bad_abi", c, &gate, VM_STATUS_BAD_ABI,
                              VM_NO_FAILING_GATE);
    c = base;
    c.input_count = VM_MAX_INPUTS + 1;
    c.wire_count = VM_INPUT_BASE + c.input_count + c.gate_count;
    failures += negative_case("bad_input_count", c, &gate,
                              VM_STATUS_BAD_INPUT_COUNT,
                              VM_NO_FAILING_GATE);
    c = base;
    c.gate_count = VM_MAX_GATES + 1;
    c.wire_count = VM_INPUT_BASE + c.input_count + c.gate_count;
    failures += negative_case("bad_gate_count", c, NULL,
                              VM_STATUS_BAD_GATE_COUNT,
                              VM_NO_FAILING_GATE);
    c = base;
    c.wire_count++;
    failures += negative_case("bad_wire_count", c, &gate,
                              VM_STATUS_BAD_WIRE_COUNT,
                              VM_NO_FAILING_GATE);
    g = gate;
    g.op = 99;
    failures += negative_case("bad_op", base, &g,
                              VM_STATUS_BAD_DESCRIPTOR, 0);
    g = gate;
    g.dst++;
    failures += negative_case("bad_dst", base, &g,
                              VM_STATUS_BAD_DESCRIPTOR, 0);
    g = gate;
    g.src0 = g.dst;
    failures += negative_case("forward_reference", base, &g,
                              VM_STATUS_BAD_DESCRIPTOR, 0);
    return failures;
}

static int run_file(const char *path, uint32_t ordinal, int repeats)
{
    struct circuit_image *image = calloc(1, sizeof(*image));
    int failures;

    if (!image) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }
    if (read_image(path, image)) {
        free(image);
        return 1;
    }
    failures = run_truth_table(image, ordinal, repeats);
    free(image);
    return failures;
}

static int run_stress(int rounds, int file_count, char **paths)
{
    struct circuit_image *images;
    uint64_t state = 0x243f6a8885a308d3ULL;
    int failures = 0;

    if (rounds < 1 || file_count < 1)
        return 1;
    images = calloc((size_t)file_count, sizeof(*images));
    if (!images) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }
    for (int i = 0; i < file_count; i++) {
        if (read_image(paths[i], &images[i])) {
            free(images);
            return 1;
        }
    }
    for (int round = 0; round < rounds; round++) {
        int index = round % file_count;
        uint64_t assignment = next_random(&state);
        if (images[index].input_count < 64)
            assignment &= (1ULL << images[index].input_count) - 1;
        failures += run_one(&images[index], assignment, "alternating_stress",
                            (uint32_t)index);
    }
    free(images);
    return failures;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s run FILE.wmc [repeats]\n"
            "       %s batch FILE.wmc [FILE.wmc ...]\n"
            "       %s stress ROUNDS FILE.wmc [FILE.wmc ...]\n"
            "       %s negative\n",
            argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv)
{
    const char *object_path = getenv("WM_BPF_OBJECT");
    const char *emit = getenv("WM_VM_EMIT_GATES");
    struct bpf_object *obj;
    struct bpf_prog_info info = {};
    uint32_t info_len = sizeof(info);
    int failures = 0;

    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }
    if (!object_path || !object_path[0])
        object_path = "build/wm.bpf.o";
    if (emit && !strcmp(emit, "0"))
        emit_gate_rows = 0;

    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();
    obj = bpf_object__open_file(object_path, NULL);
    long open_err = libbpf_get_error(obj);
    if (open_err) {
        fprintf(stderr, "bpf_object__open_file(%s) failed: %s\n",
                object_path, strerror((int)-open_err));
        return 1;
    }
    int load_err = bpf_object__load(obj);
    if (load_err) {
        fprintf(stderr, "bpf_object__load(%s) failed: %s\n",
                object_path, strerror(-load_err));
        bpf_object__close(obj);
        return 1;
    }

    circuit_prog_fd = program_fd_by_name(obj, "wm_circuit");
    circuit_fd = map_fd_by_name(obj, "CIRCUIT");
    wires_fd = map_fd_by_name(obj, "WIRES");
    control_fd = map_fd_by_name(obj, "VM_CONTROL");
    trace_fd = map_fd_by_name(obj, "VM_TRACE");
    tape_fd = map_fd_by_name(obj, "TAPE");
    if (circuit_prog_fd < 0 || circuit_fd < 0 || wires_fd < 0 ||
        control_fd < 0 || trace_fd < 0 || tape_fd < 0) {
        bpf_object__close(obj);
        return 1;
    }
    if (bpf_obj_get_info_by_fd(circuit_prog_fd, &info, &info_len)) {
        fprintf(stderr, "bpf_obj_get_info_by_fd failed: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    program_id = info.id;

    if (!strcmp(argv[1], "run")) {
        int repeats = argc > 3 ? atoi(argv[3]) : 1;
        if (argc < 3 || repeats < 1) {
            usage(argv[0]);
            failures = 1;
        } else {
            failures = run_file(argv[2], 0, repeats);
        }
    } else if (!strcmp(argv[1], "batch")) {
        if (argc < 3) {
            usage(argv[0]);
            failures = 1;
        } else {
            for (int i = 2; i < argc; i++)
                failures += run_file(argv[i], (uint32_t)(i - 2), 1);
        }
    } else if (!strcmp(argv[1], "stress")) {
        int rounds = argc > 2 ? atoi(argv[2]) : 0;
        if (argc < 4 || rounds < 1) {
            usage(argv[0]);
            failures = 1;
        } else {
            failures = run_stress(rounds, argc - 3, &argv[3]);
        }
    } else if (!strcmp(argv[1], "negative")) {
        failures = run_negative_suite();
    } else {
        usage(argv[0]);
        failures = 1;
    }

    fprintf(stderr, "wm_circuit: program_id=%u failures=%d\n",
            program_id, failures);
    bpf_object__close(obj);
    return failures ? 1 : 0;
}
