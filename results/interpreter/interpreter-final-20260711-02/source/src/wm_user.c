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

static int tape_fd = -1;
static int tape_io_failed;

static int program_fd(struct bpf_object *obj, const char *name)
{
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, name);
    if (!prog) {
        fprintf(stderr, "program %s not found in selected BPF object\n", name);
        return -1;
    }

    int fd = bpf_program__fd(prog);
    if (fd < 0)
        fprintf(stderr, "program %s has no loaded fd\n", name);
    return fd;
}

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
        fprintf(stderr, "setrlimit(RLIMIT_MEMLOCK) failed: %s\n", strerror(errno));
}

static int tape_set(uint32_t idx, uint64_t v)
{
    int err = bpf_map_update_elem(tape_fd, &idx, &v, BPF_ANY);
    if (err) {
        tape_io_failed = 1;
        fprintf(stderr, "update TAPE[%u] failed: %s\n", idx, strerror(errno));
    }
    return err;
}

static uint64_t tape_get(uint32_t idx)
{
    uint64_t v = 0;
    int err = bpf_map_lookup_elem(tape_fd, &idx, &v);
    if (err) {
        tape_io_failed = 1;
        fprintf(stderr, "lookup TAPE[%u] failed: %s\n", idx, strerror(errno));
    }
    return v;
}

struct second_update_observation {
    int observed;
    int64_t raw_ret;
    uint64_t errno_value;
    uint64_t variant_id;
    uint64_t gate_cap;
};

static struct second_update_observation read_second_update_observation(void)
{
    struct second_update_observation obs = {0};
    uint64_t raw_bits = tape_get(SECOND_UPDATE_RAW_IDX);
    uint64_t valid = tape_get(SECOND_UPDATE_VALID_IDX);

    obs.variant_id = tape_get(VARIANT_ID_IDX);
    obs.gate_cap = tape_get(GATE_CAP_OBS_IDX);
    obs.observed = valid == 1;
    if (obs.observed) {
        /* Preserve the signed helper-return bit pattern written by eBPF. */
        memcpy(&obs.raw_ret, &raw_bits, sizeof(obs.raw_ret));
        if (obs.raw_ret < 0)
            obs.errno_value = (uint64_t)(-(obs.raw_ret + 1)) + 1;
    }
    return obs;
}

static int second_update_matches_bit(const struct second_update_observation *obs,
                                     uint64_t bit)
{
    if (obs->variant_id == 4 && obs->gate_cap == 2)
        return !obs->observed; /* Explicit baseline has no capacity probe. */
    if (!((obs->variant_id == 1 && obs->gate_cap == 2) ||
          (obs->variant_id == 2 && obs->gate_cap == 64) ||
          (obs->variant_id == 3 && obs->gate_cap == 2)))
        return 0;
    if (!obs->observed)
        return 0;
    return bit ? obs->raw_ret == 0 : obs->raw_ret < 0;
}

static void print_second_update_json(const struct second_update_observation *obs)
{
    printf("\"variant_id\":%llu,\"gate_cap\":%llu,"
           "\"second_update_observed\":%s,",
           (unsigned long long)obs->variant_id,
           (unsigned long long)obs->gate_cap,
           obs->observed ? "true" : "false");
    if (obs->observed) {
        printf("\"second_update_raw_ret\":%lld,"
               "\"second_update_errno\":%llu",
               (long long)obs->raw_ret,
               (unsigned long long)obs->errno_value);
    } else {
        printf("\"second_update_raw_ret\":null,"
               "\"second_update_errno\":null");
    }
}

static int tape_zero(void)
{
    uint64_t z = 0;
    tape_io_failed = 0;
    for (uint32_t i = 0; i < TAPE_ENTRIES; i++) {
        if (bpf_map_update_elem(tape_fd, &i, &z, BPF_ANY)) {
            fprintf(stderr, "zero TAPE[%u] failed: %s\n", i, strerror(errno));
            return 1;
        }
    }
    return 0;
}

static int run_prog(int prog_fd)
{
    LIBBPF_OPTS(bpf_test_run_opts, opts);
    int err = bpf_prog_test_run_opts(prog_fd, &opts);

    if (err) {
        int code = err < 0 ? -err : errno;
        fprintf(stderr, "bpf_prog_test_run_opts failed: err=%d (%s)\n",
                err, strerror(code));
        return 1;
    }

    return 0;
}

static int test_nand(struct bpf_object *obj, int repeats, int expect_all_one,
                     const char *case_name)
{
    int prog_fd = program_fd(obj, "wm_nand");
    if (prog_fd < 0)
        return 1;
    int pass = 0;
    int total = 0;
    int normal_expected[2][2] = {{1, 1}, {1, 0}};

    for (int a = 0; a < 2; a++) {
        for (int b = 0; b < 2; b++) {
            for (int rep = 0; rep < repeats; rep++) {
                if (tape_zero())
                    return 1;
                if (tape_set(IDX_A, (uint64_t)a) ||
                    tape_set(IDX_B, (uint64_t)b))
                    return 1;
                if (run_prog(prog_fd))
                    return 1;

                uint64_t out = tape_get(IDX_NAND_OUT);
                uint64_t err = tape_get(ERR_IDX);
                struct second_update_observation obs =
                    read_second_update_observation();
                int expected = expect_all_one ? 1 : normal_expected[a][b];
                int ok = !tape_io_failed && ((int)out == expected) && err == 0 &&
                         second_update_matches_bit(&obs, out);

                printf("{\"case\":\"%s\",\"trial\":%d,\"a\":%d,\"b\":%d,"
                       "\"expected\":%d,\"actual\":%llu,\"err\":%llu,",
                       case_name, rep, a, b, expected,
                       (unsigned long long)out, (unsigned long long)err);
                print_second_update_json(&obs);
                printf(",\"passed\":%s}\n",
                       ok ? "true" : "false");
                total++;
                if (ok)
                    pass++;
            }
        }
    }

    fprintf(stderr, "%s: %d/%d passed\n", case_name, pass, total);
    return pass == total ? 0 : 1;
}

static int test_fa(struct bpf_object *obj)
{
    int prog_fd = program_fd(obj, "wm_fa");
    if (prog_fd < 0)
        return 1;
    int pass = 0;
    int total = 0;

    for (int a = 0; a < 2; a++) {
        for (int b = 0; b < 2; b++) {
            for (int cin = 0; cin < 2; cin++) {
                unsigned expected_total = (unsigned)a + (unsigned)b + (unsigned)cin;
                unsigned expected_sum = expected_total & 1u;
                unsigned expected_cout = (expected_total >> 1) & 1u;

                if (tape_zero())
                    return 1;
                if (tape_set(IDX_A, (uint64_t)a) ||
                    tape_set(IDX_B, (uint64_t)b) ||
                    tape_set(IDX_CIN, (uint64_t)cin))
                    return 1;
                if (run_prog(prog_fd))
                    return 1;

                uint64_t sum = tape_get(IDX_SUM_OUT);
                uint64_t cout = tape_get(IDX_COUT_OUT);
                uint64_t err = tape_get(ERR_IDX);
                struct second_update_observation obs =
                    read_second_update_observation();
                int ok = !tape_io_failed && sum == expected_sum &&
                         cout == expected_cout && err == 0 &&
                         second_update_matches_bit(&obs, cout);

                printf("{\"case\":\"full_adder\",\"a\":%d,\"b\":%d,\"cin\":%d,"
                       "\"expected_sum\":%u,\"expected_cout\":%u,"
                       "\"actual_sum\":%llu,\"actual_cout\":%llu,"
                       "\"err\":%llu,",
                       a, b, cin, expected_sum, expected_cout,
                       (unsigned long long)sum, (unsigned long long)cout,
                       (unsigned long long)err);
                print_second_update_json(&obs);
                printf(",\"passed\":%s}\n", ok ? "true" : "false");
                total++;
                if (ok)
                    pass++;
            }
        }
    }

    fprintf(stderr, "full_adder: %d/%d passed\n", pass, total);
    return pass == total ? 0 : 1;
}

static uint32_t prng_state;

static uint32_t next_u32(void)
{
    uint32_t x = prng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    prng_state = x;
    return x;
}

static int run_adder_case(int prog_fd, uint32_t x, uint32_t y, int trial,
                          const char *kind)
{
    if (tape_zero())
        return 1;

    for (uint32_t bit = 0; bit < WORDLEN; bit++) {
        if (tape_set(X_BASE + bit, (x >> bit) & 1u) ||
            tape_set(Y_BASE + bit, (y >> bit) & 1u))
            return 1;
    }

    if (run_prog(prog_fd))
        return 1;

    uint32_t actual = 0;
    for (uint32_t bit = 0; bit < WORDLEN; bit++)
        actual |= ((uint32_t)tape_get(S_BASE + bit) & 1u) << bit;

    uint64_t wide = (uint64_t)x + (uint64_t)y;
    uint32_t expected = (uint32_t)wide;
    uint64_t expected_carry = wide >> WORDLEN;
    uint64_t carry = tape_get(CARRY_IDX);
    uint64_t err = tape_get(ERR_IDX);
    struct second_update_observation obs = read_second_update_observation();
    int ok = !tape_io_failed && actual == expected &&
             carry == expected_carry && err == 0 &&
             second_update_matches_bit(&obs, carry);

    printf("{\"case\":\"adder32\",\"kind\":\"%s\",\"trial\":%d,"
           "\"x\":%u,\"y\":%u,\"expected\":%u,\"actual\":%u,"
           "\"expected_carry\":%llu,\"carry_out\":%llu,"
           "\"err\":%llu,",
           kind, trial, x, y, expected, actual,
           (unsigned long long)expected_carry, (unsigned long long)carry,
           (unsigned long long)err);
    print_second_update_json(&obs);
    printf(",\"passed\":%s}\n", ok ? "true" : "false");
    return ok ? 0 : 1;
}

static int test_adder(struct bpf_object *obj, int trials)
{
    int prog_fd = program_fd(obj, "wm_adder32");
    if (prog_fd < 0)
        return 1;
    uint32_t fixed[][2] = {
        {0u, 0u},
        {1u, 1u},
        {0xffffffffu, 1u},
        {0x55555555u, 0xaaaaaaaau},
        {0xffffffffu, 0xffffffffu},
    };
    int pass = 0;
    int total = 0;

    for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++) {
        int fail = run_adder_case(prog_fd, fixed[i][0], fixed[i][1],
                                  (int)i, "fixed");
        total++;
        if (!fail)
            pass++;
    }

    prng_state = 0x6d2b79f5u;
    for (int t = 0; t < trials; t++) {
        uint32_t x = next_u32();
        uint32_t y = next_u32();
        int fail = run_adder_case(prog_fd, x, y, t, "random");
        total++;
        if (!fail)
            pass++;
    }

    fprintf(stderr, "adder32: %d/%d passed\n", pass, total);
    return pass == total ? 0 : 1;
}

static int test_adder_exhaustive(struct bpf_object *obj, int width)
{
    int prog_fd = program_fd(obj, "wm_adder32");
    if (prog_fd < 0)
        return 1;
    int pass = 0;
    int total = 0;

    /* The public exhaustive mode is intentionally bounded to the evaluated
     * 8-bit domain; this also keeps trial and pass counters within int. */
    if (width < 1 || width > 8)
        width = 8;

    uint32_t n = 1u << width;
    for (uint32_t x = 0; x < n; x++) {
        for (uint32_t y = 0; y < n; y++) {
            int fail = run_adder_case(prog_fd, x, y, (int)(x * n + y),
                                      "exhaustive");
            total++;
            if (!fail)
                pass++;
        }
    }

    fprintf(stderr, "adder_exhaustive(width=%d): %d/%d passed\n",
            width, pass, total);
    return pass == total ? 0 : 1;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s nand [repeats]\n"
            "       %s nand-all1 [repeats]\n"
            "       %s fa\n"
            "       %s adder [random-trials]\n"
            "       %s adder-exhaustive [width]\n",
            argv0, argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "nand";
    const char *object_path = getenv("WM_BPF_OBJECT");
    int rc = 0;

    if (!object_path || !object_path[0])
        object_path = "build/wm.bpf.o";

    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();

    struct bpf_object *obj = bpf_object__open_file(object_path, NULL);
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

    struct bpf_map *tape = bpf_object__find_map_by_name(obj, "TAPE");
    tape_fd = tape ? bpf_map__fd(tape) : -1;
    if (tape_fd < 0) {
        fprintf(stderr, "failed to get TAPE fd from %s\n", object_path);
        bpf_object__close(obj);
        return 1;
    }

    if (!strcmp(mode, "nand")) {
        int repeats = argc > 2 ? atoi(argv[2]) : 100;
        rc = test_nand(obj, repeats, 0, "nand");
    } else if (!strcmp(mode, "nand-all1")) {
        int repeats = argc > 2 ? atoi(argv[2]) : 100;
        rc = test_nand(obj, repeats, 1, "nand_all1");
    } else if (!strcmp(mode, "fa")) {
        rc = test_fa(obj);
    } else if (!strcmp(mode, "adder")) {
        int trials = argc > 2 ? atoi(argv[2]) : 1000;
        rc = test_adder(obj, trials);
    } else if (!strcmp(mode, "adder-exhaustive")) {
        int width = argc > 2 ? atoi(argv[2]) : 8;
        rc = test_adder_exhaustive(obj, width);
    } else {
        usage(argv[0]);
        rc = 2;
    }

    bpf_object__close(obj);
    return rc;
}
