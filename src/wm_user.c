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
#include "wm.skel.h"

static int tape_fd = -1;

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
    return bpf_map_update_elem(tape_fd, &idx, &v, BPF_ANY);
}

static uint64_t tape_get(uint32_t idx)
{
    uint64_t v = 0;
    int err = bpf_map_lookup_elem(tape_fd, &idx, &v);
    if (err)
        fprintf(stderr, "lookup TAPE[%u] failed: %s\n", idx, strerror(errno));
    return v;
}

static int tape_zero(void)
{
    uint64_t z = 0;
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

static int test_nand(struct wm_bpf *skel, int repeats, int expect_all_one,
                     const char *case_name)
{
    int prog_fd = bpf_program__fd(skel->progs.wm_nand);
    int pass = 0;
    int total = 0;
    int normal_expected[2][2] = {{1, 1}, {1, 0}};

    for (int a = 0; a < 2; a++) {
        for (int b = 0; b < 2; b++) {
            for (int rep = 0; rep < repeats; rep++) {
                if (tape_zero())
                    return 1;
                tape_set(IDX_A, (uint64_t)a);
                tape_set(IDX_B, (uint64_t)b);
                if (run_prog(prog_fd))
                    return 1;

                uint64_t out = tape_get(IDX_NAND_OUT);
                uint64_t err = tape_get(ERR_IDX);
                int expected = expect_all_one ? 1 : normal_expected[a][b];
                int ok = ((int)out == expected) && err == 0;

                printf("{\"case\":\"%s\",\"trial\":%d,\"a\":%d,\"b\":%d,"
                       "\"expected\":%d,\"actual\":%llu,\"err\":%llu,"
                       "\"passed\":%s}\n",
                       case_name, rep, a, b, expected,
                       (unsigned long long)out, (unsigned long long)err,
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

static int test_fa(struct wm_bpf *skel)
{
    int prog_fd = bpf_program__fd(skel->progs.wm_fa);
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
                tape_set(IDX_A, (uint64_t)a);
                tape_set(IDX_B, (uint64_t)b);
                tape_set(IDX_CIN, (uint64_t)cin);
                if (run_prog(prog_fd))
                    return 1;

                uint64_t sum = tape_get(IDX_SUM_OUT);
                uint64_t cout = tape_get(IDX_COUT_OUT);
                uint64_t err = tape_get(ERR_IDX);
                int ok = sum == expected_sum && cout == expected_cout && err == 0;

                printf("{\"case\":\"full_adder\",\"a\":%d,\"b\":%d,\"cin\":%d,"
                       "\"expected_sum\":%u,\"expected_cout\":%u,"
                       "\"actual_sum\":%llu,\"actual_cout\":%llu,"
                       "\"err\":%llu,\"passed\":%s}\n",
                       a, b, cin, expected_sum, expected_cout,
                       (unsigned long long)sum, (unsigned long long)cout,
                       (unsigned long long)err, ok ? "true" : "false");
                total++;
                if (ok)
                    pass++;
            }
        }
    }

    fprintf(stderr, "full_adder: %d/%d passed\n", pass, total);
    return pass == total ? 0 : 1;
}

static uint32_t next_u32(void)
{
    return ((uint32_t)rand() << 16) ^ (uint32_t)rand();
}

static int run_adder_case(int prog_fd, uint32_t x, uint32_t y, int trial,
                          const char *kind)
{
    if (tape_zero())
        return 1;

    for (uint32_t bit = 0; bit < WORDLEN; bit++) {
        tape_set(X_BASE + bit, (x >> bit) & 1u);
        tape_set(Y_BASE + bit, (y >> bit) & 1u);
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
    int ok = actual == expected && carry == expected_carry && err == 0;

    printf("{\"case\":\"adder32\",\"kind\":\"%s\",\"trial\":%d,"
           "\"x\":%u,\"y\":%u,\"expected\":%u,\"actual\":%u,"
           "\"expected_carry\":%llu,\"carry_out\":%llu,"
           "\"err\":%llu,\"passed\":%s}\n",
           kind, trial, x, y, expected, actual,
           (unsigned long long)expected_carry, (unsigned long long)carry,
           (unsigned long long)err, ok ? "true" : "false");
    return ok ? 0 : 1;
}

static int test_adder(struct wm_bpf *skel, int trials)
{
    int prog_fd = bpf_program__fd(skel->progs.wm_adder32);
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

    srand(1234);
    for (int t = 0; t < trials; t++) {
        int fail = run_adder_case(prog_fd, next_u32(), next_u32(), t, "random");
        total++;
        if (!fail)
            pass++;
    }

    fprintf(stderr, "adder32: %d/%d passed\n", pass, total);
    return pass == total ? 0 : 1;
}

static int test_adder_exhaustive(struct wm_bpf *skel, int width)
{
    int prog_fd = bpf_program__fd(skel->progs.wm_adder32);
    int pass = 0;
    int total = 0;

    if (width < 1 || width > 16)
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
    int rc = 0;

    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();

    struct wm_bpf *skel = wm_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "wm_bpf__open_and_load failed\n");
        return 1;
    }

    tape_fd = bpf_map__fd(skel->maps.TAPE);
    if (tape_fd < 0) {
        fprintf(stderr, "failed to get TAPE fd\n");
        wm_bpf__destroy(skel);
        return 1;
    }

    if (!strcmp(mode, "nand")) {
        int repeats = argc > 2 ? atoi(argv[2]) : 100;
        rc = test_nand(skel, repeats, 0, "nand");
    } else if (!strcmp(mode, "nand-all1")) {
        int repeats = argc > 2 ? atoi(argv[2]) : 100;
        rc = test_nand(skel, repeats, 1, "nand_all1");
    } else if (!strcmp(mode, "fa")) {
        rc = test_fa(skel);
    } else if (!strcmp(mode, "adder")) {
        int trials = argc > 2 ? atoi(argv[2]) : 1000;
        rc = test_adder(skel, trials);
    } else if (!strcmp(mode, "adder-exhaustive")) {
        int width = argc > 2 ? atoi(argv[2]) : 8;
        rc = test_adder_exhaustive(skel, width);
    } else {
        usage(argv[0]);
        rc = 2;
    }

    wm_bpf__destroy(skel);
    return rc;
}
