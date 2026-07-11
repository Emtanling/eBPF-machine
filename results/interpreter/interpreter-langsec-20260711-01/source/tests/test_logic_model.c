#include <stdio.h>
#include <stdint.h>
#include "src/wm_common.h"

static uint64_t model_nand(uint64_t a, uint64_t b, unsigned cap)
{
    unsigned entries = 1; /* sentinel S */

    if (a & 1)
        entries++;

    if ((b & 1) == 0)
        return 1;

    return entries < cap ? 1 : 0;
}

static void model_full_adder(uint64_t a, uint64_t b, uint64_t cin,
                             uint64_t *sum, uint64_t *cout)
{
    uint64_t d   = model_nand(a, b, 2);
    uint64_t e   = model_nand(a, d, 2);
    uint64_t f   = model_nand(b, d, 2);
    uint64_t xab = model_nand(e, f, 2);
    uint64_t g   = model_nand(xab, cin, 2);
    uint64_t h   = model_nand(xab, g, 2);
    uint64_t i   = model_nand(cin, g, 2);
    *sum  = model_nand(h, i, 2);
    *cout = model_nand(d, g, 2);
}

static int check_nand(void)
{
    int expected[2][2] = {{1, 1}, {1, 0}};
    int failures = 0;

    for (int a = 0; a < 2; a++) {
        for (int b = 0; b < 2; b++) {
            uint64_t actual = model_nand((uint64_t)a, (uint64_t)b, 2);
            if ((int)actual != expected[a][b]) {
                fprintf(stderr, "nand mismatch a=%d b=%d expected=%d actual=%llu\n",
                        a, b, expected[a][b], (unsigned long long)actual);
                failures++;
            }
        }
    }

    return failures;
}

static int check_cap64_ablation(void)
{
    int failures = 0;

    for (int a = 0; a < 2; a++) {
        for (int b = 0; b < 2; b++) {
            uint64_t actual = model_nand((uint64_t)a, (uint64_t)b, 64);
            if (actual != 1) {
                fprintf(stderr, "cap64 mismatch a=%d b=%d expected=1 actual=%llu\n",
                        a, b, (unsigned long long)actual);
                failures++;
            }
        }
    }

    return failures;
}

static int check_full_adder(void)
{
    int failures = 0;

    for (int a = 0; a < 2; a++) {
        for (int b = 0; b < 2; b++) {
            for (int cin = 0; cin < 2; cin++) {
                uint64_t sum = 0;
                uint64_t cout = 0;
                unsigned total = (unsigned)a + (unsigned)b + (unsigned)cin;

                model_full_adder((uint64_t)a, (uint64_t)b, (uint64_t)cin,
                                 &sum, &cout);

                if (sum != (total & 1u) || cout != ((total >> 1) & 1u)) {
                    fprintf(stderr,
                            "fa mismatch a=%d b=%d cin=%d expected sum=%u cout=%u actual sum=%llu cout=%llu\n",
                            a, b, cin, total & 1u, (total >> 1) & 1u,
                            (unsigned long long)sum, (unsigned long long)cout);
                    failures++;
                }
            }
        }
    }

    return failures;
}

int main(void)
{
    int failures = 0;

    if (WORDLEN != 32u) {
        fprintf(stderr, "WORDLEN expected 32, got %u\n", WORDLEN);
        failures++;
    }

    failures += check_nand();
    failures += check_cap64_ablation();
    failures += check_full_adder();

    if (failures) {
        fprintf(stderr, "logic model failures: %d\n", failures);
        return 1;
    }

    puts("logic model: ok");
    return 0;
}
