/* Second witness — Frama-C EVA port.
 *
 * The SAME construction as witness2/witness.py, expressed for an independent,
 * production, sound abstract interpreter (Frama-C's EVA value analysis).  Reading
 * EVA's inferred range for `out` here reproduces the opacity result in a tool we
 * did not write — third-party backing for the system-independence claim.
 *
 * Ubuntu:  sudo apt-get install -y frama-c   (already present on the artifact VM)
 * Run (see run.sh):
 *     frama-c -eva -eva-slevel 0 nand_mod.c   # join-based
 *
 * Inputs a,b are constrained to {0,1} by guard pruning (`if (x<0||x>1) return`),
 * which needs no builtins: on the fall-through path EVA has narrowed x to [0,1].
 * `Frama_C_show_each_*` is recognised by name; EVA prints its argument's range.
 */

void Frama_C_show_each_NAND_out(int);
void Frama_C_show_each_ABLATION_out(int);

/* gate: NAND(a,b) = [ (1 + a + b) mod 3 != 0 ]
 * The output lives in the residue of acc mod 3 — a congruence the interval
 * (Cvalue) domain abstracts to the full range. */
static int nand3(int a, int b) {
    int acc = 1 + a + b;          /* acc in {1,2,3} */
    return (acc % 3) != 0 ? 1 : 0;
}

/* ablation: modulus 7. acc in {1,2,3} never hits 0 mod 7, so the gate degenerates
 * to the constant 1 — and a sound interval analysis can now certify it. */
static int nand7(int a, int b) {
    int acc = 1 + a + b;
    return (acc % 7) != 0 ? 1 : 0;
}

int main(void) {
    volatile int input = 0;                   /* reading a volatile yields an unknown int */
    int a = input; if (a < 0 || a > 1) return 0;   /* now a in [0,1] */
    int b = input; if (b < 0 || b > 1) return 0;   /* now b in [0,1] */

    int out = nand3(a, b);
    Frama_C_show_each_NAND_out(out);      /* EXPECT: {0; 1}  -> full Boolean range = TOP = A-opaque */

    int abl = nand7(a, b);
    Frama_C_show_each_ABLATION_out(abl);  /* EXPECT: {1}     -> singleton = certified (non-triviality) */
    return 0;
}
