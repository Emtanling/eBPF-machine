/* Precision control — Frama-C EVA port.
 *
 * Frama-C EVA value-range model for the modulo expression.  Inputs a and b are
 * obtained from two separate Frama_C_interval calls, so the source explicitly
 * models two independently chosen Boolean values.  The inferred range for
 * `out` is still only a global output range, not an input/output relation.
 *
 * Ubuntu:  sudo apt-get install -y frama-c   (already present on the artifact VM)
 * Run (see run.sh):
 *     frama-c -eva -eva-slevel 0 nand_mod.c   # join-based
 *
 * The archived eva_slevel0.log predates this input-model correction and must
 * not be represented as a run of the current source; see README.md.
 * `Frama_C_show_each_*` is recognised by name; EVA prints its argument's range.
 */

#include "__fc_builtin.h"

void Frama_C_show_each_NAND_out(int);
void Frama_C_show_each_ABLATION_out(int);

/* gate: NAND(a,b) = [ (1 + a + b) mod 3 != 0 ]
 * Its exact global Boolean output range is {0,1}. */
static int nand3(int a, int b) {
    int acc = 1 + a + b;          /* acc in {1,2,3} */
    return (acc % 3) != 0 ? 1 : 0;
}

/* Control: modulus 7. acc in {1,2,3} never hits 0 mod 7, so this is a
 * different, constant-one function rather than a same-semantics ablation. */
static int nand7(int a, int b) {
    int acc = 1 + a + b;
    return (acc % 7) != 0 ? 1 : 0;
}

int main(void) {
    int a = Frama_C_interval(0, 1);   /* first nondeterministic Boolean input */
    int b = Frama_C_interval(0, 1);   /* independently chosen Boolean input */

    int out = nand3(a, b);
    Frama_C_show_each_NAND_out(out);      /* EXPECT: {0; 1}, the exact global output range */

    int abl = nand7(a, b);
    Frama_C_show_each_ABLATION_out(abl);  /* EXPECT: {1}, for the different constant function */
    return 0;
}
