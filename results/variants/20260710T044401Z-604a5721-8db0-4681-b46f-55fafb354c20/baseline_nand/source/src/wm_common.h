#ifndef WM_COMMON_H
#define WM_COMMON_H

#define K_S 0u
#define K_A 1u
#define K_B 2u

#define IDX_A         0u
#define IDX_B         1u
#define IDX_NAND_OUT  2u
#define IDX_CIN       3u
#define IDX_SUM_OUT   4u
#define IDX_COUT_OUT  5u

#define X_BASE        16u
#define Y_BASE        64u
#define S_BASE        112u
#define CARRY_IDX     160u
#define ERR_IDX       161u
#define SECOND_UPDATE_RAW_IDX    162u
#define SECOND_UPDATE_VALID_IDX  163u
#define VARIANT_ID_IDX           164u
#define GATE_CAP_OBS_IDX         165u

#define TAPE_ENTRIES  256u
#define WORDLEN       32u

_Static_assert(IDX_COUT_OUT < X_BASE, "scalar indices overlap X region");
_Static_assert(X_BASE + WORDLEN <= Y_BASE, "X and Y regions overlap");
_Static_assert(Y_BASE + WORDLEN <= S_BASE, "Y and S regions overlap");
_Static_assert(S_BASE + WORDLEN <= CARRY_IDX, "S region overlaps carry slot");
_Static_assert(CARRY_IDX < ERR_IDX, "carry and err slots overlap");
_Static_assert(ERR_IDX < SECOND_UPDATE_RAW_IDX, "err and helper slots overlap");
_Static_assert(SECOND_UPDATE_RAW_IDX < SECOND_UPDATE_VALID_IDX,
               "helper observation slots overlap");
_Static_assert(SECOND_UPDATE_VALID_IDX < VARIANT_ID_IDX,
               "helper and variant observation slots overlap");
_Static_assert(VARIANT_ID_IDX < GATE_CAP_OBS_IDX,
               "variant observation slots overlap");
_Static_assert(GATE_CAP_OBS_IDX < TAPE_ENTRIES,
               "variant observation slot out of tape bounds");

#endif
