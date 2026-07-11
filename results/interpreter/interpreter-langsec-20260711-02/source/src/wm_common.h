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

/*
 * Bounded state-mediated circuit interpreter ABI (WMC1).
 *
 * The bounds are part of the declared experiment domain.  They are fixed
 * independently of verifier outcomes and must not be increased or decreased
 * merely because a particular build happens to load (or fail to load).
 *
 * Wire layout is canonical SSA:
 *   0                         constant false
 *   1                         constant true
 *   2 .. 2 + input_count - 1 primary inputs
 *   2 + input_count + i       destination of gate i
 */
#define VM_ABI_VERSION       1u
#define VM_OP_NAND           1u
#define VM_CONST_ZERO        0u
#define VM_CONST_ONE         1u
#define VM_INPUT_BASE        2u
#define VM_MAX_INPUTS        64u
#define VM_MAX_GATES         512u
#define VM_MAX_OUTPUTS       64u
#define VM_MAX_WIRES         (VM_INPUT_BASE + VM_MAX_INPUTS + VM_MAX_GATES)
#define VM_NO_FAILING_GATE   0xffffffffu

enum wm_vm_status {
    VM_STATUS_OK = 0,
    VM_STATUS_BAD_ABI = 1,
    VM_STATUS_BAD_INPUT_COUNT = 2,
    VM_STATUS_BAD_GATE_COUNT = 3,
    VM_STATUS_BAD_WIRE_COUNT = 4,
    VM_STATUS_BAD_DESCRIPTOR = 5,
    VM_STATUS_BAD_WIRE = 6,
    VM_STATUS_GATE_SETUP = 7,
    VM_STATUS_GATE_RETURN = 8,
    VM_STATUS_TRACE_WRITE = 9,
    VM_STATUS_LOOP = 10,
};

struct wm_gate_desc {
    unsigned int op;
    unsigned int src0;
    unsigned int src1;
    unsigned int dst;
};

struct wm_vm_control {
    unsigned int abi_version;
    unsigned int input_count;
    unsigned int gate_count;
    unsigned int wire_count;
    unsigned int status;
    unsigned int executed;
    unsigned int failing_gate;
    unsigned int run_seq;
};

struct wm_gate_trace {
    long long second_update_raw_ret;
    unsigned int output;
    unsigned int valid;
};

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
_Static_assert(VM_MAX_WIRES == 578u, "WMC1 wire bound changed unexpectedly");
_Static_assert(sizeof(struct wm_gate_desc) == 16u,
               "wm_gate_desc ABI size changed");
_Static_assert(sizeof(struct wm_vm_control) == 32u,
               "wm_vm_control ABI size changed");
_Static_assert(sizeof(struct wm_gate_trace) == 16u,
               "wm_gate_trace ABI size changed");

#endif
