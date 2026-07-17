# Linux R Evidence Report

**Verdict:** `LINUX_R_NOT_ESTABLISHED`

## Summary

- Linux R candidate: **False**
- Linux R established under declared contract: **False**
- Bytecode frontier declared: **False**
- Path correspondence reviewed: **False**
- Report contract in scope: **False**
- Concretization reviewed: **False**

## Required evidence

- `extractor_events_present`: **True**
- `extractor_identity_matches_runtime`: **True**
- `frontier_declared`: **False**
- `path_correspondence_reviewed`: **False**
- `joint_operational_prune_cell`: **True**
- `distinct_verifier_paths`: **True**
- `runtime_same_suffix_c_witness`: **True**
- `selected_component_omitted_from_cell_schema`: **True**
- `no_external_interference_declared`: **True**
- `serialized_execution_declared`: **True**

## Selected verifier prune cell

- Cell ID: `1`
- Program name: `rac_single`
- Visit instruction: `41`
- Equality level: `0`
- Distinct path histories: **True**
- State fingerprints equal: **False**
- Old history hash: `d699fe1aa18d9578`
- Current history hash: `e8c646b969e1dce2`

## Selected runtime witness

- Cases: `a=0` vs `a=1`
- Selected state differs: **True**
- Same suffix: **True**
- Observation differs: **True**
- Context equal: **True**

## Limitations

- A successful states_equal/is_state_visited prune is treated as an operational computed cell membership event.
- The tool does not infer the verifier's intended functional contract from source code.
- The selected runtime component must be explicitly declared omitted from the extracted cell schema.
- A program-name match alone is insufficient; the contract must select a bytecode frontier and review its correspondence to the concrete prefixes.
- Without reviewed concretization and report-contract scope, the result remains an R candidate, not a final paper claim.

Evidence digest: `90b50d4d0d2d264982db35524f7361f184459f944bfd1a53927c29055d20a75c`
