# Residuality audit: stock-linux-frontier-factorization

## Claim summary

| Claim | Result |
|---|---|
| A — accepted artifact/model flag | **yes** |
| C — output-witnessed same-suffix distinction | **yes** |
| P — bounded programmability | not established |
| R — unique-cell report criterion assessable | **yes** |
| R — report non-factorization | **yes** |
| R — output-witnessed residual collision | **yes** |
| W — policy candidate under supplied certificate | not assessed |

## Future-observation quotient

Stable classes: **2** over 2 states and 1 actions.

- Q0: `sigma-a0`
- Q1: `sigma-a1`

## C witness

Shortest witness: `sigma-a0` vs `sigma-a1` with `shared_suffix_insert_B`.

- Left outputs: `[{"success": true, "retval": 1}]`
- Right outputs: `[{"success": false, "retval": 0}]`

## R factorization audit

Report source: `Linux verifier retained-state representative from proof/report/report-map.json`

Behavioral factorization holds: **no**
Output-witnessed R collision exists: **yes**

First shortest reported collision: cell `retained:516c47f044cc3fc3`, states `sigma-a0` and `sigma-a1`, suffix `shared_suffix_insert_B`.
Left outputs: `[{"success": true, "retval": 1}]`
Right outputs: `[{"success": false, "retval": 0}]`

### Residuality spectrum

| Depth k | Behavior classes | Max classes in one report cell |
|---:|---:|---:|
| 0 | 1 | 1 |
| 1 | 2 | 2 |

## Gate-basis certificate

No gate certificate supplied.

## Scope limits

- Finite deterministic partial Mealy models only.
- R is assessable only with an explicit unique-cell report partition on the declared fiber.
- A modeled report partition is not evidence about Linux verifier computed cells.
- A gate certificate is not a proof of the full fixed-interpreter obligations for node P.
- Policy linkage and unintendedness remain declared evidence, not automatically inferred facts.

## Model notes

Finite stock-Linux adapter model built from one verifier frontier bundle. The two concrete prefix cases are kept as sigma-a0 and sigma-a1; the only action is the reviewed common xlated suffix. The report cell is the retained verifier-state representative established by proof/report/report-map.json. Object SHA256: 9e4ed906402c834eec061b9d2ed1407255b0ed44ee086a365638ee3c95e54fe5. Program tag: 100c248465bce0b0.
