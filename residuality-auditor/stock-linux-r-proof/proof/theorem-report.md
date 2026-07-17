# Definition 2 Integrated Stock-Linux R Check

Verdict: `STOCK_LINUX_R_ESTABLISHED_FOR_FROZEN_TUPLE`

| # | Check | Pass | Evidence |
|---:|---|---|---|
| 1 | fixed artifact accepted by verifier | yes | frontier-check.json result and program-info.json |
| 2 | object/program/kernel/BTF/config identity consistent | yes | frontier/state/path/report/runtime identities plus kernel-identity.json |
| 3 | two concrete states reachable | yes | membership-a0/a1.json and joint-coverage.json |
| 4 | context same | yes | runtime.json contexts for a=0 and a=1 |
| 5 | selected state different | yes | runtime selected_state plus joint selected_masks_differ |
| 6 | same suffix | yes | path-correspondence common_suffix, runtime suffix, suffix-witness.json |
| 7 | same-suffix outputs differ | yes | runtime observations and factorization conditions |
| 8 | same actual computed report cell | yes | report-map unique_cell_check representatives |
| 9 | unique-cell on chosen fiber | yes | proof/report/unique-cell-check result embedded in report-map.json |
| 10 | behavioral quotient different | yes | proof/factorization beta-map and factorization conditions |
| 11 | factorization failure | yes | proof/factorization/factorization.json |
| 12 | four independent stock-Linux R certificates | yes | proof/definition2/stock-linux-r-check.json |
| 13 | all evidence hashes match | yes | manifest.json plus embedded input_sha256 fields |

## Scope

This report checks the frozen tuple represented by the supplied evidence bundle only. It does not claim a verifier unsoundness, a vulnerability, W, or a full weird machine.
