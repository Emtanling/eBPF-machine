# Stock Linux Behavioral Factorization

Result: `REPORT_FACTORIZATION_FAILURE_ESTABLISHED`

| Check | Pass |
|---|---|
| `pi_R(sigma0) = pi_R(sigma1)` | True |
| `beta_D(sigma0) != beta_D(sigma1)` | True |
| `Obs(w, sigma0) != Obs(w, sigma1)` | True |
| old v0.2 R collision checker agrees | True |

Suffix word: `shared_suffix_insert_B`

## beta map

- `sigma-a0` -> `Q0`
- `sigma-a1` -> `Q1`

## quotient classes

- `Q0`: `sigma-a0`
- `Q1`: `sigma-a1`

The same Linux report representative covers both concrete prefix cases, but the reviewed common suffix produces different runtime observations.
