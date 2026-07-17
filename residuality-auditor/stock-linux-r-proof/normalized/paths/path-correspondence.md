# Path Correspondence Proof

Result: `PATH_CORRESPONDENCE_VERIFIED`

Frontier join: `41`
Object SHA256: `9e4ed906402c834eec061b9d2ed1407255b0ed44ee086a365638ee3c95e54fe5`
Program tag: `100c248465bce0b0`

| Runtime case | Branch | Call PC | History side | Selected mask | Observation |
|---|---|---:|---|---:|---|
| `a=0` | `select_s` | 48 | `history_right` | 1 | True |
| `a=1` | `select_a` | 46 | `history_left` | 3 | False |

Both verifier histories hit the xlated branch call predicted for their runtime input,
and both reach the same pre-suffix frontier with the same remaining xlated suffix.
