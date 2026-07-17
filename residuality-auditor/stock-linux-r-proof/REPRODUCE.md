# Reproduce / verify

From the original project checkout, the pre-freeze integrated checker was run as:

```sh
PYTHONPATH=src:. python3 -m tools.proof.check_definition2 /home/parallels/Desktop/residuality-auditor-v0.2.0/experiments/target-prune/v042-four-checks-operational-prune-cell --refresh-manifest
```

It produced:

```text
STOCK_LINUX_R_ESTABLISHED_FOR_FROZEN_TUPLE
```

To verify this frozen package's integrity from the project checkout:

```sh
PYTHONPATH=src:. python3 -m tools.proof.check_frozen_bundle /home/parallels/Desktop/residuality-auditor-v0.2.0/stock-linux-r-proof
```

Expected output:

```text
FROZEN_PROOF_BUNDLE_VERIFIED
```

The full integrated theorem report is `proof/theorem-report.md`; the machine-readable verdict is `proof/definition2/verdict.json`.
