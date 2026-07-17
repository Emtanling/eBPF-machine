# Frozen stock-Linux trace certificate

This directory contains only the V1.0 stock-Linux `rac_single` proof payload and
the minimal standard-library verifier needed to check it.

```sh
PYTHONPATH=. python3 -m tools.proof.check_frozen_bundle stock-linux-r-proof
```

Expected output:

```text
FROZEN_PROOF_BUNDLE_VERIFIED
```

`stock-linux-r-proof/` is frozen: its `MANIFEST.json` and
`CHECKSUMS.sha256` bind the raw capture, normalized certificates, proof outputs,
checker sources, and stored tuple-specific verdict. Do not edit files inside the
bundle without generating a new version and re-running the full evidence
pipeline.

The certificate is retrospective, trace-local, and relative to the
author-declared operational prune-report. It is not a general Linux functional
report, verifier-unsoundness, vulnerability, P, W, or weird-machine claim.
