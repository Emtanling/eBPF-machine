# Residuality Auditor: stock-Linux reproduction package

This directory contains the source-only capture and analysis toolchain for the
paper's stock-Linux `rac_single` experiment together with its immutable V1.0
trace certificate.

The two paths have different meanings:

- `stock-linux-r-proof/` verifies the author-generated frozen kernel/object
  tuple offline.
- `linux/`, `src/`, `tools/`, `tests/`, and `examples/` build and exercise the
  native collector, finite-model controls, and certificate-construction
  pipeline for a fresh tuple.

Verify the frozen tuple without compiling or attaching BPF programs:

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

Build and test the reproduction code from the repository root:

```sh
make stock-r-preflight
make stock-r-build
make test-stock-r-tools
```

Those commands compile and test but do not attach probes. For the exact live
capture command, required privileges, generated outputs, cleanup, and the
fexit-to-kprobe fallback, see `REPRODUCE.md` and `linux/README.md`.

The certificate is retrospective, trace-local, and relative to the
author-declared operational prune-report. It is not a general Linux functional
report, verifier-unsoundness, vulnerability, P, W, or weird-machine claim.
