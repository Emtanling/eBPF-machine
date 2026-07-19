# Residuality Auditor: stock-Linux reproduction package

This directory contains the source-only capture and analysis toolchain for the
paper's stock-Linux `rac_single` experiment together with its immutable V1.0
trace-evidence bundle and historical legacy-adapter outputs.

The two paths have different meanings:

- `stock-linux-r-proof/` verifies byte integrity for the author-generated
  frozen kernel/object tuple and replays its historical legacy adapter; it is
  not a current semantic R verdict for real Linux.
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
checker sources, and stored legacy-adapter verdict. Do not edit files inside the
bundle without generating a new version and re-running the full evidence
pipeline. `FROZEN_PROOF_BUNDLE_VERIFIED` verifies those immutable bytes; it does
not establish a current R claim for real Linux.

Build and test the reproduction code from the repository root:

```sh
python3 -m pip install -e './residuality-auditor[test]'
make stock-r-preflight
make stock-r-build
make stock-r-v2-build
make test-stock-r-v2-local
make test-ebrc
make test-stock-r-tools
make test-stock-r-v2
```

Run the install command once in the Python environment that will execute the
tests. `make test-stock-r-tools` checks for the declared `jsonschema` and
`rfc8785` dependencies before discovery and reports the same install command if
they are missing. The target does not install packages or access the network.
`make test-stock-r-v2-local` runs the V2-local proof and capture tests without
that dependency preflight; it is a focused gate, not a replacement for the full
Stock-R suite.

Those commands compile and test but do not attach probes. For the exact live
capture command, required privileges, generated outputs, cleanup, and the
fexit-to-kprobe fallback, see `REPRODUCE.md` and `linux/README.md`.

The prospective Stock-R V2 experiment is a separate controlled witness and
exact query. A valid V2 observation can report a direct verifier prune and
repeated runtime divergence. Without a checked proof it reports `UNKNOWN` /
`NOT_ESTABLISHED`; with the V2-local
`MUST_OUTCOME_PROOF` and `history-case-binding` both bound to the exact bundle,
it can establish exact-query outcome eligibility for the controlled V2 witness
only.

The U4 generic EBRC layer is separate from the source-specific V1/V2 auditors.
It compiles a validated bundle to a typed exact claim, evidence graph, and proof
DAG, then checks those documents without reading the bundle's terminal verdict
label. Its two retained controls are intentionally asymmetric: V1 is
`BLOCKED/INCONCLUSIVE`, while a complete V2 bundle is
`CERTIFIED/NONFACTORING` only at its exact operational scope. The EBRC commands
in `REPRODUCE.md` exercise the focused controls and hostile matrix.

After compiling a complete V2 control, run the fixed hostile matrix with:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -m residuality_auditor.cli ebrc-mutations \
  output/ebrc-v2-compiled --json-out output/ebrc-mutations.json
```

The baseline must be `CERTIFIED`. The matrix then checks that unsupported
family/report/observer/suffix/transport lifts are blocked and that dependency,
payload, and proof-DAG tampering is invalid.

The U5 Contextual Residual Lifting layer is a separate guarded transport rule.
It consumes a certified exact source claim plus a contextual transport proof
and can derive only `AT(target)` with evidence grade `TRANSPORTED`; it does not
authorize a `FORALL` EBRC claim. Run `make test-ebrc-context` from the
repository root for the focused synthetic controls, and see `REPRODUCE.md` for
the positive, identity, blocked, and hostile-matrix commands.

The U6 VM target pilot connects that rule to two generated stock-VM targets.
`linux/scripts/run_stock_r_context.sh` takes a complete Stock-R V2 bundle,
creates a restricted post-collision framed-context variant, compiles and loads
the target, checks the target identity and runtime bridge, and emits a
target-bound `TRANSPORTED` certificate. The public replay capsule retains two
selected nontrivial exact targets and the retained 12-case matrix summary under
`artifact/evidence/`; they are not a family theorem or a general Linux result.

## Python distribution boundary

An installed wheel places the three U1 contract schemas and three EBRC U4
schemas at
`sysconfig.get_path('data')/share/residuality-auditor/schemas`. For example:

```python
from pathlib import Path
import sysconfig

schema_dir = (
    Path(sysconfig.get_path("data"))
    / "share"
    / "residuality-auditor"
    / "schemas"
)
```

U1 publishes versioned JSON Schemas and test-side cross-document contract
checks only; it does not provide a production semantic validator. U4 adds an
executable generic checker for its finite exact-claim fragment and schemas for
the claim, evidence graph, and proof DAG. Source-specific adapters remain in
the trust path for interpreting and validating Stock-Linux bundle bytes. The
source distribution is intentionally package-only. It includes the Python
package and all six schemas, but excludes `tests/`, the Linux collectors, proof
tools, examples, and the frozen evidence bundle. Full testing, evidence
verification, and reproduction therefore require a Git checkout.

V1 records one operational-prune edge and two samples. Its historical adapter
embeds them in a deterministic two-state model with a factorization failure.
Under evidence-model v1, this does not establish stable must outcomes for real
Linux: the exact operational-prune query is `UNKNOWN` because outcome
eligibility is `NOT_ESTABLISHED`. It is not a general Linux functional report,
verifier-unsoundness, vulnerability, P, W, or weird-machine claim.
