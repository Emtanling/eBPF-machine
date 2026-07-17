# Reproduce the stock-Linux capture

This guide separates four operations that should not be conflated:

1. verify the immutable published trace certificate;
2. rebuild and test the capture/analysis code; and
3. execute a fresh privileged capture on a particular Linux kernel tuple; and
4. review, check, and freeze a new tuple-specific proof bundle.

## 1. Verify the published certificate

From this directory:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. \
  python3 -m tools.proof.check_frozen_bundle stock-linux-r-proof
```

The expected final line is:

```text
FROZEN_PROOF_BUNDLE_VERIFIED
```

This is an offline integrity and evidence-gate check. It does not load a BPF
program or claim independent reproduction.

## 2. Rebuild and test the complete source path

Use a Linux machine with kernel BTF at `/sys/kernel/btf/vmlinux`, `clang`,
`bpftool`, `libbpf`, `pkg-config`, `libelf`, `zlib`, Python 3, GNU Make, and a C
compiler. From the repository root:

```sh
make stock-r-preflight
make stock-r-build
make test-stock-r-tools
```

The build produces ignored files under `residuality-auditor/linux/build/`.
Neither the preflight nor build target attaches probes or loads the witness.

## 3. Run a fresh native capture

Use an isolated VM. The runner invokes `sudo`, attaches a kernel tracing
collector, loads the XDP witness, and temporarily pins the loaded witness under
bpffs. Review `linux/scripts/run_linux_r.sh` and `linux/README.md` before running
it.

From this directory, prefer fexit:

```sh
RAC_BACKEND=fexit ./linux/scripts/run_linux_r.sh output/linux-live
```

If preflight reports that the required fexit/BTF attachment is unavailable, use
the kprobe fallback:

```sh
RAC_BACKEND=kprobe ./linux/scripts/run_linux_r.sh output/linux-live-kprobe
```

Use a new output directory for every run. The runner records raw events,
environment and loaded-program metadata, object and translated-bytecode
digests, enriched events, a report contract, analyzer output, and prune-screen
results. Follow the cleanup instructions printed by the runner for any pinned
object left for inspection.

## 4. Review and freeze a new proof bundle

The live runner intentionally stops at a fail-closed evidence inventory. It
does not turn a prune event into R by setting a flag. The source packages under
`tools/frontier/`, `tools/path/`, `tools/state_v2/`,
`tools/concretization/`, `tools/report_map/`, `tools/subsumption/`, and
`tools/proof/` contain the normalization and independent evidence gates. The
published `stock-linux-r-proof/normalized/` and `proof/` trees show the required
versioned schemas for the frozen tuple.

After producing those proof objects for a **new** reviewed bundle, run the
integrated checker from this directory:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -m tools.proof.check_definition2 /path/to/reviewed-bundle \
  --refresh-manifest
```

Only a complete passing bundle may emit
`STOCK_LINUX_R_ESTABLISHED_FOR_FROZEN_TUPLE`. Freeze that new bundle to a new
directory and version with:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -m tools.proof.freeze_bundle \
  /path/to/reviewed-bundle /path/to/new-stock-linux-r-proof
```

Do not run `--refresh-manifest` against the published
`stock-linux-r-proof/`; verify it with the offline command in step 1 instead.

## Interpretation boundary

A fresh result is bound to its own kernel release, configuration, BTF, compiled
object, loaded-program identity, and translated bytecode. It is not identical
to the V1.0 frozen tuple merely because the sources are the same. Review and
freeze a new run separately; never copy it over `stock-linux-r-proof/` without
new manifests, checksums, and a new version.

The experiment supports only the paper's finite, retrospective, trace-local R
conclusion for the declared operational prune-report. It does not establish a
general Linux functional-report failure, verifier unsoundness, a vulnerability,
privilege escalation, P, W, or a policy-level weird machine.
