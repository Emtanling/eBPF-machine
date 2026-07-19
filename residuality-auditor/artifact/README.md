# Stock-R Replay Capsule

This directory contains the minimal public replay artifact for the Stock-R V2
and selected contextual CRL evidence.

## Files

- `evidence/replay-capsule.tar.xz` - deterministic USTAR+XZ capsule.
- `replay-manifest.json` - exact file list, SHA-256 receipts, size limits, and
  checked certificate identifiers.
- `expected-results.json` - frozen normalized replay oracle.
- `evidence/contextual-matrix-live-20260720-03.json` - compact 12-case VM
  matrix summary.
- `evidence/reproduction-summary.json` - latest verified replay record.

Capsule SHA-256:

```text
3df6b96e3dded26e9f876db8f607278bc0a65a6df31b297cb6bd3043f44151f7
```

Capsule size: 2,208,232 bytes. Manifested members: 58.

## Offline Replay

Install dependencies once, then run the replay without network access:

```sh
python3 -m pip install -e './residuality-auditor[test]'
make reproduce-paper
```

Expected output:

```text
all_expected=true
unexpected_results=0
```

Exit code `0` means the capsule hash, manifest, extracted tree, V1 blocked
status, V2 exact certificate, two selected CRL certificates, and hostile
matrices match `expected-results.json`. Exit code `1` means a replayed result
differs from the oracle. Exit code `2` means malformed or missing artifact
input.

## Privileged Matrix

The optional live VM matrix is independent of offline replay. It loads BPF
programs and requires a supported Linux host with BPF privileges:

```sh
make contextual-matrix-live \
  STOCK_R_V2_BUNDLE=residuality-auditor/output/stock-r-v2-u3-live-20260719-01 \
  CONTEXT_MATRIX_OUT=residuality-auditor/output/contextual-matrix-live-YYYYMMDD-NN
```

The published matrix used `BOUNDED_CONTEXT_SUITE_ONLY` and produced 12 expected
results: six certified transparent targets and six fail-closed hostile or
missing-obligation targets.

## Boundary

The capsule supports exact replay of the retained evidence only. It is not a
fresh independent reproduction, a `FORALL` context theorem, a general Linux R
claim, a compiler-correctness proof, a vulnerability result, P, W, or a
policy-level weird-machine claim.
