# v0.3.2 frontier proof checker

Run the checker from the repository root against a frozen Linux-R capture:

```sh
python3 -m tools.frontier.check_frontier OUTPUT_BUNDLE --out PROOF_DIRECTORY
```

The equivalent direct-script form is also supported:

```sh
python3 tools/frontier/check_frontier.py OUTPUT_BUNDLE --out PROOF_DIRECTORY
```

`--out` is required. It must name a new directory outside `OUTPUT_BUNDLE`; the
checker never writes into the raw evidence bundle. On completion it atomically
publishes the six proof artifacts, `run-manifest.json`, and `COMPLETE`.
`FRONTIER_ELIGIBLE` is emitted only when every identity, frontier, raw-history,
and remaining-xlated-suffix condition is proven. All other outcomes are
fail-closed.
