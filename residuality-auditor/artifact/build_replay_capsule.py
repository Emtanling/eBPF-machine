#!/usr/bin/env python3
"""Build the deterministic Stock-R replay capsule."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from residuality_auditor.reproduction import (
    CapsuleInputs,
    ReproductionError,
    build_replay_capsule,
)


def _certificate(value: object) -> str:
    return str(value) if isinstance(value, str) and value else "UNAVAILABLE"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v2-bundle", type=Path, required=True)
    parser.add_argument("--context-bundle", type=Path, action="append", required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)

    if len(args.context_bundle) != 2:
        parser.error("--context-bundle must be supplied exactly twice")

    try:
        manifest = build_replay_capsule(
            CapsuleInputs(
                v2_bundle=args.v2_bundle,
                context_bundles=(args.context_bundle[0], args.context_bundle[1]),
            ),
            args.archive,
            args.manifest,
        )
    except ReproductionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    certificates = manifest.get("certificates", {})
    contexts = (
        certificates.get("contexts", [])
        if isinstance(certificates, dict)
        else []
    )
    print(f"archive={args.archive}")
    print(f"archive_size={manifest['archive']['size']}")
    print(f"archive_sha256={manifest['archive']['sha256']}")
    print(
        "v2_certificate="
        + _certificate(certificates.get("v2") if isinstance(certificates, dict) else None)
    )
    for index in range(2):
        certificate = contexts[index] if isinstance(contexts, list) and index < len(contexts) else None
        print(f"context_{index}_certificate={_certificate(certificate)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
