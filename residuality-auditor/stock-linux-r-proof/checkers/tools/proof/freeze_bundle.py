#!/usr/bin/env python3
"""Build the v1.0 stock-linux-r-proof frozen bundle."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

FINAL_VERDICT = "STOCK_LINUX_R_ESTABLISHED_FOR_FROZEN_TUPLE"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} root must be object")
    return data


def _copy(src: Path, dst: Path) -> None:
    if not src.exists():
        raise FileNotFoundError(src)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def _copy_if_exists(src: Path, dst: Path) -> None:
    if src.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def _copytree(src: Path, dst: Path) -> None:
    if not src.exists():
        raise FileNotFoundError(src)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, data: dict[str, Any]) -> None:
    _write(path, json.dumps(data, indent=2, sort_keys=True) + "\n")


def _object_path_from_sha(path: Path) -> Path | None:
    try:
        parts = path.read_text(encoding="utf-8", errors="replace").split()
    except OSError:
        return None
    if len(parts) >= 2:
        return Path(parts[1])
    return None


def _all_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file())


def _manifest_files(root: Path) -> dict[str, dict[str, Any]]:
    files = {}
    for path in _all_files(root):
        rel = path.relative_to(root).as_posix()
        if rel in {"MANIFEST.json", "CHECKSUMS.sha256"}:
            continue
        files[rel] = {"sha256": sha256_file(path), "size": path.stat().st_size}
    return files


def _write_checksums(root: Path) -> None:
    lines = []
    for path in _all_files(root):
        rel = path.relative_to(root).as_posix()
        if rel == "CHECKSUMS.sha256":
            continue
        lines.append(f"{sha256_file(path)}  {rel}")
    _write(root / "CHECKSUMS.sha256", "\n".join(lines) + "\n")


def _copy_evidence(src: Path, dst: Path, project_root: Path) -> None:
    # raw/kernel
    kernel_identity = _load_json(src / "proof" / "definition2" / "kernel-identity.json")
    _copy(src / "proof" / "definition2" / "kernel-identity.json", dst / "raw" / "kernel" / "kernel-identity.json")
    for key, name in (("btf", "vmlinux.btf"), ("config", f"config-{kernel_identity.get('kernel_release', 'unknown')}")):
        item = kernel_identity.get(key) or {}
        path = Path(item.get("path", "")) if item.get("available") else None
        if path and path.exists():
            _copy(path, dst / "raw" / "kernel" / name)
    _copy(src / "proof" / "subsumption" / "kernel-source-map.json", dst / "raw" / "kernel" / "kernel-source-map.json")

    # raw/object
    for rel in ["object.sha256", "program-info.json", "program-pin.txt", "object-disassembly.txt", "source.diff", "rac_witness.bpf.c.before"]:
        _copy_if_exists(src / rel, dst / "raw" / "object" / Path(rel).name)
    obj = _object_path_from_sha(src / "object.sha256")
    if obj and obj.exists():
        _copy(obj, dst / "raw" / "object" / obj.name)
    _copy_if_exists(project_root / "linux" / "witness" / "rac_witness.bpf.c", dst / "raw" / "object" / "rac_witness.bpf.c.current")

    # raw/xlated, verifier, runtime
    for rel in ["xlated-rac_single.txt", "xlated-rac_single.sha256", "xlated.txt"]:
        _copy_if_exists(src / rel, dst / "raw" / "xlated" / Path(rel).name)
    for rel in ["events.jsonl", "events.raw.jsonl", "prune-screen.tsv"]:
        _copy_if_exists(src / rel, dst / "raw" / "verifier-events" / Path(rel).name)
    for rel in ["runtime.json", "contract.json", "analysis.json", "analysis.md"]:
        _copy_if_exists(src / rel, dst / "raw" / "runtime" / Path(rel).name)

    # normalized proof objects
    _copy(src / "frontier-check.json", dst / "normalized" / "frontier" / "frontier-check.json")
    for src_dir, dst_name in [
        ("states", "states"),
        ("path", "paths"),
        ("concrete", "concrete"),
        ("concretization", "concretization"),
        ("subsumption", "subsumption"),
        ("report", "report"),
    ]:
        _copytree(src / "proof" / src_dir, dst / "normalized" / dst_name)

    # final proof products
    (dst / "proof" / "quotient").mkdir(parents=True, exist_ok=True)
    _copy(src / "proof" / "factorization" / "behavioral-quotient.json", dst / "proof" / "quotient" / "behavioral-quotient.json")
    _copy(src / "proof" / "factorization" / "beta-map.json", dst / "proof" / "quotient" / "beta-map.json")
    (dst / "proof" / "factorization").mkdir(parents=True, exist_ok=True)
    for rel in ["discipline.json", "factorization.json", "suffix-witness.json", "factorization.md", "auditor-analysis.json", "auditor-analysis.md"]:
        _copy_if_exists(src / "proof" / "factorization" / rel, dst / "proof" / "factorization" / rel)
    _copytree(src / "proof" / "definition2", dst / "proof" / "definition2")
    _copy(src / "proof" / "definition2" / "definition2-report.md", dst / "proof" / "theorem-report.md")

    # checker and test snapshots.
    _copytree(project_root / "tools", dst / "checkers" / "tools")
    _copytree(project_root / "src" / "residuality_auditor", dst / "checkers" / "src" / "residuality_auditor")
    _copytree(project_root / "tests", dst / "tests")


def _docs(src: Path, dst: Path) -> dict[str, Any]:
    verdict = _load_json(src / "proof" / "definition2" / "verdict.json")
    definition2 = _load_json(src / "proof" / "definition2" / "definition2-check.json")
    kernel = _load_json(src / "proof" / "definition2" / "kernel-identity.json")
    identity = (_load_json(src / "frontier-check.json").get("identity") or {})
    frozen_tuple = {
        "kernel_release": kernel.get("kernel_release"),
        "btf_sha256": (kernel.get("btf") or {}).get("sha256"),
        "config_sha256": (kernel.get("config") or {}).get("sha256"),
        "object_sha256": identity.get("object_sha256"),
        "program_id": identity.get("program_id"),
        "program_tag": identity.get("program_tag"),
        "program_pin": identity.get("program_pin"),
        "xlated_sha256": identity.get("xlated_sha256") or identity.get("recorded_xlated_sha256"),
        "definition2_verdict": verdict.get("verdict"),
    }
    claim = f"""# Stock Linux R claim for the frozen tuple

For the frozen kernel build, accepted artifact, xlated frontier, execution contract, and prune-report extractor recorded in this evidence bundle, the two reachable concrete states are uniquely assigned to one retained report representative while belonging to distinct future-observation classes. Therefore `R(M_K)` holds for this frozen tuple.

Final integrated checker verdict: `{verdict.get('verdict')}`.

## Frozen tuple

- Kernel release: `{frozen_tuple['kernel_release']}`
- BTF SHA256: `{frozen_tuple['btf_sha256']}`
- Kernel config SHA256: `{frozen_tuple['config_sha256']}`
- Object SHA256: `{frozen_tuple['object_sha256']}`
- Program id/tag: `{frozen_tuple['program_id']}` / `{frozen_tuple['program_tag']}`
- Program pin: `{frozen_tuple['program_pin']}`
- Xlated SHA256: `{frozen_tuple['xlated_sha256']}`
"""
    limitations = """# Limitations

This frozen proof bundle does not claim any of the following:

- it does not generalize to other kernels, configs, BTFs, compiler outputs, or eBPF objects;
- it does not prove Linux verifier unsoundness;
- it does not prove a security vulnerability;
- it does not prove W or policy unintendedness;
- it does not prove a complete weird machine;
- it relies on the restricted observed exact=0 subsumption model documented under `normalized/subsumption/`.
"""
    reproduce = f"""# Reproduce / verify

From the original project checkout, the pre-freeze integrated checker was run as:

```sh
PYTHONPATH=src:. python3 -m tools.proof.check_definition2 {src} --refresh-manifest
```

It produced:

```text
{verdict.get('verdict')}
```

To verify this frozen package's integrity from the project checkout:

```sh
PYTHONPATH=src:. python3 -m tools.proof.check_frozen_bundle {dst}
```

Expected output:

```text
FROZEN_PROOF_BUNDLE_VERIFIED
```

The full integrated theorem report is `proof/theorem-report.md`; the machine-readable verdict is `proof/definition2/verdict.json`.
"""
    _write(dst / "CLAIM.md", claim)
    _write(dst / "LIMITATIONS.md", limitations)
    _write(dst / "REPRODUCE.md", reproduce)
    return {"frozen_tuple": frozen_tuple, "definition2_summary": definition2.get("checks", {})}


def freeze(source_bundle: Path, out: Path, *, force: bool = False) -> dict[str, Any]:
    source_bundle = source_bundle.resolve()
    out = out.resolve()
    verdict = _load_json(source_bundle / "proof" / "definition2" / "verdict.json")
    if verdict.get("verdict") != FINAL_VERDICT:
        raise ValueError(f"source bundle is not publishable: {verdict.get('verdict')}")
    if out.exists():
        if not force:
            raise FileExistsError(f"{out} already exists; pass --force to replace")
        shutil.rmtree(out)
    out.mkdir(parents=True)
    project_root = Path.cwd().resolve()
    _copy_evidence(source_bundle, out, project_root)
    metadata = _docs(source_bundle, out)
    files = _manifest_files(out)
    manifest = {
        "schema": "stock-linux-r-proof-v1",
        "source_bundle": str(source_bundle),
        "final_verdict": verdict.get("verdict"),
        "frozen_tuple": metadata["frozen_tuple"],
        "files": files,
    }
    _write_json(out / "MANIFEST.json", manifest)
    _write_checksums(out)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_bundle", type=Path)
    parser.add_argument("out", type=Path, nargs="?", default=Path("stock-linux-r-proof"))
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    manifest = freeze(args.source_bundle, args.out, force=args.force)
    print(f"FROZEN_PROOF_BUNDLE_WRITTEN {args.out} files={len(manifest['files'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
