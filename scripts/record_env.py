#!/usr/bin/env python3
import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(cmd: list[str]) -> str:
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        return f"unavailable: {exc}"


def sha256(path: Path) -> str | None:
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    obj = ROOT / "build" / "wm.bpf.o"
    verifier_log = ROOT / "results" / "verifier.log"
    feature_probe = ROOT / "results" / "feature_probe.txt"
    env = {
        "uname": run(["uname", "-a"]),
        "clang_version": run(["clang", "--version"]),
        "bpftool_version": run(["bpftool", "version"]),
        "libbpf_version": run(["pkg-config", "--modversion", "libbpf"]),
        "bpf_object_sha256": sha256(obj),
        "verifier_log_sha256": sha256(verifier_log),
        "feature_probe_sha256": sha256(feature_probe),
        "btf_vmlinux_exists": Path("/sys/kernel/btf/vmlinux").exists(),
    }
    print(json.dumps(env, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
