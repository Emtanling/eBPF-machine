#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p results

sudo bpftool feature probe kernel > results/feature_probe.txt

pin="/sys/fs/bpf/wm_poc_verify_$$"
log="results/verifier.log"
: > "$log"

set +e
sudo bpftool -d prog loadall build/wm.bpf.o "$pin" >> "$log" 2>&1
rc=$?
set -e

if sudo test -e "$pin"; then
  sudo rm -rf "$pin"
fi

{
  echo "bpftool_loadall_exit=$rc"
  sha256sum build/wm.bpf.o
} >> "$log"

exit "$rc"
