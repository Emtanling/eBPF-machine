#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUTPUT=${1:-"$ROOT/results/linux_r/linux-r-v1"}
case "$OUTPUT" in
  /*) ;;
  *) OUTPUT="$ROOT/$OUTPUT" ;;
esac
WORK=$(mktemp -d "${TMPDIR:-/tmp}/linux-r.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

cd "$ROOT"
make circuits >"$WORK/build.log" 2>&1
make BUILD="$WORK/build" GATE_CAP=2 "$WORK/build/wm_vm_user" \
  >>"$WORK/build.log" 2>&1

# Loading and executing wm_circuit is the calibration step: a successful run
# also proves acceptance of this concrete object by the running kernel.  The
# model uses only return sign/zero, never a kernel-version-specific errno.
sudo env WM_BPF_OBJECT="$WORK/build/wm.bpf.o" WM_VM_EMIT_GATES=1 \
  "$WORK/build/wm_vm_user" fixed circuits/nand.wmc 2 3 \
  >"$WORK/kernel_oracle.jsonl" 2>"$WORK/kernel_oracle.stderr"

python3 -m linux_r.generate \
  --program linux_r/program.json \
  --output "$OUTPUT" \
  --kernel-oracle "$WORK/kernel_oracle.jsonl" \
  --kernel-stderr "$WORK/kernel_oracle.stderr" \
  --build-log "$WORK/build.log" \
  --bpf-object "$WORK/build/wm.bpf.o" \
  --source src/wm.bpf.c \
  --created-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 -m linux_r.audit "$OUTPUT" --require-kernel --write
