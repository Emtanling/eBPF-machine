#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")/.." && pwd)
ROOT=$(cd "$HERE/.." && pwd)
OUT=${1:-$ROOT/output/linux-live}
BACKEND=${RAC_BACKEND:-fexit}
PIN_DIR=${RAC_PIN_DIR:-/sys/fs/bpf/rac-v03}
PIN_PATH="$PIN_DIR/rac_single"
OBJ="$HERE/build/rac_witness.bpf.o"
EVENTS_RAW="$OUT/events.raw.jsonl"
EVENTS="$OUT/events.jsonl"
mkdir -p "$OUT"

"$HERE/scripts/preflight.sh"
make -C "$HERE" all

# Preserve the emitted ELF-object CFG for comparison. Its instruction numbers
# are function-local; the kernel-linked xlated dump below is authoritative for
# verifier visit_insn values.
if command -v llvm-objdump >/dev/null 2>&1; then
  llvm-objdump -d --no-show-raw-insn "$OBJ" \
    > "$OUT/object-disassembly.txt"
elif command -v llvm-objdump-18 >/dev/null 2>&1; then
  llvm-objdump-18 -d --no-show-raw-insn "$OBJ" \
    > "$OUT/object-disassembly.txt"
fi

OBJ_SHA=$(sha256sum "$OBJ" | awk '{print $1}')
printf '%s  %s\n' "$OBJ_SHA" "$OBJ" > "$OUT/object.sha256"

case "$BACKEND" in
  fexit) COLLECTOR="$HERE/build/rac-collect-fexit" ;;
  kprobe) COLLECTOR="$HERE/build/rac-collect-kprobe" ;;
  *) echo "RAC_BACKEND must be fexit or kprobe" >&2; exit 2 ;;
esac

# Pin the exact program instance loaded by rac-witness. This keeps its kernel
# ID alive after the libbpf skeleton is destroyed and binds the xlated dump to
# the same program tag/ID used by the evidence capture.
if ! mountpoint -q /sys/fs/bpf; then
  sudo mount -t bpf bpf /sys/fs/bpf
fi
sudo mkdir -p "$PIN_DIR"
sudo rm -f "$PIN_PATH"

sudo "$COLLECTOR" -o "$EVENTS_RAW" -c rac-witness -d 0 &
COLLECTOR_PID=$!
trap 'sudo kill -INT "$COLLECTOR_PID" 2>/dev/null || true' EXIT
sleep 1
sudo env RAC_PIN_PATH="$PIN_PATH" \
  "$HERE/build/rac-witness" "$OUT/runtime.json"

# Add the ELF-object digest to the runtime evidence record. The program tag and
# program ID identify the loaded kernel object; this SHA-256 binds that object
# back to the archived input ELF.
python3 - "$OUT/runtime.json" "$OBJ_SHA" "$PIN_PATH" <<'PY'
import json
import os
import sys

path, obj_sha, pin_path = sys.argv[1:]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
data["object_sha256"] = obj_sha
data["program_pin"] = pin_path
new_path = path + ".tmp"
with open(new_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, sort_keys=False)
    f.write("\n")
os.replace(new_path, path)
PY

# Dump the exact kernel-linked program. visit_insn indices in verifier events
# refer to this global xlated instruction stream, not to llvm-objdump's
# function-local numbering.
sudo bpftool -j prog show pinned "$PIN_PATH" \
  > "$OUT/program-info.json"
if ! sudo bpftool prog dump xlated pinned "$PIN_PATH" opcodes linum \
       > "$OUT/xlated-rac_single.txt"; then
  sudo bpftool prog dump xlated pinned "$PIN_PATH" opcodes \
    > "$OUT/xlated-rac_single.txt"
fi
XLATED_SHA=$(sha256sum "$OUT/xlated-rac_single.txt" | awk '{print $1}')
printf '%s  %s\n' "$XLATED_SHA" "xlated-rac_single.txt" \
  > "$OUT/xlated-rac_single.sha256"
python3 - "$OUT/runtime.json" "$XLATED_SHA" <<'PY'
import json
import os
import sys

path, xlated_sha = sys.argv[1:]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
data["xlated_sha256"] = xlated_sha
new_path = path + ".tmp"
with open(new_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, sort_keys=False)
    f.write("\n")
os.replace(new_path, path)
PY
printf '%s\n' "$PIN_PATH" > "$OUT/program-pin.txt"

sleep 1
sudo kill -INT "$COLLECTOR_PID" || true
wait "$COLLECTOR_PID" || true
trap - EXIT

python3 "$HERE/scripts/enrich_events.py" "$EVENTS_RAW" "$EVENTS" \
  --runtime "$OUT/runtime.json" \
  --program-info "$OUT/program-info.json" \
  --object-sha "$OUT/object.sha256" \
  --program-pin "$OUT/program-pin.txt" \
  --xlated-sha "$OUT/xlated-rac_single.sha256"

python3 "$HERE/scripts/make_contract.py" "$OUT/runtime.json" "$OUT/contract.json"
PYTHONPATH="$ROOT/src" python3 -m residuality_auditor.cli linux-r \
  "$EVENTS" "$OUT/runtime.json" "$OUT/contract.json" \
  --json-out "$OUT/analysis.json" --md-out "$OUT/analysis.md"

if command -v jq >/dev/null 2>&1; then
  "$HERE/scripts/screen_prunes.sh" "$EVENTS" rac_single \
    > "$OUT/prune-screen.tsv"
fi

echo "Linux evidence bundle: $OUT"
echo "Pinned exact program: $PIN_PATH"
echo "Kernel-linked dump: $OUT/xlated-rac_single.txt"
echo "Cleanup after inspection: sudo rm -f '$PIN_PATH'"
echo "Default verdict is a candidate unless report-contract and concretization reviews are supplied."
