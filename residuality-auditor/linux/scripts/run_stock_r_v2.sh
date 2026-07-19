#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")/.." && pwd)
ROOT=$(cd "$HERE/.." && pwd)
REPO_ROOT=$(cd "$ROOT/.." && pwd)
RUN_ID=${RAC_V2_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
OUT=${1:-$ROOT/output/stock-r-v2-live-$RUN_ID}
TRIALS=${RAC_V2_TRIALS:-4}
PIN_DIR=${RAC_V2_PIN_DIR:-/sys/fs/bpf/rac-v2-$RUN_ID}
PIN_PATH="$PIN_DIR/rac_v2_single"
OBJ_BUILD="$HERE/build/rac_v2_witness.bpf.o"
TRACER_OBJ_BUILD="$HERE/build/rac_v2_tracer_fentry.bpf.o"
COLLECTOR="$HERE/build/rac-v2-collect-fentry"
WITNESS="$HERE/build/rac-v2-witness"
OBJ="$OUT/build/rac_v2_witness.bpf.o"
BTF="$OUT/build/btf-vmlinux"
EVENTS="$OUT/raw/events.jsonl"
RUNTIME="$OUT/raw/runtime.json"

if [[ ! "$TRIALS" =~ ^[0-9]+$ ]] || (( TRIALS < 4 || TRIALS % 2 )); then
  echo "RAC_V2_TRIALS must be an even integer >= 4" >&2
  exit 2
fi

case "$PIN_DIR" in
  /sys/fs/bpf/rac-v2*) ;;
  *)
    echo "RAC_V2_PIN_DIR must be under /sys/fs/bpf/rac-v2*" >&2
    exit 2
    ;;
esac

if [[ -e "$OUT" ]]; then
  echo "output path already exists; choose a fresh V2 directory: $OUT" >&2
  exit 2
fi
mkdir -p "$OUT/raw" "$OUT/build" "$OUT/audit" "$OUT/proof"
"$HERE/scripts/preflight.sh"
make -C "$HERE" build/rac-v2-collect-fentry build/rac-v2-witness

KERNEL_RELEASE=$(uname -r)

python3 "$HERE/scripts/stock_r_v2.py" source-closure "$OUT" \
  --source-root "$REPO_ROOT" \
  --source "$REPO_ROOT/Makefile" \
  --source "$REPO_ROOT/docs/design/ebrc-u0-definition-freeze.md" \
  --source "$REPO_ROOT/docs/design/ebrc-u1-hostile-derivability-gate.md" \
  --source "$REPO_ROOT/docs/design/evidence-bounded-residual-certification.md" \
  --source "$REPO_ROOT/docs/design/stock-r-v2-experiment.md" \
  --source "$REPO_ROOT/docs/plans/2026-07-19-006-feat-stock-r-v2-must-outcome-proof-plan.md" \
  --source "$REPO_ROOT/docs/plans/2026-07-19-007-evidence-bounded-residual-certification-plan.md" \
  --source "$REPO_ROOT/residuality-auditor/README.md" \
  --source "$REPO_ROOT/residuality-auditor/REPRODUCE.md" \
  --source "$REPO_ROOT/residuality-auditor/linux/Makefile" \
  --source "$REPO_ROOT/residuality-auditor/linux/README.md" \
  --source "$REPO_ROOT/residuality-auditor/linux/include/rac_v2_events.h" \
  --source "$REPO_ROOT/residuality-auditor/linux/scripts/preflight.sh" \
  --source "$REPO_ROOT/residuality-auditor/linux/scripts/run_stock_r_v2.sh" \
  --source "$REPO_ROOT/residuality-auditor/linux/scripts/stock_r_v2.py" \
  --source "$REPO_ROOT/residuality-auditor/linux/tracer/rac_v2_collect_fentry.c" \
  --source "$REPO_ROOT/residuality-auditor/linux/tracer/rac_v2_tracer_common.bpf.h" \
  --source "$REPO_ROOT/residuality-auditor/linux/tracer/rac_v2_tracer_fentry.bpf.c" \
  --source "$REPO_ROOT/residuality-auditor/linux/tracer/state_collector.c" \
  --source "$REPO_ROOT/residuality-auditor/linux/tracer/verifier_state_v2.h" \
  --source "$REPO_ROOT/residuality-auditor/linux/witness/rac_v2_witness.bpf.c" \
  --source "$REPO_ROOT/residuality-auditor/linux/witness/rac_v2_witness.c" \
  --source "$REPO_ROOT/residuality-auditor/linux/witness/rac_v2_witness.h" \
  --source "$REPO_ROOT/residuality-auditor/src/residuality_auditor/stock_r_v2.py" \
  --source "$REPO_ROOT/residuality-auditor/tests/test_stock_r_v2.py" \
  > "$OUT/build/source-closure-digest.txt"

python3 "$HERE/scripts/stock_r_v2.py" artifact-closure "$OUT" \
  --artifact "rac_v2_witness.bpf.o=$OBJ_BUILD" \
  --artifact "rac_v2_tracer_fentry.bpf.o=$TRACER_OBJ_BUILD" \
  --artifact "rac-v2-collect-fentry=$COLLECTOR" \
  --artifact "rac-v2-witness=$WITNESS" \
  --artifact "btf-vmlinux=/sys/kernel/btf/vmlinux" \
  > "$OUT/build/artifact-closure-digest.txt"

OBJ_SHA=$(sha256sum "$OBJ" | awk '{print $1}')
BTF_SHA=$(sha256sum "$BTF" | awk '{print $1}')
printf '%s\n' "$KERNEL_RELEASE" > "$OUT/build/kernel-release.txt"
printf '%s  %s\n' "$BTF_SHA" btf-vmlinux > "$OUT/build/btf.sha256"
printf '%s  %s\n' "$OBJ_SHA" rac_v2_witness.bpf.o > "$OUT/build/object.sha256"

python3 "$HERE/scripts/stock_r_v2.py" prepare "$OUT" \
  --object "$OBJ" \
  --btf "$BTF" \
  --source-manifest "$OUT/build/source-manifest.json" \
  --artifact-manifest "$OUT/build/artifact-manifest.json" \
  --kernel-release "$KERNEL_RELEASE" \
  --trials "$TRIALS" \
  > "$OUT/build/query-digest.txt"

if ! mountpoint -q /sys/fs/bpf; then
  sudo mount -t bpf bpf /sys/fs/bpf
fi
if sudo test -e "$PIN_DIR"; then
  echo "pin directory already exists; choose a fresh RAC_V2_PIN_DIR: $PIN_DIR" >&2
  exit 2
fi
sudo mkdir "$PIN_DIR"

COLLECTOR_PID=""
COLLECTOR_STATUS=0
cleanup_collector() {
  if [[ -n "$COLLECTOR_PID" ]]; then
    sudo kill -INT "$COLLECTOR_PID" 2>/dev/null || true
    set +e
    wait "$COLLECTOR_PID" 2>/dev/null
    COLLECTOR_STATUS=$?
    set -e
    COLLECTOR_PID=""
  fi
}
trap cleanup_collector EXIT

sudo "$COLLECTOR" -o "$EVENTS" -c rac-v2-witness -d 0 &
COLLECTOR_PID=$!
sleep 1

set +e
sudo env RAC_V2_PIN_PATH="$PIN_PATH" \
  RAC_V2_OBJECT_SHA256="$OBJ_SHA" \
  RAC_V2_BTF_SHA256="$BTF_SHA" \
  "$WITNESS" -o "$RUNTIME" -n "$TRIALS"
WITNESS_STATUS=$?
set -e

sleep 1
cleanup_collector
trap - EXIT

XLATED_STATUS=0
if sudo test -e "$PIN_PATH"; then
  sudo bpftool -j prog show pinned "$PIN_PATH" > "$OUT/raw/program-info.json"
  if ! sudo bpftool prog dump xlated pinned "$PIN_PATH" opcodes linum > "$OUT/raw/xlated-rac_v2_single.txt"; then
    XLATED_STATUS=1
    sudo bpftool prog dump xlated pinned "$PIN_PATH" opcodes > "$OUT/raw/xlated-rac_v2_single.txt" || true
  fi
  XLATED_SHA=$(sha256sum "$OUT/raw/xlated-rac_v2_single.txt" | awk '{print $1}')
  printf '%s  %s\n' "$XLATED_SHA" xlated-rac_v2_single.txt > "$OUT/raw/xlated-rac_v2_single.sha256"
  if [[ -f "$RUNTIME" ]]; then
    python3 "$HERE/scripts/stock_r_v2.py" seal-runtime "$OUT" \
      --xlated "$OUT/raw/xlated-rac_v2_single.txt"
    python3 "$HERE/scripts/stock_r_v2.py" prove-outcomes "$OUT" \
      > "$OUT/proof/must-outcome-proof-digest.txt"
    python3 "$HERE/scripts/stock_r_v2.py" bind-history-case "$OUT" \
      > "$OUT/proof/history-case-binding-digest.txt"
  fi
else
  XLATED_STATUS=1
fi

AUDIT_STATUS=0
if [[ -f "$EVENTS" && -f "$RUNTIME" && -f "$OUT/raw/xlated-rac_v2_single.txt" ]]; then
  set +e
  python3 "$HERE/scripts/stock_r_v2.py" audit "$OUT" \
    > "$OUT/audit/assessment-status.txt"
  AUDIT_STATUS=$?
  set -e
else
  AUDIT_STATUS=2
fi

printf '%s\n' "$COLLECTOR_STATUS" > "$OUT/audit/collector-exit-status.txt"
printf '%s\n' "$WITNESS_STATUS" > "$OUT/audit/witness-exit-status.txt"
printf '%s\n' "$XLATED_STATUS" > "$OUT/audit/xlated-exit-status.txt"
printf '%s\n' "$AUDIT_STATUS" > "$OUT/audit/audit-exit-status.txt"
python3 "$HERE/scripts/stock_r_v2.py" manifest "$OUT"

echo "Stock-R V2 evidence bundle: $OUT"
echo "Pinned exact program: $PIN_PATH"
echo "Cleanup after inspection: sudo rm -f '$PIN_PATH'"

if (( WITNESS_STATUS != 0 || XLATED_STATUS != 0 || AUDIT_STATUS != 0 )); then
  exit 1
fi
