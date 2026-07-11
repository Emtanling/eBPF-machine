#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p results
: > results/check_summary.txt

RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$(cat /proc/sys/kernel/random/uuid)}"
if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
  echo "invalid RUN_ID: use only letters, digits, '.', '_' and '-'" >&2
  exit 2
fi
RUN_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
VARIANT_ROOT="${ROOT}/results/variants/${RUN_ID}"
if [[ -e "$VARIANT_ROOT" ]]; then
  echo "refusing to overwrite existing run directory: $VARIANT_ROOT" >&2
  exit 2
fi
mkdir -p "$VARIANT_ROOT"
SOURCE_FILES=(
  Makefile
  src/wm.bpf.c
  src/wm_user.c
  src/wm_common.h
  src/vmlinux.h
  scripts/run_kernel_suite.sh
  scripts/write_provenance.py
  scripts/audit_results.py
  scripts/capture_system_evidence.sh
  scripts/record_env.py
  scripts/check_results.py
)
declare -A VARIANT_OBJ_SHA
declare -A VARIANT_USER_SHA

sudo -v

# Preserve and exercise the exact per-variant object and userspace harness.
# "xlated" is verified/transformed eBPF bytecode, not JIT-native machine code.
prepare_variant() {
  local label="$1"
  local variant_dir="${VARIANT_ROOT}/${label}"
  local obj="${variant_dir}/wm.bpf.o"
  local user="${variant_dir}/wm_user"
  local vlog="results/${label}.verifier.log"
  local xlated="results/${label}.wm_nand.xlated.txt"
  local pin="/sys/fs/bpf/wm_${label}_$$"

  mkdir -p "$variant_dir"
  install -m 0444 build/wm.bpf.o "$obj"
  install -m 0555 build/wm_user "$user"
  local source
  for source in "${SOURCE_FILES[@]}"; do
    mkdir -p "${variant_dir}/source/$(dirname "$source")"
    install -m 0444 "$source" "${variant_dir}/source/${source}"
  done
  VARIANT_OBJ_SHA[$label]="$(sha256sum "$obj" | awk '{print $1}')"
  VARIANT_USER_SHA[$label]="$(sha256sum "$user" | awk '{print $1}')"
  : > "$vlog"
  : > "$xlated"
  set +e
  sudo bpftool -d prog loadall "$obj" "$pin" >> "$vlog" 2>&1
  local rc=$?
  local dump_rc=1
  if sudo test -e "$pin/wm_nand"; then
    sudo bpftool prog dump xlated pinned "$pin/wm_nand" > "$xlated" 2>> "$vlog"
    dump_rc=$?
  fi
  if sudo test -e "$pin"; then sudo rm -rf "$pin"; fi
  set -e

  {
    echo
    echo "== xlated wm_nand (verified eBPF bytecode; not JIT native code) =="
    cat "$xlated"
    echo "bpftool_loadall_exit=${rc}"
    echo "bpftool_xlated_dump_exit=${dump_rc}"
  } >> "$vlog"

  if [[ $rc -ne 0 || $dump_rc -ne 0 || ! -s "$xlated" ]]; then
    echo "variant ${label}: verifier load or xlated dump failed" >&2
    return 1
  fi
  assert_variant_unchanged "$label"
}

assert_variant_unchanged() {
  local label="$1"
  local obj="${VARIANT_ROOT}/${label}/wm.bpf.o"
  local user="${VARIANT_ROOT}/${label}/wm_user"
  local actual_obj="$(sha256sum "$obj" | awk '{print $1}')"
  local actual_user="$(sha256sum "$user" | awk '{print $1}')"
  if [[ "$actual_obj" != "${VARIANT_OBJ_SHA[$label]}" ]]; then
    echo "variant ${label}: object changed after verifier capture" >&2
    return 1
  fi
  if [[ "$actual_user" != "${VARIANT_USER_SHA[$label]}" ]]; then
    echo "variant ${label}: userspace harness changed before provenance finalization" >&2
    return 1
  fi
}

finalize_variant() {
  local label="$1"
  local flags="$2"
  shift 2
  local result_args=()
  local source_args=()
  local result
  assert_variant_unchanged "$label"
  for result in "$@"; do
    result_args+=(--result "$result")
  done
  local source
  for source in "${SOURCE_FILES[@]}"; do
    source_args+=(--source "$source" "${VARIANT_ROOT}/${label}/source/${source}")
  done

  python3 scripts/write_provenance.py \
    --results-dir results \
    --label "$label" \
    --run-id "$RUN_ID" \
    --timestamp-utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --build-flags "$flags" \
    --bpftool-loadall-exit 0 \
    --environment results/env.json \
    --bpf-object "${VARIANT_ROOT}/${label}/wm.bpf.o" \
    --user-binary "${VARIANT_ROOT}/${label}/wm_user" \
    --verifier-log "results/${label}.verifier.log" \
    --xlated-dump "results/${label}.wm_nand.xlated.txt" \
    --build-log "results/${label}.build.log" \
    "${source_args[@]}" \
    "${result_args[@]}"
}

run_checked() {
  local label="$1"
  local variant_label="$2"
  local outfile="$3"
  shift 3
  echo "== $label =="
  assert_variant_unchanged "$variant_label"
  "$@" > "$outfile" 2> "results/${label}.stderr"
  assert_variant_unchanged "$variant_label"
  python3 scripts/check_results.py "$outfile" | tee -a results/check_summary.txt
}

build_variant() {
  local label="$1"
  shift
  make clean
  make all "$@" 2>&1 | tee "results/${label}.build.log"
}

echo "== logic model =="
echo "run_id=${RUN_ID} started_at=${RUN_TIMESTAMP}"
make clean
make test | tee results/logic_model.txt

echo "== normal build =="
build_variant nand
echo "== system evidence =="
scripts/capture_system_evidence.sh
python3 scripts/record_env.py > results/env.json
prepare_variant nand
run_checked nand nand results/nand_truth_table.jsonl \
  sudo env WM_BPF_OBJECT="${VARIANT_ROOT}/nand/wm.bpf.o" \
  "${VARIANT_ROOT}/nand/wm_user" nand 100
run_checked full_adder nand results/full_adder.jsonl \
  sudo env WM_BPF_OBJECT="${VARIANT_ROOT}/nand/wm.bpf.o" \
  "${VARIANT_ROOT}/nand/wm_user" fa
run_checked adder32 nand results/adder32.jsonl \
  sudo env WM_BPF_OBJECT="${VARIANT_ROOT}/nand/wm.bpf.o" \
  "${VARIANT_ROOT}/nand/wm_user" adder 1000
run_checked adder32_exhaustive nand results/adder32_exhaustive.jsonl \
  sudo env WM_BPF_OBJECT="${VARIANT_ROOT}/nand/wm.bpf.o" \
  "${VARIANT_ROOT}/nand/wm_user" adder-exhaustive 8
finalize_variant nand GATE_CAP=2 \
  results/nand_truth_table.jsonl results/full_adder.jsonl \
  results/adder32.jsonl results/adder32_exhaustive.jsonl

echo "== ablation: cap64 =="
build_variant ablation_cap64 GATE_CAP=64
prepare_variant ablation_cap64
run_checked ablation_cap64 ablation_cap64 results/ablation_cap64.jsonl \
  sudo env WM_BPF_OBJECT="${VARIANT_ROOT}/ablation_cap64/wm.bpf.o" \
  "${VARIANT_ROOT}/ablation_cap64/wm_user" nand-all1 100
finalize_variant ablation_cap64 GATE_CAP=64 results/ablation_cap64.jsonl

echo "== ablation: second input uses sentinel =="
build_variant ablation_k2_sentinel EXTRA_BPF_CFLAGS=-DWM_FORCE_SENTINEL_B
prepare_variant ablation_k2_sentinel
run_checked ablation_k2_sentinel ablation_k2_sentinel results/ablation_k2_sentinel.jsonl \
  sudo env WM_BPF_OBJECT="${VARIANT_ROOT}/ablation_k2_sentinel/wm.bpf.o" \
  "${VARIANT_ROOT}/ablation_k2_sentinel/wm_user" nand-all1 100
finalize_variant ablation_k2_sentinel "GATE_CAP=2 -DWM_FORCE_SENTINEL_B" \
  results/ablation_k2_sentinel.jsonl

echo "== baseline: explicit eBPF NAND =="
build_variant baseline_nand EXTRA_BPF_CFLAGS=-DWM_BASELINE_NAND
prepare_variant baseline_nand
run_checked baseline_nand baseline_nand results/baseline_nand.jsonl \
  sudo env WM_BPF_OBJECT="${VARIANT_ROOT}/baseline_nand/wm.bpf.o" \
  "${VARIANT_ROOT}/baseline_nand/wm_user" nand 100
finalize_variant baseline_nand "GATE_CAP=2 -DWM_BASELINE_NAND" \
  results/baseline_nand.jsonl

echo "== restore normal build =="
make clean
make all

echo "== semantic audit =="
python3 scripts/audit_results.py --full-suite results | tee results/audit_summary.txt

echo "suite complete"
