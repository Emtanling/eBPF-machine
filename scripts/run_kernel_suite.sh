#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p results
: > results/check_summary.txt

sudo -v

# Bind every result set to the exact binary that produced it: record the bpf
# object hash + build flags, capture a per-variant verifier log, and dump the
# xlated (post-verifier) instructions of wm_nand so an auditor can confirm the
# output is a helper return value, not an ALU result on the inputs.
record_variant() {
  local label="$1"; shift
  local flags="$*"
  local obj="build/wm.bpf.o"
  local meta="results/${label}.provenance.json"
  local vlog="results/${label}.verifier.log"
  local xlated="results/${label}.wm_nand.xlated.txt"
  local sha; sha="$(sha256sum "$obj" | awk '{print $1}')"
  local pin="/sys/fs/bpf/wm_${label}_$$"

  : > "$vlog"
  set +e
  sudo bpftool -d prog loadall "$obj" "$pin" >> "$vlog" 2>&1
  local rc=$?
  set -e

  if sudo test -e "$pin/wm_nand"; then
    echo "== xlated wm_nand ==" >> "$vlog"
    sudo bpftool prog dump xlated pinned "$pin/wm_nand" | tee -a "$vlog" > "$xlated" 2>/dev/null || true
  fi
  if sudo test -e "$pin"; then sudo rm -rf "$pin"; fi

  local vsha; vsha="$(sha256sum "$vlog" | awk '{print $1}')"
  cat > "$meta" <<META
{
  "label": "${label}",
  "build_flags": "${flags}",
  "bpf_object_sha256": "${sha}",
  "verifier_log": "$(basename "$vlog")",
  "verifier_log_sha256": "${vsha}",
  "bpftool_loadall_exit": ${rc}
}
META
  echo "provenance ${label}: obj=${sha} loadall_exit=${rc}"
}

run_checked() {
  local label="$1"
  local outfile="$2"
  shift 2
  echo "== $label =="
  "$@" > "$outfile" 2> "results/${label}.stderr"
  python3 scripts/check_results.py "$outfile" | tee -a results/check_summary.txt
}

echo "== logic model =="
make clean
make test | tee results/logic_model.txt

echo "== normal build =="
make all
echo "== system evidence =="
scripts/capture_system_evidence.sh
record_variant nand GATE_CAP=2
python3 scripts/record_env.py > results/env.json
run_checked nand results/nand_truth_table.jsonl sudo ./build/wm_user nand 100
run_checked full_adder results/full_adder.jsonl sudo ./build/wm_user fa
run_checked adder32 results/adder32.jsonl sudo ./build/wm_user adder 1000
run_checked adder32_exhaustive results/adder32_exhaustive.jsonl \
  sudo ./build/wm_user adder-exhaustive 8

echo "== ablation: cap64 =="
make clean
make all GATE_CAP=64
record_variant ablation_cap64 GATE_CAP=64
run_checked ablation_cap64 results/ablation_cap64.jsonl sudo ./build/wm_user nand-all1 100

echo "== ablation: second input uses sentinel =="
make clean
make all EXTRA_BPF_CFLAGS=-DWM_FORCE_SENTINEL_B
record_variant ablation_k2_sentinel "GATE_CAP=2 -DWM_FORCE_SENTINEL_B"
run_checked ablation_k2_sentinel results/ablation_k2_sentinel.jsonl sudo ./build/wm_user nand-all1 100

echo "== baseline: explicit eBPF NAND =="
make clean
make all EXTRA_BPF_CFLAGS=-DWM_BASELINE_NAND
record_variant baseline_nand "GATE_CAP=2 -DWM_BASELINE_NAND"
run_checked baseline_nand results/baseline_nand.jsonl sudo ./build/wm_user nand 100

echo "== restore normal build =="
make clean
make all
scripts/capture_system_evidence.sh
record_variant nand GATE_CAP=2
python3 scripts/record_env.py > results/env.json

echo "== semantic audit =="
python3 scripts/audit_results.py --full-suite results | tee results/audit_summary.txt

echo "suite complete"
