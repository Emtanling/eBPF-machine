#!/usr/bin/env bash
# Rebuild and validate the bounded data-parametric residual-circuit interpreter.
# Every result is placed under one fresh, content-addressed run directory.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUN_ID="${RUN_ID:-interpreter-$(date -u +%Y%m%dT%H%M%SZ)-$(cat /proc/sys/kernel/random/uuid)}"
if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
  echo "invalid RUN_ID: use only letters, digits, '.', '_' and '-'" >&2
  exit 2
fi

RUN_ROOT="$ROOT/results/interpreter/$RUN_ID"
VARIANT_ROOT="$RUN_ROOT/variants"
PIN_TAG="${RUN_ID//[^A-Za-z0-9_]/_}"
if [[ -e "$RUN_ROOT" ]]; then
  echo "refusing to overwrite existing run: $RUN_ROOT" >&2
  exit 2
fi
mkdir -p "$RUN_ROOT" "$VARIANT_ROOT" "$RUN_ROOT/descriptors"

KNOWN_NAMES=(const_one nand not and or xor mux half_adder full_adder)
KNOWN=()
for name in "${KNOWN_NAMES[@]}"; do
  source="circuits/${name}.wmc"
  if [[ ! -f "$source" ]]; then
    python3 scripts/circuit_tool.py compile "circuits/${name}.json" "$source"
  fi
  target="$RUN_ROOT/descriptors/${name}.wmc"
  install -m 0444 "$source" "$target"
  KNOWN+=("$target")
done

sudo -v

capture_environment() {
  sudo bpftool feature probe kernel > "$RUN_ROOT/feature_probe.txt"
  {
    uname -a
    clang --version
    cc --version
    python3 --version
    bpftool version
    pkg-config --modversion libbpf
    sha256sum /sys/kernel/btf/vmlinux
    sha256sum src/vmlinux.h
  } > "$RUN_ROOT/environment.txt"
}

build_variant() {
  local label="$1"
  shift
  local variant="$VARIANT_ROOT/$label"
  mkdir -p "$variant"
  make -B build/wm_vm_user "$@" > "$variant/build.log" 2>&1
  install -m 0444 build/wm.bpf.o "$variant/wm.bpf.o"
  install -m 0555 build/wm_vm_user "$variant/wm_vm_user"
}

capture_verifier() {
  local label="$1"
  local variant="$VARIANT_ROOT/$label"
  local pin="/sys/fs/bpf/wm_interpreter_${PIN_TAG}_${label}_$$"

  sudo bpftool -d prog loadall "$variant/wm.bpf.o" "$pin" \
    > "$variant/verifier.log" 2>&1
  sudo bpftool prog dump xlated pinned "$pin/wm_circuit" \
    > "$variant/wm_circuit.xlated.txt" 2>> "$variant/verifier.log"
  sudo bpftool prog show pinned "$pin/wm_circuit" \
    > "$variant/wm_circuit.prog.txt"
  sudo rm -rf "$pin"
}

run_known() {
  local label="$1"
  local output="$2"
  local variant="$VARIANT_ROOT/$label"
  sudo env WM_BPF_OBJECT="$variant/wm.bpf.o" "$variant/wm_vm_user" \
    batch "${KNOWN[@]}" > "$output"
}

snapshot_sources() {
  local sources=(
    Makefile
    src/wm.bpf.c
    src/wm_common.h
    src/wm_vm_user.c
    scripts/circuit_tool.py
    scripts/audit_interpreter.py
    scripts/write_interpreter_provenance.py
    scripts/run_interpreter_suite.sh
    tests/test_circuit_tool.py
  )
  local source
  for source in "${sources[@]}"; do
    mkdir -p "$RUN_ROOT/source/$(dirname "$source")"
    install -m 0444 "$source" "$RUN_ROOT/source/$source"
  done
  for source in circuits/*.json; do
    mkdir -p "$RUN_ROOT/source/circuits"
    install -m 0444 "$source" "$RUN_ROOT/source/$source"
  done
  install -m 0444 src/vmlinux.h "$RUN_ROOT/source/src/vmlinux.h"
}

capture_environment

python3 tests/test_circuit_tool.py > "$RUN_ROOT/circuit_tool_tests.txt" 2>&1
make build/test_logic_model > "$RUN_ROOT/logic_model_build.txt" 2>&1
./build/test_logic_model > "$RUN_ROOT/logic_model.txt" 2>&1

build_variant normal
capture_verifier normal
run_known normal "$RUN_ROOT/interpreter_known.jsonl"

NORMAL="$VARIANT_ROOT/normal"
sudo env WM_BPF_OBJECT="$NORMAL/wm.bpf.o" "$NORMAL/wm_vm_user" negative \
  > "$RUN_ROOT/interpreter_negative.jsonl"
sudo env WM_VM_EMIT_GATES=0 WM_BPF_OBJECT="$NORMAL/wm.bpf.o" \
  "$NORMAL/wm_vm_user" stress 10000 \
  "$RUN_ROOT/descriptors/nand.wmc" \
  "$RUN_ROOT/descriptors/full_adder.wmc" \
  "$RUN_ROOT/descriptors/mux.wmc" \
  > "$RUN_ROOT/interpreter_stress.jsonl"
python3 scripts/circuit_tool.py corpus "$RUN_ROOT/corpus" \
  --seed 3235823838 --count 100 --max-inputs 6 --max-gates 24 \
  > "$RUN_ROOT/corpus_generation.json"
sudo env WM_BPF_OBJECT="$NORMAL/wm.bpf.o" "$NORMAL/wm_vm_user" \
  batch "$RUN_ROOT"/corpus/*.wmc > "$RUN_ROOT/interpreter_random.jsonl"
python3 scripts/circuit_tool.py deep "$RUN_ROOT/boundary_deep_512.json" \
  "$RUN_ROOT/boundary_deep_512.wmc" --gates 512 \
  > "$RUN_ROOT/boundary_generation.json"
sudo env WM_BPF_OBJECT="$NORMAL/wm.bpf.o" "$NORMAL/wm_vm_user" \
  run "$RUN_ROOT/boundary_deep_512.wmc" > "$RUN_ROOT/interpreter_boundary.jsonl"
sudo env WM_BPF_OBJECT="$NORMAL/wm.bpf.o" "$NORMAL/wm_vm_user" \
  run "$RUN_ROOT/descriptors/const_one.wmc" > "$RUN_ROOT/interpreter_zero_gate.jsonl"

build_variant cap64 GATE_CAP=64
capture_verifier cap64
run_known cap64 "$RUN_ROOT/interpreter_cap64.jsonl"

build_variant sentinel EXTRA_BPF_CFLAGS=-DWM_FORCE_SENTINEL_B
capture_verifier sentinel
run_known sentinel "$RUN_ROOT/interpreter_sentinel.jsonl"

build_variant baseline EXTRA_BPF_CFLAGS=-DWM_BASELINE_NAND
capture_verifier baseline
run_known baseline "$RUN_ROOT/interpreter_baseline.jsonl"

# Leave the working tree with the normal (capacity-2) object and harness.
make -B build/wm_vm_user > "$RUN_ROOT/restore_normal_build.txt" 2>&1
snapshot_sources
python3 scripts/audit_interpreter.py "$RUN_ROOT" | tee "$RUN_ROOT/interpreter_audit.txt"
python3 scripts/write_interpreter_provenance.py write "$RUN_ROOT" --run-id "$RUN_ID"
python3 scripts/write_interpreter_provenance.py verify "$RUN_ROOT"

echo "interpreter suite complete: $RUN_ROOT"
