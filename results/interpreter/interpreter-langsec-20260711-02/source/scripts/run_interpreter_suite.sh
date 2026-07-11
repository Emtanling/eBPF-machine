#!/usr/bin/env bash
# Rebuild and validate the bounded data-parametric state-mediated interpreter.
# Every result is placed under one fresh, SHA-256 integrity-manifested run directory.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONDONTWRITEBYTECODE=1

RUN_ID="${RUN_ID:-interpreter-$(date -u +%Y%m%dT%H%M%SZ)-$(cat /proc/sys/kernel/random/uuid)}"
if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
  echo "invalid RUN_ID: use only letters, digits, '.', '_' and '-'" >&2
  exit 2
fi

RUN_ROOT="$ROOT/results/interpreter/$RUN_ID"
SOURCE_ROOT="$RUN_ROOT/source"
VARIANT_ROOT="$RUN_ROOT/variants"
PIN_TAG="${RUN_ID//[^A-Za-z0-9_]/_}"
if [[ -e "$RUN_ROOT" ]]; then
  echo "refusing to overwrite existing run: $RUN_ROOT" >&2
  exit 2
fi
mkdir -p "$RUN_ROOT" "$VARIANT_ROOT" "$RUN_ROOT/descriptors"

# A suite constructs multiple variants. Serialize entire runs so a second suite
# cannot replace an object between another suite's build and artifact snapshot.
exec 9>"$ROOT/.interpreter_suite.lock"
if ! flock -n 9; then
  echo "another interpreter suite is already running" >&2
  exit 2
fi

snapshot_sources() {
  local sources=(
    Makefile
    PAPER_DRAFT.md
    PAPER_LANGSEC_REPORT.md
    PAPER_LANGSEC_REPORT.tex
    ARTIFACT.md
    README.md
    INTERPRETER_IMPLEMENTATION_2026-07-10.md
    results/abstraction_gap_witness.md
    results/exploitable_gap.md
    src/wm.bpf.c
    src/wm_common.h
    src/wm_user.c
    src/wm_vm_user.c
    scripts/audit_results.py
    scripts/capture_system_evidence.sh
    scripts/check_results.py
    scripts/circuit_tool.py
    scripts/audit_interpreter.py
    scripts/record_env.py
    scripts/run_kernel_suite.sh
    scripts/write_interpreter_provenance.py
    scripts/write_provenance.py
    scripts/run_interpreter_suite.sh
    tests/test_audit_results.py
    tests/test_circuit_tool.py
    tests/test_logic_model.c
    tests/test_audit_interpreter.py
    tests/test_interpreter_provenance.py
    tests/test_status_mask_source.py
  )
  local source
  for source in "${sources[@]}"; do
    mkdir -p "$SOURCE_ROOT/$(dirname "$source")"
    install -m 0444 "$source" "$SOURCE_ROOT/$source"
  done
  for source in circuits/*.json; do
    mkdir -p "$SOURCE_ROOT/circuits"
    install -m 0444 "$source" "$SOURCE_ROOT/$source"
  done
  if [[ -f src/vmlinux.h ]]; then
    install -m 0444 src/vmlinux.h "$SOURCE_ROOT/src/vmlinux.h"
  else
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$SOURCE_ROOT/src/vmlinux.h"
  fi
}

snapshot_sources

KNOWN_NAMES=(const_one nand not and or xor mux half_adder full_adder)
KNOWN=()
for name in "${KNOWN_NAMES[@]}"; do
  target="$RUN_ROOT/descriptors/${name}.wmc"
  python3 "$SOURCE_ROOT/scripts/circuit_tool.py" compile \
    "$SOURCE_ROOT/circuits/${name}.json" "$target" > /dev/null
  KNOWN+=("$target")
done

sudo -v

capture_environment() {
  sudo bpftool feature probe kernel > "$RUN_ROOT/feature_probe.txt"
  {
    cat /etc/os-release
    uname -a
    clang --version
    cc --version
    python3 --version
    bpftool version
    pkg-config --modversion libbpf
    sha256sum /sys/kernel/btf/vmlinux
    sha256sum "$SOURCE_ROOT/src/vmlinux.h"
  } > "$RUN_ROOT/environment.txt"
}

build_variant() {
  local label="$1"
  shift
  local variant="$VARIANT_ROOT/$label"
  local work="$variant/work"
  mkdir -p "$variant" "$work"
  make -C "$SOURCE_ROOT" BUILD="$work" "$work/wm_vm_user" "$@" \
    > "$variant/build.log" 2>&1
  install -m 0444 "$work/wm.bpf.o" "$variant/wm.bpf.o"
  install -m 0555 "$work/wm_vm_user" "$variant/wm_vm_user"
  sha256sum "$variant/wm.bpf.o" "$variant/wm_vm_user" \
    > "$variant/artifact.sha256"
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
  local runtime_log="$3"
  local variant="$VARIANT_ROOT/$label"
  sudo env WM_BPF_OBJECT="$variant/wm.bpf.o" "$variant/wm_vm_user" \
    batch "${KNOWN[@]}" > "$output" 2> "$runtime_log"
}

capture_environment

make -C "$SOURCE_ROOT" BUILD="$RUN_ROOT/unit_build" test \
  > "$RUN_ROOT/source_tests.txt" 2>&1

build_variant normal GATE_CAP=2 EXTRA_BPF_CFLAGS=
capture_verifier normal
run_known normal "$RUN_ROOT/interpreter_known.jsonl" \
  "$RUN_ROOT/interpreter_known.runtime.log"

NORMAL="$VARIANT_ROOT/normal"
sudo env WM_BPF_OBJECT="$NORMAL/wm.bpf.o" "$NORMAL/wm_vm_user" negative \
  > "$RUN_ROOT/interpreter_negative.jsonl" \
  2> "$RUN_ROOT/interpreter_negative.runtime.log"
sudo env WM_VM_EMIT_GATES=0 WM_BPF_OBJECT="$NORMAL/wm.bpf.o" \
  "$NORMAL/wm_vm_user" stress 10000 \
  "$RUN_ROOT/descriptors/nand.wmc" \
  "$RUN_ROOT/descriptors/full_adder.wmc" \
  "$RUN_ROOT/descriptors/mux.wmc" \
  > "$RUN_ROOT/interpreter_stress.jsonl" \
  2> "$RUN_ROOT/interpreter_stress.runtime.log"
python3 "$SOURCE_ROOT/scripts/circuit_tool.py" corpus "$RUN_ROOT/corpus" \
  --seed 3235823838 --count 100 --max-inputs 6 --max-gates 24 \
  > "$RUN_ROOT/corpus_generation.json"
sudo env WM_BPF_OBJECT="$NORMAL/wm.bpf.o" "$NORMAL/wm_vm_user" \
  batch "$RUN_ROOT"/corpus/*.wmc > "$RUN_ROOT/interpreter_random.jsonl" \
  2> "$RUN_ROOT/interpreter_random.runtime.log"
python3 "$SOURCE_ROOT/scripts/circuit_tool.py" deep "$RUN_ROOT/boundary_deep_512.json" \
  "$RUN_ROOT/boundary_deep_512.wmc" --gates 512 \
  > "$RUN_ROOT/boundary_generation.json"
sudo env WM_BPF_OBJECT="$NORMAL/wm.bpf.o" "$NORMAL/wm_vm_user" \
  run "$RUN_ROOT/boundary_deep_512.wmc" > "$RUN_ROOT/interpreter_boundary.jsonl" \
  2> "$RUN_ROOT/interpreter_boundary.runtime.log"
python3 "$SOURCE_ROOT/scripts/circuit_tool.py" full-boundary \
  "$RUN_ROOT/boundary_full_64_512.json" "$RUN_ROOT/boundary_full_64_512.wmc" \
  > "$RUN_ROOT/full_boundary_generation.json"
sudo env WM_BPF_OBJECT="$NORMAL/wm.bpf.o" "$NORMAL/wm_vm_user" \
  fixed "$RUN_ROOT/boundary_full_64_512.wmc" 0 18446744073709551615 \
  > "$RUN_ROOT/interpreter_full_boundary.jsonl" \
  2> "$RUN_ROOT/interpreter_full_boundary.runtime.log"
sudo env WM_BPF_OBJECT="$NORMAL/wm.bpf.o" "$NORMAL/wm_vm_user" \
  run "$RUN_ROOT/descriptors/const_one.wmc" > "$RUN_ROOT/interpreter_zero_gate.jsonl" \
  2> "$RUN_ROOT/interpreter_zero_gate.runtime.log"

build_variant cap64 GATE_CAP=64 EXTRA_BPF_CFLAGS=
capture_verifier cap64
run_known cap64 "$RUN_ROOT/interpreter_cap64.jsonl" \
  "$RUN_ROOT/interpreter_cap64.runtime.log"

build_variant sentinel GATE_CAP=2 EXTRA_BPF_CFLAGS=-DWM_FORCE_SENTINEL_B
capture_verifier sentinel
run_known sentinel "$RUN_ROOT/interpreter_sentinel.jsonl" \
  "$RUN_ROOT/interpreter_sentinel.runtime.log"

build_variant baseline GATE_CAP=2 EXTRA_BPF_CFLAGS=-DWM_BASELINE_NAND
capture_verifier baseline
run_known baseline "$RUN_ROOT/interpreter_baseline.jsonl" \
  "$RUN_ROOT/interpreter_baseline.runtime.log"

python3 "$SOURCE_ROOT/scripts/audit_interpreter.py" "$RUN_ROOT" | \
  tee "$RUN_ROOT/interpreter_audit.txt"
python3 "$SOURCE_ROOT/scripts/write_interpreter_provenance.py" write \
  "$RUN_ROOT" --run-id "$RUN_ID"
python3 "$SOURCE_ROOT/scripts/write_interpreter_provenance.py" verify "$RUN_ROOT"

echo "interpreter suite complete: $RUN_ROOT"
