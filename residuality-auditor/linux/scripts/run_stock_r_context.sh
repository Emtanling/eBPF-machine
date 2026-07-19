#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")/.." && pwd)
ROOT=$(cd "$HERE/.." && pwd)
REPO_ROOT=$(cd "$ROOT/.." && pwd)
PYTHON=${PYTHON:-python3}
BASE=${1:?usage: run_stock_r_context.sh BASE_STOCK_R_V2_BUNDLE [OUT]}
RUN_ID=${RAC_CONTEXT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
OUT=${2:-$ROOT/output/stock-r-context-live-$RUN_ID}
TRIALS=${RAC_CONTEXT_TRIALS:-4}
PIN_DIR=${RAC_CONTEXT_PIN_DIR:-/sys/fs/bpf/rac-v2-context-$RUN_ID}
PIN_PATH="$PIN_DIR/rac_v2_single"
WORK="$OUT/work/linux"
VARIANT=${RAC_CONTEXT_VARIANT:-post-collision-frame}
CONTEXT_SUITE=${RAC_CONTEXT_SUITE:-}
CONTEXT_CASE_ID=${RAC_CONTEXT_CASE_ID:-}

if { [[ -n "$CONTEXT_SUITE" ]] && [[ -z "$CONTEXT_CASE_ID" ]]; } || \
   { [[ -z "$CONTEXT_SUITE" ]] && [[ -n "$CONTEXT_CASE_ID" ]]; }; then
  echo "RAC_CONTEXT_SUITE and RAC_CONTEXT_CASE_ID must be provided together" >&2
  exit 2
fi

if [[ ! "$TRIALS" =~ ^[0-9]+$ ]] || (( TRIALS < 4 || TRIALS % 2 )); then
  echo "RAC_CONTEXT_TRIALS must be an even integer >= 4" >&2
  exit 2
fi

case "$PIN_DIR" in
  /sys/fs/bpf/rac-v2-context*) ;;
  *)
    echo "RAC_CONTEXT_PIN_DIR must be under /sys/fs/bpf/rac-v2-context*" >&2
    exit 2
    ;;
esac

if [[ -e "$OUT" ]]; then
  echo "output path already exists; choose a fresh context directory: $OUT" >&2
  exit 2
fi

mkdir -p "$OUT/context" "$OUT/source" "$OUT/target/build" "$OUT/target/raw" "$OUT/target/audit" "$OUT/work"
"$HERE/scripts/preflight.sh"
cp -R "$HERE" "$WORK"

if [[ -n "$CONTEXT_SUITE" ]]; then
  GENERATOR_SELECTOR=(--suite "$CONTEXT_SUITE" --case-id "$CONTEXT_CASE_ID")
else
  GENERATOR_SELECTOR=(--variant "$VARIANT")
fi
PYTHONPATH="$ROOT/src:$ROOT" "$PYTHON" "$HERE/scripts/generate_stock_r_context.py" \
  "$HERE/witness/rac_v2_witness.bpf.c" \
  "$WORK/witness/rac_v2_witness.bpf.c" \
  "${GENERATOR_SELECTOR[@]}" \
  --metadata "$OUT/context/transform-metadata.json"

make -C "$WORK" clean v2

PYTHONPATH="$ROOT/src:$ROOT" "$PYTHON" -m residuality_auditor.cli ebrc stock-r-v2 \
  "$BASE" \
  --compiled-out "$OUT/source/compiled" \
  --json-out "$OUT/source/result.json"

OBJ_BUILD="$WORK/build/rac_v2_witness.bpf.o"
WITNESS="$WORK/build/rac-v2-witness"
OBJ="$OUT/target/build/rac_v2_contextual.bpf.o"
BTF="$OUT/target/build/btf-vmlinux"
RUNTIME="$OUT/target/raw/runtime.json"
XLATED="$OUT/target/raw/xlated-rac_v2_contextual.txt"

cp "$OBJ_BUILD" "$OBJ"
cp /sys/kernel/btf/vmlinux "$BTF"
OBJ_SHA=$(sha256sum "$OBJ" | awk '{print $1}')
BTF_SHA=$(sha256sum "$BTF" | awk '{print $1}')
KERNEL_RELEASE=$(uname -r)
printf '%s\n' "$KERNEL_RELEASE" > "$OUT/target/build/kernel-release.txt"
printf '%s  %s\n' "$OBJ_SHA" rac_v2_contextual.bpf.o > "$OUT/target/build/object.sha256"
printf '%s  %s\n' "$BTF_SHA" btf-vmlinux > "$OUT/target/build/btf.sha256"

if ! mountpoint -q /sys/fs/bpf; then
  sudo mount -t bpf bpf /sys/fs/bpf
fi
if sudo test -e "$PIN_DIR"; then
  echo "pin directory already exists; choose a fresh RAC_CONTEXT_PIN_DIR: $PIN_DIR" >&2
  exit 2
fi
sudo mkdir "$PIN_DIR"

cleanup_pin() {
  sudo rm -f "$PIN_PATH" 2>/dev/null || true
  sudo rmdir "$PIN_DIR" 2>/dev/null || true
}
trap cleanup_pin EXIT

sudo env RAC_V2_PIN_PATH="$PIN_PATH" \
  RAC_V2_OBJECT_SHA256="$OBJ_SHA" \
  RAC_V2_BTF_SHA256="$BTF_SHA" \
  "$WITNESS" -o "$RUNTIME" -n "$TRIALS"
sudo chown "$(id -u):$(id -g)" "$RUNTIME"

sudo bpftool -j prog show pinned "$PIN_PATH" > "$OUT/target/raw/program-info.json"
if ! sudo bpftool prog dump xlated pinned "$PIN_PATH" opcodes linum > "$XLATED"; then
  sudo bpftool prog dump xlated pinned "$PIN_PATH" opcodes > "$XLATED"
fi
XLATED_SHA=$(sha256sum "$XLATED" | awk '{print $1}')
printf '%s  %s\n' "$XLATED_SHA" xlated-rac_v2_contextual.txt > "$OUT/target/raw/xlated-rac_v2_contextual.sha256"

PYTHONPATH="$ROOT/src:$ROOT" "$PYTHON" - "$RUNTIME" "$XLATED_SHA" "$OUT/target/identity.json" <<'PY'
import json
import sys
from pathlib import Path

runtime = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
xlated_sha = sys.argv[2]
identity = runtime["identity"]
identity["xlated_sha256"] = xlated_sha
Path(sys.argv[1]).write_text(
    json.dumps(runtime, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
Path(sys.argv[3]).write_text(
    json.dumps(identity, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

set +e
PYTHONPATH="$ROOT/src:$ROOT" "$PYTHON" -m residuality_auditor.context_runtime \
  --runtime "$RUNTIME" \
  --target-identity "$OUT/target/identity.json" \
  --object "$OBJ" \
  --btf "$BTF" \
  --xlated "$XLATED" \
  --json-out "$OUT/target/audit/runtime-validation.json"
RUNTIME_VALIDATION_RC=$?
set -e

write_case_result() {
  local stage=$1
  local result_path=$2
  local runtime_rc=$3
  local crl_rc=$4
  PYTHONPATH="$ROOT/src:$ROOT" "$PYTHON" - \
    "$CONTEXT_SUITE" "$CONTEXT_CASE_ID" "$stage" "$result_path" \
    "$runtime_rc" "$crl_rc" "$OUT/context/case-result.json" <<'PY'
import json
import sys
from pathlib import Path

from residuality_auditor.context_suite import compare_case_result, load_context_suite

suite_path, case_id, stage, result_path, runtime_rc, crl_rc, output_path = sys.argv[1:]
document = json.loads(Path(result_path).read_text(encoding="utf-8"))
if stage == "TARGET_RUNTIME_VALIDATION":
    observed = {
        "stage": stage,
        "status": document.get("status"),
        "assessment": None,
        "quantifier": None,
        "evidence_grade": None,
        "reasons": sorted(set(document.get("invalid_reasons", []) + document.get("errors", []))),
    }
else:
    claim = document.get("claim", {})
    observed = {
        "stage": stage,
        "status": document.get("status"),
        "assessment": document.get("assessment", document.get("unknown_kind")),
        "quantifier": claim.get("quantifier"),
        "evidence_grade": claim.get("evidence_grade"),
        "reasons": sorted(
            set(document.get("invalid_reasons", []) + document.get("missing_obligations", []))
        ),
    }
case = load_context_suite(Path(suite_path)).case(case_id)
comparison = compare_case_result(case, observed)
comparison["schema"] = "rac-stock-r-context-case-result-v1"
comparison["runtime_validation_exit_status"] = int(runtime_rc)
comparison["crl_check_exit_status"] = int(crl_rc)
Path(output_path).write_text(
    json.dumps(comparison, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
raise SystemExit(0 if comparison["expected_match"] else 1)
PY
}

finalize_bundle() {
  uname -a > "$OUT/ENVIRONMENT.txt"
  "$PYTHON" --version >> "$OUT/ENVIRONMENT.txt"
  git -C "$REPO_ROOT" status --short > "$OUT/GIT_STATUS.txt"
  find "$OUT" -type f ! -name CHECKSUMS.sha256 -print0 | sort -z | xargs -0 sha256sum > "$OUT/CHECKSUMS.sha256"
  echo "Stock-R contextual evidence bundle: $OUT"
  echo "Target object sha256: $OBJ_SHA"
  echo "Target xlated sha256: $XLATED_SHA"
}

if (( RUNTIME_VALIDATION_RC != 0 )); then
  if [[ -z "$CONTEXT_SUITE" ]]; then
    exit "$RUNTIME_VALIDATION_RC"
  fi
  set +e
  write_case_result \
    TARGET_RUNTIME_VALIDATION "$OUT/target/audit/runtime-validation.json" \
    "$RUNTIME_VALIDATION_RC" -1
  CASE_RESULT_RC=$?
  set -e
  finalize_bundle
  exit "$CASE_RESULT_RC"
fi

set +e
PYTHONPATH="$ROOT/src:$ROOT" "$PYTHON" -m residuality_auditor.cli ebrc-context-from-source \
  --source-compiled "$OUT/source/compiled" \
  --target-identity "$OUT/target/identity.json" \
  --transform-metadata "$OUT/context/transform-metadata.json" \
  --compiled-out "$OUT/context/compiled" \
  --json-out "$OUT/context/result.json"
CRL_CHECK_RC=$?
set -e

if [[ -z "$CONTEXT_SUITE" ]]; then
  if (( CRL_CHECK_RC != 0 )); then
    exit "$CRL_CHECK_RC"
  fi
  PYTHONPATH="$ROOT/src:$ROOT" "$PYTHON" -m residuality_auditor.cli ebrc-context-mutations \
    "$OUT/context/compiled" \
    --json-out "$OUT/context/hostile-matrix.json"
  finalize_bundle
  exit 0
fi

set +e
write_case_result CRL_CHECK "$OUT/context/result.json" 0 "$CRL_CHECK_RC"
CASE_RESULT_RC=$?
set -e

CRL_STATUS=$("$PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("status", ""))' "$OUT/context/result.json")
if [[ "$CRL_STATUS" == "CERTIFIED" ]]; then
  PYTHONPATH="$ROOT/src:$ROOT" "$PYTHON" -m residuality_auditor.cli ebrc-context-mutations \
    "$OUT/context/compiled" \
    --json-out "$OUT/context/hostile-matrix.json"
fi
finalize_bundle
exit "$CASE_RESULT_RC"
