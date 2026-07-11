#!/usr/bin/env bash
# Reproduce the numeric precision audit and capture deterministic reports.
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p out

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_witness.py
bash frama_c/syntax_check.sh
python3 witness.py > out/witness.txt
python3 witness.py --json > out/witness.json

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum out/witness.json out/witness.txt > out/SHA256SUMS
else
  shasum -a 256 out/witness.json out/witness.txt > out/SHA256SUMS
fi

cat out/witness.txt
echo
echo "Captured: out/witness.txt, out/witness.json, out/SHA256SUMS"
