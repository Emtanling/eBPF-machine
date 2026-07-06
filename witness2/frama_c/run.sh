#!/usr/bin/env bash
# Third-party reproduction of the second witness on Frama-C EVA.
# Target: Ubuntu (apt install frama-c-base on 24.04).  Run:  bash run.sh
set -u
cd "$(dirname "$0")"
mkdir -p out

if ! command -v frama-c >/dev/null 2>&1; then
  echo "frama-c not found. On Ubuntu 24.04:  sudo apt-get update && sudo apt-get install -y frama-c-base"
  exit 1
fi

echo "Frama-C: $(frama-c -version 2>/dev/null | head -1)"
echo "==================================================================="
echo "Join-based value analysis (EVA), slevel 0."
echo "  EXPECT  NAND_out     = {0; 1}   (TOP -> A-opaque: working mod-3 channel)"
echo "  EXPECT  ABLATION_out = {1}      (certified: mod-7 gate degenerates to constant)"
echo "  The contrast = non-triviality: the SAME sound analyzer is blind to the"
echo "  working channel yet certifies the ablation, so the blindness is localized."
echo "==================================================================="
frama-c -eva -eva-slevel 0 nand_mod.c > out/eva_slevel0.log 2>&1
grep -E "Frama_C_show_each" out/eva_slevel0.log || echo "(see out/eva_slevel0.log)"
echo
echo "Full log: out/eva_slevel0.log"
echo "(The disjunctive 'repair' of the repair outlook — certifying the output per input — is"
echo " demonstrated in ../witness.py; in EVA it corresponds to input case-splitting.)"
