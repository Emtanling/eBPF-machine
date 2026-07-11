#!/usr/bin/env bash
# Host C syntax check only. This does not run EVA or validate Frama-C semantics.
set -euo pipefail

cd "$(dirname "$0")"
compiler="${CC:-cc}"

"$compiler" \
  -std=c11 \
  -Wall \
  -Wextra \
  -Werror \
  -fsyntax-only \
  -I static_check \
  nand_mod.c

echo "C syntax check: ok ($compiler; declaration stub only, EVA not run)"
