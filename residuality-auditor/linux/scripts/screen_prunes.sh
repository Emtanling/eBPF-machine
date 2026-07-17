#!/usr/bin/env bash
set -euo pipefail

EVENTS=${1:-output/linux-live/events.jsonl}
PROGRAM=${2:-rac_single}

command -v jq >/dev/null 2>&1 || {
  echo "jq is required" >&2
  exit 2
}

echo -e "program\tvisit_insn\thistories_distinct\told_count\tcurrent_count\told_history\tcurrent_history\tsource"
jq -r --arg program "$PROGRAM" '
  select(.event == "prune_hit" and .program_name == $program) |
  [
    .program_name,
    .visit_insn,
    (.old.history_hash != .current.history_hash),
    .old.history_count,
    .current.history_count,
    .old.history_hash,
    .current.history_hash,
    .source
  ] | @tsv
' "$EVENTS"
