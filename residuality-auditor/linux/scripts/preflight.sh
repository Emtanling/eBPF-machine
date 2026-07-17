#!/usr/bin/env bash
set -euo pipefail

fail=0
for cmd in clang bpftool pkg-config cc; do
  if ! command -v "$cmd" >/dev/null; then
    echo "MISSING: $cmd" >&2
    fail=1
  fi
done
[[ -r /sys/kernel/btf/vmlinux ]] || { echo "MISSING: /sys/kernel/btf/vmlinux" >&2; fail=1; }
[[ -r /proc/kallsyms ]] || { echo "MISSING: /proc/kallsyms" >&2; fail=1; }

if [[ -r /sys/kernel/btf/vmlinux ]] && command -v bpftool >/dev/null; then
  tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  bpftool btf dump file /sys/kernel/btf/vmlinux format raw > "$tmp"
  if grep -q "FUNC 'states_equal'" "$tmp" && grep -q "FUNC 'is_state_visited'" "$tmp"; then
    echo "OK: fexit BTF function IDs are present"
  else
    echo "WARN: fexit function IDs not found; use kprobe fallback if symbols exist" >&2
  fi
fi

if grep -qE ' [tT] states_equal$' /proc/kallsyms && grep -qE ' [tT] is_state_visited$' /proc/kallsyms; then
  echo "OK: kprobe symbols are visible"
else
  echo "WARN: verifier internal symbols are not visible in /proc/kallsyms" >&2
fi

if [[ $fail -ne 0 ]]; then
  exit 1
fi
