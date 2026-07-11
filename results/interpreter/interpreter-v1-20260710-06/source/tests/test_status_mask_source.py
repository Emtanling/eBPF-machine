#!/usr/bin/env python3
"""Guard the host-side status-mask boundary in the interpreter runner."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src" / "wm_vm_user.c").read_text(encoding="utf-8")


def main() -> int:
    guard = SOURCE.index("if (control.status != VM_STATUS_OK)")
    guard_return = SOURCE.index("return 1;", guard)
    guard_block = SOURCE[guard:guard_return]
    first_wire_projection = SOURCE.index(
        "for (uint32_t i = 0; i < image->wire_count; i++)", guard
    )
    first_trace_read = SOURCE.index("map_get(trace_fd", guard)

    assert r'\"actual\":null' in guard_block
    assert "map_get(wires_fd" not in guard_block
    assert "map_get(trace_fd" not in guard_block
    assert guard < first_wire_projection < first_trace_read
    print("status-mask source guard: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
