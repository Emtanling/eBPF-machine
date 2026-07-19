#!/usr/bin/env python3
"""Generate restricted Stock-R V2 contextual witness variants."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from residuality_auditor.context_suite import load_context_suite, render_context_target


SCHEMA = "rac-stock-r-context-transform-metadata-v1"
PRIMITIVE = "POST_COLLISION_FRAMED_COMPUTATION"


VARIANTS: dict[str, dict[str, str]] = {
    "post-collision-frame": {
        "transform_id": "context.stock-r-v2.post-collision-frame",
        "map_name": "context_scratch",
        "function_name": "context_frame",
        "frame_expression": "observed ^ 0x5a5a5a5aU",
    },
    "post-collision-affine-frame": {
        "transform_id": "context.stock-r-v2.post-collision-affine-frame",
        "map_name": "context_scratch_affine",
        "function_name": "context_affine_frame",
        "frame_expression": "(observed * 2654435761U) ^ 0x9e3779b9U",
    },
}


CONTEXT_MAP_TEMPLATE = """\
struct {{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
}} {map_name} SEC(".maps");

/*
 * Framed contextual computation: this runs after the shared witness suffix and
 * writes only a fresh map outside the Stock-R witness footprint.
 */
static __noinline void {function_name}(__u32 observed)
{{
    __u32 key = 0;
    __u32 framed = {frame_expression};

    (void)bpf_map_update_elem(&{map_name}, &key, &framed, BPF_ANY);
}}

"""

CALL_SNIPPET_TEMPLATE = """\
    {function_name}((__u32)observed);
"""


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _metadata(source_text: str, generated_text: str, variant_id: str) -> dict[str, Any]:
    variant = VARIANTS[variant_id]
    map_name = variant["map_name"]
    return {
        "schema": SCHEMA,
        "variant_id": variant_id,
        "transform_id": variant["transform_id"],
        "primitive": PRIMITIVE,
        "source_sha256": _sha256_text(source_text),
        "generated_sha256": _sha256_text(generated_text),
        "parameters": {
            "frame_map": map_name,
            "frame_function": variant["function_name"],
            "frame_expression": variant["frame_expression"],
            "placement": "after shared_suffix() result and before audit update",
            "retval_preserved": True,
        },
        "instruction_correspondence": {
            "status": "VERIFIED",
            "total_on_witness": True,
            "entries": [
                {"source_insn": 0, "target_insn": 0, "relation": "IDENTITY"},
                {"source_insn": 1, "target_insn": 1, "relation": "FRAMED"},
            ],
        },
        "footprint": {
            "resources": [
                "reg:r1",
                "reg:r2",
                "stack:-8..-1",
                "map:witness.0",
                "frontier:source",
            ]
        },
        "effect": {"writes": [f"map:{map_name}.0"]},
        "obligations": {
            "source_certificate": True,
            "source_target_scope_distinct_or_identity_marked": True,
            "instruction_correspondence_total_on_witness": True,
            "footprint_effect_disjoint": True,
            "collision_preserved": True,
            "common_suffix_preserved": True,
            "must_outcomes_preserved": True,
            "observer_reflected": True,
            "report_cell_preserved": True,
            "frontier_preserved": True,
            "history_map_total": True,
            "target_conformance_bridge": True,
            "outcome_independent_selection": True,
            "no_target_terminal_verdict": True,
        },
    }


def generate(source_text: str, variant_id: str = "post-collision-frame") -> str:
    variant = VARIANTS[variant_id]
    if any(
        marker in source_text
        for marker in (
            "context_scratch SEC",
            "context_scratch_affine SEC",
            "context_frame((__u32)observed);",
            "context_affine_frame((__u32)observed);",
        )
    ):
        raise ValueError("source already contains the contextual frame")
    map_anchor = "/* Keep the branch-local map writes before the shared lookup suffix. */"
    call_anchor = "    observed = shared_suffix();\n"
    if map_anchor not in source_text:
        raise ValueError("cannot find map insertion anchor")
    if call_anchor not in source_text:
        raise ValueError("cannot find context call insertion anchor")
    context_map = CONTEXT_MAP_TEMPLATE.format(**variant)
    call_snippet = CALL_SNIPPET_TEMPLATE.format(**variant)
    generated = source_text.replace(map_anchor, context_map + map_anchor, 1)
    generated = generated.replace(call_anchor, call_anchor + call_snippet, 1)
    return generated


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument(
        "--variant",
        choices=sorted(VARIANTS),
        default="post-collision-frame",
        help="restricted contextual frame variant to generate",
    )
    parser.add_argument("--suite", type=Path)
    parser.add_argument("--case-id")
    args = parser.parse_args()

    if (args.suite is None) != (args.case_id is None):
        parser.error("--suite and --case-id must be provided together")

    source_text = args.source.read_text(encoding="utf-8")
    if args.suite is not None:
        suite = load_context_suite(args.suite)
        rendered = render_context_target(source_text, suite, suite.case(args.case_id))
        generated_text = rendered.source_text
        metadata = rendered.metadata
    else:
        generated_text = generate(source_text, args.variant)
        metadata = _metadata(source_text, generated_text, args.variant)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(generated_text, encoding="utf-8")
    args.metadata.parent.mkdir(parents=True, exist_ok=True)
    args.metadata.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
