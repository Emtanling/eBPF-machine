#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("runtime", type=Path)
p.add_argument("output", type=Path)
p.add_argument("--program-name", default="rac_single")
p.add_argument("--visit-insn", type=int)
p.add_argument("--review-path-correspondence", action="store_true")
p.add_argument("--review-report-contract", action="store_true")
p.add_argument("--review-concretization", action="store_true")
args = p.parse_args()
runtime = json.loads(args.runtime.read_text())
contract = {
    "schema": "rac-linux-contract-v1",
    "kernel_release": runtime.get("kernel_release"),
    "program_tag": runtime.get("program_tag"),
    "program_name": args.program_name,
    "frontier": ({"visit_insn": args.visit_insn} if args.visit_insn is not None else {}),
    "path_correspondence_reviewed": args.review_path_correspondence,
    "selected_component": "G0 key set immediately before the shared post-join suffix in rac_single",
    "omitted_by_verifier_cell": ["G0 key set immediately before the shared post-join suffix in rac_single"],
    "selected_component_omission_reviewed": True,
    "same_context_fields": [
        "map_type", "max_entries", "map_flags", "serialized",
        "prefix_program", "suffix_program", "single_artifact"
    ],
    "require_distinct_verifier_histories": True,
    "require_same_state_hash": False,
    "no_external_interference": True,
    "serialized_execution": True,
    "report_contract_in_scope": args.review_report_contract,
    "concretization_reviewed": args.review_concretization,
    "notes": [
        "A states_equal success followed by is_state_visited return 1 is treated as an operational prune-cell event.",
        "Map contents are intentionally outside the extracted verifier-state schema.",
        "The two review flags must not be enabled without a written contract/concretization argument."
    ]
}
args.output.write_text(json.dumps(contract, indent=2) + "\n")
