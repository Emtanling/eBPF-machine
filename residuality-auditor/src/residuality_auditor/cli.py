from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analysis import analyze_model
from .ebrc import check_certificate
from .ebrc_adapters import (
    EBRCAdapterError,
    compile_stock_linux_v1_bundle,
    compile_stock_r_v2_bundle,
)
from .ebrc_context import (
    check_context_documents,
    make_context_documents,
    make_stock_r_context_documents,
)
from .ebrc_context_mutations import run_context_hostile_mutation_matrix
from .ebrc_mutations import run_hostile_mutation_matrix
from .linux_r import LinuxRError, analyze_linux_r, render_linux_r_markdown
from .model import ModelError, load_model
from .report import render_markdown


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="residuality-auditor",
        description=(
            "Audit finite post-acceptance residuality models and correlate Linux "
            "verifier prune cells with same-suffix runtime witnesses."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="analyze a JSON finite-state model")
    analyze.add_argument("model", type=Path)
    analyze.add_argument("--json-out", type=Path, help="write machine-readable result JSON")
    analyze.add_argument("--md-out", type=Path, help="write a Markdown evidence report")
    analyze.add_argument(
        "--spectrum-depth",
        type=int,
        default=None,
        help="limit displayed bounded residuality spectrum to depth k",
    )
    analyze.add_argument(
        "--compact",
        action="store_true",
        help="print only the claim summary to stdout",
    )

    linux_r = sub.add_parser(
        "linux-r",
        help="correlate Linux verifier prune events with a runtime same-suffix witness",
    )
    linux_r.add_argument("events", type=Path, help="JSONL emitted by the Linux verifier tracer")
    linux_r.add_argument("runtime", type=Path, help="runtime witness JSON")
    linux_r.add_argument("contract", type=Path, help="reviewed report/concretization contract JSON")
    linux_r.add_argument("--json-out", type=Path, help="write machine-readable evidence JSON")
    linux_r.add_argument("--md-out", type=Path, help="write a Markdown evidence report")
    linux_r.add_argument(
        "--compact",
        action="store_true",
        help="print only the Linux R summary to stdout",
    )

    ebrc = sub.add_parser(
        "ebrc",
        help="compile a Stock-R bundle and check a generic exact EBRC claim",
    )
    ebrc.add_argument("adapter", choices=("stock-linux-v1", "stock-r-v2"))
    ebrc.add_argument("bundle", type=Path)
    ebrc.add_argument("--json-out", type=Path, help="write the EBRC result JSON")
    ebrc.add_argument(
        "--compiled-out",
        type=Path,
        help="write claim.json, evidence-graph.json, and proof.json to this directory",
    )

    mutations = sub.add_parser(
        "ebrc-mutations",
        help="run the U4 hostile matrix against compiled exact EBRC documents",
    )
    mutations.add_argument(
        "compiled",
        type=Path,
        help="directory containing claim.json, evidence-graph.json, and proof.json",
    )
    mutations.add_argument("--json-out", type=Path, help="write the mutation matrix JSON")

    context = sub.add_parser(
        "ebrc-context",
        help="generate and check a synthetic contextual EBRC transport certificate",
    )
    context.add_argument(
        "--identity",
        action="store_true",
        help="emit the identity control instead of a nontrivial target scope",
    )
    context.add_argument(
        "--runtime-only-blocked",
        action="store_true",
        help="emit a blocked runtime-validation-only near-miss",
    )
    context.add_argument("--json-out", type=Path, help="write the CRL result JSON")
    context.add_argument(
        "--compiled-out",
        type=Path,
        help="write claim.json, evidence-graph.json, and proof.json to this directory",
    )

    context_from_source = sub.add_parser(
        "ebrc-context-from-source",
        help="derive a target CRL certificate from a certified source EBRC bundle",
    )
    context_from_source.add_argument(
        "--source-compiled",
        required=True,
        type=Path,
        help="directory containing source claim.json, evidence-graph.json, and proof.json",
    )
    context_from_source.add_argument(
        "--target-identity",
        required=True,
        type=Path,
        help="target identity JSON with object, xlated, BTF, and kernel digests",
    )
    context_from_source.add_argument(
        "--transform-metadata",
        required=True,
        type=Path,
        help="context transform metadata JSON",
    )
    context_from_source.add_argument("--json-out", type=Path, help="write the CRL result JSON")
    context_from_source.add_argument(
        "--compiled-out",
        type=Path,
        help="write claim.json, evidence-graph.json, and proof.json to this directory",
    )

    context_mutations = sub.add_parser(
        "ebrc-context-mutations",
        help="run the CRL hostile matrix against compiled contextual documents",
    )
    context_mutations.add_argument(
        "compiled",
        type=Path,
        help="directory containing claim.json, evidence-graph.json, and proof.json",
    )
    context_mutations.add_argument("--json-out", type=Path, help="write the mutation matrix JSON")
    return parser


def _read_json_object(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def _write_outputs(result: dict, json_out: Path | None, md_out: Path | None, markdown: str) -> None:
    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(
            json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if md_out:
        md_out.parent.mkdir(parents=True, exist_ok=True)
        md_out.write_text(markdown, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "analyze":
            model = load_model(args.model)
            result = analyze_model(model, spectrum_depth=args.spectrum_depth)
            markdown = render_markdown(result)
        elif args.command == "linux-r":
            result = analyze_linux_r(args.events, args.runtime, args.contract)
            markdown = render_linux_r_markdown(result)
        elif args.command == "ebrc":
            compiler = (
                compile_stock_linux_v1_bundle
                if args.adapter == "stock-linux-v1"
                else compile_stock_r_v2_bundle
            )
            compiled = compiler(args.bundle)
            result = check_certificate(compiled["graph"], compiled["claim"], compiled["proof"])
            if args.compiled_out:
                args.compiled_out.mkdir(parents=True, exist_ok=True)
                for key, filename in (
                    ("claim", "claim.json"),
                    ("graph", "evidence-graph.json"),
                    ("proof", "proof.json"),
                ):
                    (args.compiled_out / filename).write_text(
                        json.dumps(compiled[key], ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
            if args.json_out:
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(
                    json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
            json.dump(result, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
            sys.stdout.write("\n")
            return 2 if result["status"] == "INVALID_GRAPH" else 0
        elif args.command == "ebrc-mutations":
            graph = _read_json_object(args.compiled / "evidence-graph.json")
            claim = _read_json_object(args.compiled / "claim.json")
            proof = _read_json_object(args.compiled / "proof.json")
            result = run_hostile_mutation_matrix(graph, claim, proof)
            if args.json_out:
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(
                    json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
            json.dump(result, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
            sys.stdout.write("\n")
            return 0 if result["all_expected"] else 2
        elif args.command == "ebrc-context":
            missing = ["TARGET_CONFORMANCE_BRIDGE"] if args.runtime_only_blocked else None
            compiled = make_context_documents(
                trivial=args.identity,
                include_runtime_validation=args.runtime_only_blocked,
                blocked_missing=missing,
            )
            result = check_context_documents(compiled)
            if args.compiled_out:
                args.compiled_out.mkdir(parents=True, exist_ok=True)
                for key, filename in (
                    ("claim", "claim.json"),
                    ("graph", "evidence-graph.json"),
                    ("proof", "proof.json"),
                ):
                    (args.compiled_out / filename).write_text(
                        json.dumps(compiled[key], ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
            if args.json_out:
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(
                    json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
            json.dump(result, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
            sys.stdout.write("\n")
            return 2 if result["status"] == "INVALID_GRAPH" else 0
        elif args.command == "ebrc-context-from-source":
            source_graph = _read_json_object(args.source_compiled / "evidence-graph.json")
            source_claim = _read_json_object(args.source_compiled / "claim.json")
            source_proof = _read_json_object(args.source_compiled / "proof.json")
            target_identity = _read_json_object(args.target_identity)
            transform_metadata = _read_json_object(args.transform_metadata)
            compiled = make_stock_r_context_documents(
                source_graph,
                source_claim,
                source_proof,
                target_identity,
                transform_metadata,
            )
            result = check_context_documents(compiled)
            if args.compiled_out:
                args.compiled_out.mkdir(parents=True, exist_ok=True)
                for key, filename in (
                    ("claim", "claim.json"),
                    ("graph", "evidence-graph.json"),
                    ("proof", "proof.json"),
                ):
                    (args.compiled_out / filename).write_text(
                        json.dumps(compiled[key], ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
            if args.json_out:
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(
                    json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
            json.dump(result, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
            sys.stdout.write("\n")
            return 2 if result["status"] == "INVALID_GRAPH" else 0
        elif args.command == "ebrc-context-mutations":
            graph = _read_json_object(args.compiled / "evidence-graph.json")
            claim = _read_json_object(args.compiled / "claim.json")
            proof = _read_json_object(args.compiled / "proof.json")
            result = run_context_hostile_mutation_matrix(graph, claim, proof)
            if args.json_out:
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(
                    json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
            json.dump(result, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
            sys.stdout.write("\n")
            return 0 if result["all_expected"] else 2
        else:  # pragma: no cover - argparse enforces this
            parser.error(f"unknown command {args.command}")
            return 2
    except (EBRCAdapterError, ModelError, LinuxRError, ValueError) as exc:
        parser.error(str(exc))
        return 2

    _write_outputs(result, args.json_out, args.md_out, markdown)
    payload = result["summary"] if args.compact else result
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
