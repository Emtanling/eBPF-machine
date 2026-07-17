from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analysis import analyze_model
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
    return parser


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
        else:  # pragma: no cover - argparse enforces this
            parser.error(f"unknown command {args.command}")
            return 2
    except (ModelError, LinuxRError, ValueError) as exc:
        parser.error(str(exc))
        return 2

    _write_outputs(result, args.json_out, args.md_out, markdown)
    payload = result["summary"] if args.compact else result
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
