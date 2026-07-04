#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "scripts" / "audit_results.py"


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def run_audit(tmp: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(AUDIT), str(tmp)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def minimal_valid_dataset(tmp: Path) -> None:
    nand_rows = []
    all1_rows = []
    for a in (0, 1):
        for b in (0, 1):
            expected = 0 if (a and b) else 1
            nand_rows.append(
                {
                    "case": "nand",
                    "trial": 0,
                    "a": a,
                    "b": b,
                    "expected": expected,
                    "actual": expected,
                    "err": 0,
                    "passed": True,
                }
            )
            all1_rows.append(
                {
                    "case": "nand_all1",
                    "trial": 0,
                    "a": a,
                    "b": b,
                    "expected": 1,
                    "actual": 1,
                    "err": 0,
                    "passed": True,
                }
            )

    fa_rows = []
    for a in (0, 1):
        for b in (0, 1):
            for cin in (0, 1):
                total = a + b + cin
                fa_rows.append(
                    {
                        "case": "full_adder",
                        "a": a,
                        "b": b,
                        "cin": cin,
                        "expected_sum": total & 1,
                        "expected_cout": (total >> 1) & 1,
                        "actual_sum": total & 1,
                        "actual_cout": (total >> 1) & 1,
                        "err": 0,
                        "passed": True,
                    }
                )

    adder_rows = [
        {
            "case": "adder32",
            "kind": "fixed",
            "trial": 0,
            "x": 0xFFFFFFFF,
            "y": 1,
            "expected": 0,
            "actual": 0,
            "expected_carry": 1,
            "carry_out": 1,
            "err": 0,
            "passed": True,
        }
    ]

    write_jsonl(tmp / "nand_truth_table.jsonl", nand_rows)
    write_jsonl(tmp / "baseline_nand.jsonl", nand_rows)
    write_jsonl(tmp / "ablation_cap64.jsonl", all1_rows)
    write_jsonl(tmp / "ablation_k2_sentinel.jsonl", all1_rows)
    write_jsonl(tmp / "full_adder.jsonl", fa_rows)
    write_jsonl(tmp / "adder32.jsonl", adder_rows)


def test_audit_accepts_semantically_valid_dataset() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        minimal_valid_dataset(tmp)
        result = run_audit(tmp)
        assert result.returncode == 0, result.stderr + result.stdout
        assert "semantic audit: ok" in result.stdout


def test_audit_rejects_ablation_that_still_behaves_like_nand() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        minimal_valid_dataset(tmp)
        rows = (tmp / "ablation_cap64.jsonl").read_text(encoding="utf-8").splitlines()
        bad = json.loads(rows[-1])
        bad["expected"] = 0
        bad["actual"] = 0
        rows[-1] = json.dumps(bad)
        (tmp / "ablation_cap64.jsonl").write_text("\n".join(rows) + "\n", encoding="utf-8")

        result = run_audit(tmp)
        assert result.returncode != 0
        assert "ablation_cap64" in result.stderr


if __name__ == "__main__":
    test_audit_accepts_semantically_valid_dataset()
    test_audit_rejects_ablation_that_still_behaves_like_nand()
    print("audit result tests: ok")
