from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "linux" / "scripts" / "enrich_events.py"
spec = importlib.util.spec_from_file_location("enrich_events", SCRIPT)
assert spec and spec.loader
enrich_events = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enrich_events)


class EnrichEventsTests(unittest.TestCase):
    def test_enriches_only_prune_events_with_frozen_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / "events.raw.jsonl"
            out = root / "events.jsonl"
            runtime = root / "runtime.json"
            program_info = root / "program-info.json"
            object_sha = root / "object.sha256"
            program_pin = root / "program-pin.txt"
            xlated_sha = root / "xlated-rac_single.sha256"

            raw.write_text(
                json.dumps({"event": "metadata", "backend": "fexit"}) + "\n" +
                json.dumps({
                    "event": "prune_hit",
                    "old": {"history_entries": [{"insn_idx": 44}]},
                    "current": {"history_entries": [{"insn_idx": 46}]},
                }) + "\n",
                encoding="utf-8",
            )
            runtime.write_text(json.dumps({"program_pin": "/sys/fs/bpf/rac-v03/rac_single"}), encoding="utf-8")
            program_info.write_text(json.dumps({"id": 123, "tag": "abc123"}), encoding="utf-8")
            object_sha.write_text("f" * 64 + "  linux/build/rac_witness.bpf.o\n", encoding="utf-8")
            program_pin.write_text("/sys/fs/bpf/rac-v03/rac_single\n", encoding="utf-8")
            xlated_sha.write_text("e" * 64 + "  xlated-rac_single.txt\n", encoding="utf-8")

            enrich_events.enrich_events(raw, out, runtime, program_info, object_sha, program_pin, xlated_sha)

            events = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
            self.assertNotIn("object_sha256", events[0])
            self.assertEqual(events[1]["object_sha256"], "f" * 64)
            self.assertEqual(events[1]["program_id"], 123)
            self.assertEqual(events[1]["program_tag"], "abc123")
            self.assertEqual(events[1]["program_pin"], "/sys/fs/bpf/rac-v03/rac_single")
            self.assertEqual(events[1]["xlated_sha256"], "e" * 64)
            self.assertEqual(events[1]["event_identity_source"], "run_linux_r_enrichment_v1")

    def test_conflicting_raw_identity_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / "events.raw.jsonl"
            out = root / "events.jsonl"
            runtime = root / "runtime.json"
            program_info = root / "program-info.json"
            object_sha = root / "object.sha256"
            program_pin = root / "program-pin.txt"
            xlated_sha = root / "xlated-rac_single.sha256"

            raw.write_text(json.dumps({"event": "prune_hit", "program_id": 999}) + "\n", encoding="utf-8")
            runtime.write_text(json.dumps({"program_pin": "/pin"}), encoding="utf-8")
            program_info.write_text(json.dumps({"id": 123, "tag": "abc123"}), encoding="utf-8")
            object_sha.write_text("f" * 64 + "\n", encoding="utf-8")
            program_pin.write_text("/pin\n", encoding="utf-8")
            xlated_sha.write_text("e" * 64 + "\n", encoding="utf-8")

            with self.assertRaises(enrich_events.EnrichEventsError):
                enrich_events.enrich_events(raw, out, runtime, program_info, object_sha, program_pin, xlated_sha)
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
