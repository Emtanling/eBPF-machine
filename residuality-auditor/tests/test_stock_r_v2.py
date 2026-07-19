from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from residuality_auditor.stock_r_v2 import (
    StockRV2Error,
    audit_bundle,
    audit_capture,
    check_history_case_binding,
    check_must_outcome_proof,
    canonical_sha256,
    make_history_case_binding,
    make_must_outcome_proof,
    make_precommit,
)


def _hex(ch: str) -> str:
    return ch * 64


SOURCE_CLOSURE_SHA = _hex("d")
BUILD_CLOSURE_SHA = _hex("e")


def _identity() -> dict[str, object]:
    return {
        "program_name": "rac_v2_single",
        "program_id": 7001,
        "program_tag": "0123456789abcdef",
        "program_load_time": 250,
        "object_sha256": _hex("a"),
        "xlated_sha256": _hex("b"),
        "kernel_release": "6.17.0-test",
        "btf_sha256": _hex("c"),
    }


def _query(identity: dict[str, object]) -> dict[str, object]:
    static_identity = {
        field: identity[field]
        for field in ("program_name", "object_sha256", "kernel_release", "btf_sha256")
    }
    return {
        "schema": "rac-stock-r-v2-query-v1",
        "query_id": "stock-r-v2.array",
        "identity": static_identity,
        "source_closure_sha256": SOURCE_CLOSURE_SHA,
        "build_closure_sha256": BUILD_CLOSURE_SHA,
        "event_selector": {
            "exact_level": 0,
            "require_distinct_histories": True,
            "require_complete_history": True,
            "require_supported_state": True,
            "uniqueness": "EXACTLY_ONE",
        },
        "trial_plan": {
            "cases": [0, 1],
            "per_case": 2,
            "schedule": "ALTERNATING_START_ZERO",
            "observer": "XDP_RETURN_BIT",
        },
    }


def _policy(query: dict[str, object]) -> dict[str, object]:
    return {
        "schema": "rac-stock-r-v2-selection-policy-v1",
        "policy_id": "stock-r-v2.unique-operational-prune",
        "query_digest_sha256": canonical_sha256(query),
        "selector": "EXACTLY_ONE_DIRECT_PRUNE",
        "outcome_free": True,
        "forbidden_input_prefixes": ["runtime.trials", "runtime.outcomes"],
    }


def _contract(query: dict[str, object], policy: dict[str, object]) -> dict[str, object]:
    return {
        "schema": "rac-stock-r-v2-capture-contract-v1",
        "query_digest_sha256": canonical_sha256(query),
        "selection_policy_sha256": canonical_sha256(policy),
        "source_closure_sha256": query["source_closure_sha256"],
        "build_closure_sha256": query["build_closure_sha256"],
        "backend": "fentry+fexit",
        "target_comm": "rac-v2-witness",
        "program_name": query["identity"]["program_name"],
        "trial_count": 4,
        "outcome_free_selection": True,
    }


def _event(identity: dict[str, object]) -> dict[str, object]:
    return {
        "event": "prune_hit",
        "source": "fentry/fexit invocation-scoped states_equal/is_state_visited",
        "session_id": "session-v2",
        "sequence": 1,
        "equality_sequence": 41,
        "visit_sequence": 17,
        "invocation_token": 9,
        "program_name": identity["program_name"],
        "program_tag": identity["program_tag"],
        "program_load_time": identity["program_load_time"],
        "visit_insn": 123,
        "exact_level": 0,
        "states_equal_success_count": 1,
        "old": {
            "history_entries": [{"insn_idx": 11}],
            "history_total_count": 1,
            "history_captured_count": 1,
            "history_truncated": False,
            "state_v2": {"valid": True, "unsupported_mask": 0},
        },
        "current": {
            "history_entries": [{"insn_idx": 12}],
            "history_total_count": 1,
            "history_captured_count": 1,
            "history_truncated": False,
            "state_v2": {"valid": True, "unsupported_mask": 0},
        },
    }


def _events(identity: dict[str, object]) -> list[dict[str, object]]:
    return [
        {
            "event": "metadata",
            "schema": "rac-stock-r-v2-event-stream-v1",
            "session_id": "session-v2",
            "capture_started_ns": 200,
            "capture_attached_ns": 220,
            "backend": "fentry+fexit",
            "kernel_release": identity["kernel_release"],
            "target_comm": "rac-v2-witness",
        },
        _event(identity),
        {
            "event": "capture_complete",
            "schema": "rac-stock-r-v2-session-v1",
            "session_id": "session-v2",
            "capture_started_ns": 200,
            "capture_ended_ns": 500,
            "completed": True,
            "events_seen": 1,
            "tracer_events_emitted": 1,
            "ringbuf_lost_events": 0,
            "collector_parse_errors": 0,
            "unmatched_equal_events": 0,
            "ambiguous_visit_events": 0,
            "dangling_visit_contexts": 0,
            "tracer_map_update_failures": 0,
            "active_visit_contexts": 0,
            "sequence_gaps": 0,
        },
    ]


def _trial(index: int, case: int, identity: dict[str, object]) -> dict[str, object]:
    return {
        "trial_id": index,
        "case": case,
        "test_run_rc": 0,
        "test_run_errno": 0,
        "retval": case,
        "map_value_after": case,
        "map_read_rc": 0,
        "trace_read_rc": 0,
        "program_identity": {
            "program_name": identity["program_name"],
            "program_id": identity["program_id"],
            "program_tag": identity["program_tag"],
            "program_load_time": identity["program_load_time"],
        },
        "trace": {
            "branch": case,
            "reset_rc": 0,
            "branch_rc": 0,
            "lookup_missing": False,
            "selected_value": case,
            "observed_value": case,
            "trace_errors": 0,
        },
    }


def _runtime(identity: dict[str, object]) -> dict[str, object]:
    return {
        "schema": "rac-stock-r-v2-runtime-v1",
        "program_load_started_ns": 240,
        "program_load_completed_ns": 250,
        "runtime_started_ns": 300,
        "runtime_ended_ns": 400,
        "identity": copy.deepcopy(identity),
        "trials": [
            _trial(0, 0, identity),
            _trial(1, 1, identity),
            _trial(2, 0, identity),
            _trial(3, 1, identity),
        ],
    }


def _proof(query: dict[str, object], runtime: dict[str, object]) -> dict[str, object]:
    identity = runtime["identity"]
    return {
        "schema": "rac-stock-r-v2-must-outcome-proof-v1",
        "proof_id": "stock-r-v2.array-map.must-outcome",
        "checker": {
            "calculus": "stock-r-v2-array-map-must-outcome-v1",
            "source_path": "residuality-auditor/src/residuality_auditor/stock_r_v2.py",
            "source_closure_sha256": query["source_closure_sha256"],
        },
        "query_digest_sha256": canonical_sha256(query),
        "source_closure_sha256": query["source_closure_sha256"],
        "build_closure_sha256": query["build_closure_sha256"],
        "identity": {
            "program_name": identity["program_name"],
            "program_id": identity["program_id"],
            "program_tag": identity["program_tag"],
            "program_load_time": identity["program_load_time"],
            "object_sha256": identity["object_sha256"],
            "xlated_sha256": identity["xlated_sha256"],
            "kernel_release": identity["kernel_release"],
            "btf_sha256": identity["btf_sha256"],
        },
        "witness": {
            "program_name": "rac_v2_single",
            "observer": "XDP_RETURN_BIT",
            "input": {"min_size": 1, "case_byte_offset": 0, "case_mask": 1},
            "state_map": {
                "name": "g0",
                "type": "BPF_MAP_TYPE_ARRAY",
                "max_entries": 1,
                "key_type": "u32",
                "value_type": "u32",
                "slot": 0,
            },
            "suffix": "shared_suffix",
        },
        "helper_contracts": [
            {
                "helper": "bpf_map_update_elem",
                "map": "g0",
                "key": 0,
                "flag": "BPF_ANY",
                "preconditions": ["array_map_preallocated", "key_in_range", "value_width_u32"],
                "postcondition": "slot_equals_value",
                "result": "SUCCESS",
            },
            {
                "helper": "bpf_map_lookup_elem",
                "map": "g0",
                "key": 0,
                "preconditions": ["array_map_preallocated", "key_in_range", "after_successful_update"],
                "postcondition": "returns_pointer_to_slot",
                "result": "PRESENT",
            },
        ],
        "cases": [
            {
                "case": 0,
                "input": {"byte": 0, "low_bit": 0},
                "steps": [
                    {"rule": "input-low-bit", "offset": 0, "mask": 1, "value": 0},
                    {"rule": "array-update-slot", "map": "g0", "key": 0, "value": 0, "rc": 0},
                    {"rule": "array-lookup-slot", "map": "g0", "key": 0, "value": 0, "lookup_missing": False},
                    {"rule": "return-low-bit", "value": 0, "mask": 1, "retval": 0},
                ],
                "outcome": 0,
            },
            {
                "case": 1,
                "input": {"byte": 1, "low_bit": 1},
                "steps": [
                    {"rule": "input-low-bit", "offset": 0, "mask": 1, "value": 1},
                    {"rule": "array-update-slot", "map": "g0", "key": 0, "value": 1, "rc": 0},
                    {"rule": "array-lookup-slot", "map": "g0", "key": 0, "value": 1, "lookup_missing": False},
                    {"rule": "return-low-bit", "value": 1, "mask": 1, "retval": 1},
                ],
                "outcome": 1,
            },
        ],
        "derived_outcomes": {"0": 0, "1": 1},
        "assumptions": [
            "ARRAY_MAP_KEY_ZERO_IN_RANGE",
            "ARRAY_MAP_UPDATE_BPF_ANY_SUCCEEDS_FOR_KEY_ZERO",
            "ARRAY_MAP_LOOKUP_AFTER_SUCCESSFUL_UPDATE_RETURNS_SLOT",
            "BPF_PROG_TEST_RUN_SUPPLIES_ONE_INPUT_BYTE",
            "XDP_RETVAL_OBSERVER_IS_PROGRAM_RETVAL_LOW_BIT",
        ],
    }


def _binding(
    query: dict[str, object],
    events: list[dict[str, object]],
    runtime: dict[str, object],
    proof: dict[str, object],
) -> dict[str, object]:
    return make_history_case_binding(query, events[1], runtime, proof)


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _write_json(path: Path, value: object) -> bytes:
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_bytes(path, data)
    return data


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8")


def _bundle(root: Path) -> None:
    identity = _identity()
    object_bytes = b"v2 object\n"
    btf_bytes = b"v2 btf\n"
    xlated_bytes = b"v2 xlated\n"
    identity["object_sha256"] = _sha_bytes(object_bytes)
    identity["btf_sha256"] = _sha_bytes(btf_bytes)
    identity["xlated_sha256"] = _sha_bytes(xlated_bytes)

    source_rel = "residuality-auditor/src/residuality_auditor/stock_r_v2.py"
    source_path = root / "build" / "source" / source_rel
    _write_bytes(source_path, b"source closure\n")
    source_manifest = {
        "schema": "rac-stock-r-v2-source-closure-v1",
        "entries": [
            {
                "path": source_rel,
                "sha256": _sha_bytes(source_path.read_bytes()),
                "size": source_path.stat().st_size,
            }
        ],
    }
    source_manifest_bytes = _write_json(root / "build" / "source-manifest.json", source_manifest)

    artifacts = {
        "btf-vmlinux": btf_bytes,
        "rac-v2-collect-fentry": b"collector\n",
        "rac-v2-witness": b"witness\n",
        "rac_v2_tracer_fentry.bpf.o": b"tracer object\n",
        "rac_v2_witness.bpf.o": object_bytes,
    }
    artifact_entries = []
    for name, data in artifacts.items():
        path = root / "build" / name
        _write_bytes(path, data)
        artifact_entries.append({"path": name, "sha256": _sha_bytes(data), "size": len(data)})
    artifact_manifest = {
        "schema": "rac-stock-r-v2-build-closure-v1",
        "entries": sorted(artifact_entries, key=lambda entry: entry["path"]),
    }
    artifact_manifest_bytes = _write_json(root / "build" / "artifact-manifest.json", artifact_manifest)

    query = _query(identity)
    query["source_closure_sha256"] = _sha_bytes(source_manifest_bytes)
    query["build_closure_sha256"] = _sha_bytes(artifact_manifest_bytes)
    policy = _policy(query)
    precommit = make_precommit(query, policy, recorded_at_ns=100)
    contract = _contract(query, policy)
    runtime = _runtime(identity)

    _write_json(root / "query" / "query.json", query)
    _write_json(root / "query" / "selection-policy.json", policy)
    _write_json(root / "query" / "precommit.json", precommit)
    _write_json(root / "contract" / "capture-contract.json", contract)
    _write_json(root / "raw" / "runtime.json", runtime)
    _write_jsonl(root / "raw" / "events.jsonl", _events(identity))
    _write_bytes(root / "raw" / "xlated-rac_v2_single.txt", xlated_bytes)
    _write_json(
        root / "raw" / "program-info.json",
        {
            "id": identity["program_id"],
            "tag": identity["program_tag"],
            "name": identity["program_name"],
            "load_time": identity["program_load_time"],
        },
    )


class StockRV2Tests(unittest.TestCase):
    def _input(
        self,
    ) -> tuple[
        dict[str, object],
        dict[str, object],
        dict[str, object],
        dict[str, object],
        list[dict[str, object]],
        dict[str, object],
    ]:
        identity = _identity()
        query = _query(identity)
        policy = _policy(query)
        precommit = make_precommit(query, policy, recorded_at_ns=100)
        return query, policy, precommit, _contract(query, policy), _events(identity), _runtime(identity)

    def test_good_observational_capture_remains_unknown_without_must_proof(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        report = audit_capture(query, policy, precommit, events, runtime, capture_contract_document=contract)
        self.assertEqual(report["assessment"]["status"], "UNKNOWN")
        self.assertEqual(report["capture"]["status"], "CAPTURE_COMPLETE")
        self.assertEqual(report["operational_prune"]["status"], "OPERATIONAL_PRUNE_OBSERVED")
        self.assertEqual(report["runtime_replication"]["status"], "REPLICATION_OBSERVED")
        self.assertEqual(report["outcome_eligibility"]["status"], "NOT_ESTABLISHED")
        self.assertEqual(report["runtime_replication"]["outcomes_by_case"], {"0": [0], "1": [1]})

    def test_valid_must_outcome_proof_without_history_case_binding_remains_unknown(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        proof = _proof(query, runtime)
        proof_result = check_must_outcome_proof(proof, query, runtime)
        self.assertEqual(proof_result["status"], "VERIFIED")
        self.assertEqual(proof_result["derived_outcomes"], {"0": 0, "1": 1})

        report = audit_capture(
            query,
            policy,
            precommit,
            events,
            runtime,
            capture_contract_document=contract,
            must_outcome_proof_document=proof,
        )
        self.assertEqual(report["outcome_eligibility"]["status"], "NOT_ESTABLISHED")
        self.assertEqual(report["outcome_eligibility"]["must_outcome_proof"]["status"], "VERIFIED")
        self.assertEqual(report["outcome_eligibility"]["history_case_binding"]["status"], "ABSENT")
        self.assertIn("HISTORY_CASE_BINDING", report["assessment"]["missing_obligations"])
        self.assertEqual(report["assessment"]["status"], "UNKNOWN")

    def test_history_case_binding_establishes_exact_v2_nonfactor_certificate(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        proof = _proof(query, runtime)
        binding = _binding(query, events, runtime, proof)
        binding_result = check_history_case_binding(binding, query, events[1], runtime, proof)
        self.assertEqual(binding_result["status"], "VERIFIED")

        report = audit_capture(
            query,
            policy,
            precommit,
            events,
            runtime,
            capture_contract_document=contract,
            must_outcome_proof_document=proof,
            history_case_binding_document=binding,
        )
        self.assertEqual(report["outcome_eligibility"]["status"], "ESTABLISHED")
        self.assertEqual(report["outcome_eligibility"]["method"], "MUST_OUTCOME_PROOF_WITH_HISTORY_CASE_BINDING")
        self.assertEqual(report["outcome_eligibility"]["derived_outcomes"], {"0": 0, "1": 1})
        self.assertEqual(report["outcome_eligibility"]["history_case_binding"]["status"], "VERIFIED")
        self.assertEqual(report["assessment"]["status"], "NONFACTORING")
        self.assertEqual(report["assessment"]["scope"], "EXACT_STOCK_R_V2_QUERY")
        self.assertTrue(report["assessment"]["certificate"].startswith("NONFACTORING@"))

    def test_history_case_binding_tampering_fails_closed(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        proof = _proof(query, runtime)
        cases = {
            "history digest": lambda binding: binding["histories"][0].__setitem__("history_digest_sha256", _hex("f")),
            "case swap": lambda binding: binding["histories"][0].__setitem__("case", 1),
            "frontier": lambda binding: binding["frontier"].__setitem__("visit_insn", 999),
            "suffix": lambda binding: binding.__setitem__("suffix", "other_suffix"),
            "report cell": lambda binding: binding["report_cell"].__setitem__("cell_id", _hex("f")),
            "observer": lambda binding: binding.__setitem__("observer", "RAW_RETVAL"),
            "outcome": lambda binding: binding["histories"][1].__setitem__("outcome", 0),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                binding = _binding(query, events, runtime, proof)
                mutate(binding)
                report = audit_capture(
                    query,
                    policy,
                    precommit,
                    events,
                    runtime,
                    capture_contract_document=contract,
                    must_outcome_proof_document=proof,
                    history_case_binding_document=binding,
                )
                self.assertEqual(report["assessment"]["status"], "INVALID_EVIDENCE")
                self.assertNotEqual(report["outcome_eligibility"]["status"], "ESTABLISHED")
                self.assertTrue(
                    any(reason.startswith("HISTORY_CASE_BINDING_") for reason in report["invalid_reasons"])
                )

    def test_must_outcome_proof_tampering_fails_closed(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        cases = {
            "query digest": lambda proof: proof.__setitem__("query_digest_sha256", _hex("f")),
            "object digest": lambda proof: proof["identity"].__setitem__("object_sha256", _hex("f")),
            "xlated digest": lambda proof: proof["identity"].__setitem__("xlated_sha256", _hex("f")),
            "map descriptor": lambda proof: proof["witness"]["state_map"].__setitem__("max_entries", 2),
            "checker calculus": lambda proof: proof["checker"].__setitem__("calculus", "unchecked"),
            "helper weakening": lambda proof: proof["helper_contracts"][0].__setitem__("result", "MAY_FAIL"),
            "case table": lambda proof: proof.__setitem__("derived_outcomes", {"0": 1, "1": 1}),
            "derivation gap": lambda proof: proof["cases"][0].__setitem__("steps", proof["cases"][0]["steps"][:-1]),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                proof = _proof(query, runtime)
                mutate(proof)
                report = audit_capture(
                    query,
                    policy,
                    precommit,
                    events,
                    runtime,
                    capture_contract_document=contract,
                    must_outcome_proof_document=proof,
                )
                self.assertEqual(report["assessment"]["status"], "INVALID_EVIDENCE")
                self.assertNotEqual(report["outcome_eligibility"]["status"], "ESTABLISHED")
                self.assertTrue(any(reason.startswith("MUST_OUTCOME_PROOF_") for reason in report["invalid_reasons"]))

    def test_valid_must_outcome_proof_cannot_mask_runtime_mismatch(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        proof = _proof(query, runtime)
        for trial in runtime["trials"]:
            if trial["case"] == 0:
                trial["retval"] = 1
                trial["map_value_after"] = 1
                trial["trace"]["selected_value"] = 1
                trial["trace"]["observed_value"] = 1
        report = audit_capture(
            query,
            policy,
            precommit,
            events,
            runtime,
            capture_contract_document=contract,
            must_outcome_proof_document=proof,
        )
        self.assertEqual(report["assessment"]["status"], "INVALID_EVIDENCE")
        self.assertIn("MUST_OUTCOME_PROOF_RUNTIME_OUTCOME_MISMATCH", report["invalid_reasons"])
        self.assertNotEqual(report["outcome_eligibility"]["status"], "ESTABLISHED")

    def test_valid_must_outcome_proof_without_operational_prune_remains_unknown(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        proof = _proof(query, runtime)
        events[1]["program_tag"] = "1111111111111111"
        report = audit_capture(
            query,
            policy,
            precommit,
            events,
            runtime,
            capture_contract_document=contract,
            must_outcome_proof_document=proof,
        )
        self.assertEqual(report["assessment"]["status"], "UNKNOWN")
        self.assertEqual(report["operational_prune"]["status"], "OPERATIONAL_PRUNE_NOT_OBSERVED")
        self.assertEqual(report["outcome_eligibility"]["status"], "NOT_ESTABLISHED")
        self.assertIn("NO_QUALIFYING_OPERATIONAL_PRUNE", report["assessment"]["missing_obligations"])

    def test_must_outcome_proof_rejects_data_only_verified_flag(self) -> None:
        query, _policy_document, _precommit, _contract, _events, runtime = self._input()
        proof = _proof(query, runtime)
        proof["verified"] = True
        result = check_must_outcome_proof(proof, query, runtime)
        self.assertEqual(result["status"], "INVALID")
        self.assertIn("MUST_OUTCOME_PROOF_UNEXPECTED_FIELD", result["invalid_reasons"])

    def test_make_must_outcome_proof_is_checked_and_bundle_audit_reads_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _bundle(root)
            query = json.loads((root / "query" / "query.json").read_text(encoding="utf-8"))
            runtime = json.loads((root / "raw" / "runtime.json").read_text(encoding="utf-8"))
            proof = make_must_outcome_proof(query, runtime)
            _write_json(root / "proof" / "must-outcome-proof.json", proof)
            report = audit_bundle(root)
            self.assertEqual(report["outcome_eligibility"]["status"], "NOT_ESTABLISHED")
            self.assertEqual(report["outcome_eligibility"]["history_case_binding"]["status"], "ABSENT")
            binding = make_history_case_binding(
                query,
                _events(runtime["identity"])[1],
                runtime,
                proof,
            )
            _write_json(root / "proof" / "history-case-binding.json", binding)
            report = audit_bundle(root)
            self.assertEqual(report["outcome_eligibility"]["status"], "ESTABLISHED")
            self.assertEqual(report["assessment"]["status"], "NONFACTORING")

    def test_prove_outcomes_cli_writes_checked_bundle_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _bundle(root)
            script = Path(__file__).resolve().parents[1] / "linux" / "scripts" / "stock_r_v2.py"
            result = subprocess.run(
                [sys.executable, str(script), "prove-outcomes", str(root)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / "proof" / "must-outcome-proof.json").is_file())
            self.assertEqual(len(result.stdout.strip()), 64)

            report = audit_bundle(root)
            self.assertEqual(report["assessment"]["status"], "UNKNOWN")
            self.assertEqual(report["outcome_eligibility"]["history_case_binding"]["status"], "ABSENT")

            result = subprocess.run(
                [sys.executable, str(script), "bind-history-case", str(root)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / "proof" / "history-case-binding.json").is_file())
            self.assertEqual(len(result.stdout.strip()), 64)

            report = audit_bundle(root)
            self.assertEqual(report["outcome_eligibility"]["status"], "ESTABLISHED")
            self.assertEqual(report["assessment"]["status"], "NONFACTORING")

    def test_precommit_must_bind_query_and_policy(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        precommit["query_digest_sha256"] = _hex("d")
        report = audit_capture(query, policy, precommit, events, runtime, capture_contract_document=contract)
        self.assertEqual(report["assessment"]["status"], "INVALID_EVIDENCE")
        self.assertIn("PRECOMMIT_QUERY_DIGEST_MISMATCH", report["invalid_reasons"])

    def test_capture_before_precommit_is_invalid(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        precommit["recorded_at_ns"] = 200
        report = audit_capture(query, policy, precommit, events, runtime, capture_contract_document=contract)
        self.assertEqual(report["assessment"]["status"], "INVALID_EVIDENCE")
        self.assertIn("PRECOMMIT_NOT_BEFORE_CAPTURE", report["invalid_reasons"])

    def test_program_load_must_start_after_precommit(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        events[0]["capture_started_ns"] = 50
        events[0]["capture_attached_ns"] = 60
        events[-1]["capture_started_ns"] = 50
        runtime["program_load_started_ns"] = 90
        runtime["program_load_completed_ns"] = 95
        runtime["runtime_started_ns"] = 120
        report = audit_capture(query, policy, precommit, events, runtime, capture_contract_document=contract)
        self.assertEqual(report["assessment"]["status"], "INVALID_EVIDENCE")
        self.assertIn("PRECOMMIT_NOT_BEFORE_PROGRAM_LOAD", report["invalid_reasons"])

    def test_identity_mismatch_makes_prune_nonqualifying_not_a_match(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        events[1]["program_load_time"] = 251
        report = audit_capture(query, policy, precommit, events, runtime, capture_contract_document=contract)
        self.assertEqual(report["assessment"]["status"], "UNKNOWN")
        self.assertEqual(report["operational_prune"]["status"], "OPERATIONAL_PRUNE_NOT_OBSERVED")

    def test_program_tag_mismatch_makes_prune_nonqualifying(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        events[1]["program_tag"] = "1111111111111111"
        report = audit_capture(query, policy, precommit, events, runtime, capture_contract_document=contract)
        self.assertEqual(report["assessment"]["status"], "UNKNOWN")
        self.assertEqual(report["operational_prune"]["status"], "OPERATIONAL_PRUNE_NOT_OBSERVED")

    def test_multiple_qualifying_prunes_are_rejected(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        duplicate = copy.deepcopy(events[1])
        duplicate["sequence"] = 2
        duplicate["equality_sequence"] = 42
        duplicate["visit_sequence"] = 18
        events.insert(2, duplicate)
        events[-1]["events_seen"] = 2
        events[-1]["tracer_events_emitted"] = 2
        report = audit_capture(query, policy, precommit, events, runtime, capture_contract_document=contract)
        self.assertEqual(report["assessment"]["status"], "INVALID_EVIDENCE")
        self.assertIn("QUALIFYING_PRUNE_NOT_UNIQUE", report["invalid_reasons"])

    def test_incomplete_history_is_not_an_operational_cell(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        events[1]["old"]["history_truncated"] = True
        report = audit_capture(query, policy, precommit, events, runtime, capture_contract_document=contract)
        self.assertEqual(report["assessment"]["status"], "UNKNOWN")
        self.assertEqual(report["operational_prune"]["status"], "OPERATIONAL_PRUNE_NOT_OBSERVED")
        self.assertIn("NO_QUALIFYING_OPERATIONAL_PRUNE", report["assessment"]["missing_obligations"])

    def test_collector_loss_is_invalid(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        events[-1]["ringbuf_lost_events"] = 1
        report = audit_capture(query, policy, precommit, events, runtime, capture_contract_document=contract)
        self.assertEqual(report["assessment"]["status"], "INVALID_EVIDENCE")
        self.assertIn("RINGBUF_LOSS", report["invalid_reasons"])

    def test_runtime_schedule_and_trace_are_checked(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        runtime["trials"][2]["case"] = 1
        report = audit_capture(query, policy, precommit, events, runtime, capture_contract_document=contract)
        self.assertEqual(report["assessment"]["status"], "INVALID_EVIDENCE")
        self.assertIn("TRIAL_SCHEDULE_MISMATCH", report["invalid_reasons"])

    def test_runtime_identity_and_observer_must_cohere(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        runtime["trials"][1]["program_identity"]["program_id"] = 7002
        runtime["trials"][1]["retval"] = 0
        report = audit_capture(query, policy, precommit, events, runtime, capture_contract_document=contract)
        self.assertEqual(report["assessment"]["status"], "INVALID_EVIDENCE")
        self.assertIn("TRIAL_PROGRAM_ID_MISMATCH", report["invalid_reasons"])
        self.assertIn("TRIAL_OBSERVER_TRACE_MISMATCH", report["invalid_reasons"])

    def test_runtime_map_or_trace_read_failure_is_invalid(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        runtime["trials"][0]["map_read_rc"] = -5
        runtime["trials"][1]["trace_read_rc"] = -5
        report = audit_capture(query, policy, precommit, events, runtime, capture_contract_document=contract)
        self.assertEqual(report["assessment"]["status"], "INVALID_EVIDENCE")
        self.assertIn("TRIAL_MAP_READ_RC_NONZERO", report["invalid_reasons"])
        self.assertIn("TRIAL_TRACE_READ_RC_NONZERO", report["invalid_reasons"])

    def test_mixed_repeated_outcomes_are_invalid(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        runtime["trials"][2]["retval"] = 1
        runtime["trials"][2]["map_value_after"] = 1
        runtime["trials"][2]["trace"]["observed_value"] = 1
        report = audit_capture(query, policy, precommit, events, runtime, capture_contract_document=contract)
        self.assertEqual(report["assessment"]["status"], "INVALID_EVIDENCE")
        self.assertIn("TRIAL_CASE_SEMANTICS_MISMATCH", report["invalid_reasons"])

    def test_boolean_scalars_are_invalid_not_integers(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        events[1]["exact_level"] = False
        runtime["trials"][0]["retval"] = False
        report = audit_capture(query, policy, precommit, events, runtime, capture_contract_document=contract)
        self.assertEqual(report["assessment"]["status"], "INVALID_EVIDENCE")
        self.assertIn("PRUNE_EXACT_LEVEL_INVALID", report["invalid_reasons"])
        self.assertIn("TRIAL_OBSERVER_VALUE_INVALID", report["invalid_reasons"])

    def test_bundle_integrity_accepts_self_contained_fixture_and_rejects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _bundle(root)
            report = audit_bundle(root)
            self.assertEqual(report["assessment"]["status"], "UNKNOWN")
            self.assertEqual(report["operational_prune"]["status"], "OPERATIONAL_PRUNE_OBSERVED")

            (root / "build" / "source" / "residuality-auditor/src/residuality_auditor/stock_r_v2.py").write_text(
                "tampered\n", encoding="utf-8"
            )
            report = audit_bundle(root)
            self.assertEqual(report["assessment"]["status"], "INVALID_EVIDENCE")
            self.assertIn("BUNDLE_SOURCE_ENTRY_MISMATCH", report["invalid_reasons"])

    def test_bundle_integrity_checks_btf_and_program_load_time_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _bundle(root)
            (root / "build" / "btf-vmlinux").write_bytes(b"tampered btf\n")
            info = json.loads((root / "raw" / "program-info.json").read_text(encoding="utf-8"))
            info["load_time"] = 999
            _write_json(root / "raw" / "program-info.json", info)
            report = audit_bundle(root)
            self.assertEqual(report["assessment"]["status"], "INVALID_EVIDENCE")
            self.assertIn("BUNDLE_BTF_RECEIPT_MISMATCH", report["invalid_reasons"])
            self.assertIn("BUNDLE_BUILD_ENTRY_MISMATCH", report["invalid_reasons"])
            self.assertIn("BUNDLE_PROGRAM_INFO_MISMATCH", report["invalid_reasons"])

    def test_malformed_documents_raise(self) -> None:
        query, policy, precommit, contract, events, runtime = self._input()
        query["schema"] = "wrong"
        with self.assertRaises(StockRV2Error):
            audit_capture(query, policy, precommit, events, runtime, capture_contract_document=contract)


if __name__ == "__main__":
    unittest.main()
