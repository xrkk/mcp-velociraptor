"""Windows-only regressions for P05 §0.7 raw-predicate fail-closed gates.

These are negative parser contracts, not substitute evidence of a real
Windows acceptance. They are held for the Windows acceptance host by CON-002.
"""

from __future__ import annotations

import ast
from pathlib import Path
import sys
import unittest


@unittest.skipUnless(sys.platform == "win32", "CON-002: P05 behavior tests execute on Windows")
class ActivationRawFailClosedTests(unittest.TestCase):
    workflow = "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2"
    run_id = "raw-run-188"
    restore_id = "raw-restore-188"

    def _dependency(self) -> dict:
        return {
            "schema_version": 1, "workflow_id": self.workflow, "run_id": self.run_id,
            "restore_attempt_id": self.restore_id, "inventory_artifacts": {},
            "four_chains": {}, "network_observations": {},
        }

    def _entry(self) -> dict:
        return {
            "schema_version": 1, "workflow_id": self.workflow, "run_id": self.run_id,
            "restore_attempt_id": self.restore_id, "cases": {},
        }

    def _network(self) -> dict:
        return {
            "schema_version": 1, "workflow_id": self.workflow, "run_id": self.run_id,
            "restore_attempt_id": self.restore_id, "non_allowed_source": {},
            "schema_identity": {}, "service_observation": {},
        }

    def test_public_predicates_remain_importable_but_not_accepted(self) -> None:
        from tests import p05_activation_raw as raw

        self.assertTrue(issubclass(raw.ActivationRawEvidenceError, ValueError))
        self.assertTrue(callable(raw.verify_dependency_acceptance_raw))
        self.assertTrue(callable(raw.verify_entry_gate_raw))
        self.assertTrue(callable(raw.verify_network_evidence_raw))

    def test_dependency_rejects_empty_window_manifest_hash_drift_and_protected_subset(self) -> None:
        from tests import p05_activation_raw as raw

        with self.assertRaisesRegex(raw.ActivationRawEvidenceError, "not implemented") as raised:
            raw.verify_dependency_acceptance_raw(
                self._dependency(), bundle_root=Path("."), run_id=self.run_id,
                restore_attempt_id=self.restore_id, report={}, ready={},
            )
        for gate in (
            "manifest_hash_size_probe_artifact_field_join",
            "four_chain_complete_raw_sdk_messages_and_stderr",
            "ready_protected_process_exact_join_and_kill_adjacency",
            "server_client_network_window_session_loss_and_address_allowlist",
        ):
            self.assertIn(gate, str(raised.exception))

    def test_entry_rejects_200_summary_casefolded_header_bypass_and_unbracketed_counter(self) -> None:
        from tests import p05_activation_raw as raw

        with self.assertRaisesRegex(raw.ActivationRawEvidenceError, "not implemented") as raised:
            raw.verify_entry_gate_raw(
                self._entry(), bundle_root=Path("."), run_id=self.run_id,
                restore_attempt_id=self.restore_id, endpoint="http://192.168.204.232:28790/mcp",
                allowed_origin="https://allowed.example",
            )
        for gate in (
            "seven_raw_http_requests_responses_and_initialize_result",
            "casefolded_host_origin_fixed_configuration_join",
            "handler_counter_time_bracket",
        ):
            self.assertIn(gate, str(raised.exception))

    def test_network_rejects_pc006_rule_drift_public_destination_and_schema_service_summary(self) -> None:
        from tests import p05_activation_raw as raw

        with self.assertRaisesRegex(raw.ActivationRawEvidenceError, "not implemented") as raised:
            raw.verify_network_evidence_raw(
                self._network(), bundle_root=Path("."), run_id=self.run_id,
                restore_attempt_id=self.restore_id, report={"server_identity": {}},
            )
        for gate in (
            "pc006_bound_source_command_output_and_exact_192_168_204_1_232_rule",
            "complete_non_public_destination_allowlist",
            "raw_http_stdio_tools_list_and_service_observation_join",
        ):
            self.assertIn(gate, str(raised.exception))

    def test_retained_legacy_summaries_cannot_be_promoted_to_raw_originals(self) -> None:
        from tests import p05_activation_raw as raw

        for legacy in (
            {"schema": "p05-real-acceptance-v1", "ok": True},
            {"schema": "p05-dependency-acceptance-v1", "ok": True},
            [{"method": "POST", "path": "/mcp", "status_code": 200,
              "mcp_session_id": "s", "server_instance_id": "i", "request_session_id": None}],
        ):
            with self.subTest(legacy=type(legacy).__name__), self.assertRaises(raw.ActivationRawEvidenceError):
                raw.reject_summary_substitute(legacy, label="retained-original")


class ActivationRawStaticTests(unittest.TestCase):
    def test_module_is_parseable_without_running_a_behavior_test(self) -> None:
        source = Path(__file__).with_name("p05_activation_raw.py")
        ast.parse(source.read_text(encoding="utf-8"), filename=str(source))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
