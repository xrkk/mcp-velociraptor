"""Fail-closed placeholder for P05 §0.7 activation raw predicates.

This module deliberately does *not* turn the currently retained P05/P06 logs
into activation evidence. They are useful historical originals, but their
formats do not contain the facts §0.7 requires:

* ``p05-real-acceptance-v1`` records call/result summaries, Flow-state
  summaries and two point-in-time OS observations. It has no complete raw SDK
  messages, preserved stderr, complete network collection window, or a join to
  the current ready protected-process set.
* ``p05-dependency-acceptance-v1`` records before/after VQL result summaries;
  it does not retain the required current-window observation originals.
* ``p05_external_acceptance.verify_entry_gate`` writes booleans, not seven raw
  HTTP request/response/handler-counter originals.
* Known ``http-headers.json`` has only method/path/status/session/instance
  summaries, and ``server-observation.json`` is a guest identity observation.
  Neither is an entry-gate transcript or a network-capture window.

No collector schema is invented here. A later Windows-only collector must
freeze actual raw MCP/HTTP messages, handler observations, network capture
sessions, loss counters, and their command records. Only then may these public
functions grow parsers. Until then each validates the P05 §0.7 wrapper identity
and raises ``ActivationRawEvidenceError``.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any


class ActivationRawEvidenceError(ValueError):
    """A P05 activation needs an unavailable or false raw-original predicate."""


WORKFLOW_ID = "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2"

# Observed retained source formats, not a new acceptance schema. These prevent
# a later implementation from mislabelling the old summaries as P05 §0.7 raw
# originals.
KNOWN_LEGACY_SUMMARIES = {
    "p05-real-acceptance-v1": frozenset({
        "schema", "workflow_id", "attempt_id", "hostname", "started_at", "ended_at",
        "calls", "flow_states", "owned_flows", "unsettled_owned_flows", "trace_before",
        "trace_after", "network_before", "network_after", "original_domain_observation",
        "failure", "ok",
    }),
    "p05-dependency-acceptance-v1": frozenset({
        "schema", "workflow_id", "attempt_id", "started_at", "ended_at", "requested_mode",
        "initial_state", "before", "writes", "after", "ok",
    }),
    "p05-external-entry-gate-summary": frozenset({
        "no_origin_authorized", "instance_header_present", "session_header_present",
        "missing_bearer_rejected_401", "wrong_bearer_rejected_401", "bad_host_rejected",
        "unapproved_origin_rejected",
    }),
    "p06-http-headers-summary": frozenset({
        "method", "path", "status_code", "mcp_session_id", "server_instance_id",
        "request_session_id",
    }),
}

# Name every blocked predicate so callers cannot interpret the three public
# function names as completed acceptance categories.
UNIMPLEMENTED_GATES = {
    "dependency": (
        "manifest_hash_size_probe_artifact_field_join",
        "four_chain_complete_raw_sdk_messages_and_stderr",
        "ready_protected_process_exact_join_and_kill_adjacency",
        "server_client_network_window_session_loss_and_address_allowlist",
    ),
    "entry": (
        "seven_raw_http_requests_responses_and_initialize_result",
        "casefolded_host_origin_fixed_configuration_join",
        "handler_counter_time_bracket",
    ),
    "network": (
        "pc006_bound_source_command_output_and_exact_192_168_204_1_232_rule",
        "complete_non_public_destination_allowlist",
        "raw_http_stdio_tools_list_and_service_observation_join",
    ),
}


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ActivationRawEvidenceError(f"{label} must be a non-empty string")
    return value


def _phase_identity(
    document: Mapping[str, Any],
    *,
    expected_keys: set[str],
    category: str,
    run_id: str,
    restore_attempt_id: str,
) -> None:
    """Reject malformed wrapper data before announcing the deliberate block."""
    if not isinstance(document, Mapping) or set(document) != expected_keys:
        raise ActivationRawEvidenceError(f"{category} wrapper keys are invalid")
    if (
        document.get("schema_version") != 1
        or document.get("workflow_id") != WORKFLOW_ID
        or document.get("run_id") != run_id
        or document.get("restore_attempt_id") != restore_attempt_id
    ):
        raise ActivationRawEvidenceError(f"{category} wrapper identity differs from phase")
    _nonempty(run_id, f"{category}.run_id")
    _nonempty(restore_attempt_id, f"{category}.restore_attempt_id")


def _unimplemented(category: str) -> None:
    blocked = ", ".join(UNIMPLEMENTED_GATES[category])
    raise ActivationRawEvidenceError(
        f"P05 §0.7 {category} raw predicates are not implemented; "
        f"Windows collector originals are required for: {blocked}"
    )


def reject_summary_substitute(value: Any, *, label: str) -> None:
    """Reject known current summaries; unknown JSON also remains unaccepted."""
    if isinstance(value, Mapping) and value.get("schema") in {
        "p05-real-acceptance-v1", "p05-dependency-acceptance-v1"
    }:
        raise ActivationRawEvidenceError(f"{label} is a retained legacy summary, not a raw original")
    if isinstance(value, Mapping) and any(key.casefold() in {"passed", "ok", "expected"} for key in value):
        raise ActivationRawEvidenceError(f"{label} contains a verdict summary, not raw facts")
    if isinstance(value, list) and value and all(isinstance(item, Mapping) for item in value):
        keys = set().union(*(set(item) for item in value))
        if KNOWN_LEGACY_SUMMARIES["p06-http-headers-summary"].issubset(keys):
            raise ActivationRawEvidenceError(f"{label} is an HTTP-header summary, not raw HTTP evidence")
    raise ActivationRawEvidenceError(f"{label} has no frozen raw collector schema")


def verify_dependency_acceptance_raw(
    document: Mapping[str, Any],
    *,
    bundle_root: Path,
    run_id: str,
    restore_attempt_id: str,
    report: Mapping[str, Any] | None = None,
    ready: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Fail closed: dependency/four-chain originals are summaries only."""
    del bundle_root, report, ready
    _phase_identity(
        document,
        expected_keys={
            "schema_version", "workflow_id", "run_id", "restore_attempt_id",
            "inventory_artifacts", "four_chains", "network_observations",
        },
        category="dependency", run_id=run_id, restore_attempt_id=restore_attempt_id,
    )
    _unimplemented("dependency")


def verify_entry_gate_raw(
    document: Mapping[str, Any],
    *,
    bundle_root: Path,
    run_id: str,
    restore_attempt_id: str,
    endpoint: str | None = None,
    allowed_origin: str | None = None,
) -> dict[str, Any]:
    """Fail closed: P05 currently records booleans, not raw HTTP cases."""
    del bundle_root, endpoint, allowed_origin
    _phase_identity(
        document,
        expected_keys={"schema_version", "workflow_id", "run_id", "restore_attempt_id", "cases"},
        category="entry", run_id=run_id, restore_attempt_id=restore_attempt_id,
    )
    _unimplemented("entry")


def verify_network_evidence_raw(
    document: Mapping[str, Any],
    *,
    bundle_root: Path,
    run_id: str,
    restore_attempt_id: str,
    report: Mapping[str, Any],
) -> dict[str, Any]:
    """Fail closed: no complete PC006/network/schema/service originals exist."""
    del bundle_root, report
    _phase_identity(
        document,
        expected_keys={
            "schema_version", "workflow_id", "run_id", "restore_attempt_id",
            "non_allowed_source", "schema_identity", "service_observation",
        },
        category="network", run_id=run_id, restore_attempt_id=restore_attempt_id,
    )
    _unimplemented("network")
