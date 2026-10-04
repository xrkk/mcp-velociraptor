"""Read-only fixed lifecycle preflight, before backend and HTTP construction.

The native exporter has not been implemented or qualified. Consequently the
production entry always refuses after its read-only qualification gates. No
test seam, CLI option, environment value or HTTP parameter enables it.
"""
from __future__ import annotations

from tests import p05_pc026_governance as gov
from velociraptor_observation_config import load_approved, _close_note
from velociraptor_observation_sdk import _verify_approved_sdk

CONTRACT = 'PLAN/2026.10.04-02-PC026-归档生命周期与结束消费契约.md'
CONTRACT_REF = dict(path=CONTRACT, size=57074,
    sha256='b739f989632d86fe71084cdbcb2c0291b49198330b69b1595cd171d6e5f5a1d8')
CONFIG = gov.BASE + 'observation-lifecycle-configuration.json'
_BUDGETS = frozenset('max_sessions max_sdk_work max_binary_work max_pending_work '
    'max_request_body_bytes max_export_files max_export_bytes max_export_directories '
    'max_cut_bytes max_proof_bytes max_source_manifest_bytes max_maintenance_calls '
    'max_maintenance_bytes max_retained_state_bytes close_timeout_ns min_free_bytes'.split())


class ObservationStartupError(Exception):
    """No formal lifecycle authority; contains a bounded public category only."""


def _precheck_loaded(archive):
    """Private read-only gate; never creates a ledger, exporter or HTTP app."""
    from velociraptor_observation_config import CONFIG as ARCHIVE_CONFIG
    group = archive.group
    gov.require(group.allowed.get(CONTRACT) == CONTRACT_REF, 'lifecycle adopted anchor differs')
    group.read(CONTRACT_REF)
    gov.require(CONFIG in group.allowed and CONFIG not in group.freeze_refs,
                'lifecycle fixed input absent or cyclic')
    doc = group.document(group.allowed[CONFIG])
    gov.exact(doc, 'schema_version kind profile_id workflow_id contract_ref archive_config_ref '
              'deployment_ref implementation_freeze_ref budgets metadata_policy status',
              'pc026-observation-lifecycle-configuration-v1', 'AUTHORIZED')
    gov.require(doc['contract_ref'] == CONTRACT_REF
                and doc['archive_config_ref'] == group.allowed[ARCHIVE_CONFIG]
                and doc['deployment_ref'] == archive.document['deployment_ref']
                and doc['implementation_freeze_ref'] == archive.document['implementation_freeze_ref']
                and doc['profile_id'] == archive.document['profile_id']
                and doc['workflow_id'] == archive.document['workflow_id']
                and doc['metadata_policy'] == 'GLOBAL_PREFIX_NO_OTHER_SESSION_EVENTS',
                'lifecycle input bindings differ')
    budgets = doc['budgets']
    gov.require(type(budgets) is dict and set(budgets) == _BUDGETS
                and all(type(v) is int and v > 0 for v in budgets.values()), 'lifecycle budgets differ')
    old = archive.document['budgets']
    A, C = old['max_attempts'], old['max_catalog_record_bytes']
    R, B, T = (old['request_codec'][k] for k in ('max_records', 'max_record_bytes', 'max_total_bytes'))
    S, K, P, J = (budgets[k] for k in ('max_sessions', 'max_cut_bytes', 'max_proof_bytes', 'max_source_manifest_bytes'))
    # Use the actual 05 reader gate, not the historical MODEL SD vector.
    # These remain logical reserves, not native free-space/RSS qualification.
    from tests.p05_pc026_windows_reader import MAX_SD_BYTES
    D = MAX_SD_BYTES
    N = 3*A + 2 + A*R
    minimum = S*((3*A + 2)*C + A*T + N*D + P + J + 3*K)
    gov.require(budgets['max_export_files'] >= S*(2*N + 5)
                and budgets['max_export_directories'] >= 1 + S*(A + 4)
                and budgets['max_export_bytes'] >= minimum + max(K, P, J, B, C, D),
                'lifecycle export/pending reserves insufficient')
    _verify_approved_sdk(group)
    group.recheck()
    return doc


def precheck_formal_http():
    """Production closed gate; owns and closes exactly one approved group."""
    archive = None
    primary = None
    try:
        archive = load_approved()
        _precheck_loaded(archive)
        raise ObservationStartupError('native_exporter_unavailable')
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if archive is not None:
            try:
                archive.group.close()
            except BaseException:
                if primary is not None:
                    _close_note(primary)
                else:
                    raise
