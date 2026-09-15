"""Read-only reconstruction of one live candidate snapshot creation.

Consumes the same complete command-envelope format used by baseline adoption;
does not execute VMware commands or accept a parsed marker as original proof.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
import json
from pathlib import Path
from typing import Any

from tests.p05_snapshot_raw import (
    SnapshotRawError, command, host_vmx, snapshot_marker, snapshot_names, utc,
    vmsd_fields,
)

WORKFLOW_ID = 'wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2'
PREPARATION = 'Snapshot 187-固定IP+WindowsMCP开机自启'
CANDIDATE = 'Snapshot 188-Velociraptor-MCP可恢复验收基线'
KEYS = {
    'schema_version', 'workflow_id', 'candidate', 'checkpoint_marker', 'vmx',
    'tree_before', 'create_operation', 'tree_after', 'metadata_readback',
}
# PLAN-CHANGE-016: the existing Snapshot188 was created (2026-09-14T18:17:50Z)
# before live command envelopes were captured, and its tree_before state can no
# longer be re-executed authentically. A creation document may instead carry a
# bounded historical reconstruction: two real command envelopes bracketing the
# creation, the vmsd-written creation instant decoded from original vmsd bytes,
# and an attestation bound to the execution ledger. Live envelopes remain the
# default and the only mode for any future candidate creation.
RECONSTRUCTION_MODE = 'historical-reconstruction'
RECONSTRUCTION_KEYS = KEYS | {'evidence_mode', 'create_time_utc'}
ATTESTATION_KIND = 'p05-candidate-creation-attestation-v1'
ATTESTATION_KEYS = {
    'schema_version', 'kind', 'workflow_id', 'candidate', 'vmx', 'operation',
    'created_at_utc', 'no_pre_stop', 'ledger',
}


def _decode_create_instant(fields: dict[str, str]) -> Any:
    """Decode the vmsd snapshot1.createTime pair (epoch microseconds)."""
    from datetime import UTC, datetime

    try:
        high, low = int(fields['snapshot1.createTimeHigh']), int(fields['snapshot1.createTimeLow'])
    except (KeyError, ValueError) as exc:
        raise SnapshotRawError('vmsd original lacks the candidate creation instant') from exc
    microseconds = (high << 32) | low
    if microseconds <= 0:
        raise SnapshotRawError('vmsd candidate creation instant is not positive')
    return datetime.fromtimestamp(microseconds / 1_000_000, tz=UTC)


def _verify_reconstruction(
    document: Mapping[str, Any], *, vmx: Any, expected_marker: str,
    resolve: Callable[[Any, str], Path],
) -> dict[str, Any]:
    from datetime import timedelta

    originals: dict[str, Any] = {}
    for key in ('tree_before', 'create_operation', 'tree_after', 'metadata_readback'):
        path = resolve(document[key], 'creation_metadata.' + key)
        try:
            originals[key] = json.loads(path.read_text(encoding='utf-8-sig'))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SnapshotRawError('candidate reconstruction original is not readable JSON') from exc

    # The tree brackets must be genuine vmrun listSnapshots command envelopes
    # captured before and after the creation instant; their own observation and
    # operation identities are preserved (they were not created for this doc).
    for key in ('tree_before', 'tree_after'):
        envelope = originals[key]
        if not isinstance(envelope, dict):
            raise SnapshotRawError(f'{key} reconstruction original is not an envelope')
        argv = envelope.get('request', {}).get('argv') if isinstance(envelope.get('request'), dict) else None
        # Both capture generations exist: with and without the '-T ws' flag.
        if (not isinstance(argv, list) or not argv or argv[0] != '/usr/bin/vmrun'
                or 'listSnapshots' not in argv[:4] or str(vmx) not in argv):
            raise SnapshotRawError(f'{key} reconstruction original is not a snapshot-tree command')
        command(envelope, workflow_id=WORKFLOW_ID, operation_id=envelope['operation_id'],
                observation=envelope['observation'], vmx=str(vmx))
    metadata = originals['metadata_readback']
    metadata_argv = metadata.get('request', {}).get('argv') if isinstance(metadata, dict) else None
    if metadata_argv not in (
        ['/usr/bin/cat', str(vmx.with_suffix('.vmsd'))],
        ['/bin/cat', str(vmx.with_suffix('.vmsd'))],
    ):
        raise SnapshotRawError('metadata_readback reconstruction original is not a vmsd read')
    command(metadata, workflow_id=WORKFLOW_ID, operation_id=metadata['operation_id'],
            observation=metadata['observation'], vmx=str(vmx))

    before = snapshot_names(originals['tree_before']['response']['stdout'])
    after = snapshot_names(originals['tree_after']['response']['stdout'])
    if before != [PREPARATION] or set(after) != {PREPARATION, CANDIDATE} or len(after) != 2:
        raise SnapshotRawError('candidate reconstruction does not prove exactly zero to one while retaining 187')
    if utc(originals['tree_before']['ended_at']) >= utc(originals['tree_after']['started_at']):
        raise SnapshotRawError('reconstruction tree brackets overlap or run backwards')

    fields = vmsd_fields(metadata['response']['stdout'])
    marker, uid = snapshot_marker(metadata['response']['stdout'], CANDIDATE)
    names = [value for key, value in fields.items() if key.endswith('.displayName')]
    if (
        marker != expected_marker or uid == '3' or fields.get('snapshot.numSnapshots') != '2'
        or len(names) != 2 or set(names) != {PREPARATION, CANDIDATE}
    ):
        raise SnapshotRawError('reconstruction metadata count, marker or identity differs')
    prior = [key[:-12] for key, value in fields.items()
             if key.endswith('.displayName') and value == PREPARATION]
    if (len(prior) != 1 or fields.get(prior[0] + '.uid') != '3'
            or fields.get(prior[0] + '.filename') != 'Win10MalBox-Velo-Snapshot3.vmsn'):
        raise SnapshotRawError('user preparation snapshot identity was not preserved')

    # The creation instant is the one VMware itself wrote into the vmsd bytes;
    # it must sit strictly inside the real envelope bracket.
    create_instant = _decode_create_instant(fields)
    if not (utc(originals['tree_before']['ended_at']) < create_instant
            < utc(originals['tree_after']['started_at'])):
        raise SnapshotRawError('vmsd creation instant is not bracketed by the tree originals')
    if create_instant.isoformat().replace('+00:00', 'Z') != document['create_time_utc']:
        raise SnapshotRawError('declared reconstruction instant differs from vmsd bytes')

    attestation = originals['create_operation']
    if (
        not isinstance(attestation, dict) or set(attestation) != ATTESTATION_KEYS
        or attestation['schema_version'] != 1 or attestation['kind'] != ATTESTATION_KIND
        or attestation['workflow_id'] != WORKFLOW_ID or attestation['candidate'] != CANDIDATE
        or attestation['vmx'] != str(vmx) or attestation['no_pre_stop'] is not True
        or not isinstance(attestation['operation'], str)
        or 'snapshot' not in attestation['operation'] or 'vmrun' not in attestation['operation']
    ):
        raise SnapshotRawError('candidate creation attestation shape or identity differs')
    attested = utc(attestation['created_at_utc'])
    if attested > create_instant or create_instant - attested > timedelta(seconds=300):
        raise SnapshotRawError('attested creation time does not agree with the vmsd instant')
    ledger_path = resolve(attestation['ledger'], 'creation_metadata.create_operation.ledger')
    try:
        ledger = ledger_path.read_text(encoding='utf-8')
    except (OSError, UnicodeError) as exc:
        raise SnapshotRawError('creation attestation ledger is not readable') from exc
    # The execution ledger records the event with its checkpoint marker file
    # and the 187-retention assertion (its prose uses the short 187/188 names).
    if expected_marker not in ledger or '187' not in ledger:
        raise SnapshotRawError('creation attestation ledger does not name the candidate marker or the retained 187')
    return {
        'operation_id': ATTESTATION_KIND, 'vmx': str(vmx), 'checkpoint_marker': marker,
        'started_at': originals['tree_before']['started_at'],
        'create_started_at': attestation['created_at_utc'],
        'create_ended_at': create_instant.isoformat().replace('+00:00', 'Z'),
        'ended_at': originals['metadata_readback']['ended_at'],
        'evidence_mode': RECONSTRUCTION_MODE,
    }


def verify_creation(
    document: Mapping[str, Any], *, expected_vmx: str, expected_marker: str,
    resolve: Callable[[Any, str], Path],
) -> dict[str, Any]:
    """Recompute zero→one creation and preserve the user-owned 187 snapshot.

    ``resolve`` must check contained Ref path/size/SHA before returning a file;
    ``expected_vmx`` must come from the verified baseline adoption, not this
    creation document. UTC ordering is host command ordering, not VM clocks.
    A document may declare ``evidence_mode='historical-reconstruction'``
    (PLAN-CHANGE-016) for the pre-existing Snapshot188 only; every future
    creation must use live command envelopes.
    """
    vmx = host_vmx(expected_vmx)
    if isinstance(document, Mapping) and document.get('evidence_mode') == RECONSTRUCTION_MODE:
        if (
            set(document) != RECONSTRUCTION_KEYS
            or document['schema_version'] != 1 or document['workflow_id'] != WORKFLOW_ID
            or document['candidate'] != CANDIDATE or document['vmx'] != str(vmx)
            or document['checkpoint_marker'] != expected_marker
        ):
            raise SnapshotRawError('candidate reconstruction wrapper identity differs')
        return _verify_reconstruction(document, vmx=vmx, expected_marker=expected_marker, resolve=resolve)
    if (
        not isinstance(document, Mapping) or set(document) != KEYS
        or document['schema_version'] != 1 or document['workflow_id'] != WORKFLOW_ID
        or document['candidate'] != CANDIDATE or document['vmx'] != str(vmx)
        or document['checkpoint_marker'] != expected_marker
    ):
        raise SnapshotRawError('candidate creation wrapper identity differs')
    originals = {}
    for key in ('tree_before', 'create_operation', 'tree_after', 'metadata_readback'):
        path = resolve(document[key], 'creation_metadata.' + key)
        try:
            originals[key] = json.loads(path.read_text(encoding='utf-8-sig'))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SnapshotRawError('candidate command original is not readable JSON') from exc
    create = originals['create_operation']
    operation = create.get('operation_id') if isinstance(create, dict) else None
    if not isinstance(operation, str) or not operation:
        raise SnapshotRawError('candidate creation has no operation identity')
    argv = {
        'tree_before': ['/usr/bin/vmrun', '-T', 'ws', 'listSnapshots', str(vmx), 'showTree'],
        'create_operation': ['/usr/bin/vmrun', '-T', 'ws', 'snapshot', str(vmx), CANDIDATE],
        'tree_after': ['/usr/bin/vmrun', '-T', 'ws', 'listSnapshots', str(vmx), 'showTree'],
        'metadata_readback': ['/usr/bin/cat', str(vmx.with_suffix('.vmsd'))],
    }
    previous_end = None
    for key, original in originals.items():
        command(original, workflow_id=WORKFLOW_ID, operation_id=operation,
                observation=key, vmx=str(vmx), expected_argv=argv[key])
        if previous_end is not None and utc(original['started_at']) < previous_end:
            raise SnapshotRawError('candidate command sequence overlaps or runs backwards')
        previous_end = utc(original['ended_at'])
    before = snapshot_names(originals['tree_before']['response']['stdout'])
    after = snapshot_names(originals['tree_after']['response']['stdout'])
    if before != [PREPARATION] or set(after) != {PREPARATION, CANDIDATE} or len(after) != 2:
        raise SnapshotRawError('candidate creation does not prove exactly zero to one while retaining 187')
    metadata = originals['metadata_readback']['response']['stdout']
    marker, uid = snapshot_marker(metadata, CANDIDATE)
    fields = vmsd_fields(metadata)
    names = [value for key, value in fields.items() if key.endswith('.displayName')]
    if (
        marker != expected_marker or uid == '3' or fields.get('snapshot.numSnapshots') != '2'
        or len(names) != 2 or set(names) != {PREPARATION, CANDIDATE}
    ):
        raise SnapshotRawError('candidate metadata count, marker or identity differs')
    prior = [key[:-12] for key, value in fields.items()
             if key.endswith('.displayName') and value == PREPARATION]
    if (len(prior) != 1 or fields.get(prior[0] + '.uid') != '3'
            or fields.get(prior[0] + '.filename') != 'Win10MalBox-Velo-Snapshot3.vmsn'):
        raise SnapshotRawError('user preparation snapshot identity was not preserved')
    return {
        'operation_id': operation, 'vmx': str(vmx), 'checkpoint_marker': marker,
        'started_at': originals['tree_before']['started_at'],
        'create_started_at': create['started_at'], 'create_ended_at': create['ended_at'],
        'ended_at': originals['metadata_readback']['ended_at'],
    }
