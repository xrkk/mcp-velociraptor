"""Synthetic fail-closed contracts for the schema5 P06 evidence join.

The restore fixtures are attempt-bound raw command envelopes (synthetic/seam:
they model the carried-original format and never claim a Windows restore ran).
A green result here never asserts a Windows restore or activation passed.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

try:
    from . import p06_evidence as evidence
except ImportError:
    import p06_evidence as evidence


RESTORE_VMX = '/synthetic/Win10MalBox-Velo.vmx'


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')
    )


def restore_action_envelopes(
    root: Path,
    attempt: str,
    snapshot_name: str,
    marker: str,
    *,
    started_minute: int = 0,
) -> dict[str, Path]:
    """Write the four synthetic attempt-bound restore command originals."""
    def envelope(kind: str, operation: str, observation: str, request: dict, stdout: str, second: int) -> Path:
        encoded = stdout.encode('utf-8')
        document = {
            'schema_version': 1,
            'kind': evidence.RESTORE_HOST_COMMAND_KIND,
            'workflow_id': evidence.WORKFLOW_ID,
            'operation_id': operation,
            'observation': observation,
            'vmx': RESTORE_VMX,
            'restore_attempt_id': attempt,
            'request': request,
            'started_at': f'2026-09-14T00:{started_minute:02d}:{second:02d}Z',
            'ended_at': f'2026-09-14T00:{started_minute:02d}:{second + 1:02d}Z',
            'exit_status': {'code': 0},
            'response': {
                'stdout': stdout,
                'stdout_size': len(encoded),
                'stdout_sha256': hashlib.sha256(encoded).hexdigest(),
                'stderr': '',
                'stderr_size': 0,
                'stderr_sha256': hashlib.sha256(b'').hexdigest(),
            },
        }
        path = root / 'raw' / f'{kind}.json'
        _write_json(path, document)
        return path

    argv = lambda items: {'argv': items, 'command_line': ' '.join(items)}  # noqa: E731
    paths = {
        'snapshot_metadata': envelope(
            'snapshot_metadata', 'snapshot-metadata', 'snapshot-tree-readonly',
            argv(['/usr/bin/vmrun', '-T', 'ws', 'listSnapshots', RESTORE_VMX]),
            f'Total snapshots: 1\n{snapshot_name}\n', 0,
        ),
        'revert_operation': envelope(
            'revert_operation', 'revert-operation', 'single-revert',
            argv(['/usr/bin/vmrun', '-T', 'ws', 'revertToSnapshot', RESTORE_VMX, snapshot_name]),
            '', 2,
        ),
        'pre_start_marker': envelope(
            'pre_start_marker', 'pre-start-marker', 'vmx-checkpoint-marker-before-start',
            argv(['/bin/grep', '^checkpoint.vmState', RESTORE_VMX]),
            f'checkpoint.vmState = "{marker}"\n', 4,
        ),
    }
    script = ('$ErrorActionPreference=\'Stop\'; $rows=@(Get-CimInstance '
              'Win32_NetworkAdapterConfiguration -Filter \'IPEnabled=True\' | ForEach-Object { '
              '[ordered]@{ MACAddress=[string]$_.MACAddress; IPAddress=@($_.IPAddress); '
              'DHCPEnabled=[bool]$_.DHCPEnabled; IPEnabled=[bool]$_.IPEnabled } }); '
              '[ordered]@{ computer_name=$env:COMPUTERNAME; adapters=$rows } | ConvertTo-Json -Compress')
    script_encoded = script.encode('utf-8')
    stdout = json.dumps({
        'computer_name': 'DESKTOP-3FI41GR',
        'adapters': [{
            'MACAddress': '00:0C:29:83:B8:65',
            'IPAddress': ['192.168.204.232'],
            'DHCPEnabled': False,
            'IPEnabled': True,
        }],
    })
    stdout_encoded = stdout.encode('utf-8')
    hostname = {
        'schema_version': 1,
        'kind': evidence.RESTORE_GUEST_IDENTITY_KIND,
        'workflow_id': evidence.WORKFLOW_ID,
        'operation_id': 'post-restore-identity',
        'observation': 'guest-identity-via-control-plane',
        'vmx': RESTORE_VMX,
        'restore_attempt_id': attempt,
        'endpoint': 'http://192.168.204.232:28787/mcp',
        'transport': 'control-plane-mcp-http',
        'request': {
            'script': script,
            'script_sha256': hashlib.sha256(script_encoded).hexdigest(),
            'tool': 'PowerShell',
        },
        'started_at': f'2026-09-14T00:{started_minute:02d}:06Z',
        'ended_at': f'2026-09-14T00:{started_minute:02d}:07Z',
        'exit_status': {'code': 0},
        'response': {
            'stdout': stdout,
            'stdout_size': len(stdout_encoded),
            'stdout_sha256': hashlib.sha256(stdout_encoded).hexdigest(),
            'stderr': '',
            'stderr_size': 0,
            'stderr_sha256': hashlib.sha256(b'').hexdigest(),
        },
    }
    paths['post_restore_hostname'] = root / 'raw' / 'post_restore_hostname.json'
    _write_json(paths['post_restore_hostname'], hostname)
    return paths


class Schema5RestoreFixture:
    """A minimal seven-original P06_ACTIVE record rooted wholly in ``root``."""

    attempt = 'restore-schema5-synthetic'
    run_id = 'run-schema5-synthetic'
    marker = 'Win10MalBox-Velo-Snapshot9.vmsn'

    def __init__(self, root: Path) -> None:
        self.root = root
        adoption_id = str(uuid.uuid4())
        activation_id = str(uuid.uuid4())
        self.adoption = root / 'baseline-adoption' / adoption_id / 'adoption.json'
        self.activation = root / 'activation-188' / activation_id / 'activation-evidence.json'
        self.original_adoption = '/original-host/P05/baseline-adoption/' + adoption_id + '/adoption.json'
        self.original_activation = '/original-host/P05/activation-188/' + activation_id + '/activation-evidence.json'
        _write_json(self.adoption, {'synthetic': 'adoption'})
        _write_json(self.activation, {'synthetic': 'activation'})
        self.records: dict[str, Path] = restore_action_envelopes(
            root, self.attempt, evidence.SNAPSHOT_188, self.marker
        )
        self.records['baseline_adoption'] = self.adoption
        self.records['activation_evidence'] = self.activation
        self.canonical_path = root / 'raw' / 'canonical.json'
        self.records['canonical_readback'] = self.canonical_path
        self.restore = {
            'workflow_id': evidence.WORKFLOW_ID,
            'run_id': self.run_id,
            'restore_attempt_id': self.attempt,
            'snapshot_stage': 'P06_ACTIVE',
            'snapshot_name': evidence.SNAPSHOT_188,
            'checkpoint_marker': self.marker,
            'canonical_schema_version': 5,
            'canonical_epoch': 6,
            'canonical_phase': 'NETWORK_ACTIVE',
            'canonical_sha256': '',
            'restore_records': [],
        }
        self._write_canonical()

    def _reference(self, path: Path) -> dict[str, object]:
        return {
            'path': path.relative_to(self.root).as_posix(),
            'size': path.stat().st_size,
            'sha256': _sha256(path),
        }

    def _write_canonical(self, *, baseline_path: str | None = None) -> None:
        baseline_reference = self._reference(self.adoption)
        baseline_reference['path'] = self.original_adoption
        if baseline_path is not None:
            baseline_reference['path'] = baseline_path
        activation_reference = self._reference(self.activation)
        activation_reference['path'] = self.original_activation
        canonical = {
            'schema_version': 5,
            'workflow_id': evidence.WORKFLOW_ID,
            'epoch': 6,
            'phase': 'NETWORK_ACTIVE',
            'active_snapshot': {
                'name': evidence.SNAPSHOT_188,
                'checkpoint_marker': self.marker,
                'purpose': 'synthetic activated acceptance baseline',
            },
            'automatic_restore_allowlist': [evidence.SNAPSHOT_188],
            'retired_snapshots': [
                {'name': name, 'status': evidence.MANUAL_ONLY}
                for name in (
                    evidence.SNAPSHOT_183,
                    evidence.SNAPSHOT_184,
                    evidence.SNAPSHOT_1,
                    evidence.SNAPSHOT_186,
                    evidence.SNAPSHOT_187,
                )
            ],
            'baseline_evidence': {
                'source': 'synthetic-copy',
                'evidence_path': baseline_reference['path'],
                'evidence_sha256': baseline_reference['sha256'],
                'recorded_at': '2026-09-14T00:00:00Z',
            },
            'activation_evidence': {
                'source': 'synthetic-copy',
                'evidence_path': activation_reference['path'],
                'evidence_sha256': activation_reference['sha256'],
                'activated_at': '2026-09-14T00:00:01Z',
            },
        }
        _write_json(self.canonical_path, canonical)
        self.restore['canonical_sha256'] = _sha256(self.canonical_path)
        self.restore['restore_records'] = [
            {
                'kind': kind,
                'path': path.relative_to(self.root).as_posix(),
                'sha256': _sha256(path),
            }
            for kind, path in self.records.items()
        ]


class P06EvidenceSchema5Tests(unittest.TestCase):
    def test_schema5_restore_uses_only_carried_adoption_and_activation_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Schema5RestoreFixture(Path(directory))
            with (
                patch('tests.p05_baseline_adoption.verify_baseline_adoption', return_value={
                    'workflow_id': evidence.WORKFLOW_ID,
                    'adoption_id': fixture.adoption.parent.name,
                }) as adoption,
                patch.object(evidence, 'verify_activation_bundle') as activation,
            ):
                verified = evidence.verify_restore(fixture.restore, fixture.root)
            self.assertEqual(verified['baseline_adoption'], fixture.adoption)
            self.assertEqual(verified['activation_evidence'], fixture.activation)
            self.assertEqual(adoption.call_args.args[0], fixture.adoption)
            self.assertTrue(adoption.call_args.args[0].is_absolute())
            activation.assert_called_once_with(
                fixture.activation,
                require_p05_layout=True,
                expected_baseline=(
                    fixture.original_adoption,
                    _sha256(fixture.adoption),
                ),
                forbidden_identity=(fixture.attempt, fixture.run_id),
            )

    def test_rejects_canonical_baseline_path_that_does_not_name_the_carried_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Schema5RestoreFixture(Path(directory))
            fixture._write_canonical(baseline_path='host-only/adoption.json')
            with self.assertRaisesRegex(evidence.EvidenceError, 'baseline evidence path'):
                evidence.verify_restore(fixture.restore, fixture.root)

    def test_rejects_other_bundle_uuid_even_when_content_hash_matches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Schema5RestoreFixture(Path(directory))
            fixture._write_canonical(baseline_path=(
                '/original-host/P05/baseline-adoption/' + str(uuid.uuid4()) + '/adoption.json'
            ))
            with self.assertRaisesRegex(evidence.EvidenceError, 'baseline evidence path'):
                evidence.verify_restore(fixture.restore, fixture.root)

    def test_rejects_legacy_or_preparation_state_before_it_can_reach_p06(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Schema5RestoreFixture(Path(directory))
            fixture.restore['canonical_schema_version'] = 4
            fixture.restore['canonical_epoch'] = 5
            with self.assertRaisesRegex(evidence.EvidenceError, 'activated schema5 Snapshot188'):
                evidence.verify_restore(fixture.restore, fixture.root)

    def test_rejects_an_absolute_restore_record_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Schema5RestoreFixture(Path(directory))
            fixture.restore['restore_records'][0]['path'] = '/outside-package/snapshot-metadata.json'
            with self.assertRaisesRegex(evidence.EvidenceError, 'contained POSIX|escapes'):
                evidence.verify_restore(fixture.restore, fixture.root)

    def test_rejects_restore_records_that_are_not_attempt_bound_originals(self) -> None:
        def not_executed_text(fixture: Schema5RestoreFixture) -> None:
            path = fixture.records['snapshot_metadata']
            path.write_text(
                f"{fixture.attempt} {evidence.SNAPSHOT_188} {fixture.marker} DESKTOP-3FI41GR -- NOT EXECUTED",
                encoding='utf-8',
            )

        def failed_exit(fixture: Schema5RestoreFixture) -> None:
            path = fixture.records['revert_operation']
            document = json.loads(path.read_text(encoding='utf-8'))
            document['exit_status']['code'] = 1
            _write_json(path, document)

        def summary_substitute(fixture: Schema5RestoreFixture) -> None:
            path = fixture.records['pre_start_marker']
            _write_json(path, {
                'schema_version': 1, 'kind': 'p05-restore-record-summary-v1',
                'record_kind': 'pre_start_marker', 'checkpoint_marker': fixture.marker,
                'workflow_id': evidence.WORKFLOW_ID, 'restore_attempt_id': fixture.attempt,
            })

        def cross_attempt_binding(fixture: Schema5RestoreFixture) -> None:
            path = fixture.records['post_restore_hostname']
            document = json.loads(path.read_text(encoding='utf-8'))
            document['restore_attempt_id'] = 'other-restore-attempt'
            _write_json(path, document)

        def unparsed_marker(fixture: Schema5RestoreFixture) -> None:
            path = fixture.records['pre_start_marker']
            document = json.loads(path.read_text(encoding='utf-8'))
            document['response']['stdout'] = f'checkpoint.vmState = "other.vmsn"\n'
            document['response']['stdout_size'] = len(document['response']['stdout'].encode('utf-8'))
            document['response']['stdout_sha256'] = hashlib.sha256(
                document['response']['stdout'].encode('utf-8')).hexdigest()
            _write_json(path, document)

        mutations = {
            'not_executed_text': (not_executed_text, 'valid UTF-8 JSON'),
            'failed_exit': (failed_exit, 'exit successfully'),
            'summary_substitute': (summary_substitute, 'attempt-bound raw command original'),
            'cross_attempt_binding': (cross_attempt_binding, 'identity or operation differs'),
            'unparsed_marker': (unparsed_marker, 'declared checkpoint marker'),
        }
        for label, (mutate, pattern) in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                fixture = Schema5RestoreFixture(Path(directory))
                mutate(fixture)
                for record in fixture.restore['restore_records']:
                    if record['path'].startswith('raw/'):
                        record['sha256'] = _sha256(fixture.root / record['path'])
                with (
                    patch('tests.p05_baseline_adoption.verify_baseline_adoption', return_value={
                        'workflow_id': evidence.WORKFLOW_ID,
                        'adoption_id': fixture.adoption.parent.name,
                    }),
                    patch.object(evidence, 'verify_activation_bundle'),
                ):
                    with self.assertRaisesRegex(evidence.EvidenceError, pattern):
                        evidence.verify_restore(fixture.restore, fixture.root)

    def test_activation_pairing_uses_187_initial_and_188_candidates_before_raw_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'activation-188' / str(uuid.uuid4())
            path = root / 'activation-evidence.json'
            _write_json(path, {
                'schema_version': 1,
                'kind': 'snapshot188-activation-evidence-v1',
                'workflow_id': evidence.WORKFLOW_ID,
                'candidate': evidence.SNAPSHOT_188,
                'checkpoint_marker': 'Win10MalBox-Velo-Snapshot9.vmsn',
                'creation_metadata': {},
                'initial': {'restore_attempt_id': 'initial', 'run_id': 'initial-run'},
                'candidate_cycles': [
                    {'restore_attempt_id': 'cycle-one', 'run_id': 'cycle-one-run'},
                    {'restore_attempt_id': 'cycle-two', 'run_id': 'cycle-two-run'},
                ],
                'source_inputs': [],
                'implementation_sources': [],
            })
            returned = [
                ({'checkpoint_marker': 'Win10MalBox-Velo-Snapshot3.vmsn'}, ('adoption', 'a' * 64, 'id')),
                ({'checkpoint_marker': 'Win10MalBox-Velo-Snapshot9.vmsn'}, ('adoption', 'a' * 64, 'id')),
                ({'checkpoint_marker': 'Win10MalBox-Velo-Snapshot9.vmsn'}, ('adoption', 'a' * 64, 'id')),
            ]
            with (
                patch.object(evidence, '_verify_creation_metadata'),
                patch.object(evidence, '_verify_source_list'),
                patch.object(evidence, '_verify_phase', side_effect=returned) as phase,
                patch.object(evidence, '_verify_ready'),
                patch.object(evidence, '_verify_dependency_acceptance'),
                patch.object(evidence, '_verify_entry_gate'),
                patch.object(evidence, '_verify_network_evidence'),
                patch.object(evidence, '_verify_package_manifest'),
                patch.object(evidence, '_verify_creation_binding'),
            ):
                # PLAN-CHANGE-016 removed the frozen terminal block: the raw
                # transcript predicates are implemented and the strict bundle
                # check now returns its recomputed identity facts.
                facts = evidence.verify_activation_bundle(path, require_p05_layout=True)
            self.assertEqual(facts['candidate'], evidence.SNAPSHOT_188)
            self.assertEqual(facts['initial_run_id'], 'initial-run')
            self.assertEqual(facts['cycle_run_ids'], ['cycle-one-run', 'cycle-two-run'])
            self.assertEqual(phase.call_args_list[0].args[4], evidence.SNAPSHOT_187)
            self.assertEqual([call.args[4] for call in phase.call_args_list[1:]], [
                evidence.SNAPSHOT_188,
                evidence.SNAPSHOT_188,
            ])

    def test_preparation_phase_uses_six_records_without_activation_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            originals = bundle / 'p05-originals'
            attempt = 'p05-initial-synthetic'
            marker = 'Win10MalBox-Velo-Snapshot3.vmsn'
            marker = 'Win10MalBox-Velo-Snapshot3.vmsn'
            paths = restore_action_envelopes(
                originals, attempt, evidence.SNAPSHOT_187, marker
            )
            paths['baseline_adoption'] = originals / 'baseline-adoption' / str(uuid.uuid4()) / 'adoption.json'
            paths['canonical_readback'] = originals / 'raw' / 'canonical.json'
            paths['baseline_adoption'].parent.mkdir(parents=True, exist_ok=True)
            paths['baseline_adoption'].write_text('{}', encoding='utf-8')
            _write_json(paths['canonical_readback'], {
                'active_snapshot': {'checkpoint_marker': marker},
            })
            records = [
                {
                    'kind': kind,
                    'path': path.relative_to(originals).as_posix(),
                    'sha256': _sha256(path),
                }
                for kind, path in paths.items()
            ]
            restore = {
                'workflow_id': evidence.WORKFLOW_ID,
                'run_id': 'initial-run',
                'restore_attempt_id': attempt,
                'snapshot_stage': 'P05_REPAIR_INITIAL',
                'snapshot_name': evidence.SNAPSHOT_187,
                'checkpoint_marker': marker,
                'canonical_schema_version': 5,
                'canonical_epoch': 5,
                'canonical_phase': 'PREPARATION_BASELINE',
                'canonical_sha256': _sha256(paths['canonical_readback']),
                'restore_records': records,
            }
            snapshot_evidence = {
                'restore': restore,
                'scenario_id': 'p05-flow-triage-repair-initial',
                'source_sha256': 'a' * 64,
                'index_sha256': 'b' * 64,
                'mcp_session_id': 'session',
                'server_instance_id': 'instance',
                'server_observation_sha256': 'c' * 64,
            }
            phase = {'restore_attempt_id': attempt, 'run_id': 'initial-run'}
            with patch.object(
                evidence,
                '_verify_preparation_canonical',
                return_value=('baseline-adoption/synthetic/adoption.json', 'd' * 64, 'synthetic'),
            ):
                restored, _ = evidence._verify_phase_restore(
                    snapshot_evidence,
                    bundle,
                    phase,
                    'P05_REPAIR_INITIAL',
                    evidence.SNAPSHOT_187,
                    {},
                )
            self.assertEqual(restored['restore_records'], records)
            self.assertEqual({record['kind'] for record in records}, evidence.PHASE_RESTORE_KINDS)


if __name__ == '__main__':
    unittest.main()
