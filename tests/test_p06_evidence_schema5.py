"""Synthetic fail-closed contracts for the schema5 P06 evidence join.

These are byte-only fixtures.  They model an in-package copy and deliberately
mock the P05 raw-transcript terminal gate: a green result here never asserts a
Windows restore or activation passed.
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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')
    )


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
        self.records: dict[str, Path] = {
            'snapshot_metadata': root / 'raw' / 'snapshot-metadata.json',
            'revert_operation': root / 'raw' / 'revert-operation.json',
            'pre_start_marker': root / 'raw' / 'pre-start-marker.json',
            'post_restore_hostname': root / 'raw' / 'post-restore-hostname.json',
            'baseline_adoption': self.adoption,
            'activation_evidence': self.activation,
        }
        raw_values = {
            'snapshot_metadata': f'{self.attempt} {evidence.SNAPSHOT_188}',
            'revert_operation': self.attempt,
            'pre_start_marker': f'{self.attempt} {self.marker}',
            'post_restore_hostname': f'{self.attempt} DESKTOP-3FI41GR',
        }
        for kind, contents in raw_values.items():
            self.records[kind].parent.mkdir(parents=True, exist_ok=True)
            self.records[kind].write_text(contents, encoding='utf-8')
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
            paths = {
                'snapshot_metadata': originals / 'raw' / 'snapshot.json',
                'revert_operation': originals / 'raw' / 'revert.json',
                'pre_start_marker': originals / 'raw' / 'marker.json',
                'post_restore_hostname': originals / 'raw' / 'hostname.json',
                'baseline_adoption': originals / 'baseline-adoption' / str(uuid.uuid4()) / 'adoption.json',
                'canonical_readback': originals / 'raw' / 'canonical.json',
            }
            raw = {
                'snapshot_metadata': f'{attempt} {evidence.SNAPSHOT_187}',
                'revert_operation': attempt,
                'pre_start_marker': f'{attempt} {marker}',
                'post_restore_hostname': f'{attempt} DESKTOP-3FI41GR',
                'baseline_adoption': '{}',
                'canonical_readback': json.dumps({
                    'active_snapshot': {'checkpoint_marker': marker},
                }),
            }
            for kind, contents in raw.items():
                paths[kind].parent.mkdir(parents=True, exist_ok=True)
                paths[kind].write_text(contents, encoding='utf-8')
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
