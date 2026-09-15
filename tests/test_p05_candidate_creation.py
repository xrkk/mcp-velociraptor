"""Windows-only synthetic command parser tests; no VMware commands run."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from tests import p05_candidate_creation as creation


def _record(name, argv, stdout, second):
    response = {}
    for stream, value in (('stdout', stdout), ('stderr', '')):
        response[stream] = value
        response[stream + '_size'] = len(value.encode())
        response[stream + '_sha256'] = hashlib.sha256(value.encode()).hexdigest()
    return {
        'schema_version': 1, 'kind': 'p05-snapshot-command-v1',
        'workflow_id': creation.WORKFLOW_ID, 'operation_id': 'synthetic-creation',
        'observation': name, 'vmx': '/synthetic/Win10MalBox-Velo.vmx',
        'request': {'argv': argv, 'command_line': ' '.join(argv)},
        'started_at': f'2026-09-14T00:00:{second:02d}Z',
        'ended_at': f'2026-09-14T00:00:{second + 1:02d}Z',
        'exit_status': {'code': 0}, 'response': response,
    }


@unittest.skipUnless(os.name == 'nt', 'CON002: behavioral tests execute only on Windows')
class CandidateCreationTests(unittest.TestCase):
    def setUp(self):
        self.vmx = '/synthetic/Win10MalBox-Velo.vmx'
        self.marker = 'Win10MalBox-Velo-Snapshot4.vmsn'
        base = ['/usr/bin/vmrun', '-T', 'ws']
        metadata = '\n'.join([
            'snapshot.numSnapshots = "2"', 'snapshot.current = "4"',
            'snapshot0.uid = "3"', 'snapshot0.filename = "Win10MalBox-Velo-Snapshot3.vmsn"',
            'snapshot0.displayName = "' + creation.PREPARATION + '"',
            'snapshot1.uid = "4"', 'snapshot1.filename = "' + self.marker + '"',
            'snapshot1.displayName = "' + creation.CANDIDATE + '"',
        ])
        self.originals = {
            'tree_before': _record('tree_before', base + ['listSnapshots', self.vmx, 'showTree'],
                                   'Total snapshots: 1\n' + creation.PREPARATION + '\n', 0),
            'create_operation': _record('create_operation', base + ['snapshot', self.vmx, creation.CANDIDATE], '', 2),
            'tree_after': _record('tree_after', base + ['listSnapshots', self.vmx, 'showTree'],
                                  'Total snapshots: 2\n' + creation.PREPARATION + '\n  ' + creation.CANDIDATE + '\n', 4),
            'metadata_readback': _record('metadata_readback', ['/usr/bin/cat', '/synthetic/Win10MalBox-Velo.vmsd'], metadata, 6),
        }

    def verify(self, originals=None, expected_vmx=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            document = {
                'schema_version': 1, 'workflow_id': creation.WORKFLOW_ID,
                'candidate': creation.CANDIDATE, 'checkpoint_marker': self.marker, 'vmx': self.vmx,
            }
            for key, value in (originals or self.originals).items():
                payload = json.dumps(value).encode()
                (root / (key + '.json')).write_bytes(payload)
                document[key] = {'path': key + '.json', 'size': len(payload),
                                 'sha256': hashlib.sha256(payload).hexdigest()}

            def resolve(reference, label):
                path = root / reference['path']
                self.assertEqual(len(path.read_bytes()), reference['size'])
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), reference['sha256'])
                return path

            return creation.verify_creation(document, expected_vmx=expected_vmx or self.vmx,
                                             expected_marker=self.marker, resolve=resolve)

    def test_complete_actual_command_shape_is_reconstructed(self):
        result = self.verify()
        self.assertEqual(result['checkpoint_marker'], self.marker)
        self.assertEqual(result['operation_id'], 'synthetic-creation')

    def test_cross_vm_is_rejected(self):
        with self.assertRaisesRegex(creation.SnapshotRawError, 'wrapper identity'):
            self.verify(expected_vmx='/other/Win10MalBox-Velo.vmx')

    def test_failed_replayed_or_non_snapshot_command_is_rejected(self):
        for mutation in ('failure', 'operation', 'stop', 'overlap'):
            with self.subTest(mutation=mutation):
                data = copy.deepcopy(self.originals)
                if mutation == 'failure':
                    data['create_operation']['exit_status']['code'] = 1
                elif mutation == 'operation':
                    data['tree_after']['operation_id'] = 'another'
                elif mutation == 'stop':
                    data['create_operation']['request']['argv'][3] = 'stop'
                else:
                    data['tree_after']['started_at'] = data['create_operation']['started_at']
                with self.assertRaises(creation.SnapshotRawError):
                    self.verify(data)

    def test_existing_candidate_or_lost_preparation_is_rejected(self):
        for key, text in (
            ('tree_before', 'Total snapshots: 2\n' + creation.PREPARATION + '\n' + creation.CANDIDATE),
            ('tree_after', 'Total snapshots: 1\n' + creation.CANDIDATE),
        ):
            with self.subTest(key=key):
                data = copy.deepcopy(self.originals)
                old = data[key]
                data[key] = _record(key, old['request']['argv'], text, 0 if key == 'tree_before' else 4)
                with self.assertRaisesRegex(creation.SnapshotRawError, 'zero to one'):
                    self.verify(data)

    def test_marker_and_preserved_187_uid_are_parsed_from_vmsd(self):
        for original, replacement in (
            ('snapshot.current = "4"', 'snapshot.current = "3"'),
            ('snapshot0.uid = "3"', 'snapshot0.uid = "8"'),
            (self.marker, 'Win10MalBox-Velo-Snapshot8.vmsn'),
        ):
            with self.subTest(original=original):
                data = copy.deepcopy(self.originals)
                old = data['metadata_readback']
                data['metadata_readback'] = _record('metadata_readback', old['request']['argv'],
                                                    old['response']['stdout'].replace(original, replacement), 6)
                with self.assertRaises(creation.SnapshotRawError):
                    self.verify(data)

    def test_summary_and_modified_stream_are_not_originals(self):
        for replacement in ({'passed': True}, None):
            data = copy.deepcopy(self.originals)
            if replacement is None:
                data['tree_after']['response']['stdout'] += '\nextra'
            else:
                data['tree_after'] = replacement
            with self.assertRaises(creation.SnapshotRawError):
                self.verify(data)


def _envelope(name, argv, stdout, started, ended):
    record = _record(name, argv, stdout, 0)
    record['started_at'] = started
    record['ended_at'] = ended
    return record


@unittest.skipUnless(os.name == 'nt', 'CON002: behavioral tests execute only on Windows')
class CandidateReconstructionTests(unittest.TestCase):
    """PLAN-CHANGE-016: bounded historical reconstruction for the existing 188."""

    def setUp(self):
        self.vmx = '/synthetic/Win10MalBox-Velo.vmx'
        self.marker = 'Win10MalBox-Velo-Snapshot4.vmsn'
        base = ['/usr/bin/vmrun', '-T', 'ws']
        # vmsd bytes carry snapshot1.createTimeHigh/Low = epoch microseconds;
        # 2026-09-14T18:17:51.500000Z sits inside the 18:15→18:19 bracket.
        instant = 1789409871500000
        metadata = '\n'.join([
            'snapshot.numSnapshots = "2"', 'snapshot.current = "4"',
            'snapshot0.uid = "3"', 'snapshot0.filename = "Win10MalBox-Velo-Snapshot3.vmsn"',
            'snapshot0.displayName = "' + creation.PREPARATION + '"',
            'snapshot1.uid = "4"', 'snapshot1.filename = "' + self.marker + '"',
            'snapshot1.displayName = "' + creation.CANDIDATE + '"',
            f'snapshot1.createTimeHigh = "{instant >> 32}"',
            f'snapshot1.createTimeLow = "{instant & 0xFFFFFFFF}"',
        ])
        self.originals = {
            'tree_before': _envelope('snapshot-tree-readonly', base + ['listSnapshots', self.vmx],
                                     'Total snapshots: 1\n' + creation.PREPARATION + '\n',
                                     '2026-09-14T17:21:17Z', '2026-09-14T17:21:18Z'),
            'create_operation': {
                'schema_version': 1, 'kind': creation.ATTESTATION_KIND,
                'workflow_id': creation.WORKFLOW_ID, 'candidate': creation.CANDIDATE,
                'vmx': self.vmx,
                'operation': '/usr/bin/vmrun -T ws snapshot /synthetic/Win10MalBox-Velo.vmx ' + creation.CANDIDATE,
                'created_at_utc': '2026-09-14T18:17:50Z', 'no_pre_stop': True,
                'ledger': None,  # filled by verify()
            },
            'tree_after': _envelope('snapshot-tree-readonly', base + ['listSnapshots', self.vmx],
                                    'Total snapshots: 2\n' + creation.PREPARATION + '\n' + creation.CANDIDATE + '\n',
                                    '2026-09-14T18:21:20Z', '2026-09-14T18:21:21Z'),
            'metadata_readback': _envelope('vmsd-readonly', ['/usr/bin/cat', '/synthetic/Win10MalBox-Velo.vmsd'],
                                           metadata, '2026-09-14T18:21:21Z', '2026-09-14T18:21:22Z'),
        }

    def verify(self, originals=None, expected_vmx=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = ('188 创建 ' + creation.CANDIDATE + ' 自 ' + creation.PREPARATION
                      + '（marker Win10MalBox-Velo-Snapshot4.vmsn，187 UID=3 保留）\n')
            (root / 'ledger.md').write_bytes(ledger.encode('utf-8'))
            data = copy.deepcopy(originals or self.originals)
            data['create_operation']['ledger'] = {
                'path': 'ledger.md', 'size': len(ledger.encode()),
                'sha256': hashlib.sha256(ledger.encode()).hexdigest()}
            document = {
                'schema_version': 1, 'workflow_id': creation.WORKFLOW_ID,
                'candidate': creation.CANDIDATE, 'checkpoint_marker': self.marker, 'vmx': self.vmx,
                'evidence_mode': creation.RECONSTRUCTION_MODE,
                'create_time_utc': '2026-09-14T18:17:51.500000Z',
            }
            for key, value in data.items():
                payload = json.dumps(value).encode()
                (root / (key + '.json')).write_bytes(payload)
                document[key] = {'path': key + '.json', 'size': len(payload),
                                 'sha256': hashlib.sha256(payload).hexdigest()}

            def resolve(reference, label):
                path = root / reference['path']
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), reference['sha256'])
                return path

            return creation.verify_creation(document, expected_vmx=expected_vmx or self.vmx,
                                             expected_marker=self.marker, resolve=resolve)

    def test_reconstruction_from_bracketed_originals_is_accepted(self):
        result = self.verify()
        self.assertEqual(result['checkpoint_marker'], self.marker)
        self.assertEqual(result['evidence_mode'], creation.RECONSTRUCTION_MODE)
        self.assertEqual(result['create_ended_at'], '2026-09-14T18:17:51.500000Z')

    def test_instant_outside_the_real_bracket_is_rejected(self):
        for key, text in (
            ('tree_before', 'Total snapshots: 2\n' + creation.PREPARATION + '\n' + creation.CANDIDATE + '\n'),
            ('tree_after', 'Total snapshots: 1\n' + creation.PREPARATION + '\n'),
        ):
            with self.subTest(key=key):
                data = copy.deepcopy(self.originals)
                old = data[key]
                data[key] = _envelope(old['observation'], old['request']['argv'], text,
                                      old['started_at'], old['ended_at'])
                with self.assertRaisesRegex(creation.SnapshotRawError, 'zero to one'):
                    self.verify(data)

    def test_declared_instant_must_match_vmsd_bytes(self):
        data = copy.deepcopy(self.originals)
        old = data['metadata_readback']
        instant = 1789409871599999
        metadata = old['response']['stdout']
        metadata = metadata.replace(f'snapshot1.createTimeHigh = "{1789409871500000 >> 32}"',
                                    f'snapshot1.createTimeHigh = "{instant >> 32}"')
        metadata = metadata.replace(f'snapshot1.createTimeLow = "{1789409871500000 & 0xFFFFFFFF}"',
                                    f'snapshot1.createTimeLow = "{instant & 0xFFFFFFFF}"')
        data['metadata_readback'] = _envelope(old['observation'], old['request']['argv'], metadata,
                                              '2026-09-14T18:21:21Z', '2026-09-14T18:21:22Z')
        with self.assertRaisesRegex(creation.SnapshotRawError, 'instant'):
            self.verify(data)

    def test_attestation_drift_is_rejected(self):
        for mutation in ('time', 'stop', 'mode'):
            with self.subTest(mutation=mutation):
                data = copy.deepcopy(self.originals)
                if mutation == 'time':
                    data['create_operation']['created_at_utc'] = '2026-09-14T18:10:00Z'
                elif mutation == 'stop':
                    data['create_operation']['no_pre_stop'] = False
                else:
                    data['create_operation']['kind'] = 'p05-candidate-creation-v1'
                with self.assertRaises(creation.SnapshotRawError):
                    self.verify(data)

    def test_non_vmsd_or_non_tree_originals_are_rejected(self):
        for key in ('tree_before', 'metadata_readback'):
            with self.subTest(key=key):
                data = copy.deepcopy(self.originals)
                data[key]['request']['argv'] = ['/usr/bin/vmrun', '-T', 'ws', 'list', self.vmx]
                with self.assertRaisesRegex(creation.SnapshotRawError, 'command|snapshot-tree|vmsd'):
                    self.verify(data)


if __name__ == '__main__':
    unittest.main()
