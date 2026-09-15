"""Synthetic parser predicates; execute on Windows, not as restore evidence."""
import copy
import hashlib
import json
import unittest

from tests import p05_snapshot_raw as raw


class SnapshotRawTests(unittest.TestCase):
    def transcript(self):
        response = {}
        for name, text in [('stdout', 'Total snapshots: 0\n'), ('stderr', '')]:
            response[name] = text
            response[name + '_size'] = len(text.encode())
            response[name + '_sha256'] = hashlib.sha256(text.encode()).hexdigest()
        return {
            'schema_version': 1, 'kind': 'p05-snapshot-command-v1',
            'workflow_id': 'synthetic-workflow', 'operation_id': 'synthetic-operation',
            'observation': 'tree', 'vmx': '/fixture/Win10MalBox-Velo.vmx',
            'request': {'argv': ['/usr/bin/vmrun', '-T', 'ws', 'listSnapshots',
                                  '/fixture/Win10MalBox-Velo.vmx', 'showTree'],
                        'command_line': 'synthetic recorded command'},
            'started_at': '2026-09-14T00:00:00Z', 'ended_at': '2026-09-14T00:00:01Z',
            'exit_status': {'code': 0}, 'response': response,
        }

    def verify(self, value):
        return raw.command(value, workflow_id='synthetic-workflow',
                           operation_id='synthetic-operation', observation='tree',
                           vmx='/fixture/Win10MalBox-Velo.vmx',
                           expected_argv=self.transcript()['request']['argv'])

    def test_complete_command_and_linux_host_path_on_windows(self):
        self.assertEqual(self.verify(self.transcript())['exit_status'], {'code': 0})
        self.assertEqual(raw.host_vmx('/fixture/Win10MalBox-Velo.vmx').name,
                         'Win10MalBox-Velo.vmx')

    def test_rejects_failure_time_replay_command_and_stream_mutations(self):
        mutations = [
            ('exit_status', {'code': 1}), ('exit_status', {'code': False}),
            ('ended_at', '2026-09-13T00:00:00Z'), ('started_at', '2026-09-14T00:00:00'),
            ('operation_id', 'another-attempt'),
            ('request', {'argv': ['echo', 'passed'], 'command_line': 'echo passed'}),
        ]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                document = self.transcript()
                document[key] = value
                with self.assertRaises(raw.SnapshotRawError):
                    self.verify(document)
        document = self.transcript()
        document['response']['stdout'] += 'forged'
        with self.assertRaises(raw.SnapshotRawError):
            self.verify(document)

    def test_tree_total_is_not_a_substring_claim(self):
        self.assertEqual(raw.snapshot_names('Total snapshots: 1\n  snapshot name\n'), ['snapshot name'])
        for value in ['snapshot name', 'Total snapshots: 0\nsnapshot name',
                      'Total snapshots: 2\nsame\nsame']:
            with self.assertRaises(raw.SnapshotRawError):
                raw.snapshot_names(value)

    def metadata(self):
        return '\n'.join([
            'snapshot.numSnapshots = "1"', 'snapshot.current = "3"',
            'snapshot0.uid = "3"', 'snapshot0.displayName = "synthetic-187"',
            'snapshot0.filename = "Win10MalBox-Velo-Snapshot3.vmsn"',
        ])

    def test_vmsd_joins_name_uid_current_and_filename(self):
        self.assertEqual(raw.snapshot_marker(self.metadata(), 'synthetic-187', only_snapshot=True),
                         ('Win10MalBox-Velo-Snapshot3.vmsn', '3'))
        for value in [self.metadata().replace('snapshot.current = "3"', 'snapshot.current = "4"'),
                      self.metadata() + '\nsnapshot0.uid = "3"',
                      self.metadata().replace('numSnapshots = "1"', 'numSnapshots = "2"')]:
            with self.assertRaises(raw.SnapshotRawError):
                raw.snapshot_marker(value, 'synthetic-187', only_snapshot=True)

    def test_guest_identity_rejects_dhcp_and_other_adapter(self):
        value = {'computer_name': 'DESKTOP-3FI41GR', 'adapters': [{
            'MACAddress': '00:0C:29:83:B8:65', 'IPAddress': ['192.168.204.232'],
            'DHCPEnabled': False, 'IPEnabled': True,
        }]}
        raw.guest_adapter(json.dumps(value))
        for field, wrong in [('DHCPEnabled', True), ('MACAddress', '00:00:00:00:00:00')]:
            candidate = copy.deepcopy(value)
            candidate['adapters'][0][field] = wrong
            with self.assertRaises(raw.SnapshotRawError):
                raw.guest_adapter(json.dumps(candidate))


if __name__ == '__main__':
    unittest.main()
