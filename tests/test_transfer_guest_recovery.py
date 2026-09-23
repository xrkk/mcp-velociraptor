"""Author recovery tests using benign real files and owned Linux processes."""
import base64
import copy
import hashlib
import os
import time
import unittest
from unittest import mock

from tests import test_transfer_guest as fixture
from velo_transfer.errors import TransferContentError as Error
from velo_transfer.guest_service import GuestTransferService
from velo_transfer.guest_worker import same_process
from velo_transfer.protocol import publication_receipt


@unittest.skipUnless(os.name == 'posix', 'isolated POSIX guest fixture')
class GuestRecoveryTests(unittest.TestCase):
    setUp = fixture.GuestTests.setUp
    request = fixture.GuestTests.request
    wait_phase = fixture.GuestTests.wait_phase

    def pull(self, transfer_id='trial'):
        source = self.read / (transfer_id + '.txt')
        source.write_bytes(b'benign recovery fixture')
        req = self.request('pull', [{'absolute_path': str(source),
            'relative_path': 'file.txt'}], self.host / transfer_id, transfer_id=transfer_id)
        self.service.transfer_begin(req)
        self.wait_phase(req, 'SOURCE_READY')
        return req

    def prepared_pull(self):
        req = self.pull()
        self.service.transfer_finish('trial', req['request_digest'], 'prepare')
        receipt = self.wait_phase(req, 'SOURCE_PREPARED')['terminal']['prepare_receipt']
        pub = publication_receipt(receipt['binding'], receipt,
            req['expected_destination'], {'device': 1, 'inode': 2})
        return req, receipt, pub

    def test_old_status_does_not_reconcile_new_task_lease(self):
        first = self.pull('first')
        source = self.read / 'second.txt'
        source.write_bytes(b'benign second')
        second = self.request('pull', [{'absolute_path': str(source),
            'relative_path': 'file.txt'}], self.host / 'second', transfer_id='second')
        self.service.transfer_begin(second)
        until = time.monotonic() + 5
        while time.monotonic() < until:
            raw = self.service._load('second', second['request_digest'])['state']
            if not same_process(raw['owner']['pid'], raw['owner']['birth']):
                break
            time.sleep(.01)
        else:
            self.fail('second worker did not exit')
        before = self.service._store()._read(self.work / 'tasks/guest-internal-lease/state.json')
        self.assertEqual(self.service.transfer_status('first', first['request_digest'])['local_phase'],
                         'SOURCE_READY')
        after = self.service._store()._read(self.work / 'tasks/guest-internal-lease/state.json')
        self.assertEqual(before, after)
        self.wait_phase(second, 'SOURCE_READY')

    def test_resume_begin_verifies_partial_before_advertising_continuity(self):
        raw = b'benign' * 100
        req = self.request('push', [{'absolute_path': '/opaque/host', 'relative_path': 'file'}],
            self.write / 'final', {'size': len(raw) * 2,
            'sha256': '0' * 64, 'manifest_sha256': '0' * 64})
        self.service.transfer_begin(req)
        self.service.transfer_chunk('trial', req['request_digest'], 0, len(raw),
            base64.b64encode(raw).decode(), hashlib.sha256(raw).hexdigest())
        partial = self.work / 'tasks/trial/received.part'
        with partial.open('r+b') as stream:
            stream.write(b'X')
        other = GuestTransferService(self.policy, _observation=self.observation,
                                     _acl_verifier=lambda path, kind: True)
        self.addCleanup(other.shutdown)
        result = other.transfer_begin(req)
        self.assertIsNotNone(result['worker'], 'resume must run an actual byte verification worker')
        until = time.monotonic() + 5
        while time.monotonic() < until:
            result = other.transfer_status('trial', req['request_digest'])
            if result['worker']['stopped']:
                break
            time.sleep(.01)
        self.assertTrue(result['worker']['stopped'])
        self.assertEqual(result['error'], 'partial_corrupt')
        self.assertFalse((self.write / 'final').exists())

    def test_identity_observation_error_does_not_mean_worker_exited(self):
        from pathlib import Path
        from velo_transfer.guest_worker import process_birth
        birth = process_birth(os.getpid())
        with mock.patch.object(Path, 'read_text', side_effect=PermissionError('fixture')):
            with self.assertRaises(Error) as caught:
                same_process(os.getpid(), birth)
        self.assertEqual(caught.exception.code, 'worker_identity_unavailable')
        self.assertTrue(same_process(os.getpid(), birth))

    def test_unchanged_resume_rechecks_bytes_once_and_normal_chunks_stay_bounded(self):
        raw = b'benign01' * (256 * 1024)
        req = self.request('push', [{'absolute_path': '/opaque/host', 'relative_path': 'file'}],
            self.write / 'final', {'size': len(raw) + 1,
            'sha256': '0' * 64, 'manifest_sha256': '0' * 64})
        self.service.transfer_begin(req)
        for offset in range(0, len(raw), 1 << 20):
            chunk = raw[offset:offset + (1 << 20)]
            self.service.transfer_chunk('trial', req['request_digest'], offset, len(chunk),
                base64.b64encode(chunk).decode(), hashlib.sha256(chunk).hexdigest())
        # Metadata drift must not put a long rehash inside a short chunk call.
        ledger = self.work / 'tasks/trial/chunks.jsonl'
        with ledger.open('ab') as stream:
            stream.write(b'unacknowledged-tail')
        with self.assertRaises(Error) as caught:
            self.service.transfer_chunk('trial', req['request_digest'], len(raw), 1,
                base64.b64encode(b'x').decode(), hashlib.sha256(b'x').hexdigest())
        self.assertEqual(caught.exception.code, 'partial_verification_required')
        self.service.transfer_begin(req)
        self.wait_phase(req, 'DEST_RECEIVING')
        self.assertEqual(len(ledger.read_text().splitlines()), 2)
        # A second explicit resume with unchanged metadata still reads every record.
        marker = self.root / 'verified-prefix-records'
        from velo_transfer import guest_service as guest_module
        original = guest_module._strict_json
        def observe(raw_json, maximum):
            value = original(raw_json, maximum)
            if isinstance(value, dict) and set(value) == {'offset', 'count', 'sha256'}:
                with marker.open('a') as output:
                    output.write('record\n')
            return value
        with mock.patch.object(guest_module, '_strict_json', side_effect=observe):
            self.service.transfer_begin(req)
            self.wait_phase(req, 'DEST_RECEIVING')
        self.assertEqual(marker.read_text().splitlines(), ['record', 'record'])
        self.service.transfer_chunk('trial', req['request_digest'], len(raw), 1,
            base64.b64encode(b'x').decode(), hashlib.sha256(b'x').hexdigest())
        self.assertEqual(self.service.transfer_status('trial', req['request_digest'])['verified_offset'],
                         len(raw) + 1)

    def test_registration_failure_child_is_reaped_and_retry_is_possible(self):
        source = self.read / 'source.txt'
        source.write_bytes(b'benign')
        req = self.request('pull', [{'absolute_path': str(source), 'relative_path': 'file'}],
                           self.host / 'result')
        original = self.service._save
        def fail_owner(store, envelope, state):
            if state['owner'] is not None:
                raise Error('injected_registration_failure')
            return original(store, envelope, state)
        with mock.patch.object(self.service, '_save', side_effect=fail_owner):
            with self.assertRaises(Error):
                self.service.transfer_begin(req)
        self.assertFalse(self.service._owned)
        self.service.transfer_begin(req)
        self.wait_phase(req, 'SOURCE_READY')

    def test_receipt_mutations_are_side_effect_free_before_and_after_release(self):
        req, receipt, pub = self.prepared_pull()
        state_file = self.work / 'tasks/trial/state.json'
        fields = ('request_digest', 'package_sha256', 'manifest_sha256',
                  'vm_epoch', 'policy_id', 'transfer_id', 'boot_identity', 'vm_uuid')
        for released in (False, True):
            if released:
                self.service.transfer_finish('trial', req['request_digest'], 'release',
                    prepare_receipt=receipt, publication_receipt=pub)
                self.wait_phase(req, 'SOURCE_RELEASED')
            for field in fields:
                with self.subTest(released=released, binding=field):
                    wrong = copy.deepcopy(pub)
                    wrong['binding'][field] = ('1' * 64 if 'sha256' in field or field == 'request_digest'
                                               else 'wrong-identity')
                    before = state_file.read_bytes()
                    with self.assertRaises(Error):
                        self.service.transfer_finish('trial', req['request_digest'], 'release',
                            prepare_receipt=receipt, publication_receipt=wrong)
                    self.assertEqual(state_file.read_bytes(), before)
            wrong = copy.deepcopy(pub)
            wrong['destination']['canonical_path'] = '/wrong/path'
            before = state_file.read_bytes()
            with self.assertRaises(Error):
                self.service.transfer_finish('trial', req['request_digest'], 'release',
                    prepare_receipt=receipt, publication_receipt=wrong)
            self.assertEqual(state_file.read_bytes(), before)

    def test_lost_prepare_and_release_responses_replay_same_operation(self):
        req, receipt, pub = self.prepared_pull()
        before = self.service.transfer_status('trial', req['request_digest'])
        replay = self.service.transfer_finish('trial', req['request_digest'], 'prepare')
        self.assertEqual(replay['operation']['operation_id'],
                         before['terminal']['operations']['prepare']['operation_id'])
        # A host destination conflict or a lost release request leaves the source package intact.
        destination = self.host / 'trial'
        destination.mkdir()
        (destination / 'foreign.txt').write_bytes(b'foreign existing destination')
        self.assertTrue((self.work / 'tasks/trial/bundle.zip').exists())
        self.assertEqual(self.service.transfer_status('trial', req['request_digest'])['local_phase'],
                         'SOURCE_PREPARED')
        first = self.service.transfer_finish('trial', req['request_digest'], 'release',
            prepare_receipt=receipt, publication_receipt=pub)
        self.wait_phase(req, 'SOURCE_RELEASED')
        replay = self.service.transfer_finish('trial', req['request_digest'], 'release',
            prepare_receipt=receipt, publication_receipt=pub)
        self.assertEqual(replay['operation']['operation_id'], first['operation']['operation_id'])
        self.assertEqual(replay['operation']['status'], 'DONE')
        self.assertEqual((destination / 'foreign.txt').read_bytes(), b'foreign existing destination')


if __name__ == '__main__':
    unittest.main()
