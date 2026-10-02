"""Real task files/workers for PC026; injected durability faults are labelled seams."""
import base64
import copy
import hashlib
import json
import os
import time
import unittest
from unittest import mock

from tests import test_transfer_guest as fixture
from velo_transfer import guest_service as gm
from velo_transfer.errors import TransferContentError as Error
from velo_transfer.guest_service import GuestTransferService, request_digest
from velo_transfer.guest_worker import process_birth
from velo_transfer.windows_platform import observe_windows


class PrefixTests(unittest.TestCase):
    request = fixture.GuestTests.request
    wait_phase = fixture.GuestTests.wait_phase
    budget = fixture.GuestTests.budget

    def setUp(self):
        fixture.GuestTests.setUp(self)
        policy = json.loads(self.policy.read_text())
        policy["limits"]["max_batch_chunks"] = 8
        self.policy.write_text(json.dumps(policy))
        self.service.shutdown()
        self.service = GuestTransferService(self.policy, _observation=self.observation,
            _acl_verifier=lambda path, kind: True)
        self.addCleanup(self.service.shutdown)
        if os.name == 'nt':
            self.service.shutdown()
            self.observation = observe_windows()
            self.uuid = self.observation.vm_uuid
            policy = json.loads(self.policy.read_text())
            policy['expected_vm_uuid'] = self.uuid
            policy['limits']['max_duration_seconds'] = 240
            self.limits['max_duration_seconds'] = 240
            self.policy.write_text(json.dumps(policy))
            patch = mock.patch.dict(os.environ, {'VELOCIRAPTOR_TRANSFER_POLICY': str(self.policy)})
            patch.start()
            self.addCleanup(patch.stop)
            self.service = GuestTransferService(self.policy)
            self.addCleanup(self.service.shutdown)

    def push(self, size=9):
        req = self.request('push', [{'absolute_path': 'opaque-host', 'relative_path': 'file'}],
            self.write / 'final', {'size': size, 'sha256': '0' * 64, 'manifest_sha256': '1' * 64})
        req['expected_vm_identity']['boot_identity'] = self.observation.boot_identity
        req['request_digest'] = request_digest(req)
        self.service.transfer_begin(req)
        return req

    def send_chunk(self, req, offset=0, raw=b'abcd'):
        return self.service.transfer_chunk('trial', req['request_digest'], offset, len(raw),
            base64.b64encode(raw).decode(), hashlib.sha256(raw).hexdigest())

    def resume(self, req):
        self.service.transfer_begin(req)
        return self.wait_phase(req, 'DEST_RECEIVING')

    def test_actual_worker_proof_matches_ledger_new_nonce_and_deadline(self):
        req = self.push()
        self.send_chunk(req)
        before = self.service._load('trial', req['request_digest'])['state']
        first = self.resume(req)
        proof = first['prefix_verification']
        self.assertEqual(set(proof), {'schema','request_digest','worker_nonce','verified_offset',
                                    'chunk_count','ledger_sha256','completed'})
        self.assertEqual(proof['ledger_sha256'], hashlib.sha256(
            (self.work / 'tasks/trial/chunks.jsonl').read_bytes()).hexdigest())
        self.assertEqual(proof['verified_offset'], 4)
        self.assertEqual(proof['chunk_count'], 1)
        self.assertTrue(proof['completed'])
        second = self.resume(req)
        self.assertNotEqual(second['worker']['nonce'], first['worker']['nonce'])
        self.assertEqual(second['prefix_verification']['worker_nonce'], second['worker']['nonce'])
        after = self.service._load('trial', req['request_digest'])['state']
        self.assertEqual(before['deadline_monotonic'], after['deadline_monotonic'])
        self.send_chunk(req, 4, b'ef')
        self.assertIsNone(self.service.transfer_status('trial', req['request_digest'])['prefix_verification'])

    def test_zero_prefix_requires_real_worker_and_cancel_clears_proof(self):
        req = self.push()
        status = self.resume(req)
        self.assertEqual(status['prefix_verification']['ledger_sha256'], hashlib.sha256(b'').hexdigest())
        self.assertEqual(status['prefix_verification']['chunk_count'], 0)
        self.assertTrue(status['worker']['stopped'])
        stopped = self.service.transfer_abort('trial', req['request_digest'])
        self.assertIsNone(stopped['prefix_verification'])

    def test_owned_unacknowledged_tail_recovers_actual_bytes(self):
        req = self.push()
        self.send_chunk(req)
        part = self.work / 'tasks/trial/received.part'
        ledger = self.work / 'tasks/trial/chunks.jsonl'
        accepted = ledger.read_bytes()
        with part.open('ab') as f:
            f.write(b'tail')
        with ledger.open('ab') as f:
            f.write(b'unacknowledged')
        status = self.resume(req)
        self.assertEqual(part.read_bytes(), b'abcd')
        self.assertEqual(ledger.read_bytes(), accepted)
        self.assertEqual(status['prefix_verification']['ledger_sha256'], hashlib.sha256(accepted).hexdigest())

    def test_foreign_zero_prefix_is_not_truncated_or_proved(self):
        req = self.push()
        task = self.work / 'tasks/trial'
        (task / 'received.part').write_bytes(b'foreign')
        (task / 'chunks.jsonl').write_bytes(b'foreign')
        self.service.transfer_begin(req)
        until = time.monotonic() + 60
        while time.monotonic() < until:
            status = self.service.transfer_status('trial', req['request_digest'])
            if status['worker']['stopped']:
                break
            time.sleep(.02)
        self.assertEqual(status['error'], 'partial_changed')
        self.assertIsNone(status['prefix_verification'])
        self.assertEqual((task / 'received.part').read_bytes(), b'foreign')
        self.assertEqual((task / 'chunks.jsonl').read_bytes(), b'foreign')

    def test_old_object_without_proof_requires_actual_reverification(self):
        req = self.push()
        self.send_chunk(req)
        store = self.service._store()
        with store.writer():
            env = self.service._load('trial', req['request_digest'], store)
            del env['state']['prefix_verification']
            store.save('trial', env['binding'], env['revision'], env['state'])
        self.assertIsNone(self.service.transfer_status('trial', req['request_digest'])['prefix_verification'])
        self.assertTrue(self.resume(req)['prefix_verification']['completed'])

    def test_valid_batch_io_failure_retains_owned_prefix_then_recovers(self):
        req = self.push()
        self.send_chunk(req)
        original = gm.os.fsync
        def fail_payload(fd):
            if os.fstat(fd).st_size == 8:
                raise OSError('labelled injected payload fsync failure')
            return original(fd)
        chunks = [{'count': 4, 'data_base64': base64.b64encode(b'efgh').decode(),
                   'chunk_sha256': hashlib.sha256(b'efgh').hexdigest()}]
        with mock.patch.object(gm.os, 'fsync', fail_payload), self.assertRaises(OSError):
            self.service.transfer_chunks('trial', req['request_digest'], 4, chunks=chunks)
        self.assertEqual(self.service.transfer_status('trial', req['request_digest'])['verified_offset'], 4)
        self.assertEqual((self.work / 'tasks/trial/received.part').read_bytes(), b'abcdefgh')
        self.resume(req)
        self.assertEqual((self.work / 'tasks/trial/received.part').read_bytes(), b'abcd')

    def test_proof_save_fault_no_completed_and_lost_reply_keeps_real_proof(self):
        req = self.push()
        self.send_chunk(req)
        store = self.service._store()
        # Execute the production verification/persistence job in the test process
        # with an explicit owner; this fault seam is not a subprocess crash claim.
        with store.writer():
            env = self.service._load('trial', req['request_digest'], store)
            env['state']['owner'] = {'transfer_id':'trial','job':'verify_partial','nonce':'fault-test',
                'pid':os.getpid(),'birth':process_birth(os.getpid()),
                'deadline_monotonic':env['state']['deadline_monotonic'],'stopped':False}
            self.service._save(store, env, env['state'])
        original = self.service._save
        def fail_before(store, env, state):
            if state.get('prefix_verification'):
                raise OSError('labelled before proof persistence fault')
            return original(store, env, state)
        with mock.patch.object(self.service, '_save', fail_before), self.assertRaises(OSError):
            self.service._execute('trial', req['request_digest'], 'verify_partial')
        self.assertIsNone(self.service._load('trial', req['request_digest'])['state']['prefix_verification'])
        def save_then_lose(store, env, state):
            result = original(store, env, state)
            if state.get('prefix_verification'):
                raise OSError('labelled after persistence lost reply')
            return result
        with mock.patch.object(self.service, '_save', save_then_lose), self.assertRaises(OSError):
            self.service._execute('trial', req['request_digest'], 'verify_partial')
        state = self.service._load('trial', req['request_digest'])['state']
        self.assertTrue(state['prefix_verification']['completed'])
        # Test-owned registration is stopped before cleanup; do not kill our process.
        with store.writer():
            env = self.service._load('trial', req['request_digest'], store)
            env['state']['owner']['stopped'] = True
            self.service._save(store, env, env['state'])

    def test_malformed_old_nonce_wrong_offset_or_unfinished_persistent_proof_rejected(self):
        req = self.push()
        self.send_chunk(req)
        self.resume(req)
        store = self.service._store()
        for change in ({'worker_nonce':'old'}, {'verified_offset':3}, {'completed':False},
                       {'chunk_count':True}, {'extra':1}, {'request_digest':'f'*64}):
            with self.subTest(change=change), store.writer():
                env = self.service._load('trial', req['request_digest'], store)
                state = copy.deepcopy(env['state'])
                state['prefix_verification'].update(change)
                with self.assertRaises(Error):
                    store.save('trial', env['binding'], env['revision'], state)


if __name__ == '__main__':
    unittest.main()
