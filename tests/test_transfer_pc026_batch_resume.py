"""Actual guest files/workers; Linux host transport and outcome faults are seams.

Windows runs GuestBatchResumeTests with the existing conditional ACL fixture.
The host cases use a constructed HostRequest for POSIX guest paths, bypassing
only the Windows path parser and network/profile transport, not guest proofs.
"""
import base64
import copy
import hashlib
import json
import os
import unittest
from contextlib import asynccontextmanager
from pathlib import Path

from tests import test_transfer_pc026_prefix as prefix_fixture
from velo_transfer.errors import TransferContentError as Error
from velo_transfer.guest_service import GuestTransferService
from velo_transfer.adapters import AdapterError
from velo_transfer.manifest import canonical_json, digest_json
from velo_transfer.request import HostRequest


def items(*payloads):
    return [{'count': len(raw), 'data_base64': base64.b64encode(raw).decode(),
             'chunk_sha256': hashlib.sha256(raw).hexdigest()} for raw in payloads]


class GuestBatchResumeTests(unittest.TestCase):
    setUp = prefix_fixture.PrefixTests.setUp
    request = prefix_fixture.PrefixTests.request
    push = prefix_fixture.PrefixTests.push
    resume = prefix_fixture.PrefixTests.resume
    send_chunk = prefix_fixture.PrefixTests.send_chunk
    wait_phase = prefix_fixture.PrefixTests.wait_phase
    budget = prefix_fixture.PrefixTests.budget

    def snapshot(self):
        return {str(p): (p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns)
                for p in self.work.rglob('*') if p.is_file()}

    def test_nonzero_real_proof_batch_and_remaining_tail(self):
        req = self.push()
        self.send_chunk(req)
        old = self.service._load('trial', req['request_digest'])['state']
        verified = self.resume(req)
        self.assertEqual(verified['prefix_verification']['verified_offset'], 4)
        self.assertNotEqual(verified['worker']['pid'], os.getpid())
        result = self.service.transfer_chunks('trial', req['request_digest'], 4,
                                             chunks=items(b'efgh', b'i'))
        self.assertEqual(result['verified_offset'], 9)
        after = self.service._load('trial', req['request_digest'])['state']
        self.assertIsNone(after['prefix_verification'])
        self.assertEqual(after['phase'], 'DEST_RECEIVED')
        self.assertEqual(after['deadline_monotonic'], old['deadline_monotonic'])
        self.assertEqual((self.work/'tasks/trial/received.part').read_bytes(), b'abcdefghi')
        records = [json.loads(line) for line in (self.work/'tasks/trial/chunks.jsonl').read_bytes().splitlines()]
        self.assertEqual([(r['offset'], r['count']) for r in records], [(0,4), (4,4), (8,1)])

    def test_zero_real_proof_first_batch_then_new_reverification(self):
        req = self.push()
        first = self.resume(req)
        self.assertEqual(first['prefix_verification']['ledger_sha256'], hashlib.sha256(b'').hexdigest())
        self.service.transfer_chunks('trial', req['request_digest'], 0, chunks=items(b'abcd', b'ef'))
        self.assertIsNone(self.service.transfer_status('trial', req['request_digest'])['prefix_verification'])
        second = self.resume(req)
        proof = second['prefix_verification']
        self.assertNotEqual(proof['worker_nonce'], first['prefix_verification']['worker_nonce'])
        self.assertEqual((proof['verified_offset'], proof['chunk_count']), (6, 2))
        self.assertEqual(proof['ledger_sha256'], hashlib.sha256(
            (self.work/'tasks/trial/chunks.jsonl').read_bytes()).hexdigest())
        self.service.transfer_chunks('trial', req['request_digest'], 6, chunks=items(b'ghi'))
        self.assertEqual((self.work/'tasks/trial/received.part').read_bytes(), b'abcdefghi')

    def test_illegal_second_item_preserves_proof_and_all_task_bytes(self):
        req = self.push()
        self.send_chunk(req)
        status = self.resume(req)
        before = self.snapshot()
        for change in ({'chunk_sha256': '0'*64}, {'count': True}, {'data_base64': '!!!!'}):
            batch = items(b'ef', b'gh')
            batch[1].update(change)
            with self.subTest(change=change), self.assertRaises(Error):
                self.service.transfer_chunks('trial', req['request_digest'], 4, chunks=batch)
            self.assertEqual(self.snapshot(), before)
            self.assertEqual(self.service.transfer_status('trial', req['request_digest'])['prefix_verification'],
                             status['prefix_verification'])

    def test_future_owned_identity_budget_rejects_before_payload_creation(self):
        req = self.push()
        self.tighten_state_budget()
        before = self.snapshot()
        with self.assertRaises(Error) as raised:
            self.service.transfer_chunks('trial', req['request_digest'], 0, chunks=items(b'ab', b'cd'))
        self.assertEqual(raised.exception.code, 'state_budget_exceeded')
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.work/'tasks/trial/received.part').exists())
        self.assertFalse((self.work/'tasks/trial/chunks.jsonl').exists())

    def test_future_terminal_budget_retains_verified_prefix(self):
        req = self.push()
        self.send_chunk(req)
        proof = self.resume(req)['prefix_verification']
        self.tighten_state_budget()
        before = self.snapshot()
        with self.assertRaises(Error) as raised:
            self.service.transfer_chunks('trial', req['request_digest'], 4, chunks=items(b'efgh', b'i'))
        self.assertEqual(raised.exception.code, 'state_budget_exceeded')
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.service.transfer_status('trial', req['request_digest'])['prefix_verification'], proof)

    def tighten_state_budget(self):
        state_path = self.work/'tasks/trial/state.json'
        current_size = len(state_path.read_bytes())
        self.service.shutdown()
        policy = json.loads(self.policy.read_text())
        policy['limits']['max_state_bytes'] = current_size + 10
        self.policy.write_text(json.dumps(policy))
        if os.name == 'nt':
            self.service = GuestTransferService(self.policy)
        else:
            self.service = GuestTransferService(self.policy, _observation=self.observation,
                                                _acl_verifier=lambda path, kind: True)
        self.addCleanup(self.service.shutdown)


class RealGuestPeer:
    """In-process transport only; every success invokes the actual guest engine."""
    channel = 'velo'
    fallback_reason = None
    raw_chunk_bytes = 128
    batch_chunks = 2

    def __init__(self, fixture, fault_when):
        self.service = fixture.service
        self.observations = self.service.transfer_capabilities()
        self.fault_when = fault_when
        self.trace = []
        self.writes = []
        self.proofs = []
        self.calls = 0
        self.fault_index = None

    async def call(self, operation, arguments):
        self.trace.append((operation, copy.deepcopy(arguments)))
        uncertain = False
        if operation == 'transfer_chunks':
            self.calls += 1
            uncertain = self.calls == 2
            if uncertain:
                self.fault_index = len(self.trace) - 1
                if self.fault_when == 'before':
                    raise AdapterError('outcome_unknown', may_have_committed=True)
        try:
            result = getattr(self.service, operation)(**arguments)
        except Error as exc:
            raise AdapterError(exc.code) from exc
        if operation == 'transfer_chunks':
            self.writes.append((arguments['offset'], result['verified_offset']))
            state = self.service._load(arguments['transfer_id'], arguments['request_digest'])['state']
            assert state['prefix_verification'] is None
            if uncertain:
                raise AdapterError('outcome_unknown', may_have_committed=True)
        if operation == 'transfer_status' and result.get('prefix_verification'):
            proof = result['prefix_verification']
            ledger = self.service.policy.work_root/'tasks'/arguments['transfer_id']/'chunks.jsonl'
            assert proof['ledger_sha256'] == hashlib.sha256(ledger.read_bytes()).hexdigest()
            assert proof['worker_nonce'] == result['worker']['nonce']
            self.proofs.append(copy.deepcopy(result))
        return result


@unittest.skipIf(os.name == 'nt', 'Linux host coordinator integration, native guest covered separately')
class RealGuestCoordinatorTests(unittest.IsolatedAsyncioTestCase):
    async def run_case(self, when):
        from velo_transfer.host_coordinator import TransferCoordinator

        f = prefix_fixture.PrefixTests('test_actual_worker_proof_matches_ledger_new_nonce_and_deadline')
        f.setUp()
        self.addCleanup(f.doCleanups)
        source = f.host/'benign.bin'
        raw = os.urandom(2137)
        source.write_bytes(raw)
        document = {'schema': 'velo.transfer.request.v1', 'direction': 'push',
            'sources': [{'absolute_path': str(source), 'relative_path': 'benign.bin'}],
            'destination_directory': str(f.write/'final'),
            'connection_profile': str(f.host/'unused-profile.json'),
            'expected_vm_identity': {'vm_uuid': f.uuid, 'boot_identity': f.observation.boot_identity,
                                     'vm_epoch': 'fixture-epoch'},
            'evidence_context': {'producer_complete': True, 'producer_quiescent': True,
                                 'references': ['benign-fixture']},
            'budget': {k: f.limits[k] for k in ('max_files','max_metadata_bytes','max_logical_bytes',
                       'max_package_bytes','min_free_bytes','max_chunk_bytes','max_duration_seconds')}}
        document['budget']['request_timeout_seconds'] = 10
        document.update(transfer_id='trial', resume=False)
        request = HostRequest(f.host/'request.json', f.host/'.velo-transfer', 'trial', False,
                              digest_json({k:v for k,v in document.items() if k not in ('transfer_id','resume')}),
                              10, canonical_json(document))
        peer = RealGuestPeer(f, when)
        @asynccontextmanager
        async def select(profile, **kwargs):
            yield peer
        coordinator = TransferCoordinator(request,
            _adapter_selector=select, _profile_loader=lambda _: None)
        result = await coordinator.run()
        self.assertEqual(result['outcome'], 'complete', result)
        self.assertEqual((f.write/'final/benign.bin').read_bytes(), raw)
        self.assertGreater(len(peer.writes), 2)
        self.assertEqual(len({a for a,b in peer.writes}), len(peer.writes))
        self.assertEqual([a for a,b in peer.writes][1:], [b for a,b in peer.writes][:-1])
        self.assertTrue(peer.proofs)
        proof = peer.proofs[0]
        self.assertTrue(proof['worker']['stopped'])
        self.assertNotEqual(proof['worker']['pid'], os.getpid())
        self.assertEqual(proof['prefix_verification']['verified_offset'], 256 if when == 'before' else 512)
        trace = peer.trace[peer.fault_index+1:]
        operations = [op for op,args in trace]
        self.assertIn('transfer_begin', operations)
        self.assertLess(operations.index('transfer_begin'), operations.index('transfer_chunks'))
        self.assertNotIn('transfer_chunk', [op for op,args in peer.trace])
        persisted = json.loads(Path(result['result_path']).read_bytes())
        self.assertTrue(persisted['cleanup']['host'])
        self.assertTrue(persisted['cleanup']['guest'])

    async def test_uncertain_unwritten_batch_real_reconcile_then_batch(self):
        await self.run_case('before')

    async def test_uncertain_written_batch_real_reconcile_then_batch(self):
        await self.run_case('after')


if __name__ == '__main__':
    unittest.main()
