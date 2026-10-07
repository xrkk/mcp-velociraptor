"""Author recovery tests using benign real files and owned Linux processes."""
import base64
import copy
import hashlib
import json
import multiprocessing
import os
import subprocess
import sys
import time
import unittest
import uuid
from unittest import mock

from tests import test_transfer_guest as fixture
from velo_transfer.errors import TransferContentError as Error
from velo_transfer.guest_service import GuestTransferService, request_digest
from velo_transfer.guest_worker import RootLease, process_birth, same_process
from velo_transfer.windows_platform import WindowsObservation
from velo_transfer.manifest import canonical_json
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

    def next_boot(self):
        service = GuestTransferService(self.policy,
            _observation=WindowsObservation('Windows', self.uuid, 'boot-next'),
            _acl_verifier=lambda path, kind: True)
        self.addCleanup(service.shutdown)
        return service

    def push_request(self, transfer_id, boot='boot-fixture'):
        request = self.request('push',
            [{'absolute_path': '/opaque/host', 'relative_path': 'file'}],
            self.write / transfer_id,
            {'size': 10, 'sha256': '0' * 64, 'manifest_sha256': '0' * 64},
            transfer_id=transfer_id)
        request['expected_vm_identity']['boot_identity'] = boot
        request['request_digest'] = request_digest(request)
        return request

    def test_new_boot_begin_preserves_old_task_and_lease_evidence(self):
        old = self.push_request('old')
        self.service.transfer_begin(old)
        old_path = self.work / 'tasks/old/state.json'
        old_bytes = old_path.read_bytes()
        lease_path = self.work / 'tasks/guest-internal-lease/state.json'
        lease_bytes = lease_path.read_bytes()
        service = self.next_boot()
        request = self.push_request('new', 'boot-next')
        result = service.transfer_begin(request)
        self.assertEqual(result['local_phase'], 'DEST_RECEIVING')
        self.assertEqual(old_path.read_bytes(), old_bytes)
        archives = list(lease_path.parent.glob('previous-*.json'))
        self.assertEqual(len(archives), 1)
        self.assertEqual(archives[0].read_bytes(), lease_bytes)
        with self.assertRaises(Error) as caught:
            service.transfer_begin(old)
        self.assertEqual(caught.exception.code, 'vm_identity_mismatch')
        with self.assertRaises(Error) as caught:
            service.transfer_status('old', old['request_digest'])
        self.assertEqual(caught.exception.code, 'vm_identity_mismatch')
        rebound = self.push_request('old', 'boot-next')
        with self.assertRaises(Error):
            service.transfer_begin(rebound)
        self.assertEqual(old_path.read_bytes(), old_bytes)
        self.assertFalse(service._owned)
        self.assertFalse((self.write / 'old').exists())

    def test_new_boot_root_contention_cannot_migrate(self):
        self.service.transfer_begin(self.push_request('old'))
        lease_path = self.work / 'tasks/guest-internal-lease/state.json'
        before = lease_path.read_bytes()
        script = ('import sys; from pathlib import Path; '
            'from velo_transfer.guest_worker import RootLease; '
            'lock = RootLease(Path(sys.argv[1])); lock.acquire(); '
            'print("locked", flush=True); sys.stdin.readline(); lock.release()')
        child = subprocess.Popen([sys.executable, '-c', script, str(self.work)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), 'locked')
            with self.assertRaises(Error) as caught:
                self.next_boot().transfer_begin(self.push_request('new', 'boot-next'))
            self.assertEqual(caught.exception.code, 'worker_busy')
            self.assertEqual(lease_path.read_bytes(), before)
            self.assertFalse((self.work / 'tasks/new').exists())
            self.assertFalse(list(lease_path.parent.glob('previous-*.json')))
        finally:
            child.communicate('\n', timeout=5)
        self.assertEqual(child.returncode, 0)

    def rewrite_lease(self, change):
        path = self.work / 'tasks/guest-internal-lease/state.json'
        envelope = self.service._store()._read(path)
        change(envelope)
        content = {key: value for key, value in envelope.items() if key != 'sha256'}
        envelope['sha256'] = hashlib.sha256(canonical_json(content)).hexdigest()
        path.write_bytes(canonical_json(envelope))

    def test_new_boot_unknown_corrupt_or_foreign_lease_is_unchanged(self):
        self.service.transfer_begin(self.push_request('old'))
        path = self.work / 'tasks/guest-internal-lease/state.json'
        original = path.read_bytes()
        service = self.next_boot()
        mutations = {
            'foreign_vm': lambda value: value['binding'].update(vm_uuid=str(uuid.uuid4())),
            'foreign_policy': lambda value: value['binding'].update(policy_id='foreign'),
            'foreign_epoch': lambda value: value['binding'].update(vm_epoch='business'),
            'foreign_digest': lambda value: value['binding'].update(request_digest='1' * 64),
            'unknown_boot': lambda value: value['binding'].update(boot_identity=''),
            'unknown_state': lambda value: value.update(state=[]),
            'extra_state': lambda value: value['state'].update(unknown=True),
            'unknown_active': lambda value: value['state'].update(active={'unknown': True}),
            'wrong_transfer': lambda value: value.update(transfer_id='foreign'),
        }
        for label, change in mutations.items():
            with self.subTest(label=label):
                path.write_bytes(original)
                self.rewrite_lease(change)
                before = path.read_bytes()
                with self.assertRaises(Error):
                    service.transfer_begin(self.push_request('new', 'boot-next'))
                self.assertEqual(path.read_bytes(), before)
                self.assertFalse((self.work / 'tasks/new').exists())
                self.assertFalse(list(path.parent.glob('previous-*.json')))
        path.write_bytes(original.replace(b'boot-fixture', b'boot-corrupt'))
        before = path.read_bytes()
        with self.assertRaises(Error) as caught:
            service.transfer_begin(self.push_request('new', 'boot-next'))
        self.assertEqual(caught.exception.code, 'state_hash_mismatch')
        self.assertEqual(path.read_bytes(), before)
        self.assertFalse((self.work / 'tasks/new').exists())

    def test_new_boot_occupied_owner_and_reused_pid_are_not_taken_over(self):
        self.service.transfer_begin(self.push_request('old'))
        path = self.work / 'tasks/guest-internal-lease/state.json'
        original = path.read_bytes()
        birth = process_birth(os.getpid())
        service = self.next_boot()
        for label, owner_birth in (('alive', birth), ('reused_pid', 'linux-impossible')):
            with self.subTest(label=label):
                path.write_bytes(original)
                self.rewrite_lease(lambda value: value['state'].update(active={
                    'transfer_id': 'old', 'job': 'package', 'nonce': 'old-owner',
                    'pid': os.getpid(), 'birth': owner_birth,
                    'deadline_monotonic': time.monotonic() + 60, 'stopped': False}))
                before = path.read_bytes()
                with mock.patch('velo_transfer.guest_service.terminate_verified') as terminate:
                    with self.assertRaises(Error) as caught:
                        service.transfer_begin(self.push_request('new', 'boot-next'))
                    self.assertEqual(caught.exception.code, 'worker_result_unknown')
                    terminate.assert_not_called()
                self.assertTrue(same_process(os.getpid(), birth))
                self.assertEqual(path.read_bytes(), before)
                self.assertFalse((self.work / 'tasks/new').exists())
                self.assertFalse(list(path.parent.glob('previous-*.json')))

    def test_new_boot_migration_holds_root_through_archive_and_replace(self):
        self.service.transfer_begin(self.push_request('old'))
        service = self.next_boot()
        from velo_transfer.storage import TaskStore
        commit = TaskStore._commit
        sidecar = service._atomic_sidecar
        checked = []
        def assert_locked():
            contender = RootLease(self.work)
            try:
                with self.assertRaises(Error) as caught:
                    contender.acquire()
                self.assertEqual(caught.exception.code, 'worker_busy')
            finally:
                contender.release()
        def archive(*args):
            assert_locked()
            checked.append('archive')
            return sidecar(*args)
        def replace(store, path, raw, revision):
            if path.parent.name == 'guest-internal-lease':
                assert_locked()
                checked.append('replace')
            return commit(store, path, raw, revision)
        with mock.patch.object(service, '_atomic_sidecar', side_effect=archive), \
                mock.patch.object(TaskStore, '_commit', autospec=True, side_effect=replace):
            service.transfer_begin(self.push_request('new', 'boot-next'))
        self.assertEqual(checked, ['archive', 'replace'])

    def test_new_boot_concurrent_begins_make_one_archive(self):
        self.service.transfer_begin(self.push_request('old'))
        service = self.next_boot()
        context = multiprocessing.get_context('fork')
        ready = context.Barrier(2)
        results = context.Queue()
        def begin(request):
            try:
                ready.wait(timeout=5)
                deadline = time.monotonic() + 3
                while True:
                    try:
                        result = service.transfer_begin(request)
                        results.put(('ok', result['local_phase']))
                        return
                    except Error as exc:
                        if exc.code != 'writer_busy' or time.monotonic() >= deadline:
                            raise
                        time.sleep(.005)
            except Exception as exc:
                results.put(('error', str(exc)))
        children = [context.Process(target=begin,
            args=(self.push_request(name, 'boot-next'),)) for name in ('new-one', 'new-two')]
        try:
            for child in children:
                child.start()
            for child in children:
                child.join(timeout=8)
                self.assertFalse(child.is_alive())
                self.assertEqual(child.exitcode, 0)
            self.assertEqual([results.get(timeout=2) for child in children],
                             [('ok', 'DEST_RECEIVING')] * 2)
        finally:
            for child in children:
                if child.is_alive():
                    child.terminate()
                if child.pid is not None:
                    child.join(timeout=5)
                    child.close()
            results.close()
            results.join_thread()
        path = self.work / 'tasks/guest-internal-lease/state.json'
        self.assertEqual(len(list(path.parent.glob('previous-*.json'))), 1)
        envelope = service._store().load('guest-internal-lease', service._lease_binding())
        self.assertEqual(envelope['revision'], 1)
        self.assertEqual(envelope['state'], {'active': None})

    def test_new_boot_interrupted_replace_preserves_archive_and_retries(self):
        self.service.transfer_begin(self.push_request('old'))
        path = self.work / 'tasks/guest-internal-lease/state.json'
        old_bytes = path.read_bytes()
        service = self.next_boot()
        request = self.push_request('new', 'boot-next')
        with mock.patch('velo_transfer.storage._replace',
                        side_effect=OSError('injected replace failure')):
            with self.assertRaises(Error) as caught:
                service.transfer_begin(request)
        self.assertEqual(caught.exception.code, 'storage_write_failed')
        self.assertEqual(path.read_bytes(), old_bytes)
        archives = list(path.parent.glob('previous-*.json'))
        self.assertEqual(len(archives), 1)
        self.assertEqual(archives[0].read_bytes(), old_bytes)
        self.assertFalse((self.work / 'tasks/new').exists())
        self.assertEqual(service.transfer_begin(request)['local_phase'], 'DEST_RECEIVING')
        self.assertEqual(list(path.parent.glob('previous-*.json')), archives)

    def test_new_boot_real_pull_worker_and_same_boot_restart(self):
        self.service.transfer_begin(self.push_request('old'))
        self.service = self.next_boot()
        source = self.read / 'fresh.txt'
        source.write_bytes(b'benign after reboot')
        request = self.request('pull', [{'absolute_path': str(source),
            'relative_path': 'fresh.txt'}], self.host / 'fresh', transfer_id='fresh')
        request['expected_vm_identity']['boot_identity'] = 'boot-next'
        request['request_digest'] = request_digest(request)
        self.service.transfer_begin(request)
        result = self.wait_phase(request, 'SOURCE_READY')
        self.assertTrue(result['worker']['stopped'])
        self.assertIsNone(result['error'])
        restarted = self.next_boot()
        self.assertEqual(restarted.transfer_status('fresh', request['request_digest']), result)
        part = restarted.transfer_chunk('fresh', request['request_digest'], 0,
                                        result['package']['size'])
        raw = base64.b64decode(part['data_base64'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), result['package']['sha256'])
        self.assertEqual(source.read_bytes(), b'benign after reboot')
        self.assertEqual(len(list((self.work / 'tasks/guest-internal-lease').glob(
            'previous-*.json'))), 1)

    def test_new_boot_corrupt_archive_cannot_be_overwritten(self):
        self.service.transfer_begin(self.push_request('old'))
        path = self.work / 'tasks/guest-internal-lease/state.json'
        before = path.read_bytes()
        previous = json.loads(before)
        archive = path.parent / f"previous-{previous['revision']}-{previous['sha256']}.json"
        archive.write_bytes(b'unknown archive')
        archive.chmod(0o600)
        with self.assertRaises(Error) as caught:
            self.next_boot().transfer_begin(self.push_request('new', 'boot-next'))
        self.assertEqual(caught.exception.code, 'invalid_state')
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(archive.read_bytes(), b'unknown archive')
        self.assertFalse((self.work / 'tasks/new').exists())

    def test_new_boot_changed_root_lock_cannot_commit_migration(self):
        self.service.transfer_begin(self.push_request('old'))
        path = self.work / 'tasks/guest-internal-lease/state.json'
        before = path.read_bytes()
        service = self.next_boot()
        sidecar = service._atomic_sidecar
        def change_lock(*args):
            sidecar(*args)
            lock = self.work / '.guest-worker.lock'
            lock.rename(self.work / '.original-worker-lock')
            lock.write_bytes(b'')
            lock.chmod(0o600)
        with mock.patch.object(service, '_atomic_sidecar', side_effect=change_lock):
            with self.assertRaises(Error) as caught:
                service.transfer_begin(self.push_request('new', 'boot-next'))
        self.assertEqual(caught.exception.code, 'worker_lock_unavailable')
        self.assertEqual(path.read_bytes(), before)
        archives = list(path.parent.glob('previous-*.json'))
        self.assertEqual(len(archives), 1)
        self.assertEqual(archives[0].read_bytes(), before)
        self.assertFalse((self.work / 'tasks/new').exists())

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
