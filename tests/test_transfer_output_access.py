"""Completed-output handoff: real worker/cleanup seam, with native ACL seam injected."""
import os
import json
import unittest
from unittest import mock

from tests import test_transfer_guest_finalization as fixtures
from velo_transfer import guest_service
from velo_transfer.errors import TransferContentError as Error
from velo_transfer import output_access
from velo_transfer import windows_platform as platform
from pathlib import PureWindowsPath


class SharedContentAclTests(unittest.TestCase):
    def test_shared_parent_owner_write_allowed_but_stage_and_private_gates_remain_private(self):
        system = 'S-1-5-18'
        user = 'S-1-5-21-1-2-3-1001'
        drive = PureWindowsPath('C:/')
        parent, stage = drive / 'shared', drive / 'shared' / '.velo-stage-test'
        private = platform.AclSnapshot(system, (platform.Ace(0, 3, 0x1F01FF, system),))
        ordinary = platform.AclSnapshot(user, (
            platform.Ace(0, 3, output_access.MODIFY, 'S-1-5-32-545'), *private.aces))
        snapshots = {drive: ordinary, parent: ordinary, stage: private}
        verifier = platform.WindowsAclVerifier(_reader=lambda p: snapshots[p], _current_sid=system)
        with mock.patch.object(platform, 'Path', PureWindowsPath), mock.patch.object(
                platform, '_fingerprint', return_value=(1, 2, 3, 0)):
            callback = verifier.content_callback(stage, parent, shared_content=True)
            self.assertIs(callback(parent), True)
            self.assertIs(callback(stage), True)
            snapshots[stage] = ordinary
            with self.assertRaises(Error):
                callback(stage)
            for kind in ('work', 'policy', 'state'):
                with self.assertRaises(Error):
                    verifier(parent, kind, shared_content=True)

    def test_output_grants_do_not_make_users_trusted_for_dacl_owner_or_deny(self):
        system = 'S-1-5-18'
        base = platform.Ace(0, 3, 0x1F01FF, system)
        for sid in output_access.SHARED_SIDS:
            good = platform.AclSnapshot(system, (
                base, platform.Ace(0, 3, output_access.MODIFY, sid)))
            output_access.validate_output_security(good, frozenset((system,)))
            for bad in (platform.AclSnapshot(sid, good.aces),
                        platform.AclSnapshot(system, (base, platform.Ace(0, 3, 0x1F01FF, sid))),
                        platform.AclSnapshot(system, (base, platform.Ace(1, 0, 2, sid)))):
                with self.assertRaises(Error):
                    output_access.validate_output_security(bad, frozenset((system,)))

    def test_invalid_deployment_mode_fails_closed(self):
        with mock.patch.dict(os.environ, VELOCIRAPTOR_TRANSFER_OUTPUT_ACCESS='everyone_full'):
            with self.assertRaises(Error):
                output_access.configured_mode()

    def test_acl_query_diagnostic_keeps_path_and_native_code(self):
        path = PureWindowsPath('C:/output/child.txt')
        with mock.patch.object(output_access, '_read_security',
                               side_effect=Error('windows_acl_unavailable', winerror=5)):
            with self.assertRaises(Error) as caught:
                output_access.read_output_security(path)
        self.assertEqual(caught.exception.context['path'], str(path))
        self.assertEqual(caught.exception.context['winerror'], 5)
        self.assertEqual(caught.exception.context['operation'], 'GetNamedSecurityInfoW')


@unittest.skipUnless(os.name == 'posix', 'isolated fork fixture')
class OutputAccessTests(unittest.TestCase):
    budget = fixtures.FinalizationTests.budget
    request = fixtures.FinalizationTests.request
    wait_phase = fixtures.FinalizationTests.wait_phase
    published_push = fixtures.FinalizationTests.published_push
    release = fixtures.FinalizationTests.release
    stopped_status = fixtures.FinalizationTests.stopped_status

    def setUp(self):
        fixtures.FinalizationTests.setUp(self)
        secrets = self.root / 'secrets'
        secrets.mkdir(mode=0o700)
        relocated = secrets / 'policy.json'
        self.policy.rename(relocated)
        self.policy = relocated
        self.service = guest_service.GuestTransferService(self.policy,
            _observation=self.observation, _acl_verifier=lambda path, kind: True)
        self.addCleanup(self.service.shutdown)
        self.service.output_access_mode = 'shared_modify'

    def test_handoff_after_cleanup_before_release_and_durable_replay(self):
        req, destination, prepare, publication, source = self.published_push('share-ok')
        task = self.work / 'tasks' / req['transfer_id']
        marker = self.host / 'acl-called'
        def grant(root, manifest, budget, identity, trusted):
            self.assertFalse((task / 'received.part').exists())
            self.assertFalse((task / 'chunks.jsonl').exists())
            state = self.service._load(req['transfer_id'], req['request_digest'])['state']
            self.assertIsNotNone(state.get('output_access_intent'))
            self.assertEqual(state['phase'], 'DEST_RELEASING')
            self.assertIsNone(state.get('destination_verification'))
            self.assertEqual((destination / 'content.bin').read_bytes(), source.read_bytes())
            marker.write_text('granted')
            return {'objects': 2, 'acl_sha256': 'a' * 64}
        with mock.patch.object(guest_service, 'grant_output_tree', grant, create=True):
            self.release(req, prepare, publication)
            done = self.wait_phase(req, 'DEST_RELEASED')
        self.assertTrue(marker.exists())
        self.assertEqual(done['output_access']['mode'], 'shared_modify')
        self.assertTrue(done['output_access']['acl_verified'])
        self.assertEqual(done['destination_verification']['verification_phase'], 'post_cleanup')
        self.assertEqual(self.release(req, prepare, publication)['operation']['status'], 'DONE')
        self.assertEqual(self.service.transfer_status(req['transfer_id'], req['request_digest'])[
            'output_access'], done['output_access'])

    def test_acl_failure_never_completes_and_logs_path_native_error(self):
        req, destination, prepare, publication, _ = self.published_push('share-denied')
        def refuse(*args):
            raise Error('output_acl_failed', path=str(destination / 'content.bin'),
                        operation='SetSecurityInfo', winerror=5, os_error='Access is denied')
        with mock.patch.object(guest_service, 'grant_output_tree', refuse, create=True):
            self.release(req, prepare, publication)
            status = self.stopped_status(req)
        self.assertEqual(status['local_phase'], 'DEST_RELEASING')
        self.assertEqual(status['error'], 'output_acl_failed')
        self.assertIsNone(status['destination_verification'])
        path = self.work / 'tasks' / req['transfer_id'] / (
            'worker-error-' + status['worker']['nonce'] + '.json')
        record = self.service._read_sidecar(path, 256 * 1024)
        self.assertEqual(record['error']['context']['path'], str(destination / 'content.bin'))
        self.assertEqual(record['error']['context']['winerror'], 5)
        self.assertEqual(record['error']['context']['operation'], 'SetSecurityInfo')
        self.assertEqual(record['error']['context']['os_error'], 'Access is denied')

    def test_private_mode_never_calls_handoff(self):
        self.service.output_access_mode = 'private'
        req, _, prepare, publication, _ = self.published_push('share-private')
        with mock.patch.object(guest_service, 'grant_output_tree', side_effect=AssertionError,
                               create=True):
            self.release(req, prepare, publication)
            done = self.wait_phase(req, 'DEST_RELEASED')
        self.assertNotIn('output_access', done)

    def test_failed_acl_retry_preserves_intent_and_completes(self):
        req, destination, prepare, publication, _ = self.published_push('share-retry')
        with mock.patch.object(guest_service, 'grant_output_tree',
                side_effect=Error('output_acl_failed', path=str(destination), winerror=5)):
            self.release(req, prepare, publication)
            failed = self.stopped_status(req)
        self.assertEqual(failed['error'], 'output_acl_failed')
        intent = self.service._load(req['transfer_id'], req['request_digest'])[
            'state']['output_access_intent']
        with mock.patch.object(guest_service, 'grant_output_tree',
                               return_value={'objects': 2, 'acl_sha256': 'b' * 64}):
            self.release(req, prepare, publication)
            done = self.wait_phase(req, 'DEST_RELEASED')
        self.assertIsNone(done['error'])
        self.assertEqual(done['output_access']['binding'], intent['binding'])

    def test_output_mode_is_bound_at_begin(self):
        req, destination, prepare, publication, _ = self.published_push('share-bound')
        self.service.output_access_mode = 'private'
        with mock.patch.object(guest_service, 'grant_output_tree',
                               return_value={'objects': 2, 'acl_sha256': 'c' * 64}):
            self.release(req, prepare, publication)
            done = self.wait_phase(req, 'DEST_RELEASED')
        self.assertEqual(done['output_access']['mode'], 'shared_modify')

    def test_all_disk_write_scope_does_not_publish_shared_private_config_or_work(self):
        document = json.loads(self.policy.read_text())
        document['write_roots'] = [str(self.root)]
        self.policy.write_text(json.dumps(document))
        self.service = guest_service.GuestTransferService(self.policy,
            _observation=self.observation, _acl_verifier=lambda path, kind: True)
        self.addCleanup(self.service.shutdown)
        self.service.output_access_mode = 'shared_modify'
        for parent in (self.work, self.policy.parent):
            req = self.request('push', [{'absolute_path': str(self.host / 'benign'),
                'relative_path': 'benign'}], parent / 'shared-output',
                {'size': 0, 'sha256': 'a' * 64, 'manifest_sha256': 'b' * 64})
            with self.assertRaises(Error) as caught:
                self.service.transfer_begin(req)
            self.assertEqual(caught.exception.code, 'private_output_target')

    def test_capability_and_handoff_receipt_match_formal_wire_contract(self):
        from jsonschema import Draft202012Validator
        from velo_transfer.mcp_tools import _CONTRACT
        req, _, prepare, publication, _ = self.published_push('share-contract')
        with mock.patch.object(guest_service, 'grant_output_tree',
                               return_value={'objects': 2, 'acl_sha256': 'd' * 64}):
            self.release(req, prepare, publication)
            done = self.wait_phase(req, 'DEST_RELEASED')
        for name, result in (('transfer_status', done),
                             ('transfer_capabilities', self.service.transfer_capabilities())):
            body = {'schema': 'velo.transfer.mcp.response.v1', 'status': 'success', 'result': result}
            Draft202012Validator(_CONTRACT[name]['outputSchema']).validate(body)


if __name__ == '__main__':
    unittest.main()
