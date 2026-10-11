"""Local mocks of the native read boundary for the boot-service producer.

No VM, no real systemd private socket, no network and no sample execution:
every native seam is replaced with auditable static benign bytes and
temporary directories. Payload self-description must never be adopted; the
observation is derived only from the mocked manager/proc/kernel reads.
"""
import base64
import copy
import itertools
import json
import os
import shutil
import stat
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import velociraptor_linux_boot_service as boot


FRAGMENT_TEXT = ('[Unit]\n'
                 'Description=MalTrace benign boot service fixture\n'
                 '[Service]\n'
                 'Type=exec\n'
                 'User=1201\n'
                 'Group=1201\n'
                 'ExecStart={payload} --run benign\n'
                 '[Install]\n'
                 'WantedBy=multi-user.target\n')


class FakeManager:
    def __init__(self, peer=(1, 0, 0)):
        self.peer = list(peer)
        self.closed = False

    def close(self):
        self.closed = True


class Harness:
    """Static benign fixture patched over every native seam."""

    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix='boot-service-fixture-'))
        self.payload_path = self.root / 'benign-payload'
        self.fragment_path = self.root / 'maltrace-boot.service'
        # The payload bytes deliberately embed forged self-description that
        # must never be adopted by the observation.
        self.forged = dict(boot_id=str(uuid.uuid4()), vm_uuid=str(uuid.uuid4()),
                           pid='99999', verified='true')
        self.payload_bytes = (('boot_id=%s\nvm_uuid=%s\npid=%s\nverified=%s\n'
                               % (self.forged['boot_id'], self.forged['vm_uuid'],
                                  self.forged['pid'], self.forged['verified']))
                              .encode() + b'benign fixture payload\n' * 4)
        self.payload_path.write_bytes(self.payload_bytes)
        self.fragment_text = FRAGMENT_TEXT.format(payload=self.payload_path)
        self.fragment_path.write_text(self.fragment_text)
        self.invocation = 'a' * 32
        self.main_pid = 4242
        self.birth = '900100'
        self.properties = dict(
            Id='maltrace-boot.service', FragmentPath=str(self.fragment_path),
            DropInPaths='', LoadState='loaded', ActiveState='active',
            SubState='running', InvocationID=self.invocation,
            UnitFileState='enabled', Transient='no', NeedDaemonReload='no',
            ExecMainStartTimestampMonotonic='1234567',
            MainPID=str(self.main_pid), ExecMainPID=str(self.main_pid),
            User='1201', Group='1201',
            ExecStart='{ path=%s ; argv[]=%s --run benign ; ignore_errors=no ; status=0 }'
            % (self.payload_path, self.payload_path),
            ControlGroup='/system.slice/maltrace-boot.service')
        self.show_outputs = [None, None]
        self.process_births = [self.birth, self.birth]
        self.kernel = None
        self.peer = (1, 0, 0)
        self.manager_identity_value = dict(
            pid=1, birth='42', uids=[0] * 4, gids=[0] * 4,
            image='/usr/lib/systemd/systemd', image_sha256=boot.sha(b'systemd'),
            parent_pid=0, groups=[0], device=0, inode=0,
            cgroup='0::/init.scope', cmdline=['/usr/lib/systemd/systemd'])
        self.process_value = None
        self.manager = FakeManager(self.peer)
        self.clock = itertools.count(1_000_000_000, 100_000_000)

    def profile(self, **overrides):
        value = dict(unit_name='maltrace-boot.service',
                     vm_uuid='289e4d56-ebaf-5147-96ba-40dfc2a942a3',
                     boot_id='4cbc7164-7e74-4164-a43e-41885fdd74f5',
                     expected_uid=1201,
                     payload_path=str(self.payload_path),
                     fragment_path=str(self.fragment_path),
                     payload_sha256=boot.sha(self.payload_bytes),
                     fragment_sha256=boot.sha(self.fragment_text.encode()),
                     window_seconds=30)
        value.update(overrides)
        return value

    def show_text(self, which=0):
        override = self.show_outputs[which]
        properties = dict(self.properties)
        if override:
            properties.update(override)
        return ''.join('%s=%s\n' % item for item in sorted(properties.items()))

    def facts(self, birth=None):
        birth = birth or self.birth
        return dict(pid=self.main_pid, birth=birth, parent_pid=1,
                    uids=[1201] * 4, gids=[1201] * 4, groups=[1201],
                    image=str(self.payload_path),
                    image_sha256=boot.sha(self.payload_bytes),
                    device=2049, inode=999999,
                    cgroup='0::/system.slice/maltrace-boot.service',
                    cmdline=[str(self.payload_path), '--run', 'benign'])

    def run_command(self, argv, timeout):
        if argv == boot.show_argv('maltrace-boot.service'):
            which = 0 if self.show_outputs[0] is not None \
                or self.show_outputs[1] is None else 0
            return {'argv': list(argv), 'rc': 0,
                    'stdout': self.show_text(0), 'stderr': ''}
        if argv == boot.cat_argv('maltrace-boot.service'):
            return {'argv': list(argv), 'rc': 0,
                    'stdout': '# %s\n%s' % (self.properties['FragmentPath'],
                                            self.fragment_text), 'stderr': ''}
        raise AssertionError('unexpected native command %r' % (argv,))

    def patch(self, test):
        kernel = self.kernel or dict(
            boot_id=self.profile()['boot_id'],
            vm_uuid=self.profile()['vm_uuid'], reads={})
        show_calls = [0]

        def run_command(argv, timeout):
            if argv == boot.show_argv('maltrace-boot.service'):
                which = min(show_calls[0], 1)
                show_calls[0] += 1
                override = self.show_outputs[which]
                properties = dict(self.properties)
                if override:
                    properties.update(override)
                return {'argv': list(argv), 'rc': 0,
                        'stdout': ''.join('%s=%s\n' % item for item
                                          in sorted(properties.items())),
                        'stderr': ''}
            if argv == boot.cat_argv('maltrace-boot.service'):
                return self.run_command(argv, timeout)
            raise AssertionError('unexpected native command %r' % (argv,))

        process_calls = [0]

        def process_identity(pid):
            index = min(process_calls[0], len(self.process_births) - 1)
            process_calls[0] += 1
            birth = self.process_births[index]
            if isinstance(birth, Exception):
                raise birth
            return self.facts(birth)

        patches = [
            mock.patch.object(boot, 'read_kernel_identity',
                              mock.Mock(return_value=kernel)),
            mock.patch.object(boot, 'manager_identity',
                              mock.Mock(return_value=copy.deepcopy(
                                  self.manager_identity_value))),
            mock.patch.object(boot, 'open_manager',
                              mock.Mock(return_value=self.manager)),
            mock.patch.object(boot, 'run_command', mock.Mock(
                side_effect=run_command)),
            mock.patch.object(boot, 'process_identity', mock.Mock(
                side_effect=process_identity)),
            mock.patch.object(boot, 'read_exe',
                              mock.Mock(return_value=self.payload_bytes)),
            mock.patch.object(boot, '_now_mono',
                              mock.Mock(side_effect=lambda: next(self.clock))),
        ]
        for patch in patches:
            patch.start()
            test.addCleanup(patch.stop)

    def output(self, name):
        path = self.root / name
        need_dir = self.root / (name + '-parent')
        need_dir.mkdir(exist_ok=True)
        return path

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


class BootServiceCollectorTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Harness()
        self.addCleanup(self.fixture.cleanup)

    def collect(self, output_name=None, profile=None):
        self._collect_seq = getattr(self, '_collect_seq', 0) + 1
        output_name = output_name or ('out-%d' % self._collect_seq)
        output = self.fixture.root / (output_name + '-parent') / output_name
        output.parent.mkdir(exist_ok=True)
        return boot.collect_boot_service(
            profile or self.fixture.profile(), output)

    def test_success_ignores_payload_self_description(self):
        self.fixture.patch(self)
        observation, bundle = self.collect()
        self.assertEqual(observation['schema'], boot.SOURCE)
        self.assertEqual(observation['kind'], 'boot-service-observation')
        self.assertEqual(observation['actor']['pid'], self.fixture.main_pid)
        self.assertEqual(observation['actor']['uid'], 1201)
        self.assertEqual(observation['actor']['birth'], self.fixture.birth)
        self.assertEqual(observation['boot_id'],
                         self.fixture.profile()['boot_id'])
        self.assertNotIn(observation['boot_id'],
                         self.fixture.payload_bytes.decode())
        self.assertNotIn('verified', observation)
        self.assertNotIn('source_nature', observation)
        self.assertIn('prior author/installation origin not proven',
                      ' '.join(observation['limitations']))
        self.assertTrue(self.fixture.manager.closed)
        # decoder re-derives the same observation from the sealed directory
        decoded = boot.normalize_boot_service(
            bundle['output'], self.fixture.profile())
        self.assertEqual(decoded, observation)
        again = boot.normalize_boot_service(
            dict(records=self.records_of(bundle)), self.fixture.profile())
        self.assertEqual(again, observation)

    def records_of(self, bundle):
        return [json.loads(line) for line in
                Path(bundle['output'], 'raw.ndjson').read_text().splitlines()
                if line.strip()]

    def test_decoder_detects_same_byte_replacement_and_tampering(self):
        self.fixture.patch(self)
        # a copied directory is a different directory object entirely
        observation, bundle = self.collect()
        output = Path(bundle['output'])
        copied = output.parent / 'copy'
        shutil.copytree(output, copied)
        with self.assertRaisesRegex(ValueError, 'output replaced'):
            boot.normalize_boot_service(copied, self.fixture.profile())
        # tampered bytes with the inode kept fail the hash check
        os.chmod(output / 'observation.json', 0o600)
        (output / 'observation.json').write_text('tampered')
        os.chmod(output / 'observation.json', 0o400)
        with self.assertRaisesRegex(ValueError, 'raw hash mismatch'):
            boot.normalize_boot_service(output, self.fixture.profile())
        # a missing manifest is a missing original
        _, bundle2 = self.collect()
        output2 = Path(bundle2['output'])
        os.chmod(output2 / 'manifest.json', 0o600)
        (output2 / 'manifest.json').unlink()
        with self.assertRaisesRegex(ValueError, 'raw missing'):
            boot.normalize_boot_service(output2, self.fixture.profile())
        # same bytes in a new inode are still a replacement
        _, bundle3 = self.collect()
        output3 = Path(bundle3['output'])
        raw_path = output3 / 'raw.ndjson'
        same_bytes = raw_path.read_bytes()
        os.chmod(raw_path, 0o600)
        raw_path.unlink()
        raw_path.write_bytes(same_bytes)
        os.chmod(raw_path, 0o400)
        with self.assertRaisesRegex(ValueError,
                                    'original replaced with same bytes'):
            boot.normalize_boot_service(output3, self.fixture.profile())

    def test_wrong_boot_wrong_vm_and_reversed_expectation(self):
        self.fixture.patch(self)
        profile = self.fixture.profile()
        with mock.patch.object(boot, 'read_kernel_identity',
                               mock.Mock(return_value=dict(
                                   boot_id=str(uuid.uuid4()),
                                   vm_uuid=profile['vm_uuid'], reads={}))):
            with self.assertRaisesRegex(ValueError, 'wrong boot identity'):
                self.collect(profile=profile)
        with mock.patch.object(boot, 'read_kernel_identity',
                               mock.Mock(return_value=dict(
                                   boot_id=profile['boot_id'],
                                   vm_uuid=str(uuid.uuid4()), reads={}))):
            with self.assertRaisesRegex(ValueError, 'wrong vm identity'):
                self.collect(profile=profile)

    def test_foreign_peer_and_non_pid1_manager(self):
        self.fixture.peer = (901, 0, 0)
        self.fixture.manager = FakeManager(self.fixture.peer)
        self.fixture.patch(self)
        with self.assertRaisesRegex(ValueError, 'foreign manager peer'):
            self.collect()
        self.setUp()
        self.fixture.manager_identity_value = dict(
            self.fixture.manager_identity_value, pid=901)
        self.fixture.patch(self)
        with self.assertRaisesRegex(ValueError, 'manager not pid1 root'):
            self.collect()

    def test_pid_reuse_and_exit_during_read_leave_partial_evidence_only(self):
        self.fixture.patch(self)
        self.fixture.process_births = [self.fixture.birth, '999999']
        output = self.fixture.root / 'p1' / 'out'
        output.parent.mkdir(exist_ok=True)
        with self.assertRaisesRegex(ValueError, 'pid reused or replaced'):
            boot.collect_boot_service(self.fixture.profile(), output)
        self.assertTrue((output / 'raw.ndjson').is_file())
        self.assertFalse((output / 'observation.json').exists())
        self.assertFalse((output / 'manifest.json').exists())
        rows = [json.loads(line) for line in
                (output / 'raw.ndjson').read_text().splitlines() if line.strip()]
        self.assertEqual(rows[-1]['kind'], 'collection-error')
        self.assertTrue(self.fixture.manager.closed)

        self.setUp()
        self.fixture.patch(self)
        self.fixture.process_births = [self.fixture.birth,
                                       FileNotFoundError('gone')]
        output = self.fixture.root / 'p2' / 'out'
        output.parent.mkdir(exist_ok=True)
        with self.assertRaisesRegex(FileNotFoundError, 'gone'):
            boot.collect_boot_service(self.fixture.profile(), output)
        rows = [json.loads(line) for line in
                (output / 'raw.ndjson').read_text().splitlines() if line.strip()]
        self.assertEqual(rows[-1]['kind'], 'collection-error')
        self.assertFalse((output / 'observation.json').exists())

    def test_uid_conflicts_refused(self):
        for uids in ([0] * 4, [1300] * 4, [1201, 0, 1201, 1201]):
            with self.subTest(uids=uids):
                fixture = Harness()
                self.addCleanup(fixture.cleanup)
                fixture.patch(self)
                original_facts = fixture.facts
                fixture.facts = lambda birth=None, u=uids: dict(
                    original_facts(birth), uids=u, gids=u)
                output = fixture.root / ('uid-%r-parent' % (uids,)) / 'out'
                output.parent.mkdir(exist_ok=True)
                with self.assertRaisesRegex(
                        ValueError,
                        'uid mismatch|root identity refused'):
                    boot.collect_boot_service(fixture.profile(), output)

    def test_invocation_and_mainpid_changes_refused(self):
        self.fixture.patch(self)
        self.fixture.show_outputs = [None, dict(InvocationID='b' * 32)]
        with self.assertRaisesRegex(ValueError, 'invocation changed'):
            self.collect()
        self.setUp()
        self.fixture.patch(self)
        self.fixture.show_outputs = [None, dict(MainPID='5252')]
        with self.assertRaisesRegex(ValueError, 'main pid changed'):
            self.collect()

    def test_fragment_and_loaded_definition_conflicts(self):
        cases = [
            (dict(FragmentPath='/run/systemd/system/maltrace-boot.service'),
             'runtime fragment refused'),
            (dict(FragmentPath='/var/tmp/other.service'), 'fragment path conflict'),
            (dict(UnitFileState='disabled'), 'unit not enabled'),
            (dict(Transient='yes'), 'transient unit refused'),
            (dict(NeedDaemonReload='yes'), 'daemon reload pending'),
            (dict(DropInPaths='/etc/systemd/system/maltrace-boot.service.d/o.conf'),
             'drop-ins unbound'),
            (dict(User='0'), 'loaded User mismatch'),
            (dict(ExecStart='{ path=/usr/bin/other ; argv[]=/usr/bin/other }'),
             'loaded ExecStart mismatch'),
            (dict(LoadState='not-found'), 'unit not loaded'),
            (dict(ActiveState='inactive'), 'unit not active'),
            (dict(SubState='exited'), 'unit substate not running'),
        ]
        for override, code in cases:
            with self.subTest(override=override, code=code):
                fixture = Harness()
                self.addCleanup(fixture.cleanup)
                fixture.patch(self)
                fixture.show_outputs = [override, override]
                output = fixture.root / 'frag' / 'out'
                output.parent.mkdir(exist_ok=True)
                with self.assertRaisesRegex(ValueError, code):
                    boot.collect_boot_service(fixture.profile(), output)

    def test_profile_hash_and_execstart_binding_refused(self):
        self.fixture.patch(self)
        with self.assertRaisesRegex(ValueError, 'fragment hash mismatch'):
            self.collect(profile=self.fixture.profile(
                fragment_sha256=boot.sha(b'other')))
        with self.assertRaisesRegex(ValueError, 'payload hash mismatch'):
            self.collect(profile=self.fixture.profile(
                payload_sha256=boot.sha(b'other')))
        fragment = self.fixture.fragment_path
        text = self.fragment_text_without_user()
        fragment.write_text(text)
        with self.assertRaisesRegex(ValueError,
                                    'fragment User mismatch|ordinary User'):
            self.collect(profile=self.fixture.profile(
                fragment_sha256=boot.sha(text.encode())))
        other = self.fixture.root / 'other-payload'
        other.write_bytes(b'other benign payload\n')
        text2 = FRAGMENT_TEXT.format(payload=other)
        self.fixture.fragment_path.write_text(text2)
        with self.assertRaisesRegex(ValueError,
                                    'does not bind payload'):
            self.collect(profile=self.fixture.profile(
                fragment_sha256=boot.sha(text2.encode())))

    def fragment_text_without_user(self):
        return self.fixture.fragment_text.replace('User=1201\n', 'User=0\n')

    def test_profile_validation_rejects_caller_supplied_identity(self):
        base = self.fixture.profile()
        for change in (
                lambda profile: profile.update(verified=True),
                lambda profile: profile.update(source_nature='real'),
                lambda profile: profile.update(pid=1234),
                lambda profile: profile.update(birth='7'),
                lambda profile: profile.update(invocation_id='a' * 32),
                lambda profile: profile.pop('window_seconds'),
                lambda profile: profile.update(window_seconds=31),
                lambda profile: profile.update(window_seconds=True),
                lambda profile: profile.update(expected_uid=0),
                lambda profile: profile.update(expected_uid=True),
                lambda profile: profile.update(
                    payload_path=self.fixture.fragment_path),
                lambda profile: profile.update(vm_uuid='NOT-A-UUID'),
                lambda profile: profile.update(unit_name='../escape.service'),
        ):
            profile = copy.deepcopy(base)
            change(profile)
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    boot.validate_profile(profile)
        self.assertTrue(boot.validate_profile(copy.deepcopy(base)))

    def test_window_bound_enforced_on_recorded_evidence(self):
        self.fixture.patch(self)
        self.fixture.clock = itertools.count(1_000_000_000, 4_000_000_000)
        output = self.fixture.root / 'win' / 'out'
        output.parent.mkdir(exist_ok=True)
        with self.assertRaisesRegex(ValueError, 'window exceeded'):
            boot.collect_boot_service(self.fixture.profile(), output)

    def test_decoder_rejects_mutated_record_sequences(self):
        self.fixture.patch(self)
        observation, bundle = self.collect()
        records = self.records_of(bundle)
        profile = self.fixture.profile()
        boot.normalize_boot_service(dict(records=records), profile)
        for mutation, code in (
                (lambda rows: rows.pop(3), 'raw record sequence'),
                (lambda rows: rows[1].update(
                    value=dict(rows[1]['value'],
                               boot_id=str(uuid.uuid4()))),
                 'wrong boot identity'),
                (lambda rows: rows[2].update(peer=[901, 0, 0]),
                 'foreign manager peer'),
                (lambda rows: rows[7].update(pid=5252),
                 'observed pid is not the main pid'),
                (lambda rows: rows[8].update(InvocationID='c' * 32),
                 'invocation changed'),
                (lambda rows: rows[5].update(sha256=boot.sha(b'x')),
                 'fragment hash mismatch'),
                (lambda rows: rows[6].update(device=999), None),
                (lambda rows: rows[7]['value'].update(
                    cgroup='0::/user.slice/other'), 'cgroup mismatch'),
        ):
            mutated = copy.deepcopy(records)
            mutation(mutated)
            with self.subTest(code=code):
                with self.assertRaises(ValueError):
                    boot.normalize_boot_service(dict(records=mutated), profile)

    def test_fragment_link_binding_core(self):
        link_parent = self.fixture.root / 'units'
        link_parent.mkdir()
        os.chmod(link_parent, 0o755)
        original = self.fixture.root / 'original.service'
        original.write_text('[Unit]\n')
        link = link_parent / 'linked.service'
        os.symlink(original, link)
        owner = os.getuid()
        binding = boot.validate_fragment_link(link, original, owner)
        self.assertEqual(binding['link_target'], str(original))
        for change, code in (
                (lambda: os.symlink(self.fixture.root / 'nowhere', link),
                 'escapes or unbound'),
        ):
            pass
        foreign = link_parent / 'foreign.service'
        os.symlink(self.fixture.root, foreign)
        with self.assertRaisesRegex(ValueError, 'escapes or unbound'):
            boot.validate_fragment_link(foreign, original, owner)
        with self.assertRaisesRegex(ValueError, 'unprotected fragment parent'):
            boot.validate_fragment_link(link, original, owner + 12345)
        plain = link_parent / 'plain.service'
        plain.write_text('x')
        with self.assertRaisesRegex(ValueError, 'fragment link not protected'):
            boot.validate_fragment_link(plain, original, owner)

    def test_exec_image_must_match_payload_bytes(self):
        self.fixture.patch(self)
        with mock.patch.object(
                boot, 'read_exe',
                mock.Mock(return_value=b'different image bytes')):
            with self.assertRaisesRegex(ValueError, 'exec image hash mismatch'):
                self.collect()
        self.setUp()
        self.fixture.patch(self)
        with mock.patch.object(boot, 'process_identity', mock.Mock(
                return_value=dict(self.fixture.facts(),
                                  image='/usr/bin/other'))):
            with self.assertRaisesRegex(ValueError, 'exec image mismatch'):
                self.collect()


if __name__ == '__main__':
    unittest.main()
