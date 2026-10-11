"""Local mocks of the native read boundary for the boot-service producer.

No VM, no real systemd private socket, no network and no sample execution:
every native seam is replaced with auditable static benign bytes and
temporary directories. Payload self-description must never be adopted; the
observation is derived only from the mocked manager/proc/kernel reads, and
the decoder replays only from the sealed originals.
"""
import base64
import copy
import itertools
import json
import os
import shutil
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
        self.root = Path(os.environ.get('BOOT_SERVICE_TMPDIR', None)
                         or __import__('tempfile').mkdtemp(
                             prefix='boot-service-fixture-'))
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
        self.process_facts = [None, None]
        self.kernel = None
        self.peer = (1, 0, 0)
        self.manager_identity_value = dict(
            pid=1, birth='42', uids=[0] * 4, gids=[0] * 4,
            image='/usr/lib/systemd/systemd', image_sha256=boot.sha(b'systemd'),
            parent_pid=0, groups=[0], device=0, inode=0,
            cgroup='0::/init.scope', cmdline=['/usr/lib/systemd/systemd'])
        self.manager = FakeManager(self.peer)
        self.clock = itertools.count(1_000_000_000, 100_000_000)
        self.sealed = False

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

    def facts(self, birth=None):
        birth = birth or self.birth
        return dict(pid=self.main_pid, birth=birth, parent_pid=1,
                    uids=[1201] * 4, gids=[1201] * 4, groups=[1201],
                    image=str(self.payload_path),
                    image_sha256=boot.sha(self.payload_bytes),
                    device=2049, inode=999999,
                    cgroup='0::/system.slice/maltrace-boot.service',
                    cmdline=[str(self.payload_path), '--run', 'benign'])

    def patch(self, test):
        kernel = self.kernel or dict(
            boot_id=self.profile()['boot_id'],
            vm_uuid=self.profile()['vm_uuid'], reads={})
        show_calls = [0]
        process_calls = [0]
        fixture = self

        def blocked(*args, **kwargs):
            raise AssertionError('native reads are sealed after export')

        def run_command(argv, timeout):
            if fixture.sealed:
                raise AssertionError('native reads are sealed after export')
            if argv == boot.show_argv('maltrace-boot.service'):
                which = min(show_calls[0], 1)
                show_calls[0] += 1
                properties = dict(fixture.properties)
                override = fixture.show_outputs[which]
                if override:
                    properties.update(override)
                return {'argv': list(argv), 'rc': 0,
                        'stdout': ''.join('%s=%s\n' % item for item
                                          in sorted(properties.items())),
                        'stderr': ''}
            if argv == boot.cat_argv('maltrace-boot.service'):
                return {'argv': list(argv), 'rc': 0,
                        'stdout': '# %s\n%s' % (
                            fixture.properties['FragmentPath'],
                            fixture.fragment_text), 'stderr': ''}
            raise AssertionError('unexpected native command %r' % (argv,))

        def process_identity(pid):
            if fixture.sealed:
                raise AssertionError('native reads are sealed after export')
            index = min(process_calls[0], 1)
            process_calls[0] += 1
            facts = fixture.process_facts[index] or fixture.facts()
            if isinstance(facts, Exception):
                raise facts
            return copy.deepcopy(facts)

        patches = [
            mock.patch.object(boot, 'read_kernel_identity',
                              mock.Mock(return_value=kernel)),
            mock.patch.object(boot, 'manager_identity',
                              mock.Mock(return_value=copy.deepcopy(
                                  fixture.manager_identity_value))),
            mock.patch.object(boot, 'open_manager',
                              mock.Mock(return_value=fixture.manager)),
            mock.patch.object(boot, 'run_command',
                              mock.Mock(side_effect=run_command)),
            mock.patch.object(boot, 'process_identity', mock.Mock(
                side_effect=process_identity)),
            mock.patch.object(boot, 'read_exe',
                              mock.Mock(return_value=fixture.payload_bytes)),
            mock.patch.object(boot, '_now_mono',
                              mock.Mock(side_effect=lambda: next(fixture.clock))),
        ]
        for patch in patches:
            patch.start()
            test.addCleanup(patch.stop)

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

    def records_of(self, bundle):
        return [json.loads(line) for line in
                Path(bundle['output'], 'raw.ndjson').read_text().splitlines()
                if line.strip()]

    # -- success ----------------------------------------------------------
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
        decoded = boot.normalize_boot_service(
            bundle['output'], self.fixture.profile())
        self.assertEqual(decoded, observation)
        records = self.records_of(bundle)
        self.assertEqual([r['kind'] for r in records],
                         boot.RECORD_SEQUENCE)
        marked = boot.normalize_boot_service(
            dict(records=records), self.fixture.profile())
        self.assertEqual(marked['decode_trust'], 'fixture-records-only')
        del marked['decode_trust']
        self.assertEqual(marked['limitations'][-1],
                         'decoded from in-memory records; not the sealed '
                         'original channel')
        trimmed = dict(marked, limitations=observation['limitations'])
        self.assertEqual(trimmed, observation)

    def test_decoder_detects_same_byte_replacement_and_tampering(self):
        self.fixture.patch(self)
        observation, bundle = self.collect()
        output = Path(bundle['output'])
        copied = output.parent / 'copy'
        shutil.copytree(output, copied)
        with self.assertRaisesRegex(ValueError, 'output replaced'):
            boot.normalize_boot_service(copied, self.fixture.profile())
        os.chmod(output / 'observation.json', 0o600)
        (output / 'observation.json').write_text('tampered')
        os.chmod(output / 'observation.json', 0o400)
        with self.assertRaisesRegex(ValueError,
                                    'raw size mismatch|raw hash mismatch'):
            boot.normalize_boot_service(output, self.fixture.profile())
        _, bundle2 = self.collect()
        output2 = Path(bundle2['output'])
        os.chmod(output2 / 'manifest.json', 0o600)
        (output2 / 'manifest.json').unlink()
        with self.assertRaisesRegex(ValueError, 'raw missing'):
            boot.normalize_boot_service(output2, self.fixture.profile())
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
        _, bundle4 = self.collect()
        output4 = Path(bundle4['output'])
        os.chmod(output4 / 'raw.ndjson', 0o600)
        with self.assertRaisesRegex(ValueError, 'raw protection changed'):
            boot.normalize_boot_service(output4, self.fixture.profile())

    # -- identity ---------------------------------------------------------
    def test_wrong_boot_wrong_vm(self):
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

    # -- process drift ----------------------------------------------------
    def test_recheck_process_drift_refused(self):
        for field, value in (('uids', [0] * 4), ('gids', [0] * 4),
                             ('image', '/usr/bin/other'),
                             ('image_sha256', boot.sha(b'other')),
                             ('inode', 12345), ('device', 1),
                             ('cgroup', '0::/other.slice/x'),
                             ('cmdline', ['/usr/bin/other'])):
            with self.subTest(field=field):
                fixture = Harness()
                self.addCleanup(fixture.cleanup)
                fixture.patch(self)
                second = dict(fixture.facts())
                second[field] = value
                fixture.process_facts = [fixture.facts(), second]
                output = fixture.root / ('drift-%s' % field) / 'out'
                output.parent.mkdir(exist_ok=True)
                with self.assertRaisesRegex(ValueError,
                                            'process identity drifted'):
                    boot.collect_boot_service(fixture.profile(), output)
                self.assertFalse((output / 'observation.json').exists())
                self.assertFalse((output / 'manifest.json').exists())

    def test_process_exit_during_read_leaves_partial_evidence_only(self):
        self.fixture.patch(self)
        self.fixture.process_facts = [self.fixture.facts(),
                                      FileNotFoundError('gone')]
        output = self.fixture.root / 'p2' / 'out'
        output.parent.mkdir(exist_ok=True)
        with self.assertRaisesRegex(FileNotFoundError, 'gone'):
            boot.collect_boot_service(self.fixture.profile(), output)
        rows = [json.loads(line) for line in
                (output / 'raw.ndjson').read_text().splitlines() if line.strip()]
        self.assertEqual(rows[-1]['kind'], 'collection-error')
        self.assertFalse((output / 'observation.json').exists())
        self.assertTrue(self.fixture.manager.closed)

    def test_uid_conflicts_refused(self):
        for uids in ([0] * 4, [1300] * 4, [1201, 0, 1201, 1201]):
            with self.subTest(uids=uids):
                fixture = Harness()
                self.addCleanup(fixture.cleanup)
                fixture.patch(self)
                facts = fixture.facts()
                facts.update(uids=uids, gids=uids)
                fixture.process_facts = [facts, copy.deepcopy(facts)]
                output = fixture.root / ('uid-%r-parent' % (uids,)) / 'out'
                output.parent.mkdir(exist_ok=True)
                with self.assertRaisesRegex(
                        ValueError, 'uid mismatch|root identity refused'):
                    boot.collect_boot_service(fixture.profile(), output)

    # -- unit recheck -----------------------------------------------------
    def test_unit_recheck_drift_refused(self):
        for field, value in (('InvocationID', 'b' * 32), ('MainPID', '5252'),
                             ('User', '0'), ('ExecStart', '{ path=/o }'),
                             ('FragmentPath', '/etc/systemd/system/other'),
                             ('ActiveState', 'inactive')):
            with self.subTest(field=field):
                fixture = Harness()
                self.addCleanup(fixture.cleanup)
                fixture.patch(self)
                fixture.show_outputs = [None, {field: value}]
                output = fixture.root / ('show2-%s' % field) / 'out'
                output.parent.mkdir(exist_ok=True)
                with self.assertRaisesRegex(ValueError,
                                            'unit recheck drifted'):
                    boot.collect_boot_service(fixture.profile(), output)

    # -- cgroup binding ---------------------------------------------------
    def test_near_cgroup_and_manager_disagreement_refused(self):
        for cgroup, code in (
                ('0::/system.slice/maltrace-boot.service-foreign',
                 'cgroup does not bind the unit'),
                ('0::/system.slice/maltrace-boot.service.d/x',
                 'cgroup does not bind the unit'),
                ('0::/user.slice/maltrace-boot.service',
                 'manager ControlGroup disagrees')):
            with self.subTest(cgroup=cgroup):
                fixture = Harness()
                self.addCleanup(fixture.cleanup)
                fixture.patch(self)
                facts = fixture.facts()
                facts['cgroup'] = cgroup
                fixture.process_facts = [facts, copy.deepcopy(facts)]
                output = fixture.root / 'cg' / 'out'
                output.parent.mkdir(exist_ok=True)
                with self.assertRaisesRegex(ValueError, code):
                    boot.collect_boot_service(fixture.profile(), output)

    def test_manager_control_group_must_agree(self):
        self.fixture.patch(self)
        override = dict(ControlGroup='/system.slice/other.service')
        self.fixture.show_outputs = [override, override]
        with self.assertRaisesRegex(ValueError,
                                    'manager ControlGroup disagrees'):
            self.collect()

    # -- runtime fragment -------------------------------------------------
    def test_direct_runtime_fragment_refused(self):
        self.fixture.patch(self)
        original = boot.stable_file_read
        runtime_fragment = '/run/systemd/system/maltrace-boot.service'
        profile = self.fixture.profile(fragment_path=runtime_fragment,
                                       fragment_sha256=boot.sha(
                                           self.fixture.fragment_text.encode()))

        def read(path):
            if path == runtime_fragment:
                return dict(original(self.fixture.fragment_path),
                            path=path)
            return original(path)

        with mock.patch.object(boot, 'stable_file_read', side_effect=read):
            self.fixture.properties['FragmentPath'] = runtime_fragment
            with self.assertRaisesRegex(ValueError, 'runtime fragment'):
                self.collect(profile=profile)
        self.setUp()
        self.fixture.patch(self)
        self.fixture.properties['FragmentPath'] = \
            '/run/systemd/system/maltrace-boot.service'
        with self.assertRaisesRegex(ValueError, 'runtime fragment refused'):
            self.collect()

    # -- raw exe bytes ----------------------------------------------------
    def test_decoder_rejects_exe_bytes_conflict(self):
        self.fixture.patch(self)
        observation, bundle = self.collect()
        records = self.records_of(bundle)
        profile = self.fixture.profile()
        mutated = copy.deepcopy(records)
        mutated[7]['exe_read_sha256'] = boot.sha(b'different')
        with self.assertRaisesRegex(ValueError, 'exec image hash mismatch'):
            boot.normalize_boot_service(dict(records=mutated), profile)
        mutated2 = copy.deepcopy(records)
        mutated2[7]['exe_read_content'] = base64.b64encode(b'other').decode()
        with self.assertRaisesRegex(ValueError,
                                    'exe read bytes contradict hash'):
            boot.normalize_boot_service(dict(records=mutated2), profile)
        mutated3 = copy.deepcopy(records)
        mutated3[7]['exe_read_size'] = 7
        with self.assertRaisesRegex(ValueError,
                                    'exec image size mismatch'):
            boot.normalize_boot_service(dict(records=mutated3), profile)

    def test_exec_image_must_match_payload_bytes(self):
        self.fixture.patch(self)
        with mock.patch.object(
                boot, 'read_exe',
                mock.Mock(return_value=b'different image bytes')):
            with self.assertRaisesRegex(ValueError, 'exec image hash mismatch'):
                self.collect()
        self.setUp()
        self.fixture.patch(self)
        facts = self.fixture.facts()
        facts['image'] = '/usr/bin/other'
        self.fixture.process_facts = [facts, copy.deepcopy(facts)]
        with self.assertRaisesRegex(ValueError, 'exec image mismatch'):
            self.collect()

    def test_oversized_evidence_file_refused_explicitly(self):
        self.fixture.patch(self)
        big = self.fixture.root / 'big-payload'
        big.write_bytes(b'x' * (boot.INLINE_LIMIT + 1))
        text = FRAGMENT_TEXT.format(payload=big)
        fragment = self.fixture.root / 'big.service'
        fragment.write_text(text)
        self.fixture.properties['FragmentPath'] = str(fragment)
        self.fixture.properties['ExecStart'] = (
            '{ path=%s ; argv[]=%s --run benign ; ignore_errors=no ; status=0 }'
            % (big, big))
        profile = self.fixture.profile(
            payload_path=str(big), fragment_path=str(fragment),
            payload_sha256=boot.sha(big.read_bytes()),
            fragment_sha256=boot.sha(text.encode()))
        with self.assertRaisesRegex(ValueError,
                                    'evidence file exceeds bounded inline size'):
            self.collect(profile=profile)

    # -- monotonic --------------------------------------------------------
    def test_decoder_rejects_reversed_or_invalid_monotonic(self):
        self.fixture.patch(self)
        observation, bundle = self.collect()
        records = self.records_of(bundle)
        profile = self.fixture.profile()
        mutated = copy.deepcopy(records)
        mutated[-1]['monotonic_ns'] = mutated[0]['monotonic_ns'] - 1
        with self.assertRaisesRegex(ValueError,
                                    'monotonic time moved backwards'):
            boot.normalize_boot_service(dict(records=mutated), profile)
        mutated2 = copy.deepcopy(records)
        mutated2[4]['monotonic_ns'] = mutated2[3]['monotonic_ns'] - 1
        with self.assertRaisesRegex(ValueError,
                                    'monotonic time moved backwards'):
            boot.normalize_boot_service(dict(records=mutated2), profile)
        for bad in (None, True, '12', -5):
            mutated3 = copy.deepcopy(records)
            mutated3[2]['monotonic_ns'] = bad
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(ValueError,
                                            'monotonic time missing or invalid'):
                    boot.normalize_boot_service(dict(records=mutated3), profile)

    def test_window_bound_enforced_on_recorded_evidence(self):
        self.fixture.patch(self)
        self.fixture.clock = itertools.count(1_000_000_000, 4_000_000_000)
        output = self.fixture.root / 'win' / 'out'
        output.parent.mkdir(exist_ok=True)
        with self.assertRaisesRegex(ValueError, 'window exceeded'):
            boot.collect_boot_service(self.fixture.profile(), output)

    # -- manifest inventory -----------------------------------------------
    def test_manifest_inventory_must_be_exact(self):
        self.fixture.patch(self)
        observation, bundle = self.collect()
        output = Path(bundle['output'])
        os.chmod(output / 'manifest.json', 0o600)
        manifest = json.loads((output / 'manifest.json').read_text())
        manifest['files'] = {}
        (output / 'manifest.json').write_text(json.dumps(manifest))
        os.chmod(output / 'manifest.json', 0o400)
        with self.assertRaisesRegex(ValueError, 'manifest inventory'):
            boot.normalize_boot_service(output, self.fixture.profile())
        _, bundle2 = self.collect()
        output2 = Path(bundle2['output'])
        (output2 / 'extra.txt').write_text('x')
        with self.assertRaisesRegex(ValueError, 'manifest inventory'):
            boot.normalize_boot_service(output2, self.fixture.profile())
        _, bundle3 = self.collect()
        output3 = Path(bundle3['output'])
        os.chmod(output3 / 'manifest.json', 0o600)
        manifest3 = json.loads((output3 / 'manifest.json').read_text())
        del manifest3['files']['observation.json']
        (output3 / 'manifest.json').write_text(json.dumps(manifest3))
        os.chmod(output3 / 'manifest.json', 0o400)
        with self.assertRaisesRegex(ValueError, 'manifest inventory'):
            boot.normalize_boot_service(output3, self.fixture.profile())

    # -- fragment binding -------------------------------------------------
    def test_etc_link_positive_and_sealed_replay(self):
        fixture = Harness()
        self.addCleanup(fixture.cleanup)
        units = fixture.root / 'etc-systemd-system'
        units.mkdir()
        os.chmod(units, 0o755)
        link = units / 'maltrace-boot.service'
        os.symlink(fixture.fragment_path, link)
        fixture.properties['FragmentPath'] = str(link)
        fixture.patch(self)
        owner = os.getuid()
        (fixture.root / 'link').mkdir(exist_ok=True)
        with mock.patch.object(boot, 'ETC_UNITS', units), \
                mock.patch.object(boot, 'FRAGMENT_PARENTS', (units,)), \
                mock.patch.object(boot, 'FRAGMENT_LINK_OWNER', owner):
            observation, bundle = boot.collect_boot_service(
                fixture.profile(), fixture.root / 'link' / 'out')
        self.assertIsNotNone(observation['unit']['fragment_binding'])
        self.assertEqual(observation['unit']['fragment_binding']['link_target'],
                         str(fixture.fragment_path))
        # after export, seal every native read: the decoder must still
        # re-derive the observation from the sealed originals alone
        fixture.sealed = True
        decoded = boot.normalize_boot_service(bundle['output'],
                                              fixture.profile())
        self.assertEqual(decoded, observation)
        records = self.records_of(bundle)
        for mutation, code in (
                (lambda binding: binding.update(link_target='/foreign'),
                 'escapes or unbound'),
                (lambda binding: binding.update(link_uid=owner + 999),
                 'fragment link not protected'),
                (lambda binding: binding.update(target_inode=1),
                 'does not pin the original'),
                (lambda binding: binding.clear(),
                 'fragment binding link path mismatch'),
                (lambda binding: None, 'binding evidence missing'),
        ):
            mutated = copy.deepcopy(records)
            if code == 'binding evidence missing':
                mutated[5]['binding'] = None
            else:
                mutation(mutated[5]['binding'])
            with self.subTest(code=code):
                with self.assertRaisesRegex(ValueError, code):
                    boot.normalize_boot_service(dict(records=mutated),
                                                fixture.profile())

    # -- profile ----------------------------------------------------------
    def test_profile_hash_and_execstart_binding_refused(self):
        self.fixture.patch(self)
        with self.assertRaisesRegex(ValueError, 'fragment hash mismatch'):
            self.collect(profile=self.fixture.profile(
                fragment_sha256=boot.sha(b'other')))
        with self.assertRaisesRegex(ValueError, 'payload hash mismatch'):
            self.collect(profile=self.fixture.profile(
                payload_sha256=boot.sha(b'other')))
        fragment = self.fixture.fragment_path
        text = FRAGMENT_TEXT.format(payload=self.fixture.payload_path) \
            .replace('User=1201\n', 'User=0\n')
        fragment.write_text(text)
        with self.assertRaisesRegex(ValueError,
                                    'fragment User mismatch|ordinary User'):
            self.collect(profile=self.fixture.profile(
                fragment_sha256=boot.sha(text.encode())))
        other = self.fixture.root / 'other-payload'
        other.write_bytes(b'other benign payload\n')
        text2 = FRAGMENT_TEXT.format(payload=other)
        self.fixture.fragment_path.write_text(text2)
        with self.assertRaisesRegex(ValueError, 'does not bind payload'):
            self.collect(profile=self.fixture.profile(
                fragment_sha256=boot.sha(text2.encode())))

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
                lambda profile: profile.update(
                    fragment_path='/run/systemd/system/maltrace-boot.service'),
        ):
            profile = copy.deepcopy(base)
            change(profile)
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    boot.validate_profile(profile)
        self.assertTrue(boot.validate_profile(copy.deepcopy(base)))

    def test_loaded_definition_conflicts(self):
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
        self.assertEqual(binding['target_inode'], original.stat().st_ino)
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

    def test_decoder_rejects_mutated_record_sequences(self):
        self.fixture.patch(self)
        observation, bundle = self.collect()
        records = self.records_of(bundle)
        profile = self.fixture.profile()
        boot.normalize_boot_service(dict(records=copy.deepcopy(records)),
                                    profile)
        for mutation in (
                lambda rows: rows.pop(3),
                lambda rows: rows[1].update(
                    value=dict(rows[1]['value'], boot_id=str(uuid.uuid4()))),
                lambda rows: rows[2].update(peer=[901, 0, 0]),
                lambda rows: rows[7].update(pid=5252),
                lambda rows: rows[8].update(stdout='garbage'),
                lambda rows: rows[9]['value'].update(birth='1'),
                lambda rows: rows[5].update(sha256=boot.sha(b'x')),
                lambda rows: rows[5].update(content=base64.b64encode(
                    b'x').decode()),
                lambda rows: rows[6].update(device=999),
        ):
            mutated = copy.deepcopy(records)
            mutation(mutated)
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    boot.normalize_boot_service(dict(records=mutated), profile)


if __name__ == '__main__':
    unittest.main()
