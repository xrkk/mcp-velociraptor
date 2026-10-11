"""Local seam tests for the boot-resume professional module.

Every native boundary is intercepted; nothing here proves native evidence.
The complete host-side positive path with the real pinned professional
decoder and real kernel decoding lives in the MalTrace test suite.
"""
import base64
import copy
import json
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import velociraptor_linux_boot_resume as resume_mod
import velociraptor_linux_boot_service as boot
from velociraptor_linux_probe import SOURCE_ID
from velociraptor_linux_backend import sha

VM = '289e4d56-ebaf-5147-96ba-40dfc2a942a3'
BOOT = '4cbc0f6d-1111-4222-8333-abcdefabcdef'
BOOT_HEX = uuid.UUID(BOOT).hex
PID = 4321
BIRTH = '120000'
MAIN_START_US = 1_200_000_000
UID = 996
GID = 987
INVOCATION = 'a' * 32
UNIT = 'mt-gap20.service'
LINK = '/etc/systemd/system/multi-user.target.wants/' + UNIT
MANAGER_IMAGE = '/usr/lib/systemd/systemd'
MANAGER_SHA = 'c' * 64
PAYLOAD_BYTES = b'benign-resume-fixture-bytes\n'
PAYLOAD_SHA = sha(PAYLOAD_BYTES)
FRAGMENT_BYTES = (b'[Unit]\nDescription=fixture\n'
                  b'RefuseManualStart=yes\n'
                  b'After=systemd-journald.service\n'
                  b'Requires=systemd-journald.service\n'
                  b'[Service]\nType=simple\nUser=996\nGroup=987\n'
                  b'ExecStart=/opt/mt-gap20-fixture/payload\n'
                  b'Restart=no\n'
                  b'[Install]\nWantedBy=multi-user.target\n')
FRAGMENT_SHA = sha(FRAGMENT_BYTES)
PAYLOAD_INODE, UNIT_INODE, LINK_INODE, DEVICE = 600, 700, 800, 2049


def make_profile(**changes):
    profile = dict(
        unit_name=UNIT, vm_uuid=VM, boot_id=BOOT,
        expected_uid=UID, payload_path='/opt/mt-gap20-fixture/payload',
        payload_sha256=PAYLOAD_SHA,
        fragment_path='/etc/systemd/system/' + UNIT,
        fragment_sha256=FRAGMENT_SHA, enable_link_path=LINK,
        bundle_dir='/opt/mt-gap20-fixture/bundle',
        deployment_root='/opt/velociraptor',
        client_id='C.abcdef012345',
        session_id='11111111-1111-4111-8111-111111111111',
        owner_id='22222222-2222-4222-8222-222222222222',
        lifetime_seconds=120, window_seconds=20, journal_max_bytes=4194304)
    profile.update(changes)
    return profile


def bundle_observation(profile):
    return {
        'schema': boot.SOURCE, 'kind': 'boot-service-observation',
        'vm_uuid': profile['vm_uuid'], 'boot_id': profile['boot_id'],
        'unit': dict(name=profile['unit_name'],
                     fragment_path=profile['fragment_path'],
                     fragment_sha256=profile['fragment_sha256'],
                     fragment_identity=dict(device=DEVICE,
                                            inode=UNIT_INODE,
                                            size=len(FRAGMENT_BYTES)),
                     fragment_binding=None, invocation_id=INVOCATION,
                     unit_file_state='enabled',
                     started_at_monotonic=str(MAIN_START_US)),
        'payload': dict(path=profile['payload_path'],
                        sha256=profile['payload_sha256'],
                        size=len(PAYLOAD_BYTES),
                        identity=dict(device=DEVICE, inode=PAYLOAD_INODE)),
        'actor': dict(pid=PID, birth=BIRTH, uid=UID, gid=GID,
                      exe=profile['payload_path'], exe_sha256=PAYLOAD_SHA,
                      cgroup='/system.slice/' + profile['unit_name'],
                      cmdline=[profile['payload_path']]),
        'manager': dict(socket='/run/systemd/private', peer=[1, 0, 0],
                        pid1=dict(pid=1, birth='12000', uids=[0] * 4,
                                  gids=[0] * 4, image=MANAGER_IMAGE,
                                  image_sha256=MANAGER_SHA)),
        'observed_at': '2026-10-11T00:00:00+00:00', 'window_seconds': 20,
        'execstart': [profile['payload_path']], 'raw_refs': {},
        'limitations': ['fixture'],
    }


def show_stdout(profile, *, pid=PID, invocation=INVOCATION):
    payload = profile['payload_path']
    values = dict(
        Id=profile['unit_name'], FragmentPath=profile['fragment_path'],
        DropInPaths='', LoadState='loaded', ActiveState='active',
        SubState='running', InvocationID=invocation,
        UnitFileState='enabled', Transient='no', NeedDaemonReload='no',
        ExecMainStartTimestampMonotonic=str(MAIN_START_US),
        MainPID=str(pid), ExecMainPID=str(pid), User=str(UID),
        Group=str(GID),
        ExecStart=('{ path=%s ; argv[]=%s ; ignore_errors=no ; '
                   'start_time=[n/a] ; stop_time=[n/a] ; pid=%d ; '
                   'code=(null) ; status=0/0 }' % (payload, payload, pid)),
        ControlGroup='/system.slice/' + profile['unit_name'])
    return '\n'.join('%s=%s' % (key, value)
                     for key, value in values.items()) + '\n'


def journal_raw(profile, *, boot_id=None, manager=True, payload=True,
                message_id=resume_mod.UNIT_STARTED_MESSAGE_ID,
                unit=None, invocation=INVOCATION, main_pid=PID, uid=UID,
                exe=None, start_stamp=None, main_stamp=None,
                manager_exe=MANAGER_IMAGE, manager_uid='0', unit_field=None,
                extra_starts=0):
    unit = unit or profile['unit_name']
    exe = exe or profile['payload_path']
    boot = uuid.UUID(boot_id).hex if boot_id else BOOT_HEX
    entries = []
    if manager:
        entries.append(dict(
            _BOOT_ID=boot, _PID='1', _UID=manager_uid, _EXE=manager_exe,
            MESSAGE_ID=message_id, UNIT=unit_field or unit,
            INVOCATION_ID=invocation,
            _SYSTEMD_UNIT='init.scope',
            __MONOTONIC_TIMESTAMP=start_stamp
            or str(MAIN_START_US + 1000)))
        for _ in range(extra_starts):
            entries.append(dict(
                _BOOT_ID=boot, _PID='1', _UID='0', _EXE=MANAGER_IMAGE,
                MESSAGE_ID=message_id, UNIT=unit, INVOCATION_ID=invocation,
                _SYSTEMD_UNIT='init.scope',
                __MONOTONIC_TIMESTAMP=str(MAIN_START_US + 2000)))
    if payload:
        entries.append(dict(
            _BOOT_ID=boot, _SYSTEMD_UNIT=unit,
            _SYSTEMD_INVOCATION_ID=invocation, INVOCATION_ID=invocation,
            _PID=str(main_pid), _UID=str(uid), _EXE=exe,
            __MONOTONIC_TIMESTAMP=main_stamp or str(MAIN_START_US + 5000),
            MESSAGE='MT_GAP20_IDLE_MODE'))
    return ('\n'.join(json.dumps(entry) for entry in entries) + '\n').encode()


class Harness:
    def __init__(self, review, profile, **overrides):
        self.review = review
        self.profile = profile
        self.bundle = overrides.pop('bundle',
                                    bundle_observation(profile))
        self.journal = overrides.pop('journal', journal_raw(profile))
        self.show = overrides.pop('show', show_stdout(profile))
        self.facts = overrides.pop('facts', self.default_facts())
        self.receipt_changes = overrides.pop('receipt_changes', {})
        self.finish_root = overrides.pop('finish_root', None)
        self.finish_files = overrides.pop('finish_files', {})
        self.calls = []
        self.manager = dict(pid=1, birth='12000', uids=[0] * 4, gids=[0] * 4,
                            image=MANAGER_IMAGE, image_sha256=MANAGER_SHA)

    def default_facts(self):
        return dict(pid=PID, birth=BIRTH, uids=[UID] * 4, gids=[GID] * 4,
                    groups=[GID], image=self.profile['payload_path'],
                    device=DEVICE, inode=PAYLOAD_INODE,
                    image_sha256=PAYLOAD_SHA,
                    cgroup='/system.slice/' + self.profile['unit_name'],
                    cmdline=[self.profile['payload_path']])

    def stable_read(self, path):
        path = str(path)
        if path == self.profile['fragment_path']:
            data, wanted, inode, mode = (FRAGMENT_BYTES, FRAGMENT_SHA,
                                         UNIT_INODE, 0o644)
        elif path == self.profile['payload_path']:
            data, wanted, inode, mode = (PAYLOAD_BYTES, PAYLOAD_SHA,
                                         PAYLOAD_INODE, 0o555)
        else:
            raise AssertionError('unexpected read %s' % path)
        return dict(path=path, size=len(data), device=DEVICE, inode=inode,
                    nlink=1, uid=0, mode=mode, sha256=wanted,
                    content=base64.b64encode(data).decode())

    def directory(self, path):
        return dict(path=str(path), device=DEVICE, inode=77, uid=0, gid=0,
                    mode=0o755, size=4096)

    def link(self, path):
        return dict(path=str(path), target=self.profile['fragment_path'],
                    device=DEVICE, inode=LINK_INODE, uid=0, gid=0,
                    mode=0o777, size=len(self.profile['fragment_path']))

    def exe_fd(self, pid):
        return dict(path=self.profile['payload_path'], device=DEVICE,
                    inode=PAYLOAD_INODE)

    def run_command(self, argv, timeout):
        self.calls.append(list(argv))
        if argv[:2] == ['systemctl', 'show']:
            if len(argv) == 4 and argv[3] == (
                    '--property=RefuseManualStart,After,Requires'):
                return dict(
                    argv=list(argv), rc=0,
                    stdout='RefuseManualStart=yes\n'
                           'After=systemd-journald.service '
                           'systemd-journald.socket\n'
                           'Requires=systemd-journald.service\n',
                    stderr='')
            return dict(argv=list(argv), rc=0, stdout=self.show, stderr='')
        if argv[:2] == ['systemctl', 'cat']:
            text = '# %s\n%s' % (self.profile['fragment_path'],
                                 FRAGMENT_BYTES.decode())
            return dict(argv=list(argv), rc=0, stdout=text, stderr='')
        if argv[:1] == ['journalctl']:
            return dict(argv=list(argv), rc=0,
                        stdout=self.journal.decode(), stderr='')
        raise AssertionError('unexpected command %r' % (argv,))

    def scope_receipt(self, request):
        receipt = dict(request, status='APPLIED', backend_applied=True,
                       generation=1, tick_ns=10 ** 7, source=SOURCE_ID,
                       source_hashes=resume_mod.scope_source_hashes(),
                       default_targets=[dict(t) for t in request['targets']],
                       birth_basis=dict(clock_ticks_per_second=100,
                                        tick_ns=10 ** 7,
                                        proc_stat_field=22,
                                        zero_offsets={'self': 'zero'}),
                       transitions=[dict(action='applied', ready_ns=5000)])
        receipt.pop('operation_id', None)
        receipt.update(self.receipt_changes)
        return receipt

    def client(self, deployment_root, binding):
        harness = self

        class Client:
            def call(self, tool, arguments):
                request = arguments['request']
                if tool == 'linux_scope_apply':
                    return harness.scope_receipt(request)
                if tool in ('linux_scope_stop', 'linux_scope_export'):
                    return harness.finish_receipt(tool, request)
                raise AssertionError('unexpected scope tool %s' % tool)

        return Client()

    def finish_receipt(self, tool, request):
        target = dict(pid=PID, birth=BIRTH, uid=UID)
        base = dict(request, status='STOPPED', collection_stopped=True,
                    generation=1, default_targets=[target],
                    source=SOURCE_ID,
                    source_hashes=resume_mod.scope_source_hashes())
        base.pop('operation_id', None)
        if tool == 'linux_scope_stop':
            return base
        products, refs = [], []
        for name, raw in sorted(self.finish_files.items()):
            ref = dict(path=str(Path(self.finish_root) / name),
                       size=len(raw), sha256=sha(raw))
            if name == 'snapshots/export.json':
                refs.append(ref)
            else:
                products.append(ref)
        return dict(base, products=products, ref=refs[0])

    def install(self):
        patches = [
            patch.object(resume_mod, '_kernel_identity',
                         lambda: dict(boot_id=self.profile['boot_id'],
                                      vm_uuid=self.profile['vm_uuid'],
                                      reads={})),
            patch.object(resume_mod, '_manager_identity',
                         lambda pid=1: copy.deepcopy(self.manager)),
            patch.object(resume_mod, '_open_manager',
                         lambda socket, expected: SimpleNamespace(
                             peer=[1, 0, 0], close=lambda: None)),
            patch.object(resume_mod, '_run_command', self.run_command),
            patch.object(resume_mod, '_process_facts',
                         lambda pid: copy.deepcopy(self.facts)),
            patch.object(resume_mod, '_read_exe', lambda pid: PAYLOAD_BYTES),
            patch.object(resume_mod, '_stable_read', self.stable_read),
            patch.object(resume_mod, '_directory_identity', self.directory),
            patch.object(resume_mod, '_link_identity', self.link),
            patch.object(resume_mod, '_exe_fd_identity', self.exe_fd),
            patch.object(resume_mod, '_rederive',
                         lambda bundle, inner: copy.deepcopy(self.bundle)),
            patch.object(resume_mod, '_client', self.client),
            patch.object(resume_mod, 'normalize_boot_service',
                         lambda bundle, inner: copy.deepcopy(self.bundle)),
        ]
        if self.finish_root is not None:
            for relative, raw in self.finish_files.items():
                path = Path(self.finish_root) / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
        for item in patches:
            item.start()
            self.review.addCleanup(item.stop)
        return self


class ProfileTests(unittest.TestCase):
    def test_profile_round_trip_and_rejections(self):
        profile = make_profile()
        self.assertEqual(resume_mod.validate_profile(profile), profile)
        for key, value in (('client_id', 'bad id'), ('lifetime_seconds', 10),
                           ('journal_max_bytes', 10 ** 9),
                           ('session_id', 'not-a-uuid'),
                           ('bundle_dir', 'relative/path'),
                           ('enable_link_path', '/etc/systemd/system/wants/x'),
                           ('expected_uid', 0), ('window_seconds', 31)):
            with self.subTest(key=key):
                broken = make_profile(**{key: value})
                with self.assertRaises(resume_mod.BootResumeError):
                    resume_mod.validate_profile(broken)
        with self.assertRaises(resume_mod.BootResumeError):
            resume_mod.validate_profile(dict(make_profile(), pid=1))

    def test_boot_key_normalizes_uuid_and_hex_losslessly(self):
        self.assertEqual(resume_mod.boot_key(BOOT), BOOT_HEX)
        self.assertEqual(resume_mod.boot_key(BOOT_HEX), BOOT_HEX)
        with self.assertRaises(resume_mod.BootResumeError):
            resume_mod.boot_key('not-a-boot')


class JournalArgvTests(unittest.TestCase):
    def test_journal_argv_is_unambiguous_and_lossless(self):
        canonical = resume_mod.journal_argv(
            '4cbc0f6d-1111-4222-8333-abcdefabcdef', 'x.service')
        hex_form = resume_mod.journal_argv(
            '4cbc0f6d111142228333abcdefabcdef', 'x.service')
        self.assertEqual(canonical, hex_form)
        self.assertEqual(canonical[1],
                         '--boot=4cbc0f6d111142228333abcdefabcdef')
        self.assertEqual(canonical[2:], ['--unit', 'x.service',
                                         '--output=json', '--no-pager'])
        for broken in ('not-a-boot', '', '4cbc0f6d-1111',
                       'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'):
            with self.subTest(broken=broken):
                with self.assertRaises(resume_mod.BootResumeError):
                    resume_mod.journal_argv(broken, 'x.service')

    def test_resume_journal_record_uses_the_fixed_argv(self):
        case = ResumeFlowTests(
            'test_resume_records_full_identity_and_replays_verbatim')
        case.setUp()
        try:
            observation, bundle = case.resume()
            output = Path(bundle['output'])
            records = [json.loads(line) for line in
                       (output / 'raw.ndjson').read_text().splitlines()]
            record = next(r for r in records if r['kind'] == 'journal')
            self.assertEqual(record['argv'],
                             resume_mod.journal_argv(
                                 case.profile['boot_id'],
                                 case.profile['unit_name']))
            observation_doc = json.loads(
                (output / 'observation.json').read_text())
            self.assertTrue(observation_doc['ordering']['required'])
            self.assertIn('systemd-journald.service',
                          observation_doc['ordering']['after'])
        finally:
            case.doCleanups()


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.profile = make_profile()
        self.observation = bundle_observation(self.profile)
        self.unit = self.observation['unit']
        self.actor = self.observation['actor']

    def check(self, raw):
        return resume_mod.check_journal(raw, self.profile, self.unit,
                                        self.actor, MAIN_START_US,
                                        MANAGER_IMAGE)

    def test_valid_journal_requires_both_record_classes(self):
        summary = self.check(journal_raw(self.profile))
        self.assertEqual(summary['manager_records'], 1)
        self.assertEqual(summary['payload_records'], 1)
        self.assertEqual(summary['start_records'], 1)
        self.assertEqual(summary['invocation_ids'], [INVOCATION])
        self.assertIn(resume_mod.UNIT_STARTED_MESSAGE_ID,
                      summary['message_ids'])

    def test_missing_manager_start_records_refuse(self):
        with self.assertRaisesRegex(resume_mod.BootResumeError,
                                    'PID1 unit-start record'):
            self.check(journal_raw(self.profile, manager=False))

    def test_fake_manager_records_refuse(self):
        cases = {
            'fake-exe': journal_raw(self.profile,
                                    manager_exe='/bin/false'),
            'fake-uid': journal_raw(self.profile, manager_uid='996'),
            'wrong-unit': journal_raw(self.profile, unit_field='other.svc'),
            'wrong-invocation': journal_raw(self.profile,
                                            invocation='b' * 32),
            'wrong-message': journal_raw(self.profile, message_id='f' * 32),
            'foreign-boot': journal_raw(self.profile,
                                        boot_id=VM),
            'old-start': journal_raw(self.profile, start_stamp='1'),
            'multiple-starts': journal_raw(self.profile, extra_starts=1),
        }
        for label, raw in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(resume_mod.BootResumeError):
                    self.check(raw)

    def test_payload_field_mutations_refuse(self):
        cases = {
            'main-pid': journal_raw(self.profile, main_pid=999),
            'payload-uid': journal_raw(self.profile, uid=0),
            'payload-exe': journal_raw(self.profile, exe='/bin/false'),
            'payload-stamp': journal_raw(self.profile, main_stamp='1'),
        }
        for label, raw in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(resume_mod.BootResumeError):
                    self.check(raw)


class ResumeFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.profile = make_profile()
        bundle = Path(self.tmp.name) / 'bundle'
        bundle.mkdir()
        (bundle / 'manifest.json').write_text(json.dumps(
            dict(source=boot.SOURCE, directory=dict(device=1, inode=2,
                                                     mode=0o700),
                 files={})) + '\n')
        self.profile['bundle_dir'] = str(bundle)
        self.harness = Harness(self, self.profile).install()

    def resume(self):
        output = Path(self.tmp.name) / ('resume-%d' % len(
            list(Path(self.tmp.name).iterdir())))
        return resume_mod.resume(self.profile, output)

    def test_resume_records_full_identity_and_replays_verbatim(self):
        observation, bundle = self.resume()
        output = Path(bundle['output'])
        self.assertEqual(observation['target'],
                         dict(pid=PID, birth=BIRTH, uid=UID))
        self.assertEqual(observation['manager']['pid1'],
                         self.harness.manager)
        self.assertEqual(observation['manager']['peer'], [1, 0, 0])
        self.assertEqual(observation['physical']['link']['target'],
                         self.profile['fragment_path'])
        self.assertEqual(observation['scope']['apply_receipt']['status'],
                         'APPLIED')
        records = [json.loads(line) for line in
                   (output / 'raw.ndjson').read_text().splitlines()]
        self.assertEqual([r['kind'] for r in records],
                         resume_mod.RECORD_SEQUENCE)
        replayed = resume_mod.normalize_boot_resume(output, self.profile)
        self.assertEqual(replayed, observation)

    def test_manager_birth_mutation_hits_independent_bundle_binding(self):
        observation, bundle = self.resume()
        output = Path(bundle['output'])
        raw_path = output / 'raw.ndjson'
        records = [json.loads(line)
                   for line in raw_path.read_text().splitlines()]
        records[2]['identity']['birth'] = '999999'
        records[-2]['manager']['birth'] = '999999'
        raw_path.chmod(0o600)
        raw_path.write_text(''.join(
            json.dumps(record, separators=(',', ':')) + '\n'
            for record in records))
        raw_path.chmod(0o400)
        manifest_path = output / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        manifest['files']['raw.ndjson'].update(
            size=raw_path.stat().st_size, sha256=sha(raw_path.read_bytes()))
        manifest_path.chmod(0o600)
        manifest_path.write_text(json.dumps(manifest))
        manifest_path.chmod(0o400)
        with self.assertRaisesRegex(
                resume_mod.BootResumeError,
                'manager identity differs from the independent sealed boot '
                'bundle'):
            resume_mod.normalize_boot_resume(output, self.profile)

    def test_physical_identity_mutation_refuses(self):
        observation, bundle = self.resume()
        output = Path(bundle['output'])
        raw_path = output / 'raw.ndjson'
        records = [json.loads(line)
                   for line in raw_path.read_text().splitlines()]
        for record in records:
            if record['kind'] == 'enable-link':
                record['value']['inode'] = 999999
        raw_path.chmod(0o600)
        raw_path.write_text(''.join(
            json.dumps(record, separators=(',', ':')) + '\n'
            for record in records))
        raw_path.chmod(0o400)
        manifest_path = output / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        manifest['files']['raw.ndjson'].update(
            size=raw_path.stat().st_size, sha256=sha(raw_path.read_bytes()))
        manifest_path.chmod(0o600)
        manifest_path.write_text(json.dumps(manifest))
        manifest_path.chmod(0o400)
        with self.assertRaises(resume_mod.BootResumeError):
            resume_mod.normalize_boot_resume(output, self.profile)

    def test_resume_refuses_foreign_identity_and_bad_receipt(self):
        with patch.object(resume_mod, '_kernel_identity',
                          lambda: dict(boot_id=VM, vm_uuid=VM, reads={})):
            with self.assertRaises(resume_mod.BootResumeError):
                resume_mod.resume(self.profile,
                                  Path(self.tmp.name) / 'foreign')
        self.harness.receipt_changes = {'default_targets': [
            dict(pid=1, birth='1', uid=UID)]}
        with self.assertRaises(resume_mod.BootResumeError):
            self.resume()
        self.harness.receipt_changes = {}
        self.harness.facts['birth'] = '999'
        with self.assertRaises(resume_mod.BootResumeError):
            self.resume()


class FinishFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.profile = make_profile()
        self.profile['deployment_root'] = str(Path(self.tmp.name)
                                              / 'deployment')
        self.root = Path(self.tmp.name) / 'deployment' / 'scopes' / \
            self.profile['session_id']
        self.files = {
            'premise.json': json.dumps({'birth_basis': {}}).encode(),
            'generations/1/config.json': json.dumps(
                {'default_targets': [dict(pid=PID, birth=BIRTH, uid=UID)],
                 'source_sha256': sha(b'fixture-probe')}).encode(),
            'generations/1/raw.ndjson': (
                json.dumps(dict(kind='ready', monotonic_ns=1)) + '\n' +
                json.dumps(dict(kind='exec', monotonic_ns=2)) + '\n' +
                json.dumps(dict(kind='end', monotonic_ns=3)) + '\n').encode(),
            'generations/1/events.ndjson': b'',
            'generations/1/probe.bt': b'fixture-probe',
            'snapshots/export.json': b'{"status": "STOPPED"}\n',
        }
        self.harness = Harness(self, self.profile,
                               finish_root=self.root,
                               finish_files=self.files).install()

    def finish(self):
        output = Path(self.tmp.name) / ('finish-%d' % len(
            list(Path(self.tmp.name).iterdir())))
        return resume_mod.finish(self.profile, output)

    def test_finish_exports_and_replays_every_original(self):
        document, bundle = self.finish()
        output = Path(bundle['output'])
        self.assertTrue(document['stopped']['collection_stopped'])
        self.assertTrue(document['exported']['collection_stopped'])
        self.assertEqual(len(document['originals']), len(self.files))
        replayed = resume_mod.normalize_boot_resume_finish(output,
                                                           self.profile)
        self.assertEqual(replayed['exported']['status'], 'STOPPED')
        product = output / document['originals'][0]['local']
        raw = product.read_bytes()
        product.chmod(0o600)
        product.write_bytes(raw + b'x')
        with self.assertRaises(resume_mod.BootResumeError):
            resume_mod.normalize_boot_resume_finish(output, self.profile)


if __name__ == '__main__':
    unittest.main()
