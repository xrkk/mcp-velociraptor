"""Local seam tests for the boot-resume professional module.

Every native boundary is intercepted; nothing here proves native evidence.
"""
import base64
import copy
import json
import sys
import tempfile
import unittest
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
PID = 4321
BIRTH = '120000'
MAIN_START_US = 1_200_000_000
UID = 996
GID = 987
INVOCATION = 'a' * 32
PAYLOAD_BYTES = b'benign-resume-fixture-bytes\n'
PAYLOAD_SHA = sha(PAYLOAD_BYTES)
FRAGMENT_BYTES = (b'[Unit]\nDescription=fixture\n'
                  b'[Service]\nType=simple\nUser=996\nGroup=987\n'
                  b'ExecStart=/opt/mt-gap20-fixture/payload\n'
                  b'[Install]\nWantedBy=multi-user.target\n')
FRAGMENT_SHA = sha(FRAGMENT_BYTES)


def make_profile(**changes):
    profile = dict(
        unit_name='mt-gap20.service', vm_uuid=VM, boot_id=BOOT,
        expected_uid=UID, payload_path='/opt/mt-gap20-fixture/payload',
        payload_sha256=PAYLOAD_SHA,
        fragment_path='/etc/systemd/system/mt-gap20.service',
        fragment_sha256=FRAGMENT_SHA,
        bundle_dir='/opt/mt-gap20-fixture/bundle',
        deployment_root='/opt/velociraptor',
        client_id='C.abcdef012345',
        session_id='11111111-1111-4111-8111-111111111111',
        owner_id='22222222-2222-4222-8222-222222222222',
        lifetime_seconds=120, window_seconds=20, journal_max_bytes=4194304)
    profile.update(changes)
    return profile


def make_observation(profile):
    return {
        'schema': boot.SOURCE, 'kind': 'boot-service-observation',
        'vm_uuid': profile['vm_uuid'], 'boot_id': profile['boot_id'],
        'unit': dict(name=profile['unit_name'],
                     fragment_path=profile['fragment_path'],
                     fragment_sha256=profile['fragment_sha256'],
                     fragment_identity=dict(device=1, inode=2, size=3),
                     fragment_binding=None, invocation_id=INVOCATION,
                     unit_file_state='enabled',
                     started_at_monotonic=str(MAIN_START_US)),
        'payload': dict(path=profile['payload_path'],
                        sha256=profile['payload_sha256'], size=len(PAYLOAD_BYTES),
                        identity=dict(device=1, inode=3)),
        'actor': dict(pid=PID, birth=BIRTH, uid=UID, gid=GID,
                      exe=profile['payload_path'], exe_sha256=PAYLOAD_SHA,
                      cgroup='/system.slice/' + profile['unit_name'],
                      cmdline=[profile['payload_path']]),
        'manager': dict(pid=1, birth='1', uids=[0] * 4, gids=[0] * 4,
                        image='/usr/lib/systemd/systemd',
                        image_sha256='c' * 64),
        'observed_at': '2026-10-11T00:00:00+00:00', 'window_seconds': 20,
        'execstart': [profile['payload_path']], 'raw_refs': {},
        'limitations': ['fixture'],
    }


def show_stdout(profile, *, pid=PID, invocation=INVOCATION, active='active',
                unit_file_state='enabled'):
    payload = profile['payload_path']
    values = dict(
        Id=profile['unit_name'], FragmentPath=profile['fragment_path'],
        DropInPaths='', LoadState='loaded', ActiveState=active,
        SubState='running', InvocationID=invocation,
        UnitFileState=unit_file_state, Transient='no',
        NeedDaemonReload='no',
        ExecMainStartTimestampMonotonic=str(MAIN_START_US),
        MainPID=str(pid), ExecMainPID=str(pid), User=str(UID),
        Group=str(GID),
        ExecStart=('{ path=%s ; argv[]=%s ; ignore_errors=no ; '
                   'start_time=[n/a] ; stop_time=[n/a] ; pid=%d ; '
                   'code=(null) ; status=0/0 }' % (payload, payload, pid)),
        ControlGroup='/system.slice/' + profile['unit_name'])
    return '\n'.join('%s=%s' % (key, value)
                     for key, value in values.items()) + '\n'


def journal_raw(profile, *, boot_id=None, unit=None, invocation=INVOCATION,
                pid=PID, exe=None, stamp='1200500000'):
    unit = unit or profile['unit_name']
    exe = exe or profile['payload_path']
    entries = [
        dict(_BOOT_ID=boot_id or profile['boot_id'], _SYSTEMD_UNIT=unit,
             INVOCATION_ID=invocation, _PID='1',
             __MONOTONIC_TIMESTAMP=str(MAIN_START_US - 1000),
             MESSAGE_ID='39f53479d3a045ac8e11786248231fbf'),
        dict(_BOOT_ID=boot_id or profile['boot_id'], _SYSTEMD_UNIT=unit,
             INVOCATION_ID=invocation, _PID=str(pid), _EXE=exe,
             __MONOTONIC_TIMESTAMP=stamp, MESSAGE='MT_GAP20_IDLE_MODE'),
        dict(_BOOT_ID=boot_id or profile['boot_id'], _SYSTEMD_UNIT=unit,
             INVOCATION_ID=invocation, _PID='1',
             __MONOTONIC_TIMESTAMP='1201000000',
             MESSAGE_ID='39f53479d3a045ac8e11786248231fbf'),
    ]
    return ('\n'.join(json.dumps(entry) for entry in entries) + '\n').encode()


class Harness:
    def __init__(self, review, profile, **overrides):
        self.review = review
        self.profile = profile
        self.observation = overrides.pop('observation',
                                         make_observation(profile))
        self.journal = overrides.pop('journal',
                                     journal_raw(profile))
        self.show = overrides.pop('show', show_stdout(profile))
        self.facts = overrides.pop('facts', self.default_facts())
        self.receipt_changes = overrides.pop('receipt_changes', {})
        self.finish_root = overrides.pop('finish_root', None)
        self.finish_files = overrides.pop('finish_files', {})
        self.calls = []

    def default_facts(self):
        return dict(pid=PID, birth=BIRTH, uids=[UID] * 4, gids=[GID] * 4,
                    groups=[GID], image=self.profile['payload_path'],
                    device=1, inode=7, image_sha256=PAYLOAD_SHA,
                    cgroup='/system.slice/' + self.profile['unit_name'],
                    cmdline=[self.profile['payload_path']])

    def stable_read(self, path):
        path = str(path)
        if path == self.profile['fragment_path']:
            data, wanted = FRAGMENT_BYTES, self.profile['fragment_sha256']
        elif path == self.profile['payload_path']:
            data, wanted = PAYLOAD_BYTES, self.profile['payload_sha256']
        else:
            raise AssertionError('unexpected read %s' % path)
        return dict(path=path, size=len(data), device=1, inode=9, nlink=1,
                    uid=0, mode=0o444, sha256=wanted,
                    content=base64.b64encode(data).decode())

    def run_command(self, argv, timeout):
        self.calls.append(list(argv))
        if argv[:2] == ['systemctl', 'show']:
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
        binding = self.profile
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
                         lambda pid=1: dict(pid=1, birth='1', uids=[0] * 4,
                                            gids=[0] * 4,
                                            image='/usr/lib/systemd/systemd',
                                            image_sha256='c' * 64)),
            patch.object(resume_mod, '_open_manager',
                         lambda socket, expected: SimpleNamespace(
                             peer=[1, 0, 0], close=lambda: None)),
            patch.object(resume_mod, '_run_command', self.run_command),
            patch.object(resume_mod, '_process_facts',
                         lambda pid: copy.deepcopy(self.facts)),
            patch.object(resume_mod, '_read_exe', lambda pid: PAYLOAD_BYTES),
            patch.object(resume_mod, '_stable_read', self.stable_read),
            patch.object(resume_mod, '_rederive',
                         lambda bundle, inner: copy.deepcopy(self.observation)),
            patch.object(resume_mod, '_client', self.client),
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
                           ('expected_uid', 0), ('window_seconds', 31)):
            with self.subTest(key=key):
                broken = make_profile(**{key: value})
                with self.assertRaises(resume_mod.BootResumeError):
                    resume_mod.validate_profile(broken)
        with self.assertRaises(resume_mod.BootResumeError):
            resume_mod.validate_profile(dict(make_profile(), pid=1))


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.profile = make_profile()
        self.observation = make_observation(self.profile)
        self.unit = self.observation['unit']
        self.actor = self.observation['actor']

    def check(self, raw, **changes):
        profile = self.profile
        unit = dict(self.unit, **changes.pop('unit_changes', {}))
        actor = dict(self.actor, **changes.pop('actor_changes', {}))
        return resume_mod.check_journal(raw, profile, unit, actor,
                                        MAIN_START_US)

    def test_valid_journal_carries_structured_boot_identity(self):
        summary = self.check(journal_raw(self.profile))
        self.assertEqual(summary['unit_records'], 3)
        self.assertEqual(summary['main_records'], 1)
        self.assertEqual(summary['invocation_ids'], [INVOCATION])
        self.assertIn('39f53479d3a045ac8e11786248231fbf',
                      summary['message_ids'])

    def test_foreign_or_missing_structured_records_refuse(self):
        cases = {
            'foreign-boot': (journal_raw(self.profile, boot_id=VM), {}),
            'foreign-invocation': (journal_raw(self.profile,
                                               invocation='b' * 32), {}),
            'missing-main-pid': (journal_raw(self.profile, pid=999), {}),
            'foreign-exe': (journal_raw(self.profile, exe='/bin/false'), {}),
            'unit-mismatch': (journal_raw(self.profile, unit='other.service'),
                              {}),
        }
        for label, (raw, changes) in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(resume_mod.BootResumeError):
                    self.check(raw, **changes)

    def test_oversized_or_backwards_journal_refuses(self):
        with self.assertRaises(resume_mod.BootResumeError):
            self.check(b'x' * (self.profile['journal_max_bytes'] + 1))
        with self.assertRaises(resume_mod.BootResumeError):
            self.check(journal_raw(self.profile, stamp='10'))


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
        with patch.object(resume_mod, 'normalize_boot_service',
                          lambda bundle, inner: copy.deepcopy(
                              self.harness.observation)):
            return resume_mod.resume(self.profile, output)

    def test_resume_records_ready_scope_and_sealed_output(self):
        observation, bundle = self.resume()
        output = Path(bundle['output'])
        self.assertEqual(observation['target'],
                         dict(pid=PID, birth=BIRTH, uid=UID))
        self.assertEqual(observation['scope']['apply_receipt']['status'],
                         'APPLIED')
        self.assertEqual(observation['journal']['invocation_ids'],
                         [INVOCATION])
        records = [json.loads(line) for line in
                   (output / 'raw.ndjson').read_text().splitlines()]
        self.assertEqual([r['kind'] for r in records],
                         resume_mod.RECORD_SEQUENCE)
        self.assertTrue((output / 'journal.jsonl').is_file())
        self.assertEqual(stat_mode(output / 'observation.json'), 0o400)
        self.assertEqual(bundle['manifest']['files'].keys(),
                         set(resume_mod.RESUME_FILES))

    def test_resume_decodes_and_detects_tampering(self):
        observation, bundle = self.resume()
        output = Path(bundle['output'])
        with patch.object(resume_mod, 'normalize_boot_service',
                          lambda bundle_dir, inner: copy.deepcopy(
                              self.harness.observation)):
            replayed = resume_mod.normalize_boot_resume(output, self.profile)
        self.assertEqual(replayed['target'], observation['target'])
        raw_path = output / 'raw.ndjson'
        original = raw_path.read_bytes()
        raw_path.chmod(0o600)
        raw_path.write_bytes(original.replace(b'observation-complete',
                                              b'observation-completX'))
        with patch.object(resume_mod, 'normalize_boot_service',
                          lambda bundle_dir, inner: copy.deepcopy(
                              self.harness.observation)):
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


def stat_mode(path):
    return path.stat().st_mode & 0o777


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
                {'default_targets': [dict(pid=PID, birth=BIRTH, uid=UID)]}
            ).encode(),
            'generations/1/raw.ndjson': (
                json.dumps(dict(kind='ready', monotonic_ns=1)) + '\n' +
                json.dumps(dict(kind='exec', monotonic_ns=2)) + '\n' +
                json.dumps(dict(kind='end', monotonic_ns=3)) + '\n').encode(),
            'generations/1/events.ndjson': b'',
            'generations/1/probe.bt': b'fixture',
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

    def test_finish_refuses_foreign_boot_or_unconfirmed_stop(self):
        with patch.object(resume_mod, '_kernel_identity',
                          lambda: dict(boot_id=VM, vm_uuid=VM, reads={})):
            with self.assertRaises(resume_mod.BootResumeError):
                self.finish()

        def broken(tool, request):
            if tool == 'linux_scope_stop':
                return dict(self.harness.finish_receipt(tool, request),
                            collection_stopped=False)
            return self.harness.finish_receipt(tool, request)

        self.harness.client = lambda deployment_root, binding: SimpleNamespace(
            call=lambda tool, arguments: broken(tool, arguments['request']))
        with patch.object(resume_mod, '_client', self.harness.client):
            with self.assertRaises(resume_mod.BootResumeError):
                self.finish()


if __name__ == '__main__':
    unittest.main()
