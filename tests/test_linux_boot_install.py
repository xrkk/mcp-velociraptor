"""Explicit synthetic boot-install source fixtures; these never certify native execution."""
import base64
import copy
import os
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import velociraptor_linux_scheduler as scheduler
import velociraptor_linux_boot_install as source

UNIT_PATH = '/etc/systemd/system/one.service'
LINK_PATH = '/etc/systemd/system/multi-user.target.wants/one.service'


def fixture():
    root = dict(boot_id='boot', pid=123, start_time='42')
    actor = dict(pid=123, birth='42', parent_pid=1, uids=[1201] * 4,
                 gids=[2201] * 4, groups=[], image='/fixture/sample',
                 inode=1, device=2049, cgroup='0::/root',
                 cmdline=['/fixture/sample'])
    manager = dict(actor, pid=1, birth='1', uids=[0] * 4, gids=[0] * 4,
                   image='/usr/lib/systemd/systemd', image_sha256='b' * 64)
    config = dict(directory='/opt/t42/origin', service='one.service',
                  payload='payload', manager=manager,
                  socket='/run/systemd/private', window_seconds=12,
                  mechanism='boot-install', manager_scope='system')
    binding = dict(session_id='session', owner_id='owner', boot_id='boot',
                   vm_uuid='vm', client_id='client')
    rows = []

    def row(kind, stamp, **kw):
        rows.append(dict(kind=kind, monotonic_ns=stamp, **kw))

    row('intent', 200, source=source.SOURCE, config=config, binding=binding,
        root=root, directory_inode=500, directory_device=2049)
    row('fresh', 210, peer=[1, 0, 0], absent=['one.service'],
        units={'one.service': dict(LoadState='not-found', ActiveState='inactive',
                                   FragmentPath='', ActivationDetails=[],
                                   InvocationID=[])})
    row('ready', 220, deadline_ns=90000000000)
    payload = b'\x7fELFexplicit-local-fixture-only'
    unit_text = ('[Unit]\nDescription=benign captured origin\n'
                 'DefaultDependencies=no\nRefuseManualStart=yes\n'
                 '[Service]\nType=simple\nUser=1201\nGroup=2201\n'
                 'ExecStart=/opt/t42/origin/payload\nRestart=no\n'
                 '[Install]\nWantedBy=multi-user.target\n').encode()
    files = {}
    for i, (name, raw) in enumerate([('payload', payload), ('one.service', unit_text)]):
        files[name] = dict(path='/opt/t42/origin/' + name, inode=600 + i,
                           device=2049, size=len(raw), sha256=source.sha(raw),
                           content=base64.b64encode(raw).decode())
        row('closed-write', 1000 * (i + 1), actor=copy.deepcopy(actor),
            file=copy.deepcopy(files[name]), lease='F_RDLCK')
    show_stdout = ('Id=one.service\nFragmentPath=' + UNIT_PATH + '\nDropInPaths=\n'
                   'LoadState=loaded\nActiveState=inactive\nSubState=dead\n'
                   'InvocationID=\nUnitFileState=enabled\nTransient=no\n'
                   'NeedDaemonReload=no\nMainPID=0\nExecMainPID=0\n'
                   'User=1201\nGroup=2201\n'
                   'ExecStart={ path=/opt/t42/origin/payload ; '
                   'argv[]=/opt/t42/origin/payload ; ignore_errors=no ; status=0 }\n')
    result = dict(
        destination=dict(path=UNIT_PATH, inode=700, device=2049, mode=0o644,
                         uid=0, gid=0, size=len(unit_text),
                         sha256=files['one.service']['sha256']),
        link=dict(path=LINK_PATH, target=UNIT_PATH, inode=800, device=2049,
                  uid=0),
        protection=dict(
            payload=dict(path='/opt/t42/origin/payload', uid=0, mode=0o555),
            directory=dict(path='/opt/t42/origin', uid=0, mode=0o555)),
        reload=dict(argv=list(source.RELOAD_ARGV), rc=0, stdout='',
                    stderr=''),
        show=dict(argv=source.show_argv('one.service'), rc=0,
                  stdout=show_stdout, stderr=''),
        cat=dict(argv=source.cat_argv('one.service'), rc=0,
                 stdout='# ' + UNIT_PATH + '\n'
                        + unit_text.decode() + '\n', stderr=''))
    row('install-intent', 6000000, manager=copy.deepcopy(manager), peer=[1, 0, 0],
        unit_target=UNIT_PATH, link=LINK_PATH,
        reload_argv=list(source.RELOAD_ARGV),
        source=dict(payload=copy.deepcopy(files['payload']),
                    service=copy.deepcopy(files['one.service'])),
        kernel_prefix=dict(path='fixture', size=10, sha256='f' * 64),
        root_exit_ns=5000000)
    row('install-result', 7000000, **copy.deepcopy(result))
    row('closed', 8000000, error=None, lease_broken=False)
    events = []
    for kind, stamp, detail in (
            ('exec', 300, ['/fixture/sample']),
            ('modify', 500, ['payload', 500, 8388609, 30]),
            ('modify', 1500, ['one.service', 500, 8388609, 100]),
            ('exit', 5000000, [0])):
        events.append(dict(kind=kind, monotonic_ns=stamp, pid=123, birth='42',
                           uid=1201, root_pid=123, root_birth='42',
                           detail=detail, generation=1, source='fixture-kernel',
                           strings_may_be_truncated=False))
    arguments = dict(config=config, binding=binding, root=root,
                     credentials=copy.deepcopy(actor), kernel=events)
    return rows, arguments, files, result


class BootInstallProfileTests(unittest.TestCase):
    def base(self):
        _rows, arguments, _files, _result = fixture()
        return arguments

    def test_fixed_shape_only_and_forbidden_authority_fields(self):
        arguments = self.base()
        source.validate_profile(arguments['config'])
        self.assertEqual(scheduler.source_name(arguments['config']),
                         source.SOURCE)
        self.assertEqual(scheduler.unit_names(arguments['config']),
                         ['one.service'])
        for change in (lambda c: c.update(socket='/run/foreign'),
                       lambda c: c['manager'].update(pid=901),
                       lambda c: c['manager'].update(uids=[0, 0, 0, 1201]),
                       lambda c: c.update(manager_scope='user'),
                       lambda c: c.pop('manager_scope'),
                       lambda c: c.update(mechanism='timer'),
                       lambda c: c.update(verified=True),
                       lambda c: c.update(service='../escape.service'),
                       lambda c: c.update(window_seconds=31)):
            config = self.base()['config']
            change(config)
            with self.subTest(config=config.get('socket', config)):
                with self.assertRaises(ValueError):
                    source.validate_profile(config)


class BootInstallIdentityTypeTests(unittest.TestCase):
    def test_manager_numeric_aliases_are_not_kernel_identity(self):
        for field, value in (('pid', True), ('uids', [False] * 4),
                             ('gids', [False] * 4), ('birth', '0')):
            with self.subTest(field=field):
                _, arguments, _, _ = fixture()
                arguments['config']['manager'][field] = value
                with self.assertRaisesRegex(ValueError, 'system manager identity required'):
                    source.validate_profile(arguments['config'])

    def test_non_integer_and_root_author_credentials_are_refused(self):
        rows, arguments, _, _ = fixture()
        import copy
        raw = base64.b64decode(rows[4]['file']['content'])
        for field, value in (('uids', [True] * 4), ('gids', [True] * 4),
                             ('uids', [0] * 4), ('uids', [1201.0] * 4),
                             ('gids', [2**32 - 1] * 4), ('groups', [True])):
            credentials = copy.deepcopy(arguments['credentials'])
            credentials[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaisesRegex(ValueError, 'ordinary installation identity required'):
                    source.parse_installation_unit(raw, credentials,
                                                   '/opt/t42/origin/payload')


class BootInstallSourceTests(unittest.TestCase):
    def test_captured_origin_and_one_trusted_installation_replay(self):
        rows, arguments, files, _result = fixture()
        events = source.normalize(rows, **arguments)
        self.assertEqual([e['kind'] for e in events], ['artifact', 'definition'])
        artifact, definition = events
        self.assertEqual(artifact['artifact_sha256'], files['payload']['sha256'])
        self.assertEqual(artifact['monotonic_ns'], 1000)
        self.assertEqual(definition['definition_mechanism'], 'boot-install')
        self.assertEqual(definition['definition_id'], 'system:one.service')
        self.assertEqual(definition['definition_binds_sha256'],
                         files['payload']['sha256'])
        self.assertEqual(definition['monotonic_ns'], 2000)
        install_ref = definition['install_ref']
        self.assertEqual(install_ref['unit_path'], UNIT_PATH)
        self.assertEqual(install_ref['unit_sha256'],
                         files['one.service']['sha256'])
        self.assertEqual(install_ref['link'], LINK_PATH)
        self.assertEqual(install_ref['installer'], dict(pid=1, uid=0))
        self.assertEqual(install_ref['reload_rc'], 0)
        self.assertEqual(definition['source_rows'][0], 5)
        self.assertTrue(all(e['source_rows'] for e in events))
        # the ordinary sample root is the author; the root manager is not
        self.assertEqual(definition['instance']['pid'],
                         arguments['root']['pid'])
        self.assertEqual(definition['instance']['start_time'],
                         arguments['root']['start_time'])

    def test_router_wires_scheduler_entry_points_to_the_installation_module(self):
        rows, arguments, _files, _result = fixture()
        routed = scheduler.normalize(rows, **arguments)
        self.assertEqual([e['kind'] for e in routed],
                         ['artifact', 'definition'])

    def test_identity_conflicts_refuse_with_specific_reasons(self):
        cases = {
            'same-pid-different-birth': (
                lambda r, a: r[3]['actor'].update(birth='999'),
                'origin author is not the ordinary sample root'),
            'root-uid': (
                lambda r, a: r[3]['actor'].update(uids=[0] * 4),
                'unknown/dead writer identity'),
            'profile-uid-drift': (
                lambda r, a: a['credentials'].update(uids=[1301] * 4),
                'unknown/dead writer identity'),
            'foreign-boot': (
                lambda r, a: a['root'].update(boot_id='foreign'),
                'install boot conflict'),
            'foreign-vm': (
                lambda r, a: r[0].update(
                    binding=dict(r[0]['binding'], vm_uuid='foreign')),
                'install independent expectation mismatch'),
            'no-definition': (
                lambda r, a: r.remove(r[4]), 'one version of every origin artifact'),
            'no-kernel-write': (
                lambda r, a: a['kernel'].__setitem__(1, dict(
                    a['kernel'][1], kind='open')),
                'actual content write missing'),
            'no-root-exit': (
                lambda r, a: a['kernel'].__setitem__(3, dict(
                    a['kernel'][3], kind='open')),
                'actual root exit missing'),
            'reversed-write-order': (_reverse_write_order,
                'origin write order missing'),
            'two-versions': (
                lambda r, a: r.insert(5, dict(r[3], monotonic_ns=3000)),
                'one version of every origin artifact'),
            'raw-bytes-tamper': (
                lambda r, a: r[3]['file'].update(sha256='c' * 64),
                'unbound origin content'),
            'not-fresh-unit': (
                lambda r, a: r[1]['units']['one.service'].update(
                    LoadState='loaded'),
                'existing definition or invocation'),
            'install-before-exit': (
                lambda r, a: r[5].update(monotonic_ns=4000000),
                'installation order conflict'),
            'wrong-install-authority': (
                lambda r, a: r[5]['manager'].update(uids=[1201] * 4),
                'installer is not the pid1 root manager'),
            'install-manager-birth-drift': (
                lambda r, a: r[5]['manager'].update(birth='999'),
                'install manager identity conflict'),
            'install-manager-image-drift': (
                lambda r, a: r[5]['manager'].update(image='/foreign/manager'),
                'install manager identity conflict'),
            'install-manager-image-hash-drift': (
                lambda r, a: r[5]['manager'].update(image_sha256='c' * 64),
                'install manager identity conflict'),
            'foreign-install-peer': (
                lambda r, a: r[5].update(peer=[901, 1201, 2201]),
                'foreign install peer'),
            'wrong-install-target': (
                lambda r, a: r[6]['destination'].update(path='/etc/systemd/system/other.service'),
                'installed unit destination mismatch'),
            'wrong-install-content': (
                lambda r, a: r[6]['destination'].update(sha256='f' * 64),
                'installed unit destination mismatch'),
            'foreign-link': (
                lambda r, a: r[6]['link'].update(target='/etc/systemd/system/other.service'),
                'enablement link mismatch'),
            'protection-drift': (
                lambda r, a: r[6]['protection']['payload'].update(mode=0o755),
                'origin protection mismatch'),
            'reload-failed': (
                lambda r, a: r[6]['reload'].update(rc=1),
                'daemon reload unconfirmed'),
            'repeated-install': (
                lambda r, a: r.insert(6, dict(r[5], monotonic_ns=6500000)),
                'trusted installation missing or ambiguous'),
            'unknown-admin-action': (
                lambda r, a: r.insert(7, dict(kind='install-refused',
                                               monotonic_ns=7500000,
                                               error='x')),
                'trusted installation missing or ambiguous'),
            'unit-not-inactive': (
                lambda r, a: r[6]['show'].update(
                    stdout=r[6]['show']['stdout'].replace(
                        'ActiveState=inactive', 'ActiveState=active')),
                'unit must stay inactive'),
            'unit-invocation-present': (
                lambda r, a: r[6]['show'].update(
                    stdout=r[6]['show']['stdout'].replace(
                        'InvocationID=\n', 'InvocationID=abcdef0123456789\n')),
                'unit must have no invocation'),
            'unit-not-enabled': (
                lambda r, a: r[6]['show'].update(
                    stdout=r[6]['show']['stdout'].replace(
                        'UnitFileState=enabled', 'UnitFileState=disabled')),
                'unit not enabled'),
            'cat-not-captured-bytes': (
                lambda r, a: r[6]['cat'].update(stdout='# other\n'),
                'cat does not reproduce the captured unit bytes'),
            'payload-argv-conflict': (
                lambda r, a: _mutate_unit(r, a, b'Restart=no\n',
                                          b'Restart=no\nExtra=payload --run\n'),
                'unsupported installation unit options'),
            'execstart-argument': (
                lambda r, a: _mutate_unit(
                    r, a, b'ExecStart=/opt/t42/origin/payload\n',
                    b'ExecStart=/opt/t42/origin/payload --run benign\n'),
                'installation ExecStart must bind the captured payload'),
            'execstart-wrong-path': (
                lambda r, a: _mutate_unit(
                    r, a, b'ExecStart=/opt/t42/origin/payload\n',
                    b'ExecStart=/opt/t42/other\n'),
                'installation ExecStart must bind the captured payload'),
            'wrong-user': (
                lambda r, a: _mutate_unit(r, a, b'User=1201\n', b'User=0\n'),
                'ordinary installation identity required'),
            'wrong-type': (
                lambda r, a: _mutate_unit(r, a, b'Type=simple\n', b'Type=exec\n'),
                'unsupported installation service semantics'),
            'wrong-wanted-by': (
                lambda r, a: _mutate_unit(
                    r, a, b'WantedBy=multi-user.target\n',
                    b'WantedBy=default.target\n'),
                'unsupported enablement target'),
            'incomplete-close': (
                lambda r, a: r[-1].update(error='deadline'),
                'incomplete or mutable installation originals'),
            'lease-broken': (
                lambda r, a: r[-1].update(lease_broken=True),
                'incomplete or mutable installation originals'),
            'missing-intent': (
                lambda r, a: r.remove(r[5]),
                'trusted installation missing or ambiguous'),
        }
        for name, (mutate, reason) in cases.items():
            with self.subTest(name=name):
                rows, arguments, _files, _result = fixture()
                mutate(rows, arguments)
                with self.assertRaisesRegex(ValueError, reason):
                    source.normalize(rows, **arguments)


def _reverse_write_order(rows, arguments):
    payload_row, service_row = rows[3], rows[4]
    rows[3] = dict(service_row, monotonic_ns=1000)
    rows[4] = dict(payload_row, monotonic_ns=2000)
    arguments['kernel'][1]['monotonic_ns'] = 1500
    arguments['kernel'][2]['monotonic_ns'] = 500


def _mutate_unit(rows, arguments, old, new):
    """Rewrite the captured unit bytes and every pinned copy coherently."""
    captured = None
    for row in rows:
        if row['kind'] == 'closed-write' and row['file']['path'].endswith('.service'):
            raw = base64.b64decode(row['file']['content']).replace(old, new)
            captured = raw
            row['file'].update(content=base64.b64encode(raw).decode(),
                               size=len(raw), sha256=source.sha(raw))
    assert captured is not None
    intent = next(r for r in rows if r['kind'] == 'install-intent')
    intent['source']['service'].update(
        content=base64.b64encode(captured).decode(), size=len(captured),
        sha256=source.sha(captured))
    result = next(r for r in rows if r['kind'] == 'install-result')
    result['destination'].update(size=len(captured),
                                 sha256=source.sha(captured))
    result['cat']['stdout'] = '# ' + UNIT_PATH + '\n' + captured.decode() + '\n'




def ordered_fixture():
    """The legacy fixture re-shaped to the one ordered captured form."""
    rows, arguments, files, result = fixture()
    old_raw = base64.b64decode(files['one.service']['content'])
    text = old_raw.decode().replace(
        '[Unit]\nDescription=benign captured origin\n',
        '[Unit]\nDescription=benign captured origin\n'
        'After=systemd-journald.service\n'
        'Requires=systemd-journald.service\n')
    new_raw = text.encode()
    new_sha = source.sha(new_raw)
    files['one.service'] = dict(files['one.service'], size=len(new_raw),
                                sha256=new_sha,
                                content=base64.b64encode(new_raw).decode())
    rows[4]['file'] = dict(files['one.service'])
    rows[5]['source']['service'] = dict(files['one.service'])
    install_row = next(row for row in rows
                       if row['kind'] == 'install-result')
    install_row['destination'].update(size=len(new_raw), sha256=new_sha)
    install_row['cat']['stdout'] = ('# ' + UNIT_PATH + '\n'
                                    + new_raw.decode() + '\n')
    install_row['ordering'] = dict(
        argv=source.ordering_argv('one.service'), rc=0,
        stdout='After=systemd-journald.service systemd-journald.socket\n'
               'Requires=systemd-journald.service\n',
        stderr='', after=['systemd-journald.service',
                          'systemd-journald.socket'],
        requires=['systemd-journald.service'])
    return rows, arguments, files, install_row


class BootInstallOrderedShapeTests(unittest.TestCase):
    def unit_text(self):
        _rows, _arguments, files, _result = ordered_fixture()
        return base64.b64decode(files['one.service']['content'])

    def credentials(self):
        _rows, arguments, _files, _result = ordered_fixture()
        return arguments['credentials']

    def test_ordered_shape_parses_and_replays_with_loaded_ordering(self):
        rows, arguments, files, _result = ordered_fixture()
        parsed = source.parse_installation_unit(
            base64.b64decode(files['one.service']['content']),
            arguments['credentials'], files['payload']['path'])
        self.assertTrue(parsed['ordering_required'])
        events = source.normalize(rows, **arguments)
        self.assertEqual([e['kind'] for e in events],
                         ['artifact', 'definition'])
        self.assertEqual(events[1]['install_ref']['unit_sha256'],
                         files['one.service']['sha256'])

    def test_legacy_shape_still_replays_without_ordering(self):
        rows, arguments, files, _result = fixture()
        parsed = source.parse_installation_unit(
            base64.b64decode(files['one.service']['content']),
            arguments['credentials'], files['payload']['path'])
        self.assertFalse(parsed['ordering_required'])
        events = source.normalize(rows, **arguments)
        self.assertEqual([e['kind'] for e in events],
                         ['artifact', 'definition'])

    def test_ordered_shape_parser_negatives(self):
        raw = self.unit_text()
        credentials = self.credentials()
        cases = {
            'partial-pair': raw.replace(b'Requires=systemd-journald.service\n',
                                        b''),
            'wrong-dependency': raw.replace(
                b'After=systemd-journald.service\n',
                b'After=other.service\n'),
            'extra-unit-key': raw.replace(b'RefuseManualStart=yes\n',
                                          b'RefuseManualStart=yes\n'
                                          b'Wants=extra.service\n'),
            'extra-service-key': raw.replace(b'Restart=no\n',
                                             b'Restart=no\n'
                                             b'Environment=A=B\n'),
            'multi-token': raw.replace(
                b'After=systemd-journald.service\n',
                b'After=systemd-journald.service basic.target\n'),
        }
        for label, broken in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    source.parse_installation_unit(broken, credentials,
                                                   '/opt/t42/origin/payload')

    def test_ordered_shape_requires_the_loaded_ordering_proof(self):
        def mutate(case):
            rows, arguments, files, install_row = ordered_fixture()
            case(rows, install_row)
            return rows, arguments

        cases = {
            'missing-proof': (
                lambda r, result: result.pop('ordering'),
                'installed loaded ordering proof missing'),
            'rc-and-argv': (
                lambda r, result: result['ordering'].update(rc=1),
                'installed loaded ordering proof argv/rc mismatch'),
            'wrong-argv': (
                lambda r, result: result['ordering'].update(
                    argv=['systemctl', 'show', 'one.service']),
                'installed loaded ordering proof argv/rc mismatch'),
            'tokens-differ': (
                lambda r, result: result['ordering'].update(
                    after=['other.service']),
                'installed loaded ordering tokens differ'),
            'no-journald-token': (
                lambda r, result: (
                    result['ordering'].update(
                        stdout='After=basic.target\n'
                               'Requires=basic.target\n',
                        after=['basic.target'],
                        requires=['basic.target'])),
                'installed loaded ordering lacks the journald dependency'),
        }
        for label, (case, reason) in cases.items():
            with self.subTest(label=label):
                rows, arguments = mutate(case)
                with self.assertRaisesRegex(ValueError, reason):
                    source.normalize(rows, **arguments)

    def test_legacy_shape_rejects_an_ordering_proof(self):
        rows, arguments, _files, _result = fixture()
        install_row = next(row for row in rows
                           if row['kind'] == 'install-result')
        install_row['ordering'] = dict(
            argv=source.ordering_argv('one.service'), rc=0, stdout='',
            stderr='', after=[], requires=[])
        with self.assertRaisesRegex(ValueError,
                                    'legacy installation must not carry'):
            source.normalize(rows, **arguments)



class BootInstallCapturedFixtureArgumentsTests(unittest.TestCase):
    payload = '/opt/t42/origin/payload'

    def arguments(self, ready=False):
        args = [self.payload, '--scenario', 'scheduled', '--run-id',
                'scheduled-1', '--root', '/opt/t42/origin/case',
                '--schedule-source', 'systemd']
        if ready:
            args += ['--schedule-ready-file', '/opt/t42/origin/ready']
        return args

    def coherent(self, tokens, ordered=False):
        rows, arguments, files, result = (ordered_fixture() if ordered else fixture())
        _mutate_unit(rows, arguments, ('ExecStart=' + self.payload + '\n').encode(),
                     ('ExecStart=' + ' '.join(tokens) + '\n').encode())
        result = next(row for row in rows if row['kind'] == 'install-result')
        result['show']['stdout'] = result['show']['stdout'].replace(
            'argv[]=' + self.payload + ' ;', 'argv[]=' + ' '.join(tokens) + ' ;')
        return rows, arguments, result

    def test_legacy_unit_result_remains_exact_and_unchanged(self):
        rows, arguments, files, _ = fixture()
        parsed = source.parse_installation_unit(base64.b64decode(files['one.service']['content']),
                                                arguments['credentials'], self.payload)
        self.assertEqual(parsed, dict(user='1201', group='2201', execstart=self.payload,
                                      wanted_by='multi-user.target', ordering_required=False,
                                      after=None, requires=None))
        self.assertEqual(len(source.normalize(rows, **arguments)), 2)

    def test_captured_scheduled_and_ready_args_replay_both_unit_shapes(self):
        for ordered in (False, True):
            for ready in (False, True):
                with self.subTest(ordered=ordered, ready=ready):
                    tokens = self.arguments(ready)
                    rows, arguments, result = self.coherent(tokens, ordered)
                    captured = source.verify_captured(rows, **arguments, boundary_ns=8000000)
                    self.assertEqual(captured['unit']['execstart_argv'], tokens)
                    events = source.normalize(rows, **arguments)
                    self.assertEqual([row['kind'] for row in events], ['artifact', 'definition'])
                    self.assertEqual(events[1]['install_ref']['unit_sha256'],
                                     result['destination']['sha256'])

    def test_specific_argument_guards_with_coherent_originals(self):
        cases = [
            (4, 'bad%id', 'scheduled fixture run-id unsupported'),
            (4, 'bad$id', 'scheduled fixture run-id unsupported'),
            (6, '/opt/foreign/case', 'scheduled fixture case must belong'),
            (6, '/opt/t42/origin/../case', 'scheduled fixture case must belong'),
            (8, 'cron', 'installation ExecStart must bind'),
            (3, '--unknown', 'installation ExecStart must bind'),
        ]
        for offset, replacement, reason in cases:
            tokens = self.arguments()
            tokens[offset] = replacement
            rows, arguments, _ = self.coherent(tokens)
            with self.subTest(offset=offset, replacement=replacement):
                with self.assertRaisesRegex(ValueError, reason):
                    source.normalize(rows, **arguments)
        for offset, replacement in [(9, '--other'), (10, '/opt/foreign/ready')]:
            tokens = self.arguments(True)
            tokens[offset] = replacement
            rows, arguments, _ = self.coherent(tokens)
            with self.assertRaisesRegex(ValueError, 'scheduled fixture readiness must belong'):
                source.normalize(rows, **arguments)

    def test_loaded_command_must_equal_the_actual_captured_args(self):
        rows, arguments, result = self.coherent(self.arguments(True))
        result['show']['stdout'] = result['show']['stdout'].replace(
            '--run-id scheduled-1', '--run-id other-run')
        with self.assertRaisesRegex(ValueError, 'loaded ExecStart differs from captured'):
            source.normalize(rows, **arguments)

    def test_missing_and_extra_tokens_are_not_generic_argv_support(self):
        for tokens in [self.arguments()[:-1], self.arguments() + ['--extra', 'value'],
                       self.arguments() + ['--schedule-source', 'systemd'],
                       [self.payload, '--run', 'benign']]:
            rows, arguments, _ = self.coherent(tokens)
            with self.assertRaisesRegex(ValueError, 'installation ExecStart must bind|scheduled fixture readiness'):
                source.normalize(rows, **arguments)

    def test_caller_argv_still_cannot_replace_captured_unit_evidence(self):
        rows, arguments, _ = self.coherent(self.arguments())
        arguments['config']['argv'] = self.arguments()
        with self.assertRaisesRegex(ValueError, 'caller supplied forbidden field'):
            source.normalize(rows, **arguments)


if __name__ == '__main__':
    unittest.main()
