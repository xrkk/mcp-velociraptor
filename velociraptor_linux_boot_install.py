"""Captured ordinary origin plus ONE trusted persistent installation.

The scheduler collector proves a fresh first invocation; the boot-service
producer observes an already-running invocation. Neither can answer how a
unit came to exist. This module closes that origin gap for one fixed
benign shape: an ordinary sample writes a native ELF payload and exactly
one installation unit into a new empty directory under real fanotify
CLOSE_WRITE with held read leases, and only after the captured originals,
the ordinary author and the actual root exit pass the independent
kernel-prefix verification does the trusted system manager perform ONE
fixed installation - an exclusive /etc/systemd/system unit copy, one
root-protected enablement symlink and one daemon-reload. The unit is
never started, restarted or executed; it stays enabled and inactive with
no invocation. Root administration is recorded as the installer, never
as the sample author.

Honest boundaries: no invocation is searched, the kernel scope is never
extended, no scheduler-fire verdict is produced, and nothing here claims
cross-boot autonomy. verified/source_nature can never be supplied by the
caller; the decoder re-derives everything from preserved originals.
"""
import base64
import configparser
import json
import os
import re
import shlex
import signal
import stat
import subprocess
import time
from pathlib import Path

from velociraptor_linux_scheduler import (Collector, artifact_names,
                                          unit_names, validate_fresh, sha,
                                          process)

SOURCE = 'MalTrace.SystemBootInstall.v1'
UNIT_DIRECTORY = Path('/etc/systemd/system')
WANTS_DIRECTORY = Path('/etc/systemd/system/multi-user.target.wants')
RELOAD_ARGV = ['/usr/bin/systemctl', 'daemon-reload']
SHOW_INSTALL_PROPERTIES = ('Id', 'FragmentPath', 'DropInPaths', 'LoadState',
                           'ActiveState', 'SubState', 'InvocationID',
                           'UnitFileState', 'Transient', 'NeedDaemonReload',
                           'MainPID', 'ExecMainPID', 'User', 'Group',
                           'ExecStart')
ORDERING_PROPERTIES = ('After', 'Requires')
JOURNALD_DEPENDENCY = 'systemd-journald.service'
INSTALLATION_SECTIONS = {'Unit': {'Description', 'DefaultDependencies',
                                  'RefuseManualStart'},
                         'Service': {'Type', 'User', 'Group', 'ExecStart',
                                     'Restart'},
                         'Install': {'WantedBy'}}
PROFILE_FIELDS = {'directory', 'service', 'payload', 'manager', 'socket',
                  'window_seconds', 'mechanism', 'manager_scope'}
FORBIDDEN_PROFILE_FIELDS = ('verified', 'source_nature', 'identity',
                            'command', 'shell', 'argv', 'invocation_id',
                            'invocationid', 'pid', 'birth')
LIMITATIONS = [
    'captured origin proves only the observed ordinary writes and the one '
    'trusted installation; early execution and any later invocation remain unproven',
    'the unit stays enabled but inactive; no execution or scheduler-fire '
    'verdict is produced by this source',
    'cross-boot autonomy requires an independently sealed counterboot source '
    'and a confirmed host bridge',
]


class BootInstallError(ValueError):
    pass


def need(condition, message, detail=''):
    if not condition:
        raise BootInstallError(
            message + (': ' + str(detail) if detail else ''))


def show_argv(unit_name):
    return ['/usr/bin/systemctl', 'show', unit_name,
            '--property=' + ','.join(SHOW_INSTALL_PROPERTIES)]


def cat_argv(unit_name):
    return ['/usr/bin/systemctl', 'cat', unit_name]


def validate_profile(config):
    """System-manager boot-install origin profile, fixed shape only.

    The field set matches the system service scheduler profile plus the
    explicit mechanism; caller-supplied authority, identity or verdict
    fields are refused outright.
    """
    need(isinstance(config, dict), 'profile must be an object')
    for key in FORBIDDEN_PROFILE_FIELDS:
        need(key not in config, 'caller supplied forbidden field', key)
    need(set(config) == PROFILE_FIELDS, 'boot-install fields',
         'expected exactly %r' % sorted(PROFILE_FIELDS))
    need(config['mechanism'] == 'boot-install', 'boot-install mechanism required')
    need(config['manager_scope'] == 'system', 'system manager scope required')
    manager = config['manager']
    need(isinstance(manager, dict) and type(manager.get('pid')) is int and manager['pid'] == 1
         and all(isinstance(manager.get(k), list) and len(manager[k]) == 4
                 and all(type(v) is int and v == 0 for v in manager[k])
                 for k in ('uids', 'gids'))
         and manager.get('uids') == [0] * 4 and manager.get('gids') == [0] * 4
         and isinstance(manager.get('birth'), str) and manager['birth'].isdigit() and int(manager['birth']) > 0,
         'system manager identity required')
    need(config['socket'] == '/run/systemd/private', 'system manager socket required')
    directory = Path(config['directory'])
    need(directory.is_absolute() and directory.name and not directory.is_symlink(),
         'boot-install directory')
    need(type(config['window_seconds']) is int and 1 <= config['window_seconds'] <= 30,
         'boot-install deadline')
    for key in ('payload', 'service'):
        need(re.fullmatch(r'[a-zA-Z0-9_.-]{1,30}', config[key]),
             'short flat name required', key)
    need(config['service'].endswith('.service'), 'service unit name required')
    need(len(set(artifact_names_for(config))) == len(artifact_names_for(config)),
         'boot-install names')
    return dict(config)


def artifact_names_for(config):
    return [config['payload'], config['service']]


def unit_names_for(config):
    return [config['service']]


def ordering_argv(unit_name):
    return ['systemctl', 'show', unit_name,
            '--property=' + ','.join(ORDERING_PROPERTIES)]


def parse_installation_unit(raw, credentials, payload_path):
    """Strict fixed-shape unit parse; nothing outside the supported
    installation semantics survives."""
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    parser.read_string(raw.decode())
    need(not parser.defaults()
         and set(parser.sections()) == set(INSTALLATION_SECTIONS),
         'unsupported installation unit sections')
    unit, service, install = (parser['Unit'], parser['Service'],
                              parser['Install'])
    legacy_unit = set(INSTALLATION_SECTIONS['Unit'])
    ordered_unit = legacy_unit | set(ORDERING_PROPERTIES)
    unit_options = set(unit)
    need(unit_options in (legacy_unit, ordered_unit),
         'unsupported installation unit options')
    need(set(service) == INSTALLATION_SECTIONS['Service']
         and set(install) == INSTALLATION_SECTIONS['Install'],
         'unsupported installation unit options')
    ordering_required = unit_options == ordered_unit
    if ordering_required:
        need(unit['After'] == JOURNALD_DEPENDENCY
             and unit['Requires'] == JOURNALD_DEPENDENCY,
             'unsupported installation journald ordering')
    need(unit['DefaultDependencies'] == 'no'
         and unit['RefuseManualStart'] == 'yes',
         'unsupported installation unit semantics')
    need(service['Type'] == 'simple' and service['Restart'] == 'no',
         'unsupported installation service semantics')
    need(all(isinstance(credentials.get(k), list) and len(credentials[k]) == 4
             and all(type(v) is int and 0 < v < 2**32 - 1
                     for v in credentials[k]) for k in ('uids', 'gids'))
         and isinstance(credentials.get('groups'), list)
         and all(type(v) is int and 0 <= v < 2**32 - 1
                 for v in credentials['groups']),
         'ordinary installation identity required')
    need(service['User'] == str(credentials['uids'][1])
         and service['Group'] == str(credentials['gids'][1])
         and credentials['uids'][1] > 0 and credentials['gids'][1] > 0,
         'ordinary installation identity required')
    tokens = shlex.split(service['ExecStart'])
    need(tokens == [payload_path],
         'installation ExecStart must bind the captured payload without arguments')
    need(install['WantedBy'] == 'multi-user.target',
         'unsupported enablement target')
    return dict(user=service['User'], group=service['Group'],
                execstart=tokens[0], wanted_by=install['WantedBy'],
                ordering_required=ordering_required,
                after=unit['After'] if ordering_required else None,
                requires=unit['Requires'] if ordering_required else None)


def verify_captured(rows, *, config, binding, root, credentials, kernel,
                    boundary_ns):
    """Re-derive the captured ordinary origin from raw rows and kernel
    originals only. Shared by the online install gate and the sealed
    replay; no filesystem re-read, no name/time fallback."""
    config = validate_profile(config)
    need(rows and [r['monotonic_ns'] for r in rows]
         == sorted(r['monotonic_ns'] for r in rows), 'install source order')
    kinds = {}
    for i, row in enumerate(rows):
        kinds.setdefault(row['kind'], []).append((i + 1, row))
    for name in ('intent', 'fresh', 'ready'):
        need(len(kinds.get(name, [])) == 1, 'missing/duplicate ' + name)
    intent, fresh, ready = [kinds[k][0][1] for k in ('intent', 'fresh',
                                                     'ready')]
    need(intent['source'] == SOURCE and intent['config'] == config
         and intent['binding'] == binding and intent['root'] == root,
         'install independent expectation mismatch')
    manager = config['manager']
    validate_fresh(fresh['units'], config)
    need(fresh['absent'] == unit_names_for(config)
         and fresh['peer'] == [manager['pid'], manager['uids'][1],
                               manager['gids'][1]],
         'manager/freshness conflict')
    boot = binding['boot_id']
    need(root['boot_id'] == boot, 'install boot conflict')
    root_key = (root['pid'], root['start_time'])
    members, seen = {root_key}, {root_key}

    def live(actor, ns):
        for event in kernel:
            if event['monotonic_ns'] > ns:
                break
            key = (event['pid'], event['birth'])
            need(key in members
                 and (event['root_pid'], event['root_birth']) == root_key,
                 'foreign kernel member')
            if event['kind'] == 'fork':
                child = (event['detail'][0], str(event['detail'][1]))
                need(child not in seen, 'reused child')
                seen.add(child)
                members.add(child)
            elif event['kind'] == 'exit':
                members.remove(key)
        return (actor['pid'], actor['birth']) in members

    names = set(artifact_names_for(config))
    closes = kinds.get('closed-write', [])
    need(len(closes) == len(names), 'one version of every origin artifact required')
    files, writes = {}, {}
    for number, row in closes:
        value, actor = row['file'], row['actor']
        name = Path(value['path']).name
        need(name in names and name not in files
             and value['path'] == str(Path(config['directory']) / name),
             'foreign/duplicate artifact')
        raw = base64.b64decode(value['content'], validate=True)
        need(len(raw) == value['size'] and sha(raw) == value['sha256']
             and row.get('lease') == 'F_RDLCK', 'unbound origin content')
        need((actor['pid'], actor['birth']) == root_key,
             'origin author is not the ordinary sample root')
        need(actor['uids'] == credentials['uids']
             and actor['gids'] == credentials['gids']
             and actor['groups'] == credentials['groups'],
             'unknown/dead writer identity')
        need(live(actor, row['monotonic_ns']), 'writer outside the author liveness window')
        dev = (os.major(value['device']) << 20) | os.minor(value['device'])
        need(any(e['kind'] == 'modify' and (e['pid'], e['birth']) == root_key
                 and e['monotonic_ns'] < row['monotonic_ns']
                 and not e['strings_may_be_truncated']
                 and e['detail'][:3] == [name, intent['directory_inode'], dev]
                 and e['detail'][3] > 0 for e in kernel),
             'actual content write missing')
        files[name] = (value, raw)
        writes[name] = (number, row)
    payload, service = files[config['payload']], files[config['service']]
    need(payload[1].startswith(b'\x7fELF'), 'only native ELF payload supported')
    unit = parse_installation_unit(service[1], credentials, payload[0]['path'])
    root_execs = [e for e in kernel if e['kind'] == 'exec'
                  and (e['pid'], e['birth']) == root_key]
    root_exits = [e for e in kernel if e['kind'] == 'exit'
                  and (e['pid'], e['birth']) == root_key]
    need(len(root_execs) == 1
         and ready['monotonic_ns'] < root_execs[0]['monotonic_ns'],
         'origin root exec missing or unready')
    payload_write = writes[config['payload']][1]
    service_write = writes[config['service']][1]
    need(root_execs[0]['monotonic_ns'] < payload_write['monotonic_ns']
         < service_write['monotonic_ns'],
         'origin write order missing (payload must precede the definition)')
    need(len(root_exits) == 1, 'actual root exit missing')
    need(service_write['monotonic_ns'] < root_exits[0]['monotonic_ns']
         <= boundary_ns, 'install window/order conflict')
    return dict(files=files, writes=writes, unit=unit,
                root_exec_ns=root_execs[0]['monotonic_ns'],
                root_exit_ns=root_exits[0]['monotonic_ns'])


def _parse_ordering(stdout):
    """Parse the fixed `systemctl show --property=After,Requires` output."""
    values = {}
    for line in stdout.splitlines():
        if not line.strip():
            continue
        need('=' in line, 'unparsed ordering show line', line)
        key, value = line.split('=', 1)
        need(key in ORDERING_PROPERTIES and key not in values,
             'unexpected ordering property', key)
        values[key] = sorted(token for token in value.split() if token)
    need(set(values) == set(ORDERING_PROPERTIES),
         'missing ordering property')
    return dict(after=values['After'], requires=values['Requires'])


def _parse_show(stdout):
    properties = {}
    for line in stdout.splitlines():
        need('=' in line, 'unparsed systemctl show line', line)
        key, value = line.split('=', 1)
        need(key not in properties, 'duplicate property', key)
        properties[key] = value
    for key in SHOW_INSTALL_PROPERTIES:
        need(key in properties, 'missing property', key)
    return properties


def _parse_loaded_execstart(text):
    need(isinstance(text, str) and text.startswith('{') and text.endswith('}'),
         'loaded ExecStart structure unsupported', repr(text[:80]))
    segments = [segment.strip() for segment in text[1:-1].split(' ; ')]
    path = argv = None
    for segment in segments:
        if segment.startswith('path='):
            need(path is None, 'loaded ExecStart structure unsupported')
            path = segment[len('path='):]
            if len(path) >= 2 and path.startswith('"') and path.endswith('"'):
                path = path[1:-1]
            need(path and '"' not in path and '\\' not in path,
                 'loaded ExecStart structure unsupported', repr(path))
        elif segment.startswith('argv[]='):
            need(argv is None, 'loaded ExecStart structure unsupported')
            argv = shlex.split(segment[len('argv[]='):])
        elif segment.startswith(('start_time=', 'stop_time=')):
            value = segment.split('=', 1)[1]
            need(re.fullmatch(r'\[[^\[\]{};"\\\r\n\t]*\]', value) is not None,
                 'loaded ExecStart structure unsupported', repr(segment[:60]))
        else:
            need('=' in segment and ' ' not in segment
                 and '"' not in segment and '\\' not in segment,
                 'loaded ExecStart structure unsupported', repr(segment[:60]))
    need(path is not None and argv is not None,
         'loaded ExecStart structure unsupported')
    return path, argv


def check_installed_show(properties, profile, captured):
    """The persistent unit must actually load with the captured bytes,
    stay enabled and inactive, and carry no invocation."""
    payload_path = captured['files'][profile['payload']][0]['path']
    need(properties['Id'] == profile['service'], 'unit id mismatch',
         properties['Id'])
    need(properties['LoadState'] == 'loaded', 'unit not loaded',
         properties['LoadState'])
    need(properties['ActiveState'] == 'inactive', 'unit must stay inactive',
         properties['ActiveState'])
    need(properties['SubState'] == 'dead', 'unit substate must be dead',
         properties['SubState'])
    need(properties['UnitFileState'] == 'enabled', 'unit not enabled',
         properties['UnitFileState'])
    need(properties['Transient'] == 'no', 'transient unit refused')
    need(properties['NeedDaemonReload'] == 'no', 'daemon reload pending')
    need(properties['DropInPaths'] == '', 'drop-ins unbound',
         properties['DropInPaths'])
    need(properties['InvocationID'] == '', 'unit must have no invocation',
         properties['InvocationID'])
    need(properties['MainPID'] == '0' and properties['ExecMainPID'] == '0',
         'inactive unit must have no main pid')
    need(properties['FragmentPath'] == str(UNIT_DIRECTORY / profile['service']),
         'installed fragment path mismatch', properties['FragmentPath'])
    need(properties['User'] == captured['unit']['user']
         and properties['Group'] == captured['unit']['group'],
         'loaded ordinary identity mismatch')
    path, argv = _parse_loaded_execstart(properties['ExecStart'])
    need(path == payload_path and argv == [payload_path],
         'loaded ExecStart must bind the captured payload without arguments')


def qualify(rows, *, config, binding, root, credentials, kernel, boundary_ns):
    """Final replay: the captured ordinary origin AND the one trusted
    installation, both re-derived from preserved originals alone."""
    config = validate_profile(config)
    captured = verify_captured(rows, config=config, binding=binding, root=root,
                               credentials=credentials, kernel=kernel,
                               boundary_ns=boundary_ns)
    ends = [r for r in rows if r['kind'] == 'closed']
    need(len(ends) == 1 and not ends[0]['error']
         and not ends[0]['lease_broken'],
         'incomplete or mutable installation originals')
    intents = [r for r in rows if r['kind'] == 'install-intent']
    results = [r for r in rows if r['kind'] == 'install-result']
    refusals = [r for r in rows if r['kind'] == 'install-refused']
    need(len(intents) == 1 and len(results) == 1 and not refusals,
         'trusted installation missing or ambiguous')
    intent, result = intents[0], results[0]
    manager = config['manager']
    unit_target = UNIT_DIRECTORY / config['service']
    link_target = WANTS_DIRECTORY / config['service']
    need(captured['root_exit_ns'] < intent['monotonic_ns']
         < result['monotonic_ns'] < ends[0]['monotonic_ns'] <= boundary_ns,
         'installation order conflict')
    need(intent['peer'] == [manager['pid'], 0, 0], 'foreign install peer',
         repr(intent.get('peer')))
    identity = intent.get('manager')
    need(isinstance(identity, dict) and identity.get('pid') == 1
         and identity.get('uids') == [0] * 4 and identity.get('gids') == [0] * 4,
         'installer is not the pid1 root manager')
    need(all(identity.get(k) == manager.get(k) for k in
             ('pid', 'birth', 'uids', 'gids', 'groups', 'image',
              'image_sha256', 'device', 'inode', 'cgroup', 'cmdline')),
         'install manager identity conflict')
    source = intent.get('source') or {}
    for label in ('payload', 'service'):
        held = captured['files'][config[label]][0]
        recorded = source.get(label) or {}
        need(all(recorded.get(k) == held[k] for k in
                 ('path', 'inode', 'device', 'size', 'sha256')),
             'install source original mismatch', label)
    need(intent.get('unit_target') == str(unit_target)
         and intent.get('link') == str(link_target)
         and intent.get('reload_argv') == list(RELOAD_ARGV),
         'install intent plan mismatch')
    destination = result.get('destination') or {}
    service_value = captured['files'][config['service']][0]
    need(destination.get('path') == str(unit_target)
         and destination.get('sha256') == service_value['sha256']
         and destination.get('size') == service_value['size']
         and destination.get('mode') == 0o644 and destination.get('uid') == 0
         and type(destination.get('inode')) is int
         and type(destination.get('device')) is int,
         'installed unit destination mismatch')
    link = result.get('link') or {}
    need(link.get('path') == str(link_target)
         and link.get('target') == str(unit_target)
         and link.get('uid') == 0 and type(link.get('inode')) is int,
         'enablement link mismatch')
    protection = result.get('protection') or {}
    need(protection.get('payload', {}).get('mode') == 0o555
         and protection.get('payload', {}).get('uid') == 0
         and protection.get('directory', {}).get('mode') == 0o555
         and protection.get('directory', {}).get('uid') == 0,
         'origin protection mismatch')
    reload_result = result.get('reload') or {}
    need(reload_result.get('argv') == list(RELOAD_ARGV)
         and reload_result.get('rc') == 0
         and isinstance(reload_result.get('stdout'), str)
         and isinstance(reload_result.get('stderr'), str),
         'daemon reload unconfirmed')
    show = result.get('show') or {}
    need(show.get('argv') == show_argv(config['service'])
         and show.get('rc') == 0, 'installed show unconfirmed')
    check_installed_show(_parse_show(show.get('stdout', '')), config, captured)
    cat = result.get('cat') or {}
    need(cat.get('argv') == cat_argv(config['service']) and cat.get('rc') == 0,
         'installed cat unconfirmed')
    service_raw = captured['files'][config['service']][1]
    need('# ' + str(unit_target) in (cat.get('stdout') or '')
         and service_raw.decode() in (cat.get('stdout') or ''),
         'cat does not reproduce the captured unit bytes')
    ordering = result.get('ordering')
    if captured['unit']['ordering_required']:
        need(isinstance(ordering, dict)
             and set(ordering) == {'argv', 'rc', 'stdout', 'stderr',
                                   'after', 'requires'},
             'installed loaded ordering proof missing')
        need(ordering.get('argv') == ordering_argv(config['service'])
             and ordering.get('rc') == 0
             and isinstance(ordering.get('stdout'), str)
             and isinstance(ordering.get('stderr'), str),
             'installed loaded ordering proof argv/rc mismatch')
        derived = _parse_ordering(ordering['stdout'])
        need(derived == dict(after=ordering['after'],
                             requires=ordering['requires']),
             'installed loaded ordering tokens differ')
        need(JOURNALD_DEPENDENCY in ordering['after']
             and JOURNALD_DEPENDENCY in ordering['requires'],
             'installed loaded ordering lacks the journald dependency')
    else:
        need('ordering' not in result,
             'legacy installation must not carry an ordering proof')
    version = sha(json.dumps([service_value['sha256'],
                              captured['files'][config['payload']][0]['sha256']],
                             separators=(',', ':')).encode())
    instance = dict(boot_id=binding['boot_id'], pid=root['pid'],
                    start_time=root['start_time'])
    numbers = {}
    for i, row in enumerate(rows, 1):
        if row['kind'] in ('install-intent', 'install-result'):
            numbers[row['kind']] = i
    payload_write = captured['writes'][config['payload']]
    service_write = captured['writes'][config['service']]
    return [dict(kind='artifact', instance=instance,
                 artifact_path=captured['files'][config['payload']][0]['path'],
                 artifact_sha256=captured['files'][config['payload']][0]['sha256'],
                 monotonic_ns=payload_write[1]['monotonic_ns'],
                 source_rows=[payload_write[0]]),
            dict(kind='definition', instance=instance,
                 artifact_path=captured['files'][config['payload']][0]['path'],
                 definition_id='system:' + config['service'],
                 definition_mechanism='boot-install', definition_version=version,
                 definition_binds_sha256=captured['files'][config['payload']][0]['sha256'],
                 monotonic_ns=service_write[1]['monotonic_ns'],
                 install_ref=dict(unit_path=str(unit_target),
                                  unit_sha256=service_value['sha256'],
                                  link=str(link_target),
                                  reload_rc=reload_result['rc'],
                                  installer=dict(pid=identity['pid'], uid=0),
                                  source_rows=[numbers['install-intent'],
                                               numbers['install-result']]),
                 source_rows=[service_write[0], numbers['install-intent'],
                              numbers['install-result']])]


def normalize(rows, **arguments):
    """Final replay requires actual closure, never a fabricated close."""
    ends = [r for r in rows if r['kind'] == 'closed']
    need(len(ends) == 1 and not ends[0]['error'] and not ends[0]['lease_broken'],
         'incomplete or mutable installation originals')
    return qualify(rows, boundary_ns=ends[0]['monotonic_ns'], **arguments)


class InstallationCollector(Collector):
    """Captured ordinary origin plus ONE trusted persistent installation.

    The fanotify drain, held read leases and snapshots come from the
    shared Collector; this specialization never probes an invocation,
    never extends the kernel scope and never emits a scheduler-fire. The
    single trusted management action happens only after the captured
    originals, the ordinary author and the actual root exit pass the
    independent kernel-prefix verification, and only once.
    """

    def __init__(self, config, output, binding, root, credentials, client):
        self.credentials = credentials
        self.client = client
        self.install_attempted = False
        super().__init__(config, output, binding, root)

    def tick(self):
        self.install_origin()

    def kernel_prefix(self):
        from velociraptor_linux_probe import decode
        path = self.output.parent / 'generations/1/raw.ndjson'
        raw = path.read_bytes()
        need(len(raw) <= 16 * 1024 * 1024, 'kernel prefix bound')
        # A pipe write may end mid-line. Only complete physical records qualify.
        complete = raw[:raw.rfind(b'\n') + 1]
        events = []
        for line in complete.splitlines():
            if line.strip():
                event = decode(line, 1)
                if event['kind'] not in ('ready', 'end'):
                    events.append(event)
        need(events and [e['monotonic_ns'] for e in events] ==
             sorted(e['monotonic_ns'] for e in events), 'kernel prefix order')
        return events, dict(path=str(path), size=len(complete),
                            sha256=sha(complete))

    def stable_read(self, fd, held, name):
        before = os.fstat(fd)
        raw = os.pread(fd, held['size'] + 1, 0)
        after = os.fstat(fd)
        need((before.st_ino, before.st_dev, before.st_size)
             == (after.st_ino, after.st_dev, after.st_size)
             and len(raw) == held['size'] and sha(raw) == held['sha256'],
             'held origin changed', name)
        return raw

    def install_origin(self):
        if self.install_attempted:
            return
        if len(self.leases) < len(artifact_names_for(self.config)):
            return
        try:
            need(not self.error and not self.lease_broken
                 and not self.finish_event.is_set(),
                 'install source unhealthy')
            need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()
                 == self.binding['boot_id'], 'install boot conflict')
            with self.lock:
                rows = list(self.records)
            kernel, prefix = self.kernel_prefix()
            captured = verify_captured(rows, config=self.config,
                                       binding=self.binding, root=self.root,
                                       credentials=self.credentials,
                                       kernel=kernel,
                                       boundary_ns=time.monotonic_ns())
            self.perform_installation(captured, kernel, prefix)
            self.install_attempted = True
        except Exception as error:
            # The kernel prefix is a pipe drain: the actual root exit can
            # still be in flight milliseconds after the waitpid observation.
            # That single transient is retried (throttled) for the rest of
            # the bounded window instead of consuming the one install.
            if 'actual root exit missing' in str(error) and not self.error \
                    and not self.finish_event.is_set():
                return
            self.install_attempted = True
            self.record('install-refused',
                        error=type(error).__name__ + ':' + str(error))

    def perform_installation(self, captured, kernel, prefix):
        config = self.config
        payload_held = self.leases[config['payload']][1]
        service_held = self.leases[config['service']][1]
        payload_raw = self.stable_read(self.leases[config['payload']][0],
                                       payload_held, config['payload'])
        service_raw = self.stable_read(self.leases[config['service']][0],
                                       service_held, config['service'])
        manager = config['manager']
        identity = process(manager['pid'])
        need(all(identity[k] == manager[k] for k in
                 ('birth', 'uids', 'gids', 'image', 'image_sha256')),
             'install manager drift')
        fresh = {name: {key: self.manager.get(name, 'Unit', key, signature)
                        for key, signature in
                        [('LoadState', 's'), ('ActiveState', 's'),
                         ('FragmentPath', 's'), ('ActivationDetails', 'a(ss)'),
                         ('InvocationID', 'ay')]}
                 for name in unit_names_for(config)}
        validate_fresh(fresh, config)
        need(self.manager.peer == [manager['pid'], manager['uids'][1],
                                   manager['gids'][1]], 'foreign install peer')
        unit_target = UNIT_DIRECTORY / config['service']
        link_target = WANTS_DIRECTORY / config['service']
        for parent in (UNIT_DIRECTORY, WANTS_DIRECTORY):
            st = parent.lstat()
            need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0
                 and not st.st_mode & 0o022, 'unprotected system directory',
                 str(parent))
        need(not unit_target.exists() and not unit_target.is_symlink(),
             'unit target already exists')
        need(not link_target.exists() and not link_target.is_symlink(),
             'enable link already exists')
        self.record('install-intent', manager=identity, peer=self.manager.peer,
                    unit_target=str(unit_target), link=str(link_target),
                    reload_argv=list(RELOAD_ARGV),
                    source=dict(payload=payload_held, service=service_held),
                    kernel_prefix=prefix,
                    root_exit_ns=captured['root_exit_ns'])
        # 1 one exclusive persistent unit copy, root:root 0644
        fd = os.open(unit_target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(service_raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(unit_target, 0, 0)
        os.chmod(unit_target, 0o644)
        installed = unit_target.stat()
        need(installed.st_size == service_held['size']
             and sha(service_raw) == service_held['sha256'],
             'installed unit bytes differ')
        # 2 the captured payload and directory become root-protected 0555;
        #   the unit's ordinary User/Group semantics are untouched
        protection = {}
        for label, path in (('payload', self.directory / config['payload']),
                            ('directory', self.directory)):
            os.chown(path, 0, 0)
            os.chmod(path, 0o555)
            st = path.stat()
            protection[label] = dict(path=str(path), uid=st.st_uid,
                                     mode=stat.S_IMODE(st.st_mode))
        # 3 one exclusive root-protected enablement symlink
        os.symlink(str(unit_target), link_target)
        link_stat = link_target.lstat()
        need(stat.S_ISLNK(link_stat.st_mode) and link_stat.st_uid == 0
             and os.readlink(link_target) == str(unit_target),
             'enable link not bound')
        # 4 one fixed daemon-reload; never a start/restart/payload execution
        result = subprocess.run(RELOAD_ARGV, capture_output=True, text=True,
                                timeout=20)
        self.record('reload-result', argv=list(RELOAD_ARGV),
                    rc=result.returncode, stdout=result.stdout,
                    stderr=result.stderr)
        need(result.returncode == 0, 'daemon reload unknown')
        # 5 independent fixed show/cat proof of the actual load
        show = subprocess.run(show_argv(config['service']),
                              capture_output=True, text=True, timeout=20)
        cat = subprocess.run(cat_argv(config['service']),
                             capture_output=True, text=True, timeout=20)
        need(show.returncode == 0 and cat.returncode == 0,
             'installed unit proof failed')
        parsed = parse_installation_unit(service_raw, self.credentials,
                                         str(self.directory / config['payload']))
        ordering_record = None
        if parsed['ordering_required']:
            ordering = subprocess.run(ordering_argv(config['service']),
                                      capture_output=True, text=True,
                                      timeout=20)
            need(ordering.returncode == 0,
                 'installed loaded ordering proof failed')
            derived = _parse_ordering(ordering.stdout)
            need(JOURNALD_DEPENDENCY in derived['after']
                 and JOURNALD_DEPENDENCY in derived['requires'],
                 'installed loaded ordering lacks the journald dependency')
            ordering_record = dict(argv=ordering_argv(config['service']),
                                   rc=ordering.returncode,
                                   stdout=ordering.stdout,
                                   stderr=ordering.stderr, **derived)
        self.record('install-result',
                    destination=dict(path=str(unit_target),
                                     inode=installed.st_ino,
                                     device=installed.st_dev,
                                     mode=stat.S_IMODE(installed.st_mode),
                                     uid=installed.st_uid, gid=installed.st_gid,
                                     size=installed.st_size,
                                     sha256=sha(service_raw)),
                    link=dict(path=str(link_target),
                              target=os.readlink(link_target),
                              inode=link_stat.st_ino, device=link_stat.st_dev,
                              uid=link_stat.st_uid),
                    protection=protection,
                    reload=dict(argv=list(RELOAD_ARGV), rc=result.returncode,
                                stdout=result.stdout, stderr=result.stderr),
                    show=dict(argv=show_argv(config['service']),
                              rc=show.returncode, stdout=show.stdout,
                              stderr=show.stderr),
                    cat=dict(argv=cat_argv(config['service']),
                             rc=cat.returncode, stdout=cat.stdout,
                             stderr=cat.stderr),
                    **({'ordering': ordering_record}
                       if ordering_record is not None else {}))
        self.install = dict(unit=str(unit_target), link=str(link_target))

    def close(self):
        if not self.closed and not self.install_attempted:
            self.record('install-refused',
                        error='no complete captured origin before close')
        # No unit stop and no journal fetch: this unit was never started,
        # stays enabled-inactive and is removed only by the round's precise
        # uninstall. Release the drain and held leases without touching it.
        self.finish_event.set()
        if self.thread:
            self.thread.join(2)
            need(not self.thread.is_alive(), 'install drain stop unknown')
        elif self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
        if self.manager:
            self.manager.close()
        signal.signal(signal.SIGIO, self.old_sigio)
        self.record('closed', error=self.error, lease_broken=self.lease_broken)
        os.fsync(self.stream.fileno())
        self.stream.close()
        self.closed = True
