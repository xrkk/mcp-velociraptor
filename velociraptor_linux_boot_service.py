"""Read-only late-attach evidence producer for an already-running system service.

The existing scheduler collector proves a *fresh* first invocation and refuses
any unit that already exists, so it cannot describe the ordinary-UID service
that systemd started by itself at boot. This module observes such an existing
invocation without starting, restarting or enabling anything: the system
manager peer is authenticated against the real PID1 over /run/systemd/private,
unit properties come from fixed-argv systemctl calls, and the live process,
definition fragment and payload image are read through /proc and stable-file
reads. Every request/response is preserved in an exclusive output directory
and the decoder re-derives the same observation from those originals.

Honest late-attach boundaries are part of the output: this producer never
claims the pre-observation start instant, the installing authority, or any
cross-boot causality. verified/source_nature can never be supplied by the
caller; no scheduler-fire verdict is produced here.
"""
import base64
import json
import os
import re
import shlex
import stat
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from velociraptor_linux_scheduler import PrivateManager, process, sha

SOURCE = 'MalTrace.SystemBootService.v1'
MANAGER_SOCKET = '/run/systemd/private'
KERNEL_BOOT = '/proc/sys/kernel/random/boot_id'
KERNEL_VM = '/sys/class/dmi/id/product_uuid'
ETC_UNITS = Path('/etc/systemd/system')
PROFILE_FIELDS = {'unit_name', 'vm_uuid', 'boot_id', 'expected_uid',
                  'payload_path', 'fragment_path', 'payload_sha256',
                  'fragment_sha256', 'window_seconds'}
FORBIDDEN_FIELDS = ('pid', 'birth', 'invocation_id', 'invocationid',
                    'verified', 'source_nature', 'command', 'shell', 'argv')
SHOW_PROPERTIES = ('Id', 'FragmentPath', 'DropInPaths', 'LoadState',
                   'ActiveState', 'SubState', 'InvocationID', 'UnitFileState',
                   'Transient', 'NeedDaemonReload', 'ExecMainStartTimestampMonotonic',
                   'MainPID', 'ExecMainPID', 'User', 'Group', 'ExecStart',
                   'ControlGroup')
PAYLOAD_INLINE_LIMIT = 16 * 1024 * 1024
LIMITATIONS = [
    'prior author/installation origin not proven by this producer',
    'early execution before readiness not captured',
    'cross-boot autonomy requires independently sealed A source and confirmed host bridge',
]


class BootServiceError(ValueError):
    def __init__(self, code, detail=''):
        super().__init__(code + (': ' + detail if detail else ''))
        self.code = code


def need(condition, code, detail=''):
    if not condition:
        raise BootServiceError(code, detail)


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':')) + '\n'


def _now_mono():
    return time.monotonic_ns()


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def show_argv(unit_name):
    return ['systemctl', 'show', unit_name,
            '--property=' + ','.join(SHOW_PROPERTIES)]


def cat_argv(unit_name):
    return ['systemctl', 'cat', unit_name]


# -- native boundary seams (tests replace these, production reads the host) --
def read_kernel_identity():
    return {'boot_id': Path(KERNEL_BOOT).read_text().strip(),
            'vm_uuid': Path(KERNEL_VM).read_text().strip().lower(),
            'reads': {KERNEL_BOOT: 'kernel file', KERNEL_VM: 'kernel file'}}


def manager_identity(pid=1):
    return process(pid)


def open_manager(socket_path, expected):
    return PrivateManager(socket_path, expected)


def run_command(argv, timeout):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return {'argv': list(argv), 'rc': result.returncode,
            'stdout': result.stdout, 'stderr': result.stderr}


def read_exe(pid):
    return (Path('/proc') / str(pid) / 'exe').read_bytes()


def process_identity(pid):
    return process(pid)


def stable_file_read(path):
    """One file, read through a no-follow fd, stat pinned before and after."""
    path = Path(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
         'not a single regular file', str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        data = stream.read()
    after = path.lstat()
    need((before.st_dev, before.st_ino, before.st_size)
         == (after.st_dev, after.st_ino, after.st_size)
         and before.st_nlink == after.st_nlink == 1, 'file changed during read',
         str(path))
    return dict(path=str(path), size=before.st_size,
                device=before.st_dev, inode=before.st_ino, nlink=before.st_nlink,
                uid=before.st_uid, mode=stat.S_IMODE(before.st_mode),
                sha256=sha(data),
                content=base64.b64encode(data).decode()
                if len(data) <= PAYLOAD_INLINE_LIMIT else None)


# -- profile ---------------------------------------------------------------
def validate_profile(profile):
    need(isinstance(profile, dict), 'profile must be an object')
    for key in FORBIDDEN_FIELDS:
        need(key not in profile, 'caller supplied forbidden field', key)
    need(set(profile) == PROFILE_FIELDS, 'profile fields',
         'expected exactly %r' % sorted(PROFILE_FIELDS))
    unit = profile['unit_name']
    need(isinstance(unit, str) and re.fullmatch(r'[a-zA-Z0-9_.-]{1,30}', unit)
         and unit.endswith('.service') and '/' not in unit,
         'unit_name must be a short flat .service name')
    for key in ('vm_uuid', 'boot_id'):
        value = profile[key]
        need(isinstance(value, str)
             and str(uuid.UUID(value)) == value.lower(),
             key + ' must be a canonical lowercase UUID')
    uid = profile['expected_uid']
    need(type(uid) is int and not isinstance(uid, bool) and 0 < uid < 2 ** 31,
         'expected_uid must be a non-boolean positive ordinary UID')
    for key in ('payload_path', 'fragment_path'):
        value = profile[key]
        need(isinstance(value, str) and os.path.isabs(value)
             and value == os.path.normpath(value) and '..' not in value.split(os.sep),
             key + ' must be a canonical absolute path')
    need(profile['payload_path'] != profile['fragment_path'],
         'payload and fragment must be distinct files')
    for key in ('payload_sha256', 'fragment_sha256'):
        need(isinstance(profile[key], str)
             and re.fullmatch(r'[0-9a-f]{64}', profile[key]),
             key + ' must be lowercase 64 hex')
    window = profile['window_seconds']
    need(type(window) is int and not isinstance(window, bool)
         and 1 <= window <= 30, 'window_seconds must be an integer in 1..30')
    return dict(profile)


def parse_show(stdout):
    properties = {}
    for line in stdout.splitlines():
        need('=' in line, 'unparsed systemctl show line', line)
        key, value = line.split('=', 1)
        need(key not in properties, 'duplicate property', key)
        properties[key] = value
    for key in SHOW_PROPERTIES:
        need(key in properties, 'missing property', key)
    return properties


def fragment_execstart(fragment_bytes):
    for line in fragment_bytes.decode('utf-8', errors='strict').splitlines():
        if line.startswith('ExecStart='):
            return shlex.split(line[len('ExecStart='):])
    raise BootServiceError('fragment lacks ExecStart', '')


def fragment_user(fragment_bytes, expected_uid):
    for line in fragment_bytes.decode('utf-8', errors='strict').splitlines():
        if line.startswith('User='):
            need(line == 'User=%d' % (expected_uid,), 'fragment User mismatch',
                 line)
            return
    raise BootServiceError('fragment lacks ordinary User', '')


def validate_fragment_link(link, target_path, owner_uid):
    """Link-binding core shared by the production wrapper and the tests."""
    parent = link.parent
    st = parent.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == owner_uid
         and not st.st_mode & 0o022, 'unprotected fragment parent',
         str(parent))
    before = link.lstat()
    need(stat.S_ISLNK(before.st_mode) and before.st_uid == owner_uid,
         'fragment link not protected', str(link))
    target = os.readlink(link)
    need(target == str(target_path)
         and Path(target).resolve() == Path(target_path),
         'fragment link escapes or unbound', target)
    after = link.lstat()
    need((before.st_ino, before.st_dev, before.st_ctime_ns)
         == (after.st_ino, after.st_dev, after.st_ctime_ns),
         'fragment link changed during read')
    return dict(fragment_path=str(link), link_target=target,
                link_uid=before.st_uid, link_inode=before.st_ino,
                link_device=before.st_dev)


def _check_fragment_link(fragment_path, unit_name, original_path):
    """FragmentPath may be the protected /etc/systemd/system symlink."""
    link = ETC_UNITS / unit_name
    need(fragment_path == str(link), 'fragment path conflict', fragment_path)
    for parent in (Path('/etc'), ETC_UNITS):
        st = parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0
             and not st.st_mode & 0o022, 'unprotected fragment parent',
             str(parent))
    return validate_fragment_link(link, original_path, 0)


def bind_fragment_path(properties, profile):
    fragment_path = properties['FragmentPath']
    binding = None
    if fragment_path == profile['fragment_path']:
        return None
    need(not fragment_path.startswith('/run/'), 'runtime fragment refused',
         fragment_path)
    binding = _check_fragment_link(fragment_path, profile['unit_name'],
                                   Path(profile['fragment_path']))
    return binding


def check_properties(properties, profile):
    need(properties['Id'] == profile['unit_name'], 'unit id mismatch',
         properties['Id'])
    need(properties['LoadState'] == 'loaded', 'unit not loaded',
         properties['LoadState'])
    need(properties['ActiveState'] == 'active', 'unit not active',
         properties['ActiveState'])
    need(properties['SubState'] == 'running', 'unit substate not running',
         properties['SubState'])
    need(properties['Transient'] == 'no', 'transient unit refused')
    need(properties['NeedDaemonReload'] == 'no', 'daemon reload pending')
    need(properties['UnitFileState'] == 'enabled', 'unit not enabled',
         properties['UnitFileState'])
    need(properties['DropInPaths'] == '', 'drop-ins unbound',
         properties['DropInPaths'])
    need(re.fullmatch(r'[0-9a-f]{32}', properties['InvocationID']),
         'invocation id invalid', properties['InvocationID'])
    main_pid = properties['MainPID']
    need(main_pid.isdigit() and int(main_pid) > 0, 'no live main pid', main_pid)
    need(properties['User'] == str(profile['expected_uid']),
         'loaded User mismatch', properties['User'])
    need(re.fullmatch(r'\d+', properties['ExecMainStartTimestampMonotonic']),
         'no native start time', properties['ExecMainStartTimestampMonotonic'])
    need(profile['payload_path'] in properties['ExecStart'],
         'loaded ExecStart mismatch', properties['ExecStart'])
    return int(main_pid)


def check_process_facts(facts, profile, expected_argv):
    need(facts['uids'] == [profile['expected_uid']] * 4, 'uid mismatch',
         repr(facts['uids']))
    need(all(value != 0 for value in facts['uids'] + facts['gids']),
         'root identity refused', repr((facts['uids'], facts['gids'])))
    need(facts['image'] == profile['payload_path'], 'exec image mismatch',
         facts['image'])
    need(facts['cmdline'] == expected_argv, 'cmdline mismatch',
         repr(facts['cmdline']))
    need(('/' + profile['unit_name']) in facts['cgroup'], 'cgroup mismatch',
         facts['cgroup'])
    return True


def check_records(records, profile):
    """Pure decoder: re-derive the observation from raw records only."""
    validate_profile(profile)
    kinds = [record['kind'] for record in records]
    expected = ['intent', 'kernel-identity', 'manager-open', 'unit-show',
                'unit-cat', 'fragment', 'payload', 'process', 'recheck',
                'observation-complete']
    need(kinds == expected, 'raw record sequence', repr(kinds))
    for record in records:
        need('monotonic_ns' in record, 'record lacks monotonic time')
    need(records[-1]['monotonic_ns'] - records[0]['monotonic_ns']
         <= profile['window_seconds'] * 10 ** 9, 'window exceeded')

    need(records[0]['source'] == SOURCE, 'source mismatch')
    need(records[0]['profile'] == profile, 'intent profile mismatch')

    kernel = records[1]['value']
    need(kernel['boot_id'] == profile['boot_id'], 'wrong boot identity',
         kernel['boot_id'])
    need(kernel['vm_uuid'] == profile['vm_uuid'], 'wrong vm identity',
         kernel['vm_uuid'])

    manager = records[2]
    need(manager['socket'] == MANAGER_SOCKET, 'manager socket mismatch')
    need(manager['peer'] == [1, 0, 0], 'foreign manager peer',
         repr(manager['peer']))
    identity = manager['identity']
    need(identity['pid'] == 1 and identity['uids'] == [0] * 4
         and identity['gids'] == [0] * 4, 'manager not pid1 root',
         repr((identity['pid'], identity['uids'], identity['gids'])))

    show = records[3]
    need(show['argv'] == show_argv(profile['unit_name']), 'show argv mutated')
    need(show['rc'] == 0, 'systemctl show failed', str(show['rc']))
    properties = parse_show(show['stdout'])
    main_pid = check_properties(properties, profile)
    fragment_binding = bind_fragment_path(properties, profile)

    cat = records[4]
    need(cat['argv'] == cat_argv(profile['unit_name']), 'cat argv mutated')
    need(cat['rc'] == 0, 'systemctl cat failed', str(cat['rc']))
    need('# ' + (properties['FragmentPath']) in cat['stdout'],
         'cat lacks fragment marker')

    fragment = records[5]
    need(fragment['path'] == profile['fragment_path'], 'fragment path mismatch',
         fragment['path'])
    need(fragment['sha256'] == profile['fragment_sha256'],
         'fragment hash mismatch', fragment['sha256'])
    fragment_bytes = base64.b64decode(fragment['content'])
    need(sha(fragment_bytes) == fragment['sha256'],
         'fragment bytes contradict hash')
    execstart = fragment_execstart(fragment_bytes)
    need(execstart and execstart[0] == profile['payload_path'],
         'fragment ExecStart does not bind payload', repr(execstart[:1]))
    fragment_user(fragment_bytes, profile['expected_uid'])
    for token in execstart[1:]:
        need(token in properties['ExecStart'] or token in cat['stdout'],
             'fragment arguments absent from loaded definition', token)

    payload = records[6]
    need(payload['path'] == profile['payload_path'], 'payload path mismatch',
         payload['path'])
    need(payload['sha256'] == profile['payload_sha256'],
         'payload hash mismatch', payload['sha256'])

    facts = records[7]['value']
    need(records[7]['pid'] == main_pid, 'observed pid is not the main pid',
         str(records[7]['pid']))
    check_process_facts(facts, profile, execstart)
    need(facts['image_sha256'] == payload['sha256'], 'exec image hash mismatch',
         facts['image_sha256'])

    recheck = records[8]
    need(recheck['peer'] == [1, 0, 0], 'manager peer drifted on recheck')
    need(recheck['InvocationID'] == properties['InvocationID'],
         'invocation changed during read')
    need(recheck['MainPID'] == properties['MainPID'],
         'main pid changed during read')
    need(recheck['birth'] == facts['birth'], 'pid reused or replaced',
         recheck['birth'])
    for label, record in (('fragment', fragment), ('payload', payload)):
        again = recheck['files'][label]
        need((again['device'], again['inode'], again['size'], again['sha256'])
             == (record['device'], record['inode'], record['size'],
                 record['sha256']), label + ' replaced during read')
    need(recheck['manager_identity'] == identity, 'manager identity drifted')

    return build_observation(records, properties, fragment_binding, facts,
                             execstart, main_pid)


def build_observation(records, properties, fragment_binding, facts, execstart,
                      main_pid):
    fragment = records[5]
    payload = records[6]
    return {
        'schema': SOURCE,
        'kind': 'boot-service-observation',
        'vm_uuid': records[1]['value']['vm_uuid'],
        'boot_id': records[1]['value']['boot_id'],
        'unit': {
            'name': properties['Id'],
            'fragment_path': properties['FragmentPath'],
            'fragment_sha256': fragment['sha256'],
            'fragment_identity': dict(device=fragment['device'],
                                      inode=fragment['inode'],
                                      size=fragment['size']),
            'fragment_binding': fragment_binding,
            'invocation_id': properties['InvocationID'],
            'unit_file_state': properties['UnitFileState'],
            'started_at_monotonic': properties['ExecMainStartTimestampMonotonic'],
        },
        'payload': {
            'path': payload['path'],
            'sha256': payload['sha256'],
            'size': payload['size'],
            'identity': dict(device=payload['device'], inode=payload['inode']),
        },
        'actor': {
            'pid': main_pid,
            'birth': facts['birth'],
            'uid': facts['uids'][0],
            'gid': facts['gids'][0],
            'exe': facts['image'],
            'exe_sha256': facts['image_sha256'],
            'cgroup': facts['cgroup'],
            'cmdline': facts['cmdline'],
        },
        'manager': {
            'socket': records[2]['socket'],
            'peer': records[2]['peer'],
            'pid1': {key: records[2]['identity'][key]
                     for key in ('pid', 'birth', 'uids', 'gids', 'image',
                                 'image_sha256')},
        },
        'observed_at': records[-1]['observed_at'],
        'window_seconds': records[0]['profile']['window_seconds'],
        'execstart': execstart,
        'raw_refs': {
            'records': len(records),
            'pointers': {
                'vm_uuid': 'records[1].value.vm_uuid',
                'boot_id': 'records[1].value.boot_id',
                'manager_peer': 'records[2].peer',
                'invocation_id': 'records[3].stdout InvocationID',
                'main_pid': 'records[3].stdout MainPID',
                'fragment_sha256': 'records[5].sha256',
                'payload_sha256': 'records[6].sha256',
                'actor_pid': 'records[7].pid',
                'actor_birth': 'records[7].value.birth',
                'actor_uid': 'records[7].value.uids',
            },
        },
        'limitations': list(LIMITATIONS),
    }


class _RawWriter:
    def __init__(self, output):
        self.path = output / 'raw.ndjson'
        self.stream = self.path.open('xb', buffering=0)
        os.chmod(self.path, 0o600)
        self.count = 0

    def write(self, kind, **payload):
        self.count += 1
        record = dict(index=self.count, kind=kind,
                      monotonic_ns=_now_mono(), **payload)
        self.stream.write(_canonical(record).encode())
        return record

    def close(self):
        if self.stream is not None:
            self.stream.close()
            self.stream = None


def collect_boot_service(profile, output_directory):
    """Bounded read-only observation of one already-running system service.

    Returns (observation, bundle). All native access is read-only; nothing is
    started, restarted, enabled or reloaded. Any refusal still closes every
    descriptor and leaves the exclusive output directory behind as evidence.
    """
    profile = validate_profile(dict(profile))
    output = Path(output_directory)
    need(not output.exists() and not output.is_symlink()
         and output.parent.is_dir() and not output.parent.is_symlink(),
         'output directory must be new and exclusive', str(output))
    output.mkdir(mode=0o700)
    directory_stat = output.stat()
    raw = _RawWriter(output)
    manager = None
    error = None
    records = []
    try:
        records.append(raw.write('intent', source=SOURCE, profile=profile,
                                 output=str(output)))
        kernel = read_kernel_identity()
        records.append(raw.write('kernel-identity', value=kernel))
        need(kernel['boot_id'] == profile['boot_id'], 'wrong boot identity',
             kernel['boot_id'])
        need(kernel['vm_uuid'] == profile['vm_uuid'], 'wrong vm identity',
             kernel['vm_uuid'])

        identity = manager_identity(1)
        need(identity['pid'] == 1 and identity['uids'] == [0] * 4
             and identity['gids'] == [0] * 4, 'manager not pid1 root')
        manager = open_manager(MANAGER_SOCKET, identity)
        peer = list(manager.peer)
        records.append(raw.write('manager-open', socket=MANAGER_SOCKET,
                                 peer=peer, identity={
                                     key: identity[key] for key in
                                     ('pid', 'birth', 'uids', 'gids', 'image',
                                      'image_sha256')}))
        need(peer == [1, 0, 0], 'foreign manager peer', repr(peer))

        show = run_command(show_argv(profile['unit_name']),
                           profile['window_seconds'])
        records.append(raw.write('unit-show', **show))
        need(show['rc'] == 0, 'systemctl show failed', str(show['rc']))
        properties = parse_show(show['stdout'])
        main_pid = check_properties(properties, profile)
        fragment_binding = bind_fragment_path(properties, profile)

        cat = run_command(cat_argv(profile['unit_name']),
                          profile['window_seconds'])
        records.append(raw.write('unit-cat', **cat))
        need(cat['rc'] == 0, 'systemctl cat failed', str(cat['rc']))
        need('# ' + properties['FragmentPath'] in cat['stdout'],
             'cat lacks fragment marker')

        fragment = stable_file_read(profile['fragment_path'])
        records.append(raw.write('fragment', **fragment))
        need(fragment['sha256'] == profile['fragment_sha256'],
             'fragment hash mismatch', fragment['sha256'])
        fragment_bytes = base64.b64decode(fragment['content'])
        execstart = fragment_execstart(fragment_bytes)
        need(execstart[0] == profile['payload_path'],
             'fragment ExecStart does not bind payload')
        fragment_user(fragment_bytes, profile['expected_uid'])

        payload = stable_file_read(profile['payload_path'])
        records.append(raw.write('payload', **payload))
        need(payload['sha256'] == profile['payload_sha256'],
             'payload hash mismatch', payload['sha256'])

        facts = process_identity(main_pid)
        exe_bytes = read_exe(main_pid)
        records.append(raw.write('process', pid=main_pid, value=facts,
                                 exe_read_sha256=sha(exe_bytes),
                                 exe_read_size=len(exe_bytes)))
        need(sha(exe_bytes) == payload['sha256'], 'exec image hash mismatch')
        check_process_facts(facts, profile, execstart)

        identity_again = manager_identity(1)
        manager.close()
        manager = None
        facts_again = process_identity(main_pid)
        recheck_show = run_command(show_argv(profile['unit_name']),
                                   profile['window_seconds'])
        recheck_properties = parse_show(recheck_show['stdout']) \
            if recheck_show['rc'] == 0 else {}
        fragment_again = stable_file_read(profile['fragment_path'])
        payload_again = stable_file_read(profile['payload_path'])
        records.append(raw.write(
            'recheck', peer=peer, manager_identity={
                key: identity_again[key] for key in
                ('pid', 'birth', 'uids', 'gids', 'image', 'image_sha256')},
            InvocationID=recheck_properties.get('InvocationID'),
            MainPID=recheck_properties.get('MainPID'),
            birth=facts_again['birth'],
            files={'fragment': fragment_again, 'payload': payload_again}))
        need(identity_again['birth'] == identity['birth'],
             'manager identity drifted')
        need(recheck_show['rc'] == 0, 'recheck systemctl failed')
        need(recheck_properties['InvocationID'] == properties['InvocationID'],
             'invocation changed during read')
        need(recheck_properties['MainPID'] == str(main_pid),
             'main pid changed during read')
        need(facts_again['birth'] == facts['birth'],
             'pid reused or replaced')
        for label, first in (('fragment', fragment), ('payload', payload)):
            again = records[-1]['files'][label]
            need((again['device'], again['inode'], again['size'],
                  again['sha256'])
                 == (first['device'], first['inode'], first['size'],
                     first['sha256']), label + ' replaced during read')

        records.append(raw.write('observation-complete', observed_at=_now_iso(),
                                 records=raw.count))
        raw.close()
        raw = None
        observation = check_records(_load_records(output / 'raw.ndjson'),
                                    profile)
        files = {}
        for name in ('raw.ndjson', 'observation.json'):
            target = output / name
            if name == 'observation.json':
                data = _canonical(observation).encode()
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            st = target.stat()
            files[name] = dict(size=st.st_size, sha256=sha(target.read_bytes()),
                               inode=st.st_ino, device=st.st_dev)
        manifest = dict(source=SOURCE, directory=dict(
            device=directory_stat.st_dev, inode=directory_stat.st_ino,
            mode=stat.S_IMODE(directory_stat.st_mode)), files=files)
        manifest_path = output / 'manifest.json'
        data = _canonical(manifest).encode()
        fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        for name in ('raw.ndjson', 'observation.json', 'manifest.json'):
            os.chmod(output / name, 0o400)
        bundle = dict(output=str(output), manifest=manifest)
        return observation, bundle
    except BaseException as caught:
        error = caught
        raise
    finally:
        if raw is not None:
            try:
                raw.write('collection-error',
                          error=type(error).__name__ if error is not None
                          else 'unknown',
                          detail=str(error)[:400] if error is not None else '')
            except BaseException:
                pass
            raw.close()
        if manager is not None:
            manager.close()


def _load_records(path):
    records = []
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def normalize_boot_service(raw_bundle, expected_profile):
    """Re-derive and re-verify the observation from the preserved originals."""
    profile = validate_profile(dict(expected_profile))
    if isinstance(raw_bundle, (str, Path)):
        output = Path(raw_bundle)
        st = output.lstat()
        need(stat.S_ISDIR(st.st_mode) and not output.is_symlink(),
             'output replaced', str(output))
        need((output / 'manifest.json').is_file()
             and (output / 'raw.ndjson').is_file()
             and (output / 'observation.json').is_file(),
             'raw missing')
        manifest = json.loads((output / 'manifest.json').read_text())
        need(manifest['directory']['device'] == st.st_dev
             and manifest['directory']['inode'] == st.st_ino,
             'output replaced', str(output))
        for name, expected_file in manifest['files'].items():
            target = output / name
            need(target.is_file() and not target.is_symlink(), 'raw missing',
                 name)
            current = target.stat()
            need((current.st_ino, current.st_dev)
                 == (expected_file['inode'], expected_file['device']),
                 'original replaced with same bytes', name)
            need(sha(target.read_bytes()) == expected_file['sha256'],
                 'raw hash mismatch', name)
        records = _load_records(output / 'raw.ndjson')
    else:
        need(isinstance(raw_bundle, dict) and 'records' in raw_bundle,
             'bundle must be an output directory or a records bundle')
        records = raw_bundle['records']
    return check_records(records, profile)
