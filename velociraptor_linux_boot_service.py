"""Read-only late-attach evidence producer for an already-running system service.

The existing scheduler collector proves a *fresh* first invocation and refuses
any unit that already exists, so it cannot describe the ordinary-UID service
that systemd started by itself at boot. This module observes such an existing
invocation without starting, restarting or enabling anything: the system
manager peer is authenticated against the real PID1 over /run/systemd/private,
unit properties come from fixed-argv systemctl calls (recorded twice, in
full), and the live process, definition fragment, payload image and /proc exe
image are read through stable no-follow descriptors whose before/after fstat
identities are pinned to the opened object. Every request/response and every
read byte sequence is preserved in an exclusive output directory and the
decoder re-derives the same observation from those originals alone, never
re-reading the collection-time filesystem.

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
FRAGMENT_PARENTS = (Path('/etc'), ETC_UNITS)
FRAGMENT_LINK_OWNER = 0
RUNTIME_PREFIX = '/run/'
INLINE_LIMIT = 16 * 1024 * 1024
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
RECHECK_PROPERTIES = ('Id', 'FragmentPath', 'DropInPaths', 'LoadState',
                      'ActiveState', 'SubState', 'InvocationID', 'UnitFileState',
                      'Transient', 'NeedDaemonReload', 'MainPID', 'ExecMainPID',
                      'User', 'Group', 'ExecStart', 'ControlGroup')
RAW_FILES = ('raw.ndjson', 'observation.json')
DIRECTORY_FILES = frozenset(RAW_FILES) | {'manifest.json'}
PROCESS_FACT_KEYS = ('pid', 'birth', 'uids', 'gids', 'image', 'device',
                     'inode', 'image_sha256', 'cgroup', 'cmdline')
MANAGER_FACT_KEYS = ('pid', 'birth', 'uids', 'gids', 'image', 'image_sha256')
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
    """One regular file read through a no-follow descriptor.

    The before/after identities are fstat of the OPENED descriptor, so a path
    swap during the read cannot substitute different content. Oversized
    inputs are refused explicitly instead of being silently downgraded.
    """
    path = Path(path)
    path_stat = path.lstat()
    need(stat.S_ISREG(path_stat.st_mode) and path_stat.st_nlink == 1,
         'not a single regular file', str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        data = stream.read()
        after = os.fstat(stream.fileno())
    need(before.st_dev == after.st_dev and before.st_ino == after.st_ino,
         'file replaced during read', str(path))
    need(before.st_size == after.st_size == len(data),
         'file size changed during read', str(path))
    need(len(data) <= INLINE_LIMIT, 'evidence file exceeds bounded inline size',
         '%s (%d bytes)' % (path, len(data)))
    return dict(path=str(path), size=before.st_size,
                device=before.st_dev, inode=before.st_ino,
                nlink=before.st_nlink, uid=before.st_uid,
                mode=stat.S_IMODE(before.st_mode),
                sha256=sha(data),
                content=base64.b64encode(data).decode())


def bounded_bytes(data, label):
    need(len(data) <= INLINE_LIMIT, 'evidence file exceeds bounded inline size',
         '%s (%d bytes)' % (label, len(data)))
    return dict(content=base64.b64encode(data).decode(), size=len(data),
                sha256=sha(data))


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
             and value == os.path.normpath(value)
             and '..' not in value.split(os.sep),
             key + ' must be a canonical absolute path')
    need(profile['payload_path'] != profile['fragment_path'],
         'payload and fragment must be distinct files')
    need(not profile['fragment_path'].startswith(RUNTIME_PREFIX),
         'runtime fragment path refused', profile['fragment_path'])
    for key in ('payload_sha256', 'fragment_sha256'):
        need(isinstance(profile[key], str)
             and re.fullmatch(r'[0-9a-f]{64}', profile[key]),
             key + ' must be lowercase 64 hex')
    window = profile['window_seconds']
    need(type(window) is int and not isinstance(window, bool)
         and 1 <= window <= 30, 'window_seconds must be an integer in 1..30')
    return dict(profile)


def _split_quoted(text):
    """Split an argv[] segment of the fixed systemctl show format.

    Only plain tokens and complete double-quoted tokens are interpretable;
    embedded quotes, escapes or unterminated quoting are refused instead of
    guessed. No shell is ever involved.
    """
    tokens = []
    index, length = 0, len(text)
    while index < length:
        while index < length and text[index] == ' ':
            index += 1
        if index >= length:
            break
        if text[index] == '"':
            end = text.find('"', index + 1)
            need(end != -1, 'loaded ExecStart structure unsupported',
                 'unterminated quoted token')
            inner = text[index + 1:end]
            need('"' not in inner and '\\' not in inner,
                 'loaded ExecStart structure unsupported',
                 'uninterpretable quoting')
            tokens.append(inner)
            index = end + 1
            need(index >= length or text[index] == ' ',
                 'loaded ExecStart structure unsupported',
                 'uninterpretable quoting')
        else:
            end = text.find(' ', index)
            if end == -1:
                end = length
            token = text[index:end]
            need('"' not in token and '\\' not in token,
                 'loaded ExecStart structure unsupported',
                 'uninterpretable token')
            tokens.append(token)
            index = end
    return tokens


def parse_loaded_execstart(text):
    """Parse the fixed `systemctl show` ExecStart structure exactly.

    Supported form: `{ path=P ; argv[]=P t1 t2 ; key=value ; ... }` with at
    most one path segment and exactly one argv[] segment (one supported
    execution definition). Anything else is refused with a specific code;
    there is no substring, shlex or shell fallback.
    """
    need(isinstance(text, str) and text.startswith('{') and text.endswith('}'),
         'loaded ExecStart structure unsupported', repr(text[:80]))
    segments = [segment.strip() for segment in text[1:-1].split(' ; ')]
    need(len(segments) >= 2, 'loaded ExecStart structure unsupported',
         repr(text[:80]))
    path = None
    argv = None
    for segment in segments:
        if segment.startswith('path='):
            need(path is None, 'loaded ExecStart structure unsupported',
                 'multiple path segments')
            path = segment[len('path='):]
            if len(path) >= 2 and path.startswith('"') and path.endswith('"'):
                path = path[1:-1]
            need(path and '"' not in path and '\\' not in path,
                 'loaded ExecStart structure unsupported', repr(path))
        elif segment.startswith('argv[]='):
            need(argv is None, 'loaded ExecStart structure unsupported',
                 'multiple argv segments')
            argv = _split_quoted(segment[len('argv[]='):])
        else:
            need('=' in segment and ' ' not in segment
                 and '"' not in segment and '\\' not in segment,
                 'loaded ExecStart structure unsupported', repr(segment[:60]))
    need(path is not None, 'loaded ExecStart structure unsupported',
         'missing path segment')
    need(argv is not None, 'loaded ExecStart structure unsupported',
         'missing argv segment')
    return path, argv


def check_loaded_execstart(loaded_text, profile, fragment_argv=None):
    """Exact binding of the real loaded execution definition.

    The loaded path must equal the pinned payload path, the loaded argv must
    start with that same path, and once the fragment has been parsed the
    complete loaded argv must equal the fragment's real ExecStart argv.
    """
    path, argv = parse_loaded_execstart(loaded_text)
    need(path == profile['payload_path'], 'loaded ExecStart path mismatch',
         path)
    need(argv and argv[0] == path, 'loaded ExecStart argv head mismatch',
         repr(argv[:1]))
    if fragment_argv is not None:
        need(argv == fragment_argv,
             'loaded ExecStart argv differs from fragment',
             '%r vs %r' % (argv, fragment_argv))
    return path, argv


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
    """Link-binding core: protected parent, owned link, exact target."""
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
    target_stat = Path(target_path).stat()
    return dict(fragment_path=str(link), link_target=target,
                link_uid=before.st_uid, link_inode=before.st_ino,
                link_device=before.st_dev,
                target_inode=target_stat.st_ino,
                target_device=target_stat.st_dev)


def fragment_link_binding(fragment_path, unit_name, original_path):
    """Production wrapper: FragmentPath must be the protected /etc link."""
    link = ETC_UNITS / unit_name
    need(fragment_path == str(link), 'fragment path conflict', fragment_path)
    for parent in FRAGMENT_PARENTS:
        st = parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == FRAGMENT_LINK_OWNER
             and not st.st_mode & 0o022, 'unprotected fragment parent',
             str(parent))
    binding = validate_fragment_link(link, original_path, FRAGMENT_LINK_OWNER)
    binding['link_owner'] = FRAGMENT_LINK_OWNER
    return binding


def bind_fragment_path(properties, profile):
    """Runtime definitions are always refused; direct or /etc-link binding
    is decided only after the runtime check, never by name equality."""
    fragment_path = properties['FragmentPath']
    need(not fragment_path.startswith(RUNTIME_PREFIX),
         'runtime fragment refused', fragment_path)
    if fragment_path == profile['fragment_path']:
        return None
    return fragment_link_binding(fragment_path, profile['unit_name'],
                                 Path(profile['fragment_path']))


def check_binding_record(binding, properties, profile, fragment):
    """Pure replay of the link binding from collection-time raw evidence.

    Every comparison uses only recorded values: the decoder never re-reads
    the collection-time filesystem to reconstruct the binding.
    """
    if properties['FragmentPath'] == profile['fragment_path']:
        need(binding is None, 'unexpected fragment binding evidence')
        return None
    need(isinstance(binding, dict), 'fragment binding evidence missing')
    need(binding.get('fragment_path') == properties['FragmentPath'],
         'fragment binding link path mismatch',
         str(binding.get('fragment_path')))
    need(str(binding.get('fragment_path', '')).endswith(
        '/' + profile['unit_name']), 'fragment binding link path mismatch',
        str(binding.get('fragment_path')))
    need(binding.get('link_target') == profile['fragment_path'],
         'fragment link escapes or unbound', str(binding.get('link_target')))
    need(binding.get('link_uid') == binding.get('link_owner'),
         'fragment link not protected',
         repr((binding.get('link_uid'), binding.get('link_owner'))))
    need(binding.get('target_device') == fragment['device']
         and binding.get('target_inode') == fragment['inode'],
         'fragment binding does not pin the original',
         '%r vs %r' % ((binding.get('target_device'),
                         binding.get('target_inode')),
                        (fragment['device'], fragment['inode'])))
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
    check_loaded_execstart(properties['ExecStart'], profile)
    return int(main_pid)


def _cgroup_path(value):
    text = str(value).strip()
    return text[3:] if text.startswith('0::') else text


def cgroup_binds_unit(cgroup, unit_name, manager_control_group):
    """The unit must be a complete cgroup path component and agree with the
    manager's own ControlGroup for this unit."""
    components = [part for part in _cgroup_path(cgroup).split('/') if part]
    need(unit_name in components, 'cgroup does not bind the unit',
         str(cgroup))
    need(_cgroup_path(manager_control_group) == _cgroup_path(cgroup),
         'manager ControlGroup disagrees', manager_control_group)


def check_process_facts(facts, profile, expected_argv, properties):
    need(facts['uids'] == [profile['expected_uid']] * 4, 'uid mismatch',
         repr(facts['uids']))
    need(all(value != 0 for value in facts['uids'] + facts['gids']),
         'root identity refused', repr((facts['uids'], facts['gids'])))
    need(facts['image'] == profile['payload_path'], 'exec image mismatch',
         facts['image'])
    need(facts['cmdline'] == expected_argv, 'cmdline mismatch',
         repr(facts['cmdline']))
    cgroup_binds_unit(facts['cgroup'], profile['unit_name'],
                      properties['ControlGroup'])
    return True


def _check_monotonic(records, profile):
    previous = None
    for record in records:
        value = record.get('monotonic_ns')
        need(type(value) is int and not isinstance(value, bool) and value >= 0,
             'monotonic time missing or invalid', repr(value))
        need(previous is None or value >= previous,
             'monotonic time moved backwards', repr(value))
        previous = value
    need(records[-1]['monotonic_ns'] >= records[0]['monotonic_ns'],
         'monotonic time moved backwards')
    need(records[-1]['monotonic_ns'] - records[0]['monotonic_ns']
         <= profile['window_seconds'] * 10 ** 9, 'window exceeded')


def _check_raw_bytes(record, label):
    content = record.get('content')
    need(isinstance(content, str) and content, label + ' bytes missing')
    data = base64.b64decode(content)
    need(sha(data) == record['sha256'], label + ' bytes contradict hash')
    need(len(data) == record['size'], label + ' bytes contradict size')
    return data


RECORD_SEQUENCE = ['intent', 'kernel-identity', 'manager-open', 'unit-show',
                   'unit-cat', 'fragment', 'payload', 'process',
                   'unit-show-recheck', 'process-recheck', 'recheck',
                   'observation-complete']


def check_records(records, profile):
    """Pure decoder: re-derive the observation from raw records only."""
    validate_profile(profile)
    kinds = [record['kind'] for record in records]
    need(kinds == RECORD_SEQUENCE, 'raw record sequence', repr(kinds))
    _check_monotonic(records, profile)

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
    need(isinstance(show.get('stdout'), str) and isinstance(show.get('stderr'), str),
         'show raw response incomplete')
    properties = parse_show(show['stdout'])
    main_pid = check_properties(properties, profile)

    cat = records[4]
    need(cat['argv'] == cat_argv(profile['unit_name']), 'cat argv mutated')
    need(cat['rc'] == 0, 'systemctl cat failed', str(cat['rc']))
    need('# ' + properties['FragmentPath'] in cat['stdout'],
         'cat lacks fragment marker')

    fragment = records[5]
    need(fragment['path'] == profile['fragment_path'], 'fragment path mismatch',
         fragment['path'])
    need(fragment['sha256'] == profile['fragment_sha256'],
         'fragment hash mismatch', fragment['sha256'])
    fragment_bytes = _check_raw_bytes(fragment, 'fragment')
    binding = check_binding_record(fragment.get('binding'), properties,
                                   profile, fragment)
    execstart = fragment_execstart(fragment_bytes)
    need(execstart and execstart[0] == profile['payload_path'],
         'fragment ExecStart does not bind payload', repr(execstart[:1]))
    fragment_user(fragment_bytes, profile['expected_uid'])
    check_loaded_execstart(properties['ExecStart'], profile,
                           fragment_argv=execstart)

    payload = records[6]
    need(payload['path'] == profile['payload_path'], 'payload path mismatch',
         payload['path'])
    need(payload['sha256'] == profile['payload_sha256'],
         'payload hash mismatch', payload['sha256'])
    _check_raw_bytes(payload, 'payload')

    facts = records[7]['value']
    need(records[7]['pid'] == main_pid, 'observed pid is not the main pid',
         str(records[7]['pid']))
    check_process_facts(facts, profile, execstart, properties)
    need(records[7].get('exe_read_sha256') == payload['sha256'],
         'exec image hash mismatch',
         str(records[7].get('exe_read_sha256')))
    need(records[7].get('exe_read_size') == payload['size'],
         'exec image size mismatch', str(records[7].get('exe_read_size')))
    need(facts['image_sha256'] == payload['sha256'],
         'proc image hash mismatch', facts['image_sha256'])
    exe_bytes = base64.b64decode(records[7].get('exe_read_content') or '')
    need(sha(exe_bytes) == records[7].get('exe_read_sha256'),
         'exe read bytes contradict hash')
    need(len(exe_bytes) == records[7].get('exe_read_size'),
         'exe read bytes contradict size')

    show2 = records[8]
    need(show2['argv'] == show_argv(profile['unit_name']),
         'recheck show argv mutated')
    need(show2['rc'] == 0, 'recheck systemctl failed', str(show2['rc']))
    need(isinstance(show2.get('stdout'), str)
         and isinstance(show2.get('stderr'), str),
         'recheck show raw response incomplete')
    properties2 = parse_show(show2['stdout'])
    for key in RECHECK_PROPERTIES:
        need(properties2.get(key) == properties.get(key),
             'unit recheck drifted', key)

    facts2 = records[9]['value']
    need(records[9]['pid'] == main_pid, 'recheck pid changed',
         str(records[9]['pid']))
    for key in PROCESS_FACT_KEYS:
        need(facts2.get(key) == facts.get(key), 'process identity drifted',
             key)

    recheck = records[10]
    need(recheck['manager_identity'] == {
        key: identity[key] for key in MANAGER_FACT_KEYS},
        'manager identity drifted')
    for label, record in (('fragment', fragment), ('payload', payload)):
        again = recheck['files'][label]
        need((again['device'], again['inode'], again['size'], again['sha256'])
             == (record['device'], record['inode'], record['size'],
                 record['sha256']), label + ' replaced during read')

    return build_observation(records, properties, binding, facts, execstart,
                             main_pid)


def build_observation(records, properties, binding, facts, execstart,
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
            'fragment_binding': binding,
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
                     for key in MANAGER_FACT_KEYS},
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
                'fragment_binding': 'records[5].binding',
                'payload_sha256': 'records[6].sha256',
                'exe_read': 'records[7].exe_read_sha256',
                'actor_pid': 'records[7].pid',
                'actor_birth': 'records[7].value.birth',
                'actor_uid': 'records[7].value.uids',
                'unit_recheck': 'records[8].stdout',
                'process_recheck': 'records[9].value',
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


def _exclusive_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def collect_boot_service(profile, output_directory):
    """Bounded read-only observation of one already-running system service.

    Returns (observation, bundle). All native access is read-only; nothing is
    started, restarted, enabled or reloaded. Any refusal still closes every
    descriptor and leaves the exclusive output directory behind as evidence.
    Every sub-read is bounded by the REMAINING profile window, never by a
    fresh per-command budget.
    """
    profile = validate_profile(dict(profile))
    output = Path(output_directory)
    need(not output.exists() and not output.is_symlink()
         and output.parent.is_dir() and not output.parent.is_symlink(),
         'output directory must be new and exclusive', str(output))
    output.mkdir(mode=0o700)
    directory_stat = output.stat()
    started = time.monotonic()

    def remaining():
        left = profile['window_seconds'] - (time.monotonic() - started)
        need(left > 0, 'window exceeded')
        return max(0.5, left)

    raw = _RawWriter(output)
    manager = None
    error = None
    try:
        raw.write('intent', source=SOURCE, profile=profile,
                  output=str(output))
        kernel = read_kernel_identity()
        raw.write('kernel-identity', value=kernel)
        need(kernel['boot_id'] == profile['boot_id'], 'wrong boot identity',
             kernel['boot_id'])
        need(kernel['vm_uuid'] == profile['vm_uuid'], 'wrong vm identity',
             kernel['vm_uuid'])

        identity = manager_identity(1)
        need(identity['pid'] == 1 and identity['uids'] == [0] * 4
             and identity['gids'] == [0] * 4, 'manager not pid1 root')
        manager = open_manager(MANAGER_SOCKET, identity)
        peer = list(manager.peer)
        raw.write('manager-open', socket=MANAGER_SOCKET, peer=peer,
                  identity={key: identity[key] for key in MANAGER_FACT_KEYS})
        need(peer == [1, 0, 0], 'foreign manager peer', repr(peer))

        show = run_command(show_argv(profile['unit_name']), remaining())
        raw.write('unit-show', **show)
        need(show['rc'] == 0, 'systemctl show failed', str(show['rc']))
        properties = parse_show(show['stdout'])
        main_pid = check_properties(properties, profile)
        binding = bind_fragment_path(properties, profile)

        cat = run_command(cat_argv(profile['unit_name']), remaining())
        raw.write('unit-cat', **cat)
        need(cat['rc'] == 0, 'systemctl cat failed', str(cat['rc']))
        need('# ' + properties['FragmentPath'] in cat['stdout'],
             'cat lacks fragment marker')

        fragment = stable_file_read(profile['fragment_path'])
        raw.write('fragment', binding=binding, **fragment)
        need(fragment['sha256'] == profile['fragment_sha256'],
             'fragment hash mismatch', fragment['sha256'])
        fragment_bytes = base64.b64decode(fragment['content'])
        execstart = fragment_execstart(fragment_bytes)
        need(execstart[0] == profile['payload_path'],
             'fragment ExecStart does not bind payload')
        fragment_user(fragment_bytes, profile['expected_uid'])
        check_loaded_execstart(properties['ExecStart'], profile,
                               fragment_argv=execstart)

        payload = stable_file_read(profile['payload_path'])
        raw.write('payload', **payload)
        need(payload['sha256'] == profile['payload_sha256'],
             'payload hash mismatch', payload['sha256'])

        facts = process_identity(main_pid)
        exe_bytes = read_exe(main_pid)
        exe_read = bounded_bytes(exe_bytes, '/proc/%d/exe' % (main_pid,))
        raw.write('process', pid=main_pid, value=facts,
                  exe_read_sha256=exe_read['sha256'],
                  exe_read_size=exe_read['size'],
                  exe_read_content=exe_read['content'])
        need(exe_read['sha256'] == payload['sha256'],
             'exec image hash mismatch')
        check_process_facts(facts, profile, execstart, properties)
        manager.close()
        manager = None

        show2 = run_command(show_argv(profile['unit_name']), remaining())
        raw.write('unit-show-recheck', **show2)
        need(show2['rc'] == 0, 'recheck systemctl failed', str(show2['rc']))
        properties2 = parse_show(show2['stdout'])
        for key in RECHECK_PROPERTIES:
            need(properties2.get(key) == properties.get(key),
                 'unit recheck drifted', key)

        facts2 = process_identity(main_pid)
        raw.write('process-recheck', pid=main_pid, value=facts2)
        need(records_pid(facts2) == main_pid, 'recheck pid changed')
        for key in PROCESS_FACT_KEYS:
            need(facts2.get(key) == facts.get(key), 'process identity drifted',
                 key)

        identity_again = manager_identity(1)
        fragment_again = stable_file_read(profile['fragment_path'])
        payload_again = stable_file_read(profile['payload_path'])
        raw.write('recheck', manager_identity={
            key: identity_again[key] for key in MANAGER_FACT_KEYS},
            files={'fragment': fragment_again, 'payload': payload_again})
        need(identity_again['birth'] == identity['birth']
             and identity_again['uids'] == identity['uids']
             and identity_again['gids'] == identity['gids']
             and identity_again['image'] == identity['image']
             and identity_again['image_sha256'] == identity['image_sha256'],
             'manager identity drifted')
        for label, first in (('fragment', fragment), ('payload', payload)):
            again = (fragment_again if label == 'fragment'
                     else payload_again)
            need((again['device'], again['inode'], again['size'],
                  again['sha256'])
                 == (first['device'], first['inode'], first['size'],
                     first['sha256']), label + ' replaced during read')

        raw.write('observation-complete', observed_at=_now_iso(),
                  records=raw.count)
        raw.close()
        raw = None
        observation = check_records(_load_records(output / 'raw.ndjson'),
                                    profile)
        _exclusive_file(output / 'observation.json',
                        _canonical(observation).encode())
        for name in RAW_FILES:
            os.chmod(output / name, 0o400)
        files = {}
        for name in RAW_FILES:
            target = output / name
            st = target.stat()
            files[name] = dict(size=st.st_size,
                               sha256=sha(target.read_bytes()),
                               inode=st.st_ino, device=st.st_dev,
                               mode=stat.S_IMODE(st.st_mode),
                               regular=stat.S_ISREG(st.st_mode),
                               nlink=st.st_nlink)
        manifest = dict(
            source=SOURCE,
            directory=dict(device=directory_stat.st_dev,
                           inode=directory_stat.st_ino,
                           mode=stat.S_IMODE(directory_stat.st_mode)),
            files=files)
        _exclusive_file(output / 'manifest.json', _canonical(manifest).encode())
        os.chmod(output / 'manifest.json', 0o400)
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


def records_pid(facts):
    return facts.get('pid')


def _load_records(path):
    records = []
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def _check_manifest_inventory(output, manifest):
    listing = {entry.name for entry in os.scandir(output)}
    need(listing == set(DIRECTORY_FILES), 'manifest inventory',
         repr(sorted(listing)))
    need(set(manifest['files']) == set(RAW_FILES), 'manifest inventory',
         repr(sorted(manifest['files'])))
    st = output.lstat()
    need(stat.S_ISDIR(st.st_mode) and not output.is_symlink(),
         'output replaced', str(output))
    need(manifest['directory']['device'] == st.st_dev
         and manifest['directory']['inode'] == st.st_ino
         and manifest['directory']['mode'] == stat.S_IMODE(st.st_mode),
         'output replaced', str(output))
    for name, expected_file in manifest['files'].items():
        target = output / name
        need(target.is_file() and not target.is_symlink(), 'raw missing',
             name)
        current = target.stat()
        need(stat.S_ISREG(current.st_mode), 'raw not a regular file', name)
        need((current.st_ino, current.st_dev)
             == (expected_file['inode'], expected_file['device']),
             'original replaced with same bytes', name)
        need(current.st_size == expected_file['size'], 'raw size mismatch',
             name)
        need(stat.S_IMODE(current.st_mode) == expected_file['mode']
             == 0o400, 'raw protection changed', name)
        need(current.st_nlink == 1, 'raw not a single file', name)
        need(sha(target.read_bytes()) == expected_file['sha256'],
             'raw hash mismatch', name)


def normalize_boot_service(raw_bundle, expected_profile):
    """Re-derive and re-verify the observation from preserved originals.

    A directory bundle is the production original channel: the manifest
    inventory, directory identity and every file's inode/hash/protection are
    re-verified before decoding. A plain records mapping is accepted only as
    a low-trust fixture decode for local development; it can never grant
    native or causal qualification, and the result is marked accordingly.
    """
    profile = validate_profile(dict(expected_profile))
    if isinstance(raw_bundle, (str, Path)):
        output = Path(raw_bundle)
        need((output / 'manifest.json').is_file()
             and (output / 'raw.ndjson').is_file()
             and (output / 'observation.json').is_file(),
             'raw missing')
        manifest = json.loads((output / 'manifest.json').read_text())
        _check_manifest_inventory(output, manifest)
        records = _load_records(output / 'raw.ndjson')
        return check_records(records, profile)
    need(isinstance(raw_bundle, dict) and 'records' in raw_bundle,
         'bundle must be an output directory or a records bundle')
    observation = check_records(raw_bundle['records'], profile)
    marked = dict(observation)
    marked['decode_trust'] = 'fixture-records-only'
    marked['limitations'] = list(observation['limitations']) + [
        'decoded from in-memory records; not the sealed original channel']
    return marked
