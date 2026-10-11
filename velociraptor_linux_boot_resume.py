"""Resume qualification for one systemd-autostarted ordinary service.

The unit was already started by PID1 before this module ran; nothing here
starts, restarts, enables or reloads it. The sealed boot-service observation
is re-derived from its original directory, the live kernel/manager/unit and
process facts are observed twice, the real journald boot record is kept as a
bounded original, and only then is a professional kernel scope applied to the
exact observed pid/birth/uid. Stop and export close the same scope later.
"""
from __future__ import annotations
import base64
import copy
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from velociraptor_linux_boot_service import (
    BootServiceError, INLINE_LIMIT, MANAGER_SOCKET, PROCESS_FACT_KEYS,
    validate_profile as validate_boot_profile, normalize_boot_service,
    read_kernel_identity, manager_identity, open_manager, run_command,
    process_identity, read_exe, stable_file_read, show_argv, cat_argv,
    parse_show, check_properties, bind_fragment_path, check_process_facts,
    cgroup_binds_unit, fragment_execstart, fragment_user,
    check_loaded_execstart, bounded_bytes, check_records, need, sha)
from velociraptor_linux_boot_service import SOURCE as BOOT_SERVICE_SOURCE
from velociraptor_linux_probe import SOURCE_ID

SOURCE = 'MalTrace.SystemBootResume.v1'
RESUME_FILES = ('raw.ndjson', 'journal.jsonl', 'observation.json')
FINISH_FILES = ('finish.json',)
JOURNAL_ARGV = ('journalctl', '--boot', None, '--unit', None,
                '--output=json', '--no-pager')
SCOPE_MODULES = ('velociraptor_linux_scope.py', 'velociraptor_linux_worker.py',
                 'velociraptor_linux_probe.py')
UNIT_STARTED_MESSAGE_ID = '39f53479d3a045ac8e11786248231fbf'
WANTS_DIR = '/etc/systemd/system/multi-user.target.wants'
MANUAL_SHOW_PROPERTIES = ('RefuseManualStart', 'After', 'Requires')
JOURNALD_DEPENDENCY = 'systemd-journald.service'
PROFILE_FIELDS = {'unit_name', 'vm_uuid', 'boot_id', 'expected_uid',
                  'payload_path', 'payload_sha256', 'fragment_path',
                  'fragment_sha256', 'enable_link_path', 'bundle_dir',
                  'deployment_root', 'client_id', 'session_id', 'owner_id',
                  'lifetime_seconds', 'window_seconds', 'journal_max_bytes'}
BOOT_FIELDS = {'unit_name', 'vm_uuid', 'boot_id', 'expected_uid',
               'payload_path', 'payload_sha256', 'fragment_path',
               'fragment_sha256', 'window_seconds'}
RECORD_SEQUENCE = ['intent', 'kernel-identity', 'manager-open', 'bundle',
                   'unit-show', 'manual-show', 'unit-cat', 'fragment',
                   'payload', 'enable-link', 'process', 'journal',
                   'scope-apply-intent', 'scope-apply-receipt', 'recheck',
                   'observation-complete']
PHYSICAL_IDENTITY_FIELDS = ('device', 'inode', 'uid', 'gid', 'mode', 'size',
                            'sha256')
LIMITATIONS = [
    'the service was started by PID1 before this observation: its early '
    'execution is not captured and remains an explicit initial_exec_gap',
    'the journal record is bounded-read; an oversized journal is refused, '
    'never silently truncated',
    'installation causality and the boot transition require the independently '
    'sealed A source and the confirmed host bridge',
]


class BootResumeError(ValueError):
    def __init__(self, code, detail=''):
        super().__init__(code + (': ' + detail if detail else ''))
        self.code = code


def _need(condition, code, detail=''):
    if not condition:
        raise BootResumeError(code, detail)


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':')) + '\n'


def _now_mono():
    return time.monotonic_ns()


def _now_iso():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _hex64(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[0-9a-f]{64}', value))


def boot_key(value):
    """Lossless canonical comparison key for boot ids.

    journald `_BOOT_ID` is a 32-hex string without hyphens; the kernel
    exposes the canonical hyphenated UUID. Both are normalized to the same
    32-hex lowercase form and never compared as raw strings.
    """
    _need(isinstance(value, str) and value.strip(),
          'boot id missing')
    text = value.strip().lower()
    if re.fullmatch(r'[0-9a-f]{32}', text):
        return text
    try:
        return uuid.UUID(text).hex
    except (ValueError, AttributeError, TypeError):
        raise BootResumeError('boot id is neither a UUID nor 32 hex',
                              repr(value)) from None


def boot_profile(profile):
    return {name: profile[name] for name in BOOT_FIELDS}


def validate_profile(profile):
    _need(isinstance(profile, dict), 'profile must be an object')
    _need(set(profile) == PROFILE_FIELDS, 'profile fields',
          'expected exactly %r' % sorted(PROFILE_FIELDS))
    inner = boot_profile(profile)
    try:
        validate_boot_profile(inner)
    except BootServiceError as error:
        raise BootResumeError('invalid boot profile', str(error)) from None
    link = profile['enable_link_path']
    _need(isinstance(link, str) and os.path.isabs(link)
          and link == os.path.normpath(link)
          and '..' not in link.split(os.sep),
          'enable_link_path must be a canonical absolute path')
    derived = WANTS_DIR + '/' + profile['unit_name']
    _need(link == derived,
          'enable_link_path must derive from the fixed unit',
          '%r != %r' % (link, derived))
    bundle = profile['bundle_dir']
    _need(isinstance(bundle, str) and os.path.isabs(bundle)
          and bundle == os.path.normpath(bundle)
          and '..' not in bundle.split(os.sep),
          'bundle_dir must be a canonical absolute path')
    deployment = profile['deployment_root']
    _need(isinstance(deployment, str) and os.path.isabs(deployment)
          and deployment == os.path.normpath(deployment)
          and '..' not in deployment.split(os.sep),
          'deployment_root must be a canonical absolute path')
    _need(isinstance(profile['client_id'], str)
          and re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', profile['client_id']),
          'client_id invalid')
    for key in ('session_id', 'owner_id'):
        value = profile[key]
        try:
            canonical_uuid = str(uuid.UUID(value)) if isinstance(value, str) \
                else None
        except (ValueError, AttributeError, TypeError):
            canonical_uuid = None
        _need(canonical_uuid is not None
              and canonical_uuid == value.lower(),
              key + ' must be a canonical lowercase UUID')
    lifetime = profile['lifetime_seconds']
    _need(type(lifetime) is int and not isinstance(lifetime, bool)
          and 30 <= lifetime <= 900, 'lifetime_seconds must be 30..900')
    bound = profile['journal_max_bytes']
    _need(type(bound) is int and not isinstance(bound, bool)
          and 1024 <= bound <= INLINE_LIMIT,
          'journal_max_bytes must be 1024..%d' % INLINE_LIMIT)
    return dict(profile)


def check_scope_receipt(receipt, binding, target):
    _need(isinstance(receipt, dict), 'scope receipt must be an object')
    for key, value in binding.items():
        _need(receipt.get(key) == value, 'scope receipt binding mismatch',
              key)
    _need(receipt.get('status') == 'APPLIED'
          and receipt.get('backend_applied') is True,
          'professional scope not applied')
    _need(receipt.get('generation') == 1, 'scope generation differs')
    _need(receipt.get('tick_ns') == 10 ** 7, 'scope tick unit unsupported')
    basis = receipt.get('birth_basis') or {}
    _need(basis.get('clock_ticks_per_second') == 100
          and basis.get('tick_ns') == 10 ** 7
          and basis.get('proc_stat_field') == 22,
          'birth basis missing')
    _need(receipt.get('default_targets') == [target],
          'scope default targets differ from the observed process')
    _need(receipt.get('source') == SOURCE_ID, 'scope source differs')
    return receipt


def scope_source_hashes():
    return {name: sha(Path(__file__).with_name(name).read_bytes())
            for name in SCOPE_MODULES}


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


def _load_records(path):
    records = []
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


# -- native boundary seams (tests replace these, production reads the host) --
def _kernel_identity():
    return read_kernel_identity()


def _manager_identity(pid=1):
    return manager_identity(pid)


def _open_manager(socket_path, expected):
    return open_manager(socket_path, expected)


def _run_command(argv, timeout):
    return run_command(argv, timeout)


def _process_facts(pid):
    return process_identity(pid)


def _read_exe(pid):
    return read_exe(pid)


def _stable_read(path):
    return stable_file_read(path)


def _link_identity(path):
    return link_identity(path)


def _directory_identity(path):
    return directory_identity(path)


def _exe_fd_identity(pid):
    link = Path('/proc') / str(pid) / 'exe'
    target = os.readlink(link)
    st = link.stat()
    return dict(path=target, device=st.st_dev, inode=st.st_ino)


def _rederive(bundle_dir, inner_profile):
    return normalize_boot_service(bundle_dir, inner_profile)


def _client(deployment_root, binding):
    from velociraptor_linux_cli import RegisteredLinuxClient
    return RegisteredLinuxClient.for_scope(deployment_root, binding)


def journal_argv(boot_id, unit_name):
    """The one unambiguous fixed journal argv.

    `--boot=<32hex>` is the only accepted form: the separate-argument form
    with the canonical hyphenated UUID is rejected by the real journalctl
    (`Failed to add match ... invalid argument`). The boot id is normalized
    losslessly through boot_key and malformed ids are refused.
    """
    return ['journalctl', '--boot=' + boot_key(boot_id), '--unit', unit_name,
            '--output=json', '--no-pager']


def manual_show_argv(unit_name):
    return ['systemctl', 'show', unit_name,
            '--property=' + ','.join(MANUAL_SHOW_PROPERTIES)]


def stat_identity(st):
    return dict(device=st.st_dev, inode=st.st_ino, uid=st.st_uid,
                gid=st.st_gid, mode=stat.S_IMODE(st.st_mode),
                size=st.st_size)


def directory_identity(path):
    """One twice-read directory identity without following any link."""
    p = Path(path)
    before = p.lstat()
    _need(stat.S_ISDIR(before.st_mode) and not stat.S_ISLNK(before.st_mode),
          'parent is not a real directory', str(p))
    after = p.lstat()
    _need((before.st_dev, before.st_ino, before.st_uid, before.st_gid,
           before.st_mode) == (after.st_dev, after.st_ino, after.st_uid,
                               after.st_gid, after.st_mode),
          'parent changed during read', str(p))
    return dict(path=str(p), **stat_identity(before))


def link_identity(path):
    """One twice-read symlink identity through lstat/readlink only."""
    p = Path(path)
    before = p.lstat()
    _need(stat.S_ISLNK(before.st_mode), 'enable link is not a symlink',
          str(p))
    target = os.readlink(p)
    after = p.lstat()
    _need((before.st_dev, before.st_ino, before.st_uid, before.st_gid,
           stat.S_IMODE(before.st_mode), before.st_size, before.st_mtime_ns)
          == (after.st_dev, after.st_ino, after.st_uid, after.st_gid,
              stat.S_IMODE(after.st_mode), after.st_size, after.st_mtime_ns),
          'enable link changed during read', str(p))
    return dict(path=str(p), target=target, device=before.st_dev,
                inode=before.st_ino, uid=before.st_uid, gid=before.st_gid,
                mode=stat.S_IMODE(before.st_mode), size=before.st_size)


def file_identity(record):
    return {key: record[key] for key in
            ('path', 'device', 'inode', 'uid', 'mode', 'size', 'sha256')}


def _manager_records(entries):
    return [e for e in entries
            if str(e.get('_PID')) == '1' and str(e.get('_UID')) == '0']


def check_journal(raw, profile, unit, actor, main_start_us, manager_image):
    """Structural journald verification against the live observations.

    Two independent record classes are required: PID1 manager startup
    records (sender bound to the independently observed manager image and
    the target UNIT/INVOCATION_ID/message id) and payload records sent by
    the actual ordinary main process. Only journald's own structured fields
    are consumed; English message text is never a source of truth. An
    oversized journal is refused before any decode, never truncated. Boot
    ids are compared through their canonical 32-hex form.
    """
    _need(isinstance(raw, bytes) and len(raw) > 0, 'journal record empty')
    _need(len(raw) <= profile['journal_max_bytes'],
          'journal record exceeds the bounded size',
          '%d > %d' % (len(raw), profile['journal_max_bytes']))
    boot = boot_key(profile['boot_id'])
    entries = []
    for line in raw.decode('utf-8', errors='strict').splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        _need(isinstance(value, dict), 'journal entry not an object')
        _need(value.get('_BOOT_ID') is not None
              and boot_key(value.get('_BOOT_ID')) == boot,
              'journal entry boot differs')
        entries.append(value)
    _need(entries, 'journal has no entries for the boot')

    managers = _manager_records(entries)
    starts = [e for e in managers
              if e.get('MESSAGE_ID') == UNIT_STARTED_MESSAGE_ID]
    _need(starts, 'journal lacks the PID1 unit-start record')
    _need(len(starts) == 1,
          'journal carries multiple unit-start records for one invocation')
    start = starts[0]
    _need(start.get('UNIT') == profile['unit_name'],
          'journal start record UNIT differs from the fixed unit')
    _need(start.get('INVOCATION_ID') == unit['invocation_id'],
          'journal start record INVOCATION_ID differs from the live unit')
    _need(start.get('_EXE') == manager_image,
          'journal start record sender is not the observed manager')
    if start.get('_SYSTEMD_UNIT') is not None:
        _need(start.get('_SYSTEMD_UNIT') != profile['unit_name'],
              'manager record cannot be the business unit sender')
    stamp = start.get('__MONOTONIC_TIMESTAMP')
    _need(isinstance(stamp, str) and stamp.isdigit(),
          'journal start record monotonic timestamp missing')
    start_us = int(stamp)
    _need(start_us >= main_start_us,
          'journal start record predates the native service start')

    payload = [e for e in entries
               if e.get('_SYSTEMD_UNIT') == profile['unit_name']
               and str(e.get('_PID')) == str(actor['pid'])]
    _need(payload, 'journal lacks the observed main pid as a sender')
    first_main = None
    for e in payload:
        _need(str(e.get('_UID')) == str(actor['uid']),
              'journal payload sender uid differs from the ordinary main')
        _need(e.get('_EXE') == profile['payload_path'],
              'journal payload sender image differs from the payload')
        _need(e.get('_SYSTEMD_INVOCATION_ID') == unit['invocation_id'],
              'journal payload sender invocation differs from the live unit')
        if e.get('INVOCATION_ID') is not None:
            _need(e['INVOCATION_ID'] == unit['invocation_id'],
                  'journal payload unit invocation differs')
        stamp = e.get('__MONOTONIC_TIMESTAMP')
        _need(isinstance(stamp, str) and stamp.isdigit(),
              'journal payload monotonic timestamp missing')
        value = int(stamp)
        _need(value >= start_us,
              'journal payload entry predates the unit-start record')
        if first_main is None or value < first_main:
            first_main = value
    birth = int(actor['birth']) * 10 ** 7
    _need(first_main * 1000 >= birth - 10 ** 9,
          'first payload journal entry predates the process birth')
    _need(main_start_us * 1000 <= birth + 5 * 10 ** 9
          and main_start_us * 1000 >= birth - 5 * 10 ** 9,
          'manager start and process birth differ beyond the native bound')
    invocation = {e.get('INVOCATION_ID') for e in entries
                  if e.get('INVOCATION_ID') is not None}
    for value in invocation:
        _need(value == unit['invocation_id'],
              'journal carries a foreign invocation id')
    message_ids = sorted({e['MESSAGE_ID'] for e in entries
                          if isinstance(e.get('MESSAGE_ID'), str)})
    _need(UNIT_STARTED_MESSAGE_ID in message_ids
          and all(boot_key(e['_BOOT_ID']) == boot for e in entries),
          'journal structured boot identity differs')
    return dict(rc=0, size=len(raw), sha256=sha(raw), records=len(entries),
                manager_records=len(managers), start_records=1,
                payload_records=len(payload),
                unit_records=len([e for e in entries
                                  if e.get('_SYSTEMD_UNIT')
                                  == profile['unit_name']
                                  or e.get('UNIT') == profile['unit_name']]),
                main_records=len(payload),
                start_monotonic_us=start_us,
                first_payload_monotonic_us=first_main,
                invocation_ids=sorted(invocation),
                message_ids=message_ids)


def derive_ordering(manual_props, manual_argv, fragment_lines):
    """Derive and guard the loaded journald ordering from real originals.

    The ordered captured shape carries After= and Requires= exactly for
    systemd-journald.service in its fragment; its loaded properties must
    list the same dependency in both token sets. The legacy shape has
    neither line and keeps its previous semantics. A partial pair, an
    arbitrary dependency value or a loaded set without the fixed
    dependency is refused.
    """
    after = sorted(t for t in (manual_props.get('After') or '').split() if t)
    requires = sorted(t for t in (manual_props.get('Requires') or '').split()
                      if t)
    after_line = ('After=' + JOURNALD_DEPENDENCY) in fragment_lines
    requires_line = ('Requires=' + JOURNALD_DEPENDENCY) in fragment_lines
    _need(after_line == requires_line,
          'partial journald ordering in the fragment')
    if after_line:
        _need(JOURNALD_DEPENDENCY in after
              and JOURNALD_DEPENDENCY in requires,
              'loaded ordering lacks the fixed journald dependency')
    return dict(required=after_line, after=after, requires=requires,
                argv=list(manual_argv))


def build_observation_document(*, profile, unit, actor, payload, identity,
                                peer, target, summary, binding, properties,
                                execstart, fragment, payload_read, link,
                                link_parent, unit_parent, payload_parent,
                                exe_fd, request, receipt, ready_ns,
                                source_hashes, ordering):
    """The one canonical resume observation shape.

    Both the live producer and the host-side replay build the document
    through this function, so a complete rebuild can be compared verbatim
    with the sealed observation instead of checking selected fields.
    """
    return dict(
        schema=SOURCE, kind='boot-resume-observation',
        vm_uuid=profile['vm_uuid'], boot_id=profile['boot_id'],
        unit=dict(name=unit['name'], fragment_path=unit['fragment_path'],
                  fragment_sha256=unit['fragment_sha256'],
                  fragment_identity=unit['fragment_identity'],
                  fragment_binding=binding,
                  invocation_id=unit['invocation_id'],
                  unit_file_state=unit['unit_file_state'],
                  main_pid=actor['pid'],
                  exec_main_start_monotonic_us=int(
                      properties['ExecMainStartTimestampMonotonic']),
                  execstart=list(execstart)),
        payload=dict(path=payload['path'], sha256=payload['sha256'],
                     size=payload['size'], identity=payload['identity']),
        physical=dict(unit=file_identity(fragment),
                      payload=file_identity(payload_read),
                      link=link, link_parent=link_parent,
                      unit_parent=unit_parent,
                      payload_parent=payload_parent, exe_fd=exe_fd,
                      refuse_manual_start='yes'),
        actor=dict(pid=actor['pid'], birth=actor['birth'], uid=actor['uid'],
                   gid=actor['gid'], exe=actor['exe'],
                   exe_sha256=actor['exe_sha256'], cgroup=actor['cgroup'],
                   cmdline=list(actor['cmdline'])),
        manager=dict(socket=MANAGER_SOCKET, peer=list(peer),
                     pid1={key: identity[key] for key in
                           ('pid', 'birth', 'uids', 'gids', 'image',
                            'image_sha256')}),
        ordering=dict(ordering),
        target=dict(target), journal=dict(summary),
        scope=dict(apply_request=request, apply_receipt=receipt,
                   generation=1, ready_ns=ready_ns,
                   source_hashes=dict(source_hashes)),
        limitations=list(LIMITATIONS))


def resume(profile, output_directory):
    """Observe the already-running service once and apply the kernel scope.

    Read-only until the single scope apply request; the unit is never
    started, restarted, enabled, reloaded or modified.
    """
    profile = validate_profile(dict(profile))
    inner = boot_profile(profile)
    output = Path(output_directory)
    _need(not output.exists() and not output.is_symlink()
          and output.parent.is_dir() and not output.parent.is_symlink(),
          'output directory must be new and exclusive', str(output))
    output.mkdir(mode=0o700)
    directory_stat = output.stat()
    started = time.monotonic()

    def remaining():
        left = profile['window_seconds'] - (time.monotonic() - started)
        _need(left > 0, 'window exceeded')
        return max(0.5, left)

    raw = _RawWriter(output)
    manager = None
    error = None
    try:
        raw.write('intent', source=SOURCE, profile=profile,
                  output=str(output))
        kernel = _kernel_identity()
        raw.write('kernel-identity', value=kernel)
        _need(kernel['boot_id'] == profile['boot_id']
              and kernel['vm_uuid'] == profile['vm_uuid'],
              'wrong kernel identity',
              '%r/%r' % (kernel['boot_id'], kernel['vm_uuid']))

        identity = _manager_identity(1)
        _need(identity['pid'] == 1 and identity['uids'] == [0] * 4
              and identity['gids'] == [0] * 4, 'manager not pid1 root')
        manager = _open_manager(MANAGER_SOCKET, identity)
        peer = list(manager.peer)
        raw.write('manager-open', socket=MANAGER_SOCKET, peer=peer,
                  identity={key: identity[key]
                            for key in ('pid', 'birth', 'uids', 'gids',
                                        'image', 'image_sha256')})
        _need(peer == [1, 0, 0], 'foreign manager peer', repr(peer))

        observation = _rederive(profile['bundle_dir'], inner)
        _need('decode_trust' not in observation,
              'sealed-directory bundle required')
        actor, unit, payload = (observation['actor'], observation['unit'],
                                observation['payload'])
        bundle_manifest = json.loads(
            (Path(profile['bundle_dir']) / 'manifest.json').read_bytes())
        raw.write('bundle',
                  observation_sha256=sha(_canonical(observation).encode()),
                  manifest_sha256=sha(_canonical(bundle_manifest).encode()),
                  directory=bundle_manifest.get('directory'))

        show = _run_command(show_argv(profile['unit_name']), remaining())
        raw.write('unit-show', **show)
        _need(show['rc'] == 0, 'systemctl show failed', str(show['rc']))
        properties = parse_show(show['stdout'])
        main_pid = check_properties(properties, inner)
        binding = bind_fragment_path(properties, inner)
        _need(main_pid == actor['pid'], 'live main pid differs from the '
              'sealed observation')
        _need(properties['InvocationID'] == unit['invocation_id'],
              'live invocation differs from the sealed observation')

        manual = _run_command(manual_show_argv(profile['unit_name']),
                              remaining())
        raw.write('manual-show', **manual)
        _need(manual['rc'] == 0, 'systemctl show RefuseManualStart failed')
        manual_props = {}
        for line in manual['stdout'].splitlines():
            if line.strip():
                _need('=' in line, 'unparsed manual show line', line)
                key, value = line.split('=', 1)
                _need(key not in manual_props, 'duplicate manual show line',
                      key)
                manual_props[key] = value
        _need(manual_props.get('RefuseManualStart') == 'yes',
              'loaded RefuseManualStart is not yes',
              repr(manual_props.get('RefuseManualStart')))

        cat = _run_command(cat_argv(profile['unit_name']), remaining())
        raw.write('unit-cat', **cat)
        _need(cat['rc'] == 0, 'systemctl cat failed', str(cat['rc']))
        _need('# ' + properties['FragmentPath'] in cat['stdout'],
              'cat lacks the fragment marker')

        fragment = _stable_read(profile['fragment_path'])
        raw.write('fragment', binding=binding, **fragment)
        _need(fragment['sha256'] == profile['fragment_sha256']
              == unit['fragment_sha256'], 'fragment hash mismatch')
        fragment_bytes = base64.b64decode(fragment['content'])
        fragment_lines = fragment_bytes.decode('utf-8',
                                               errors='strict').splitlines()
        _need('RefuseManualStart=yes' in fragment_lines,
              'fragment lacks the fixed RefuseManualStart=yes')
        _need('WantedBy=multi-user.target' in fragment_lines,
              'fragment lacks the fixed boot enablement')
        ordering = derive_ordering(manual_props, manual['argv'],
                                   fragment_lines)
        execstart = fragment_execstart(fragment_bytes)
        _need(execstart[0] == profile['payload_path'],
              'fragment ExecStart does not bind the payload')
        fragment_user(fragment_bytes, profile['expected_uid'])
        check_loaded_execstart(properties['ExecStart'], inner,
                               fragment_argv=execstart)

        payload_read = _stable_read(profile['payload_path'])
        raw.write('payload', **payload_read)
        _need(payload_read['sha256'] == profile['payload_sha256']
              == payload['sha256'], 'payload hash mismatch')

        link = _link_identity(profile['enable_link_path'])
        link_parent = _directory_identity(
            Path(profile['enable_link_path']).parent)
        unit_parent = _directory_identity(
            Path(profile['fragment_path']).parent)
        payload_parent = _directory_identity(
            Path(profile['payload_path']).parent)
        exe_fd = _exe_fd_identity(actor['pid'])
        raw.write('enable-link', value=link, link_parent=link_parent,
                  unit_parent=unit_parent, payload_parent=payload_parent,
                  exe_fd=exe_fd)
        _need(link['target'] == profile['fragment_path'],
              'enable link target differs from the fixed unit')
        _need(link['uid'] == 0
              and not link_parent['mode'] & 0o022
              and link_parent['uid'] == 0,
              'enable link or its parent is not root protected')
        _need(unit_parent['uid'] == 0 and not unit_parent['mode'] & 0o022,
              'unit parent is not root protected')
        _need(exe_fd['path'] == profile['payload_path']
              and (exe_fd['device'], exe_fd['inode'])
              == (payload_read['device'], payload_read['inode']),
              'exec fd does not bind the persistent payload inode')

        facts = _process_facts(actor['pid'])
        exe_read = bounded_bytes(_read_exe(actor['pid']),
                                 '/proc/%d/exe' % (actor['pid'],))
        raw.write('process', pid=actor['pid'], value=facts,
                  exe_read_sha256=exe_read['sha256'])
        check_process_facts(facts, inner, execstart, properties)
        _need(facts['birth'] == actor['birth']
              and facts['uids'][0] == actor['uid']
              and facts['gids'][0] == actor['gid']
              and facts['cmdline'] == actor['cmdline'],
              'live process differs from the sealed observation')
        _need(exe_read['sha256'] == payload['sha256'],
              'exec image hash mismatch')

        journal = _run_command(journal_argv(profile['boot_id'],
                                            profile['unit_name']),
                               remaining())
        _need(journal['rc'] == 0, 'journalctl failed', str(journal['rc']))
        journal_raw = journal['stdout'].encode('utf-8')
        summary = check_journal(journal_raw, profile, unit, actor,
                                int(properties[
                                    'ExecMainStartTimestampMonotonic']),
                                identity['image'])
        summary['argv'] = list(journal['argv'])
        raw.write('journal', **summary)
        _exclusive_file(output / 'journal.jsonl', journal_raw)

        scope_binding = dict(session_id=profile['session_id'],
                             owner_id=profile['owner_id'],
                             client_id=profile['client_id'],
                             vm_uuid=profile['vm_uuid'],
                             boot_id=profile['boot_id'])
        target = dict(pid=actor['pid'], birth=actor['birth'],
                      uid=actor['uid'])
        request = dict(scope_binding, operation_id=str(uuid.uuid4()),
                       targets=[target],
                       lifetime_seconds=profile['lifetime_seconds'])
        raw.write('scope-apply-intent', request=request)
        client = _client(profile['deployment_root'], scope_binding)
        receipt = client.call('linux_scope_apply', {'request': request})
        _need(isinstance(receipt, dict), 'scope apply returned no receipt')
        raw.write('scope-apply-receipt', receipt=receipt)
        check_scope_receipt(receipt, scope_binding, target)
        source_hashes = scope_source_hashes()
        for name, value in source_hashes.items():
            _need(receipt.get('source_hashes', {}).get(name) == value,
                  'scope source hash mismatch', name)
        ready_ns = next((t['ready_ns'] for t in receipt['transitions']
                         if t.get('action') == 'applied'
                         and type(t.get('ready_ns')) is int), None)
        _need(ready_ns is not None, 'scope ready marker missing')

        facts2 = _process_facts(actor['pid'])
        identity_again = _manager_identity(1)
        show2 = _run_command(show_argv(profile['unit_name']), remaining())
        properties2 = (parse_show(show2['stdout'])
                       if show2['rc'] == 0 else {})
        manual2 = _run_command(manual_show_argv(profile['unit_name']),
                               remaining())
        manual_props2 = {}
        for line in (manual2.get('stdout') or '').splitlines():
            if line.strip() and '=' in line:
                key, value = line.split('=', 1)
                manual_props2[key] = value
        fragment2 = _stable_read(profile['fragment_path'])
        fragment2_lines = base64.b64decode(
            fragment2['content']).decode('utf-8',
                                        errors='strict').splitlines()
        ordering2 = derive_ordering(manual_props2, manual2['argv'],
                                    fragment2_lines)
        payload2 = _stable_read(profile['payload_path'])
        link2 = _link_identity(profile['enable_link_path'])
        exe_fd2 = _exe_fd_identity(actor['pid'])
        raw.write('recheck',
                  process={key: facts2.get(key) for key in PROCESS_FACT_KEYS},
                  manager={key: identity_again[key] for key in
                           ('pid', 'birth', 'uids', 'gids', 'image',
                            'image_sha256')},
                  show_rc=show2['rc'],
                  invocation_id=properties2.get('InvocationID'),
                  main_pid=properties2.get('MainPID'),
                  manual_rc=manual2['rc'],
                  refuse_manual_start=manual_props2.get('RefuseManualStart'),
                  fragment=file_identity(fragment2),
                  fragment_content_sha256=fragment2['sha256'],
                  payload=file_identity(payload2),
                  payload_content_sha256=payload2['sha256'],
                  link=link2, exe_fd=exe_fd2)
        _need(show2['rc'] == 0
              and properties2.get('InvocationID') == unit['invocation_id']
              and properties2.get('MainPID') == str(actor['pid'])
              and properties2.get('FragmentPath')
              == properties['FragmentPath'],
              'unit recheck drifted')
        _need(manual2['rc'] == 0
              and manual_props2.get('RefuseManualStart') == 'yes'
              and ordering2 == ordering,
              'loaded RefuseManualStart/ordering recheck drifted')
        for key in ('pid', 'birth', 'uids', 'gids', 'image', 'image_sha256',
                    'cgroup', 'cmdline'):
            _need(facts2.get(key) == facts.get(key),
                  'process recheck drifted', key)
        _need(identity_again['birth'] == identity['birth']
              and identity_again['uids'] == identity['uids']
              and identity_again['gids'] == identity['gids']
              and identity_again['image'] == identity['image']
              and identity_again['image_sha256'] == identity['image_sha256'],
              'manager recheck drifted')
        _need(file_identity(fragment2) == file_identity(fragment)
              and file_identity(payload2) == file_identity(payload_read)
              and link2 == link and exe_fd2 == exe_fd,
              'persistent object recheck drifted')

        raw.write('observation-complete', observed_at=_now_iso(),
                  records=raw.count)
        raw.close()
        raw = None
        observation_doc = build_observation_document(
            profile=profile, unit=unit, actor=actor, payload=payload,
            identity=identity, peer=peer, target=target, summary=summary,
            binding=binding, properties=properties, execstart=execstart,
            fragment=fragment, payload_read=payload_read, link=link,
            link_parent=link_parent, unit_parent=unit_parent,
            payload_parent=payload_parent, exe_fd=exe_fd, request=request,
            receipt=receipt, ready_ns=ready_ns, source_hashes=source_hashes,
            ordering=ordering)
        _exclusive_file(output / 'observation.json',
                        _canonical(observation_doc).encode())
        for name in RESUME_FILES:
            os.chmod(output / name, 0o400)
        files = {}
        for name in RESUME_FILES:
            target_path = output / name
            st = target_path.stat()
            files[name] = dict(size=st.st_size,
                               sha256=sha(target_path.read_bytes()),
                               inode=st.st_ino, device=st.st_dev,
                               nlink=st.st_nlink,
                               mode=stat.S_IMODE(st.st_mode))
        manifest = dict(source=SOURCE, kind='boot-resume',
                        directory=dict(device=directory_stat.st_dev,
                                       inode=directory_stat.st_ino,
                                       mode=stat.S_IMODE(
                                           directory_stat.st_mode)),
                        files=files)
        _exclusive_file(output / 'manifest.json',
                        _canonical(manifest).encode())
        os.chmod(output / 'manifest.json', 0o400)
        return observation_doc, dict(output=str(output), manifest=manifest)
    except BaseException as caught:
        error = caught
        raise
    finally:
        if raw is not None:
            try:
                raw.write('collection-error',
                          error=type(error).__name__ if error is not None
                          else 'unknown',
                          detail=str(error)[:400] if error is not None
                          else '')
            except BaseException:
                pass
            raw.close()
        if manager is not None:
            manager.close()


def finish(profile, output_directory):
    """Stop and export exactly this scope, preserving every raw original."""
    profile = validate_profile(dict(profile))
    output = Path(output_directory)
    _need(not output.exists() and not output.is_symlink()
          and output.parent.is_dir() and not output.parent.is_symlink(),
          'output directory must be new and exclusive', str(output))
    output.mkdir(mode=0o700)
    (output / 'products').mkdir(mode=0o700)
    directory_stat = output.stat()
    kernel = _kernel_identity()
    _need(kernel['boot_id'] == profile['boot_id']
          and kernel['vm_uuid'] == profile['vm_uuid'],
          'wrong kernel identity at finish')
    scope_binding = dict(session_id=profile['session_id'],
                         owner_id=profile['owner_id'],
                         client_id=profile['client_id'],
                         vm_uuid=profile['vm_uuid'],
                         boot_id=profile['boot_id'])
    client = _client(profile['deployment_root'], scope_binding)
    directory = Path(profile['deployment_root']) / 'scopes' / \
        profile['session_id']
    _need(directory.is_dir() and not directory.is_symlink(),
          'scope directory missing')
    stopped = client.call('linux_scope_stop', {
        'request': dict(scope_binding, operation_id=str(uuid.uuid4()))})
    _need(isinstance(stopped, dict) and stopped.get('collection_stopped')
          is True, 'scope stop not confirmed')
    _need(stopped.get('status') == 'STOPPED', 'scope stop status differs',
          str(stopped.get('status')))
    exported = client.call('linux_scope_export', {
        'request': dict(scope_binding, operation_id=str(uuid.uuid4()))})
    _need(isinstance(exported, dict) and exported.get('collection_stopped')
          is True, 'scope export not confirmed')
    _need(exported.get('status') == 'STOPPED', 'scope export status differs')
    _need(all(exported.get(k) == v for k, v in scope_binding.items()),
          'scope export binding mismatch')
    _need(exported.get('generation') == 1, 'scope generation differs')
    _need(exported.get('default_targets') == stopped.get('default_targets')
          and len(exported.get('default_targets') or []) == 1,
          'scope export target differs')
    source_hashes = scope_source_hashes()
    for receipt in (stopped, exported):
        for name, value in source_hashes.items():
            _need(receipt.get('source_hashes', {}).get(name) == value,
                  'scope source hash mismatch at finish', name)
    refs = [*exported.get('products', []), exported['ref']]
    from velociraptor_linux_backend import verify_ref
    records, total = [], 0
    for index, ref in enumerate(refs):
        raw = verify_ref(ref, directory)
        total += len(raw)
        _need(total <= 32 * 1024 * 1024, 'finish originals bound')
        name = 'products/%04d.bin' % index
        _exclusive_file(output / name, raw)
        records.append(dict(ref=ref, local=name, size=len(raw),
                            sha256=sha(raw)))
    finish_doc = dict(schema=SOURCE, kind='boot-resume-finish',
                      vm_uuid=profile['vm_uuid'],
                      boot_id=profile['boot_id'],
                      binding=scope_binding,
                      stopped=stopped, exported=exported,
                      originals=records)
    _exclusive_file(output / 'finish.json',
                    _canonical(finish_doc).encode())
    for path in sorted(output.rglob('*')):
        if path.is_file():
            os.chmod(path, 0o400)
    files = {}
    for path in sorted(output.rglob('*')):
        if path.is_file():
            rel = str(path.relative_to(output))
            st = path.stat()
            files[rel] = dict(size=st.st_size,
                              sha256=sha(path.read_bytes()),
                              inode=st.st_ino, device=st.st_dev,
                              nlink=st.st_nlink,
                              mode=stat.S_IMODE(st.st_mode))
    manifest = dict(source=SOURCE, kind='boot-resume-finish',
                    directory=dict(device=directory_stat.st_dev,
                                   inode=directory_stat.st_ino,
                                   mode=stat.S_IMODE(directory_stat.st_mode)),
                    files=files)
    _exclusive_file(output / 'manifest.json',
                    _canonical(manifest).encode())
    os.chmod(output / 'manifest.json', 0o400)
    return finish_doc, dict(output=str(output), manifest=manifest)


def _check_manifest(output, manifest, names, label, transport_record=None):
    _need(isinstance(manifest, dict) and manifest.get('source') == SOURCE,
          label + ' manifest source differs')
    st = output.lstat()
    _need(stat.S_ISDIR(st.st_mode) and not output.is_symlink(),
          label + ' output replaced')
    directory = manifest.get('directory') or {}
    listing = set(manifest.get('files') or {})
    _need(listing == set(names), label + ' manifest inventory',
          repr(sorted(listing)))
    for name in sorted(names):
        entry = manifest['files'][name]
        path = output / name
        _need(path.is_file() and not path.is_symlink(), label + ' missing',
              name)
        current = path.stat()
        _need(stat.S_ISREG(current.st_mode), label + ' not regular', name)
        _need(current.st_size == entry['size']
              and current.st_nlink == 1
              and stat.S_IMODE(current.st_mode) == entry['mode'] == 0o400,
              label + ' protection changed', name)
        _need(sha(path.read_bytes()) == entry['sha256'],
              label + ' hash mismatch', name)
    if transport_record is None:
        _need(directory.get('device') == st.st_dev
              and directory.get('inode') == st.st_ino
              and directory.get('mode') == stat.S_IMODE(st.st_mode),
              label + ' output replaced')
        for name in sorted(names):
            entry = manifest['files'][name]
            current = (output / name).stat()
            _need((current.st_ino, current.st_dev)
                  == (entry['inode'], entry['device']),
                  label + ' replaced with same bytes', name)
        return
    # Explicit cross-filesystem transport landing: the guest manifest
    # bytes and every guest stat identity stay the originals; the host
    # copy is pinned by content hash, protection and a stable two-read
    # directory identity instead of the guest device/inode.
    _need(isinstance(transport_record, dict)
          and set(transport_record) == {'manifest_sha256', 'directory',
                                        'files'},
          label + ' transport record malformed')
    _need(transport_record['manifest_sha256']
          == sha(_canonical(manifest).encode()),
          label + ' guest manifest changed')
    _need(transport_record['directory'] == directory,
          label + ' guest directory identity differs')
    _need(set(transport_record['files']) == set(names),
          label + ' transport inventory differs')
    for name in sorted(names):
        _need(transport_record['files'][name] == manifest['files'][name],
              label + ' guest file identity differs: ' + name)
    st_again = output.lstat()
    _need((st_again.st_dev, st_again.st_ino, st_again.st_mode)
          == (st.st_dev, st.st_ino, st.st_mode),
          label + ' host directory changed during read')


def _normalize_bundle(bundle_dir, inner, transport_record=None):
    """Re-derive the sealed boot-service observation.

    Same-filesystem reads use the accepted boot-service decoder directly.
    An explicit transport landing verifies the guest manifest and stat
    identities against the copied files and then re-decodes the records.
    """
    if transport_record is None:
        observation = normalize_boot_service(bundle_dir, inner)
        _need('decode_trust' not in observation,
              'sealed bundle channel required')
        return observation
    output = Path(bundle_dir)
    _need((output / 'manifest.json').is_file(), 'bundle manifest missing')
    manifest = json.loads((output / 'manifest.json').read_bytes())
    _need(isinstance(manifest, dict)
          and manifest.get('source') == BOOT_SERVICE_SOURCE
          and set(manifest.get('files') or {}) == {'raw.ndjson',
                                                   'observation.json'},
          'bundle manifest malformed')
    _need(isinstance(transport_record, dict)
          and set(transport_record) == {'manifest_sha256', 'directory',
                                        'files'}
          and transport_record['manifest_sha256']
          == sha(_canonical(manifest).encode())
          and transport_record['directory'] == manifest.get('directory')
          and transport_record['files'] == manifest.get('files'),
          'bundle transport record differs from the guest manifest')
    for name in ('raw.ndjson', 'observation.json'):
        path = output / name
        entry = manifest['files'][name]
        _need(path.is_file() and not path.is_symlink(),
              'bundle original missing', name)
        current = path.stat()
        _need(current.st_size == entry['size'] and current.st_nlink == 1
              and stat.S_IMODE(current.st_mode) == entry['mode'] == 0o400
              and sha(path.read_bytes()) == entry['sha256'],
              'bundle original differs from the guest manifest', name)
    st = output.lstat()
    st_again = output.lstat()
    _need(stat.S_ISDIR(st.st_mode) and not output.is_symlink()
          and (st.st_dev, st.st_ino, st.st_mode)
          == (st_again.st_dev, st_again.st_ino, st_again.st_mode),
          'bundle directory replaced')
    observation = check_records(_load_records(output / 'raw.ndjson'), inner)
    stored = json.loads((output / 'observation.json').read_bytes())
    _need(stored == observation,
          'bundle observation differs from the sealed raw records')
    return observation


def normalize_boot_resume(output_directory, expected_profile,
                          transport=None, bundle_host_dir=None):
    """Re-derive the COMPLETE resume observation from its sealed originals.

    The manifest inventory, directory identity and every file's
    inode/hash/protection are re-verified; the sealed bundle is re-decoded;
    the manager identity is bound to the independent sealed boot-service
    manager; the journal is re-checked structurally; and the canonical
    observation document is rebuilt from the records and compared VERBATIM
    with the sealed observation. No live access happens here.
    """
    profile = validate_profile(dict(expected_profile))
    inner = boot_profile(profile)
    output = Path(output_directory)
    _need((output / 'manifest.json').is_file(), 'resume output missing')
    manifest = json.loads((output / 'manifest.json').read_text())
    _check_manifest(output, manifest, RESUME_FILES, 'resume',
                    None if transport is None else transport.get('resume'))
    records = _load_records(output / 'raw.ndjson')
    observation = json.loads((output / 'observation.json').read_text())
    journal_raw = (output / 'journal.jsonl').read_bytes()
    _need(isinstance(observation, dict), 'observation not an object')
    _need(observation.get('schema') == SOURCE
          and observation.get('kind') == 'boot-resume-observation',
          'observation schema differs')
    _need([r.get('kind') for r in records] == RECORD_SEQUENCE,
          'resume record sequence differs',
          repr([r.get('kind') for r in records]))
    for index, record in enumerate(records, 1):
        _need(record.get('index') == index, 'record index gap')
        _need(type(record.get('monotonic_ns')) is int
              and record['monotonic_ns'] >= 0, 'record time missing')
        _need(index == 1 or record['monotonic_ns']
              >= records[index - 2]['monotonic_ns'],
              'record time moved backwards')
    _need(records[-1]['monotonic_ns'] - records[0]['monotonic_ns']
          <= profile['window_seconds'] * 10 ** 9, 'window exceeded')
    by_kind = {record['kind']: record for record in records}
    intent = records[0]
    _need(intent.get('source') == SOURCE
          and intent.get('profile') == profile, 'intent profile differs')
    kernel = by_kind['kernel-identity']['value']
    _need(kernel.get('boot_id') == profile['boot_id']
          and kernel.get('vm_uuid') == profile['vm_uuid'],
          'kernel identity differs')

    identity = copy.deepcopy(by_kind['manager-open'].get('identity') or {})
    peer = list(by_kind['manager-open'].get('peer') or [])
    _need(peer == [1, 0, 0], 'manager peer differs')
    _need(type(identity.get('pid')) is int and identity['pid'] == 1
          and isinstance(identity.get('birth'), str)
          and identity['birth'].isdigit()
          and isinstance(identity.get('uids'), list)
          and len(identity['uids']) == 4
          and all(type(x) is int and x == 0 for x in identity['uids'])
          and isinstance(identity.get('gids'), list)
          and len(identity['gids']) == 4
          and all(type(x) is int and x == 0 for x in identity['gids'])
          and isinstance(identity.get('image'), str)
          and identity['image'].startswith('/')
          and _hex64(identity.get('image_sha256')),
          'manager identity malformed')

    bundle_root = profile['bundle_dir']
    if transport is not None:
        _need(isinstance(bundle_host_dir, str)
              and os.path.isabs(bundle_host_dir),
              'transport requires the host bundle directory')
        bundle_root = bundle_host_dir
    bundle_observation = _normalize_bundle(
        bundle_root, inner,
        None if transport is None else transport.get('bundle'))
    _need(by_kind['bundle'].get('observation_sha256')
          == sha(_canonical(bundle_observation).encode()),
          'recorded bundle observation differs from the sealed bundle')
    actor, unit, payload = (bundle_observation['actor'],
                            bundle_observation['unit'],
                            bundle_observation['payload'])
    sealed_manager = bundle_observation.get('manager') or {}
    _need(sealed_manager.get('peer') == peer
          and sealed_manager.get('pid1') == identity,
          'manager identity differs from the independent sealed boot bundle')

    show = by_kind['unit-show']
    _need(show.get('rc') == 0 and show.get('stdout'), 'show record differs')
    properties = parse_show(show['stdout'])
    main_pid = check_properties(properties, inner)
    _need(main_pid == actor['pid'], 'recorded show pid differs')
    _need(properties['InvocationID'] == unit['invocation_id'],
          'recorded show invocation differs')
    manual = by_kind['manual-show']
    _need(manual.get('rc') == 0, 'recorded manual show rc differs')
    manual_props = {}
    for line in (manual.get('stdout') or '').splitlines():
        if line.strip() and '=' in line:
            key, value = line.split('=', 1)
            _need(key not in manual_props, 'duplicate manual show line', key)
            manual_props[key] = value
    _need(manual_props.get('RefuseManualStart') == 'yes',
          'recorded RefuseManualStart differs')
    cat = by_kind['unit-cat']
    _need(cat.get('rc') == 0
          and '# ' + properties['FragmentPath'] in cat.get('stdout', ''),
          'cat record differs')

    fragment = by_kind['fragment']
    _need(fragment.get('sha256') == profile['fragment_sha256']
          == unit['fragment_sha256'], 'fragment record differs')
    _need(fragment.get('device') == unit['fragment_identity'].get('device')
          and fragment.get('inode') == unit['fragment_identity'].get('inode')
          and fragment.get('size') == unit['fragment_identity'].get('size'),
          'fragment record differs from the sealed bundle identity')
    fragment_bytes = base64.b64decode(fragment['content'])
    fragment_lines = fragment_bytes.decode('utf-8',
                                           errors='strict').splitlines()
    _need('RefuseManualStart=yes' in fragment_lines
          and 'WantedBy=multi-user.target' in fragment_lines,
          'recorded fragment lacks the fixed start/enablement shape')
    ordering = derive_ordering(manual_props, manual['argv'], fragment_lines)
    execstart = fragment_execstart(fragment_bytes)
    _need(execstart[0] == profile['payload_path'],
          'recorded fragment ExecStart does not bind the payload')
    fragment_user(fragment_bytes, profile['expected_uid'])
    check_loaded_execstart(properties['ExecStart'], inner,
                           fragment_argv=execstart)
    payload_record = by_kind['payload']
    _need(payload_record.get('sha256') == profile['payload_sha256']
          == payload['sha256'], 'payload record differs')
    _need(payload_record.get('device') == payload['identity'].get('device')
          and payload_record.get('inode') == payload['identity'].get('inode')
          and payload_record.get('size') == payload.get('size'),
          'payload record differs from the sealed bundle identity')

    link_record = by_kind['enable-link']
    link = link_record.get('value') or {}
    link_parent = link_record.get('link_parent') or {}
    unit_parent = link_record.get('unit_parent') or {}
    payload_parent = link_record.get('payload_parent') or {}
    exe_fd = link_record.get('exe_fd') or {}
    _need(link.get('path') == profile['enable_link_path']
          and link.get('target') == profile['fragment_path']
          and link.get('uid') == 0
          and link_parent.get('uid') == 0
          and not int(link_parent.get('mode') or 0) & 0o022
          and unit_parent.get('uid') == 0
          and not int(unit_parent.get('mode') or 0) & 0o022,
          'recorded enable link/parent differs')
    _need(exe_fd.get('path') == profile['payload_path']
          and (exe_fd.get('device'), exe_fd.get('inode'))
          == (payload_record.get('device'), payload_record.get('inode')),
          'recorded exec fd does not bind the persistent payload inode')

    process = by_kind['process']
    facts = copy.deepcopy(process.get('value') or {})
    _need(process.get('pid') == actor['pid']
          and process.get('exe_read_sha256') == payload['sha256'],
          'process record differs from the sealed observation')
    for key, expected in (
            ('birth', actor['birth']), ('uids', [actor['uid']] * 4),
            ('gids', [actor['gid']] * 4), ('image', actor['exe']),
            ('image_sha256', actor['exe_sha256']),
            ('cgroup', actor['cgroup']), ('cmdline', actor['cmdline'])):
        _need(facts.get(key) == expected,
              'process record differs from the sealed observation: ' + key)
    _need(type(facts.get('uids')) is list
          and facts['uids'][:1] == [actor['uid']]
          and type(facts.get('gids')) is list
          and facts['gids'][:1] == [actor['gid']],
          'process credentials are not strict integer slots')

    journal_record = dict(by_kind['journal'])
    for key in ('index', 'kind', 'monotonic_ns'):
        journal_record.pop(key, None)
    _need(journal_record.pop('argv', None)
          == journal_argv(profile['boot_id'], profile['unit_name']),
          'journal argv differs')
    summary = dict(journal_record)
    summary['argv'] = journal_argv(profile['boot_id'], profile['unit_name'])
    fresh_summary = check_journal(
        journal_raw, profile, unit, actor,
        int(properties['ExecMainStartTimestampMonotonic']),
        identity['image'])
    fresh_summary['argv'] = summary['argv']
    _need(fresh_summary == summary,
          'journal record differs from the replayed original')
    _need(sha(journal_raw) == summary['sha256']
          and len(journal_raw) == summary['size'],
          'journal original differs from its record')

    apply_request = by_kind['scope-apply-intent'].get('request')
    receipt = by_kind['scope-apply-receipt'].get('receipt')
    _need(isinstance(apply_request, dict) and isinstance(receipt, dict),
          'scope records missing')
    scope_binding = dict(session_id=profile['session_id'],
                         owner_id=profile['owner_id'],
                         client_id=profile['client_id'],
                         vm_uuid=profile['vm_uuid'],
                         boot_id=profile['boot_id'])
    target = dict(pid=actor['pid'], birth=actor['birth'], uid=actor['uid'])
    _need(apply_request == dict(scope_binding,
                                operation_id=apply_request.get(
                                    'operation_id'),
                                targets=[target],
                                lifetime_seconds=profile[
                                    'lifetime_seconds']),
          'scope apply request differs')
    check_scope_receipt(receipt, scope_binding, target)
    source_hashes = scope_source_hashes()
    for name, value in source_hashes.items():
        _need(receipt.get('source_hashes', {}).get(name) == value,
              'scope receipt source hash differs', name)
    ready_ns = next((row['ready_ns'] for row in receipt['transitions']
                     if row.get('action') == 'applied'
                     and type(row.get('ready_ns')) is int), None)
    _need(ready_ns is not None, 'scope ready marker missing')

    recheck = by_kind['recheck']
    _need(recheck.get('show_rc') == 0
          and recheck.get('invocation_id') == unit['invocation_id']
          and recheck.get('main_pid') == str(actor['pid'])
          and recheck.get('manual_rc') == 0
          and recheck.get('refuse_manual_start') == 'yes',
          'recheck record drifted')
    for key in ('pid', 'birth', 'uids', 'gids', 'image', 'image_sha256',
                'cgroup', 'cmdline'):
        _need(recheck.get('process', {}).get(key) == facts.get(key),
              'recheck process drifted: ' + key)
    _need(recheck.get('manager') == identity, 'recheck manager drifted')
    _need(recheck.get('fragment') == file_identity(fragment)
          and recheck.get('payload') == file_identity(payload_record)
          and recheck.get('link') == link
          and recheck.get('exe_fd') == exe_fd,
          'recheck persistent object drifted')

    rebuilt = build_observation_document(
        profile=profile, unit=unit, actor=actor, payload=payload,
        identity=identity, peer=peer, target=target, summary=summary,
        binding=bind_fragment_path(properties, inner),
        properties=properties, execstart=execstart, fragment=fragment,
        payload_read=payload_record, link=link, link_parent=link_parent,
        unit_parent=unit_parent, payload_parent=payload_parent,
        exe_fd=exe_fd, request=apply_request, receipt=receipt,
        ready_ns=ready_ns, source_hashes=source_hashes,
        ordering=ordering)
    _need(rebuilt == observation,
          'observation differs from the complete replay')
    return observation


def normalize_boot_resume_finish(output_directory, expected_profile,
                                 transport=None):
    """Replay the stop/export originals; every copied product is re-hashed."""
    profile = validate_profile(dict(expected_profile))
    output = Path(output_directory)
    _need((output / 'manifest.json').is_file(), 'finish output missing')
    manifest = json.loads((output / 'manifest.json').read_text())
    names = set(manifest.get('files') or {})
    _need('finish.json' in names, 'finish document missing')
    _check_manifest(output, manifest, names, 'finish',
                    None if transport is None else transport.get('finish'))
    document = json.loads((output / 'finish.json').read_text())
    _need(isinstance(document, dict)
          and document.get('schema') == SOURCE
          and document.get('kind') == 'boot-resume-finish',
          'finish schema differs')
    scope_binding = dict(session_id=profile['session_id'],
                         owner_id=profile['owner_id'],
                         client_id=profile['client_id'],
                         vm_uuid=profile['vm_uuid'],
                         boot_id=profile['boot_id'])
    _need(document.get('binding') == scope_binding,
          'finish binding differs')
    _need(document.get('vm_uuid') == profile['vm_uuid']
          and document.get('boot_id') == profile['boot_id'],
          'finish identity differs')
    stopped, exported = document.get('stopped') or {}, \
        document.get('exported') or {}
    _need(stopped.get('status') == 'STOPPED'
          and stopped.get('collection_stopped') is True,
          'stop record differs')
    _need(exported.get('status') == 'STOPPED'
          and exported.get('collection_stopped') is True,
          'export record differs')
    _need(exported.get('generation') == 1, 'export generation differs')
    for receipt in (stopped, exported):
        _need(all(receipt.get(k) == v for k, v in scope_binding.items()),
              'finish receipt binding differs')
        for name, value in scope_source_hashes().items():
            _need(receipt.get('source_hashes', {}).get(name) == value,
                  'finish receipt source hash differs', name)
    refs = [*exported.get('products', []), exported.get('ref')]
    records = document.get('originals') or []
    _need(len(records) == len(refs), 'finish original inventory differs')
    for record, ref in zip(records, refs):
        local = output / record['local']
        _need(local.is_file() and not local.is_symlink(),
              'finish original missing', record['local'])
        raw = local.read_bytes()
        _need(record.get('ref') == ref
              and record.get('size') == len(raw)
              and record.get('sha256') == sha(raw) == ref.get('sha256'),
              'finish original differs from its reference')
    return document
