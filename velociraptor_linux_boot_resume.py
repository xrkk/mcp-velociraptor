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
    check_loaded_execstart, bounded_bytes, need, sha)
from velociraptor_linux_probe import SOURCE_ID

SOURCE = 'MalTrace.SystemBootResume.v1'
RESUME_FILES = ('raw.ndjson', 'journal.jsonl', 'observation.json')
FINISH_FILES = ('finish.json',)
JOURNAL_ARGV = ('journalctl', '--boot', None, '--unit', None,
                '--output=json', '--no-pager')
SCOPE_MODULES = ('velociraptor_linux_scope.py', 'velociraptor_linux_worker.py',
                 'velociraptor_linux_probe.py')
PROFILE_FIELDS = {'unit_name', 'vm_uuid', 'boot_id', 'expected_uid',
                  'payload_path', 'payload_sha256', 'fragment_path',
                  'fragment_sha256', 'bundle_dir', 'deployment_root',
                  'client_id', 'session_id', 'owner_id', 'lifetime_seconds',
                  'window_seconds', 'journal_max_bytes'}
BOOT_FIELDS = {'unit_name', 'vm_uuid', 'boot_id', 'expected_uid',
               'payload_path', 'payload_sha256', 'fragment_path',
               'fragment_sha256', 'window_seconds'}
RECORD_SEQUENCE = ['intent', 'kernel-identity', 'manager-open', 'bundle',
                   'unit-show', 'unit-cat', 'fragment', 'payload', 'process',
                   'journal', 'scope-apply-intent', 'scope-apply-receipt',
                   'recheck', 'observation-complete']
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


def _rederive(bundle_dir, inner_profile):
    return normalize_boot_service(bundle_dir, inner_profile)


def _client(deployment_root, binding):
    from velociraptor_linux_cli import RegisteredLinuxClient
    return RegisteredLinuxClient.for_scope(deployment_root, binding)


def journal_argv(boot_id, unit_name):
    return ['journalctl', '--boot', boot_id, '--unit', unit_name,
            '--output=json', '--no-pager']


def check_journal(raw, profile, unit, actor, main_start_us):
    """Structural journald verification against the live observations.

    Only journald's own structured fields are consumed; English message text
    is never a source of truth. An oversized journal is refused before any
    decode, never silently truncated.
    """
    _need(isinstance(raw, bytes) and len(raw) > 0, 'journal record empty')
    _need(len(raw) <= profile['journal_max_bytes'],
          'journal record exceeds the bounded size',
          '%d > %d' % (len(raw), profile['journal_max_bytes']))
    entries, first_unit, first_main, message_ids = [], None, None, set()
    for line in raw.decode('utf-8', errors='strict').splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        _need(isinstance(value, dict), 'journal entry not an object')
        _need(value.get('_BOOT_ID') == profile['boot_id'],
              'journal entry boot differs')
        entries.append(value)
    _need(entries, 'journal has no entries for the boot')
    unit_entries = [e for e in entries
                    if e.get('_SYSTEMD_UNIT') == profile['unit_name']]
    _need(unit_entries, 'journal lacks the managed unit identity')
    invocation = {e.get('INVOCATION_ID') for e in unit_entries}
    _need(invocation == {unit['invocation_id']},
          'journal invocation ids differ from the live invocation',
          repr(sorted(x for x in invocation if x is not None)))
    main = [e for e in unit_entries if e.get('_PID') == str(actor['pid'])]
    _need(main, 'journal lacks the observed main pid')
    _need(all(e.get('_BOOT_ID') == profile['boot_id'] for e in main),
          'journal main entries carry a foreign boot')
    _need(all(e.get('_EXE') == profile['payload_path'] for e in main),
          'journal main entries do not carry the payload image')
    for e in main:
        stamp = e.get('__MONOTONIC_TIMESTAMP')
        _need(isinstance(stamp, str) and stamp.isdigit(),
              'journal monotonic timestamp missing')
        value = int(stamp)
        _need(value >= main_start_us,
              'journal entry predates the native service start')
        if first_main is None or value < first_main:
            first_main = value
    for e in unit_entries:
        stamp = e.get('__MONOTONIC_TIMESTAMP')
        _need(isinstance(stamp, str) and stamp.isdigit(),
              'journal unit monotonic timestamp missing')
        if first_unit is None or int(stamp) < first_unit:
            first_unit = int(stamp)
    birth = int(actor['birth']) * 10 ** 7
    _need(first_main * 1000 >= birth - 10 ** 9,
          'first payload journal entry predates the process birth')
    _need(main_start_us * 1000 <= birth + 5 * 10 ** 9
          and main_start_us * 1000 >= birth - 5 * 10 ** 9,
          'manager start and process birth differ beyond the native bound')
    for e in unit_entries:
        if isinstance(e.get('MESSAGE_ID'), str):
            message_ids.add(e['MESSAGE_ID'])
    return dict(rc=0, size=len(raw), sha256=sha(raw), records=len(entries),
                unit_records=len(unit_entries), main_records=len(main),
                invocation_ids=sorted(x for x in invocation if x is not None),
                first_unit_monotonic_us=first_unit,
                first_main_monotonic_us=first_main,
                message_ids=sorted(message_ids))


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
                                    'ExecMainStartTimestampMonotonic']))
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
        raw.write('recheck',
                  process={key: facts2.get(key) for key in PROCESS_FACT_KEYS},
                  manager={key: identity_again[key] for key in
                           ('pid', 'birth', 'uids', 'gids', 'image',
                            'image_sha256')},
                  show_rc=show2['rc'],
                  invocation_id=properties2.get('InvocationID'),
                  main_pid=properties2.get('MainPID'))
        _need(show2['rc'] == 0
              and properties2.get('InvocationID') == unit['invocation_id']
              and properties2.get('MainPID') == str(actor['pid'])
              and properties2.get('FragmentPath')
              == properties['FragmentPath'],
              'unit recheck drifted')
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

        raw.write('observation-complete', observed_at=_now_iso(),
                  records=raw.count)
        raw.close()
        raw = None
        observation_doc = dict(
            schema=SOURCE, kind='boot-resume-observation',
            vm_uuid=profile['vm_uuid'], boot_id=profile['boot_id'],
            unit=dict(name=unit['name'],
                      fragment_path=unit['fragment_path'],
                      fragment_sha256=unit['fragment_sha256'],
                      fragment_identity=unit['fragment_identity'],
                      fragment_binding=binding,
                      invocation_id=unit['invocation_id'],
                      unit_file_state=unit['unit_file_state'],
                      main_pid=actor['pid'],
                      exec_main_start_monotonic_us=int(
                          properties['ExecMainStartTimestampMonotonic']),
                      execstart=execstart),
            payload=dict(path=payload['path'], sha256=payload['sha256'],
                         size=payload['size'], identity=payload['identity']),
            actor=dict(pid=actor['pid'], birth=actor['birth'],
                       uid=actor['uid'], gid=actor['gid'],
                       exe=actor['exe'], exe_sha256=actor['exe_sha256'],
                       cgroup=actor['cgroup'], cmdline=actor['cmdline']),
            manager=dict(pid=1, birth=identity['birth'],
                         image_sha256=identity['image_sha256'],
                         peer=peer),
            target=target,
            journal=summary,
            scope=dict(apply_request=request, apply_receipt=receipt,
                       generation=1, ready_ns=ready_ns,
                       source_hashes=source_hashes),
            limitations=list(LIMITATIONS))
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


def _check_manifest(output, manifest, names, label):
    _need(isinstance(manifest, dict) and manifest.get('source') == SOURCE,
          label + ' manifest source differs')
    st = output.lstat()
    _need(stat.S_ISDIR(st.st_mode) and not output.is_symlink(),
          label + ' output replaced')
    directory = manifest.get('directory') or {}
    _need(directory.get('device') == st.st_dev
          and directory.get('inode') == st.st_ino
          and directory.get('mode') == stat.S_IMODE(st.st_mode),
          label + ' output replaced')
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
        _need((current.st_ino, current.st_dev)
              == (entry['inode'], entry['device']),
              label + ' replaced with same bytes', name)
        _need(current.st_size == entry['size']
              and current.st_nlink == 1
              and stat.S_IMODE(current.st_mode) == entry['mode'] == 0o400,
              label + ' protection changed', name)
        _need(sha(path.read_bytes()) == entry['sha256'],
              label + ' hash mismatch', name)


def normalize_boot_resume(output_directory, expected_profile):
    """Re-derive the resume observation from its sealed originals.

    The manifest inventory, directory identity and every file's
    inode/hash/protection are re-verified; the sealed bundle is re-decoded
    and all recorded live observations are cross-checked against it. No live
    access happens here - this is the host-side replay channel.
    """
    profile = validate_profile(dict(expected_profile))
    inner = boot_profile(profile)
    output = Path(output_directory)
    _need((output / 'manifest.json').is_file(), 'resume output missing')
    manifest = json.loads((output / 'manifest.json').read_text())
    _check_manifest(output, manifest, RESUME_FILES, 'resume')
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
    intent = records[0]
    _need(intent.get('source') == SOURCE
          and intent.get('profile') == profile, 'intent profile differs')
    kernel = records[1]['value']
    _need(kernel.get('boot_id') == profile['boot_id']
          and kernel.get('vm_uuid') == profile['vm_uuid'],
          'kernel identity differs')
    manager_record = records[2]
    _need(list(manager_record.get('peer') or []) == [1, 0, 0],
          'manager peer differs')
    _need(manager_record.get('identity', {}).get('uids') == [0] * 4,
          'manager identity differs')
    bundle_observation = normalize_boot_service(profile['bundle_dir'], inner)
    _need('decode_trust' not in bundle_observation,
          'sealed bundle channel required')
    _need(records[3].get('observation_sha256')
          == sha(_canonical(bundle_observation).encode()),
          'recorded bundle observation differs from the sealed bundle')
    actor, unit, payload = (bundle_observation['actor'],
                            bundle_observation['unit'],
                            bundle_observation['payload'])
    show = records[4]
    _need(show.get('rc') == 0 and show.get('stdout'), 'show record differs')
    properties = parse_show(show['stdout'])
    main_pid = check_properties(properties, inner)
    _need(main_pid == actor['pid'], 'recorded show pid differs')
    _need(properties['InvocationID'] == unit['invocation_id'],
          'recorded show invocation differs')
    cat = records[5]
    _need(cat.get('rc') == 0
          and '# ' + properties['FragmentPath'] in cat.get('stdout', ''),
          'cat record differs')
    fragment = records[6]
    _need(fragment.get('sha256') == profile['fragment_sha256']
          == unit['fragment_sha256'], 'fragment record differs')
    payload_record = records[7]
    _need(payload_record.get('sha256') == profile['payload_sha256']
          == payload['sha256'], 'payload record differs')
    process = records[8]
    _need(process.get('pid') == actor['pid']
          and process.get('value', {}).get('birth') == actor['birth']
          and process.get('value', {}).get('cmdline') == actor['cmdline']
          and process.get('exe_read_sha256') == payload['sha256'],
          'process record differs from the sealed observation')
    journal_record = dict(records[9])
    _need(journal_record.pop('argv', None)
          == journal_argv(profile['boot_id'], profile['unit_name']),
          'journal argv differs')
    summary = dict(journal_record)
    summary['argv'] = journal_argv(profile['boot_id'], profile['unit_name'])
    _need(sha(journal_raw) == summary['sha256']
          and len(journal_raw) == summary['size'],
          'journal original differs from its record')
    _need(summary.get('unit_records', 0) > 0
          and summary.get('main_records', 0) > 0,
          'journal record incomplete')
    _need(summary.get('invocation_ids') == [unit['invocation_id']],
          'journal invocation record differs')
    check_journal(journal_raw, profile, unit, actor,
                  int(properties['ExecMainStartTimestampMonotonic']))
    apply_request = records[10].get('request')
    receipt = records[11].get('receipt')
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
    recheck = records[12]
    _need(recheck.get('show_rc') == 0
          and recheck.get('invocation_id') == unit['invocation_id']
          and recheck.get('main_pid') == str(actor['pid'])
          and recheck.get('process', {}).get('birth') == actor['birth']
          and recheck.get('process', {}).get('cmdline') == actor['cmdline']
          and recheck.get('manager', {}).get('image_sha256')
          == records[2]['identity']['image_sha256'],
          'recheck record drifted')
    _need(observation.get('vm_uuid') == profile['vm_uuid']
          and observation.get('boot_id') == profile['boot_id']
          and observation.get('target') == target
          and observation.get('actor', {}).get('pid') == actor['pid']
          and observation.get('actor', {}).get('birth') == actor['birth']
          and observation.get('unit', {}).get('invocation_id')
          == unit['invocation_id']
          and observation.get('payload', {}).get('sha256')
          == payload['sha256']
          and observation.get('journal', {}).get('sha256')
          == summary['sha256']
          and observation.get('scope', {}).get('apply_receipt') == receipt,
          'observation differs from the replayed originals')
    return observation


def normalize_boot_resume_finish(output_directory, expected_profile):
    """Replay the stop/export originals; every copied product is re-hashed."""
    profile = validate_profile(dict(expected_profile))
    output = Path(output_directory)
    _need((output / 'manifest.json').is_file(), 'finish output missing')
    manifest = json.loads((output / 'manifest.json').read_text())
    names = set(manifest.get('files') or {})
    _need('finish.json' in names, 'finish document missing')
    _check_manifest(output, manifest, names, 'finish')
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
