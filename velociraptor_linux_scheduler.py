"""Bounded first-invocation user timer evidence, not a general scheduler claim.

Private systemd peer credentials, fanotify inode snapshots under read leases,
and live process credentials are independent of sample output. The collector
never starts a payload. Only a complete observed chain can extend kernel scope.
"""
import base64
import ctypes as C
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import threading
import time

SOURCE = 'MalTrace.UserTimer.v1'
PERMISSION = 0x10000 | 0x40000
CLOSE_WRITE = 0x8
OVERFLOW = 0x4000


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def process(pid, image_hash=True):
    p = Path('/proc') / str(pid)
    before = (p / 'stat').read_text()
    fields = dict(x.split(':', 1) for x in (p / 'status').read_text().splitlines())
    st = (p / 'exe').stat()
    value = dict(pid=pid, birth=before.rsplit(')', 1)[1].split()[19],
                 parent_pid=int(before.rsplit(')', 1)[1].split()[1]),
                 uids=list(map(int, fields['Uid'].split())),
                 gids=list(map(int, fields['Gid'].split())),
                 groups=list(map(int, fields['Groups'].split())),
                 image=os.readlink(p / 'exe'), device=st.st_dev, inode=st.st_ino,
                 cgroup=(p / 'cgroup').read_text(),
                 cmdline=(p / 'cmdline').read_bytes().decode().split('\0')[:-1])
    if image_hash:
        value['image_sha256'] = sha((p / 'exe').read_bytes())
    need((p / 'stat').read_text().rsplit(')', 1)[1].split()[19] == value['birth'], 'PID reused')
    return value


class PrivateManager:
    """sd-bus peer mode (busctl's message-bus mode does not fit this socket)."""
    def __init__(self, path, expected):
        self.lib = C.CDLL('libsystemd.so.0')
        ptr, string = C.c_void_p, C.c_char_p
        declarations = [
            ('sd_bus_new', [C.POINTER(ptr)], C.c_int),
            ('sd_bus_set_address', [ptr, string], C.c_int),
            ('sd_bus_set_bus_client', [ptr, C.c_int], C.c_int),
            ('sd_bus_set_method_call_timeout', [ptr, C.c_uint64], C.c_int),
            ('sd_bus_start', [ptr], C.c_int), ('sd_bus_get_fd', [ptr], C.c_int),
            ('sd_bus_get_property', [ptr, string, string, string, string, ptr, C.POINTER(ptr), string], C.c_int),
            ('sd_bus_message_peek_type', [ptr, C.POINTER(C.c_char), C.POINTER(string)], C.c_int),
            ('sd_bus_message_enter_container', [ptr, C.c_char, string], C.c_int),
            ('sd_bus_message_exit_container', [ptr], C.c_int),
            ('sd_bus_message_read_basic', [ptr, C.c_char, ptr], C.c_int),
            ('sd_bus_message_unref', [ptr], ptr), ('sd_bus_unref', [ptr], ptr)]
        for name, args, result in declarations:
            f = getattr(self.lib, name)
            f.argtypes, f.restype = args, result
        self.bus = ptr()
        self.check(self.lib.sd_bus_new(C.byref(self.bus)))
        try:
            self.check(self.lib.sd_bus_set_address(self.bus, ('unix:path=' + path).encode()))
            self.check(self.lib.sd_bus_set_bus_client(self.bus, 0))
            self.check(self.lib.sd_bus_set_method_call_timeout(self.bus, 1000000))
            self.check(self.lib.sd_bus_start(self.bus))
            with socket.fromfd(self.check(self.lib.sd_bus_get_fd(self.bus)), socket.AF_UNIX, socket.SOCK_STREAM) as s:
                self.peer = list(struct.unpack('3i', s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)))
            need(self.peer == [expected['pid'], expected['uids'][1], expected['gids'][1]], 'foreign manager peer')
            current = process(expected['pid'])
            need(all(current[k] == expected[k] for k in ('birth', 'uids', 'gids', 'image', 'image_sha256')), 'manager drift')
        except BaseException:
            self.close()
            raise

    @staticmethod
    def check(result):
        if result < 0:
            raise OSError(-result, 'sd-bus')
        return result

    def read(self, message):
        kind, contents = C.c_char(), C.c_char_p()
        if not self.check(self.lib.sd_bus_message_peek_type(message, C.byref(kind), C.byref(contents))):
            return None
        kind = kind.value
        if kind in (b'a', b'r', b'e', b'v'):
            self.check(self.lib.sd_bus_message_enter_container(message, kind, contents.value))
            values = []
            while True:
                value = self.read(message)
                if value is None:
                    break
                values.append(value)
            self.check(self.lib.sd_bus_message_exit_container(message))
            return values
        cls = {b's': C.c_char_p, b'o': C.c_char_p, b'g': C.c_char_p, b'b': C.c_int,
               b'u': C.c_uint32, b'i': C.c_int32, b't': C.c_uint64, b'x': C.c_int64, b'y': C.c_uint8}[kind]
        value = cls()
        self.check(self.lib.sd_bus_message_read_basic(message, kind, C.byref(value)))
        return value.value.decode() if cls is C.c_char_p else value.value

    def get(self, unit, interface, name, signature):
        need(re.fullmatch(r'[a-zA-Z0-9_.-]+', unit), 'unsupported unit name')
        escaped = ''.join(c if c.isalnum() else '_%02x' % ord(c) for c in unit)
        path = '/org/freedesktop/systemd1/unit/' + escaped
        reply = C.c_void_p()
        result = self.lib.sd_bus_get_property(self.bus, None, path.encode(),
            ('org.freedesktop.systemd1.' + interface).encode(), name.encode(), None, C.byref(reply), signature.encode())
        if result < 0:
            raise OSError(-result, 'sd-bus ' + unit + ':' + interface + '.' + name)
        try:
            return self.read(reply)
        finally:
            self.lib.sd_bus_message_unref(reply)

    def close(self):
        if self.bus:
            self.lib.sd_bus_unref(self.bus)
            self.bus = None


def validate_profile(config):
    need(set(config) == {'directory', 'service', 'timer', 'payload', 'manager', 'socket', 'window_seconds'}, 'scheduler fields')
    directory = Path(config['directory'])
    need(directory.is_absolute() and directory.name and not directory.is_symlink(), 'scheduler directory')
    need(type(config['window_seconds']) is int and 1 <= config['window_seconds'] <= 30, 'scheduler deadline')
    for key in ('service', 'timer', 'payload'):
        need(re.fullmatch(r'[a-zA-Z0-9_.-]{1,30}', config[key]), 'short flat name required')
    need(config['service'].endswith('.service') and config['timer'].endswith('.timer')
         and len({config[k] for k in ('service', 'timer', 'payload')}) == 3, 'scheduler names')
    need(config['manager']['uids'][1] > 0, 'ordinary manager required')


def validate_fresh(units, config):
    need(set(units) == {config['service'], config['timer']}, 'fresh unit inventory')
    for value in units.values():
        need(value['LoadState'] == 'not-found' and value['ActiveState'] == 'inactive'
             and value['FragmentPath'] == '' and value['ActivationDetails'] == []
             and not any(value['InvocationID']), 'existing definition or invocation')


class Collector:
    """No new process/socket: one bounded fanotify drain thread plus caller tick.

    Read leases freeze observed inodes, not names. A competing writable open
    breaks the lease and invalidates the entire chain; rename/replacement is
    caught by the inode used by manager/exec. Short-lived missed writers or
    payloads are unavailable. Close releases all permissions and leases.
    """
    def __init__(self, config, output, binding, root):
        validate_profile(config)
        self.config, self.binding, self.root = config, binding, root
        self.directory = Path(config['directory'])
        need(not list(self.directory.iterdir()), 'artifact directory must start empty')
        self.directory_stat = self.directory.stat()
        self.output = Path(output)
        self.output.mkdir(mode=0o700)
        self.stream = (self.output / 'raw.ndjson').open('xb', buffering=0)
        os.chmod(self.output / 'raw.ndjson', 0o600)
        self.lock = threading.Lock()
        self.records, self.leases, self.execs = [], {}, []
        self.error, self.closed, self.lease_broken = None, False, False
        self.finish_event = threading.Event()
        self.manager = None
        self.fd = -1
        self.thread = None
        self.old_sigio = signal.getsignal(signal.SIGIO)
        self.deadline = time.monotonic() + 90
        self.invocation = None
        self.last_tick = 0
        self.record('intent', config=config, binding=binding, root=root, source=SOURCE,
                    directory_inode=self.directory_stat.st_ino, directory_device=self.directory_stat.st_dev)
        try:
            self.manager = PrivateManager(config['socket'], config['manager'])
            fresh = {}
            for name in (config['service'], config['timer']):
                # systemd's object lookup may create a not-found stub. Its Id
                # is not evidence that a definition or invocation existed.
                fresh[name] = {key: self.manager.get(name, 'Unit', key, signature)
                    for key, signature in [('LoadState','s'), ('ActiveState','s'),
                        ('FragmentPath','s'), ('ActivationDetails','a(ss)'), ('InvocationID','ay')]}
            validate_fresh(fresh, config)
            self.record('fresh', peer=self.manager.peer,
                        absent=[config['service'], config['timer']], units=fresh)
            libc = C.CDLL(None, use_errno=True)
            libc.fanotify_init.argtypes = [C.c_uint, C.c_uint]
            libc.fanotify_mark.argtypes = [C.c_int, C.c_uint, C.c_uint64, C.c_int, C.c_char_p]
            self.fd = libc.fanotify_init(0x4 | 0x1 | 0x2, os.O_RDONLY | os.O_CLOEXEC | os.O_LARGEFILE)
            if self.fd < 0:
                raise OSError(C.get_errno(), 'fanotify_init')
            if libc.fanotify_mark(self.fd, 0x1, PERMISSION | CLOSE_WRITE | 0x8000000, -100, str(self.directory).encode()) < 0:
                raise OSError(C.get_errno(), 'fanotify_mark')
            signal.signal(signal.SIGIO, lambda *_: setattr(self, 'lease_broken', True))
            self.thread = threading.Thread(target=self.drain, name='bounded-user-timer-evidence')
            self.thread.start()
            self.record('ready', deadline_ns=time.monotonic_ns() + 90 * 10**9)
        except BaseException:
            self.close()
            raise

    def record(self, kind, **fields):
        with self.lock:
            row = dict(kind=kind, monotonic_ns=time.monotonic_ns(), **fields)
            need(len(self.records) < 1000 and self.stream.tell() < 16*1024*1024, 'scheduler output bound')
            self.stream.write((json.dumps(row, sort_keys=True) + '\n').encode())
            self.records.append(row)
            return row

    def fail(self, error):
        self.error = self.error or str(error)
        self.finish_event.set()

    def snapshot(self, fd):
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 2*1024*1024, 'unsupported artifact')
        raw = os.pread(fd, before.st_size + 1, 0)
        after = os.fstat(fd)
        need((before.st_ino, before.st_dev, before.st_size, before.st_ctime_ns, before.st_mtime_ns) ==
             (after.st_ino, after.st_dev, after.st_size, after.st_ctime_ns, after.st_mtime_ns)
             and len(raw) == before.st_size, 'artifact changed during read')
        return dict(inode=before.st_ino, device=before.st_dev, size=len(raw), sha256=sha(raw),
                    content=base64.b64encode(raw).decode(), path=os.readlink('/proc/self/fd/' + str(fd)))

    def drain(self):
        try:
            while not self.finish_event.is_set() and time.monotonic() < self.deadline:
                need(not self.lease_broken, 'read lease broken: mutable version unavailable')
                if not select.select([self.fd], [], [], .02)[0]:
                    continue
                data = os.read(self.fd, 65536)
                offset = 0
                while offset < len(data):
                    length, version, _, metadata, mask, fd, pid = struct.unpack_from('=IBBHQii', data, offset)
                    need(version == 3 and length >= 24 and metadata == 24, 'fanotify metadata unsupported')
                    offset += length
                    need(not mask & OVERFLOW and fd >= 0, 'fanotify loss')
                    keep = False
                    try:
                        path = os.readlink('/proc/self/fd/' + str(fd))
                        name = Path(path).name
                        need(Path(path).parent == self.directory and name in
                             {self.config[k] for k in ('service', 'timer', 'payload')}, 'foreign/replaced artifact')
                        if mask & CLOSE_WRITE:
                            need(name not in self.leases, 'second content version')
                            actor = process(pid, image_hash=False)
                            fcntl.fcntl(fd, fcntl.F_SETOWN, os.getpid())
                            # CLOSE_WRITE can be queued just before the writable
                            # file reference finishes closing. Retry only EAGAIN
                            # for this exact fd, without changing the observation.
                            until = time.monotonic() + .1
                            while True:
                                try:
                                    fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
                                    break
                                except OSError as error:
                                    if error.errno != 11 or time.monotonic() >= until:
                                        raise
                                    time.sleep(.001)
                            value = self.snapshot(fd)
                            need(process(pid, False)['birth'] == actor['birth'], 'writer disappeared or reused')
                            self.leases[name] = (fd, value)
                            keep = True
                            self.record('closed-write', actor=actor, file=value, lease='F_RDLCK')
                        elif mask & PERMISSION:
                            # The permission event fd names the inode actually
                            # opened, including through a replaced path.
                            actor = process(pid, image_hash=False)
                            manager = self.config['manager']
                            is_manager = (pid, actor['birth']) == (manager['pid'], manager['birth'])
                            is_exec = bool(mask & 0x40000)
                            if is_manager or is_exec:
                                need(name in self.leases, 'use without observed closed version')
                                value = self.snapshot(fd)
                                held = self.leases[name][1]
                                need(all(value[k] == held[k] for k in ('inode', 'device', 'sha256', 'size', 'path')), 'used version differs')
                                self.record('exec-open' if is_exec else 'manager-open', actor=actor, file=value)
                                if is_exec:
                                    self.execs.append((actor, value))
                    finally:
                        if mask & PERMISSION:
                            os.write(self.fd, struct.pack('=iI', fd, 1))  # FAN_ALLOW; collector is not a policy engine.
                        if not keep:
                            os.close(fd)
            if not self.finish_event.is_set():
                self.fail('scheduler collection deadline')
        except BaseException as error:
            self.fail(error)
        finally:
            # Closing the group releases queued permission events. Held leases
            # are released even if the owner cancels while root still runs.
            if self.fd >= 0:
                os.close(self.fd)
                self.fd = -1
            for fd, _ in self.leases.values():
                try:
                    fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
                    os.close(fd)
                except OSError:
                    pass

    def tick(self):
        need(not self.error, self.error or 'scheduler source failed')
        if time.monotonic() - self.last_tick < .1 or not self.execs:
            return
        self.last_tick = time.monotonic()
        c = self.config
        pid = self.manager.get(c['service'], 'Service', 'MainPID', 'u')
        if not pid:
            return
        actor = process(pid, False)
        matches = [(p, f) for p, f in self.execs if (p['pid'], p['birth']) == (pid, actor['birth'])]
        if not matches or actor['image'] != str(self.directory / c['payload']):
            return
        # /proc/exe can already name the new inode while exec is still
        # installing argv. Preserve the transient observation and wait for
        # the selected no-argument command before starting a proof transaction.
        if actor['cmdline'] != [str(self.directory / c['payload'])]:
            self.record('exec-transition', actor=actor)
            return
        invocation = self.manager.get(c['service'], 'Unit', 'InvocationID', 'ay')
        if self.invocation is not None:
            need(invocation == self.invocation, 'second invocation unsupported')
            return
        self.invocation = invocation
        self.record('invocation-probe', actor=actor, invocation_id=invocation, peer=self.manager.peer)
        service, timer = {}, {}
        for name, interface, sig in [('ActivationDetails','Unit','a(ss)'), ('InvocationID','Unit','ay'),
                ('ControlGroup','Service','s'), ('FragmentPath','Unit','s'), ('DropInPaths','Unit','as'),
                ('ExecStart','Service','a(sasbttttuii)'), ('NRestarts','Service','u'),
                ('RefuseManualStart','Unit','b'), ('MainPID','Service','u')]:
            service[name] = self.manager.get(c['service'], interface, name, sig)
            self.record('manager-property', unit=c['service'], interface=interface, property=name, value=service[name])
        for name, interface, sig in [('Unit','Timer','s'), ('LastTriggerUSecMonotonic','Timer','t'),
                ('TimersMonotonic','Timer','a(stt)'), ('FragmentPath','Unit','s'), ('DropInPaths','Unit','as'),
                ('Persistent','Timer','b'), ('ActivationDetails','Unit','a(ss)')]:
            timer[name] = self.manager.get(c['timer'], interface, name, sig)
            self.record('manager-property', unit=c['timer'], interface=interface, property=name, value=timer[name])
        need(process(pid, False) == actor, 'instance changed during manager query')
        self.invocation = invocation
        self.record('invocation', service=service, timer=timer, actor=actor, peer=self.manager.peer)

    def close(self):
        if self.closed:
            return
        if self.manager and self.thread:
            try:
                current = process(self.config['manager']['pid'])
                need(all(current[k] == self.config['manager'][k] for k in
                         ('birth', 'uids', 'gids', 'image', 'image_sha256')), 'cleanup manager drift')
                for unit in (self.config['timer'], self.config['service']):
                    try:
                        fragment = self.manager.get(unit, 'Unit', 'FragmentPath', 's')
                    except OSError as error:
                        need(error.errno in (2, 6, 53), 'cleanup unit unknown')
                        continue
                    need(fragment == str(self.directory / unit), 'cleanup unit ownership unknown')
                    argv = ['sudo', '-n', '-u', '#' + str(current['uids'][1]), 'env',
                            'XDG_RUNTIME_DIR=' + str(Path(self.config['socket']).parent.parent),
                            'DBUS_SESSION_BUS_ADDRESS=unix:path=' + self.config['socket'],
                            '/usr/bin/systemctl', '--user', 'stop', unit]
                    self.record('stop-intent', argv=argv)
                    result = subprocess.run(argv, capture_output=True, text=True, timeout=8)
                    self.record('stop-result', rc=result.returncode, stdout=result.stdout, stderr=result.stderr)
                    need(result.returncode == 0, 'owned unit stop unknown')
                if self.invocation:
                    argv = ['journalctl', '--no-pager', '--output=json',
                            '_SYSTEMD_INVOCATION_ID=' + bytes(self.invocation).hex(),
                            '_UID=' + str(current['uids'][1])]
                    result = subprocess.run(argv, capture_output=True, timeout=5)
                    need(result.returncode == 0 and len(result.stdout) <= 1024*1024, 'journal original unavailable')
                    self.record('journal', argv=argv, rc=result.returncode,
                                stdout_base64=base64.b64encode(result.stdout).decode(),
                                stderr_base64=base64.b64encode(result.stderr).decode())
            except BaseException as error:
                self.error = self.error or 'CLEANUP_UNKNOWN:' + str(error)
        self.finish_event.set()
        if self.thread:
            self.thread.join(2)
            need(not self.thread.is_alive(), 'scheduler drain stop unknown')
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


def qualify(rows, *, config, binding, root, credentials, kernel, boundary_ns):
    """Shared complete-chain qualification for online admission and sealed replay.

    Only a complete first timer invocation emits semantic records. Every source
    fact remains mapped to raw row numbers; missing/ambiguous facts raise rather
    than silently falling back to names, time proximity, or sample assertions.
    """
    import configparser
    validate_profile(config)
    need(rows and [r['monotonic_ns'] for r in rows] == sorted(r['monotonic_ns'] for r in rows), 'scheduler order')
    kinds = {}
    for i, row in enumerate(rows):
        kinds.setdefault(row['kind'], []).append((i + 1, row))
    for name in ('intent', 'fresh', 'ready', 'invocation'):
        need(len(kinds.get(name, [])) == 1, 'missing/duplicate ' + name)
    intent, fresh, fire = [kinds[k][0][1] for k in ('intent', 'fresh', 'invocation')]
    need(intent['source'] == SOURCE and intent['config'] == config and intent['binding'] == binding
         and intent['root'] == root, 'scheduler independent expectation mismatch')
    manager = config['manager']
    validate_fresh(fresh['units'], config)
    need(fresh['absent'] == [config['service'], config['timer']]
         and fresh['peer'] == fire['peer'] == [manager['pid'], manager['uids'][1], manager['gids'][1]], 'manager/freshness conflict')
    boot = binding['boot_id']
    need(root['boot_id'] == boot, 'scheduler boot conflict')
    root_key = (root['pid'], root['start_time'])

    def key(actor):
        return actor['pid'], actor['birth']

    def live(actor, ns):
        members, seen = {root_key}, {root_key}
        for event in kernel:
            if event['monotonic_ns'] > ns:
                break
            k = (event['pid'], event['birth'])
            need(k in members and (event['root_pid'], event['root_birth']) == root_key, 'foreign kernel member')
            if event['kind'] == 'fork':
                child = (event['detail'][0], str(event['detail'][1]))
                need(child not in seen, 'reused child')
                seen.add(child)
                members.add(child)
            elif event['kind'] == 'exit':
                members.remove(k)
        return key(actor) in members

    closes = kinds.get('closed-write', [])
    need(len(closes) == 3, 'one version of all three artifacts required')
    files, writes = {}, {}
    for number, row in closes:
        value, actor = row['file'], row['actor']
        name = Path(value['path']).name
        need(name in {config[k] for k in ('payload', 'service', 'timer')} and name not in files
             and value['path'] == str(Path(config['directory']) / name), 'foreign/duplicate artifact')
        raw = base64.b64decode(value['content'], validate=True)
        need(len(raw) == value['size'] and sha(raw) == value['sha256'] and row['lease'] == 'F_RDLCK', 'unbound artifact content')
        need(live(actor, row['monotonic_ns']) and actor['uids'] == credentials['uids']
             and actor['gids'] == credentials['gids'] and actor['groups'] == credentials['groups'], 'unknown/dead writer identity')
        dev = (os.major(value['device']) << 20) | os.minor(value['device'])
        need(any(e['kind'] == 'modify' and (e['pid'], e['birth']) == key(actor)
                 and e['monotonic_ns'] < row['monotonic_ns'] and not e['strings_may_be_truncated']
                 and e['detail'][:3] == [name, intent['directory_inode'], dev] and e['detail'][3] > 0
                 for e in kernel), 'actual content write missing')
        files[name] = (value, raw)
        writes[name] = (number, row)
    payload, service, timer = [files[config[k]] for k in ('payload', 'service', 'timer')]
    need(payload[1].startswith(b'\x7fELF'), 'only native ELF payload supported')

    def parse(raw, allowed):
        c = configparser.ConfigParser(interpolation=None, strict=True)
        c.optionxform = str
        c.read_string(raw.decode())
        need(not c.defaults() and set(c.sections()) == set(allowed), 'unsupported definition sections')
        need(all(set(c[s]) == allowed[s] for s in allowed), 'unsupported definition options')
        return c

    s = parse(service[1], {'Unit': {'Description','DefaultDependencies','RefuseManualStart'},
        'Service': {'Type','ExecStart','Restart','RuntimeMaxSec','StandardOutput','StandardError'}})
    t = parse(timer[1], {'Unit': {'Description','DefaultDependencies'},
        'Timer': {'Unit','OnActiveSec','AccuracySec','RemainAfterElapse','Persistent'}})
    need(s['Unit']['DefaultDependencies'] == t['Unit']['DefaultDependencies'] == 'no'
         and s['Unit']['RefuseManualStart'] == 'yes' and s['Service']['Type'] == 'exec'
         and s['Service']['ExecStart'] == payload[0]['path'] and s['Service']['Restart'] == 'no'
         and re.fullmatch(r'(?:[4-9]|[12][0-9]|30)s', s['Service']['RuntimeMaxSec'])
         and s['Service']['StandardOutput'] == s['Service']['StandardError'] == 'journal'
         and t['Timer']['Unit'] == config['service'] and t['Timer']['AccuracySec'] == '1ms'
         and t['Timer']['RemainAfterElapse'] == 'yes' and t['Timer']['Persistent'] == 'no'
         and re.fullmatch(r'[1-9]s', t['Timer']['OnActiveSec']), 'unsupported definition semantics')
    loaded = {}
    for number, row in kinds.get('manager-open', []):
        actor, f = row['actor'], row['file']
        need(key(actor) == key(manager) and actor['uids'] == manager['uids'], 'foreign definition loader')
        name = Path(f['path']).name
        need(name in files and all(f[k] == files[name][0][k] for k in ('path','inode','device','sha256','content','size')), 'loaded definition version mismatch')
        loaded.setdefault(name, number)
    need(all(config[k] in loaded for k in ('service', 'timer')), 'actual definition load missing')
    sp, tp, actor = fire['service'], fire['timer'], fire['actor']
    details = dict(sp['ActivationDetails'])
    need(len(sp['ActivationDetails']) == len(details) == 3 and details['trigger_unit'] == config['timer'], 'real timer fire missing')
    trigger_ns = int(details['trigger_timer_monotonic_usec']) * 1000
    need(int(details['trigger_timer_realtime_usec']) > 0 and trigger_ns > 0
         and tp['LastTriggerUSecMonotonic'] * 1000 == trigger_ns
         and tp['Unit'] == config['service'] and tp['Persistent'] == 0
         and tp['ActivationDetails'] == [] and len(tp['TimersMonotonic']) == 1
         and tp['TimersMonotonic'][0][:2] == ['OnActiveUSec', int(t['Timer']['OnActiveSec'][:-1]) * 1000000], 'timer facts conflict')
    need(sp['RefuseManualStart'] == 1 and sp['NRestarts'] == 0
         and sp['DropInPaths'] == tp['DropInPaths'] == []
         and sp['FragmentPath'] == service[0]['path'] and tp['FragmentPath'] == timer[0]['path']
         and len(sp['InvocationID']) == 16 and any(sp['InvocationID'])
         and sp['MainPID'] == actor['pid'] and actor['parent_pid'] == manager['pid']
         and actor['uids'] == credentials['uids'] and actor['gids'] == credentials['gids']
         and actor['groups'] == credentials['groups'], 'invocation/credentials conflict')
    need(len(sp['ExecStart']) == 1 and sp['ExecStart'][0][:3] == [payload[0]['path'], [payload[0]['path']], False], 'effective ExecStart conflict')
    need(sp['ControlGroup'] and any(x.endswith(':' + sp['ControlGroup']) for x in actor['cgroup'].splitlines()), 'service cgroup conflict')
    need(actor['image'] == payload[0]['path'] and actor['cmdline'] == [payload[0]['path']] and all(actor[k] == payload[0][k] for k in ('inode','device')), 'actual executed inode differs')
    opens = [(n, r) for n, r in kinds.get('exec-open', []) if key(r['actor']) == key(actor)]
    need(len(opens) == 1 and all(opens[0][1]['file'][k] == payload[0][k] for k in ('path','inode','device','sha256','content','size'))
         and opens[0][1]['actor']['parent_pid'] == manager['pid'], 'actual exec open missing or replaced')
    exits = [e for e in kernel if e['kind'] == 'exit' and (e['pid'], e['birth']) == root_key]
    ready = kinds['ready'][0][1]
    root_execs = [e for e in kernel if e['kind'] == 'exec' and (e['pid'], e['birth']) == root_key]
    need(len(root_execs) == 1 and ready['monotonic_ns'] < root_execs[0]['monotonic_ns']
         and fire['monotonic_ns'] < ready['deadline_ns'], 'scheduler not ready or expired')
    need(len(exits) == 1 and fire['monotonic_ns'] <= exits[0]['monotonic_ns'] + config['window_seconds'] * 10**9, 'post-root window expired')
    need(len(exits) == 1 and exits[0]['monotonic_ns'] < trigger_ns <= opens[0][1]['monotonic_ns'] <= fire['monotonic_ns'] < boundary_ns, 'post-root fire order missing')
    a = writes[config['payload']]
    d = max((writes[config['service']], writes[config['timer']]), key=lambda item: item[1]['monotonic_ns'])
    need(a[1]['monotonic_ns'] < d[1]['monotonic_ns'] < trigger_ns
         and writes[config['service']][1]['actor'] == writes[config['timer']][1]['actor'], 'definition author/order conflict')
    version = sha(json.dumps([service[0]['sha256'], timer[0]['sha256'], payload[0]['sha256']], separators=(',', ':')).encode())
    definition_id = 'user:%d:%s' % (manager['uids'][1], config['timer'])
    def instance(a):
        return dict(boot_id=boot, pid=a['pid'], start_time=a['birth'])
    return [dict(kind='artifact', instance=instance(a[1]['actor']), artifact_path=payload[0]['path'],
                 artifact_sha256=payload[0]['sha256'], monotonic_ns=a[1]['monotonic_ns'], source_rows=[a[0]]),
            dict(kind='definition', instance=instance(d[1]['actor']), artifact_path=payload[0]['path'],
                 definition_id=definition_id, definition_mechanism='timer', definition_version=version,
                 definition_binds_sha256=payload[0]['sha256'], monotonic_ns=d[1]['monotonic_ns'],
                 source_rows=[writes[config['service']][0], writes[config['timer']][0], loaded[config['service']], loaded[config['timer']]]),
            dict(kind='scheduler-fire', fired_instance=instance(actor), image=payload[0]['path'],
                 executable_sha256=payload[0]['sha256'], fire_definition_id=definition_id,
                 fire_definition_version=version, monotonic_ns=trigger_ns,
                 execution_identity=actor, invocation_id=bytes(sp['InvocationID']).hex(),
                 source_rows=[kinds['fresh'][0][0], opens[0][0], kinds['invocation'][0][0]])]


def normalize(rows, **arguments):
    """Final replay requires actual closure, never a fabricated online close."""
    ends = [r for r in rows if r['kind'] == 'closed']
    need(len(ends) == 1 and not ends[0]['error'] and not ends[0]['lease_broken'],
         'incomplete or mutable scheduler originals')
    return qualify(rows, boundary_ns=ends[0]['monotonic_ns'], **arguments)


class FollowingCollector(Collector):
    """One qualified extension, with the existing autonomous scope deadline.

    The extension origin is the fired instance, NOT an invented root fork.
    All decisions and the real acknowledgment are retained beside raw facts.
    Scope stop/export remains the caller's existing finally obligation, even
    for an unknown extension outcome. Failed admission is never retried.
    """
    def __init__(self, config, output, binding, root, credentials, client):
        self.credentials, self.client = credentials, client
        self.follow_attempted = False
        super().__init__(config, output, binding, root)

    def kernel_prefix(self):
        from velociraptor_linux_probe import decode
        path = self.output.parent / 'generations/1/raw.ndjson'
        raw = path.read_bytes()
        need(len(raw) <= 16*1024*1024, 'kernel prefix bound')
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
        return events, dict(path=str(path), size=len(complete), sha256=sha(complete))

    def tick(self):
        super().tick()
        if self.follow_attempted or not any(r['kind'] == 'invocation' for r in self.records):
            return
        self.follow_attempted = True
        try:
            import math
            import uuid
            need(not self.error and not self.lease_broken and not self.finish_event.is_set(),
                 'scheduler source unhealthy')
            need(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == self.binding['boot_id'],
                 'admission boot conflict')
            with self.lock:
                rows = list(self.records)
            kernel, prefix = self.kernel_prefix()
            proof = qualify(rows, config=self.config, binding=self.binding, root=self.root,
                            credentials=self.credentials, kernel=kernel, boundary_ns=time.monotonic_ns())
            fire = proof[-1]
            actor = process(fire['fired_instance']['pid'])
            need(all(actor[k] == fire['execution_identity'][k] for k in fire['execution_identity'])
                 and actor['image_sha256'] == fire['executable_sha256'], 'admission instance drift')
            root_exit = next(e['monotonic_ns'] for e in kernel if e['kind'] == 'exit'
                             and (e['pid'], e['birth']) == (self.root['pid'], self.root['start_time']))
            until = root_exit + self.config['window_seconds'] * 10**9
            remaining = (until - time.monotonic_ns()) / 10**9
            need(remaining >= 5, 'insufficient admission window')
            target = dict(pid=actor['pid'], birth=actor['birth'], uid=actor['uids'][1])
            request = dict(self.binding, operation_id=str(uuid.uuid4()), targets=[target],
                           reason='qualified first user timer invocation ' + fire['invocation_id'],
                           expires_in_seconds=math.ceil(remaining) + 5, termination='scope stop or bounded extension expiry')
            self.record('admission-intent', proof=proof, kernel_prefix=prefix, actor=actor,
                        request=request, observation_deadline_ns=until)
            need(not self.error and not self.lease_broken, 'source changed before admission')
            receipt = self.client.call('linux_scope_extend', {'request': request})
            need(receipt.get('status') == 'APPLIED' and receipt.get('backend_applied') is True
                 and receipt.get('generation') == 2 and receipt['extension']['targets'] == [target]
                 and all(receipt[k] == self.binding[k] for k in self.binding), 'extension not ready')
            applied = [t for t in receipt['transitions'] if t['action'] == 'applied' and t['generation'] == 2]
            need(len(applied) == 1 and applied[0]['ready_ns'] < receipt['extension']['expires_ns'],
                 'extension readiness missing or expired')
            need(not self.error and not self.lease_broken, 'source changed during admission')
            live = process(actor['pid'])
            need(live == actor, 'payload exited or changed before readiness acknowledgment')
            self.record('admission-ready', receipt=receipt, actor=live,
                        ready_ns=applied[0]['ready_ns'], fire_to_ready_ns=applied[0]['ready_ns']-fire['monotonic_ns'],
                        coverage='bounded after readiness; initial exec supplied by independent scheduler identity')
        except Exception as error:
            self.record('admission-insufficient', error=type(error).__name__ + ':' + str(error))

    def close(self):
        if not self.closed and not self.follow_attempted:
            self.record('admission-insufficient', error='no complete live invocation before close')
        super().close()
