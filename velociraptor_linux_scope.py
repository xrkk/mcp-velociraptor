"""Durable, bounded guest-local professional scope control (single operator).

The custom kernel worker owns the probes. A CLI receipt is successful only
following a worker acknowledgment and matching live PID/birth. No query drives
expiry. Unknown outcomes require query/stop; requests are never replayed.
"""
from __future__ import annotations
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

from velociraptor_linux_backend import canonical, private_path, publish, require, sha
from velociraptor_linux_probe import BPFTRACE_SHA, SOURCE_ID

TERMINAL = {'STOPPED', 'EXPIRED', 'FAILED'}
BINDING = {'session_id', 'owner_id', 'client_id', 'vm_uuid', 'boot_id'}


def now():
    return time.monotonic_ns()


def identifier(value):
    require(isinstance(value, str) and str(uuid.UUID(value)) == value, 'INVALID_ID')
    return value


def process(pid):
    try:
        p = Path('/proc') / str(pid)
        raw = (p / 'stat').read_text().rsplit(')', 1)[1].split()
        return {'pid': pid, 'birth': raw[19], 'uid': p.stat().st_uid,
                'alive': raw[0] not in ('Z', 'X')}
    except FileNotFoundError:
        return None


def alive(binding):
    if not binding:
        return False
    p = process(binding['pid'])
    return bool(p and p['alive'] and p['birth'] == binding['birth'])


def targets(values):
    require(isinstance(values, list) and 1 <= len(values) <= 16, 'TARGETS_REQUIRED')
    result = []
    for v in values:
        require(isinstance(v, dict) and set(v) == {'pid', 'birth', 'uid'}, 'TARGET_FIELDS')
        require(type(v['pid']) is int and 1 < v['pid'] < 2**31
                and type(v['uid']) is int and v['uid'] > 0
                and isinstance(v['birth'], str) and v['birth'].isdigit(), 'TARGET_ID')
        p = process(v['pid'])
        require(p and p['alive'] and all(p[k] == v[k] for k in v), 'TARGET_REUSED_OR_MISSING')
        require(v not in result, 'DUPLICATE_TARGET')
        result.append(dict(v))
    return result


def atomic(path, value):
    tmp = path.with_name('.' + path.name + '.' + str(uuid.uuid4()))
    publish(tmp, canonical(value))
    os.replace(tmp, path)


def read(path):
    return json.loads(private_path(path).read_bytes())


def ref(path):
    data = private_path(path).read_bytes()
    return {'path': str(path), 'size': len(data), 'sha256': sha(data)}


def validate_request(action, request):
    require(isinstance(request, dict), 'REQUEST_TYPE')
    extra = {
        'apply': {'targets', 'lifetime_seconds'}, 'update': {'targets'},
        'extend': {'targets', 'reason', 'expires_in_seconds', 'termination'},
        'withdraw': set(), 'stop': set(), 'query': set(), 'export': set(),
    }
    require(action in extra and set(request) == BINDING | {'operation_id'} | extra[action], 'REQUEST_FIELDS')
    for k in ('session_id', 'owner_id', 'operation_id', 'vm_uuid', 'boot_id'):
        identifier(request[k])
    if action in ('apply', 'update', 'extend'):
        targets(request['targets'])
    if action == 'apply':
        require(type(request['lifetime_seconds']) is int
                and 30 <= request['lifetime_seconds'] <= 900, 'LIFETIME_REQUIRED')
    if action == 'extend':
        require(type(request['expires_in_seconds']) is int
                and 5 <= request['expires_in_seconds'] <= 300, 'EXPIRY_REQUIRED')
        for k in ('reason', 'termination'):
            require(isinstance(request[k], str) and 0 < len(request[k].strip()) <= 1024, 'INTENT_REQUIRED')


class ScopeBackend:
    def __init__(self, professional):
        self.professional = professional
        self.root = professional.root / 'scopes'

    def _identity(self, request):
        self.professional.identity()
        require(all(request[k] == self.professional.binding[k]
                    for k in ('client_id', 'vm_uuid', 'boot_id')), 'SCOPE_BINDING')
        self.professional.route(request['client_id'])

    def _directory(self, request):
        directory = self.root / request['session_id']
        private_path(self.root, directory=True)
        private_path(directory, directory=True)
        premise = read(directory / 'premise.json')
        require(all(premise[k] == request[k] for k in BINDING), 'FOREIGN_SCOPE')
        return directory

    def call(self, action, request):
        validate_request(action, request)
        self._identity(request)
        if action == 'apply':
            return self._apply(request)
        directory = self._directory(request)
        if action in ('query', 'export'):
            return self._snapshot(directory, export=action == 'export')
        # Serialize a single operator's command submission. No API retry/replay.
        with (directory / 'control.lock').open('rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = read(directory / 'state.json')
            if action == 'stop' and not alive(state.get('worker')):
                return self._recover_stop(directory, state)
            require(state['status'] == 'APPLIED' and alive(state.get('worker')), 'SCOPE_NOT_ACTIVE')
            command = dict(request, action=action, requested_ns=now())
            publish(directory / 'requests' / (request['operation_id'] + '.json'), canonical(command))
            result = self._await(directory, request['operation_id'])
            if action == 'stop':
                self._wait_exit(result['worker'])
                require(not alive(result.get('probe')), 'PROBE_STOP_UNKNOWN')
            return self._snapshot(directory)

    def _apply(self, request):
        require(os.geteuid() == 0, 'ROOT_COLLECTOR_REQUIRED')
        require(sha(Path('/usr/bin/bpftrace').read_bytes()) == BPFTRACE_SHA, 'BPFTRACE_DRIFT')
        require(os.sysconf('SC_CLK_TCK') == 100, 'CLOCK_UNSUPPORTED')
        require(Path('/sys/kernel/btf/vmlinux').is_file(), 'BTF_REQUIRED')
        if not self.root.exists():
            self.root.mkdir(mode=0o700)
        private_path(self.root, directory=True)
        directory = self.root / request['session_id']
        directory.mkdir(mode=0o700)  # Existing sessions are never overwritten.
        for name in ('requests', 'responses', 'generations', 'snapshots'):
            (directory / name).mkdir(mode=0o700)
        modules = ['velociraptor_linux_scope.py', 'velociraptor_linux_worker.py', 'velociraptor_linux_probe.py']
        source = {name: sha(Path(__file__).with_name(name).read_bytes()) for name in modules}
        premise = dict(request, source=SOURCE_ID, source_hashes=source,
                       bpftrace_sha256=BPFTRACE_SHA, kernel=os.uname().release,
                       tick_ns=10**7, started_ns=now())
        premise['deadline_ns'] = premise['started_ns'] + request['lifetime_seconds'] * 10**9
        publish(directory / 'premise.json', canonical(premise))
        publish(directory / 'control.lock', b'')
        # Explicit import path with isolated Python; no inherited module overrides.
        package = str(Path(__file__).resolve().parent)
        code = 'import sys;sys.path.insert(0,sys.argv[1]);from velociraptor_linux_worker import main;main(sys.argv[2])'
        argv = [sys.executable, '-I', '-B', '-c', code, package, str(directory)]
        with (directory / 'worker-stderr.txt').open('xb') as err:
            os.chmod(directory / 'worker-stderr.txt', 0o600)
            worker = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=err, start_new_session=True, env={'PATH': '/usr/bin:/usr/sbin'})
        publish(directory / 'launch.json', canonical({'worker': process(worker.pid), 'argv': argv}))
        self._await(directory, request['operation_id'])
        return self._snapshot(directory)

    def _await(self, directory, operation):
        path = directory / 'responses' / (operation + '.json')
        end = time.monotonic() + 25
        while time.monotonic() < end:
            if path.exists():
                result = read(path)
                require(result['ok'], result.get('error', 'SCOPE_FAILED'))
                return result['state']
            time.sleep(.05)
        require(False, 'SCOPE_OUTCOME_UNKNOWN')

    @staticmethod
    def _wait_exit(binding):
        end = time.monotonic() + 12
        while alive(binding) and time.monotonic() < end:
            time.sleep(.05)
        require(not alive(binding), 'WORKER_STOP_UNKNOWN')

    def _recover_stop(self, directory, state):
        # The kernel deadline and PDEATHSIG already bound interrupted workers.
        # Never signal a merely matching PID/name; verify the original argv too.
        probe = state.get('probe')
        if state['status'] in TERMINAL and not alive(probe):
            return self._snapshot(directory)
        if alive(probe):
            argv = (Path('/proc') / str(probe['pid']) / 'cmdline').read_bytes().split(b'\0')[:-1]
            require(argv == [x.encode() for x in state['probe_argv']], 'PROBE_OWNER_UNKNOWN')
            os.kill(probe['pid'], signal.SIGTERM)
            self._wait_exit(probe)
        state.update(status='FAILED', backend_applied=False, collection_stopped=True,
                     failure='WORKER_INTERRUPTED', recovered_ns=now())
        atomic(directory / 'state.json', state)
        return self._snapshot(directory)

    def _snapshot(self, directory, export=False):
        state = read(directory / 'state.json')
        if state['status'] == 'APPLIED' and (not alive(state.get('worker')) or not alive(state.get('probe'))):
            state.update(status='UNKNOWN', backend_applied=False, failure='WORKER_OR_PROBE_MISSING')
        if state['status'] in TERMINAL:
            state['collection_stopped'] = not alive(state.get('worker')) and not alive(state.get('probe'))
        # Query never mutates the worker or expiry state. Kernel gating is autonomous.
        if state['status'] == 'APPLIED' and now() >= state['deadline_ns']:
            state.update(status='UNKNOWN', backend_applied=False, failure='DEADLINE_AWAITING_TERMINAL')
        products = []
        if export:
            require(state.get('collection_stopped'), 'EXPORT_REQUIRES_TERMINAL')
            for path in sorted(directory.rglob('*')):
                if path.is_file() and path.parent.name != 'snapshots' and path.name not in ('control.lock',):
                    products.append(ref(path))
        state['products'] = products
        path = directory / 'snapshots' / (str(uuid.uuid4()) + '.json')
        receipt = publish(path, canonical(state))
        return dict(state, ref=receipt)
