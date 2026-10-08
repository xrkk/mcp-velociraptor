"""Private bounded executor for MalTrace.ScopedKernel.v1; no listening socket."""
import ctypes
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import time
import uuid

from velociraptor_linux_backend import canonical, publish, require, sha
from velociraptor_linux_probe import program, decode
from velociraptor_linux_scope import (now, process, alive, atomic, read, targets,
                                     validate_request, BINDING)


class Worker:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.premise = read(self.directory / 'premise.json')
        self.state = dict(self.premise, status='STARTING', backend_applied=False,
                          worker=process(os.getpid()), probe=None, generation=0,
                          default_targets=self.premise['targets'], extension=None,
                          transitions=[], event_count=0, collection_stopped=False,
                          limitations=['custom kernel source, not an upstream VR artifact',
                                       'generation switches have explicit observation gaps',
                                       '32-byte strings; 31-byte values may be truncated',
                                       'file identity is name + parent inode/device; no invented full path',
                                       'network source covers IPv4 TCP connect; not packet capture',
                                       'vfs_write modifications; mmap/direct-I/O not covered'])
        self.child = None
        self.known = {}
        self.pending = b''
        self.raw = self.events = self.stderr = None
        self.terminate = False
        self.fault = None
        self.ready = False
        self.done = False

    def save(self):
        atomic(self.directory / 'state.json', self.state)

    def transition(self, action, **detail):
        record = dict(action=action, at_ns=now(), generation=self.state['generation'], **detail)
        self.state['transitions'].append(record)
        publish(self.directory / ('transition-' + str(uuid.uuid4()) + '.json'), canonical(record))
        self.save()

    def reply(self, operation, ok, error=None):
        publish(self.directory / 'responses' / (operation + '.json'),
                canonical(dict(ok=ok, error=error, state=self.state)))

    def active_targets(self):
        deadline = self.premise['deadline_ns']
        roots = {(x['pid'], x['birth']): dict(x, until_ns=deadline,
                 root_pid=x['pid'], root_birth=x['birth']) for x in self.state['default_targets']}
        ext = self.state['extension']
        if ext and ext['expires_ns'] > now():
            for x in ext['targets']:
                roots.setdefault((x['pid'], x['birth']), dict(x, until_ns=ext['expires_ns'],
                                 root_pid=x['pid'], root_birth=x['birth']))
        seeds = dict(roots)
        for key, child in self.known.items():
            root = roots.get((child['root_pid'], child['root_birth']))
            if root and alive(child):
                seeds.setdefault(key, dict(child, until_ns=root['until_ns']))
        require(len(seeds) <= 128, 'DESCENDANT_LIMIT')
        return list(seeds.values())

    def start_probe(self):
        self.state.update(status='APPLYING', backend_applied=False)
        self.state['generation'] += 1
        generation = self.state['generation']
        seeds = self.active_targets()
        source = program(seeds, self.premise['deadline_ns'], self.premise['tick_ns'])
        root = self.directory / 'generations' / str(generation)
        root.mkdir(mode=0o700)
        config = dict(targets=seeds, default_targets=self.state['default_targets'],
                      extension=self.state['extension'], deadline_ns=self.premise['deadline_ns'],
                      generated_ns=now(), source_sha256=sha(source.encode()))
        publish(root / 'config.json', canonical(config))
        publish(root / 'probe.bt', source.encode())
        self.raw = (root / 'raw.ndjson').open('xb', buffering=0)
        self.events = (root / 'events.ndjson').open('xb', buffering=0)
        self.stderr = (root / 'stderr.txt').open('xb', buffering=0)
        for name in ('raw.ndjson', 'events.ndjson', 'stderr.txt'):
            os.chmod(root / name, 0o600)
        argv = ['/usr/bin/bpftrace', '-q', '-f', 'json', str(root / 'probe.bt')]
        parent = os.getpid()
        def death_signal():
            libc = ctypes.CDLL(None)
            if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0 or os.getppid() != parent:
                os._exit(90)
        self.child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                      stderr=self.stderr, preexec_fn=death_signal,
                                      env={'PATH': '/usr/bin:/usr/sbin', 'BPFTRACE_MAX_STRLEN': '32',
                                           'BPFTRACE_MAX_MAP_KEYS': '1024'})
        os.set_blocking(self.child.stdout.fileno(), False)
        self.state.update(probe=process(self.child.pid), probe_argv=argv,
                          config_ref={'path': str(root / 'config.json'), 'sha256': sha(canonical(config)),
                                      'size': len(canonical(config))})
        self.ready = self.done = False
        self.pending = b''
        self.transition('attach_started')
        end = time.monotonic() + 18
        while not self.ready and time.monotonic() < end and not self.terminate:
            self.drain(.05)
            require(self.child.poll() is None, 'PROBE_START_FAILED')
            require(not self.fault, self.fault or 'PROBE_SOURCE_FAILED')
        require(self.ready and not self.terminate, 'PROBE_READY_TIMEOUT')
        require(now() < self.premise['deadline_ns'], 'DEADLINE_DURING_ATTACH')
        self.state.update(status='APPLIED', backend_applied=True)
        self.transition('applied', ready_ns=self.ready)

    def drain(self, wait=0):
        if self.child is None or self.child.stdout.closed:
            return
        if not select.select([self.child.stdout], [], [], wait)[0]:
            return
        data = os.read(self.child.stdout.fileno(), 65536)
        if not data:
            return
        self.raw.write(data)
        self.pending += data
        require(len(self.pending) < 1024*1024 and self.raw.tell() < 16*1024*1024, 'OUTPUT_BOUND')
        while b'\n' in self.pending:
            line, self.pending = self.pending.split(b'\n', 1)
            if not line.strip():
                continue
            try:
                event = decode(line, self.state['generation'])
            except (ValueError, KeyError, TypeError, IndexError):
                self.fault = 'SOURCE_LOSS_OR_FORMAT'
                continue
            if event['kind'] == 'ready':
                self.ready = event['monotonic_ns']
            elif event['kind'] == 'end':
                self.done = True
            else:
                self.state['event_count'] += 1
                require(self.state['event_count'] <= 50000, 'EVENT_BOUND')
                event['sequence'] = self.state['event_count']
                self.events.write(canonical(event))
                if event['kind'] == 'fork':
                    child = dict(pid=event['detail'][0], birth=str(event['detail'][1]),
                                 uid=event['uid'], root_pid=event['root_pid'], root_birth=event['root_birth'])
                    self.known[(child['pid'], child['birth'])] = child
                    require(len(self.known) <= 128, 'DESCENDANT_LIMIT')
                elif event['kind'] == 'exit':
                    self.known.pop((event['pid'], event['birth']), None)

    def stop_probe(self):
        if self.child is None:
            return
        self.state.update(status='DETACHING', backend_applied=False)
        self.transition('detach_started')
        if self.child.poll() is None:
            self.child.terminate()
        end = time.monotonic() + 8
        while self.child.poll() is None and time.monotonic() < end:
            self.drain(.02)
        if self.child.poll() is None:
            self.child.kill()
            self.child.wait(timeout=3)
            self.fault = 'PROBE_FORCED_KILL'
        for _ in range(10):
            self.drain(.01)
        rc = self.child.wait(timeout=1)
        self.child.stdout.close()
        for f in (self.raw, self.events, self.stderr):
            os.fsync(f.fileno())
            f.close()
        self.transition('detached', returncode=rc, end_marker=self.done)
        if rc != 0 or not self.done:
            self.fault = self.fault or 'PROBE_EXIT_INCOMPLETE'
        self.child = None

    def change(self, command):
        action = command['action']
        request = {k: v for k, v in command.items() if k not in ('action', 'requested_ns')}
        validate_request(action, request)
        require(all(request[k] == self.premise[k] for k in BINDING), 'FOREIGN_SCOPE')
        self.transition('intent', command=command)
        self.stop_probe()
        require(not self.fault, self.fault or 'DETACH_FAILED')
        if action == 'stop':
            self.state.update(status='STOPPED', backend_applied=False, collection_stopped=True)
            self.transition('stopped')
            return
        if action == 'update':
            self.state['default_targets'] = targets(command['targets'])
        elif action == 'extend':
            extension = dict(command, expires_ns=min(self.premise['deadline_ns'],
                               command['requested_ns'] + command['expires_in_seconds'] * 10**9))
            require(extension['expires_ns'] > now(), 'EXTENSION_EXPIRED_BEFORE_APPLY')
            self.state['extension'] = extension
        elif action == 'withdraw':
            self.state['extension'] = None
        self.start_probe()

    def run(self):
        os.umask(0o077)
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, 'terminate', True))
        signal.signal(signal.SIGINT, lambda *_: setattr(self, 'terminate', True))
        operation = self.premise['operation_id']
        self.save()
        try:
            targets(self.premise['targets'])
            self.start_probe()
            self.reply(operation, True)
            operation = None
            while self.state['status'] == 'APPLIED' and not self.terminate:
                self.drain(.05)
                require(not self.fault, self.fault or 'SOURCE_FAILED')
                if now() >= self.premise['deadline_ns']:
                    self.stop_probe()
                    self.state.update(status='EXPIRED', backend_applied=False, collection_stopped=True)
                    self.transition('deadline_expired')
                    break
                require(self.child.poll() is None, 'PROBE_UNEXPECTED_EXIT')
                ext = self.state['extension']
                if ext and now() >= ext['expires_ns']:
                    self.transition('extension_expired', expires_ns=ext['expires_ns'])
                    self.stop_probe()
                    require(not self.fault, self.fault or 'DETACH_FAILED')
                    self.state['extension'] = None
                    self.start_probe()
                for path in sorted((self.directory / 'requests').glob('*.json')):
                    if (self.directory / 'responses' / path.name).exists():
                        continue
                    operation = path.stem
                    self.change(read(path))
                    self.reply(operation, True)
                    operation = None
                    if self.state['status'] != 'APPLIED':
                        break
            if self.terminate:
                raise RuntimeError('WORKER_INTERRUPTED')
        except Exception as error:
            self.fault = getattr(error, 'code', None) or str(error)[:200]
        finally:
            try:
                self.stop_probe()
            except Exception as error:
                self.fault = 'CLEANUP_UNKNOWN:' + type(error).__name__
            if self.fault:
                self.state.update(status='FAILED', backend_applied=False, failure=self.fault,
                                  collection_stopped=not alive(self.state.get('probe')))
            self.state['finished_ns'] = now()
            self.save()
            if operation and not (self.directory / 'responses' / (operation + '.json')).exists():
                self.reply(operation, False, self.fault)


def main(directory):
    Worker(directory).run()
