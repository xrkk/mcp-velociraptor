"""Private PC026 ingress/ledger/SDK chain, with conservative close refusal.

No public MODEL factory or production fallback. Fixed approved construction
borrows the native exporter from one ledger-owned group. Successful close
requires the native publisher/readback external final I/O witness.
"""
from __future__ import annotations

import asyncio
import contextvars
from dataclasses import dataclass, field
import hashlib
import json
import os
import sys
import threading
import time
import types
import weakref

import anyio
from mcp.server.streamable_http import (
    StreamableHTTPServerTransport, check_accept_headers, jsonrpc_message_adapter)
from mcp.shared.dispatcher import coerce_request_id
from starlette.requests import Request
from starlette.responses import JSONResponse

from velo_transfer.wire import strict_json, one_header
from velociraptor_observation import ObservationScope, _canonical, _json_copy, _current
from velociraptor_observation_attempts import ArchiveAttemptLedger
from velociraptor_observation_workers import _WorkerGroup, _CURRENT_OWNER

_APPROVED_CONTROLLERS = weakref.WeakSet()

def _approved_controller(value):
    return type(value) is SessionController and value in _APPROVED_CONTROLLERS and not value._ledger._closed and not value._ledger._unknown

_CURRENT_HTTP = contextvars.ContextVar('pc026_controller_http', default=None)
_PROTOCOLS = frozenset(('2024-11-05','2025-03-26','2025-06-18','2025-11-25'))


class ControllerError(Exception):
    def __init__(self, code, status=503):
        self.code, self.status = code, status
        super().__init__(code)


class _Ticket:
    __slots__ = ()
    def __new__(cls):
        raise TypeError('tickets are controller-issued')


@dataclass(eq=False, slots=True)
class _Temporary:
    """One private allocation owner; not a work/admission receipt.

    Charges specified storage only. Parser/extension allocations require their
    own qualified bounds; a successful storage reservation cannot certify them.
    """
    controller: object
    size: int
    owner: object
    released: bool = False

    def release(self):
        with self.controller._lock:
            if not self.released:
                self.controller._temporary_reserved -= self.size
                self.released = True


class _BodyBuffer:
    """Fixed backing storage, no bytearray geometric growth or slice copies."""
    __slots__ = ('storage', 'view', 'length')
    def __init__(self, capacity):
        self.storage = bytearray(capacity)
        self.view = memoryview(self.storage)
        self.length = 0

    def append(self, chunk):
        end = self.length + len(chunk)
        if end > len(self.storage):
            raise ControllerError('body_budget', 413)
        # Equal-sized assignment does not grow the fixed bytearray.
        self.view[self.length:end] = chunk
        self.length = end

    def finish(self):
        # Two one-dimensional views share one managed buffer; no data slice.
        with self.view[:self.length] as part:
            return bytes(part)

    def close(self):
        self.view.release()
        self.view = self.storage = None


def _body_storage_bound(capacity):
    """CPython 3.13 LP64 buffer layout, not allocator arenas or total RSS.

    Includes bytearray header + NUL, bytes header (includes NUL), two 1-D
    memoryview headers/shape-stride-suboffset triples and their shared managed
    Py_buffer. GC heads contain two uintptr_t. Layout is checked, never inferred
    from the later measured graph. Backend-owned ASGI chunks are not copied.
    """
    if type(capacity) is not int or not 0 <= capacity <= sys.maxsize:
        raise ControllerError('temporary_size_invalid')
    import struct
    pointer = struct.calcsize('P')
    if (sys.implementation.name != 'cpython' or sys.version_info[:2] != (3, 13)
            or pointer != 8 or bytes.__basicsize__ != 33
            or bytearray.__basicsize__ != 56 or memoryview.__basicsize__ != 144):
        raise ControllerError('buffer_layout_unqualified')
    gc_head = 2 * pointer
    # PyObject_HEAD(16), flags(4)+alignment(4), exports(8), Py_buffer(80).
    managed = 16 + 8 + 8 + 80 + gc_head
    views = 2 * (memoryview.__basicsize__ + 3 * pointer + gc_head)
    # Buffer has three pointer slots, reservation four, plus PyObject_HEAD.
    owners = (16 + 3 * pointer) + (16 + 4 * pointer) + 2 * gc_head
    result = bytearray.__basicsize__ + capacity + 1 + bytes.__basicsize__ + capacity + managed + views + owners
    if result > sys.maxsize:raise ControllerError('temporary_size_invalid')
    return result


def _body_capacity(headers, limit):
    # Content-Length reduces storage, never enlarges the actual byte gate.
    # No declared length uses the configured maximum. Duplicate/malformed
    # declarations refuse before allocation. Actual ASGI EOF is still required.
    values = [v for k, v in headers if k.lower() == b'content-length']
    if not values:return limit
    if (len(values) != 1 or not values[0] or len(values[0]) > 20
            or any(c < 48 or c > 57 for c in values[0])):
        raise ControllerError('content_length', 400)
    capacity = int(values[0])
    if capacity > limit:raise ControllerError('body_budget', 413)
    return capacity


@dataclass
class _Work:
    sequence: int
    session: str | None
    owner: bytes
    message: dict
    attempt: object = None
    journal: object = None
    scope: object = None
    worker_owner: object = None
    enqueued: bool = False
    started: bool = False
    handler_exited: bool = False
    http_exited: bool = False
    cancelled: bool = False
    outcome: str | None = None
    error: BaseException | None = None
    streams: list = field(default_factory=list)
    pending_creation: bool = False
    request_sha256: str | None = None
    response_pending: object = None
    maintenance_exchange: object = None
    request_bytes: int = 0
    response_bytes: int = 0
    receive_waiter: object = None
    input_storage: object = None


@dataclass(eq=False)
class _CloseIO:
    session: str
    thread: object = None
    task: object = None
    result: object = None
    error: BaseException | None = None
    wrapper_exited: bool = False
    joined: bool = False
    temporary: object = None


@dataclass(eq=False)
class _TransferChild:
    """Permanent causal record; only actual wait and cleanup receipts close it."""
    sequence: int
    session: str
    owner: object
    transfer_id: str
    digest: str
    job: str
    nonce: str
    root: object
    root_identity: tuple
    controller: object
    pid: int | None = None
    birth: str | None = None
    process: object = None
    report: object = None
    activation_closed: bool = False
    wait_status: int | None = None
    resources_closed: bool = False
    error: BaseException | None = None
    no_spawn: bool = False
    native_resources_closed: bool = False
    lock: object = field(default_factory=threading.RLock)

    def _fault(self, error):
        self.error = self.error or error
        self.controller._unknown(self.session)

    def _poll(self):
        from velo_transfer.guest_worker import RootLease
        with self.lock:
            if self.resources_closed: return True
            if self.no_spawn:
                self.resources_closed = self.native_resources_closed = True
                return True
            if self.pid is None or self.report is None: return False
            try:
                if self.wait_status is None:
                    if os.name == 'posix':
                        pid, status = os.waitpid(self.pid, os.WNOHANG)
                        if pid == 0: return False
                        if pid != self.pid: raise ControllerError('child_wait_identity')
                        self.wait_status = status
                    else:
                        if self.process.poll() is None: return False
                        self.wait_status = self.process.wait(timeout=0)
                # Read only after real native wait. The bounded pipe cannot
                # substitute for exit, and durable owner.stopped is never used.
                if os.name == 'posix':
                    raw = os.read(self.report, 4097)
                    eof = os.read(self.report, 1) == b''
                    fd, self.report = self.report, None
                    os.close(fd)
                else:
                    stream, self.report = self.report, None
                    raw = stream.read(4097)
                    eof = stream.read(1) == b''
                    stream.close()
                    # Popen keeps the actual process handle after wait().
                    self.process._handle.Close()
                self.native_resources_closed=True
                expected = dict(transfer_id=self.transfer_id, digest=self.digest,
                    job=self.job, nonce=self.nonce, pid=self.pid, birth=self.birth,
                    guard_joined=True, lease_closed=True, body_exited=True)
                if (not eof or len(raw)>4096 or not raw.endswith(b'\n')
                        or strict_json(raw) != expected or not self.activation_closed):
                    raise ControllerError('child_cleanup_unconfirmed')
                root = self.root.lstat()
                if (root.st_dev,root.st_ino) != self.root_identity:
                    raise ControllerError('child_root_changed')
                probe=RootLease(self.root)
                probe.acquire()
                try:
                    after=self.root.lstat()
                    if (after.st_dev,after.st_ino) != self.root_identity:
                        raise ControllerError('child_root_changed')
                finally: probe.release()
                self.resources_closed=True
                return True
            except BaseException as exc:
                # ChildProcessError is unknown unless this record itself has
                # already observed the native wait. Never invent a reap.
                self._fault(exc)
                return False


class _Threads(_WorkerGroup):
    def __init__(self, controller, session):
        super().__init__(controller._limits['max_sdk_work'])
        self._controller, self._session = controller, session
    def _observe(self):
        self._controller._retained_gate()

    def _next(self):
        # Group -> short controller lock only; no inverse lock acquisition.
        sequence = self._controller._sequence_for(self._session, 'retained')
        self._sequence = sequence
        return sequence


class SessionController:
    def __init__(self):
        raise TypeError('use open_approved(instance_id)')

    @classmethod
    def open_approved(cls, instance_id):
        import re
        if type(instance_id) is not str or not re.fullmatch('[0-9a-f]{32}',instance_id):
            raise ControllerError('instance_invalid')
        from velociraptor_observation_config import load_approved, _close_note
        from velociraptor_observation_startup import _precheck_loaded
        from velociraptor_observation_export import NativeExporter, _preflight
        archive=load_approved()
        ledger=None
        try:
            lifecycle=_precheck_loaded(archive)
            _preflight(archive,lifecycle['budgets'])
            ledger=object.__new__(ArchiveAttemptLedger)
            ledger._initialize(instance_id,archive)
            exporter=NativeExporter._borrow(ledger,lifecycle)
            self=object.__new__(cls)
            self._initialize(ledger,lifecycle['budgets'])
            self._exporter=exporter
            _APPROVED_CONTROLLERS.add(self)
            return self
        except BaseException as primary:
            # _initialize already cleans its failed acquisition. A completed
            # ledger owns all subsequent cleanup, including the borrowed group.
            if ledger is None:
                try:archive.group.close()
                except BaseException:_close_note(primary)
            elif not ledger._closed:
                ledger._poison()
                ledger._closed=True
                ledger._cleanup(primary)
            raise

    def _abort_startup(self, primary):
        # Idempotent pre-lifespan cleanup only. Once the SDK has entered, its
        # async drain owns cleanup; a lost loop must retain UNKNOWN resources.
        with self._lock:
            if self._startup_error is None:self._startup_error=primary
            if self._ledger._closed:return
            manager=getattr(self,'_manager',None)
            safe=(self._startup_phase in ('ACQUIRED','ENTERING') and self._state!='UNKNOWN'
                and not self._work and not self._sessions and not self._close_io
                and not self._children and not self._pending and not self._temporary_reserved
                and (manager is None or manager._task_group is None
                     and not manager._owned_transports))
            self._state='UNKNOWN'
            if not safe:
                primary.add_note('observation_startup_resources_retained_unknown')
                return
            self._startup_phase='ABORTED'
            self._ledger._poison()
            self._ledger._closed=True
            try:self._ledger._cleanup(primary)
            except BaseException as error:
                self._startup_cleanup_error=error
                primary.add_note('observation_startup_cleanup_failed')

    def _starting(self):
        with self._lock:
            if self._startup_phase!='ACQUIRED' or self._ledger._closed:
                raise ControllerError('lifespan_reentered')
            self._startup_phase='ENTERING'

    def _lifespan_entered(self):
        with self._lock:self._startup_phase='ACTIVE'

    def _lifespan_exited(self):
        with self._lock:
            if self._startup_phase=='ACTIVE':self._startup_phase='EXITED'

    def _initialize(self, ledger, budgets):
        # Private test fixture seam; never reachable from HTTP/config/env/CLI.
        if type(ledger) is not ArchiveAttemptLedger or ledger._closed or ledger._unknown:
            raise ControllerError('ledger_invalid')
        from velociraptor_observation_startup import _BUDGETS
        if (type(budgets) is not dict or set(budgets) != _BUDGETS
                or any(type(x) is not int or x <= 0 for x in budgets.values())):
            raise ControllerError('budgets_invalid')
        self._ledger, self._limits = ledger, dict(budgets)
        self._lock = threading.RLock()
        self._state, self._sequence, self._retained = 'ACTIVE', 0, 0
        self._startup_phase='ACQUIRED'
        self._startup_error=None
        self._startup_cleanup_error=None
        self._work, self._sessions, self._sequence_records = {}, {}, {}
        self._pending = 0
        self._close_tasks = {}
        self._children = {}
        self._binary_sequences = set()
        self._outgoing = {}
        self._outgoing_records = []
        self._prefixes = {}
        self._close_errors = {}
        self._retained_measured_peak = 0
        self._close_io = {}
        self._exporter = None
        self._closed_cuts = {}
        self._maintenance = {}
        self._transfer_service = None
        self._temporary_reserved = 0
        self._temporary_peak = 0

    def _reserve_temporary(self, size, owner):
        if type(size) is not int or not 0 < size <= sys.maxsize:
            raise ControllerError('temporary_size_invalid')
        with self._lock:
            self._retained_gate(size)
            lease = _Temporary(self, size, owner)
            self._temporary_reserved += size
            self._temporary_peak = max(self._temporary_peak, self._temporary_reserved)
            return lease

    def _release_input_storage(self, row):
        with self._lock:
            if row.input_storage is not None and row.http_exited and row.handler_exited:
                row.input_storage.release()

    def _reserve_maintenance(self, original, session, owner, *, calls, bytes, attempts, binary, sdk_work):
        """Atomically reserve internal capacity after native source authorization.

        History includes the initial live SDK GET; its later bytes are charged
        by that ingress owner. Reservation is permanent, including failures.
        """
        values=dict(calls=calls,bytes=bytes,attempts=attempts,binary=binary,sdk_work=sdk_work)
        if any(type(n) is not int or n<0 for n in values.values()) or not calls or not bytes or not sdk_work:
            raise ControllerError('maintenance_plan_invalid')
        with self._lock:
            first=self._sessions.get(original);target=self._sessions.get(session)
            if (self._state!='ACTIVE' or first is None or target is None or original==session
                    or first['owner']!=owner or target['owner']!=owner or first['state']!='CLOSED'
                    or original not in self._closed_cuts or target['state']!='OPEN' or not target['initialized']
                    or self._exporter is None or not self._exporter.receipt(original,self._closed_cuts[original])):
                raise ControllerError('maintenance_source_invalid')
            if session in self._maintenance:raise ControllerError('maintenance_reentered')
            history=[r for r in self._work.values() if r.session==session]
            if any(not r.http_exited and r.message.get('method')!='HTTP_GET_SSE' for r in history):
                raise ControllerError('maintenance_initialization_pending')
            planned=dict(values,calls=calls+len(history),
                bytes=bytes+sum(r.request_bytes+r.response_bytes for r in history))
            used_calls=sum(r['plan']['calls'] for r in self._maintenance.values())
            used_bytes=sum(r['plan']['bytes'] for r in self._maintenance.values())
            if (used_calls+planned['calls']>self._limits['max_maintenance_calls']
                    or used_bytes+planned['bytes']>self._limits['max_maintenance_bytes']
                    or self._ledger._attempt_count+self._reserved_capacity('attempts')+attempts>self._ledger._limits['max_attempts']
                    or len(self._binary_sequences)+self._reserved_capacity('binary')+binary>self._limits['max_binary_work']
                    or self._sequence+self._reserved_capacity('sdk_work')+sdk_work>self._limits['max_sdk_work']):
                raise ControllerError('maintenance_capacity')
            self._retained_gate(_message_size(values)+4096)
            self._maintenance[session]=dict(original=original,owner=owner,plan=planned,initial_calls=len(history),
                initial_bytes=planned['bytes']-bytes,
                remaining=dict(values),exchanges=[])
            for r in history:
                if not r.http_exited:
                    exchange=dict(method='HTTP_GET',request_bytes=r.request_bytes,response_bytes=r.response_bytes,finished=False,error=None)
                    r.maintenance_exchange=exchange
                    self._maintenance[session]['exchanges'].append(exchange)

    def _activate_maintenance(self, session, owner, message, body_size):
        if message.get('method')!='tools/call' or message.get('params',{}).get('name')!='transfer_begin':return None
        request=message['params'].get('arguments',{}).get('request')
        if type(request) is not dict or request.get('direction')!='pull' or self._exporter is None:return None
        sources=request.get('sources')
        if type(sources) is not list:return None
        candidates=[]
        for item in sources:
            if type(item) is not dict or type(item.get('absolute_path')) is not str:continue
            if self._exporter._namespace_source(item['absolute_path']):candidates.append(item['absolute_path'])
        if not candidates:return None  # Ordinary transfer retains its existing policy.
        with self._lock:
            matches=[original for original,descriptor in self._closed_cuts.items()
                if candidates==[str(self._exporter._source_path(original))] and len(sources)==1]
            if len(matches)!=1:raise ControllerError('maintenance_source_invalid')
            original=matches[0]
            first=self._sessions.get(original);target=self._sessions.get(session)
            if (first is None or target is None or original==session or first['owner']!=owner
                    or target['owner']!=owner or first['state']!='CLOSED' or target['state']!='OPEN'
                    or not target['initialized'] or not self._exporter.receipt(original,self._closed_cuts[original])):
                raise ControllerError('maintenance_source_invalid')
            if session in self._maintenance:
                binding=self._maintenance[session].get('transfer_binding')
                if binding!=(request.get('transfer_id'),request.get('request_digest')):
                    raise ControllerError('maintenance_reentered')
                return None  # Same immutable transfer resume uses already reserved capacity.
            if self._transfer_service is None:raise ControllerError('maintenance_transfer_unavailable')
            service=self._transfer_service._get()
            service._validate_request(request)  # Read-only identity/policy/schema/producer gate.
            path=service.policy.resolve_local(sources[0]['absolute_path'],'read')
            if str(path)!=sources[0]['absolute_path']:raise ControllerError('maintenance_path')
            from velociraptor_observation_maintenance_plan import acquisition_plan
            # Reserve temporary native read storage before native source readback.
            reservation=self._reserve_temporary(2*self._exporter._plan['pending'],'maintenance-source-read')
            try:
                facts=self._exporter._maintenance_source(original)
                plan=acquisition_plan(facts,service.policy.limits,request['budget'],self._limits['max_request_body_bytes'])
                self._reserve_maintenance(original,session,owner,**plan)
            finally:reservation.release()
            self._maintenance[session]['transfer_binding']=(request['transfer_id'],request['request_digest'])
            exchange=self._maintenance_exchange(session,owner,'HTTP_POST')
            self._maintenance_bytes(session,exchange,body_size)
            return exchange

    async def _prepare_maintenance(self, session, owner, message, body_size):
        params=message.get('params',{})
        request=params.get('arguments',{}).get('request')
        if (message.get('method')!='tools/call' or params.get('name')!='transfer_begin'
                or type(request) is not dict or request.get('direction')!='pull' or self._exporter is None):return None
        sources=request.get('sources')
        if type(sources) is not list or not any(type(r) is dict and type(r.get('absolute_path')) is str
                and self._exporter._namespace_source(r['absolute_path']) for r in sources):return None
        with self._lock:
            if session in self._maintenance:
                return self._activate_maintenance(session,owner,message,body_size)
        deadline=time.monotonic_ns()+self._limits['close_timeout_ns']
        try:
            return await self._owned_close_io(session,
                lambda:self._activate_maintenance(session,owner,message,body_size),deadline,'maintenance_activation')
        except BaseException:
            # A failed validation can safely refuse, but a live native task may
            # still own resources. Never claim that timeout/cancellation stops it.
            io=self._close_io.get((session,'maintenance_activation'))
            if io is not None and not io.joined:self._unknown(session)
            raise

    def _reserved_capacity(self, kind, except_session=None):
        return sum(r['remaining'][kind] for session,r in self._maintenance.items() if session!=except_session)

    def _maintenance_exchange(self, session, owner, method):
        with self._lock:
            maintenance=self._maintenance.get(session)
            if maintenance is None:return None
            if maintenance['owner']!=owner:raise ControllerError('maintenance_owner')
            if maintenance['remaining']['calls']<=0:
                self._state='DRAINING';raise ControllerError('maintenance_calls')
            self._retained_gate(512)
            maintenance['remaining']['calls']-=1
            row=dict(method=method,request_bytes=0,response_bytes=0,finished=False,error=None)
            maintenance['exchanges'].append(row)
            return row

    def _maintenance_bytes(self, session, row, count, response=False):
        if row is None:return
        with self._lock:
            maintenance=self._maintenance[session]
            row['response_bytes' if response else 'request_bytes']+=count
            before=maintenance['remaining']['bytes']
            maintenance['remaining']['bytes']-=count
            if before>=0 and maintenance['remaining']['bytes']<0:
                self._unknown(session);raise ControllerError('maintenance_bytes')

    def _capacity_for(self, session, kind, used, limit):
        maintenance=self._maintenance.get(session)
        reserved=self._reserved_capacity(kind,session)
        if maintenance is None and not reserved:return
        if maintenance is not None and maintenance['remaining'][kind]<=0:
            raise ControllerError('maintenance_'+kind)
        if used+reserved>=limit:
            raise ControllerError('reserved_'+kind)

    def _consume_capacity(self, session, kind):
        if session in self._maintenance:self._maintenance[session]['remaining'][kind]-=1

    def _unknown(self, session=None):
        with self._lock:
            self._state = 'UNKNOWN'
            if session in self._sessions: self._sessions[session]['state'] = 'UNKNOWN'

    def _sequence_for(self, session, kind):
        with self._lock:
            if self._state == 'UNKNOWN': raise ControllerError('instance_unknown')
            if self._sequence >= self._limits['max_sdk_work']:
                self._state = 'DRAINING'
                raise ControllerError('work_budget')
            self._capacity_for(session,'sdk_work',self._sequence,self._limits['max_sdk_work'])
            self._consume_capacity(session,'sdk_work')
            self._sequence += 1
            self._sequence_records[self._sequence] = (session, kind)
            return self._sequence

    def _measure_retained(self, temporary=()):
        # Domain-owned Python graph, not allocator arenas, backend memory, native
        # kernel objects or total RSS. Shared objects/cycles are charged once.
        from collections import deque
        from dataclasses import fields, is_dataclass
        seen={id(v):v for v in (self,self._ledger,self._ledger._config)}
        if hasattr(self,'_manager'):
            seen.update({id(v):v for v in (self._manager,self._manager.app)})
        def size(value,depth=0):
            if id(value) in seen:return 0
            seen[id(value)]=value;total=sys.getsizeof(value)
            if depth>256:raise ControllerError('retained_graph_depth_unknown')
            if type(value) is dict:
                return total+sum(size(k,depth+1)+size(v,depth+1) for k,v in list(value.items()))
            if type(value) in (list,tuple,set,frozenset,deque):
                return total+sum(size(v,depth+1) for v in tuple(value))
            if isinstance(value,memoryview):return total+size(value.obj,depth+1)
            if isinstance(value,contextvars.Context):
                return total+sum(size(k,depth+1)+size(v,depth+1) for k,v in value.items())
            if isinstance(value,types.FunctionType):
                # Code/global modules are shared executable state, not mutable
                # domain data; closure cells and defaults retain actual payloads.
                return total+size(value.__defaults__,depth+1)+size(value.__kwdefaults__,depth+1)+sum(
                    size(cell,depth+1) for cell in value.__closure__ or ())
            if isinstance(value,types.CellType):
                try:content=value.cell_contents
                except ValueError:return total
                return total+size(content,depth+1)
            if isinstance(value,(type,types.ModuleType)):return total
            if isinstance(value,types.MethodType):return total+size(value.__self__,depth+1)
            if isinstance(value,types.FrameType):
                # Python 3.13 uses FrameLocalsProxy, not a dict. Read its actual
                # locals without traversing shared executable globals.
                return total+sys.getsizeof(value.f_locals)+sum(
                    size(k,depth+1)+size(v,depth+1) for k,v in list(value.f_locals.items()))
            if isinstance(value,types.TracebackType):
                return total+size(value.tb_frame,depth+1)+size(value.tb_next,depth+1)
            if isinstance(value,types.CoroutineType):
                return total+size(value.cr_frame,depth+1)+size(value.cr_await,depth+1)
            if isinstance(value,types.AsyncGeneratorType):
                return total+size(value.ag_frame,depth+1)+size(value.ag_await,depth+1)
            if isinstance(value,types.GeneratorType):
                return total+size(value.gi_frame,depth+1)+size(value.gi_yieldfrom,depth+1)
            if isinstance(value,asyncio.Task):
                return total+size(value.get_coro(),depth+1)+size(value.get_stack(),depth+1)
            if isinstance(value,BaseException):
                return (total+size(value.args,depth+1)+size(vars(value),depth+1)+size(value.__traceback__,depth+1)
                    +size(value.__cause__,depth+1)+size(value.__context__,depth+1))
            module=type(value).__module__
            if module.startswith(('velociraptor_observation','anyio.streams.','mcp.shared.',
                    'mcp.server.connection','mcp.server.runner','mcp.types','threading','contextlib',
                    'anyio._backends._asyncio','pathlib')):
                if hasattr(value,'__dict__'):total+=size(vars(value),depth+1)
                if is_dataclass(value):total+=sum(size(getattr(value,f.name),depth+1) for f in fields(value) if hasattr(value,f.name))
                for cls in type(value).__mro__:
                    slots=cls.__dict__.get('__slots__',())
                    if isinstance(slots,str):slots=(slots,)
                    total+=sum(size(getattr(value,name),depth+1) for name in slots
                        if name not in ('__dict__','__weakref__') and hasattr(value,name))
            return total
        roots=(self._work,self._sessions,self._sequence_records,self._children,self._binary_sequences,
            self._outgoing,self._outgoing_records,self._prefixes,self._close_errors,self._close_io,
            self._closed_cuts,self._maintenance,self._close_tasks,
            None if self._exporter is None else vars(self._exporter),self._ledger._attempts,self._ledger._seen,self._ledger._issued_prefixes)
        measured=size((roots,temporary))
        self._retained_measured_peak=max(self._retained_measured_peak,measured)
        return measured

    def _retained_gate(self, extra=0, *, temporary=()):
        with self._lock:
            try:measured=self._measure_retained(temporary)
            except BaseException:
                self._unknown();raise
            self._retained=max(self._retained,measured)
            if self._retained+self._temporary_reserved+extra>self._limits['max_retained_state_bytes']:
                if self._state!='UNKNOWN':self._state='DRAINING'
                raise ControllerError('retained_budget')

    def _pending_count(self, response=None):
        # One instance-wide gate. Retired entries remain permanent; completion
        # releases only pending capacity, never sequence/history capacity.
        incoming=sum((not (r.handler_exited and r.http_exited) if r.sequence in self._binary_sequences
            else not r.handler_exited and r.response_pending is None and (r.pending_creation or not r.enqueued))
            for r in self._work.values())
        children=sum(r.pid is None and not r.resources_closed and not r.no_spawn
            for r in self._children.values())
        outgoing=sum(r is not response
            and r['dispatcher']._pending.get(coerce_request_id(r['message']['id'])) is r['pending']
            for r in self._outgoing_records)
        return incoming+children+outgoing

    def _pending_gate(self, response=None):
        if self._pending_count(response)>=self._limits['max_pending_work']:
            self._state='DRAINING'
            raise ControllerError('pending_budget')

    def _settle_unclaimed(self, row):
        # Only an unhanded-off ticket is ours to claim. Once enqueued, an HTTP
        # failure cannot steal the journal from a possibly running SDK worker.
        if not row.enqueued and not row.started and not row.handler_exited:
            if row.journal is not None and not self._ledger._unknown:
                self._claim(row)
                self._finish(row,'cancelled')
            elif row.attempt is None:
                row.outcome='not_dispatched';row.handler_exited=True

    async def _owned_close_io(self, session, function, deadline, phase=None, *, temporary_bytes=None):
        # The controller owns both the real non-daemon native-I/O thread and its
        # waiter before start. HTTP cancellation/timeout cannot abandon either.
        row=_CloseIO(session)
        if temporary_bytes is not None:
            row.temporary=self._reserve_temporary(temporary_bytes,row)
        def execute():
            try:row.result=function()
            except BaseException as error:row.error=row.error or error
            finally:
                row.wrapper_exited=True
                if row.temporary is not None:row.temporary.release()
        async def join():
            # Poll the real thread rather than notifying a possibly closed loop
            # from native code. Loop loss keeps the permanent record unjoined.
            try:
                while row.thread.is_alive():await asyncio.sleep(.001)
                row.thread.join()
                if row.thread.is_alive() or not row.wrapper_exited:
                    raise ControllerError('close_io_join_unknown')
                row.joined=True
            except BaseException as error:
                if row.error is None:row.error=error
                else:row.error.add_note('close_io_join_unknown')
                self._unknown(session)
                # Preserve errors in the owned row, including Task cancellation.
        try:row.thread=threading.Thread(target=execute,daemon=False,name='pc026-close-io')
        except BaseException:
            if row.temporary is not None:row.temporary.release()
            raise
        key=session if phase is None else (session,phase)
        with self._lock:
            if key in self._close_io:
                if row.temporary is not None:row.temporary.release()
                raise ControllerError('close_io_reentered')
            self._close_io[key]=row
        try:row.thread.start()
        except BaseException as error:
            # A raised start is not proof of no start. Some launchers can
            # start the real worker and then raise; its finally owns release.
            if row.thread.ident is None and not row.thread.is_alive() and row.temporary is not None:
                row.temporary.release()
            row.error=error;self._unknown(session);raise
        joining=join()
        try:row.task=asyncio.create_task(joining)
        except BaseException as error:
            joining.close()
            if row.error is None:row.error=error
            else:row.error.add_note('close_io_join_task_start_unknown')
            self._unknown(session)
            raise row.error
        while not row.task.done():
            if time.monotonic_ns()>=deadline:raise ControllerError('close_io_timeout')
            await anyio.sleep(.001)
        row.task.result()
        if row.error is not None:raise row.error
        return row.result

    def _reserve_transfer(self, owner, transfer_id, digest, job, nonce, root):
        group=owner.group
        # Same lock order as retained threads. Descendants of admitted owners
        # remain admissible after CLOSING, but foreign/ended owners do not.
        with group._lock:
            if (type(group) is not _Threads or group._controller is not self
                    or not group._valid(owner)):
                raise ControllerError('child_owner_invalid')
            info=root.lstat()
            with self._lock:
                self._pending_gate()
                retained=4096+len(str(root).encode('utf-8'))+len(transfer_id)+len(digest)+len(job)+len(nonce)
                if self._retained+retained > self._limits['max_retained_state_bytes']:
                    self._state='DRAINING';raise ControllerError('child_retained_budget')
                self._retained_gate(retained)
                sequence=self._sequence_for(group._session,'transfer_child')
                row=_TransferChild(sequence,group._session,owner,transfer_id,digest,
                    job,nonce,root,(info.st_dev,info.st_ino),self)
                self._children[sequence]=row
                self._retained+=retained
                return row

    def _children_closed(self, session):
        # No controller lock around native calls or RootLease acquisition.
        with self._lock:
            rows=[r for r in self._children.values() if r.session==session]
        result=True
        for row in rows:
            if not row._poll(): result=False
        return result

    def _attach_manager(self, manager):
        from velociraptor_observation_sdk_adapter import _TrackedManager
        if type(manager) is not _TrackedManager or manager.stateless or manager.session_idle_timeout is not None:
            raise ControllerError('manager_invalid')
        self._manager = manager
        manager._controller = self

    def _creating(self, session, scope, transport):
        ticket = scope.get('pc026.ticket')
        with self._lock:
            row = self._work.get(ticket)
            if row is None or row.session is not None or row.message.get('method') != 'initialize':
                self._unknown(); raise ControllerError('creation_not_owned')
            row.session = session
            self._sequence_records[row.sequence]=(session,'http_message')
            self._sessions[session] = dict(state='PENDING', owner=row.owner,
                transport=transport, threads=_Threads(self, session), initialized=False)
            self._pending -= 1
            row.pending_creation=False
            if hasattr(self,'_bindings'):self._bindings.owners[session]=row.owner

    async def _await_initialized(self, session, owner, message):
        if session is None:return
        deadline=time.monotonic_ns()+self._limits['close_timeout_ns']
        while True:
            with self._lock:
                data=self._sessions.get(session)
                if data is None or data['owner']!=owner:return
                if message.get('method')=='notifications/initialized':
                    if data['state']!='PENDING':return
                    pending=any(r.session==session and r.message.get('method')=='initialize'
                        and r.enqueued and not r.http_exited for r in self._work.values())
                    if not pending:return
                elif data['initialized'] or data['state']!='OPEN':return
                if message.get('method')!='notifications/initialized':
                    pending=any(r.session==session and r.message.get('method')=='notifications/initialized'
                        and r.enqueued and not r.handler_exited for r in self._work.values())
                    if not pending:return
            # The pinned SDK sends notification HTTP 202 before its runner has
            # dispatched it. Wait that real admitted tail, never invent readiness.
            if time.monotonic_ns()>=deadline:raise ControllerError('session_not_initialized',409)
            await anyio.sleep(.001)

    def _admit(self, session, owner, message, response=None):
        encoded = _canonical(message)
        with self._lock:
            tail=response is not None or message.get('method')=='notifications/cancelled'
            if self._state != 'ACTIVE' and not (self._state=='DRAINING' and session is not None and tail):
                raise ControllerError('draining')
            if session is None:
                if (len(self._sessions)+self._pending >= self._limits['max_sessions']
                        or self._pending >= self._limits['max_pending_work']):
                    self._state='DRAINING'; raise ControllerError('session_budget')
            else:
                current = self._sessions.get(session)
                if current is None or current['owner'] != owner: raise ControllerError('session_not_found',404)
                if current['state'] != 'OPEN': raise ControllerError('closing',409)
                if not current['initialized'] and message.get('method') != 'notifications/initialized':
                    raise ControllerError('session_not_initialized',409)
            if message.get('method')=='tools/call':
                maintenance=self._maintenance.get(session)
                if maintenance is not None:
                    params=message.get('params',{});args=params.get('arguments',{})
                    from velo_transfer.mcp_tools import TRANSFER_TOOL_NAMES
                    name=params.get('name')
                    if name not in TRANSFER_TOOL_NAMES:raise ControllerError('maintenance_tool')
                    if name!='transfer_capabilities':
                        details=args.get('request',args)
                        if (details.get('transfer_id'),details.get('request_digest'))!=maintenance['transfer_binding']:
                            raise ControllerError('maintenance_transfer_binding')
                self._capacity_for(session,'attempts',self._ledger._attempt_count,self._ledger._limits['max_attempts'])
            self._pending_gate(response)
            copied=_json_copy(message)
            retained=_message_size(copied)+sys.getsizeof(_Work)+1024
            if self._retained+retained > self._limits['max_retained_state_bytes']:
                self._state='DRAINING'; raise ControllerError('retained_budget')
            self._retained_gate(retained)
            ticket = object.__new__(_Ticket)
            row = _Work(self._sequence_for(session,'http_message'), session, owner, copied,
                pending_creation=session is None)
            self._work[ticket] = row
            self._retained += retained
            if session is None:self._pending += 1
            return ticket, row

    def _admit_binary(self, session, owner, sha):
        with self._lock:
            if len(self._binary_sequences)>=self._limits['max_binary_work']:
                self._state='DRAINING';raise ControllerError('binary_budget')
            self._capacity_for(session,'binary',len(self._binary_sequences),self._limits['max_binary_work'])
            ticket,row=self._admit(session,owner,dict(method='HTTP_CHUNKBIN'))
            self._consume_capacity(session,'binary')
            self._sequence_records[row.sequence]=(session,'binary_http')
            self._binary_sequences.add(row.sequence)
            row.request_sha256=sha
            row.enqueued=row.started=True
            return ticket,row

    def _issued_request(self, dispatcher, message):
        owner=_CURRENT_OWNER.get()
        group=getattr(owner,'group',None)
        if type(group) is not _Threads or group._controller is not self:
            self._unknown();raise ControllerError('outbound_owner_invalid')
        with group._lock:
            if not group._valid(owner):
                self._unknown(group._session);raise ControllerError('outbound_owner_ended')
            pending=dispatcher._pending.get(coerce_request_id(message.id))
            if pending is None:raise ControllerError('outbound_pending_missing')
            with self._lock:
                key=(id(dispatcher),type(message.id),message.id)
                previous=self._outgoing.get(key)
                if previous is not None and dispatcher._pending.get(coerce_request_id(message.id)) is previous['pending']:
                    self._unknown(group._session);raise ControllerError('outbound_reentered')
                self._pending_gate()
                retained=4096+_message_size(message.model_dump(mode='json',by_alias=True))
                if self._retained+retained>self._limits['max_retained_state_bytes']:
                    self._state='DRAINING';raise ControllerError('outbound_retained_budget')
                self._retained_gate(retained)
                sequence=self._sequence_for(group._session,'outbound_request')
                pending.send=dispatcher._resources.watch(pending.send)
                pending.receive=dispatcher._resources.watch(pending.receive)
                issued=dict(dispatcher=dispatcher,pending=pending,owner=owner,
                    session=group._session,reply=None,sequence=sequence,
                    message=message.model_dump(mode='json',by_alias=True))
                self._outgoing[key]=issued
                self._outgoing_records.append(issued)
                self._retained+=retained

    def _response_pending(self, session, message):
        data=self._sessions.get(session)
        if data is None:raise ControllerError('session_not_found',404)
        dispatcher=getattr(data['transport']._owned,'dispatcher',None)
        key=(id(dispatcher),type(message.get('id')),message.get('id'))
        issued=self._outgoing.get(key)
        if (issued is None or issued['session']!=session or issued['reply'] is not None
                or dispatcher._pending.get(coerce_request_id(message['id'])) is not issued['pending']):
            raise ControllerError('response_not_pending',400)
        return issued

    async def _consume_response(self, dispatcher, item, consume):
        request=getattr(item.metadata,'request_context',None)
        ticket=None if request is None else request.scope.get('pc026.ticket')
        with self._lock:
            row=self._work.get(ticket)
            if row is None or row.started or row.response_pending is None:
                self._unknown();raise ControllerError('response_ticket_unowned')
            if type(item.message.id) is not type(row.message.get('id')) or item.message.id!=row.message.get('id'):
                self._unknown(row.session);raise ControllerError('response_id_differs')
            issued=row.response_pending
            if issued['reply'] is not row or issued['dispatcher'] is not dispatcher:
                self._unknown(row.session);raise ControllerError('response_pending_differs')
            row.started=True
            present=dispatcher._pending.get(coerce_request_id(item.message.id)) is issued['pending']
        try:
            if present:await consume()
            row.outcome='returned' if present else 'not_dispatched'
            row.handler_exited=True
            self._release_input_storage(row)
        except BaseException as error:
            row.error=error;self._unknown(row.session);raise

    def _begin(self, row):
        msg = row.message
        if msg.get('method') != 'tools/call': return
        params = msg['params']; rid = msg['id']
        key = dict(instance_id=self._ledger._instance,session_id=row.session,
            request_id_type='integer' if type(rid) is int else 'string',request_id=rid)
        tool = params['name']; sha=hashlib.sha256(_canonical(params.get('arguments',{}))).hexdigest()
        try:
            with self._lock:
                self._capacity_for(row.session,'attempts',self._ledger._attempt_count,self._ledger._limits['max_attempts'])
                row.attempt = self._ledger.begin(key,tool,sha)
                self._consume_capacity(row.session,'attempts')
            if row.attempt.decision == 'NEW':
                row.journal = self._ledger.accept(row.attempt)
                codec = self._ledger._config.codec
                row.scope = ObservationScope(key,tool,sha,codec.max_records-2,codec.max_record_bytes)
                row.scope._journal_required = True
        except BaseException as error:
            row.error=error
            self._unknown(row.session); raise

    def _claim(self, row):
        scope = row.scope
        if scope is not None:
            row.journal.claim(scope._journal_owner,scope._key,scope._tool,scope._arguments_sha256)
            scope._journal,scope._journal_ready = row.journal,True

    def _finish(self, row, outcome, primary=None):
        try:
            if row.scope is not None:
                row.scope._finish(outcome)
                # Use the actual seal argument, not the diagnostic snapshot.
                self._ledger.finish(row.attempt,outcome)
            row.outcome, row.handler_exited = outcome, True
            self._release_input_storage(row)
        except BaseException as error:
            row.error=row.error or error
            self._unknown(row.session)
            if primary is not None:
                primary.add_note('controller_finalization_unknown')
                return
            raise

    async def _dispatch(self, dctx, method, params, call_next):
        request = getattr(dctx.message_metadata,'request_context',None)
        ticket = None if request is None else request.scope.get('pc026.ticket')
        with self._lock:
            row=self._work.get(ticket)
            if row is None or row.started or row.handler_exited:
                self._unknown(); raise ControllerError('ticket_unowned_or_reentered')
            expected=row.message
            rid=getattr(dctx,'request_id',None)
            if (expected.get('method') != method or _canonical(expected.get('params')) != _canonical(params)
                    or type(expected.get('id')) is not type(rid) or expected.get('id') != rid):
                self._unknown(row.session); raise ControllerError('ticket_context_differs')
            row.started=True
        threads=self._sessions[row.session]['threads']
        primary=None; outcome='returned'; observation_token=owner_token=None
        try:
            self._claim(row)
            row.worker_owner=threads._admit()
            owner_token=_CURRENT_OWNER.set(row.worker_owner)
            if row.scope is not None: observation_token=_current.set(row.scope)
            result=await call_next(dctx,method,params)
            if method=='notifications/initialized':
                with self._lock:
                    self._sessions[row.session]['initialized']=True
                    if hasattr(self,'_bindings'):self._bindings.initialized.add(row.session)
        except BaseException as exc:
            primary=exc
            outcome='cancelled' if isinstance(exc,anyio.get_cancelled_exc_class()) else 'raised'
            raise
        finally:
            with anyio.CancelScope(shield=True):
                try:
                    if row.worker_owner is not None: threads._finish_owner(row.worker_owner,primary=primary)
                    self._finish(row,outcome,primary)
                except BaseException:
                    self._unknown(row.session)
                    if primary is None: raise
                    primary.add_note('controller_worker_finish_unknown')
                finally:
                    if observation_token is not None: _current.reset(observation_token)
                    if owner_token is not None: _CURRENT_OWNER.reset(owner_token)
        return result

    def _conflicts(self, one, two):
        a,b=one.message,two.message
        return ('id' in a and 'method' in a and 'id' in b and 'method' in b
                and (str(a['id'])==str(b['id']) or coerce_request_id(a['id'])==coerce_request_id(b['id'])))

    async def _slot(self, row, receive=None):
        disconnect=None
        ready=False
        try:
            while True:
                with self._lock:
                    if row.cancelled:return False
                    previous=[p for p in self._work.values() if p.session==row.session
                        and p.sequence<row.sequence and self._conflicts(row,p)
                        and not (p.http_exited and p.handler_exited and all(s.closed for s in p.streams))]
                    if disconnect is not None and disconnect.done():
                        part=disconnect.result()
                        if part['type']!='http.disconnect':
                            self._unknown(row.session);raise ControllerError('queued_receive_unknown')
                        row.cancelled=True
                        return False
                    if not previous:
                        ready=True
                        break
                    if self._pending_count()>self._limits['max_pending_work']:
                        row.cancelled=True
                        return False
                # Full request-body EOF was already observed. Only the queued
                # owner reads disconnect, and it joins before SDK takes receive.
                if receive is not None and disconnect is None:
                    receiving=receive()
                    try:disconnect=asyncio.create_task(receiving)
                    except BaseException:
                        receiving.close();raise
                    row.receive_waiter=disconnect
                await anyio.sleep(.001)
        finally:
            if disconnect is not None:
                with anyio.CancelScope(shield=True):
                    if not disconnect.done():disconnect.cancel()
                    try:part=await disconnect
                    except asyncio.CancelledError:pass
                    else:
                        if part['type']=='http.disconnect':row.cancelled=True
                        else:
                            self._unknown(row.session);raise ControllerError('queued_receive_unknown')
                    if not disconnect.done():
                        self._unknown(row.session);raise ControllerError('queued_receive_join_unknown')
        with self._lock:
            if not ready or row.cancelled:return False
            row.enqueued=True
            return True

    def _cancel(self, session, rid):
        with self._lock:
            rows=[r for r in self._work.values() if r.session==session
                and type(r.message.get('id')) is type(rid) and r.message.get('id')==rid
                and 'method' in r.message and not r.handler_exited]
            if not rows: return False
            row=min(rows,key=lambda r:r.sequence)
            if row.enqueued: return True  # Only exact typed active target forwarded.
            row.cancelled=True
            return False

    async def _close_session(self, session, owner, reason='DELETE'):
        with self._lock:
            data=self._sessions.get(session)
            if data is None or data['owner'] != owner: raise ControllerError('session_not_found',404)
            if data['state']=='UNKNOWN' or self._state=='UNKNOWN':raise ControllerError('close_unknown')
            if data['state']=='CLOSED':return self._closed_cuts[session]
            if data['state']!='OPEN': raise ControllerError('closing',409)
            data['state']='CLOSING'
            for row in self._work.values():
                if row.session==session and not row.enqueued: row.cancelled=True
        data['threads']._freeze()
        deadline=time.monotonic_ns()+self._limits['close_timeout_ns']
        try:
            task=asyncio.create_task(data['transport'].terminate())
            self._close_tasks[session]=task
            while True:
                if task.done():task.result()
                with self._lock:
                    complete=all(r.handler_exited and r.http_exited for r in self._work.values() if r.session==session)
                children_closed=self._children_closed(session)
                if data['state']=='UNKNOWN':raise ControllerError('child_unknown')
                if task.done() and complete and children_closed and data['transport']._owned.known_closed() and data['threads']._quiescent(): break
                if time.monotonic_ns()>=deadline: raise ControllerError('close_unknown')
                await anyio.sleep(.001)
        except BaseException:
            with self._lock:
                data['state']='UNKNOWN'
                if self._state!='UNKNOWN':self._state='DRAINING'
            raise
        # Collect the actual native prefix only after the causal barrier.
        # A prefix alone cannot authorize 200. Reserve before its source copy.
        try:
            remaining=self._limits['max_retained_state_bytes']-self._retained
            def collect():
                reserve=getattr(self._exporter,'reserve',None)
                if reserve is not None:reserve(session)
                return self._ledger._session_prefix(session,max_files=self._limits['max_export_files'],
                    max_bytes=min(self._limits['max_export_bytes'],remaining))
            prefix=await self._owned_close_io(session,collect,deadline)
            if time.monotonic_ns()>=deadline:raise ControllerError('close_unknown')
            retained=_message_size(vars(prefix))+sum(_message_size(vars(r)) for r in prefix.originals)
            with self._lock:
                if self._state=='UNKNOWN' or self._ledger._unknown:raise ControllerError('prefix_unknown')
                if self._retained+retained>self._limits['max_retained_state_bytes']:
                    raise ControllerError('prefix_retained_budget')
                self._prefixes[session]=prefix
                self._retained+=retained
        except BaseException as error:
            self._close_errors[session]=error
            self._unknown(session);raise
        if self._exporter is None:raise ControllerError('cut_unavailable')
        try:
            self._retained_gate()
            proof=self._lifecycle(session,reason)
            self._retained_gate(_message_size(proof))
            def retain_export(graph):
                self._retain_export(graph)
                if time.monotonic_ns()>=deadline:raise ControllerError('export_deadline')
            descriptor=await self._owned_close_io(session,
                lambda:self._exporter.publish(prefix,proof,retain=retain_export),deadline,'export')
            if time.monotonic_ns()>=deadline:raise ControllerError('close_unknown')
            self._retained_gate()
            from velociraptor_observation_cut import close_headers
            close_headers(descriptor)  # Strict path/Ref/header before CLOSED.
            with self._lock:
                if self._state=='UNKNOWN' or self._ledger._unknown or not self._exporter.receipt(session,descriptor):
                    raise ControllerError('export_close_unknown')
                self._closed_cuts[session]=descriptor
                data['state']='CLOSED'
            return descriptor
        except BaseException as error:
            self._close_errors[session]=error;self._unknown(session);raise

    def _retain_export(self, graph):
        # Late native work may release resources after timeout/cancellation;
        # it must not begin a successful native publication after UNKNOWN.
        with self._lock:
            if self._state=='UNKNOWN' or self._ledger._unknown:
                raise ControllerError('export_owner_unknown')
            self._retained_gate(temporary=graph)

    def _lifecycle(self, session, reason):
        from velociraptor_observation_sdk import PIN_REF
        data=self._sessions[session];resources=data['transport']._owned
        if not resources.known_closed() or not data['threads']._quiescent():
            raise ControllerError('lifecycle_cleanup_unknown')
        with self._lock:
            messages=[];binary=[];children=[]
            for row in self._work.values():
                if row.session!=session:continue
                if (not row.handler_exited or not row.http_exited or any(not s.closed for s in row.streams)
                        or row.receive_waiter is not None and not row.receive_waiter.done()):
                    raise ControllerError('lifecycle_http_unknown')
                if row.sequence in self._binary_sequences:
                    binary.append(dict(operation_sequence=row.sequence,request_sha256=row.request_sha256,
                        outcome=row.outcome,thread_exited=True,resources_closed=True))
                else:
                    rid=row.message.get('id')
                    messages.append(dict(operation_sequence=row.sequence,request_id_type=None if rid is None
                        else 'integer' if type(rid) is int else 'string',request_id=rid,
                        method=row.message.get('method','JSONRPC_RESPONSE'),handler_outcome=row.outcome,worker_exited=True))
            for row in self._outgoing_records:
                if row['session']!=session:continue
                pending=row['pending']
                if not pending.send.closed or not pending.receive.closed:raise ControllerError('lifecycle_outgoing_unknown')
                rid=row['message']['id'];reply=row['reply']
                messages.append(dict(operation_sequence=row['sequence'],request_id_type='integer' if type(rid) is int else 'string',
                    request_id=rid,method=row['message']['method'],handler_outcome='returned' if reply is not None
                        and reply.outcome=='returned' else 'cancelled',worker_exited=True))
            for row in self._children.values():
                if row.session!=session:continue
                if row.no_spawn or not row.resources_closed or row.wait_status is None or row.error is not None:
                    raise ControllerError('lifecycle_child_unknown')
                children.append(dict(operation_sequence=row.sequence,transfer_id=row.transfer_id,request_digest=row.digest,
                    worker_nonce=row.nonce,pid=row.pid,birth=row.birth,job=row.job,process_exited=True,resources_closed=True))
            return dict(schema_version=1,kind='pc026-observation-session-lifecycle-v1',instance_id=self._ledger._instance,
                session_id=session,sdk_pin_ref=dict(PIN_REF),close_reason=reason,admission_watermark=self._sequence,
                sdk_work=dict(messages=sorted(messages,key=lambda r:r['operation_sequence']),transfer_workers=children),
                binary_work=binary,attempt_sequences=[],cleanup=dict(runner_exited=True,dispatcher_joined=True,
                    connection_closed=True,transport_closed=True,journals_closed=True,export_io_closed=True),status='CLOSED_KNOWN')

    async def _drain(self):
        with self._lock:
            if self._state=='UNKNOWN':raise ControllerError('instance_unknown')
            if self._state=='CLOSED':return
            self._state='DRAINING'
            sessions=list(self._sessions.items())
        for session,data in sessions:
            await self._close_session(session,data['owner'],'SERVICE_STOP')
        if any(not row.joined for row in self._close_io.values()):raise ControllerError('drain_io_unknown')
        deadline=time.monotonic_ns()+self._limits['close_timeout_ns']
        try:
            await self._owned_close_io(None,self._ledger.close,deadline,'ledger_close')
            if self._ledger._unknown or not self._ledger._closed:raise ControllerError('drain_ledger_unknown')
            with self._lock:self._state='CLOSED'
        except BaseException:
            self._unknown();raise


def _message_size(value):
    # Count the retained parsed object, including container/string overhead;
    # canonical byte length alone substantially undercounts Python objects.
    total=sys.getsizeof(value)
    if type(value) is dict:
        total+=sum(_message_size(k)+_message_size(v) for k,v in value.items())
    elif type(value) in (list,tuple):total+=sum(_message_size(v) for v in value)
    return total


class _BinaryIngress:
    """Private controlled route, with an independent owner and no 08 parent."""
    def __init__(self, controller, service):
        from velo_transfer.http_wire import chunk_endpoint
        self.controller=controller
        self.endpoint=chunk_endpoint(service)

    async def __call__(self, scope, receive, send):
        from velo_transfer import wire
        c=self.controller;row=None;owner_token=observation_token=None;primary=None;started=False
        maintenance=None;session=None;original_send=send;input_storage=None;buffer=None
        async def maintenance_send(message):
            if message['type']=='http.response.body':
                if row is not None:row.response_bytes+=len(message.get('body',b''))
                c._maintenance_bytes(session,maintenance if maintenance is not None else (row.maintenance_exchange if row is not None else None),len(message.get('body',b'')),True)
            await original_send(message)
        send=maintenance_send
        try:
            owner=scope.get('velo.bearer_owner')
            if type(owner) is not bytes or len(owner)!=32:raise ControllerError('unauthorized',401)
            if scope.get('method')!='POST':raise ControllerError('method',405)
            headers=scope.get('headers',[])
            session=one_header(headers,'mcp-session-id')
            version=one_header(headers,'mcp-protocol-version')
            if version not in _PROTOCOLS:raise ControllerError('protocol',400)
            if one_header(headers,'x-mcp-server-instance')!=c._ledger._instance:
                raise ControllerError('instance',400)
            if one_header(headers,'content-type')!='application/octet-stream':
                raise ControllerError('content_type',415)
            with c._lock:
                bound=c._maintenance.get(session)
                if bound is not None and (one_header(headers,'x-velo-transfer-id'),one_header(headers,'x-velo-request-digest'))!=bound['transfer_binding']:
                    raise ControllerError('maintenance_transfer_binding')
            if hasattr(c,'_bindings'):
                rejected=c._bindings.check(headers,owner,instance_required=True)
                if rejected is not None:return await rejected(scope,receive,send)
            direction,args=wire.request_headers(headers)
            maintenance=c._maintenance_exchange(session,owner,'HTTP_CHUNKBIN')
            capacity=_body_capacity(headers,min(wire.BODY_LIMIT,c._limits['max_request_body_bytes']))
            input_storage=c._reserve_temporary(_body_storage_bound(capacity),'binary-input')
            buffer=_BodyBuffer(capacity)
            while True:
                part=await receive()
                if part['type']!='http.request':raise ControllerError('body_incomplete',400)
                raw=part.get('body',b'')
                c._maintenance_bytes(session,maintenance,len(raw))
                buffer.append(raw)
                if not part.get('more_body',False):break
            body=buffer.finish()
            wire.decode(body,direction+'_request')
            ticket,row=c._admit_binary(session,owner,hashlib.sha256(body).hexdigest())
            row.input_storage=input_storage;input_storage.owner=row
            row.request_bytes=len(body)
            group=c._sessions[session]['threads']
            row.worker_owner=group._admit()
            owner_token=_CURRENT_OWNER.set(row.worker_owner)
            observation_token=_current.set(None)
            sent=False
            async def replay():
                nonlocal sent
                if not sent:
                    sent=True;return dict(type='http.request',body=body,more_body=False)
                return await receive()
            response=await self.endpoint(Request(scope,replay))
            row.handler_exited=True;row.outcome='returned'
            async def observed(message):
                nonlocal started
                if message['type']=='http.response.start':started=True
                await send(message)
            await response(scope,receive,observed)
        except ControllerError as error:
            primary=error
            if row is not None:row.error=error;c._unknown(row.session)
            if started:raise
            await JSONResponse(dict(error=dict(code=error.code)),status_code=error.status)(scope,receive,send)
        except wire.WireError:
            await JSONResponse(dict(error=dict(code='invalid_frame')),status_code=400)(scope,receive,send)
        except BaseException as error:
            primary=error
            if row is not None:
                row.error=error
                row.outcome='cancelled' if isinstance(error,anyio.get_cancelled_exc_class()) else 'raised'
                c._unknown(row.session)
            raise
        finally:
            if buffer is not None:buffer.close()
            if input_storage is not None and row is None:input_storage.release()
            if maintenance is not None:maintenance['finished']=True
            if row is not None and row.maintenance_exchange is not None:row.maintenance_exchange['finished']=True
            if row is not None:
                with anyio.CancelScope(shield=True):
                    try:
                        if row.worker_owner is not None:group._finish_owner(row.worker_owner,primary=primary)
                        row.handler_exited=True
                    except BaseException:c._unknown(row.session);raise
                    finally:
                        if observation_token is not None:_current.reset(observation_token)
                        if owner_token is not None:_CURRENT_OWNER.reset(owner_token)
                        row.http_exited=True
                        c._release_input_storage(row)


class _HTTPIngress:
    """Private route behind the actual bearer and HostOrigin gates."""
    def __init__(self, controller): self.controller=controller
    async def __call__(self, scope, receive, send):
        if scope['type']!='http': return
        c=self.controller;row=None;response_started=False;response_pending=None
        maintenance=None;session=None;original_send=send;input_storage=None;buffer=None;transfer=False
        async def maintenance_send(message):
            if message['type']=='http.response.body':
                from velo_transfer import wire
                if transfer and row is not None and row.response_bytes+len(message.get('body',b''))>wire.BODY_LIMIT:
                    raise ControllerError('response_body_budget',413)
                if row is not None:row.response_bytes+=len(message.get('body',b''))
                c._maintenance_bytes(session,maintenance if maintenance is not None else (row.maintenance_exchange if row is not None else None),len(message.get('body',b'')),True)
            await original_send(message)
        send=maintenance_send
        try:
            owner=scope.get('velo.bearer_owner')
            if type(owner) is not bytes or len(owner)!=32: raise ControllerError('unauthorized',401)
            headers=scope.get('headers',[])
            session=one_header(headers,'mcp-session-id',required=False)
            version=one_header(headers,'mcp-protocol-version',required=False)
            if version is not None and version not in _PROTOCOLS:raise ControllerError('protocol',400)
            if any(k.lower()==b'last-event-id' for k,v in headers):raise ControllerError('replay_denied',400)
            method=scope['method']
            maintenance=c._maintenance_exchange(session,owner,'HTTP_'+method)
            if method=='DELETE':
                descriptor=await c._close_session(session,owner)
                from velociraptor_observation_cut import close_headers
                return await JSONResponse({},status_code=200,headers=close_headers(descriptor))(scope,receive,send)
            if method not in ('POST','GET'):raise ControllerError('method',405)
            request=Request(scope,receive)
            has_json,has_sse=check_accept_headers(request)
            if not has_sse or (method=='POST' and not has_json):raise ControllerError('accept',406)
            if method=='GET':
                message={'method':'HTTP_GET_SSE'}
                if session is None or version is None:raise ControllerError('session_required',400)
                body=b''
            else:
                if not StreamableHTTPServerTransport._check_content_type(None,request):raise ControllerError('content_type',415)
                # Count actual full ASGI bytes; a disconnect is not EOF.
                capacity=_body_capacity(headers,c._limits['max_request_body_bytes'])
                input_storage=c._reserve_temporary(_body_storage_bound(capacity),'json-input')
                buffer=_BodyBuffer(capacity)
                while True:
                    part=await receive()
                    if part['type']!='http.request':raise ControllerError('body_incomplete',400)
                    chunk=part.get('body',b'')
                    c._maintenance_bytes(session,maintenance,len(chunk))
                    buffer.append(chunk)
                    if not part.get('more_body',False):break
                body=buffer.finish();message=strict_json(body)
                _canonical(_json_copy(message));jsonrpc_message_adapter.validate_python(message,by_name=False)
                if type(message) is not dict:raise ControllerError('envelope',400)
                if 'id' in message and type(message['id']) not in (str,int):raise ControllerError('typed_id',400)
                if 'method' not in message:
                    if session is None or version is None:raise ControllerError('session_required',400)
                    with c._lock:
                        data=c._sessions.get(session)
                        if data is None or data['owner']!=owner:raise ControllerError('session_not_found',404)
                        response_pending=c._response_pending(session,message)
                elif message.get('method')=='initialize':
                    if session is not None:raise ControllerError('initialize_conflict',400)
                    if message.get('params',{}).get('protocolVersion') not in _PROTOCOLS:raise ControllerError('protocol',400)
                elif session is None or version is None:raise ControllerError('session_required',400)
                if message.get('method')=='tools/call':
                    from velo_transfer.mcp_tools import TRANSFER_TOOL_NAMES
                    params=message.get('params')
                    transfer=type(params) is dict and params.get('name') in TRANSFER_TOOL_NAMES
                    if ('id' not in message or type(params) is not dict or type(params.get('name')) is not str
                        or not params['name'] or type(params.get('arguments',{})) is not dict):
                        raise ControllerError('tool_parent',400)
            if not transfer and len(body)>4<<20:raise ControllerError('body_budget',413)
            await c._await_initialized(session,owner,message)
            if maintenance is None:
                maintenance=await c._prepare_maintenance(session,owner,message,len(body))
            with c._lock:
                # Recheck and reserve the actual outgoing waiter atomically.
                if response_pending is not None:response_pending=c._response_pending(session,message)
                ticket,row=c._admit(session,owner,message,response_pending)
                row.input_storage=input_storage
                if input_storage is not None:input_storage.owner=row
                row.request_bytes=len(body)
                if response_pending is not None:
                    row.response_pending=response_pending;response_pending['reply']=row
            scope={**scope,'pc026.ticket':ticket}
            c._begin(row)
            if row.attempt is not None and row.attempt.decision=='REJECTED':
                row.outcome='not_dispatched';row.handler_exited=True
                return await JSONResponse({'jsonrpc':'2.0','id':message['id'],
                    'error':{'code':-32600,'message':row.attempt.reason}})(scope,receive,send)
            if message.get('method')=='notifications/cancelled' and not c._cancel(session,message.get('params',{}).get('requestId')):
                row.outcome='not_dispatched';row.handler_exited=True
                return await JSONResponse(None,status_code=202)(scope,receive,send)
            if not await c._slot(row,receive):
                c._claim(row);c._finish(row,'cancelled')
                return await JSONResponse({'jsonrpc':'2.0','id':message.get('id'),
                    'error':{'code':-32800,'message':'Request cancelled'}})(scope,receive,send)
            delivered=False;status=None
            async def replay():
                nonlocal delivered
                if not delivered:
                    delivered=True;return {'type':'http.request','body':body,'more_body':False}
                return await receive()
            async def observed_send(msg):
                nonlocal status,response_started
                if msg['type']=='http.response.start':
                    status=msg['status'];response_started=True
                await send(msg)
            token=_CURRENT_HTTP.set((c,ticket,row))
            try:await c._manager.handle_request(scope,replay,observed_send)
            finally:_CURRENT_HTTP.reset(token)
            if message.get('method')=='HTTP_GET_SSE':row.handler_exited=True;row.outcome='returned'
            if message.get('method')=='initialize':
                deadline=time.monotonic_ns()+c._limits['close_timeout_ns']
                while row.session is not None and not row.handler_exited and status==200:
                    if time.monotonic_ns()>=deadline:
                        c._unknown(row.session);raise ControllerError('initialize_tail_unknown')
                    await anyio.sleep(.001)
                with c._lock:
                    if row.session is not None and row.handler_exited and row.outcome=='returned' and status==200:
                        c._sessions[row.session]['state']='OPEN'
                    else:c._unknown(row.session)
            if message.get('method')=='notifications/initialized' and row.handler_exited:
                c._sessions[row.session]['initialized']=True
        except ControllerError as exc:
            return await JSONResponse({'error':{'code':exc.code}},status_code=exc.status)(scope,receive,send)
        except Exception as error:
            if row is not None:
                row.error=row.error or error
                c._unknown(row.session)
            if response_started:raise
            return await JSONResponse({'error':{'code':'invalid_or_unknown'}},status_code=503 if row is not None or scope.get('method')=='DELETE' else 400)(scope,receive,send)
        except BaseException as error:
            if row is not None and row.enqueued and not row.handler_exited:
                # SDK ownership may already exist. Never claim its journal or
                # report quiescence merely because the HTTP caller vanished.
                row.error=row.error or error;c._unknown(row.session)
            if row is not None and row.attempt is not None and row.journal is not None and not row.enqueued:
                with anyio.CancelScope(shield=True):
                    try:c._claim(row);c._finish(row,'cancelled')
                    except BaseException:c._unknown(row.session)
            raise
        finally:
            if buffer is not None:buffer.close()
            if input_storage is not None and row is None:input_storage.release()
            if maintenance is not None:maintenance['finished']=True
            if row is not None and row.maintenance_exchange is not None:row.maintenance_exchange['finished']=True
            if row is not None:
                with anyio.CancelScope(shield=True):
                    try:c._settle_unclaimed(row)
                    except BaseException as error:
                        row.error=row.error or error;c._unknown(row.session)
                if row.message.get('method')=='HTTP_GET_SSE' and not row.handler_exited:
                    row.handler_exited=True;row.outcome='raised';c._unknown(row.session)
                row.http_exited=True
                if row.pending_creation:
                    with c._lock:
                        c._pending-=1;row.pending_creation=False
                    row.handler_exited=True
                    c._unknown()
                c._release_input_storage(row)
