"""Private PC026 ingress/ledger/SDK chain, with conservative close refusal.

No public MODEL factory or production fallback. The fixed approved constructor
still refuses while the native exporter is unavailable. Tests alone install a
real MODEL publisher; successful close requires its external final I/O witness.
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


@dataclass(eq=False)
class _CloseIO:
    session: str
    thread: object = None
    task: object = None
    result: object = None
    error: BaseException | None = None
    wrapper_exited: bool = False
    joined: bool = False


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
        from velociraptor_observation_startup import precheck_formal_http
        precheck_formal_http()  # No root/writer/listener or test override.
        raise ControllerError('native_exporter_unavailable')

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
            self._sequence += 1
            self._sequence_records[self._sequence] = (session, kind)
            return self._sequence

    def _measure_retained(self):
        # Domain-owned Python graph, not allocator arenas, backend memory, native
        # kernel objects or total RSS. Shared objects/cycles are charged once.
        from collections import deque
        from dataclasses import fields, is_dataclass
        seen={id(self),id(self._ledger),id(self._ledger._config)}
        if hasattr(self,'_manager'):seen.add(id(self._manager))
        def size(value,depth=0):
            if id(value) in seen:return 0
            seen.add(id(value));total=sys.getsizeof(value)
            if depth>64:raise ControllerError('retained_depth')
            if type(value) is dict:
                return total+sum(size(k,depth+1)+size(v,depth+1) for k,v in list(value.items()))
            if type(value) in (list,tuple,set,frozenset,deque):
                return total+sum(size(v,depth+1) for v in tuple(value))
            module=type(value).__module__
            if module.startswith(('velociraptor_observation','anyio.streams.','mcp.shared._context_streams')):
                if hasattr(value,'__dict__'):total+=size(vars(value),depth+1)
                elif is_dataclass(value):total+=sum(size(getattr(value,f.name),depth+1) for f in fields(value))
            elif isinstance(value,BaseException):
                total+=size(value.args,depth+1)+size(vars(value),depth+1)
                tb=value.__traceback__
                while tb is not None:
                    if id(tb) in seen:break
                    seen.add(id(tb));total+=sys.getsizeof(tb)+sys.getsizeof(tb.tb_frame)
                    tb=tb.tb_next
            return total
        roots=(self._work,self._sessions,self._sequence_records,self._children,self._binary_sequences,
            self._outgoing,self._outgoing_records,self._prefixes,self._close_errors,self._close_io,
            self._closed_cuts,self._ledger._attempts,self._ledger._seen)
        measured=size(roots)
        self._retained_measured_peak=max(self._retained_measured_peak,measured)
        return measured

    def _retained_gate(self, extra=0):
        with self._lock:
            measured=self._measure_retained()
            self._retained=max(self._retained,measured)
            if self._retained+extra>self._limits['max_retained_state_bytes']:
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

    async def _owned_close_io(self, session, function, deadline, phase=None):
        # The controller owns both the real non-daemon native-I/O thread and its
        # waiter before start. HTTP cancellation/timeout cannot abandon either.
        row=_CloseIO(session)
        loop=asyncio.get_running_loop();done=loop.create_future()
        def notify():
            if not done.done():done.set_result(None)
        def execute():
            try:row.result=function()
            except BaseException as error:row.error=error
            finally:
                row.wrapper_exited=True
                loop.call_soon_threadsafe(notify)
        async def join():
            await done
            row.thread.join()
            if row.thread.is_alive() or not row.wrapper_exited:
                raise ControllerError('close_io_join_unknown')
            row.joined=True
            # Keep errors in the permanent row, rather than an unobserved Task.
        row.thread=threading.Thread(target=execute,daemon=False,name='pc026-close-io')
        key=session if phase is None else (session,phase)
        with self._lock:
            if key in self._close_io:raise ControllerError('close_io_reentered')
            self._close_io[key]=row
        try:row.thread.start()
        except BaseException as error:
            row.error=error;self._unknown(session);raise
        row.task=asyncio.create_task(join())
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

    async def _await_initialized(self, session, owner, message):
        if session is None or message.get('method')=='notifications/initialized':return
        deadline=time.monotonic_ns()+self._limits['close_timeout_ns']
        while True:
            with self._lock:
                data=self._sessions.get(session)
                if data is None or data['owner']!=owner:return
                if data['initialized'] or data['state']!='OPEN':return
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
            ticket,row=self._admit(session,owner,dict(method='HTTP_CHUNKBIN'))
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
            row.attempt = self._ledger.begin(key,tool,sha)
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
                with self._lock: self._sessions[row.session]['initialized']=True
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

    async def _slot(self, row):
        while True:
            with self._lock:
                if row.cancelled: return False
                previous=[p for p in self._work.values() if p.session==row.session
                    and p.sequence<row.sequence and self._conflicts(row,p)
                    and not (p.http_exited and p.handler_exited and all(s.closed for s in p.streams))]
                if not previous:
                    row.enqueued=True
                    return True
                if self._pending_count()>self._limits['max_pending_work']:
                    row.cancelled=True
                    return False
            await anyio.sleep(.001)

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
        # Export publication is still unavailable: a prefix cannot authorize 200.
        try:
            remaining=self._limits['max_retained_state_bytes']-self._retained
            prefix=await self._owned_close_io(session,
                lambda:self._ledger._session_prefix(session,max_files=self._limits['max_export_files'],
                    max_bytes=min(self._limits['max_export_bytes'],remaining)),deadline)
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
            descriptor=await self._owned_close_io(session,
                lambda:self._exporter.publish(prefix,proof),deadline,'export')
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

    def _lifecycle(self, session, reason):
        from velociraptor_observation_sdk import PIN_REF
        data=self._sessions[session];resources=data['transport']._owned
        if not resources.known_closed() or not data['threads']._quiescent():
            raise ControllerError('lifecycle_cleanup_unknown')
        with self._lock:
            messages=[];binary=[];children=[]
            for row in self._work.values():
                if row.session!=session:continue
                if not row.handler_exited or not row.http_exited or any(not s.closed for s in row.streams):
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
            direction,args=wire.request_headers(headers)
            body=bytearray()
            while True:
                part=await receive()
                if part['type']!='http.request':raise ControllerError('body_incomplete',400)
                raw=part.get('body',b'')
                if len(body)+len(raw)>min(wire.BODY_LIMIT,c._limits['max_request_body_bytes']):
                    raise ControllerError('body_budget',413)
                body.extend(raw)
                if not part.get('more_body',False):break
            body=bytes(body)
            wire.decode(body,direction+'_request')
            ticket,row=c._admit_binary(session,owner,hashlib.sha256(body).hexdigest())
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


class _HTTPIngress:
    """Private route behind the actual bearer and HostOrigin gates."""
    def __init__(self, controller): self.controller=controller
    async def __call__(self, scope, receive, send):
        if scope['type']!='http': return
        c=self.controller;row=None;response_started=False;response_pending=None
        try:
            owner=scope.get('velo.bearer_owner')
            if type(owner) is not bytes or len(owner)!=32: raise ControllerError('unauthorized',401)
            headers=scope.get('headers',[])
            session=one_header(headers,'mcp-session-id',required=False)
            version=one_header(headers,'mcp-protocol-version',required=False)
            if version is not None and version not in _PROTOCOLS:raise ControllerError('protocol',400)
            if any(k.lower()==b'last-event-id' for k,v in headers):raise ControllerError('replay_denied',400)
            method=scope['method']
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
                body=bytearray()
                while True:
                    part=await receive()
                    if part['type']!='http.request':raise ControllerError('body_incomplete',400)
                    chunk=part.get('body',b'')
                    if len(body)+len(chunk)>c._limits['max_request_body_bytes']:raise ControllerError('body_budget',413)
                    body.extend(chunk)
                    if not part.get('more_body',False):break
                body=bytes(body);message=strict_json(body)
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
                    params=message.get('params')
                    if ('id' not in message or type(params) is not dict or type(params.get('name')) is not str
                        or not params['name'] or type(params.get('arguments',{})) is not dict):
                        raise ControllerError('tool_parent',400)
            await c._await_initialized(session,owner,message)
            with c._lock:
                # Recheck and reserve the actual outgoing waiter atomically.
                if response_pending is not None:response_pending=c._response_pending(session,message)
                ticket,row=c._admit(session,owner,message,response_pending)
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
            if not await c._slot(row):
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
        except BaseException:
            if row is not None and row.attempt is not None and row.journal is not None and not row.enqueued:
                with anyio.CancelScope(shield=True):
                    try:c._claim(row);c._finish(row,'cancelled')
                    except BaseException:c._unknown(row.session)
            raise
        finally:
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
