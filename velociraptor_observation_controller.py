"""Private PC026 ingress/ledger/SDK chain, with conservative close refusal.

No public MODEL factory or production fallback. The fixed approved constructor
still refuses while the native exporter is unavailable. This partial controller
cannot publish cuts or certify CLOSED; DELETE never passes through SDK's 200.
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
                pending=sum(not r.resources_closed for r in self._children.values())
                if pending >= self._limits['max_pending_work']:
                    self._state='DRAINING'; raise ControllerError('child_pending_budget')
                retained=4096+len(str(root).encode('utf-8'))+len(transfer_id)+len(digest)+len(job)+len(nonce)
                if self._retained+retained > self._limits['max_retained_state_bytes']:
                    self._state='DRAINING';raise ControllerError('child_retained_budget')
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

    def _admit(self, session, owner, message):
        encoded = _canonical(message)
        with self._lock:
            if self._state != 'ACTIVE': raise ControllerError('draining')
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
            copied=_json_copy(message)
            retained=_message_size(copied)+sys.getsizeof(_Work)+1024
            if self._retained+retained > self._limits['max_retained_state_bytes']:
                self._state='DRAINING'; raise ControllerError('retained_budget')
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
                retained=4096+_message_size(message.model_dump(mode='json',by_alias=True))
                if self._retained+retained>self._limits['max_retained_state_bytes']:
                    self._state='DRAINING';raise ControllerError('outbound_retained_budget')
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
                queued=sum(not p.enqueued and not p.handler_exited and p.session==row.session
                           for p in self._work.values())
                if queued>self._limits['max_pending_work']:
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

    async def _close_session(self, session, owner):
        with self._lock:
            data=self._sessions.get(session)
            if data is None or data['owner'] != owner: raise ControllerError('session_not_found',404)
            if data['state']=='UNKNOWN':raise ControllerError('close_unknown')
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
        # No fake cut. Export/child closure is not implemented yet.
        raise ControllerError('cut_unavailable')


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
                await c._close_session(session,owner)
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
            with c._lock:
                # Recheck and reserve the actual outgoing waiter atomically.
                if response_pending is not None:response_pending=c._response_pending(session,message)
                ticket,row=c._admit(session,owner,message)
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
            return await JSONResponse({'error':{'code':'invalid_or_unknown'}},status_code=400 if row is None else 503)(scope,receive,send)
        except BaseException:
            if row is not None and row.attempt is not None and row.journal is not None and not row.enqueued:
                with anyio.CancelScope(shield=True):
                    try:c._claim(row);c._finish(row,'cancelled')
                    except BaseException:c._unknown(row.session)
            raise
        finally:
            if row is not None:
                row.http_exited=True
                if row.pending_creation:
                    with c._lock:
                        c._pending-=1;row.pending_creation=False
                    row.handler_exited=True
                    c._unknown()
