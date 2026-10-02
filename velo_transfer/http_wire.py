"""SDK-owned session binding and bounded ASGI I/O for the transfer wire."""
from __future__ import annotations

import asyncio
import base64
import hashlib

from starlette.responses import JSONResponse, Response
from . import wire


def security_error(status, code):
    return JSONResponse({"error": {"code": code}}, status_code=status)


class BodyLimitExceeded(Exception):
    """Abort an already-started response; never publish a truncated success."""


class SDKSessionBindings:
    """Observe real SDK handshakes; the manager remains the lifetime authority.

    The installed SDK exposes session_manager publicly but not a live-session
    lookup. This narrow version seam uses its actual transport table and
    is_terminated/idle_scope. An unsupported manager fails closed.
    """
    def __init__(self, manager, instance):
        self.manager = manager
        self.instance = instance
        self.owners = {}
        self.initialized = set()

    def live(self, session):
        manager = self.manager
        if manager is None or getattr(manager, '_task_group', None) is None:
            return False
        transport = getattr(manager, '_server_instances', {}).get(session)
        if transport is None or transport.is_terminated:
            self.owners.pop(session, None); self.initialized.discard(session)
            return False
        idle = getattr(transport, "idle_scope", None)
        if idle is not None:
            import anyio
            if idle.cancel_called or idle.deadline <= anyio.current_time():
                return False
        return True

    def check(self, headers, owner, *, instance_required=False):
        try:
            session = wire.one_header(headers, 'mcp-session-id', required=False)
        except wire.WireError:
            return security_error(400, 'invalid_frame')
        if session is None:
            return security_error(400, 'session_required')
        if not self.live(session) or session not in self.initialized or self.owners.get(session) != owner:
            return security_error(404, 'session_not_found')
        try:
            expected = wire.one_header(headers, 'x-mcp-server-instance', required=instance_required)
        except wire.WireError:
            return security_error(400, 'invalid_frame')
        if expected is not None and expected != self.instance:
            return security_error(400, 'invalid_frame')
        return None


class TransferHTTPGate:
    def __init__(self, app, bindings, mcp_path='/mcp', body_limit=wire.BODY_LIMIT):
        self.app = app; self.bindings = bindings; self.mcp_path = mcp_path
        self.body_limit = min(body_limit, wire.BODY_LIMIT)

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        headers = scope.get('headers', [])
        owner = scope.get('velo.bearer_owner')
        binary = scope.get('path') == '/chunkbin'
        if binary:
            error = self.bindings.check(headers, owner, instance_required=True)
            if error is not None:
                return await error(scope, receive, send)
        if not binary and (scope.get('path') != self.mcp_path or scope.get('method') != 'POST'):
            return await self.app(scope, receive, send)
        if not binary:
            # Header-present SDK sessions can be checked before body budgeting.
            # The initial handshake has no id; initialized notification is the
            # only legitimate request on a not-yet-ready owned live session.
            try:
                session = wire.one_header(headers, 'mcp-session-id', required=False)
            except wire.WireError:
                return await security_error(400, 'invalid_frame')(scope, receive, send)
            if session is not None and (not self.bindings.live(session) or self.bindings.owners.get(session) != owner):
                return await security_error(404, 'session_not_found')(scope, receive, send)
        # Count actual ASGI receive bytes, never trust Content-Length. Bound
        # buffering before SDK parsing/writer dispatch, including absent/fake CL.
        body = bytearray()
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            part = message.get('body', b'')
            if len(body) + len(part) > self.body_limit:
                return await security_error(413, 'body_too_large')(scope, receive, send)
            body.extend(part)
            if not message.get('more_body', False):
                break
        method = None; transfer = binary
        if not binary:
            try:
                value = wire.strict_json(bytes(body))
                if not isinstance(value, dict):
                    raise wire.WireError('invalid_frame')
                method = value.get('method')
                params = value.get('params')
                transfer = method == 'tools/call' and isinstance(params, dict) and params.get('name') in (
                    'transfer_capabilities', 'transfer_begin', 'transfer_status', 'transfer_chunk',
                    'transfer_chunks', 'transfer_finish', 'transfer_abort')
            except wire.WireError:
                return await security_error(400, 'invalid_frame')(scope, receive, send)
            # Keep the SDK's prior 4 MiB limit for the original DFIR slice.
            if not transfer and len(body) > 4 << 20:
                return await security_error(413, 'body_too_large')(scope, receive, send)
            if transfer:
                error = self.bindings.check(headers, owner)
                if error is not None:
                    return await error(scope, receive, send)
        delivered = False
        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
            return await receive()
        started = False; count = 0; start_message = None
        async def counted_send(message):
            nonlocal started, count, start_message
            if message['type'] == 'http.response.start':
                start_message = message
                if method == 'initialize' and message['status'] == 200:
                    session = next((v.decode('ascii') for k,v in message.get('headers', []) if k.lower()==b'mcp-session-id'), None)
                    if session and self.bindings.live(session):
                        self.bindings.owners[session] = owner
                if method == 'notifications/initialized' and message['status'] == 202:
                    try: session = wire.one_header(headers, 'mcp-session-id')
                    except wire.WireError: session = None
                    if session and self.bindings.live(session) and self.bindings.owners.get(session) == owner:
                        self.bindings.initialized.add(session)
                if not transfer:
                    started = True; await send(message)
                return
            if message['type'] == 'http.response.body' and transfer:
                count += len(message.get('body', b''))
                if count > self.body_limit:
                    if not started:
                        await security_error(413, 'body_too_large')(scope, receive, send)
                    raise BodyLimitExceeded('body_too_large')
                if not started:
                    await send(start_message); started = True
            await send(message)
        await self.app(scope, replay, counted_send)


def chunk_endpoint(service):
    async def endpoint(request):
        try:
            if wire.one_header(request.scope['headers'], 'content-type') != 'application/octet-stream':
                return security_error(415, 'unsupported_media_type')
        except wire.WireError:
            return security_error(415, 'unsupported_media_type')
        try:
            direction, arguments = wire.request_headers(request.scope['headers'])
            body = bytearray()
            async for part in request.stream():
                if len(body) + len(part) > wire.BODY_LIMIT:
                    return security_error(413, 'body_too_large')
                body.extend(part)
            header, payload = wire.decode(bytes(body), direction + '_request')
            if direction == 'push':
                chunks = []; cursor = 0
                for item in header['chunks']:
                    end = cursor + item['count']
                    chunks.append(dict(item, data_base64=base64.b64encode(payload[cursor:end]).decode('ascii')))
                    cursor = end
                arguments['chunks'] = chunks
        except wire.WireError:
            return security_error(400, 'invalid_frame')
        try:
            # Existing engine binds direction/digest/budget to registered state
            # and validates the entire batch before obtaining writer ownership.
            envelope = await asyncio.to_thread(service.invoke, 'transfer_chunks', **arguments)
            if envelope.status == 'error':
                code = envelope.error['code']
                code = code if type(code) is str and code in wire.CODES else 'internal_error'
                body = wire.encode({'status':'error','error':{'code':code}}, b'', 'error_response')
            elif direction == 'push':
                r = envelope.result
                body = wire.encode({'status':'success','result':{'verified_offset':r['verified_offset'],
                    'accepted':r['accepted']}}, b'', 'push_response')
            else:
                r = envelope.result; chunks = r['chunks']
                payload = b''.join(base64.b64decode(c['data_base64'], validate=True) for c in chunks)
                meta = [{k:c[k] for k in ('offset','count','chunk_sha256')} for c in chunks]
                body = wire.encode({'status':'success','result':{'verified_offset':r['verified_offset'],'chunks':meta}},
                                   payload, 'pull_response')
        except Exception:
            return security_error(500, 'internal_error')
        return Response(body, media_type='application/octet-stream')
    return endpoint
