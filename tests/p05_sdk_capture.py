"""Passive capture of the original SDK JSON-RPC messages for P05 tests.

The owning stdio/HTTP context still owns the transport. No protocol messages
are added, transformed or replayed, and credentials are not a capture input.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path

import anyio


def _utc():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def _instant(text):
    instant = datetime.fromisoformat(text.replace('Z', '+00:00'))
    if instant.tzinfo is None:
        raise ValueError('capture timestamp must carry a timezone')
    return instant.astimezone(timezone.utc)


class SDKCapture:
    def __init__(self, path: Path):
        self.path = path
        self.stream = path.open('xb')
        self.sequence = 0
        # In-memory index of client requests so a call can join its raw
        # JSON-RPC id; identical repeated polls must never become ambiguous.
        self.sent_requests = []

    def record(self, direction, started, ended, message):
        # Capture the SDK SessionMessage's actual JSON-RPC object, not the
        # caller's derived structuredContent or a hand-written expected value.
        value = message.message.model_dump(mode='json', by_alias=True, exclude_none=True)
        self.sequence += 1
        if direction == 'client_to_server' and value.get('method') and 'id' in value:
            self.sent_requests.append({
                'id': value['id'],
                'method': value['method'],
                'params': value.get('params'),
                'started': _instant(started),
                'ended': _instant(ended),
            })
        payload = (json.dumps({
            'sequence': self.sequence, 'direction': direction,
            'started_at': started, 'ended_at': ended, 'message': value,
        }, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
        self.stream.write(payload)
        self.stream.flush()
        os.fsync(self.stream.fileno())

    def request_id_for(self, *, tool, arguments, started_at, ended_at):
        """Return the real JSON-RPC id of the one tools/call request sent
        inside the caller's [started_at, ended_at] window with these
        resolved arguments.  Raises when the join is not unique."""
        window_started = _instant(started_at)
        window_ended = _instant(ended_at)
        matches = [
            row for row in self.sent_requests
            if row['method'] == 'tools/call'
            and isinstance(row['params'], dict)
            and row['params'].get('name') == tool
            and row['params'].get('arguments') == arguments
            and window_started <= row['started'] and row['ended'] <= window_ended
        ]
        if len(matches) != 1:
            raise ValueError(f'captured tools/call does not join one unique raw SDK request for {tool}')
        return matches[0]['id']

    def wrap(self, read, write):
        return _Read(read, self), _Write(write, self)

    def close(self):
        self.stream.close()


class _Read:
    def __init__(self, stream, capture):
        self.stream, self.capture = stream, capture

    def __getattr__(self, name):
        return getattr(self.stream, name)

    async def __aenter__(self):
        await self.stream.__aenter__()
        return self

    async def __aexit__(self, *exc):
        return await self.stream.__aexit__(*exc)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return await self.receive()
        except anyio.EndOfStream:
            raise StopAsyncIteration from None

    async def receive(self):
        message = await self.stream.receive()
        if isinstance(message, BaseException):
            # The original exception is delivered unchanged; it is not a
            # JSON-RPC message and its potentially sensitive text is not logged.
            return message
        # The underlying receive may wait while a request is sent.  Timestamp
        # the message when it actually becomes available, not when that wait
        # began, so concurrent pipe waits cannot invert the causal transcript.
        started = _utc()
        self.capture.record('server_to_client', started, _utc(), message)
        return message


class _Write:
    def __init__(self, stream, capture):
        self.stream, self.capture = stream, capture

    def __getattr__(self, name):
        return getattr(self.stream, name)

    async def __aenter__(self):
        await self.stream.__aenter__()
        return self

    async def __aexit__(self, *exc):
        return await self.stream.__aexit__(*exc)

    async def send(self, message):
        started = _utc()
        await self.stream.send(message)
        self.capture.record('client_to_server', started, _utc(), message)
