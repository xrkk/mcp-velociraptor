"""Real SDK Streamable HTTP transport used by the flow-host CLI.

The coordinator only sees a connected ``ClientSession``; this module owns the
httpx2 client, the streamable-http duplex streams and orderly shutdown. The
optional ``http_client`` parameter is a narrow injection point for explicitly
simulated external transport faults in offline evidence; it never changes
protocol, validation or success qualification.

Shutdown keeps the FIRST failure: a body exception propagates untouched, and a
clean body only fails when shutdown itself failed. Partially-entered contexts
are never exited (an ``__aenter__`` failure leaves nothing to close at that
level), which keeps connect faults from cascading into spurious CancelledError.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


@asynccontextmanager
async def open_session(url: str, token: str | None, request_timeout: float, *,
                       http_client: httpx2.AsyncClient | None = None):
    """Yield one initialized ClientSession over the authenticated velo endpoint."""
    headers = {"Authorization": "Bearer " + token} if token else {}
    client = http_client
    owned = client is None
    if owned:
        client = httpx2.AsyncClient(headers={**headers, "Accept-Encoding": "identity"},
                                    timeout=request_timeout, follow_redirects=False,
                                    trust_env=False)
    streams_cm = None
    session_cm = None
    streams_entered = False
    session_entered = False
    entered_ok = False
    primary = None
    body_error = False
    try:
        streams_cm = streamable_http_client(url, http_client=client)
        read, write = await streams_cm.__aenter__()
        streams_entered = True
        session_cm = ClientSession(read, write)
        await session_cm.__aenter__()
        session_entered = True
        await session_cm.initialize()
        entered_ok = True
        try:
            yield session_cm
        except BaseException:
            body_error = True
            raise
    finally:
        if session_entered:
            try:
                await session_cm.__aexit__(None, None, None)
            except Exception as exc:
                primary = primary or exc
        if streams_entered:
            try:
                await streams_cm.__aexit__(None, None, None)
            except Exception as exc:
                primary = primary or exc
        if owned:
            try:
                await client.aclose()
            except Exception as exc:
                primary = primary or exc
        if entered_ok and not body_error and primary is not None:
            raise primary
