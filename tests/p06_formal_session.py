"""One external official-SDK session for P06 test attempts, never stdio."""

from contextlib import asynccontextmanager
import hashlib
import ipaddress
import os
from pathlib import Path
import socket
from urllib.parse import urlsplit


@asynccontextmanager
async def formal_session(endpoint, token_env, observation_path, run_dir, report):
    import httpx2
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    from tests.scenario_runner import (
        HttpHeaderCapture, canonical_bytes, tools_schema_document,
        utc_now, verify_server_observation,
    )

    parsed = urlsplit(endpoint)
    if (parsed.scheme != 'http' or parsed.port != 28790 or parsed.path != '/mcp'
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError('invalid formal endpoint')
    ipaddress.IPv4Address(parsed.hostname)
    token = os.environ.get(token_env, '').strip()
    if not token:
        raise ValueError('formal HTTP bearer token is not configured')
    capture = HttpHeaderCapture(httpx2.AsyncHTTPTransport())
    try:
        async with httpx2.AsyncClient(headers={'Authorization': f'Bearer {token}'},
                                     timeout=60, transport=capture) as client:
            async with streamable_http_client(endpoint, http_client=client) as (read, write):
                async with ClientSession(read, write) as session:
                    report['mcp_session']['initialized_at'] = utc_now()
                    await session.initialize()
                    row = next((row for row in capture.responses
                                if row['method'] == 'POST' and row['mcp_session_id']), None)
                    if row is None or not row['server_instance_id']:
                        raise ValueError('initialize response lacks formal session or instance identity')
                    report['mcp_session']['id'] = row['mcp_session_id']
                    capture.expected_identity = (row['mcp_session_id'], row['server_instance_id'])
                    observed = verify_server_observation(Path(observation_path), row['server_instance_id'])
                    if socket.gethostname().casefold() == observed['computer_name'].casefold():
                        raise ValueError('formal P06 client must execute outside the target VM')
                    raw = Path(observation_path).read_bytes()
                    (run_dir / 'server-observation.json').write_bytes(raw)
                    report['server_observation_sha256'] = hashlib.sha256(raw).hexdigest()
                    report['server_identity'] = {key: value for key, value in observed.items() if key != 'observed_at'}
                    listing = await session.list_tools()
                    (run_dir/'tools-list.json').write_bytes(canonical_bytes(
                        listing.model_dump(mode='json',by_alias=True,exclude_none=True)))
                    tools = listing.tools
                    document = tools_schema_document(tools)
                    raw = canonical_bytes(document)
                    (run_dir / 'tools-schema.json').write_bytes(raw)
                    report['tools_schema_sha256'] = hashlib.sha256(raw).hexdigest()
                    if len(tools) != 130 or len({tool.name for tool in tools}) != 130:
                        raise ValueError('formal tools/list must contain 130 unique tools')
                    yield session
    finally:
        report['mcp_session']['closed_at'] = utc_now()
        (run_dir / 'http-headers.json').write_bytes(canonical_bytes(capture.responses))
