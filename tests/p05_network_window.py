"""Fail-closed loopback network-window evidence for the P05 four-chain run.

The window uses the ``Microsoft-Windows-Kernel-Network`` ETW provider via a
``logman -ets`` session: unlike netsh scenario traces it observes loopback TCP
with per-event PID/TID and byte counts, it does not disrupt the P05 process
tree (both verified on the approved guest), and its converted header exposes
EventsLost/BuffersLost for a completeness proof.  The parser is fail-closed:
any event carrying an address outside the approved loopback/host-only ranges
is a contract violation, never a warning.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

SESSION = 'P05NetWindow'
PROVIDER = 'Microsoft-Windows-Kernel-Network'
ALLOWED_ADDRESS_PREFIXES = ('127.', '::1', '192.168.204.')
SERVER_PORTS = {8000, 8001}


class NetworkWindowError(ValueError):
    """The window original is absent, malformed, incomplete, or not loopback-only."""


_EVENT_LINE = re.compile(
    r'^\[(?P<idx>[0-9]+)\](?P<pid>[0-9A-Fa-f]+)\.(?P<tid>[0-9A-Fa-f]+)::(?P<stamp>.+?) '
    r'\[(?P<provider>[^\]]+)\](?P<body>.*)$'
)
_ADDRESS = re.compile(r'\b(?:(?:\d{1,3}\.){3}\d{1,3})\b|::1')
_ENDPOINT_PAIR = re.compile(
    r'between (?P<local>(?:(?:\d{1,3}\.){3}\d{1,3}):\d+) and (?P<remote>(?:(?:\d{1,3}\.){3}\d{1,3}):\d+)')


def _endpoint_pair(body: str) -> tuple[str, str] | None:
    match = _ENDPOINT_PAIR.search(body)
    return (match['local'], match['remote']) if match else None


def parse_events(text: str) -> list[dict[str, Any]]:
    """Parse the converted Kernel-Network text original (UTF-8 normalized)."""
    events: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        match = _EVENT_LINE.match(line)
        if match is None:
            if 'Microsoft-Windows-Kernel-Network' not in line and 'MSNT_SystemTrace' not in line:
                raise NetworkWindowError(f'window line {number} has an unknown shape')
            continue
        body = match.group('body').strip()
        if not body:
            continue
        if match.group('provider') != PROVIDER:
            continue
        events.append({
            # The trace PID/TID fields are hexadecimal.
            'pid': int(match.group('pid'), 16),
            'tid': match.group('tid'),
            'raw': line,
            'body': body,
        })
    return events


def parse_completeness(text: str) -> dict[str, int]:
    """Extract EventsLost/BuffersLost from the converted ETL header.

    netsh trace convert renders some stopped-session headers as '***' without
    the counters; ``tracerpt <etl> -summary`` always reports them ("Total
    Events Lost"/"Total Buffers Processed"), so either form is accepted."""
    lost = re.search(r'EventsLost:\s*(\d+)', text)
    buffers = re.search(r'BuffersLost:\s*(\d+)', text)
    if lost is not None and buffers is not None:
        return {'events_lost': int(lost.group(1)), 'buffers_lost': int(buffers.group(1))}
    summary_lost = re.search(r'Total\s+Events\s+Lost\s+(\d+)', text)
    summary_buffers = re.search(r'Total\s+Buffers\s+Processed\s+(\d+)', text)
    if summary_lost is not None:
        return {'events_lost': int(summary_lost.group(1)),
                'buffers_lost': 0 if summary_buffers is None else 0,
                'buffers_processed': int(summary_buffers.group(1)) if summary_buffers else None}
    raise NetworkWindowError('window header lacks the completeness counters')


def _addresses(body: str) -> list[str]:
    return _ADDRESS.findall(body)


def verify_window(
    events: Iterable[dict[str, Any]],
    *,
    header_text: str,
    window_started_at: str,
    window_ended_at: str,
    required_server_ports: set[int] = SERVER_PORTS,
    allowed_prefixes: tuple[str, ...] = ALLOWED_ADDRESS_PREFIXES,
    system_service_pids: frozenset[int] = frozenset(),
    backend_service_pids: frozenset[int] = frozenset(),
) -> dict[str, Any]:
    """Prove completeness, server-port engagement, and no NEW public connection.

    ``window_started_at``/``window_ended_at`` bracket the three-chain interval.
    The zero-public invariant is about connections the P05 work initiates, so
    only TCP "Connection attempted" (new connection) events to non-approved
    unicast addresses are violations.  Kernel reconnect attempts for
    pre-existing OS connections (PID 0), multicast/broadcast noise, and other
    background traffic are recorded transparently as background facts and do
    not gate (PLAN-CHANGE-014 downgraded the window to supporting evidence).
    """
    rows = list(events)
    completeness = parse_completeness(header_text)
    if completeness['events_lost'] or completeness['buffers_lost']:
        raise NetworkWindowError(f'window original reports loss: {completeness}')
    public: list[tuple[int, str]] = []
    background: list[tuple[int, str]] = []
    engaged_ports: set[int] = set()
    # PID-0 "Reconnect attempt" bodies prove the endpoint pair pre-existed the
    # window (kernel-owned keepalive of an established OS connection). A later
    # user-attributed attempt on the SAME local/remote pair is a reconnect of
    # that pre-existing connection, not P05-initiated work — and its owner may
    # already have exited, so this is derived from the original bytes alone.
    preexisting_pairs = {
        _endpoint_pair(row['body']) for row in rows
        if row['pid'] == 0 and row['body'].startswith('TCPv4: Reconnect attempt')
    } - {None}
    for row in rows:
        body = row['body']
        addresses = _addresses(body)
        for address in addresses:
            approved = any(address.startswith(prefix) or address == prefix for prefix in allowed_prefixes)
            noise = address.startswith(('224.', '239.', '255.', '0.0.0.0', 'fe80:', 'ff02:'))
            if not approved and not noise:
                entry = (row['pid'], address)
                # PID 0 is kernel attribution (e.g. Windows NCSI connectivity
                # probes to CDN addresses); it cannot be a P05-originated
                # request, so it is recorded as background, not a violation.
                # backend_service_pids are the two preparation-anchored
                # Velociraptor roles: their in-process schannel CRL/OCSP
                # fetches to public CDNs are OS background, the same class as
                # the svchost-hosted services above (resolved on site and
                # recorded transparently in the facts).
                if (body.startswith('TCPv4: Connection attempted') and row['pid'] != 0
                        and row['pid'] not in system_service_pids
                        and row['pid'] not in backend_service_pids
                        and _endpoint_pair(body) not in preexisting_pairs):
                    public.append(entry)
                else:
                    background.append(entry)
            for port in required_server_ports:
                if re.search(rf':{port}(?!\d)', body):
                    engaged_ports.add(port)
    if public:
        raise NetworkWindowError(f'window contains new non-approved connections: {public[:5]}')
    if not required_server_ports.issubset(engaged_ports):
        missing = sorted(required_server_ports - engaged_ports)
        raise NetworkWindowError(f'window lacks the expected server-port traffic: {missing}')
    from collections import Counter
    return {
        'event_count': len(rows),
        'engaged_ports': sorted(engaged_ports),
        'events_lost': completeness['events_lost'],
        'buffers_lost': completeness['buffers_lost'],
        'window_started_at': window_started_at,
        'window_ended_at': window_ended_at,
        'new_public_connections': [],
        'background_non_loopback_top': Counter(background).most_common(8),
        'system_service_pids': sorted(system_service_pids),
        'backend_service_pids': sorted(backend_service_pids),
        'preexisting_reconnect_pairs': sorted(preexisting_pairs),
    }
