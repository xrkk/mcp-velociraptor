"""Read-only predicates for original host snapshot command transcripts.

Paths in the transcript identify the controlled host, not files to open on
the verifier's machine. This deliberately also works in Windows verification.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any


class SnapshotRawError(ValueError):
    pass


COMMAND_KEYS = {
    'schema_version', 'kind', 'workflow_id', 'operation_id', 'observation',
    'vmx', 'request', 'started_at', 'ended_at', 'exit_status', 'response',
}
RESPONSE_KEYS = {
    'stdout', 'stdout_size', 'stdout_sha256',
    'stderr', 'stderr_size', 'stderr_sha256',
}


def utc(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith('Z'):
        raise SnapshotRawError('command timestamp must be an explicit UTC instant')
    try:
        parsed = datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError as exc:
        raise SnapshotRawError('invalid command timestamp') from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise SnapshotRawError('command timestamp is not UTC')
    return parsed


def host_vmx(value: Any) -> PurePosixPath:
    if (
        not isinstance(value, str) or not value.startswith('/')
        or '\\' in value or any(part in {'.', '..', ''} for part in value[1:].split('/'))
        or PurePosixPath(value).name != 'Win10MalBox-Velo.vmx'
    ):
        raise SnapshotRawError('host VMX identity is not a canonical absolute path')
    return PurePosixPath(value)


def command(
    value: Any, *, workflow_id: str, operation_id: str,
    observation: str, vmx: str, expected_argv: list[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != COMMAND_KEYS:
        raise SnapshotRawError('snapshot command transcript keys differ')
    if (
        value['schema_version'] != 1 or value['kind'] != 'p05-snapshot-command-v1'
        or value['workflow_id'] != workflow_id or value['operation_id'] != operation_id
        or value['observation'] != observation or value['vmx'] != vmx
    ):
        raise SnapshotRawError('snapshot command transcript identity differs')
    host_vmx(vmx)
    request = value['request']
    if (
        not isinstance(request, dict) or set(request) != {'argv', 'command_line'}
        or not isinstance(request['argv'], list) or not request['argv']
        or any(not isinstance(item, str) or not item for item in request['argv'])
        or not isinstance(request['command_line'], str) or not request['command_line']
        or (expected_argv is not None and request['argv'] != expected_argv)
    ):
        raise SnapshotRawError('snapshot command request differs')
    if utc(value['ended_at']) < utc(value['started_at']):
        raise SnapshotRawError('snapshot command time order differs')
    status = value['exit_status']
    if not isinstance(status, dict) or set(status) != {'code'} or type(status['code']) is not int or status['code'] != 0:
        raise SnapshotRawError('snapshot command did not exit successfully')
    response = value['response']
    if not isinstance(response, dict) or set(response) != RESPONSE_KEYS:
        raise SnapshotRawError('snapshot command lacks complete stdout/stderr')
    for stream in ('stdout', 'stderr'):
        text = response[stream]
        if not isinstance(text, str):
            raise SnapshotRawError('snapshot response stream is not text')
        raw = text.encode('utf-8')
        if (
            type(response[stream + '_size']) is not int
            or response[stream + '_size'] != len(raw)
            or response[stream + '_sha256'] != hashlib.sha256(raw).hexdigest()
        ):
            raise SnapshotRawError('snapshot response stream bytes differ')
    return value


def snapshot_names(stdout: str) -> list[str]:
    lines = stdout.splitlines()
    if not lines or re.fullmatch(r'Total snapshots: [0-9]+', lines[0].strip()) is None:
        raise SnapshotRawError('snapshot tree lacks the actual vmrun total')
    total = int(lines[0].strip().rsplit(' ', 1)[1])
    names = [line.strip() for line in lines[1:] if line.strip()]
    if len(names) != total or len(set(names)) != len(names):
        raise SnapshotRawError('snapshot tree count or unique names differ')
    return names


def vmsd_fields(stdout: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in stdout.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'\s*([\w.]+)\s*=\s*"([^"\r\n]*)"\s*', line)
        if match is None or match[1] in result:
            raise SnapshotRawError('vmsd original is malformed or duplicates a key')
        result[match[1]] = match[2]
    if not result:
        raise SnapshotRawError('vmsd original is empty')
    return result


def snapshot_marker(stdout: str, name: str, *, only_snapshot: bool = False) -> tuple[str, str]:
    fields = vmsd_fields(stdout)
    indices = [key[:-12] for key, value in fields.items() if key.endswith('.displayName') and value == name]
    if len(indices) != 1:
        raise SnapshotRawError('vmsd does not uniquely identify the selected snapshot')
    prefix = indices[0]
    marker = fields.get(prefix + '.filename', '')
    uid = fields.get(prefix + '.uid', '')
    if re.fullmatch(r'Win10MalBox-Velo-Snapshot[0-9]+\.vmsn', marker) is None or not uid.isdigit():
        raise SnapshotRawError('vmsd selected snapshot marker or UID differs')
    if fields.get('snapshot.current') != uid:
        raise SnapshotRawError('vmsd current does not identify the selected snapshot')
    if only_snapshot:
        display_names = [key for key in fields if key.endswith('.displayName')]
        if fields.get('snapshot.numSnapshots') != '1' or len(display_names) != 1:
            raise SnapshotRawError('vmsd contains another snapshot')
    return marker, uid


def guest_adapter(stdout: str) -> None:
    try:
        result = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise SnapshotRawError('guest identity response is not JSON') from exc
    if not isinstance(result, dict) or set(result) != {'computer_name', 'adapters'}:
        raise SnapshotRawError('guest identity response keys differ')
    if result['computer_name'] != 'DESKTOP-3FI41GR' or not isinstance(result['adapters'], list):
        raise SnapshotRawError('guest identity hostname or adapters differ')
    matching = []
    for row in result['adapters']:
        if not isinstance(row, dict) or set(row) != {'MACAddress', 'IPAddress', 'DHCPEnabled', 'IPEnabled'}:
            raise SnapshotRawError('guest adapter response fields differ')
        if not isinstance(row['IPAddress'], list) or any(not isinstance(item, str) for item in row['IPAddress']):
            raise SnapshotRawError('guest adapter IP addresses differ')
        mac = row['MACAddress']
        if not isinstance(mac, str):
            raise SnapshotRawError('guest adapter MAC differs')
        if mac.lower().replace('-', ':') == '00:0c:29:83:b8:65':
            matching.append(row)
        elif '192.168.204.232' in row['IPAddress']:
            raise SnapshotRawError('fixed IP belongs to another adapter')
    if (
        len(matching) != 1 or matching[0]['DHCPEnabled'] is not False
        or matching[0]['IPEnabled'] is not True
        or matching[0]['IPAddress'].count('192.168.204.232') != 1
    ):
        raise SnapshotRawError('guest fixed MAC/IP/DHCP identity differs')
