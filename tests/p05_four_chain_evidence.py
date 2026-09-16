"""Fail-closed parsing of the P05 three-chain raw acceptance originals.

PLAN-CHANGE-014 removed the netsh-trace PacketCapture chain (network capture
is the FakeNet-NG domain); the chains are Autoruns, Triage, and KillProcess.
This module consumes carried bundle references.  It never calls PowerShell,
``netsh``, an MCP server, or a Windows API: the Windows collector is
``p05_real_acceptance``.  A caller must separately supply the formal report
and the complete twelve-observation ready record.  The activation entry point
below stays closed until the network-window parser contract is re-adjudicated.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import stat
from typing import Any, Mapping

from tests.p05_ready_evidence import ReadyEvidenceError, verify_ready_raw_evidence


class FourChainEvidenceError(ValueError):
    """A carried three-chain original is absent, altered, or semantically false."""


WORKFLOW_ID = 'wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2'
REF_KEYS = {'path', 'size', 'sha256'}
COMMAND_KEYS = {
    'schema_version', 'kind', 'label', 'round_id', 'command', 'started_at',
    'ended_at', 'exit_code', 'stdout', 'stderr',
}
SDK_ROW_KEYS = {'sequence', 'direction', 'started_at', 'ended_at', 'message'}
REQUIRED_RAW = {
    'kill-pre-processes', 'kill-post-target', 'kill-post-processes',
}


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in '0123456789abcdef' for char in value)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise FourChainEvidenceError(f'{label} must be a non-empty string')
    return value


def _utc(value: Any, label: str) -> datetime:
    text = _text(value, label)
    try:
        instant = datetime.fromisoformat(text.replace('Z', '+00:00'))
    except ValueError as exc:
        raise FourChainEvidenceError(f'{label} is not RFC3339') from exc
    if instant.tzinfo is None or instant.utcoffset() != timedelta(0):
        raise FourChainEvidenceError(f'{label} is not UTC')
    return instant.astimezone(UTC)


def _plain_file(root: Path, relative: Any, label: str) -> Path:
    if (
        not isinstance(relative, str) or not relative or '\\' in relative
        or any(part in {'', '.', '..'} for part in relative.split('/'))
    ):
        raise FourChainEvidenceError(f'{label} is not a contained POSIX path')
    candidate = Path(relative)
    if candidate.is_absolute() or PureWindowsPath(relative).drive or '..' in candidate.parts:
        raise FourChainEvidenceError(f'{label} escapes its evidence root')
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise FourChainEvidenceError(f'{label} root is unavailable') from exc
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode) or getattr(root_info, 'st_file_attributes', 0) & 0x400:
        raise FourChainEvidenceError(f'{label} root is not a plain directory')
    current = root
    try:
        for part in candidate.parts:
            current /= part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise FourChainEvidenceError(f'{label} crosses a link or reparse point')
    except OSError as exc:
        raise FourChainEvidenceError(f'{label} is unavailable') from exc
    if not stat.S_ISREG(current.lstat().st_mode):
        raise FourChainEvidenceError(f'{label} is not a regular file')
    return current


def _resolve_ref(root: Path, value: Any, label: str, seen: dict[str, tuple[int, str]]) -> Path:
    if not isinstance(value, Mapping) or set(value) != REF_KEYS:
        raise FourChainEvidenceError(f'{label} must have exact path/size/sha256 keys')
    path_value = _text(value.get('path'), f'{label}.path')
    if type(value.get('size')) is not int or value['size'] < 0 or not _sha256(value.get('sha256')):
        raise FourChainEvidenceError(f'{label} byte identity is invalid')
    identity = (value['size'], value['sha256'])
    previous = seen.setdefault(path_value, identity)
    if previous != identity:
        raise FourChainEvidenceError(f'{label} repeats a path with a conflicting identity')
    path = _plain_file(root, path_value, label)
    if path.stat().st_size != value['size'] or _digest(path) != value['sha256']:
        raise FourChainEvidenceError(f'{label} bytes differ from its Ref')
    return path


def _json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding='utf-8-sig'))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FourChainEvidenceError(f'{label} is not UTF-8 JSON') from exc
    if not isinstance(value, dict):
        raise FourChainEvidenceError(f'{label} must be a JSON object')
    return value


def _expected_powershell(script: str) -> list[str]:
    return ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script]


def _command(path: Path, expected_label: str) -> tuple[dict[str, Any], datetime, datetime]:
    value = _json(path, expected_label)
    if set(value) != COMMAND_KEYS or value.get('schema_version') != 1 or value.get('kind') != 'p05-command-observation-v1':
        raise FourChainEvidenceError(f'{expected_label} command envelope shape is invalid')
    if value.get('label') != expected_label or not isinstance(value.get('round_id'), str) or not value['round_id']:
        raise FourChainEvidenceError(f'{expected_label} command label or round differs')
    command = value.get('command')
    if not isinstance(command, dict) or set(command) != {'argv'} or not isinstance(command['argv'], list) or not all(isinstance(item, str) and item for item in command['argv']):
        raise FourChainEvidenceError(f'{expected_label} command argv is invalid')
    if type(value.get('exit_code')) is not int or not isinstance(value.get('stdout'), str) or not isinstance(value.get('stderr'), str):
        raise FourChainEvidenceError(f'{expected_label} command result is not a complete raw result')
    started = _utc(value.get('started_at'), f'{expected_label}.started_at')
    ended = _utc(value.get('ended_at'), f'{expected_label}.ended_at')
    if ended < started:
        raise FourChainEvidenceError(f'{expected_label} command ends before it starts')
    return value, started, ended


def _parse_process_rows(raw: str, label: str) -> list[dict[str, Any]]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FourChainEvidenceError(f'{label} stdout is not the original process JSON') from exc
    rows = value if isinstance(value, list) else [value]
    if not rows or any(not isinstance(row, dict) for row in rows):
        raise FourChainEvidenceError(f'{label} has no actual process rows')
    return rows


def _flow_id(call: dict[str, Any], label: str) -> str:
    result = call.get('result')
    if not isinstance(result, dict) or result.get('is_error') is not False or not isinstance(result.get('structured'), dict):
        raise FourChainEvidenceError(f'{label} is not a successful structured MCP call')
    return _text(result['structured'].get('flow_id'), f'{label}.flow_id')


def _call(calls: Mapping[str, Any], label: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    value = calls.get(label)
    expected = {'tool', 'arguments', 'result', 'started_at', 'ended_at', 'mcp_result', 'sdk_request_id'}
    if not isinstance(value, dict) or set(value) != expected:
        raise FourChainEvidenceError(f'{label} call original shape is invalid')
    request_id = value['sdk_request_id']
    if isinstance(request_id, bool) or not isinstance(request_id, (int, str)):
        raise FourChainEvidenceError(f'{label} does not carry its real raw SDK JSON-RPC request id')
    if value.get('tool') != tool or value.get('arguments') != arguments:
        raise FourChainEvidenceError(f'{label} tool or resolved arguments differ')
    result = value['result']
    if not isinstance(result, dict) or set(result) != {'is_error', 'structured'} or type(result['is_error']) is not bool:
        raise FourChainEvidenceError(f'{label} result projection is invalid')
    if not isinstance(value.get('mcp_result'), dict):
        raise FourChainEvidenceError(f'{label} lacks the raw SDK result projection')
    if value['mcp_result'].get('isError') is not result['is_error'] or value['mcp_result'].get('structuredContent') != result['structured']:
        raise FourChainEvidenceError(f'{label} raw SDK result and derived call result differ')
    started = _utc(value['started_at'], f'{label}.started_at')
    ended = _utc(value['ended_at'], f'{label}.ended_at')
    if ended < started:
        raise FourChainEvidenceError(f'{label} call ends before it starts')
    return value


def _require_finished(calls: Mapping[str, Any], states: Mapping[str, Any], flow_id: str, label: str) -> None:
    polls = [
        value for value in calls.values()
        if isinstance(value, dict) and value.get('tool') == 'get_flow_status'
        and value.get('arguments') == {'flow_id': flow_id}
    ]
    if not polls or flow_id not in states or not isinstance(states[flow_id], list):
        raise FourChainEvidenceError(f'{label} lacks raw Flow status polling')
    observed: list[str] = []
    for position, poll in enumerate(polls):
        result = poll.get('result')
        if not isinstance(result, dict) or result.get('is_error') is not False or not isinstance(result.get('structured'), dict):
            raise FourChainEvidenceError(f'{label} poll {position} is unsuccessful')
        state = _text(result['structured'].get('state'), f'{label} poll state')
        observed.append(state)
    if observed != states[flow_id] or observed[-1] != 'FINISHED' or 'ERROR' in observed:
        raise FourChainEvidenceError(f'{label} Flow did not retain an exact successful FINISHED sequence')


def _load_sdk(path: Path) -> tuple[list[dict[str, Any]], dict[Any, tuple[dict[str, Any], dict[str, Any]]]]:
    try:
        lines = path.read_text(encoding='utf-8-sig').splitlines()
    except (OSError, UnicodeError) as exc:
        raise FourChainEvidenceError('SDK capture is not readable UTF-8') from exc
    if not lines:
        raise FourChainEvidenceError('SDK capture is empty')
    rows: list[dict[str, Any]] = []
    requests: dict[Any, dict[str, Any]] = {}
    responses: dict[Any, dict[str, Any]] = {}
    for expected_sequence, line in enumerate(lines, start=1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise FourChainEvidenceError('SDK capture NDJSON has an invalid row') from exc
        if not isinstance(row, dict) or set(row) != SDK_ROW_KEYS or row.get('sequence') != expected_sequence:
            raise FourChainEvidenceError('SDK capture row keys or sequence are invalid')
        if row.get('direction') not in {'client_to_server', 'server_to_client'} or not isinstance(row.get('message'), dict):
            raise FourChainEvidenceError('SDK capture row lacks an actual SessionMessage JSON-RPC object')
        started = _utc(row.get('started_at'), 'SDK capture started_at')
        ended = _utc(row.get('ended_at'), 'SDK capture ended_at')
        if ended < started or row['message'].get('jsonrpc') != '2.0':
            raise FourChainEvidenceError('SDK capture timestamp or JSON-RPC version is invalid')
        message = row['message']
        if row['direction'] == 'client_to_server' and 'method' in message and 'id' in message:
            request_id = message['id']
            if isinstance(request_id, bool) or request_id in requests:
                raise FourChainEvidenceError('SDK request ID is invalid or reused')
            requests[request_id] = row
        if row['direction'] == 'server_to_client' and 'id' in message:
            response_id = message['id']
            if isinstance(response_id, bool) or response_id in responses or 'result' not in message:
                raise FourChainEvidenceError('SDK response ID is invalid, reused, or lacks a raw result')
            responses[response_id] = row
        rows.append(row)
    pairs: dict[Any, tuple[dict[str, Any], dict[str, Any]]] = {}
    for request_id, request in requests.items():
        response = responses.get(request_id)
        if response is None or request['sequence'] >= response['sequence']:
            raise FourChainEvidenceError('SDK request lacks a later matching raw response')
        pairs[request_id] = (request, response)
    return rows, pairs


def _require_sdk_method(pairs: Mapping[Any, tuple[dict[str, Any], dict[str, Any]]], method: str) -> tuple[dict[str, Any], dict[str, Any]]:
    matches = [pair for pair in pairs.values() if pair[0]['message'].get('method') == method]
    if len(matches) != 1:
        raise FourChainEvidenceError(f'SDK capture must retain exactly one {method} request/response pair')
    return matches[0]


def _join_calls_to_sdk(calls: Mapping[str, Any], pairs: Mapping[Any, tuple[dict[str, Any], dict[str, Any]]]) -> None:
    """Join every retained call to its raw SDK exchange by the real JSON-RPC
    id, the request/response time window, and byte-equal response content.
    Repeated identical flow polls have distinct ids and stay unambiguous."""
    used_ids: set[Any] = set()
    for label, call in calls.items():
        if not isinstance(label, str):
            raise FourChainEvidenceError('call label is not a string')
        if not isinstance(call, dict):
            raise FourChainEvidenceError(f'{label} call is not an object')
        request_id = call.get('sdk_request_id')
        if isinstance(request_id, bool) or not isinstance(request_id, (int, str)):
            raise FourChainEvidenceError(f'{label} does not carry its real raw SDK JSON-RPC request id')
        pair = pairs.get(request_id)
        if pair is None:
            raise FourChainEvidenceError(f'{label} SDK request id does not join a captured request/response pair')
        request, response = pair
        message = request['message']
        params = message.get('params')
        if (
            message.get('method') != 'tools/call'
            or not isinstance(params, dict)
            or params.get('name') != call.get('tool')
            or params.get('arguments') != call.get('arguments')
        ):
            raise FourChainEvidenceError(f'{label} raw SDK request does not match its recorded call')
        if response['message'].get('result') != call.get('mcp_result'):
            raise FourChainEvidenceError(f'{label} raw SDK response does not equal its retained mcp_result')
        call_started = _utc(call.get('started_at'), f'{label}.started_at')
        call_ended = _utc(call.get('ended_at'), f'{label}.ended_at')
        if (
            call_started > _utc(request['started_at'], f'{label} SDK request started_at')
            or call_ended < _utc(request['ended_at'], f'{label} SDK request ended_at')
            or call_started > _utc(response['started_at'], f'{label} SDK response started_at')
            or call_ended < _utc(response['ended_at'], f'{label} SDK response ended_at')
        ):
            raise FourChainEvidenceError(f'{label} raw SDK exchange lies outside its recorded call window')
        if request_id in used_ids:
            raise FourChainEvidenceError(f'{label} reuses an already joined raw SDK request id')
        used_ids.add(request_id)
    tool_ids = {
        request_id for request_id, pair in pairs.items()
        if pair[0]['message'].get('method') == 'tools/call'
    }
    if used_ids != tool_ids:
        raise FourChainEvidenceError('raw SDK tools/call messages have been omitted from or added outside calls')


def verify_three_chain_core(
    bundle_root: Path,
    three_chains_ref: Mapping[str, Any],
    ready_ref: Mapping[str, Any],
    report: Mapping[str, Any],
) -> dict[str, Any]:
    """Parse complete three-chain originals and their ready/report joins."""
    if not bundle_root.is_absolute():
        raise FourChainEvidenceError('three-chain bundle root must be absolute')
    seen: dict[str, tuple[int, str]] = {}
    evidence_path = _resolve_ref(bundle_root, three_chains_ref, 'three_chains', seen)
    ready_path = _resolve_ref(bundle_root, ready_ref, 'ready', seen)
    evidence = _json(evidence_path, 'three_chains')
    ready = _json(ready_path, 'ready')
    if (
        evidence.get('schema') != 'p05-real-acceptance-v1'
        or evidence.get('workflow_id') != WORKFLOW_ID
        or not isinstance(evidence.get('attempt_id'), str)
        or not evidence['attempt_id']
        or evidence.get('failure') is not None
        or evidence.get('final_observation_failures')
        or evidence.get('ok') is not True
        or not isinstance(evidence.get('calls'), dict)
        or not isinstance(evidence.get('flow_states'), dict)
        or not isinstance(evidence.get('raw_originals'), dict)
        or not isinstance(evidence.get('raw_observations'), dict)
    ):
        raise FourChainEvidenceError('three-chain evidence is not a successful complete P05 raw record')
    if ready.get('workflow_id') != WORKFLOW_ID or ready.get('restore_attempt_id') != evidence['attempt_id']:
        raise FourChainEvidenceError('ready original does not join the three-chain workflow/attempt')
    if not isinstance(report, Mapping) or report.get('run_id') != ready.get('run_id'):
        raise FourChainEvidenceError('formal report does not join the complete ready original')
    try:
        ready_facts = verify_ready_raw_evidence(ready, bundle_root=bundle_root, report=report)
    except ReadyEvidenceError as exc:
        raise FourChainEvidenceError(f'ready originals are not complete: {exc}') from exc
    started = _utc(evidence.get('started_at'), 'three-chain started_at')
    ended = _utc(evidence.get('ended_at'), 'three-chain ended_at')
    if ended < started:
        raise FourChainEvidenceError('three-chain record ends before it starts')
    evidence_root = evidence_path.parent
    local_seen: dict[str, tuple[int, str]] = {}
    raw_originals = evidence['raw_originals']
    if set(raw_originals) != {'sdk_messages', 'stderr'}:
        raise FourChainEvidenceError('three-chain raw originals must retain both SDK messages and stderr')
    sdk_path = _resolve_ref(evidence_root, raw_originals['sdk_messages'], 'sdk_messages', local_seen)
    _resolve_ref(evidence_root, raw_originals['stderr'], 'bridge stderr', local_seen)
    observations = evidence['raw_observations']
    if set(observations) != REQUIRED_RAW:
        raise FourChainEvidenceError('three-chain raw command set is incomplete or contains an unexpected summary')
    commands: dict[str, tuple[dict[str, Any], datetime, datetime]] = {}
    for label in REQUIRED_RAW:
        path = _resolve_ref(evidence_root, observations[label], f'raw observation {label}', local_seen)
        commands[label] = _command(path, label)
    for label, (document, command_started, command_ended) in commands.items():
        if not (started <= command_started <= command_ended <= ended):
            raise FourChainEvidenceError(f'{label} is outside the three-chain UTC interval')
        if document['exit_code'] != 0:
            raise FourChainEvidenceError(f'{label} fixed observation command failed')
    calls = evidence['calls']
    states = evidence['flow_states']
    # Autoruns chain
    autoruns = _call(calls, 'autoruns', 'Windows.Sysinternals.Autoruns', {})
    autoruns_id = _flow_id(autoruns, 'autoruns')
    _require_finished(calls, states, autoruns_id, 'autoruns')
    autoruns_rows = _call(calls, 'autoruns-results', 'get_flow_results', {'flow_id': autoruns_id, 'page_size': 10})
    data = autoruns_rows['result']['structured'].get('data') if isinstance(autoruns_rows['result']['structured'], dict) else None
    if not isinstance(data, list) or not any(isinstance(row, dict) and row for row in data):
        raise FourChainEvidenceError('Autoruns lacks an actual result source row')
    # Triage chain
    triage = _call(calls, 'triage', 'collect_forensic_triage', {})
    triage_id = _flow_id(triage, 'triage')
    _require_finished(calls, states, triage_id, 'triage')
    triage_results = _call(calls, 'triage-results', 'get_flow_results', {'flow_id': triage_id, 'page_size': 10})
    triage_files = _call(calls, 'triage-files', 'list_flow_files', {'flow_id': triage_id})
    for label, call in {'triage-results': triage_results, 'triage-files': triage_files}.items():
        structured = call['result']['structured']
        if not isinstance(structured, dict) or not isinstance(structured.get('data'), list):
            raise FourChainEvidenceError(f'{label} lacks an actual raw data list')
    # Kill chain
    raw_kill = calls.get('kill-process')
    if not isinstance(raw_kill, dict) or not isinstance(raw_kill.get('arguments'), dict):
        raise FourChainEvidenceError('KillProcess call lacks an actual arguments object')
    killed = _call(calls, 'kill-process', 'kill_process', {'pid': raw_kill['arguments'].get('pid')})
    target_pid = killed['arguments']['pid']
    if type(target_pid) is not int or target_pid <= 4:
        raise FourChainEvidenceError('KillProcess target PID is invalid')
    kill_id = _flow_id(killed, 'kill-process')
    _require_finished(calls, states, kill_id, 'kill-process')
    kill_rows = _call(calls, 'kill-results', 'get_flow_results', {'flow_id': kill_id, 'page_size': 10})
    kill_data = kill_rows['result']['structured'].get('data') if isinstance(kill_rows['result']['structured'], dict) else None
    if not isinstance(kill_data, list) or not any(
        isinstance(row, dict) and row.get('Pid') == target_pid and row.get('Killed') == target_pid for row in kill_data
    ):
        raise FourChainEvidenceError('KillProcess raw result does not retain exact Pid/Killed identity')
    pre_process, _, _ = commands['kill-pre-processes']
    post_target, _, _ = commands['kill-post-target']
    post_process, _, _ = commands['kill-post-processes']
    from tests.p05_real_acceptance import PS_PROCESS_IDENTITY, PS_PROCESS_SNAPSHOT
    if pre_process['command']['argv'] != _expected_powershell(PS_PROCESS_SNAPSHOT % target_pid):
        raise FourChainEvidenceError('kill pre-process observation is not the fixed target-inclusive process snapshot')
    if post_target['command']['argv'] != _expected_powershell(PS_PROCESS_IDENTITY % target_pid):
        raise FourChainEvidenceError('kill post-target observation is not the fixed PID identity query')
    if post_process['command']['argv'] != _expected_powershell(PS_PROCESS_SNAPSHOT % -1):
        raise FourChainEvidenceError('kill post-process observation is not the fixed protected-process snapshot')
    pre_rows = _parse_process_rows(pre_process['stdout'], 'kill pre-processes')
    target_rows = [row for row in pre_rows if row.get('ProcessId') == target_pid]
    if len(target_rows) != 1 or target_rows[0].get('CreationDate') != ready_facts['fixture_creation_time_utc']:
        raise FourChainEvidenceError('kill pre-process original does not join the ready fixture PID/start identity')
    if post_target['stdout'].strip() != 'null' or any(row.get('ProcessId') == target_pid for row in _parse_process_rows(post_process['stdout'], 'kill post-processes')):
        raise FourChainEvidenceError('KillProcess target absence is not proven by both post-call raw process originals')
    if not (pre_process['round_id'] == 'kill-pre'):
        raise FourChainEvidenceError('KillProcess pre originals are not one round')
    if not (post_target['round_id'] == post_process['round_id'] == 'kill-post'):
        raise FourChainEvidenceError('KillProcess post originals are not one round')
    post_rows = _parse_process_rows(post_process['stdout'], 'kill post-processes')
    pre_by_pid = {row.get('ProcessId'): row for row in pre_rows if type(row.get('ProcessId')) is int}
    post_by_pid = {row.get('ProcessId'): row for row in post_rows if type(row.get('ProcessId')) is int}
    protected_pids = {0, 4, target_rows[0].get('ParentProcessId')}
    protected_pids.update(row.get('ProcessId') for row in pre_rows if str(row.get('Name', '')).lower().startswith('velociraptor'))
    # The kill target is itself an approved-argv process in the ready facts;
    # ready's own semantics exclude it from the protected set, and the chain
    # join must apply the same exclusion or every genuine ready join fails.
    protected_pids.update(
        pid for pid in ready_facts.get('approved_guest_argv_pids', [])
        if pid != target_pid
    )
    protected_pids.update(
        pre_by_pid[pid].get('ParentProcessId') for pid in list(protected_pids)
        if pid in pre_by_pid
    )
    if target_pid in protected_pids or any(type(pid) is not int or pid not in pre_by_pid for pid in protected_pids):
        raise FourChainEvidenceError('KillProcess pre original lacks the complete protected PID set')
    if any(
        pid not in post_by_pid or post_by_pid[pid].get('CreationDate') != pre_by_pid[pid].get('CreationDate')
        for pid in protected_pids
    ):
        raise FourChainEvidenceError('KillProcess protected PID/start identities changed after the call')
    if not isinstance(evidence.get('owned_flows'), list) or evidence['owned_flows'] != [autoruns_id, triage_id, kill_id]:
        raise FourChainEvidenceError('owned Flow originals do not retain the three actual chain flows in order')
    if evidence.get('unsettled_owned_flows') != [] or evidence.get('active_flow_count_at_exit') != 0:
        raise FourChainEvidenceError('three-chain record retains active owned resources')
    _, pairs = _load_sdk(sdk_path)
    initialize = _require_sdk_method(pairs, 'initialize')
    tools_list = _require_sdk_method(pairs, 'tools/list')
    listed = tools_list[1]['message'].get('result')
    if not isinstance(listed, dict) or not isinstance(listed.get('tools'), list) or len(listed['tools']) != 130:
        raise FourChainEvidenceError('raw SDK tools/list result does not contain the registered 130 tools')
    if initialize[0]['sequence'] >= tools_list[0]['sequence']:
        raise FourChainEvidenceError('raw SDK tools/list preceded initialize')
    _join_calls_to_sdk(calls, pairs)
    return {
        'attempt_id': evidence['attempt_id'],
        'flow_ids': [autoruns_id, triage_id, kill_id],
        'fixture_pid': target_pid,
        'ready': ready_facts,
    }


def verify_three_chain_evidence(
    bundle_root: Path,
    three_chains_ref: Mapping[str, Any],
    ready_ref: Mapping[str, Any],
    report: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify local chains, then deliberately hold activation for network evidence."""
    verify_three_chain_core(bundle_root, three_chains_ref, ready_ref, report)
    raise FourChainEvidenceError(
        'full host/server/client network-window raw parser is not implemented; activation remains blocked'
    )
