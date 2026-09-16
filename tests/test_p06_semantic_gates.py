"""Synthetic semantic-gate contracts for P05/P06 activation evidence.

Every fixture here is a synthetic/seam input: a green gate result proves the
parser's predicates, never that a Windows collection, restore, or activation
actually ran.  The fixtures reuse the P05 raw-parser test builders so the
gates are exercised against the same shapes the collectors emit.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import tests.test_p05_ready_evidence as ready_tests
from tests import p06_evidence as evidence
from tests.test_p06_evidence_schema5 import RESTORE_VMX, restore_action_envelopes

REPO_ROOT = Path(__file__).resolve().parents[1]
VMX = RESTORE_VMX
READY_CASE_NAME = (
    'test_valid_synthetic_transcripts_validate_without_claiming_windows_execution'
)


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')
    )


def _ref(root: Path, path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    return {
        'path': path.relative_to(root).as_posix(),
        'size': len(payload),
        'sha256': _sha256_bytes(payload),
    }


def _streams(stdout: str, stderr: str = '') -> dict[str, object]:
    return {
        'stdout': stdout,
        'stdout_size': len(stdout.encode('utf-8')),
        'stdout_sha256': _sha256_bytes(stdout.encode('utf-8')),
        'stderr': stderr,
        'stderr_size': len(stderr.encode('utf-8')),
        'stderr_sha256': _sha256_bytes(stderr.encode('utf-8')),
    }


class ReadyGateFixture:
    """A complete synthetic ready package (reuses the P05 parser fixtures)."""

    stage = 'P05_REPAIR_CANDIDATE'
    snapshot = evidence.SNAPSHOT_188
    marker = 'Win10MalBox-Velo-Snapshot341.vmsn'

    def __init__(self, root: Path, run_id: str = 'run-ready-gate', attempt: str = 'restore-ready-gate',
                 ref_root: Path | None = None) -> None:
        self.root = root
        self.ref_root = ref_root or root
        self.run_id = run_id
        self.attempt = attempt
        case = ready_tests.ReadyRawEvidenceTests(READY_CASE_NAME)
        with (
            patch.object(ready_tests, 'RUN_ID', run_id),
            patch.object(ready_tests, 'RESTORE_ID', attempt),
        ):
            self.ready, self.report = case._valid_inputs(root)
        self.ready.update({
            'run_id': run_id,
            'restore_attempt_id': attempt,
            'snapshot_stage': self.stage,
            'snapshot_name': self.snapshot,
            'checkpoint_marker': self.marker,
        })
        for observation, reference in self.ready['observations'].items():
            self.ready['observations'][observation] = _ref(self.ref_root, root / reference['path'])
        self.ready_path = root / 'ready.json'
        _write_json(self.ready_path, self.ready)
        self.report_path = root / 'report.json'
        _write_json(self.report_path, self.report)
        self.phase = {
            'run_id': run_id,
            'restore_attempt_id': attempt,
            'ready': _ref(self.ref_root, self.ready_path),
            'report': _ref(self.ref_root, self.report_path),
        }

    def expected_restore(self) -> dict[str, object]:
        return {
            'snapshot_stage': self.stage,
            'snapshot_name': self.snapshot,
            'checkpoint_marker': self.marker,
        }

    def rewrite_observation(self, name: str, payload: object) -> None:
        path = self.root / 'raw' / f'{name}.json'
        _write_json(path, payload)
        self.ready['observations'][name] = _ref(self.ref_root, path)
        _write_json(self.ready_path, self.ready)
        self.phase['ready'] = _ref(self.ref_root, self.ready_path)


class ReadyGateTests(unittest.TestCase):
    def test_accepts_a_valid_ready_package_joined_to_its_phase_restore(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReadyGateFixture(Path(directory))
            evidence._verify_ready(
                fixture.root, fixture.phase, {}, expected_restore=fixture.expected_restore()
            )

    def test_rejects_stage_name_or_marker_drift_against_the_verified_restore(self) -> None:
        for field in ('snapshot_stage', 'snapshot_name', 'checkpoint_marker'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                fixture = ReadyGateFixture(Path(directory))
                expected = fixture.expected_restore()
                expected[field] = 'WRONG'
                with self.assertRaisesRegex(
                    evidence.EvidenceError, f'ready {field} differs from the verified phase restore'
                ):
                    evidence._verify_ready(fixture.root, fixture.phase, {}, expected_restore=expected)

    def test_rejects_hash_correct_non_original_observation_ref(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReadyGateFixture(Path(directory))
            fixture.rewrite_observation(
                'guest_identity', {'NOT_AN_ORIGINAL': True, 'status': 'failed'}
            )
            with self.assertRaisesRegex(evidence.EvidenceError, 'ready raw evidence is invalid'):
                evidence._verify_ready(
                    fixture.root, fixture.phase, {}, expected_restore=fixture.expected_restore()
                )

    def test_rejects_one_transcript_standing_in_for_two_observations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReadyGateFixture(Path(directory))
            fixture.ready['observations']['host_processes'] = dict(
                fixture.ready['observations']['host_clock']
            )
            _write_json(fixture.ready_path, fixture.ready)
            fixture.phase['ready'] = _ref(fixture.root, fixture.ready_path)
            with self.assertRaisesRegex(evidence.EvidenceError, 'ready raw evidence is invalid'):
                evidence._verify_ready(
                    fixture.root, fixture.phase, {}, expected_restore=fixture.expected_restore()
                )

    def test_rejects_missing_report_join_or_phase_identity_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReadyGateFixture(Path(directory))
            del fixture.phase['report']
            with self.assertRaisesRegex(evidence.EvidenceError, 'phase report Ref join'):
                evidence._verify_ready(fixture.root, fixture.phase, {})
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReadyGateFixture(Path(directory))
            fixture.phase['run_id'] = 'another-run'
            with self.assertRaisesRegex(evidence.EvidenceError, 'ready shape or phase identity'):
                evidence._verify_ready(fixture.root, fixture.phase, {})


class DependencyGateFixture(ReadyGateFixture):
    """Ready package plus three-chain, inventory, and window originals."""

    def __init__(self, root: Path, run_id: str = 'run-ready-gate', attempt: str = 'restore-ready-gate',
                 ref_root: Path | None = None) -> None:
        super().__init__(root, run_id=run_id, attempt=attempt, ref_root=ref_root)
        self.chain_dir = root / 'chain'
        self._write_chain()
        self.window_path = root / 'network' / 'network-window.txt'
        self._write_window()
        self.document = {
            'schema_version': 1,
            'workflow_id': evidence.WORKFLOW_ID,
            'run_id': run_id,
            'restore_attempt_id': attempt,
            'inventory_artifacts': _ref(self.ref_root, root / 'raw' / 'dependencies.json'),
            'four_chains': _ref(self.ref_root, self.chain_dir / 'p05-real-acceptance.json'),
            'network_observations': _ref(self.ref_root, self.window_path),
        }
        self.path = root / 'dependency-acceptance.json'
        _write_json(self.path, self.document)
        self.phase['dependency_acceptance'] = _ref(self.ref_root, self.path)

    def _write_chain(self) -> None:
        from tests import p05_four_chain_evidence as three
        from tests import p05_real_acceptance as acceptance

        guest = json.loads(json.loads(
            (self.root / 'raw' / 'guest_processes.json').read_text(encoding='utf-8')
        )['response']['stdout'])
        rows = guest['processes']
        calls: dict[str, dict] = {}
        sdk: list[dict] = []
        next_id = [3]

        def pair(request_id: int, method: str, params: dict, result: dict) -> None:
            sequence = len(sdk) + 1
            sdk.append({
                'sequence': sequence, 'direction': 'client_to_server',
                'started_at': '2026-09-13T12:00:10Z', 'ended_at': '2026-09-13T12:00:10Z',
                'message': {'jsonrpc': '2.0', 'id': request_id, 'method': method, 'params': params},
            })
            sdk.append({
                'sequence': sequence + 1, 'direction': 'server_to_client',
                'started_at': '2026-09-13T12:00:11Z', 'ended_at': '2026-09-13T12:00:11Z',
                'message': {'jsonrpc': '2.0', 'id': request_id, 'result': result},
            })

        pair(1, 'initialize', {}, {'protocolVersion': '2025-03-26'})
        pair(2, 'tools/list', {}, {'tools': [{} for _ in range(130)]})

        def call(label: str, tool: str, arguments: dict, structured: dict) -> None:
            result = {'isError': False, 'structuredContent': structured}
            request_id = next_id[0]
            next_id[0] += 1
            pair(request_id, 'tools/call', {'name': tool, 'arguments': arguments}, result)
            calls[label] = {
                'tool': tool, 'arguments': arguments,
                'result': {'is_error': False, 'structured': structured},
                'started_at': '2026-09-13T12:00:10Z', 'ended_at': '2026-09-13T12:00:11Z',
                'mcp_result': result, 'sdk_request_id': request_id,
            }

        flow_states: dict[str, list[str]] = {}

        def flow(prefix: str, flow_id: str) -> None:
            index = len(flow_states.get(flow_id, []))
            call(f'{prefix}-poll-{index:03d}', 'get_flow_status', {'flow_id': flow_id}, {'state': 'FINISHED'})
            flow_states.setdefault(flow_id, []).append('FINISHED')

        call('autoruns', 'Windows.Sysinternals.Autoruns', {}, {'flow_id': 'F-auto'})
        flow('autoruns', 'F-auto')
        call('autoruns-results', 'get_flow_results', {'flow_id': 'F-auto', 'page_size': 10},
             {'data': [{'Source': 'Autoruns'}]})
        call('triage', 'collect_forensic_triage', {}, {'flow_id': 'F-triage'})
        flow('triage', 'F-triage')
        call('triage-results', 'get_flow_results', {'flow_id': 'F-triage', 'page_size': 10},
             {'data': [{'Source': 'Triage'}]})
        call('triage-files', 'list_flow_files', {'flow_id': 'F-triage'}, {'data': []})
        call('kill-process', 'kill_process', {'pid': 600}, {'flow_id': 'F-kill'})
        flow('kill', 'F-kill')
        call('kill-results', 'get_flow_results', {'flow_id': 'F-kill', 'page_size': 10},
             {'data': [{'Pid': 600, 'Killed': 600}]})

        def command(label: str, round_id: str, argv: list[str], stdout: str) -> dict:
            return {
                'schema_version': 1, 'kind': 'p05-command-observation-v1', 'label': label,
                'round_id': round_id, 'command': {'argv': argv},
                'started_at': '2026-09-13T12:00:30Z', 'ended_at': '2026-09-13T12:00:31Z',
                'exit_code': 0, 'stdout': stdout, 'stderr': '',
            }

        raw_observations = {}
        for label, (round_id, argv, stdout) in {
            'kill-pre-processes': ('kill-pre', three._expected_powershell(
                acceptance.PS_PROCESS_SNAPSHOT % 600), json.dumps(rows)),
            'kill-post-target': ('kill-post', three._expected_powershell(
                acceptance.PS_PROCESS_IDENTITY % 600), 'null'),
            'kill-post-processes': ('kill-post', three._expected_powershell(
                acceptance.PS_PROCESS_SNAPSHOT % -1), json.dumps(
                [row for row in rows if row['ProcessId'] != 600])),
        }.items():
            path = self.chain_dir / 'raw' / f'{label}.json'
            _write_json(path, command(label, round_id, argv, stdout))
            raw_observations[label] = _ref(self.chain_dir, path)
        sdk_path = self.chain_dir / 'sdk-messages.ndjson'
        sdk_path.write_text(
            '\n'.join(json.dumps(row, sort_keys=True, separators=(',', ':')) for row in sdk) + '\n',
            encoding='utf-8')
        stderr_path = self.chain_dir / 'bridge-stderr.log'
        stderr_path.write_text('', encoding='utf-8')
        self.chain = {
            'schema': 'p05-real-acceptance-v1',
            'workflow_id': evidence.WORKFLOW_ID,
            'attempt_id': self.attempt,
            'started_at': '2026-09-13T12:00:00Z',
            'ended_at': '2026-09-13T12:01:00Z',
            'ok': True,
            'calls': calls,
            'flow_states': dict(flow_states),
            'owned_flows': ['F-auto', 'F-triage', 'F-kill'],
            'unsettled_owned_flows': [],
            'final_observation_failures': [],
            'active_flow_count_at_exit': 0,
            'raw_originals': {
                'sdk_messages': _ref(self.chain_dir, sdk_path),
                'stderr': _ref(self.chain_dir, stderr_path),
            },
            'raw_observations': raw_observations,
        }
        _write_json(self.chain_dir / 'p05-real-acceptance.json', self.chain)

    def _write_window(self, *, events_lost: int = 0) -> None:
        # The converted trace keeps completeness counters inside the tolerated
        # MSNT_SystemTrace header line, exactly like the collected original.
        header = (
            '[0]0000.0000::2026-09-13T12:00:29.000Z '
            f'[MSNT_SystemTrace]EventsLost: {events_lost} BuffersLost: 0\n'
        )
        events = (
            '[0]000003E8.00000123::2026-09-13T12:00:30.000Z '
            '[Microsoft-Windows-Kernel-Network]TCPv4: Connection attempted '
            'between 127.0.0.1:5000 and 127.0.0.1:8000\n'
            '[1]000007D0.00000456::2026-09-13T12:00:31.000Z '
            '[Microsoft-Windows-Kernel-Network]TCPv4: Connection attempted '
            'between 127.0.0.1:5001 and 127.0.0.1:8001\n'
        )
        self.window_path.parent.mkdir(parents=True, exist_ok=True)
        self.window_path.write_text(header + events, encoding='utf-8')


class DependencyGateTests(unittest.TestCase):
    def test_accepts_complete_dependency_originals(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = DependencyGateFixture(Path(directory))
            evidence._verify_dependency_acceptance(fixture.root, fixture.phase, {})

    def test_rejects_hash_correct_non_original_four_chains_or_window(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = DependencyGateFixture(Path(directory))
            bad = fixture.root / 'bad.json'
            _write_json(bad, {'NOT_AN_ORIGINAL': True, 'status': 'failed'})
            fixture.document['four_chains'] = _ref(fixture.root, bad)
            _write_json(fixture.path, fixture.document)
            fixture.phase['dependency_acceptance'] = _ref(fixture.root, fixture.path)
            with self.assertRaisesRegex(evidence.EvidenceError, 'four-chain originals are invalid'):
                evidence._verify_dependency_acceptance(fixture.root, fixture.phase, {})
        with tempfile.TemporaryDirectory() as directory:
            fixture = DependencyGateFixture(Path(directory))
            bad = fixture.root / 'bad.json'
            _write_json(bad, {'NOT_AN_ORIGINAL': True, 'status': 'failed'})
            fixture.document['network_observations'] = _ref(fixture.root, bad)
            _write_json(fixture.path, fixture.document)
            fixture.phase['dependency_acceptance'] = _ref(fixture.root, fixture.path)
            with self.assertRaisesRegex(evidence.EvidenceError, 'network window original is invalid'):
                evidence._verify_dependency_acceptance(fixture.root, fixture.phase, {})

    def test_rejects_lossy_window_and_cross_attempt_chain_and_missing_joins(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = DependencyGateFixture(Path(directory))
            fixture._write_window(events_lost=3)
            fixture.document['network_observations'] = _ref(fixture.root, fixture.window_path)
            _write_json(fixture.path, fixture.document)
            fixture.phase['dependency_acceptance'] = _ref(fixture.root, fixture.path)
            with self.assertRaisesRegex(evidence.EvidenceError, 'network window original is invalid'):
                evidence._verify_dependency_acceptance(fixture.root, fixture.phase, {})
        with tempfile.TemporaryDirectory() as directory:
            fixture = DependencyGateFixture(Path(directory))
            fixture.chain['attempt_id'] = 'other-attempt'
            _write_json(fixture.chain_dir / 'p05-real-acceptance.json', fixture.chain)
            with self.assertRaisesRegex(evidence.EvidenceError, 'four-chain originals are invalid'):
                evidence._verify_dependency_acceptance(fixture.root, fixture.phase, {})
        with tempfile.TemporaryDirectory() as directory:
            fixture = DependencyGateFixture(Path(directory))
            del fixture.phase['ready']
            with self.assertRaisesRegex(evidence.EvidenceError, 'ready and report Ref joins'):
                evidence._verify_dependency_acceptance(fixture.root, fixture.phase, {})


class EntryGateFixture:
    run_id = 'run-entry-gate'
    attempt = 'restore-entry-gate'
    instance = 'synthetic-instance-01'

    def __init__(self, root: Path, ref_root: Path | None = None) -> None:
        self.root = root
        self.ref_root = ref_root or root
        self.cases: dict[str, Path] = {}
        for name in (
            'no_origin', 'allowed_origin', 'missing_bearer', 'wrong_bearer',
            'missing_host', 'wrong_host', 'wrong_origin',
        ):
            path = root / 'entry-gate' / 'cases' / f'{name}.json'
            _write_json(path, self._case(name))
            self.cases[name] = path
        self.document = {
            'schema_version': 1,
            'workflow_id': evidence.WORKFLOW_ID,
            'run_id': self.run_id,
            'restore_attempt_id': self.attempt,
            'cases': {name: _ref(self.ref_root, path) for name, path in self.cases.items()},
        }
        self.path = root / 'entry-gate.json'
        _write_json(self.path, self.document)
        self.phase = {
            'run_id': self.run_id,
            'restore_attempt_id': self.attempt,
            'entry_gate': _ref(self.ref_root, self.path),
        }

    def _counter(self, count: int, moment: str) -> dict[str, object]:
        stdout = json.dumps({'count': count})
        return {
            'schema_version': 1,
            'kind': 'p05-http-handler-counter-v1',
            'workflow_id': evidence.WORKFLOW_ID,
            'run_id': self.run_id,
            'restore_attempt_id': self.attempt,
            'count': count,
            'instance': self.instance,
            'time': moment,
            'command': {
                'argv': ['powershell.exe', '-Command', 'read dispatch counter'],
                'command_line': 'powershell.exe -Command read dispatch counter',
                'exit_status': {'code': 0},
            },
            'output': _streams(stdout),
        }

    def _case(self, name: str, *, status: int | None = None, delta: int | None = None) -> dict[str, object]:
        from tests.p05_http_evidence import GUEST_HOST, MCP_PATH, SERVICE_PORT

        success = name in {'no_origin', 'allowed_origin'}
        status = 200 if success else (
            status if status is not None
            else 401 if name in {'missing_bearer', 'wrong_bearer'}
            else 400 if name == 'missing_host'
            else 421 if name == 'wrong_host'
            else 403
        )
        delta = (1 if success else 0) if delta is None else delta
        payload = {
            'jsonrpc': '2.0', 'id': f'entry-gate:{name}', 'method': 'initialize',
            'params': {
                'protocolVersion': '2025-06-18', 'capabilities': {},
                'clientInfo': {'name': 'p05-http-evidence', 'version': '1'},
            },
        }
        body = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        headers = [
            {'name': 'content-type', 'value': 'application/json'},
            {'name': 'accept', 'value': 'application/json, text/event-stream'},
            {'name': 'content-length', 'value': str(len(body.encode('utf-8')))},
        ]
        if name != 'missing_host':
            headers.append({'name': 'host', 'value': (
                'rebind.example' if name == 'wrong_host' else f'{GUEST_HOST}:{SERVICE_PORT}'
            )})
        if name == 'allowed_origin':
            headers.append({'name': 'origin', 'value': evidence.ENTRY_ALLOWED_ORIGIN})
        elif name == 'wrong_origin':
            headers.append({'name': 'origin', 'value': 'https://not-allowed.example'})
        result = {
            'protocolVersion': '2025-06-18', 'capabilities': {},
            'serverInfo': {'name': 'velociraptor-mcp', 'version': ''},
        }
        response_headers = [{'name': 'content-type', 'value': 'text/event-stream'}]
        if success:
            response_headers.extend([
                {'name': 'mcp-session-id', 'value': 'synthetic-session'},
                {'name': 'x-mcp-server-instance', 'value': self.instance},
            ])
            response_body = (
                'event: message\r\ndata: ' + json.dumps(
                    {'jsonrpc': '2.0', 'id': f'entry-gate:{name}', 'result': result},
                    sort_keys=True, separators=(',', ':'),
                ) + '\r\n\r\n'
            )
        else:
            response_body = '{}'
        return {
            'schema_version': 1,
            'kind': 'p05-entry-gate-case-v1',
            'workflow_id': evidence.WORKFLOW_ID,
            'run_id': self.run_id,
            'restore_attempt_id': self.attempt,
            'case': name,
            'request': {
                'method': 'POST', 'target': MCP_PATH, 'http_version': 'HTTP/1.1',
                'headers': headers,
                'authorization_configured': name != 'missing_bearer',
                'body': {
                    'encoding': 'utf-8', 'text': body,
                    'size': len(body.encode('utf-8')),
                    'sha256': _sha256_bytes(body.encode('utf-8')),
                },
                'first_utc': '2026-09-13T12:00:00.100Z',
                'last_utc': '2026-09-13T12:00:00.200Z',
            },
            'response': {
                'status': status, 'reason': 'x', 'headers': response_headers,
                'body': {
                    'encoding': 'utf-8', 'text': response_body,
                    'size': len(response_body.encode('utf-8')),
                    'sha256': _sha256_bytes(response_body.encode('utf-8')),
                },
            },
            'counter_before': self._counter(0 if delta >= 0 else 5, '2026-09-13T12:00:00.050Z'),
            'counter_after': self._counter(delta if delta >= 0 else 5, '2026-09-13T12:00:00.300Z'),
        }

    def rewrite_case(self, name: str, document: dict[str, object]) -> None:
        _write_json(self.cases[name], document)
        self.document['cases'][name] = _ref(self.ref_root, self.cases[name])
        _write_json(self.path, self.document)
        self.phase['entry_gate'] = _ref(self.ref_root, self.path)


class EntryGateTests(unittest.TestCase):
    def test_accepts_a_complete_seven_case_raw_entry_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EntryGateFixture(Path(directory))
            evidence._verify_entry_gate(fixture.root, fixture.phase, {})

    def test_rejects_wrong_bearer_accepted_or_handler_entered_on_a_negative(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EntryGateFixture(Path(directory))
            accepted = fixture._case('wrong_bearer', status=200, delta=1)
            fixture.rewrite_case('wrong_bearer', accepted)
            with self.assertRaisesRegex(evidence.EvidenceError, 'entry-gate originals are invalid'):
                evidence._verify_entry_gate(fixture.root, fixture.phase, {})
        with tempfile.TemporaryDirectory() as directory:
            fixture = EntryGateFixture(Path(directory))
            entered = fixture._case('missing_bearer', delta=1)
            fixture.rewrite_case('missing_bearer', entered)
            with self.assertRaisesRegex(evidence.EvidenceError, 'entry-gate originals are invalid'):
                evidence._verify_entry_gate(fixture.root, fixture.phase, {})

    def test_rejects_hash_correct_non_original_case_and_missing_case(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EntryGateFixture(Path(directory))
            fixture.rewrite_case('no_origin', {'NOT_AN_ORIGINAL': True, 'status': 'failed'})
            with self.assertRaisesRegex(evidence.EvidenceError, 'entry-gate originals are invalid'):
                evidence._verify_entry_gate(fixture.root, fixture.phase, {})
        with tempfile.TemporaryDirectory() as directory:
            fixture = EntryGateFixture(Path(directory))
            del fixture.document['cases']['wrong_origin']
            _write_json(fixture.path, fixture.document)
            fixture.phase['entry_gate'] = _ref(fixture.root, fixture.path)
            with self.assertRaisesRegex(evidence.EvidenceError, 'shape or phase identity'):
                evidence._verify_entry_gate(fixture.root, fixture.phase, {})

    def test_rejects_success_without_session_or_instance_header(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EntryGateFixture(Path(directory))
            document = fixture._case('allowed_origin')
            document['response']['headers'] = [
                header for header in document['response']['headers']
                if header['name'] != 'mcp-session-id'
            ]
            fixture.rewrite_case('allowed_origin', document)
            with self.assertRaisesRegex(evidence.EvidenceError, 'entry-gate originals are invalid'):
                evidence._verify_entry_gate(fixture.root, fixture.phase, {})


class NetworkGateFixture:
    """A genuinely valid synthetic network evidence package (B01-B05 shapes).

    Every original here actually satisfies the PC006/schemIdentity predicates:
    a curl bound-source probe with a classified failure, a dual-port control
    with per-port structured results, the unique exact firewall rule, two
    distinct adapter listings joined to the report, and the service
    observation join.  Synthetic/seam: no Windows network was probed.
    """

    run_id = 'run-network-gate'
    attempt = 'restore-network-gate'
    probe_source = '192.168.204.99'
    comparison_port = 28787
    probe_started = '2026-09-13T12:00:40Z'
    probe_ended = '2026-09-13T12:00:41Z'
    server_identity = {
        'computer_name': 'DESKTOP-3FI41GR',
        'service_name': 'mcp-velociraptor',
        'pid': 42,
        'process_start_time_utc': '2026-09-13T23:59:58Z',
        'instance_id': 'synthetic-instance',
        'executable_sha256': 'b' * 64,
    }

    def __init__(self, root: Path, ref_root: Path | None = None) -> None:
        self.root = root
        self.ref_root = ref_root or root
        names = [f'synthetic_tool_{number:03d}' for number in range(130)]
        self.listing = {'tools': [{'name': name, 'inputSchema': {'type': 'object'}} for name in names]}
        self.report = {
            'run_id': self.run_id,
            'server_identity': dict(self.server_identity),
            'started_at': '2026-09-13T12:00:00Z',
            'ended_at': '2026-09-13T12:01:00Z',
            'mcp_session': {'id': 'synthetic-session'},
            'tools_schema_sha256': hashlib.sha256(
                evidence._normalized_tools_bytes(self.listing)
            ).hexdigest(),
        }
        self.report_path = root / 'report.json'
        _write_json(self.report_path, self.report)
        self._write_pc006()
        self._write_schema_identity()
        self._write_service_observation()
        self.document = {
            'schema_version': 1,
            'workflow_id': evidence.WORKFLOW_ID,
            'run_id': self.run_id,
            'restore_attempt_id': self.attempt,
            'non_allowed_source': _ref(self.ref_root, self.pc006_path),
            'schema_identity': _ref(self.ref_root, self.schema_identity_path),
            'service_observation': _ref(self.ref_root, self.observation_path),
        }
        self.path = root / 'network-evidence.json'
        _write_json(self.path, self.document)
        self.phase = {
            'run_id': self.run_id,
            'restore_attempt_id': self.attempt,
            'network_evidence': _ref(self.ref_root, self.path),
            'report': _ref(self.ref_root, self.report_path),
        }

    def _element(self, name: str, envelope: dict[str, object]) -> Path:
        path = self.root / 'pc006' / f'{name}.json'
        _write_json(path, envelope)
        return path

    def _element_envelope(
        self, operation_id: str, observation: str, request: dict[str, object],
        stdout: str, *, exit_code: int,
    ) -> dict[str, object]:
        return {
            'schema_version': 1,
            'kind': evidence.RESTORE_HOST_COMMAND_KIND,
            'workflow_id': evidence.WORKFLOW_ID,
            'run_id': self.run_id,
            'restore_attempt_id': self.attempt,
            'operation_id': operation_id,
            'observation': observation,
            'vmx': VMX,
            'request': request,
            'started_at': self.probe_started,
            'ended_at': self.probe_ended,
            'exit_status': {'code': exit_code},
            'response': _streams(stdout),
        }

    def _write_pc006(self) -> None:
        bound_facts = {
            'schema_version': 1, 'kind': evidence.CONNECT_PROBE_KIND,
            'source': self.probe_source,
            'target': {'host': '192.168.204.232', 'port': 28790, 'path': '/mcp'},
            'outcome': 'unreachable', 'error_class': 'connection-refused',
        }
        bound_argv = ['/usr/bin/curl', '--interface', self.probe_source,
                      'http://192.168.204.232:28790/mcp']
        bound = self._element_envelope(
            'pc006-bound-source', 'bound-source-connect-failure',
            {'argv': bound_argv, 'command_line': ' '.join(bound_argv)},
            json.dumps(bound_facts), exit_code=7,
        )
        dual_facts = {
            'schema_version': 1, 'kind': evidence.DUAL_PORT_KIND,
            'probe_source_address': self.probe_source,
            'target_host': '192.168.204.232',
            'ports': [
                {'port': 28790, 'protected_by_formal_rule': True,
                 'from_probe_source': {'outcome': 'unreachable', 'error_class': 'connection-refused'},
                 'from_allowed_source': {'outcome': 'responded', 'http_status': 401}},
                {'port': self.comparison_port, 'protected_by_formal_rule': False,
                 'from_probe_source': {'outcome': 'unreachable', 'error_class': 'connection-refused'},
                 'from_allowed_source': {'outcome': 'responded', 'http_status': 406}},
            ],
        }
        dual_argv = ['/usr/bin/connect-probe', '--source', self.probe_source,
                     '28790', str(self.comparison_port)]
        dual = self._element_envelope(
            'pc006-dual-port', 'dual-port-comparison',
            {'argv': dual_argv, 'command_line': ' '.join(dual_argv)},
            json.dumps(dual_facts), exit_code=2,
        )
        rule = {
            'name': 'mcp-velociraptor-28790',
            'display_name': 'mcp-velociraptor-28790',
            'direction': 'Inbound', 'action': 'Allow', 'enabled': True,
            'protocol': 'TCP', 'local_port': 28790,
            'local_address': '192.168.204.232', 'remote_address': '192.168.204.1',
        }
        firewall_argv = ['/usr/bin/ssh', 'guest', 'Get-NetFirewallRule']
        firewall = self._element_envelope(
            'pc006-firewall-rule', 'firewall-rule-verify',
            {'argv': firewall_argv, 'command_line': ' '.join(firewall_argv)},
            json.dumps({'rules': [rule]}), exit_code=0,
        )
        self.pc006 = {
            'schema_version': 1,
            'kind': evidence.PC006_BOUNDARY_KIND,
            'workflow_id': evidence.WORKFLOW_ID,
            'run_id': self.run_id,
            'restore_attempt_id': self.attempt,
            'probe_source_address': self.probe_source,
            'comparison_port': self.comparison_port,
            'bound_source_failure': _ref(self.ref_root, self._element('bound-source', bound)),
            'dual_port_control': _ref(self.ref_root, self._element('dual-port', dual)),
            'firewall_rule': _ref(self.ref_root, self._element('firewall-rule', firewall)),
        }
        self.pc006_path = self.root / 'pc006' / 'pc006.json'
        _write_json(self.pc006_path, self.pc006)

    def _write_schema_identity(self, *, drift: bool = False, http_path: Path | None = None,
                               stdio_path: Path | None = None, http_session: str | None = None,
                               http_instance: str | None = None) -> None:
        names = [f'synthetic_tool_{number:03d}' for number in range(130)]
        http_listing = {'tools': [{'name': name, 'inputSchema': {'type': 'object'}} for name in names]}
        stdio_names = list(names)
        if drift:
            stdio_names[0] = 'a_different_tool_name'
        stdio_listing = {'tools': [{'name': name, 'inputSchema': {'type': 'object'}} for name in stdio_names]}
        if http_path is None:
            http_path = self.root / 'schema' / 'http-tools-list.json'
            _write_json(http_path, http_listing)
        if stdio_path is None:
            stdio_path = self.root / 'schema' / 'stdio-tools-list.json'
            _write_json(stdio_path, stdio_listing)
        self.schema_identity = {
            'schema_version': 1,
            'kind': evidence.SCHEMA_IDENTITY_KIND,
            'workflow_id': evidence.WORKFLOW_ID,
            'run_id': self.run_id,
            'restore_attempt_id': self.attempt,
            'http': {
                'transport': 'http',
                'session_id': http_session or self.report['mcp_session']['id'],
                'instance_id': http_instance or self.server_identity['instance_id'],
                'tools_list': _ref(self.ref_root, http_path),
            },
            'stdio': {
                'transport': 'stdio',
                'session_id': 'synthetic-stdio-session',
                'instance_id': 'synthetic-stdio-instance',
                'tools_list': _ref(self.ref_root, stdio_path),
            },
        }
        self.schema_identity_path = self.root / 'schema' / 'schema-identity.json'
        _write_json(self.schema_identity_path, self.schema_identity)

    def _write_service_observation(self, *, instance: str | None = None) -> None:
        observation = {
            **self.server_identity,
            'instance_id': instance or self.server_identity['instance_id'],
            'observed_at': '2026-09-13T23:59:59Z',
        }
        self.observation_path = self.root / 'service-observation.json'
        _write_json(self.observation_path, observation)


class NetworkGateTests(unittest.TestCase):
    def test_accepts_complete_pc006_dual_schema_and_service_join(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = NetworkGateFixture(Path(directory))
            evidence._verify_network_evidence(fixture.root, fixture.phase, {})

    def test_rejects_verdict_summary_pc006_and_single_schema_digest(self) -> None:
        # The retained real-bundle shapes: a string-summary pc006 document and
        # a bare single tools-schema file must both be rejected (CHK-028).
        with tempfile.TemporaryDirectory() as directory:
            fixture = NetworkGateFixture(Path(directory))
            summary = fixture.root / 'pc006' / 'pc006-summary.json'
            _write_json(summary, {
                'schema_version': 1, 'kind': 'p05-pc006-boundary-v1',
                'workflow_id': evidence.WORKFLOW_ID, 'run_id': fixture.run_id,
                'restore_attempt_id': fixture.attempt,
                'formal_28790': '401 (host source)', 'control_28787': '406 (host source)',
                'rule_unique': True,
            })
            fixture.document['non_allowed_source'] = _ref(fixture.root, summary)
            _write_json(fixture.path, fixture.document)
            fixture.phase['network_evidence'] = _ref(fixture.root, fixture.path)
            with self.assertRaisesRegex(evidence.EvidenceError, 'PC006 boundary document shape'):
                evidence._verify_network_evidence(fixture.root, fixture.phase, {})
        with tempfile.TemporaryDirectory() as directory:
            fixture = NetworkGateFixture(Path(directory))
            single = fixture.root / 'schema' / 'tools-schema.json'
            _write_json(single, {'tools': [
                {'name': f'synthetic_tool_{number:03d}', 'inputSchema': {'type': 'object'}}
                for number in range(130)
            ]})
            fixture.document['schema_identity'] = _ref(fixture.root, single)
            _write_json(fixture.path, fixture.document)
            fixture.phase['network_evidence'] = _ref(fixture.root, fixture.path)
            with self.assertRaisesRegex(evidence.EvidenceError, 'schema identity document shape'):
                evidence._verify_network_evidence(fixture.root, fixture.phase, {})

    def test_b01_rejects_each_wrong_rule_name(self) -> None:
        for change in ('both', 'name_only', 'display_only', 'both_equal_wrong'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                fixture = NetworkGateFixture(Path(directory))
                path = fixture.root / 'pc006' / 'firewall-rule.json'
                document = json.loads(path.read_text(encoding='utf-8'))
                rules = json.loads(document['response']['stdout'])
                if change in ('both', 'both_equal_wrong'):
                    rules['rules'][0]['name'] = rules['rules'][0]['display_name'] = 'wrong-rule'
                elif change == 'name_only':
                    rules['rules'][0]['name'] = 'wrong-rule'
                else:
                    rules['rules'][0]['display_name'] = 'wrong-rule'
                document['response'] = _streams(json.dumps(rules))
                _write_json(path, document)
                fixture.pc006['firewall_rule'] = _ref(fixture.root, path)
                _write_json(fixture.pc006_path, fixture.pc006)
                fixture.document['non_allowed_source'] = _ref(fixture.root, fixture.pc006_path)
                _write_json(fixture.path, fixture.document)
                fixture.phase['network_evidence'] = _ref(fixture.root, fixture.path)
                with self.assertRaisesRegex(evidence.EvidenceError, 'unique exact 28790 host-only rule'):
                    evidence._verify_network_evidence(fixture.root, fixture.phase, {})

    def test_b02_rejects_unbound_mismatched_or_allowed_bound_source(self) -> None:
        def rewrite(fixture: NetworkGateFixture, argv: list[str], stdout: str | None = None,
                    exit_code: int = 7) -> None:
            path = fixture.root / 'pc006' / 'bound-source.json'
            document = json.loads(path.read_text(encoding='utf-8'))
            document['request'] = {'argv': argv, 'command_line': ' '.join(argv)}
            if stdout is not None:
                document['response'] = _streams(stdout)
            document['exit_status']['code'] = exit_code
            _write_json(path, document)
            fixture.pc006['bound_source_failure'] = _ref(fixture.root, path)
            _write_json(fixture.pc006_path, fixture.pc006)
            fixture.document['non_allowed_source'] = _ref(fixture.root, fixture.pc006_path)
            _write_json(fixture.path, fixture.document)
            fixture.phase['network_evidence'] = _ref(fixture.root, fixture.path)

        mutations = {
            # No binding parameter at all (codex-r01 'unbound_source' shape).
            'unbound': (['/usr/bin/curl', 'http://192.168.204.232:28790/mcp', '28787'], None, 7,
                        'carries no bound source parameter'),
            # Bound to the allowed host source.
            'allowed_source': (['/usr/bin/curl', '--interface', '192.168.204.1',
                                'http://192.168.204.232:28790/mcp'], None, 7,
                               'differs from the declared probe source'),
            # Binding present but different from the declared probe source.
            'other_source': (['/usr/bin/curl', '--interface', '192.168.204.98',
                              'http://192.168.204.232:28790/mcp'], None, 7,
                             'differs from the declared probe source'),
            # Unrecognized collector command shape.
            'not_a_probe': (['false', 'http://192.168.204.232:28790/mcp', '28787'],
                            'not a network test', 127,
                            'not a recognized collector probe command'),
            # Structured facts that do not state the classified failure.
            'unclassified': (['/usr/bin/curl', '--interface', '192.168.204.99',
                              'http://192.168.204.232:28790/mcp'],
                             json.dumps({'schema_version': 1, 'kind': evidence.CONNECT_PROBE_KIND,
                                         'source': '192.168.204.99',
                                         'target': {'host': '192.168.204.232', 'port': 28790, 'path': '/mcp'},
                                         'outcome': 'unreachable', 'error_class': 'syntax-error'}), 7,
                             'classified connection failure'),
        }
        for label, (argv, stdout, code, pattern) in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                fixture = NetworkGateFixture(Path(directory))
                rewrite(fixture, argv, stdout, code)
                with self.assertRaisesRegex(evidence.EvidenceError, pattern):
                    evidence._verify_network_evidence(fixture.root, fixture.phase, {})

    def test_b03_rejects_unparsed_or_partial_dual_port_results(self) -> None:
        def rewrite(fixture: NetworkGateFixture, stdout: str, argv: list[str] | None = None) -> None:
            path = fixture.root / 'pc006' / 'dual-port.json'
            document = json.loads(path.read_text(encoding='utf-8'))
            if argv is not None:
                document['request'] = {'argv': argv, 'command_line': ' '.join(argv)}
            document['response'] = _streams(stdout)
            _write_json(path, document)
            fixture.pc006['dual_port_control'] = _ref(fixture.root, path)
            _write_json(fixture.pc006_path, fixture.pc006)
            fixture.document['non_allowed_source'] = _ref(fixture.root, fixture.pc006_path)
            _write_json(fixture.path, fixture.document)
            fixture.phase['network_evidence'] = _ref(fixture.root, fixture.path)

        with tempfile.TemporaryDirectory() as directory:
            fixture = NetworkGateFixture(Path(directory))
            rewrite(fixture, 'both unreachable from bound source')
            with self.assertRaisesRegex(evidence.EvidenceError, 'structured probe result'):
                evidence._verify_network_evidence(fixture.root, fixture.phase, {})
        with tempfile.TemporaryDirectory() as directory:
            fixture = NetworkGateFixture(Path(directory))
            facts = json.loads(json.dumps({
                'schema_version': 1, 'kind': evidence.DUAL_PORT_KIND,
                'probe_source_address': fixture.probe_source, 'target_host': '192.168.204.232',
                'ports': [
                    {'port': 28790, 'protected_by_formal_rule': True,
                     'from_probe_source': {'outcome': 'unreachable', 'error_class': 'connection-refused'},
                     'from_allowed_source': {'outcome': 'responded', 'http_status': 401}},
                ],
            }))
            rewrite(fixture, json.dumps(facts))
            with self.assertRaisesRegex(evidence.EvidenceError, 'both per-port results'):
                evidence._verify_network_evidence(fixture.root, fixture.phase, {})
        with tempfile.TemporaryDirectory() as directory:
            fixture = NetworkGateFixture(Path(directory))
            facts = json.loads((fixture.root / 'pc006' / 'dual-port.json').read_text(encoding='utf-8'))
            ports = json.loads(json.dumps(json.loads(facts['response']['stdout'])))
            ports['ports'][1]['from_allowed_source'] = {'outcome': 'unreachable', 'error_class': 'connection-refused'}
            rewrite(fixture, json.dumps(ports))
            with self.assertRaisesRegex(evidence.EvidenceError, 'live unprotected control'):
                evidence._verify_network_evidence(fixture.root, fixture.phase, {})
        with tempfile.TemporaryDirectory() as directory:
            fixture = NetworkGateFixture(Path(directory))
            argv = ['/usr/bin/connect-probe', '--source', fixture.probe_source, '--ports', '28790,28787']
            rewrite(fixture, json.dumps({
                'schema_version': 1, 'kind': evidence.DUAL_PORT_KIND,
                'probe_source_address': fixture.probe_source, 'target_host': '192.168.204.232',
                'ports': [
                    {'port': 28790, 'protected_by_formal_rule': True,
                     'from_probe_source': {'outcome': 'unreachable', 'error_class': 'connection-refused'},
                     'from_allowed_source': {'outcome': 'responded', 'http_status': 401}},
                    {'port': 28787, 'protected_by_formal_rule': False,
                     'from_probe_source': {'outcome': 'unreachable', 'error_class': 'connection-refused'},
                     'from_allowed_source': {'outcome': 'responded', 'http_status': 406}},
                ],
            }), argv=argv)
            with self.assertRaisesRegex(evidence.EvidenceError, 'does not probe both ports'):
                evidence._verify_network_evidence(fixture.root, fixture.phase, {})

    def test_b04_rejects_elements_outside_the_phase_window_or_rebound_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = NetworkGateFixture(Path(directory))
            path = fixture.root / 'pc006' / 'bound-source.json'
            document = json.loads(path.read_text(encoding='utf-8'))
            document['started_at'] = '2000-01-01T00:00:00Z'
            document['ended_at'] = '2000-01-01T00:00:01Z'
            _write_json(path, document)
            fixture.pc006['bound_source_failure'] = _ref(fixture.root, path)
            _write_json(fixture.pc006_path, fixture.pc006)
            fixture.document['non_allowed_source'] = _ref(fixture.root, fixture.pc006_path)
            _write_json(fixture.path, fixture.document)
            fixture.phase['network_evidence'] = _ref(fixture.root, fixture.path)
            with self.assertRaisesRegex(evidence.EvidenceError, 'outside its phase report interval'):
                evidence._verify_network_evidence(fixture.root, fixture.phase, {})
        with tempfile.TemporaryDirectory() as directory:
            fixture = NetworkGateFixture(Path(directory))
            path = fixture.root / 'pc006' / 'dual-port.json'
            document = json.loads(path.read_text(encoding='utf-8'))
            document['run_id'] = 'another-run'
            _write_json(path, document)
            fixture.pc006['dual_port_control'] = _ref(fixture.root, path)
            _write_json(fixture.pc006_path, fixture.pc006)
            fixture.document['non_allowed_source'] = _ref(fixture.root, fixture.pc006_path)
            _write_json(fixture.path, fixture.document)
            fixture.phase['network_evidence'] = _ref(fixture.root, fixture.path)
            with self.assertRaisesRegex(evidence.EvidenceError, 'envelope shape or phase identity'):
                evidence._verify_network_evidence(fixture.root, fixture.phase, {})

    def test_b05_rejects_unbound_drifted_or_duplicated_schema_pairs(self) -> None:
        # All-zero report hash: mutual equality must not float the pair.
        with tempfile.TemporaryDirectory() as directory:
            fixture = NetworkGateFixture(Path(directory))
            fixture.report['tools_schema_sha256'] = '0' * 64
            _write_json(fixture.report_path, fixture.report)
            fixture.phase['report'] = _ref(fixture.root, fixture.report_path)
            with self.assertRaisesRegex(evidence.EvidenceError, "report's tools_schema_sha256"):
                evidence._verify_network_evidence(fixture.root, fixture.phase, {})
        # Drifted stdio listing.
        with tempfile.TemporaryDirectory() as directory:
            fixture = NetworkGateFixture(Path(directory))
            fixture._write_schema_identity(drift=True)
            fixture.document['schema_identity'] = _ref(fixture.root, fixture.schema_identity_path)
            _write_json(fixture.path, fixture.document)
            fixture.phase['network_evidence'] = _ref(fixture.root, fixture.path)
            with self.assertRaisesRegex(evidence.EvidenceError, 'do not normalize to the same schema'):
                evidence._verify_network_evidence(fixture.root, fixture.phase, {})
        # The same file standing in for both adapters.
        with tempfile.TemporaryDirectory() as directory:
            fixture = NetworkGateFixture(Path(directory))
            single = fixture.root / 'schema' / 'http-tools-list.json'
            fixture._write_schema_identity(stdio_path=single)
            fixture.document['schema_identity'] = _ref(fixture.root, fixture.schema_identity_path)
            _write_json(fixture.path, fixture.document)
            fixture.phase['network_evidence'] = _ref(fixture.root, fixture.path)
            with self.assertRaisesRegex(evidence.EvidenceError, 'both adapter originals'):
                evidence._verify_network_evidence(fixture.root, fixture.phase, {})
        # HTTP adapter not joined to this report's session/instance.
        with tempfile.TemporaryDirectory() as directory:
            fixture = NetworkGateFixture(Path(directory))
            fixture._write_schema_identity(http_session='another-session')
            fixture.document['schema_identity'] = _ref(fixture.root, fixture.schema_identity_path)
            _write_json(fixture.path, fixture.document)
            fixture.phase['network_evidence'] = _ref(fixture.root, fixture.path)
            with self.assertRaisesRegex(evidence.EvidenceError, 'report session and service instance'):
                evidence._verify_network_evidence(fixture.root, fixture.phase, {})
        # stdio adapter reusing the HTTP session.
        with tempfile.TemporaryDirectory() as directory:
            fixture = NetworkGateFixture(Path(directory))
            fixture.schema_identity['stdio']['session_id'] = fixture.report['mcp_session']['id']
            _write_json(fixture.schema_identity_path, fixture.schema_identity)
            fixture.document['schema_identity'] = _ref(fixture.root, fixture.schema_identity_path)
            _write_json(fixture.path, fixture.document)
            fixture.phase['network_evidence'] = _ref(fixture.root, fixture.path)
            with self.assertRaisesRegex(evidence.EvidenceError, 'distinct adapter session'):
                evidence._verify_network_evidence(fixture.root, fixture.phase, {})

    def test_rejects_drifted_service_instance_and_broad_rule(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = NetworkGateFixture(Path(directory))
            fixture._write_service_observation(instance='drifted-instance')
            fixture.document['service_observation'] = _ref(fixture.root, fixture.observation_path)
            _write_json(fixture.path, fixture.document)
            fixture.phase['network_evidence'] = _ref(fixture.root, fixture.path)
            with self.assertRaisesRegex(evidence.EvidenceError, 'does not join the report identity'):
                evidence._verify_network_evidence(fixture.root, fixture.phase, {})
        with tempfile.TemporaryDirectory() as directory:
            fixture = NetworkGateFixture(Path(directory))
            rule_path = fixture.root / 'pc006' / 'firewall-rule.json'
            document = json.loads(rule_path.read_text(encoding='utf-8'))
            rule = json.loads(document['response']['stdout'])['rules'][0]
            rule['remote_address'] = '192.168.204.0/24'
            document['response'] = _streams(json.dumps({'rules': [rule]}))
            _write_json(rule_path, document)
            fixture.pc006['firewall_rule'] = _ref(fixture.root, rule_path)
            _write_json(fixture.pc006_path, fixture.pc006)
            fixture.document['non_allowed_source'] = _ref(fixture.root, fixture.pc006_path)
            _write_json(fixture.path, fixture.document)
            fixture.phase['network_evidence'] = _ref(fixture.root, fixture.path)
            with self.assertRaisesRegex(evidence.EvidenceError, 'unique exact 28790 host-only rule'):
                evidence._verify_network_evidence(fixture.root, fixture.phase, {})

    def test_rejects_succeeding_boundary_probe_or_missing_report_join(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = NetworkGateFixture(Path(directory))
            bound_path = fixture.root / 'pc006' / 'bound-source.json'
            document = json.loads(bound_path.read_text(encoding='utf-8'))
            document['exit_status']['code'] = 0
            _write_json(bound_path, document)
            fixture.pc006['bound_source_failure'] = _ref(fixture.root, bound_path)
            _write_json(fixture.pc006_path, fixture.pc006)
            fixture.document['non_allowed_source'] = _ref(fixture.root, fixture.pc006_path)
            _write_json(fixture.path, fixture.document)
            fixture.phase['network_evidence'] = _ref(fixture.root, fixture.path)
            with self.assertRaisesRegex(evidence.EvidenceError, 'unexpectedly succeeded'):
                evidence._verify_network_evidence(fixture.root, fixture.phase, {})
        with tempfile.TemporaryDirectory() as directory:
            fixture = NetworkGateFixture(Path(directory))
            del fixture.phase['report']
            with self.assertRaisesRegex(evidence.EvidenceError, 'phase report Ref join'):
                evidence._verify_network_evidence(fixture.root, fixture.phase, {})


class RestoreOriginalGateTests(unittest.TestCase):
    attempt = 'restore-original-gate'
    marker = 'Win10MalBox-Velo-Snapshot4.vmsn'

    def _paths(self, root: Path) -> dict[str, Path]:
        return restore_action_envelopes(root, self.attempt, evidence.SNAPSHOT_188, self.marker)

    def test_accepts_one_chronologically_ordered_attempt_bound_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self._paths(root)
            evidence._verify_restore_raw_records({
                'restore_attempt_id': self.attempt,
                'snapshot_name': evidence.SNAPSHOT_188,
                'checkpoint_marker': self.marker,
            }, paths)

    def test_rejects_not_executed_text_failed_exit_and_cross_attempt(self) -> None:
        restore = {
            'restore_attempt_id': self.attempt,
            'snapshot_name': evidence.SNAPSHOT_188,
            'checkpoint_marker': self.marker,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self._paths(root)
            paths['snapshot_metadata'].write_text(
                f'{self.attempt} {evidence.SNAPSHOT_188} {self.marker} DESKTOP-3FI41GR -- NOT EXECUTED',
                encoding='utf-8',
            )
            with self.assertRaisesRegex(evidence.EvidenceError, 'valid UTF-8 JSON'):
                evidence._verify_restore_raw_records(restore, paths)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self._paths(root)
            document = json.loads(paths['revert_operation'].read_text(encoding='utf-8'))
            document['exit_status']['code'] = 1
            _write_json(paths['revert_operation'], document)
            with self.assertRaisesRegex(evidence.EvidenceError, 'did not exit successfully'):
                evidence._verify_restore_raw_records(restore, paths)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self._paths(root)
            document = json.loads(paths['pre_start_marker'].read_text(encoding='utf-8'))
            document['restore_attempt_id'] = 'other-attempt'
            _write_json(paths['pre_start_marker'], document)
            with self.assertRaisesRegex(evidence.EvidenceError, 'identity or operation differs'):
                evidence._verify_restore_raw_records(restore, paths)

    def test_rejects_wrong_revert_target_unparsed_marker_and_guest_identity_drift(self) -> None:
        restore = {
            'restore_attempt_id': self.attempt,
            'snapshot_name': evidence.SNAPSHOT_188,
            'checkpoint_marker': self.marker,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self._paths(root)
            document = json.loads(paths['revert_operation'].read_text(encoding='utf-8'))
            document['request']['argv'][-1] = evidence.SNAPSHOT_187
            document['request']['command_line'] = ' '.join(document['request']['argv'])
            _write_json(paths['revert_operation'], document)
            with self.assertRaisesRegex(evidence.EvidenceError, 'revertToSnapshot command for the selected snapshot'):
                evidence._verify_restore_raw_records(restore, paths)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self._paths(root)
            document = json.loads(paths['pre_start_marker'].read_text(encoding='utf-8'))
            stdout = 'checkpoint.vmState = "Win10MalBox-Velo-Snapshot9.vmsn"\n'
            document['response'] = _streams(stdout)
            _write_json(paths['pre_start_marker'], document)
            with self.assertRaisesRegex(evidence.EvidenceError, 'declared checkpoint marker'):
                evidence._verify_restore_raw_records(restore, paths)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self._paths(root)
            document = json.loads(paths['post_restore_hostname'].read_text(encoding='utf-8'))
            stdout = json.dumps({
                'computer_name': 'DESKTOP-3FI41GR',
                'adapters': [{
                    'MACAddress': '00:0C:29:83:B8:65', 'IPAddress': ['192.168.204.232'],
                    'DHCPEnabled': True, 'IPEnabled': True,
                }],
            })
            document['response'] = _streams(stdout)
            _write_json(paths['post_restore_hostname'], document)
            with self.assertRaisesRegex(evidence.EvidenceError, 'guest identity readback'):
                evidence._verify_restore_raw_records(restore, paths)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self._paths(root)
            document = json.loads(paths['post_restore_hostname'].read_text(encoding='utf-8'))
            document['started_at'] = '2026-09-14T00:00:00Z'
            _write_json(paths['post_restore_hostname'], document)
            with self.assertRaisesRegex(evidence.EvidenceError, 'chronologically ordered attempt'):
                evidence._verify_restore_raw_records(restore, paths)

    def test_b06_rejects_masquerading_commands_and_contradictory_command_lines(self) -> None:
        restore = {
            'restore_attempt_id': self.attempt,
            'snapshot_name': evidence.SNAPSHOT_188,
            'checkpoint_marker': self.marker,
        }
        # echo with a contradicting command line (codex-r01 shape).
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self._paths(root)
            document = json.loads(paths['revert_operation'].read_text(encoding='utf-8'))
            document['request']['argv'][0] = '/bin/echo'
            document['request']['command_line'] = 'echo NOT EXECUTED'
            _write_json(paths['revert_operation'], document)
            with self.assertRaisesRegex(evidence.EvidenceError, 'command_line contradicts its argv'):
                evidence._verify_restore_raw_records(restore, paths)
        # echo with a self-consistent command line still is not vmrun.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self._paths(root)
            document = json.loads(paths['revert_operation'].read_text(encoding='utf-8'))
            argv = document['request']['argv']
            argv[0] = '/bin/echo'
            document['request']['command_line'] = ' '.join(argv)
            _write_json(paths['revert_operation'], document)
            with self.assertRaisesRegex(evidence.EvidenceError, 'vmrun revertToSnapshot command'):
                evidence._verify_restore_raw_records(restore, paths)
        # A real vmrun path but the wrong fixed action.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self._paths(root)
            document = json.loads(paths['revert_operation'].read_text(encoding='utf-8'))
            argv = document['request']['argv']
            argv[3] = 'listSnapshots'
            document['request']['command_line'] = ' '.join(argv)
            _write_json(paths['revert_operation'], document)
            with self.assertRaisesRegex(evidence.EvidenceError, 'vmrun revertToSnapshot command'):
                evidence._verify_restore_raw_records(restore, paths)
        # snapshot_metadata recorded from a non-vmrun executable.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self._paths(root)
            document = json.loads(paths['snapshot_metadata'].read_text(encoding='utf-8'))
            document['request']['argv'][0] = '/usr/bin/faketree'
            document['request']['command_line'] = ' '.join(document['request']['argv'])
            _write_json(paths['snapshot_metadata'], document)
            with self.assertRaisesRegex(evidence.EvidenceError, 'vmrun listSnapshots command'):
                evidence._verify_restore_raw_records(restore, paths)
        # pre-start marker read back by an unrelated executable.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self._paths(root)
            document = json.loads(paths['pre_start_marker'].read_text(encoding='utf-8'))
            document['request']['argv'][0] = '/usr/bin/python3'
            document['request']['command_line'] = ' '.join(document['request']['argv'])
            _write_json(paths['pre_start_marker'], document)
            with self.assertRaisesRegex(evidence.EvidenceError, 'vmx checkpoint readback command'):
                evidence._verify_restore_raw_records(restore, paths)
        # guest observation whose script is not the fixed identity query.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self._paths(root)
            document = json.loads(paths['post_restore_hostname'].read_text(encoding='utf-8'))
            script = 'Write-Output fixed'
            document['request']['script'] = script
            document['request']['script_sha256'] = hashlib.sha256(script.encode('utf-8')).hexdigest()
            _write_json(paths['post_restore_hostname'], document)
            with self.assertRaisesRegex(evidence.EvidenceError, 'fixed guest identity query'):
                evidence._verify_restore_raw_records(restore, paths)


@unittest.skipUnless(os.name == 'nt', 'CON002: the full synthetic pack joins the Windows acceptance components')
class FullSyntheticActivationBundleTests(unittest.TestCase):
    """A whole synthetic snapshot188 activation pack through the public entry.

    Synthetic/seam: every original is fabricated here.  Passing proves the
    complete gate chain of ``verify_activation_bundle``; it never asserts that
    any real Windows activation evidence exists.
    """

    def test_verify_activation_bundle_accepts_a_fully_closed_synthetic_pack(self) -> None:
        from tests.test_p05_baseline_adoption import BaselineAdoptionTests
        from tests.test_p06_activation_structure import P05PhaseFixture

        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / 'activation-188' / str(uuid.uuid4())
            bundle.mkdir(parents=True)
            marker = 'Win10MalBox-Velo-Snapshot4.vmsn'

            # ---- baseline adoption (self-contained under p05-originals) ----
            adoption_case = BaselineAdoptionTests('test_accepts_complete_self_contained_record_and_expected_old_bytes')
            adoption_case.setUp()
            try:
                adoption = adoption_case.adoption(vmx=VMX)
                adoption_case.write_adoption(adoption)
                adoption_dir = adoption_case.bundle
                originals = bundle / 'p05-originals'
                adoption_target = originals / 'baseline-adoption' / adoption_case.adoption_id
                adoption_target.parent.mkdir(parents=True, exist_ok=True)
                for member in sorted(adoption_dir.rglob('*')):
                    if member.is_file():
                        target = adoption_target / member.relative_to(adoption_dir)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(member.read_bytes())
                adoption_bytes = (adoption_target / 'adoption.json').read_bytes()
            finally:
                adoption_case.tearDown()

            # ---- creation metadata (live zero-to-one envelopes) ----
            from tests import p05_candidate_creation as creation
            from tests.test_p05_candidate_creation import _record

            creation_originals = {
                'tree_before': _record('tree_before',
                                       ['/usr/bin/vmrun', '-T', 'ws', 'listSnapshots', VMX, 'showTree'],
                                       'Total snapshots: 1\n' + creation.PREPARATION + '\n', 0),
                'create_operation': _record('create_operation',
                                            ['/usr/bin/vmrun', '-T', 'ws', 'snapshot', VMX, creation.CANDIDATE],
                                            '', 2),
                'tree_after': _record('tree_after',
                                      ['/usr/bin/vmrun', '-T', 'ws', 'listSnapshots', VMX, 'showTree'],
                                      'Total snapshots: 2\n' + creation.PREPARATION + '\n  ' + creation.CANDIDATE + '\n', 4),
                'metadata_readback': _record('metadata_readback', ['/usr/bin/cat', VMX[:-4] + '.vmsd'],
                                             '\n'.join([
                                                 'snapshot.numSnapshots = "2"', 'snapshot.current = "4"',
                                                 'snapshot0.uid = "3"', 'snapshot0.filename = ' + '"Win10MalBox-Velo-Snapshot3.vmsn"',
                                                 'snapshot0.displayName = "' + creation.PREPARATION + '"',
                                                 'snapshot1.uid = "4"', 'snapshot1.filename = "' + marker + '"',
                                                 'snapshot1.displayName = "' + creation.CANDIDATE + '"',
                                             ]), 6),
            }
            for record in creation_originals.values():
                record['started_at'] = record['started_at'].replace('T00:00:', 'T01:00:')
                record['ended_at'] = record['ended_at'].replace('T00:00:', 'T01:00:')
            creation_metadata = {
                'schema_version': 1, 'workflow_id': evidence.WORKFLOW_ID,
                'candidate': evidence.SNAPSHOT_188, 'checkpoint_marker': marker, 'vmx': VMX,
            }
            for key, value in creation_originals.items():
                payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
                path = bundle / 'creation' / f'{key}.json'
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
                creation_metadata[key] = {'path': path.relative_to(bundle).as_posix(),
                                          'size': len(payload), 'sha256': _sha256_bytes(payload)}

            # ---- three phases ----
            def build_phase(name: str, scenario_id: str, stage: str, snapshot: str, phase_marker: str,
                            run_id: str, attempt: str, hour: int) -> dict[str, object]:
                phase_root = bundle / name
                ready_root = phase_root / 'ready-evidence'
                phase = P05PhaseFixture(phase_root, scenario_id)
                # bind the runner identity to the ready host-process originals
                phase.report['runner'] = {
                    'pid': 7000, 'process_start_time_utc': '2026-09-13T12:00:01Z',
                    'executable_sha256': 'a' * 64,
                }
                _shift_report_times(phase, hour)
                phase.report['run_id'] = run_id
                _write_json(phase.report_path, phase.report)

                ready = ReadyGateFixture(ready_root, run_id=run_id, attempt=attempt, ref_root=bundle)
                ready.stage, ready.snapshot, ready.marker = stage, snapshot, phase_marker
                ready.ready.update({
                    'snapshot_stage': stage, 'snapshot_name': snapshot,
                    'checkpoint_marker': phase_marker,
                })
                _write_json(ready.ready_path, ready.ready)

                dependency = DependencyGateFixture.__new__(DependencyGateFixture)
                dependency.root = ready_root
                dependency.run_id = run_id
                dependency.attempt = attempt
                dependency.chain_dir = phase_root / 'chain'
                DependencyGateFixture._write_chain(dependency)
                dependency.window_path = phase_root / 'network' / 'network-window.txt'
                DependencyGateFixture._write_window(dependency)
                dependency.document = {
                    'schema_version': 1, 'workflow_id': evidence.WORKFLOW_ID,
                    'run_id': run_id, 'restore_attempt_id': attempt,
                    'inventory_artifacts': _ref(bundle, ready_root / 'raw' / 'dependencies.json'),
                    'four_chains': _ref(bundle, dependency.chain_dir / 'p05-real-acceptance.json'),
                    'network_observations': _ref(bundle, dependency.window_path),
                }
                dependency.path = phase_root / 'dependency-acceptance.json'
                _write_json(dependency.path, dependency.document)

                entry = EntryGateFixture(phase_root, ref_root=bundle)
                entry.run_id, entry.attempt = run_id, attempt
                for name_, path_ in entry.cases.items():
                    document = json.loads(path_.read_text(encoding='utf-8'))
                    document['run_id'] = run_id
                    document['restore_attempt_id'] = attempt
                    for counter in ('counter_before', 'counter_after'):
                        document[counter]['run_id'] = run_id
                        document[counter]['restore_attempt_id'] = attempt
                    _write_json(path_, document)
                    entry.document["cases"][name_] = _ref(bundle, path_)
                entry.document['run_id'] = run_id
                entry.document['restore_attempt_id'] = attempt
                _write_json(entry.path, entry.document)

                network = NetworkGateFixture(phase_root, ref_root=bundle)
                network.run_id, network.attempt = run_id, attempt
                network.server_identity = dict(phase.report['server_identity'])
                network.report = {
                    'run_id': run_id,
                    'server_identity': dict(phase.report['server_identity']),
                    'started_at': phase.report['started_at'],
                    'ended_at': phase.report['ended_at'],
                    'mcp_session': dict(phase.report['mcp_session']),
                    'tools_schema_sha256': phase.report['tools_schema_sha256'],
                }
                network.probe_started = f'2026-09-14T{hour:02d}:00:40Z'
                network.probe_ended = f'2026-09-14T{hour:02d}:00:41Z'
                _write_json(network.report_path, network.report)
                network._write_pc006()
                # The HTTP adapter original is this phase's own tools/list; a
                # byte copy is the distinct stdio original, both normalizing
                # to the report's tools_schema_sha256 (B05).
                stdio_copy = phase_root / 'schema' / 'stdio-tools-list.json'
                stdio_copy.parent.mkdir(parents=True, exist_ok=True)
                stdio_copy.write_bytes((phase.run_dir / 'tools-list.json').read_bytes())
                network._write_schema_identity(
                    http_path=phase.run_dir / 'tools-list.json',
                    stdio_path=stdio_copy,
                    http_session=phase.report['mcp_session']['id'],
                    http_instance=phase.report['server_identity']['instance_id'],
                )
                network._write_service_observation()
                network.document.update({
                    'run_id': run_id, 'restore_attempt_id': attempt,
                    'non_allowed_source': _ref(bundle, network.pc006_path),
                    'schema_identity': _ref(bundle, network.schema_identity_path),
                    'service_observation': _ref(bundle, network.observation_path),
                })
                _write_json(network.path, network.document)

                restore_dir = originals / attempt
                action_paths = restore_action_envelopes(
                    restore_dir, attempt, snapshot, phase_marker, started_minute=30 + hour)
                canonical = {
                    'schema_version': 5, 'workflow_id': evidence.WORKFLOW_ID,
                    'epoch': 5, 'phase': 'PREPARATION_BASELINE',
                    'active_snapshot': {
                        'name': evidence.SNAPSHOT_187,
                        'checkpoint_marker': 'Win10MalBox-Velo-Snapshot3.vmsn',
                        'purpose': 'synthetic preparation baseline',
                    },
                    'automatic_restore_allowlist': [evidence.SNAPSHOT_187],
                    'retired_snapshots': [
                        {'name': name_, 'status': evidence.MANUAL_ONLY}
                        for name_ in (evidence.SNAPSHOT_183, evidence.SNAPSHOT_184,
                                      evidence.SNAPSHOT_1, evidence.SNAPSHOT_186)
                    ],
                    'baseline_evidence': {
                        'source': 'synthetic-copy',
                        'evidence_path': f'/original-host/P05/baseline-adoption/{adoption_case.adoption_id}/adoption.json',
                        'evidence_sha256': _sha256_bytes(adoption_bytes),
                        'recorded_at': '2026-09-13T00:00:00Z',
                    },
                    'activation_evidence': None,
                }
                canonical_path = restore_dir / 'canonical.json'
                _write_json(canonical_path, canonical)
                records = {
                    **action_paths,
                    'canonical_readback': canonical_path,
                    'baseline_adoption': adoption_target / 'adoption.json',
                }
                snapshot_evidence = {
                    'restore': {
                        'workflow_id': evidence.WORKFLOW_ID, 'run_id': run_id,
                        'restore_attempt_id': attempt, 'snapshot_stage': stage,
                        'snapshot_name': snapshot, 'checkpoint_marker': phase_marker,
                        'canonical_schema_version': 5, 'canonical_epoch': 5,
                        'canonical_phase': 'PREPARATION_BASELINE',
                        'canonical_sha256': _sha256_bytes(canonical_path.read_bytes()),
                        'restore_records': [
                            {'kind': kind, 'path': path_.relative_to(originals).as_posix(),
                             'sha256': _sha256_bytes(path_.read_bytes())}
                            for kind, path_ in records.items()
                        ],
                    },
                    'scenario_id': scenario_id,
                    'source_sha256': phase.report['source_sha256'],
                    'index_sha256': phase.report['index_sha256'],
                    'mcp_session_id': phase.report['mcp_session']['id'],
                    'server_instance_id': phase.report['server_identity']['instance_id'],
                    'server_observation_sha256': phase.report['server_observation_sha256'],
                }
                _write_json(phase.snapshot_path, snapshot_evidence)
                phase.report['snapshot_evidence_sha256'] = _sha256_bytes(phase.snapshot_path.read_bytes())
                _write_json(phase.report_path, phase.report)
                members = []
                for member in sorted(phase_root.rglob('*')):
                    if member.is_file():
                        members.append(_ref(bundle, member))
                members.sort(key=lambda item: str(item['path']).encode('utf-8'))
                manifest_path = phase_root / 'package-manifest.json'
                _write_json(manifest_path, {'schema_version': 1, 'members': members})
                return {
                    'restore_attempt_id': attempt, 'run_id': run_id,
                    'report': _ref(bundle, phase.report_path),
                    'snapshot_evidence': _ref(bundle, phase.snapshot_path),
                    'ready': _ref(bundle, ready.ready_path),
                    'dependency_acceptance': _ref(bundle, dependency.path),
                    'entry_gate': _ref(bundle, entry.path),
                    'network_evidence': _ref(bundle, network.path),
                    'package_manifest': _ref(bundle, manifest_path),
                }

            def _shift_report_times(phase: P05PhaseFixture, hours: int) -> None:
                from datetime import datetime, timedelta, timezone

                def shift(value: str) -> str:
                    moment = datetime.fromisoformat(value.replace('Z', '+00:00'))
                    return (moment + timedelta(hours=hours)).isoformat(
                        timespec='seconds' if '.' not in value else 'milliseconds'
                    ).replace('+00:00', 'Z')

                report = phase.report
                report['started_at'] = shift(report['started_at'])
                report['ended_at'] = shift(report['ended_at'])
                report['mcp_session']['initialized_at'] = shift(report['mcp_session']['initialized_at'])
                report['mcp_session']['closed_at'] = shift(report['mcp_session']['closed_at'])
                for call in report['calls']:
                    call['started_at'] = shift(call['started_at'])
                    call['ended_at'] = shift(call['ended_at'])
                observation = json.loads((phase.observation_path).read_text(encoding='utf-8'))
                observation['observed_at'] = shift(observation['observed_at'])
                _write_json(phase.observation_path, observation)
                report['server_observation_sha256'] = _sha256_bytes(phase.observation_path.read_bytes())

            initial = build_phase(
                'initial', 'p05-flow-triage-repair-initial', 'P05_REPAIR_INITIAL',
                evidence.SNAPSHOT_187, 'Win10MalBox-Velo-Snapshot3.vmsn',
                'run-initial-synthetic', 'p05-restore-initial-synthetic', 0)
            cycle_one = build_phase(
                'cycle-1', 'p05-flow-triage-repair-candidate', 'P05_REPAIR_CANDIDATE',
                evidence.SNAPSHOT_188, marker,
                'run-cycle-one-synthetic', 'p05-restore-cycle-one-synthetic', 2)
            cycle_two = build_phase(
                'cycle-2', 'p05-flow-triage-repair-candidate', 'P05_REPAIR_CANDIDATE',
                evidence.SNAPSHOT_188, marker,
                'run-cycle-two-synthetic', 'p05-restore-cycle-two-synthetic', 3)

            # ---- source copies (built after the phases so the ready fixtures'
            # synthetic-triage dependency manifest bytes are the carried ones) ----
            phase_manifest = (bundle / 'initial' / 'ready-evidence' / 'source' / 'tests' / 'data'
                              / 'p05_dependency_manifest.json').read_bytes()
            for repo_path in sorted(evidence.SOURCE_INPUT_ALLOWLIST | evidence.IMPLEMENTATION_SOURCE_ALLOWLIST):
                target = bundle / 'source' / repo_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(
                    phase_manifest if repo_path == 'tests/data/p05_dependency_manifest.json'
                    else (REPO_ROOT / repo_path).read_bytes()
                )
            # The ready parser also freezes the kill artifact under source/;
            # it is a ready-join source, not an allowlist member (the real
            # bundle's gap at this exact path is what its dependency gate now
            # rejects).
            kill_target = bundle / 'source' / 'tests' / 'fixtures' / 'artifacts' / 'Generic.Utils.KillProcess.yaml'
            kill_target.parent.mkdir(parents=True, exist_ok=True)
            kill_target.write_bytes(
                (REPO_ROOT / 'tests' / 'fixtures' / 'artifacts' / 'Generic.Utils.KillProcess.yaml').read_bytes()
            )
            source_rows = []
            for repo_path in sorted(evidence.SOURCE_INPUT_ALLOWLIST):
                target = bundle / 'source' / repo_path
                payload = target.read_bytes()
                source_rows.append({
                    'repo_path': repo_path,
                    'blob': hashlib.sha1(f'blob {len(payload)}\0'.encode('ascii') + payload).hexdigest(),
                    'content': _ref(bundle, target),
                })
            implementation_rows = []
            for repo_path in sorted(evidence.IMPLEMENTATION_SOURCE_ALLOWLIST):
                target = bundle / 'source' / repo_path
                payload = target.read_bytes()
                implementation_rows.append({
                    'repo_path': repo_path,
                    'blob': hashlib.sha1(f'blob {len(payload)}\0'.encode('ascii') + payload).hexdigest(),
                    'content': _ref(bundle, target),
                })
            creation_metadata_path = bundle / 'creation' / 'creation-metadata.json'
            _write_json(creation_metadata_path, creation_metadata)
            activation = {
                'schema_version': 1,
                'kind': 'snapshot188-activation-evidence-v1',
                'workflow_id': evidence.WORKFLOW_ID,
                'candidate': evidence.SNAPSHOT_188,
                'checkpoint_marker': marker,
                'creation_metadata': _ref(bundle, creation_metadata_path),
                'initial': initial,
                'candidate_cycles': [cycle_one, cycle_two],
                'source_inputs': source_rows,
                'implementation_sources': implementation_rows,
            }
            activation_path = bundle / 'activation-evidence.json'
            _write_json(activation_path, activation)

            facts = evidence.verify_activation_bundle(activation_path, require_p05_layout=True)
            self.assertEqual(facts['candidate'], evidence.SNAPSHOT_188)
            self.assertEqual(facts['initial_run_id'], 'run-initial-synthetic')
            self.assertEqual(facts['cycle_run_ids'], ['run-cycle-one-synthetic', 'run-cycle-two-synthetic'])


if __name__ == '__main__':
    unittest.main()
