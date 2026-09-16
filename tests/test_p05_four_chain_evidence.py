"""Windows-gated mock originals for the P05 three-chain parser.

These fixtures exercise byte/reference and JSON-RPC joins only.  They neither
claim that a Windows Flow ran nor bypass the final network-window fail-closed
gate.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import p05_four_chain_evidence as three
from tests import p05_real_acceptance as acceptance


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode())


def _ref(root: Path, path: Path) -> dict[str, object]:
    return {
        'path': path.relative_to(root).as_posix(),
        'size': path.stat().st_size,
        'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
    }


class ThreeChainFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.evidence_dir = root / 'three'
        self.evidence_path = self.evidence_dir / 'p05-real-acceptance.json'
        self.ready_path = root / 'ready.json'
        self.ready = {
            'workflow_id': three.WORKFLOW_ID,
            'restore_attempt_id': 'p05-synthetic',
            'run_id': 'run-synthetic',
        }
        _write(self.ready_path, self.ready)
        self.calls: dict[str, dict] = {}
        self.sdk: list[dict] = []
        self._next_id = 3
        self._sdk_pair(1, 'initialize', {}, {'protocolVersion': '2025-03-26'})
        self._sdk_pair(2, 'tools/list', {}, {'tools': [{} for _ in range(130)]})
        self._build_calls()
        self._write_raw()
        self.evidence = self._evidence()
        self.write_evidence()

    def _sdk_pair(self, request_id: int, method: str, params: dict, result: dict,
                  request_at: str = '2026-09-14T00:00:01Z', response_at: str = '2026-09-14T00:00:02Z') -> None:
        sequence = len(self.sdk) + 1
        self.sdk.append({
            'sequence': sequence,
            'direction': 'client_to_server',
            'started_at': request_at,
            'ended_at': request_at,
            'message': {'jsonrpc': '2.0', 'id': request_id, 'method': method, 'params': params},
        })
        self.sdk.append({
            'sequence': sequence + 1,
            'direction': 'server_to_client',
            'started_at': response_at,
            'ended_at': response_at,
            'message': {'jsonrpc': '2.0', 'id': request_id, 'result': result},
        })

    def _call(self, label: str, tool: str, arguments: dict, structured: dict) -> None:
        result = {'isError': False, 'structuredContent': structured}
        request_id = self._next_id
        # The raw SDK exchange happens inside the call's own UTC window.
        self._sdk_pair(request_id, 'tools/call', {'name': tool, 'arguments': arguments}, result,
                       request_at='2026-09-14T00:00:10Z', response_at='2026-09-14T00:00:11Z')
        self._next_id += 1
        self.calls[label] = {
            'tool': tool,
            'arguments': arguments,
            'result': {'is_error': False, 'structured': structured},
            'started_at': '2026-09-14T00:00:10Z',
            'ended_at': '2026-09-14T00:00:11Z',
            'mcp_result': result,
            'sdk_request_id': request_id,
        }

    def _flow(self, prefix: str, flow_id: str, states: tuple[str, ...] = ('FINISHED',)) -> None:
        for index, state in enumerate(states):
            self._call(f'{prefix}-poll-{index:03d}', 'get_flow_status', {'flow_id': flow_id}, {'state': state})
        self.flow_states.setdefault(flow_id, []).extend(states)

    def _build_calls(self) -> None:
        self.flow_states: dict[str, list[str]] = {}
        self._call('autoruns', 'Windows.Sysinternals.Autoruns', {}, {'flow_id': 'F-auto'})
        self._flow('autoruns', 'F-auto')
        self._call('autoruns-results', 'get_flow_results', {'flow_id': 'F-auto', 'page_size': 10}, {'data': [{'Source': 'Autoruns'}]})
        self._call('triage', 'collect_forensic_triage', {}, {'flow_id': 'F-triage'})
        self._flow('triage', 'F-triage')
        self._call('triage-results', 'get_flow_results', {'flow_id': 'F-triage', 'page_size': 10}, {'data': [{'Source': 'Triage'}]})
        self._call('triage-files', 'list_flow_files', {'flow_id': 'F-triage'}, {'data': []})
        self._call('kill-process', 'kill_process', {'pid': 300}, {'flow_id': 'F-kill'})
        self._flow('kill', 'F-kill')
        self._call('kill-results', 'get_flow_results', {'flow_id': 'F-kill', 'page_size': 10}, {'data': [{'Pid': 300, 'Killed': 300}]})

    def _command(self, label: str, round_id: str, argv: list[str], stdout: str) -> dict:
        return {
            'schema_version': 1,
            'kind': 'p05-command-observation-v1',
            'label': label,
            'round_id': round_id,
            'command': {'argv': argv},
            'started_at': '2026-09-14T00:00:30Z',
            'ended_at': '2026-09-14T00:00:31Z',
            'exit_code': 0,
            'stdout': stdout,
            'stderr': '',
        }

    def _write_raw(self) -> None:
        target = {
            'ProcessId': 300, 'ParentProcessId': 42, 'Name': 'python.exe',
            'CreationDate': '2026-09-14T00:00:00Z',
            'CommandLine': three.WORKFLOW_ID + '|p05-synthetic',
        }
        shared = [
            {'ProcessId': 0, 'ParentProcessId': 0, 'Name': 'System Idle Process', 'CreationDate': '2026-09-01T00:00:00Z'},
            {'ProcessId': 4, 'ParentProcessId': 0, 'Name': 'System', 'CreationDate': '2026-09-01T00:00:00Z'},
            {'ProcessId': 99, 'ParentProcessId': 4, 'Name': 'powershell.exe', 'CreationDate': '2026-09-01T00:00:00Z'},
            {'ProcessId': 100, 'ParentProcessId': 99, 'Name': 'python.exe', 'CreationDate': '2026-09-01T00:00:00Z'},
            {'ProcessId': 42, 'ParentProcessId': 99, 'Name': 'powershell.exe', 'CreationDate': '2026-09-01T00:00:00Z'},
            {'ProcessId': 200, 'ParentProcessId': 99, 'Name': 'velociraptor.exe', 'CreationDate': '2026-09-01T00:00:00Z'},
            {'ProcessId': 201, 'ParentProcessId': 99, 'Name': 'velociraptor-client.exe', 'CreationDate': '2026-09-01T00:00:00Z'},
        ]
        commands = {
            'kill-pre-processes': ('kill-pre', three._expected_powershell(acceptance.PS_PROCESS_SNAPSHOT % 300), json.dumps([*shared, target])),
            'kill-post-target': ('kill-post', three._expected_powershell(acceptance.PS_PROCESS_IDENTITY % 300), 'null'),
            'kill-post-processes': ('kill-post', three._expected_powershell(acceptance.PS_PROCESS_SNAPSHOT % -1), json.dumps(shared)),
        }
        self.raw_observations = {}
        for label, (round_id, argv, stdout) in commands.items():
            path = self.evidence_dir / 'raw' / f'{label}.json'
            _write(path, self._command(label, round_id, argv, stdout))
            self.raw_observations[label] = _ref(self.evidence_dir, path)
        sdk = self.evidence_dir / 'sdk-messages.ndjson'
        sdk.parent.mkdir(parents=True, exist_ok=True)
        sdk.write_text('\n'.join(json.dumps(row, sort_keys=True, separators=(',', ':')) for row in self.sdk) + '\n')
        stderr = self.evidence_dir / 'bridge-stderr.log'
        stderr.write_text('')
        self.raw_originals = {'sdk_messages': _ref(self.evidence_dir, sdk), 'stderr': _ref(self.evidence_dir, stderr)}

    def _evidence(self) -> dict:
        return {
            'schema': 'p05-real-acceptance-v1',
            'workflow_id': three.WORKFLOW_ID,
            'attempt_id': 'p05-synthetic',
            'started_at': '2026-09-14T00:00:00Z',
            'ended_at': '2026-09-14T00:01:00Z',
            'ok': True,
            'calls': self.calls,
            'flow_states': dict(self.flow_states),
            'owned_flows': ['F-auto', 'F-triage', 'F-kill'],
            'unsettled_owned_flows': [],
            'final_observation_failures': [],
            'active_flow_count_at_exit': 0,
            'raw_originals': self.raw_originals,
            'raw_observations': self.raw_observations,
        }

    def write_evidence(self) -> None:
        _write(self.evidence_path, self.evidence)

    def references(self) -> tuple[dict[str, object], dict[str, object]]:
        return _ref(self.root, self.evidence_path), _ref(self.root, self.ready_path)


@unittest.skipUnless(os.name == 'nt', 'CON002: behavioral tests execute only on Windows')
class ThreeChainEvidenceTests(unittest.TestCase):
    READY_FACTS = {
        'fixture_pid': 300,
        'fixture_creation_time_utc': '2026-09-14T00:00:00Z',
        'approved_guest_argv_pids': [99, 100],
    }

    def _verify(self, fixture: ThreeChainFixture):
        chains, ready = fixture.references()
        return three.verify_three_chain_core(fixture.root, chains, ready, {'run_id': 'run-synthetic'})

    def test_parses_full_local_three_chain_and_sdk_originals(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = ThreeChainFixture(Path(directory))
            with patch.object(three, 'verify_ready_raw_evidence', return_value=dict(self.READY_FACTS)):
                derived = self._verify(fixture)
        self.assertEqual(derived['flow_ids'][-1], 'F-kill')
        self.assertEqual(derived['fixture_pid'], 300)

    def test_kill_join_accepts_ready_facts_that_include_the_kill_target(self):
        # A genuine ready join returns the fixture target PID inside
        # approved_guest_argv_pids; the chain must still treat it as the kill
        # target, not as a protected process (CHK-028 join correction).
        with tempfile.TemporaryDirectory() as directory:
            fixture = ThreeChainFixture(Path(directory))
            facts = dict(self.READY_FACTS)
            facts['approved_guest_argv_pids'] = sorted(
                [*facts['approved_guest_argv_pids'], facts['fixture_pid']]
            )
            with patch.object(three, 'verify_ready_raw_evidence', return_value=facts):
                derived = self._verify(fixture)
        self.assertEqual(derived['fixture_pid'], 300)

    def test_rejects_sdk_result_substitution_process_absence_and_missing_raw_observation(self):
        mutations = {
            'sdk_result': lambda fixture: fixture.sdk[-1]['message'].update({'result': {'isError': True}}),
            'post_target_summary': lambda fixture: fixture.evidence['raw_observations'].pop('kill-post-target'),
            'sdk_id_swap': lambda fixture: fixture.calls['triage-poll-000'].update(
                sdk_request_id=fixture.calls['kill-poll-000']['sdk_request_id']
            ),
            'cleanup_failure': lambda fixture: fixture.evidence.update(
                {'final_observation_failures': [{'type': 'RuntimeError', 'message': 'x'}], 'ok': False}
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                fixture = ThreeChainFixture(Path(directory))
                mutate(fixture)
                if label == 'sdk_result':
                    sdk = fixture.evidence_dir / 'sdk-messages.ndjson'
                    sdk.write_text('\n'.join(json.dumps(row, sort_keys=True, separators=(',', ':')) for row in fixture.sdk) + '\n')
                    fixture.evidence['raw_originals']['sdk_messages'] = _ref(fixture.evidence_dir, sdk)
                fixture.write_evidence()
                with patch.object(three, 'verify_ready_raw_evidence', return_value=dict(self.READY_FACTS)), \
                        self.assertRaises(three.FourChainEvidenceError):
                    self._verify(fixture)

    def test_complete_entry_stays_closed_until_full_network_window_parser_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = ThreeChainFixture(Path(directory))
            chains, ready = fixture.references()
            with patch.object(three, 'verify_ready_raw_evidence', return_value=dict(self.READY_FACTS)), \
                    self.assertRaisesRegex(three.FourChainEvidenceError, 'network-window'):
                three.verify_three_chain_evidence(fixture.root, chains, ready, {'run_id': 'run-synthetic'})


if __name__ == '__main__':
    unittest.main()
