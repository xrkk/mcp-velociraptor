"""Windows-pack mocks for P05 phase source/report closure.

The fixtures deliberately stop before P05 restore originals and the terminal raw
activation predicates.  They exercise only the cross-platform byte/structure
parser; running them is Windows-gated because the source runner is a Windows
acceptance component.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from . import p06_evidence as evidence
except ImportError:
    import p06_evidence as evidence


REPO_ROOT = Path(__file__).resolve().parents[1]
UTC_START = '2026-09-14T00:00:00Z'
UTC_END = '2026-09-14T00:01:00Z'


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')
    )


def _reference(root: Path, path: Path) -> dict[str, object]:
    return {
        'path': path.relative_to(root).as_posix(),
        'size': path.stat().st_size,
        'sha256': _sha256(path),
    }


class P05PhaseFixture:
    """One fully closed synthetic report using the frozen initial scenario."""

    scenario_id = 'p05-flow-triage-repair-initial'
    stage = 'P05_REPAIR_INITIAL'
    snapshot = evidence.SNAPSHOT_187

    def __init__(self, root: Path, scenario_id: str = 'p05-flow-triage-repair-initial') -> None:
        self.root = root
        self.run_dir = root / 'runs' / 'synthetic-p05-initial'
        self.report_path = self.run_dir / 'report.json'
        self.snapshot_path = root / 'snapshots' / 'synthetic-p05-initial.json'
        self.source_copies = self._copy_sources()
        self.scenario_id = scenario_id
        fixed = evidence.P05_SCENARIOS[scenario_id]
        self.stage = fixed['stage']
        self.snapshot = fixed['snapshot']
        # Frozen inputs are UTF-8 regardless of the guest's ANSI code page.
        self.scenario = json.loads(self.source_copies[evidence.P05_SCENARIOS[self.scenario_id]['path']].read_text(encoding='utf-8'))
        self.fixture = {
            'schema_version': 1,
            'fixture_spec_sha256': evidence.P05_FIXTURE_SPEC_SHA256,
            'workflow_id': evidence.WORKFLOW_ID,
            'attempt_id': 'synthetic-attempt',
            'ownership_marker': 'synthetic-owner',
            'hostname': 'DESKTOP-3FI41GR',
            'fixture_root': r'C:\\VelociraptorMCP\\fixtures-p05',
            'files': [
                {'path': r'C:\\VelociraptorMCP\\fixtures-p05\\ascii.txt'},
                {'path': r'C:\\VelociraptorMCP\\fixtures-p05\\utf8 空格.txt'},
            ],
            'registry': {},
            'event': {},
            'task': {},
            'process': {},
        }
        _write_json(self.run_dir / 'fixture-instance.json', self.fixture)
        self.observation_path = self.run_dir / 'server-observation.json'
        _write_json(self.observation_path, {
            'computer_name': 'DESKTOP-3FI41GR',
            'service_name': 'mcp-velociraptor',
            'pid': 42,
            'process_start_time_utc': '2026-09-13T23:59:58Z',
            'instance_id': 'synthetic-instance',
            'executable_sha256': 'b' * 64,
            'observed_at': '2026-09-13T23:59:59Z',
        })
        self._write_tools()
        self.calls, self.steps = self._calls_and_steps()
        self._write_snapshot()
        self.report = self._report()
        self._write_report()
        self._write_phase_support_files()

    def _copy_sources(self) -> dict[str, Path]:
        copies: dict[str, Path] = {}
        source_paths = {
            evidence.P05_INDEX_SOURCE,
            evidence.P05_FIXTURE_SOURCE,
            evidence.P05_SCHEMA_SOURCE,
            *(value['path'] for value in evidence.P05_SCENARIOS.values()),
        }
        for repo_path in source_paths:
            target = self.root / 'source' / repo_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((REPO_ROOT / repo_path).read_bytes())
            copies[repo_path] = target
        return copies

    def _write_tools(self) -> None:
        names = sorted({step['tool'] for step in self.scenario['steps']})
        names.extend(f'synthetic_tool_{number:03d}' for number in range(130 - len(names)))
        listing = {
            'tools': [
                {'name': name, 'inputSchema': {'type': 'object'}}
                for name in names
            ]
        }
        _write_json(self.run_dir / 'tools-list.json', listing)
        normalized = [
            {'name': tool['name'], 'inputSchema': tool['inputSchema'], 'outputSchema': None}
            for tool in listing['tools']
        ]
        normalized.sort(key=lambda item: item['name'])
        (self.run_dir / 'tools-schema.json').write_bytes(
            (json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')
        )

    def _calls_and_steps(self) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        from tests.scenario_runner import evaluate_assertion, resolve_value

        calls: list[dict[str, object]] = []
        steps: list[dict[str, object]] = []
        completed: dict[str, object] = {}
        for sequence, source_step in enumerate(self.scenario['steps'], start=1):
            arguments = resolve_value(source_step['arguments'], completed, self.fixture)
            if source_step['tool'] in {'collect_file', 'collect_forensic_triage'}:
                structured = {'flow_id': f'flow-{source_step["id"]}'}
            elif source_step['tool'] == 'get_flow_status':
                structured = {'state': 'FINISHED'}
            else:
                structured = {'data': [{}]}
            result = {'isError': False, 'structuredContent': structured}
            assertion_spec = source_step.get('repeat_until', {}).get('assertions', source_step['assertions'])
            evaluated = [evaluate_assertion(item, result, self.fixture) for item in assertion_spec]
            second = sequence * 2
            calls.append({
                'arguments': arguments,
                'attempt': 1,
                'sequence': sequence,
                'is_error': False,
                'step_id': source_step['id'],
                'structured': structured,
                'mcp_result': result,
                'tool': source_step['tool'],
                'started_at': f'2026-09-14T00:00:{second:02d}Z',
                'ended_at': f'2026-09-14T00:00:{second + 1:02d}Z',
                'duration_ms': 1,
            })
            steps.append({
                'assertions': evaluated,
                'id': source_step['id'],
                'kind': 'tool',
                'passed': True,
            })
            completed[source_step['id']] = result
        return calls, steps

    def _write_snapshot(self) -> None:
        _write_json(self.snapshot_path, {
            'restore': {},
            'scenario_id': self.scenario_id,
            'source_sha256': _sha256(self.source_copies[evidence.P05_SCENARIOS[self.scenario_id]['path']]),
            'index_sha256': _sha256(self.source_copies[evidence.P05_INDEX_SOURCE]),
            'mcp_session_id': 'synthetic-session',
            'server_instance_id': 'synthetic-instance',
            'server_observation_sha256': _sha256(self.observation_path),
        })

    def _report(self) -> dict[str, object]:
        fixture_path = self.run_dir / 'fixture-instance.json'
        tools_schema = self.run_dir / 'tools-schema.json'
        return {
            'schema_version': 2,
            'scenario': self.scenario_id,
            'source_sha256': _sha256(self.source_copies[evidence.P05_SCENARIOS[self.scenario_id]['path']]),
            'index_sha256': _sha256(self.source_copies[evidence.P05_INDEX_SOURCE]),
            'fixture_spec_sha256': evidence.P05_FIXTURE_SPEC_SHA256,
            'fixture_instance_sha256': _sha256(fixture_path),
            'run_id': 'synthetic-p05-run',
            'transport': 'streamable-http',
            'endpoint': 'http://192.168.204.232:28790/mcp',
            'authorization_configured': True,
            'tools_schema_sha256': _sha256(tools_schema),
            'snapshot_evidence_sha256': _sha256(self.snapshot_path),
            'mcp_session': {
                'id': 'synthetic-session',
                'initialized_at': '2026-09-14T00:00:01Z',
                'closed_at': '2026-09-14T00:00:59Z',
            },
            'server_identity': {
                'computer_name': 'DESKTOP-3FI41GR',
                'service_name': 'mcp-velociraptor',
                'pid': 42,
                'process_start_time_utc': '2026-09-13T23:59:58Z',
                'instance_id': 'synthetic-instance',
                'executable_sha256': 'b' * 64,
            },
            'server_observation_sha256': _sha256(self.observation_path),
            'runner': {'pid': 100, 'process_start_time_utc': '2026-09-13T23:59:57Z',
                       'executable_sha256': 'd' * 64},
            'started_at': UTC_START,
            'ended_at': UTC_END,
            'duration_ms': 60_000,
            'status': 'success',
            'calls': self.calls,
            'steps': self.steps,
            'cleanup': [],
            'failure': None,
            'unexecuted_step_ids': [],
            # Same semantics as the real runner: one row per distinct tool
            # actually called by this scenario run.
            'coverage': [
                {'scenario_id': self.scenario_id, 'tool': tool}
                for tool in sorted({call['tool'] for call in self.calls})
            ],
        }

    def _write_report(self) -> None:
        _write_json(self.report_path, self.report)

    def _write_phase_support_files(self) -> None:
        self.support: dict[str, Path] = {}
        for name in {'ready', 'dependency_acceptance', 'entry_gate', 'network_evidence', 'package_manifest'}:
            path = self.root / 'phase-support' / f'{name}.json'
            _write_json(path, {'synthetic': name})
            self.support[name] = path

    def phase(self) -> dict[str, object]:
        phase = {
            'restore_attempt_id': 'synthetic-restore-attempt',
            'run_id': 'synthetic-p05-run',
            'report': _reference(self.root, self.report_path),
            'snapshot_evidence': _reference(self.root, self.snapshot_path),
        }
        phase.update({name: _reference(self.root, path) for name, path in self.support.items()})
        return phase

    def verify(self) -> None:
        with patch.object(
            evidence,
            '_verify_phase_restore',
            return_value=({}, ('synthetic/adoption.json', 'c' * 64, 'synthetic-adoption')),
        ):
            evidence._verify_phase(
                self.root,
                self.phase(),
                self.scenario_id,
                self.stage,
                self.snapshot,
                {},
                self.source_copies,
            )


@unittest.skipUnless(os.name == 'nt', 'Windows-only P05/P06 acceptance mock pack')
class ActivationStructureWindowsTests(unittest.TestCase):
    def _fresh(self, scenario_id: str = P05PhaseFixture.scenario_id) -> tuple[tempfile.TemporaryDirectory, P05PhaseFixture]:
        directory = tempfile.TemporaryDirectory()
        return directory, P05PhaseFixture(Path(directory.name), scenario_id)

    def test_accepts_a_closed_synthetic_fixed_p05_phase(self) -> None:
        for scenario_id in evidence.P05_SCENARIOS:
            with self.subTest(scenario_id=scenario_id):
                directory, fixture = self._fresh(scenario_id)
                with directory:
                    fixture.verify()

    def test_rejects_empty_missing_extra_or_mismatched_execution_rows(self) -> None:
        mutations = {
            'empty_calls': lambda fixture: fixture.report.update({'calls': [], 'steps': []}),
            'missing_call': lambda fixture: fixture.report['calls'].pop(),
            'extra_call': lambda fixture: fixture.report['calls'].append(copy.deepcopy(fixture.report['calls'][-1])),
            'resolved_argument': lambda fixture: fixture.report['calls'][0]['arguments'].update({'path': 'other'}),
            'sdk_projection': lambda fixture: fixture.report['calls'][0]['mcp_result'].update({'isError': True}),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                directory, fixture = self._fresh()
                with directory:
                    mutate(fixture)
                    fixture._write_report()
                    with self.assertRaises(evidence.EvidenceError):
                        fixture.verify()

    def test_rejects_early_repeat_success_and_invalid_time_or_identity_join(self) -> None:
        def early_success(fixture: P05PhaseFixture) -> None:
            duplicate = copy.deepcopy(fixture.report['calls'][1])
            fixture.report['calls'].insert(1, duplicate)
            for sequence, call in enumerate(fixture.report['calls'], start=1):
                call['sequence'] = sequence
                second = sequence * 2
                call['started_at'] = f'2026-09-14T00:00:{second:02d}Z'
                call['ended_at'] = f'2026-09-14T00:00:{second + 1:02d}Z'
            fixture.report['calls'][1]['attempt'] = 1
            fixture.report['calls'][2]['attempt'] = 2

        def call_outside_report(fixture: P05PhaseFixture) -> None:
            fixture.report['calls'][0]['started_at'] = '2026-09-13T23:59:59Z'

        def missing_session(fixture: P05PhaseFixture) -> None:
            fixture.report['mcp_session']['id'] = ''

        def snapshot_mismatch(fixture: P05PhaseFixture) -> None:
            snapshot = json.loads(fixture.snapshot_path.read_text(encoding='utf-8'))
            snapshot['server_instance_id'] = 'different-instance'
            _write_json(fixture.snapshot_path, snapshot)
            fixture.report['snapshot_evidence_sha256'] = _sha256(fixture.snapshot_path)

        mutations = {
            'early_repeat_success': early_success,
            'call_outside_report': call_outside_report,
            'missing_session': missing_session,
            'snapshot_identity_join': snapshot_mismatch,
            'session_precedes_report': lambda fixture: fixture.report['mcp_session'].update(
                {'initialized_at': '2026-09-13T23:59:59Z'}),
            'session_outlasts_report': lambda fixture: fixture.report['mcp_session'].update(
                {'closed_at': '2026-09-14T00:01:01Z'}),
            'wrong_service': lambda fixture: fixture.report['server_identity'].update(
                {'service_name': 'other-service'}),
            'wrong_endpoint': lambda fixture: fixture.report.update(
                {'endpoint': 'http://127.0.0.1:8000/mcp'}),
            'boolean_sequence': lambda fixture: fixture.report['calls'][0].update({'sequence': True}),
            'invalid_runner': lambda fixture: fixture.report.update({'runner': {}}),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                directory, fixture = self._fresh()
                with directory:
                    mutate(fixture)
                    fixture._write_report()
                    with self.assertRaises(evidence.EvidenceError):
                        fixture.verify()

    def test_rejects_mutated_frozen_index_or_fixture_instance_bytes(self) -> None:
        for label, mutate in {
            'fixed_index': lambda fixture: fixture.source_copies[evidence.P05_INDEX_SOURCE].write_text('{}', encoding='utf-8'),
            'fixture_instance': lambda fixture: fixture.run_dir.joinpath('fixture-instance.json').write_text('{}', encoding='utf-8'),
        }.items():
            with self.subTest(label=label):
                directory, fixture = self._fresh()
                with directory:
                    mutate(fixture)
                    with self.assertRaises(evidence.EvidenceError):
                        fixture.verify()


if __name__ == '__main__':
    unittest.main()
