"""Unit contract tests for the schema2 P06 aggregate verifier."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

try:
    from . import p06_aggregate_reports as aggregate
except ImportError:
    import p06_aggregate_reports as aggregate


SNAPSHOT_186 = "Snapshot 186-Velociraptor-MCP网络部署基线"
SNAPSHOT_188 = "Snapshot 188-Velociraptor-MCP可恢复验收基线"
SCENARIOS = [
    "p06-compromise-scope",
    "p06-ransomware-root-cause",
    "p06-credential-lateral-movement",
    "p06-data-exfiltration",
    "p06-remediation-validation",
]


def canonical(value) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")


import hashlib


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def seal(run_dir, root):
    from tests.p06_package import member_inventory
    (run_dir/'package-manifest.json').write_bytes(canonical(member_inventory(run_dir,root)))
    return aggregate.package_hash(run_dir,root)


def build_report(scenario: str, index: int) -> dict:
    tools_document = [
        {"name": f"tool-{number:03d}", "inputSchema": {}, "outputSchema": {}} for number in range(130)
    ]
    tools_bytes = canonical(tools_document)
    session_id = f"session-{index}"
    instance_id = f"instance-{index}"
    observation_hash = sha_bytes(json.dumps({"obs": index}).encode("utf-8"))
    report = {
        "schema_version": 2,
        "scenario": scenario,
        "source_sha256": f"s{index:064d}"[-64:],
        "index_sha256": f"i{index:064d}"[-64:],
        "fixture_spec_sha256": "f" * 64,
        "fixture_instance_sha256": "g" * 64,
        "run_id": f"run-{index}",
        "transport": "streamable-http",
        "endpoint": "http://192.168.204.149:28790/mcp",
        "authorization_configured": True,
        "tools_schema_sha256": sha_bytes(tools_bytes),
        "snapshot_evidence_sha256": None,
        "mcp_session": {
            "id": session_id,
            "initialized_at": "2026-09-07T10:00:00+08:00",
            "closed_at": "2026-09-07T10:05:00+08:00",
        },
        "server_identity": {
            "computer_name": "DESKTOP-3FI41GR",
            "service_name": "mcp-velociraptor",
            "pid": 1000 + index,
            "process_start_time_utc": "2026-09-07T09:00:00+08:00",
            "instance_id": instance_id,
            "executable_sha256": "e" * 64,
        },
        "server_observation_sha256": observation_hash,
        "runner": {
            "pid": 2000 + index,
            "process_start_time_utc": "2026-09-07T09:30:00+08:00",
            "executable_sha256": "r" * 64,
        },
        "started_at": "2026-09-07T10:00:00+08:00",
        "ended_at": "2026-09-07T10:05:00+08:00",
        "duration_ms": 300000,
        "status": "success",
        "calls": [{"sequence": number} for number in range(1, 4)],
        "steps": [],
        "cleanup": [],
        "failure": None,
        "unexecuted_step_ids": [],
        "coverage": [
            {"scenario_id": scenario, "tool": f"tool-{number:03d}"} for number in range(129)
        ],
    }
    return report


def materialize_originals(root: Path, run_dir: Path, report: dict, restore: dict) -> None:
    """Synthetic unit fixtures carry actual bytes with the same join contract."""
    attempt = restore['restore_attempt_id']
    suffix = f'{int(run_dir.name.rsplit("-", 1)[1]):012d}'
    adoption_bundle = root / 'baseline-adoption' / f'123e4567-e89b-12d3-a456-{suffix}'
    adoption_bundle.mkdir(parents=True)
    adoption_path = adoption_bundle / 'adoption.json'
    adoption_path.write_bytes(canonical({
        'kind': 'user187-preparation-adoption-v1',
        'workflow_id': restore['workflow_id'],
    }))
    bundle = root / 'activation-188' / f'123e4567-e89b-12d4-a456-{suffix}'
    bundle.mkdir(parents=True)
    activation = {
        'candidate': SNAPSHOT_188, 'checkpoint_marker': restore['checkpoint_marker'],
        'workflow_id': restore['workflow_id'],
        'cycles': [{'restore_attempt_id': f'cycle-{i}', 'report_status': 'success'} for i in (1, 2)],
    }
    activation_path = bundle / 'activation-evidence.json'
    activation_path.write_bytes(canonical(activation))
    state = {
        'schema_version': 5, 'epoch': 6, 'phase': 'NETWORK_ACTIVE',
        'workflow_id': restore['workflow_id'],
        'active_snapshot': {'name': SNAPSHOT_188, 'checkpoint_marker': restore['checkpoint_marker']},
        'automatic_restore_allowlist': [SNAPSHOT_188],
        'baseline_evidence': {
            'evidence_path': adoption_path.relative_to(root).as_posix(),
            'evidence_sha256': sha_bytes(adoption_path.read_bytes()),
        },
        'activation_evidence': {
            'evidence_path': activation_path.relative_to(root).as_posix(),
            'evidence_sha256': sha_bytes(activation_path.read_bytes()),
        },
    }
    state_path = run_dir / 'canonical.json'
    state_path.write_bytes(canonical(state))
    restore['canonical_sha256'] = sha_bytes(state_path.read_bytes())
    records = {
        'canonical_readback': state_path,
        'baseline_adoption': adoption_path,
        'activation_evidence': activation_path,
    }
    for kind, value in {
        'snapshot_metadata': SNAPSHOT_188,
        'revert_operation': 'exit_code=0',
        'pre_start_marker': restore['checkpoint_marker'],
        'post_restore_hostname': 'DESKTOP-3FI41GR',
    }.items():
        path = run_dir / f'{kind}.json'
        path.write_bytes(canonical({'restore_attempt_id': attempt, 'raw': value}))
        records[kind] = path
    restore['restore_records'] = [
        {'kind': kind, 'path': path.relative_to(root).as_posix(), 'sha256': sha_bytes(path.read_bytes())}
        for kind, path in records.items()
    ]
    observation = {**report['server_identity'], 'observed_at': report['started_at']}
    raw = canonical(observation)
    (run_dir / 'server-observation.json').write_bytes(raw)
    report['server_observation_sha256'] = sha_bytes(raw)


class AggregateFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.evidence = root / "evidence"
        self.evidence.mkdir(parents=True)
        self.manifest = {
            "schema_version": 1,
            "scenario_ids": SCENARIOS,
            "tool_count": 129,
            "relations": [
                {"scenario_id": scenario, "tool": f"tool-{number:03d}"}
                for scenario in SCENARIOS
                for number in range(129)
            ],
        }
        self.ledger_rows = []
        self.reports = []
        for index, scenario in enumerate(SCENARIOS, start=1):
            report = build_report(scenario, index)
            run_dir = self.evidence / f"run-{index}"
            run_dir.mkdir()
            tools_document = [
                {"name": f"tool-{number:03d}", "inputSchema": {}, "outputSchema": {}}
                for number in range(130)
            ]
            (run_dir / "tools-schema.json").write_bytes(canonical(tools_document))
            (run_dir / 'tools-list.json').write_bytes(canonical({'tools':tools_document}))
            snapshot_evidence = {
                "restore": {
                    "workflow_id": "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2",
                    "run_id": report["run_id"],
                    "restore_attempt_id": f"restore-{index}",
                    "snapshot_stage": "P06_ACTIVE",
                    "snapshot_name": SNAPSHOT_188,
                    "checkpoint_marker": f"win10h2-MalBox-20241110-Snapshot10{index}.vmsn",
                    "canonical_schema_version": 5,
                    "canonical_epoch": 6,
                    "canonical_phase": "NETWORK_ACTIVE",
                    "canonical_sha256": "c" * 64,
                    "restore_records": [],
                },
                "scenario_id": scenario,
                "source_sha256": report["source_sha256"],
                "index_sha256": report["index_sha256"],
                "mcp_session_id": report["mcp_session"]["id"],
                "server_instance_id": report["server_identity"]["instance_id"],
                "server_observation_sha256": report["server_observation_sha256"],
            }
            materialize_originals(self.evidence, run_dir, report, snapshot_evidence['restore'])
            snapshot_evidence['server_observation_sha256'] = report['server_observation_sha256']
            evidence_bytes = canonical(snapshot_evidence)
            (run_dir / "snapshot-evidence.json").write_bytes(evidence_bytes)
            report["snapshot_evidence_sha256"] = sha_bytes(evidence_bytes)
            report_bytes = canonical(report)
            report_path = run_dir / "report.json"
            report_path.write_bytes(report_bytes)
            self.reports.append(report)
            self.ledger_rows.append(
                {
                    "monotonic_attempt": index,
                    "scenario": scenario,
                    "status": "success",
                    "report_relative_path": f"run-{index}/report.json",
                    "report_sha256": sha_bytes(report_bytes),
                    "package_sha256": seal(run_dir, self.evidence),
                    'manifest_relative_path':f'run-{index}/package-manifest.json',
                    **aggregate.ledger_identity(report),
                    'received_at': report['ended_at'],
                    "source_sha256": report["source_sha256"],
                    "index_sha256": report["index_sha256"],
                    "fixture_instance_sha256": report["fixture_instance_sha256"],
                    "fixture_spec_sha256": report["fixture_spec_sha256"],
                    "tools_schema_sha256": report["tools_schema_sha256"],
                }
            )
        # One earlier failed attempt (attempt 1) with its own package bytes.
        history_dir = self.evidence / "run-0"
        history_dir.mkdir()
        history_report = build_report(SCENARIOS[0], 0)
        history_report["status"] = "failed"
        history_report["failure"] = {
            "type": "ScenarioFailure",
            "step_id": "d042-start",
            "message": "history fixture failure",
        }
        history_bytes = canonical(history_report)
        (history_dir / "report.json").write_bytes(history_bytes)
        (history_dir / "tools-schema.json").write_bytes(b"{}\n")
        self.ledger_rows.insert(
            0,
            {
                "monotonic_attempt": 1,
                "scenario": SCENARIOS[0],
                "status": "failed",
                "report_relative_path": "run-0/report.json",
                "report_sha256": sha_bytes(history_bytes),
                "package_sha256": seal(history_dir,self.evidence),
                'manifest_relative_path':'run-0/package-manifest.json',
                **aggregate.ledger_identity(history_report),
                'received_at':history_report['ended_at'],
                "source_sha256": history_report["source_sha256"],
                "index_sha256": history_report["index_sha256"],
                "fixture_instance_sha256": history_report["fixture_instance_sha256"],
                "fixture_spec_sha256": history_report["fixture_spec_sha256"],
                "tools_schema_sha256": history_report["tools_schema_sha256"],
            },
        )
        for position, row in enumerate(self.ledger_rows, start=1):
            row["monotonic_attempt"] = position
            row['manifest_sha256'] = row['package_sha256']
        for index in range(len(SCENARIOS)):
            self.reports[index]["run_id"] = f"run-{index + 1}"
        (self.evidence / "ledger.jsonl").write_text(
            "\n".join(json.dumps(row) for row in self.ledger_rows) + "\n", encoding="utf-8"
        )
        self.attempts = list(range(1, len(self.ledger_rows) + 1))
        self.selected_attempts = {
            scenario: 2 + index for index, scenario in enumerate(SCENARIOS)
        }
        self.selection = {
            "schema_version": 2,
            "all_attempts": self.attempts,
            "selected": {
                scenario: {
                    **{key:self.ledger_rows[self.selected_attempts[scenario]-1][key] for key in
                       ('manifest_relative_path','manifest_sha256','package_sha256')},
                    "monotonic_attempt": self.selected_attempts[scenario],
                    "report_sha256": self.ledger_rows[self.selected_attempts[scenario] - 1][
                        "report_sha256"
                    ],
                }
                for scenario in SCENARIOS
            },
            "rejected": {"1": "history fixture failure retained for attempt completeness"},
        }
        (self.evidence / "selection.json").write_text(
            json.dumps(self.selection), encoding="utf-8"
        )

    def rewrite_report(self, index: int, mutate) -> None:
        report_path = self.evidence / f"run-{index}" / "report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        mutate(report)
        payload = canonical(report)
        report_path.write_bytes(payload)
        row = self.ledger_rows[self.selected_attempts[SCENARIOS[index - 1]] - 1]
        row["report_sha256"] = sha_bytes(payload)
        row["package_sha256"] = seal(report_path.parent, self.evidence)
        row['manifest_sha256'] = row['package_sha256']
        row.update(aggregate.ledger_identity(report))
        self.selection["selected"][SCENARIOS[index - 1]]["report_sha256"] = row["report_sha256"]
        self.selection['selected'][SCENARIOS[index-1]].update({key:row[key] for key in
                                                            ('manifest_relative_path','manifest_sha256','package_sha256')})
        self.flush_side_files()

    def flush_side_files(self) -> None:
        (self.evidence / "ledger.jsonl").write_text(
            "\n".join(json.dumps(row) for row in self.ledger_rows) + "\n", encoding="utf-8"
        )
        (self.evidence / "selection.json").write_text(
            json.dumps(self.selection), encoding="utf-8"
        )

    def run_aggregate(self) -> dict:
        # These synthetic fixtures isolate byte/identity binding. Resource
        # admission has its own fixtures. Snapshot188 transcript parsing stays
        # fail-closed in production, so it is deliberately stubbed here rather
        # than treated as a host-side P06 acceptance run.
        with (patch.object(aggregate, 'verify_resource_evidence') as resource_verifier,
              patch.object(aggregate, 'verify_restore', return_value={})):
            result = aggregate.aggregate(
                evidence_root=self.evidence,
                ledger_path=self.evidence / "ledger.jsonl",
                selection_path=self.evidence / "selection.json",
                manifest_path=self._manifest_path(),
            )
            if resource_verifier.call_count!=5:
                raise AssertionError('aggregation bypassed a scenario resource verifier')
            return result

    def _manifest_path(self) -> Path:
        path = self.root / "manifest.json"
        path.write_text(json.dumps(self.manifest), encoding="utf-8")
        return path


class AggregateSchema2Tests(unittest.TestCase):
    def test_resource_verifier_failure_prevents_aggregate_success(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AggregateFixture(Path(directory))
            with (patch.object(aggregate, 'verify_resource_evidence',
                               side_effect=ValueError('missing original resource reading')),
                  patch.object(aggregate, 'verify_restore', return_value={})):
                with self.assertRaisesRegex(aggregate.AggregateError,
                                            'missing original resource reading'):
                    aggregate.aggregate(
                        evidence_root=fixture.evidence,
                        ledger_path=fixture.evidence / 'ledger.jsonl',
                        selection_path=fixture.evidence / 'selection.json',
                        manifest_path=fixture._manifest_path(),
                    )

    def test_missing_original_record_is_rejected_even_when_report_hash_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AggregateFixture(Path(directory))
            (fixture.evidence / 'run-1' / 'revert_operation.json').unlink()
            with self.assertRaises((aggregate.AggregateError, OSError)):
                fixture.run_aggregate()

    def test_placeholder_canonical_hash_is_rejected_even_with_rehashed_package(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AggregateFixture(Path(directory))
            path = fixture.evidence / 'run-1' / 'snapshot-evidence.json'
            evidence = json.loads(path.read_text(encoding='utf-8'))
            evidence['restore']['canonical_sha256'] = 'a' * 64
            path.write_bytes(canonical(evidence))
            fixture.rewrite_report(1, lambda r: r.update(snapshot_evidence_sha256=sha_bytes(path.read_bytes())))
            with (patch.object(aggregate, 'verify_resource_evidence'),
                  patch.object(aggregate, 'verify_restore', side_effect=ValueError('canonical SHA differs'))):
                with self.assertRaisesRegex(aggregate.AggregateError, 'canonical SHA'):
                    aggregate.aggregate(
                        evidence_root=fixture.evidence,
                        ledger_path=fixture.evidence / 'ledger.jsonl',
                        selection_path=fixture.evidence / 'selection.json',
                        manifest_path=fixture._manifest_path(),
                    )

    def test_server_observation_cannot_be_replaced_by_matching_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AggregateFixture(Path(directory))
            path = fixture.evidence / 'run-1' / 'server-observation.json'
            observation = json.loads(path.read_text(encoding='utf-8'))
            observation['pid'] += 1
            path.write_bytes(canonical(observation))
            fixture.rewrite_report(1, lambda r: None)
            with self.assertRaisesRegex(aggregate.AggregateError, 'observation bytes'):
                fixture.run_aggregate()

    def test_recursive_package_hash_includes_nested_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'nested').mkdir()
            original = aggregate.package_hash(path)
            (path / 'nested' / 'evidence.txt').write_text('raw evidence')
            self.assertNotEqual(original, aggregate.package_hash(path))

    def test_valid_five_binding_fixtures_aggregate_with_separate_resource_verifier(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AggregateFixture(Path(directory))
            result = fixture.run_aggregate()
            self.assertEqual(result["status"], "success")
            self.assertEqual(result["schema_version"], 2)
            self.assertEqual(result["relation_count"], 645)
            self.assertEqual(result["distinct_restore_attempt_count"], 5)
            self.assertEqual(result["distinct_session_count"], 5)

    def test_schema1_and_stdio_reports_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AggregateFixture(Path(directory))
            fixture.rewrite_report(1, lambda report: report.__setitem__("schema_version", 1))
            with self.assertRaises(aggregate.AggregateError):
                fixture.run_aggregate()

            fixture2 = AggregateFixture(Path(tempfile.mkdtemp()))
            fixture2.rewrite_report(
                2,
                lambda report: (
                    report.__setitem__("transport", "stdio"),
                    report.__setitem__("endpoint", None),
                ),
            )
            with self.assertRaises(aggregate.AggregateError):
                fixture2.run_aggregate()

    def test_tools_schema_and_snapshot_evidence_bindings(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AggregateFixture(Path(directory))
            fixture.rewrite_report(
                3, lambda report: report.__setitem__("tools_schema_sha256", "0" * 64)
            )
            with self.assertRaises(aggregate.AggregateError):
                fixture.run_aggregate()

            fixture2 = AggregateFixture(Path(tempfile.mkdtemp()))
            fixture2.rewrite_report(
                4, lambda report: report.__setitem__("snapshot_evidence_sha256", "0" * 64)
            )
            with self.assertRaises(aggregate.AggregateError):
                fixture2.run_aggregate()

    def test_legacy_snapshot186_or_schema4_report_cannot_impersonate_the_active_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AggregateFixture(Path(directory))
            run_dir = fixture.evidence / "run-5"
            evidence = json.loads((run_dir / "snapshot-evidence.json").read_text(encoding="utf-8"))
            evidence["restore"]["snapshot_name"] = SNAPSHOT_186
            payload = canonical(evidence)
            (run_dir / "snapshot-evidence.json").write_bytes(payload)
            fixture.rewrite_report(
                5, lambda report: report.__setitem__("snapshot_evidence_sha256", sha_bytes(payload))
            )
            with self.assertRaises(aggregate.AggregateError):
                fixture.run_aggregate()

        with tempfile.TemporaryDirectory() as directory:
            fixture = AggregateFixture(Path(directory))
            run_dir = fixture.evidence / "run-5"
            evidence = json.loads((run_dir / "snapshot-evidence.json").read_text(encoding="utf-8"))
            evidence["restore"]["canonical_schema_version"] = 4
            evidence["restore"]["canonical_epoch"] = 5
            payload = canonical(evidence)
            (run_dir / "snapshot-evidence.json").write_bytes(payload)
            fixture.rewrite_report(
                5, lambda report: report.__setitem__("snapshot_evidence_sha256", sha_bytes(payload))
            )
            with self.assertRaises(aggregate.AggregateError):
                fixture.run_aggregate()

    def test_reused_restore_attempt_across_reports_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AggregateFixture(Path(directory))
            run_dir = fixture.evidence / "run-2"
            evidence = json.loads((run_dir / "snapshot-evidence.json").read_text(encoding="utf-8"))
            evidence["restore"]["restore_attempt_id"] = "restore-1"
            evidence["restore"]["run_id"] = fixture.reports[1]["run_id"]
            payload = canonical(evidence)
            (run_dir / "snapshot-evidence.json").write_bytes(payload)
            fixture.rewrite_report(
                2, lambda report: report.__setitem__("snapshot_evidence_sha256", sha_bytes(payload))
            )
            with self.assertRaises(aggregate.AggregateError):
                fixture.run_aggregate()


if __name__ == "__main__":
    unittest.main()
