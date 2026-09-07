"""Unit contract tests for the schema2 P06 aggregate verifier."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

import p06_aggregate_reports as aggregate


SNAPSHOT_186 = "Snapshot 186-Velociraptor-MCP网络部署基线"
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
            {"scenario_id": scenario, "tool": f"tool-{number:03d}"} for number in range(130)
        ],
    }
    return report


class AggregateFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.evidence = root / "evidence"
        self.evidence.mkdir(parents=True)
        self.manifest = {
            "schema_version": 1,
            "scenario_ids": SCENARIOS,
            "tool_count": 130,
            "relations": [
                {"scenario_id": scenario, "tool": f"tool-{number:03d}"}
                for scenario in SCENARIOS
                for number in range(130)
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
            snapshot_evidence = {
                "restore": {
                    "workflow_id": "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2",
                    "run_id": report["run_id"],
                    "restore_attempt_id": f"restore-{index}",
                    "snapshot_stage": "P06_ACTIVE",
                    "snapshot_name": SNAPSHOT_186,
                    "checkpoint_marker": f"win10h2-MalBox-20241110-Snapshot10{index}.vmsn",
                    "canonical_schema_version": 3,
                    "canonical_epoch": 4,
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
                    "report_relative_path": f"run-{index}/report.json",
                    "report_sha256": sha_bytes(report_bytes),
                    "package_sha256": f"p{index:064d}"[-64:],
                    "source_sha256": report["source_sha256"],
                    "index_sha256": report["index_sha256"],
                    "fixture_instance_sha256": report["fixture_instance_sha256"],
                    "fixture_spec_sha256": report["fixture_spec_sha256"],
                    "tools_schema_sha256": report["tools_schema_sha256"],
                }
            )
        (self.evidence / "ledger.jsonl").write_text(
            "\n".join(json.dumps(row) for row in self.ledger_rows) + "\n", encoding="utf-8"
        )
        self.selection = {
            "schema_version": 1,
            "all_attempts": list(range(1, len(SCENARIOS) + 1)),
            "selected": {
                scenario: {
                    "monotonic_attempt": index,
                    "report_sha256": row["report_sha256"],
                }
                for index, (scenario, row) in enumerate(zip(SCENARIOS, self.ledger_rows), start=1)
            },
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
        row = self.ledger_rows[index - 1]
        row["report_sha256"] = sha_bytes(payload)
        self.selection["selected"][SCENARIOS[index - 1]]["report_sha256"] = row["report_sha256"]
        self.flush_side_files()

    def flush_side_files(self) -> None:
        (self.evidence / "ledger.jsonl").write_text(
            "\n".join(json.dumps(row) for row in self.ledger_rows) + "\n", encoding="utf-8"
        )
        (self.evidence / "selection.json").write_text(
            json.dumps(self.selection), encoding="utf-8"
        )

    def run_aggregate(self) -> dict:
        return aggregate.aggregate(
            evidence_root=self.evidence,
            ledger_path=self.evidence / "ledger.jsonl",
            selection_path=self.evidence / "selection.json",
            manifest_path=self._manifest_path(),
        )

    def _manifest_path(self) -> Path:
        path = self.root / "manifest.json"
        path.write_text(json.dumps(self.manifest), encoding="utf-8")
        return path


class AggregateSchema2Tests(unittest.TestCase):
    def test_valid_five_scenario_evidence_aggregates(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AggregateFixture(Path(directory))
            result = fixture.run_aggregate()
            self.assertEqual(result["status"], "success")
            self.assertEqual(result["schema_version"], 2)
            self.assertEqual(result["relation_count"], 650)
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

    def test_185_report_cannot_impersonate_the_active_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AggregateFixture(Path(directory))
            run_dir = fixture.evidence / "run-5"
            evidence = json.loads((run_dir / "snapshot-evidence.json").read_text(encoding="utf-8"))
            evidence["restore"]["snapshot_name"] = "Snapshot 185-Velociraptor-MCP依赖与情景基线"
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
