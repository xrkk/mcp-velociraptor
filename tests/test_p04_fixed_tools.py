from __future__ import annotations

import hashlib
import errno
import os
import subprocess
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from velociraptor_api import get_flow_result_count
from velociraptor_dynamic_artifacts import ArtifactSpec
from velociraptor_fixed_tools import FixedToolService
from velociraptor_mcp_core import (
    AlreadyExistsError,
    BackendError,
    DependencyMissingError,
    FlowReferenceResult,
    NotCancellableError,
    TargetContext,
    canonical_json_bytes,
)


ARTIFACT = "Windows.Test.Fixed"
SPEC = ArtifactSpec(
    name=ARTIFACT,
    description="fixed test artifact",
    definition_sha256="0" * 64,
    parameters=(),
)


def flow_row(flow_id="F.test", state="WAITING"):
    return {
        "session_id": flow_id,
        "state": state,
        "status": "",
        "create_time": 1,
        "start_time": 0,
        "active_time": 0,
        "total_collected_rows": 0,
        "total_logs": 0,
        "total_uploaded_files": 0,
        "total_uploaded_bytes": 0,
        "artifacts": [ARTIFACT],
        "artifacts_with_results": [ARTIFACT + "/Rows"],
        "request": {"artifacts": [ARTIFACT]},
    }


class FakeBackend:
    def __init__(self):
        self.calls = []
        self.flows = {
            "F.test": flow_row(),
            "F.file": {
                **flow_row("F.file", "FINISHED"),
                "total_uploaded_files": 1,
                "total_uploaded_bytes": 7,
            },
        }
        self.results = [{"row": index} for index in range(5)]
        self.results_by_source = None
        self.file_bytes = b"payload"
        self.uploads = [
            {
                "Upload": {
                    "Path": r"C:\fixture\same.txt",
                    "Size": len(self.file_bytes),
                    "StoredSize": len(self.file_bytes),
                    "Components": [
                        "clients",
                        "C.one",
                        "collections",
                        "F.file",
                        "uploads",
                        "auto",
                        "C:",
                        "fixture",
                        "same.txt",
                    ],
                    "Accessor": "auto",
                    "UploadId": 3,
                }
            }
        ]
        self.dependencies = set()
        self.hunt_state = "PAUSED"
        self.hunt_flow = None
        self.fail_vfs_at = None

    def list_windows_clients(self):
        return [{"client_id": "C.one"}]

    def client_id_exists(self, client_id):
        return client_id == "C.one"

    def run_vql(self, query, *, max_rows):
        self.calls.append(("run_vql", query, max_rows))
        return [{"row": index} for index in range(max_rows)]

    def artifact_exists(self, artifact):
        self.calls.append(("artifact_exists", artifact))
        return artifact in self.dependencies

    def get_flow_details(self, client_id, flow_id):
        self.calls.append(("get_flow_details", client_id, flow_id))
        return self.flows.get(flow_id)

    def get_flow_results_window(
        self, client_id, flow_id, artifact, *, source, start_row, count
    ):
        self.calls.append(
            ("get_flow_results_window", client_id, flow_id, artifact, source, start_row, count)
        )
        rows = (
            self.results_by_source[source]
            if self.results_by_source is not None
            else self.results
        )
        return rows[start_row : start_row + count]

    def get_flow_result_count(self, client_id, flow_id, artifact, *, source):
        self.calls.append(("get_flow_result_count", client_id, flow_id, artifact, source))
        rows = (
            self.results_by_source[source]
            if self.results_by_source is not None
            else self.results
        )
        return len(rows)

    def list_flow_uploads(self, client_id, flow_id):
        self.calls.append(("list_flow_uploads", client_id, flow_id))
        return list(self.uploads)

    def read_vfs_buffer(self, components, *, offset, length, padding):
        self.calls.append(
            ("read_vfs_buffer", tuple(components), offset, length, padding)
        )
        if self.fail_vfs_at == offset:
            raise OSError(errno.ENOSPC, "injected no-space failure")
        return self.file_bytes[offset : offset + length]

    def cancel_flow(self, client_id, flow_id):
        self.calls.append(("cancel_flow", client_id, flow_id))
        self.flows[flow_id] = {**self.flows[flow_id], "state": "ERROR", "status": "cancelled"}

    def start_collection(self, client_id, artifact, parameters=None, *, timeout=None):
        flow_id = "F.started"
        self.calls.append(("start_collection", client_id, artifact, parameters, timeout))
        self.flows[flow_id] = flow_row(flow_id)
        self.flows[flow_id]["artifacts"] = [artifact]
        self.flows[flow_id]["request"] = {"artifacts": [artifact]}
        return FlowReferenceResult(
            operation="start_collection",
            status="WAITING",
            warnings=[],
            flow_id=flow_id,
        )

    def create_paused_hunt(self, artifact, parameters, description):
        self.calls.append(("create_paused_hunt", artifact, parameters, description))
        return "H.real"

    def add_hunt_flow(self, client_id, hunt_id, flow_id):
        self.calls.append(("add_hunt_flow", client_id, hunt_id, flow_id))
        self.hunt_flow = {
            "HuntId": hunt_id,
            "ClientId": client_id,
            "FlowId": flow_id,
            "FlowState": self.flows[flow_id]["state"],
        }

    def get_hunt_details(self, hunt_id):
        self.calls.append(("get_hunt_details", hunt_id))
        return {"hunt_id": hunt_id, "state": self.hunt_state, "stats": {"scheduled": 1}}

    def list_hunt_flows(self, hunt_id):
        self.calls.append(("list_hunt_flows", hunt_id))
        return [dict(self.hunt_flow)] if self.hunt_flow else []

    def stop_hunt(self, hunt_id):
        self.calls.append(("stop_hunt", hunt_id))
        self.hunt_state = "STOPPED"


class FixedToolServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.backend = FakeBackend()
        self.service = FixedToolService(
            [SPEC],
            TargetContext(self.backend),
            self.backend,
            download_root=self.temp.name,
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_run_vql_is_bounded_and_structured(self):
        result = self.service.run_vql("SELECT * FROM scope()")
        self.assertEqual(len(result.data), 250)
        self.assertTrue(result.truncated)
        self.assertEqual(self.backend.calls[-1], ("run_vql", "SELECT * FROM scope()", 251))

    def test_flow_status_and_three_cursor_pages(self):
        status = self.service.get_flow_status("F.test")
        self.assertEqual((status.flow_id, status.state), ("F.test", "WAITING"))
        first = self.service.get_flow_results("F.test", "Rows", None, 1)
        second = self.service.get_flow_results("F.test", ARTIFACT + "/Rows", first.pagination.next_cursor, 1)
        third = self.service.get_flow_results("F.test", None, second.pagination.next_cursor, 1)
        self.assertEqual([page.data[0]["row"] for page in (first, second, third)], [0, 1, 2])
        self.assertEqual(
            [page.pagination.cursor for page in (first, second, third)],
            ["v1:0", "v1:1", "v1:2"],
        )

    def test_omitted_source_pages_across_all_known_sources(self):
        self.backend.flows["F.test"]["artifacts_with_results"] = [
            ARTIFACT + "/A",
            ARTIFACT + "/B",
        ]
        self.backend.results_by_source = {
            "A": [{"value": "a0"}, {"value": "a1"}],
            "B": [{"value": "b0"}, {"value": "b1"}],
        }
        first = self.service.get_flow_results("F.test", None, None, 3)
        second = self.service.get_flow_results(
            "F.test", None, first.pagination.next_cursor, 3
        )
        self.assertEqual([row["value"] for row in first.data], ["a0", "a1", "b0"])
        self.assertEqual([row["value"] for row in second.data], ["b1"])
        self.assertFalse(second.pagination.truncated)

    def test_file_identity_deduplicates_exact_rows_and_rejects_conflicts(self):
        first = self.service.list_flow_files("F.file")
        identity = {
            "accessor": "auto",
            "components": [
                "clients",
                "C.one",
                "collections",
                "F.file",
                "uploads",
                "auto",
                "C:",
                "fixture",
                "same.txt",
            ],
            "upload_id": 3,
        }
        expected_id = hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
        self.assertEqual(first.data[0].file_id, expected_id)

        self.backend.uploads.append(dict(self.backend.uploads[0]))
        duplicate = self.service.list_flow_files("F.file")
        self.assertEqual(len(duplicate.data), 1)

        conflict = {"Upload": dict(self.backend.uploads[0]["Upload"])}
        conflict["Upload"]["Size"] = 99
        self.backend.uploads.append(conflict)
        with self.assertRaises(BackendError):
            self.service.list_flow_files("F.file")

    def test_same_name_in_different_directories_has_two_stable_ids(self):
        second = {"Upload": dict(self.backend.uploads[0]["Upload"])}
        second["Upload"]["Path"] = r"C:\other\same.txt"
        second["Upload"]["Components"] = list(second["Upload"]["Components"])
        second["Upload"]["Components"][-2] = "other"
        second["Upload"]["UploadId"] = 4
        self.backend.uploads.append(second)
        rows = self.service.list_flow_files("F.file").data
        self.assertEqual(len(rows), 2)
        self.assertEqual({Path(row.original_path).name for row in rows}, {"same.txt"})
        self.assertEqual(len({row.file_id for row in rows}), 2)

    def test_concurrent_download_is_create_if_absent(self):
        file_id = self.service.list_flow_files("F.file").data[0].file_id
        outcomes = []

        def call():
            try:
                return ("success", self.service.download_flow_file("F.file", file_id))
            except AlreadyExistsError as exc:
                return ("exists", exc)

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: call(), range(2)))
        self.assertEqual(sorted(kind for kind, _ in outcomes), ["exists", "success"])
        success = next(value for kind, value in outcomes if kind == "success")
        completed = Path(success.local_path)
        self.assertEqual(completed.read_bytes(), self.backend.file_bytes)
        self.assertEqual(success.sha256, hashlib.sha256(self.backend.file_bytes).hexdigest())
        self.assertEqual(list(Path(self.temp.name).rglob("*.part")), [])
        self.assertNotIn("F.file", str(completed))

    def test_midstream_failure_leaves_no_completed_file_or_part(self):
        file_id = self.service.list_flow_files("F.file").data[0].file_id
        self.backend.fail_vfs_at = len(self.backend.file_bytes)
        with self.assertRaises(BackendError):
            self.service.download_flow_file("F.file", file_id)
        self.assertEqual(list(Path(self.temp.name).rglob("content.bin")), [])
        self.assertEqual(list(Path(self.temp.name).rglob("*.part")), [])

    def test_malicious_flow_id_is_hashed_and_cannot_escape(self):
        malicious = r"..\..\outside"
        self.backend.flows[malicious] = {
            **flow_row(malicious, "FINISHED"),
            "total_uploaded_files": 1,
            "total_uploaded_bytes": len(self.backend.file_bytes),
        }
        self.backend.uploads[0]["Upload"]["Components"][3] = malicious
        file_id = self.service.list_flow_files(malicious).data[0].file_id
        result = self.service.download_flow_file(malicious, file_id)
        completed = Path(result.local_path)
        self.assertTrue(completed.is_relative_to(Path(self.temp.name).resolve()))
        self.assertNotIn("outside", str(completed))

    def test_upload_metadata_cannot_escape_requested_flow_scope(self):
        self.backend.uploads[0]["Upload"]["Components"][3] = "F.other"
        with self.assertRaises(BackendError):
            self.service.list_flow_files("F.file")

    def test_reparse_download_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as outer:
            real = Path(outer) / "real"
            link = Path(outer) / "link"
            real.mkdir()
            if os.name == "nt":
                completed = subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(link), str(real)],
                    capture_output=True,
                    check=False,
                )
                if completed.returncode != 0:
                    self.skipTest("junction creation is unavailable")
            else:
                link.symlink_to(real, target_is_directory=True)
            service = FixedToolService(
                [SPEC], TargetContext(self.backend), self.backend, download_root=str(link)
            )
            file_id = service.list_flow_files("F.file").data[0].file_id
            with self.assertRaises(BackendError):
                service.download_flow_file("F.file", file_id)
            if os.name == "nt":
                os.rmdir(link)

    def test_hunt_trace_is_paused_collect_then_exact_add_and_stop_does_not_cancel(self):
        started = self.service.start_hunt(ARTIFACT, None, "test hunt")
        self.assertEqual((started.hunt_id, started.flow_id, started.client_id), ("H.real", "F.started", "C.one"))
        operation_names = [call[0] for call in self.backend.calls]
        self.assertLess(operation_names.index("create_paused_hunt"), operation_names.index("start_collection"))
        self.assertLess(operation_names.index("start_collection"), operation_names.index("add_hunt_flow"))
        stopped = self.service.stop_hunt("H.real")
        self.assertEqual(stopped.state, "STOPPED")
        self.assertEqual(stopped.flow_state_before, "WAITING")
        self.assertEqual(stopped.flow_state_after, "WAITING")
        self.assertFalse(any(call[0] == "cancel_flow" for call in self.backend.calls))

    def test_cancel_terminal_rejected_and_nonterminal_reports_transition(self):
        result = self.service.cancel_flow("F.test")
        self.assertEqual((result.state_before, result.state_after), ("WAITING", "ERROR"))
        with self.assertRaises(NotCancellableError):
            self.service.cancel_flow("F.test")

    def test_collect_file_uses_drive_and_csv_without_exposing_target(self):
        result = self.service.collect_file(r"C:\fixture\a file.txt")
        self.assertEqual(result.flow_id, "F.started")
        call = next(item for item in self.backend.calls if item[0] == "start_collection")
        self.assertEqual(call[1:3], ("C.one", "Generic.Collectors.File"))
        self.assertEqual(call[3]["Root"], "C:")
        self.assertEqual(call[3]["collectionSpec"], "Glob\nfixture\\a file.txt\n")

    def test_missing_dependencies_create_no_flow(self):
        with self.assertRaises(DependencyMissingError):
            self.service.collect_forensic_triage()
        with self.assertRaises(DependencyMissingError):
            self.service.kill_process(123)
        self.assertFalse(any(call[0] == "start_collection" for call in self.backend.calls))


class FlowResultCountTests(unittest.TestCase):
    @patch(
        "velociraptor_api.run_vql_query",
        return_value=[{"Count": 1}, {"Count": 2}, {"Count": 3}],
    )
    def test_uses_final_running_count(self, _run_vql_query):
        self.assertEqual(
            get_flow_result_count(
                "C.one", "F.test", "Generic.Collectors.File", source="Rows"
            ),
            3,
        )


if __name__ == "__main__":
    unittest.main()
