"""Isolated stdio/loopback fixture for the PC018/PC019 contract slice."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp.server.transport_security import TransportSecuritySettings

from tests.p04_fixture_server import dynamic_candidate
from velociraptor_fixed_tools import (
    TRIAGE_ARTIFACT,
    TRIAGE_MAX_UPLOAD_BYTES,
    register_fixed_tools,
    validate_combined_registry,
)
from velociraptor_mcp_core import FlowReferenceResult, TargetContext


ARTIFACT = "Windows.System.Pslist"


class FixtureBackend:
    def __init__(self) -> None:
        self.state = os.environ.get("STATE_PAGING_FIXTURE_STATE", "WAITING")
        self.start_count = 0
        self.rows = {
            ("F.page-a", "A"): [{"value": "a0"}, {"value": "a1"}],
            ("F.page-a", "B"): [{"value": "b0"}, {"value": "b1"}],
            ("F.page-b", "A"): [{"value": "c0"}, {"value": "c1"}],
            ("F.page-b", "B"): [{"value": "d0"}, {"value": "d1"}],
            ("F.empty", "A"): [],
        }

    def list_windows_clients(self):
        return [{"client_id": "C.fixture"}]

    def client_id_exists(self, client_id):
        return client_id == "C.fixture"

    def start_collection(
        self,
        client_id: str,
        artifact: str,
        parameters: Mapping[str, Any] | None = None,
        *,
        timeout: int | None = None,
        max_upload_bytes: int | None = None,
    ):
        self.start_count += 1
        trace_path = os.environ.get("STATE_PAGING_FIXTURE_TRACE")
        if trace_path:
            with Path(trace_path).open("a", encoding="utf-8") as stream:
                stream.write(
                    json.dumps(
                        {
                            "call_index": self.start_count,
                            "artifact": artifact,
                            "timeout": timeout,
                            "max_upload_bytes": max_upload_bytes,
                        },
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    + "\n"
                )
        expected_budget = (
            TRIAGE_MAX_UPLOAD_BYTES if artifact == TRIAGE_ARTIFACT else None
        )
        assert max_upload_bytes == expected_budget
        flow_id = f"F.start-{self.start_count}"
        if self.state == "__MISSING__":
            return SimpleNamespace(flow_id=flow_id)
        state = "" if self.state == "__EMPTY__" else self.state
        return FlowReferenceResult(
            operation="start_collection",
            status=state,
            warnings=[],
            flow_id=flow_id,
        )

    def artifact_exists(self, artifact):
        return True

    def create_paused_hunt(self, artifact, parameters, description):
        return "H.fixture"

    def add_hunt_flow(self, client_id, hunt_id, flow_id):
        return None

    def get_hunt_details(self, hunt_id):
        return {"hunt_id": hunt_id, "state": "PAUSED", "stats": {}}

    def list_hunt_flows(self, hunt_id):
        return []

    def stop_hunt(self, hunt_id):
        return None

    def cancel_flow(self, client_id, flow_id):
        return None

    def run_vql(self, query, *, max_rows):
        return []

    def get_flow_details(self, client_id, flow_id):
        if flow_id not in {"F.page-a", "F.page-b", "F.empty"}:
            return None
        return {
            "session_id": flow_id,
            "state": "FINISHED",
            "artifacts": [ARTIFACT],
            "artifacts_with_results": [ARTIFACT + "/A", ARTIFACT + "/B"],
            "request": {"artifacts": [ARTIFACT]},
        }

    def get_flow_result_count(self, client_id, flow_id, artifact, *, source):
        return len(self.rows[(flow_id, source)])

    def get_flow_results_window(
        self, client_id, flow_id, artifact, *, source, start_row, count
    ):
        return self.rows[(flow_id, source)][start_row : start_row + count]

    def list_flow_uploads(self, client_id, flow_id):
        return []

    def read_vfs_buffer(self, components, *, offset, length, padding):
        return b""


def main() -> int:
    server, specs = dynamic_candidate()
    backend = FixtureBackend()
    register_fixed_tools(
        server, specs, TargetContext(backend), backend, download_root=None
    )
    validate_combined_registry(server, specs)
    if os.environ.get("STATE_PAGING_FIXTURE_TRANSPORT") != "http":
        server.run("stdio")
        return 0

    import uvicorn

    port = int(os.environ["STATE_PAGING_FIXTURE_PORT"])
    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=False,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[f"127.0.0.1:{port}"],
            allowed_origins=[],
        ),
        host="127.0.0.1",
    )
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
