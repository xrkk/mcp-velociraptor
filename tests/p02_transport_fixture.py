"""Shared-registration transport fixture for ACC-P02-009/010.

Boots the exact production registration path (``bridge.create_server``) with
an injected fake backend, then selects stdio or the formal HTTP entry through
the same fail-closed transport seam the real bridge uses.  The fixture exists
only as a test subprocess and never enters the product tools/list.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from velociraptor_mcp_core import FlowReferenceResult, TargetContext

import mcp_velociraptor_bridge as bridge


class FakeBackend:
    """Read-only fake covering every backend method the toolset can reach."""

    def __init__(self) -> None:
        self.start_collection_calls: list[dict[str, Any]] = []

    def list_windows_clients(self) -> list[dict[str, Any]]:
        return [{"client_id": "C.fake", "system": "windows"}]

    def client_id_exists(self, client_id: str) -> bool:
        return client_id == "C.fake"

    def start_collection(
        self,
        client_id: str,
        artifact: str,
        parameters: Mapping[str, Any] | None = None,
        *,
        timeout: int | None = None,
    ) -> FlowReferenceResult:
        self.start_collection_calls.append(
            {"client_id": client_id, "artifact": artifact, "parameters": dict(parameters or {})}
        )
        return FlowReferenceResult(
            operation="start_collection",
            status="FINISHED",
            warnings=[],
            flow_id="F.FAKE0001",
        )

    def run_vql(self, query: str, *, max_rows: int) -> list[dict[str, Any]]:
        return []

    def artifact_exists(self, artifact: str) -> bool:
        return True

    def get_flow_details(self, client_id: str, flow_id: str) -> dict[str, Any] | None:
        return {"flow_id": flow_id, "state": "FINISHED"}

    def get_flow_results_window(
        self,
        client_id: str,
        flow_id: str,
        artifact: str,
        *,
        source: str | None,
        start_row: int,
        count: int,
    ) -> list[dict[str, Any]]:
        return []

    def get_flow_result_count(
        self, client_id: str, flow_id: str, artifact: str, *, source: str | None
    ) -> int:
        return 0

    def list_flow_uploads(self, client_id: str, flow_id: str) -> list[dict[str, Any]]:
        return []

    def read_vfs_buffer(
        self, components, *, offset: int, length: int, padding: bool
    ) -> bytes:
        return b""

    def cancel_flow(self, client_id: str, flow_id: str) -> None:
        return None

    def create_paused_hunt(
        self,
        artifact: str,
        parameters: Mapping[str, Any] | None,
        description: str,
    ) -> str:
        return "H.FAKEHUNT1"

    def add_hunt_flow(self, client_id: str, hunt_id: str, flow_id: str) -> None:
        return None

    def get_hunt_details(self, hunt_id: str) -> dict[str, Any] | None:
        return {"hunt_id": hunt_id, "state": "PAUSED"}

    def list_hunt_flows(self, hunt_id: str) -> list[dict[str, Any]]:
        return []

    def stop_hunt(self, hunt_id: str) -> None:
        return None


def main() -> int:
    fake = FakeBackend()
    bridge.velociraptor_backend = fake
    bridge.target_context = TargetContext(fake)
    return bridge.main()


if __name__ == "__main__":
    raise SystemExit(main())
