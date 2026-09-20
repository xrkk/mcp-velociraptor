"""Synthetic stdio/loopback fixture for the PC017 logical-file contract."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp.server.transport_security import TransportSecuritySettings
from tests.p04_fixture_server import dynamic_candidate
import velociraptor_fixed_tools as fixed
from velociraptor_fixed_tools import register_fixed_tools, validate_combined_registry
from velociraptor_mcp_core import BackendError, TargetContext


def row(name, *, size, stored, upload_id, kind=None, path=None):
    result = {
        "Upload": {
            "Path": path or rf"C:\fixture\{name}",
            "Size": size,
            "StoredSize": stored,
            "Components": [
                "clients", "C.fixture", "collections", "FLOW", "uploads",
                "auto", "C:", "fixture", name,
            ],
            "Accessor": "auto",
            "UploadId": upload_id,
        }
    }
    if kind is not None:
        result["Type"] = kind
    return result


class Backend:
    normal = b"protocol-payload"
    compact = b"ABCDXYZ"
    logical = b"\0\0\0ABCD\0\0XYZ\0\0\0\0"

    def __init__(self):
        self.current_flow = ""

    def list_windows_clients(self): return [{"client_id": "C.fixture"}]
    def client_id_exists(self, client_id): return client_id == "C.fixture"
    def run_vql(self, query, *, max_rows): return []
    def artifact_exists(self, artifact): return True
    def get_flow_details(self, client_id, flow_id):
        if flow_id not in {"F.normal", "F.sparse", "F.bad", "F.post", "F.error"}:
            return None
        return {
            "session_id": flow_id,
            "state": "ERROR" if flow_id == "F.error" else "FINISHED",
            "status": "synthetic",
            "create_time": 1, "start_time": 1, "active_time": 1,
            "total_collected_rows": 0, "total_logs": 0,
            "total_uploaded_files": 1, "total_uploaded_bytes": 7,
            "artifacts": ["Windows.System.Pslist"],
            "artifacts_with_results": [],
            "request": {"artifacts": ["Windows.System.Pslist"]},
        }
    def get_flow_results_window(self, *args, **kwargs): return []
    def get_flow_result_count(self, *args, **kwargs): return 0
    def list_flow_uploads(self, client_id, flow_id):
        self.current_flow = flow_id
        if flow_id == "F.bad":
            bad = row("bad.bin", size=1, stored=1, upload_id=9)
            bad["Type"] = "future"
            return [bad]
        if flow_id == "F.sparse":
            data = row("sparse.bin", size=16, stored=7, upload_id=2)
            index = row(
                "sparse.bin", size=16, stored=7, upload_id=2, kind="idx",
                path=r"C:\fixture\sparse.bin.idx",
            )
            rows = [data, index]
        else:
            rows = [row("normal.bin", size=len(self.normal), stored=len(self.normal), upload_id=1)]
        for item in rows:
            item["Upload"]["Components"][3] = flow_id
        return rows
    def read_vfs_buffer(self, components, *, offset, length, padding):
        flow = components[3]
        value = self.logical if flow == "F.sparse" and padding else self.compact if flow == "F.sparse" else self.normal
        return value[offset : offset + length]
    def cancel_flow(self, client_id, flow_id): return None
    def start_collection(self, *args, **kwargs): raise AssertionError("not used")
    def create_paused_hunt(self, *args, **kwargs): raise AssertionError("not used")
    def add_hunt_flow(self, *args, **kwargs): return None
    def get_hunt_details(self, hunt_id): return None
    def list_hunt_flows(self, hunt_id): return []
    def stop_hunt(self, hunt_id): return None


def main() -> int:
    server, specs = dynamic_candidate()
    backend = Backend()
    original_safe_chain = fixed._assert_safe_chain

    def safe_chain(root, *paths):
        if backend.current_flow == "F.post" and any(path.name == "content.bin" for path in paths):
            raise BackendError(details={"operation": "download_flow_file", "reason": "injected"})
        return original_safe_chain(root, *paths)

    fixed._assert_safe_chain = safe_chain
    register_fixed_tools(
        server, specs, TargetContext(backend), backend,
        download_root=os.environ["PC017_FILE_ROOT"],
    )
    validate_combined_registry(server, specs)
    if os.environ.get("PC017_FILE_TRANSPORT") != "http":
        server.run("stdio")
        return 0
    import uvicorn
    port = int(os.environ["PC017_FILE_PORT"])
    app = server.streamable_http_app(
        streamable_http_path="/mcp", stateless_http=False,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[f"127.0.0.1:{port}"], allowed_origins=[],
        ), host="127.0.0.1",
    )
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
