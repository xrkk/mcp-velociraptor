"""Isolated P03 server used to prove atomic startup and generated schemas."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp.server.mcpserver import MCPServer

import velociraptor_dynamic_artifacts as dynamic
from velociraptor_dynamic_artifacts import ArtifactRegistryError
from velociraptor_mcp_core import FlowReferenceResult


RAW = "name: Windows.Fixture.Dynamic\ntype: CLIENT\n"
APPROVED = {"Windows.Fixture.Dynamic": hashlib.sha256(RAW.encode("utf-8")).hexdigest()}


class FixtureBackend:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def list_windows_clients(self) -> list[dict]:
        return [{"client_id": "C.fixture"}]

    def client_id_exists(self, client_id: str) -> bool:
        return client_id == "C.fixture"

    def start_collection(self, client_id, artifact, parameters=None, **_kwargs):
        self.calls.append(
            {"client_id": client_id, "artifact": artifact, "parameters": parameters}
        )
        return FlowReferenceResult(
            operation="start_collection",
            status="RUNNING",
            warnings=[],
            flow_id=f"F.fixture.{len(self.calls)}",
        )


def row() -> dict:
    return {
        "name": "Windows.Fixture.Dynamic",
        "type": "CLIENT",
        "description": "Fixture dynamic artifact.",
        "raw": RAW,
        "parameters": [
            {
                "name": "Boot execute",
                "type": "bool",
                "default": "Y",
                "description": "Whether to execute at boot.",
            },
            {
                "name": "Mode",
                "type": "choices",
                "choices": ["Safe", "Deep"],
                "default": "Safe",
            },
            {"name": "Needle", "type": "regex", "default": "."},
            {"name": "Secret", "type": "hidden", "default": "x"},
            {"name": "Upload", "type": "upload", "default": ""},
        ],
    }


def main() -> int:
    failure = os.environ.get("P03_FIXTURE_FAILURE", "").strip()
    if failure == "connection":
        print("P03 startup failed: backend connection unavailable", file=sys.stderr)
        return 2

    rows = [row()]
    server = MCPServer("p03-fixture")
    backend = FixtureBackend()
    target = dynamic.TargetContext(backend)
    if failure == "missing":
        rows = []
    elif failure == "type":
        rows[0]["type"] = "SERVER"
    elif failure == "conflict":
        server.add_tool(lambda: None, name="Windows.Fixture.Dynamic")
    elif failure == "schema":
        original = dynamic.Draft202012Validator.check_schema

        def reject_schema(_schema):
            raise ArtifactRegistryError("generated schema is invalid")

        dynamic.Draft202012Validator.check_schema = reject_schema
    else:
        original = None

    try:
        dynamic.register_dynamic_artifact_tools(
            server, rows, target, backend, approved=APPROVED
        )
    except Exception as exc:
        print(f"P03 startup failed: {exc}", file=sys.stderr)
        return 2
    finally:
        if failure == "schema" and original is not None:
            dynamic.Draft202012Validator.check_schema = original

    server.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
