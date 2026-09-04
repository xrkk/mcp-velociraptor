from __future__ import annotations

import os
import sys

from mcp.server.mcpserver import MCPServer

import velociraptor_fixed_tools as fixed
from velociraptor_dynamic_artifacts import (
    APPROVED_WINDOWS_ARTIFACTS,
    ArtifactRegistryError,
    ArtifactSpec,
    _strict_tool_schema,
)
from velociraptor_mcp_core import FlowReferenceResult, TargetContext


class FakeBackend:
    def list_windows_clients(self):
        return [{"client_id": "C.fixture"}]

    def client_id_exists(self, client_id):
        return client_id == "C.fixture"


def dynamic_candidate():
    server = MCPServer("p04-fixture")
    specs = []

    def handler() -> FlowReferenceResult:
        return FlowReferenceResult(
            operation="fixture", status="success", warnings=[], flow_id="F.fixture"
        )

    for name in APPROVED_WINDOWS_ARTIFACTS:
        server.add_tool(handler, name=name, description="fixture")
        _strict_tool_schema(server._tool_manager.get_tool(name))
        specs.append(
            ArtifactSpec(
                name=name,
                description="fixture",
                definition_sha256="0" * 64,
                parameters=(),
            )
        )
    return server, tuple(specs)


def main():
    failure = os.environ.get("P04_FIXTURE_FAILURE", "")
    server, specs = dynamic_candidate()
    backend = FakeBackend()
    original_names = fixed.FIXED_TOOL_NAMES
    try:
        if failure == "dynamic_fixed_conflict":
            def conflict() -> FlowReferenceResult:
                return FlowReferenceResult(
                    operation="fixture", status="success", warnings=[], flow_id="F.fixture"
                )
            server.add_tool(conflict, name="run_vql")
        elif failure == "fixed_duplicate":
            fixed.FIXED_TOOL_NAMES = original_names + (original_names[0],)

        if failure == "nth_registration":
            original_add = server.add_tool
            counter = {"value": 0}
            def failing_add(*args, **kwargs):
                counter["value"] += 1
                if counter["value"] == 5:
                    raise ArtifactRegistryError("injected fifth fixed registration failure")
                return original_add(*args, **kwargs)
            server.add_tool = failing_add

        fixed.register_fixed_tools(
            server,
            specs,
            TargetContext(backend),
            backend,
            download_root=None,
        )
        if failure == "invalid_input_schema":
            server._tool_manager.get_tool("run_vql").parameters = {"type": "invalid"}
        elif failure == "missing_output_schema":
            server._tool_manager.get_tool("run_vql").fn_metadata.output_schema = None
        elif failure == "invalid_output_schema":
            server._tool_manager.get_tool("run_vql").fn_metadata.output_schema = {
                "type": "invalid"
            }
        fixed.validate_combined_registry(server, specs)
    except Exception as exc:
        print(
            f"P04 fixture startup failed ({type(exc).__name__}): contract validation failed",
            file=sys.stderr,
        )
        return 2
    finally:
        fixed.FIXED_TOOL_NAMES = original_names

    if failure:
        print("P04 fixture startup failed: injection was not reached", file=sys.stderr)
        return 2
    server.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
