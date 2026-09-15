"""Velociraptor MCP bridge: single server, dual transport, 130 tools.

The bridge constructs exactly one MCPServer instance and registers the
complete 130-tool face (118 dynamic Windows artifacts + 12 fixed lifecycle
tools) through it.  Both the formal Streamable HTTP entry and the internal
testing stdio adapter share this one registration and business implementation.
"""

from __future__ import annotations

import logging
import os
import sys

from mcp.server.mcpserver import MCPServer

from velociraptor_api import init_stub, read_root_artifact_definitions
from velociraptor_dynamic_artifacts import (
    ArtifactRegistryError,
    register_dynamic_artifact_tools,
)
from velociraptor_fixed_tools import register_fixed_tools, validate_combined_registry
from velociraptor_mcp_core import TargetContext, VelociraptorBackend
from velociraptor_transport import (
    FORMAL_TRANSPORT,
    TransportConfigError,
    resolve_transport_config,
    run_formal_http,
)


# Keep stdio responses clean by suppressing chatty MCP library info logs.
logging.getLogger("mcp").setLevel(logging.WARNING)

velociraptor_backend = VelociraptorBackend()
target_context = TargetContext(velociraptor_backend)


def create_server() -> MCPServer:
    """Construct the single MCPServer instance and register the toolset once.

    Both entry transports share this one registration; no second server is
    constructed and no tool is registered twice.
    """
    # velociraptor_api loads repo-local .env before resolving this setting.
    init_stub(os.environ.get("VELOCIRAPTOR_API_CONFIG"))
    rows = read_root_artifact_definitions()
    server = MCPServer("velociraptor-mcp")
    specs = register_dynamic_artifact_tools(
        server,
        rows,
        target_context,
        velociraptor_backend,
    )
    register_fixed_tools(
        server,
        specs,
        target_context,
        velociraptor_backend,
        download_root=os.environ.get("VELOCIRAPTOR_DOWNLOAD_ROOT"),
    )
    validate_combined_registry(server, specs)
    return server


def main(*, on_ready=None, stop_requested=None, on_failure=None) -> int:
    """Resolve the fail-closed transport seam, then run the single server."""
    try:
        config = resolve_transport_config()
    except TransportConfigError as exc:
        if on_failure is not None:
            on_failure("TRANSPORT_CONFIG_INVALID")
        print(
            f"Velociraptor MCP transport configuration rejected: {exc}",
            file=sys.stderr,
        )
        return 2

    if config.mode != FORMAL_TRANSPORT and (on_ready is not None or stop_requested is not None):
        if on_failure is not None:
            on_failure("SERVICE_TRANSPORT_INVALID")
        print('Service lifecycle requires the formal HTTP transport', file=sys.stderr)
        return 2

    try:
        server = create_server()
    except ArtifactRegistryError as exc:
        if on_failure is not None:
            on_failure("ARTIFACT_REGISTRY_INVALID")
        print(f"Velociraptor MCP startup failed: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        if on_failure is not None:
            on_failure("BACKEND_INITIALIZATION_FAILED")
        print(
            "Velociraptor MCP startup failed: backend initialization or metadata "
            f"read failed ({type(exc).__name__})",
            file=sys.stderr,
        )
        return 2

    if config.mode == FORMAL_TRANSPORT:
        if on_ready is None and stop_requested is None:
            run_formal_http(server, config)
        else:
            run_formal_http(server, config, on_ready=on_ready, stop_requested=stop_requested)
    else:
        server.run("stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
