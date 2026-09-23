"""Benign 136-tool stdio fixture with no Velociraptor API or guest policy."""

from tests.test_p04_registration import FakeBackend, _dummy_dynamic_server
from velo_transfer.mcp_tools import TRANSFER_TOOL_NAMES, register_transfer_tools
from velociraptor_fixed_tools import register_fixed_tools, validate_combined_registry
from velociraptor_mcp_core import TargetContext


def main():
    server, specs = _dummy_dynamic_server()
    backend = FakeBackend()
    register_fixed_tools(server, specs, TargetContext(backend), backend, download_root=None)
    manager = register_transfer_tools(server)
    validate_combined_registry(server, specs, transfer_names=TRANSFER_TOOL_NAMES)
    try:
        server.run("stdio")
    finally:
        manager.shutdown()


if __name__ == "__main__":
    main()
