"""Isolated stdio fixture that registers the production P02 result primitives."""

import sys
from pathlib import Path
from typing import Annotated

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult

from velociraptor_mcp_core import (
    DataResult,
    InvalidArgumentError,
    Pagination,
    ResultBase,
    TargetContext,
    error_result,
    success_result,
)


class FixtureBackend:
    def __init__(self) -> None:
        self.queries = 0

    def list_windows_clients(self) -> list[dict]:
        self.queries += 1
        return [{"client_id": "C.fixture", "system": "windows"}]

    def client_id_exists(self, client_id: str) -> bool:
        return client_id == "C.fixture"


mcp = MCPServer("p02-fixture")
backend = FixtureBackend()
target = TargetContext(backend)


@mcp.tool()
def p02_success() -> Annotated[CallToolResult, DataResult]:
    model = DataResult(
        operation="fixture_success",
        status="FINISHED",
        warnings=[],
        data=[{"value": 1}],
        pagination=Pagination(
            cursor="v1:0",
            next_cursor=None,
            page_size=50,
            returned=1,
            truncated=False,
        ),
    )
    return success_result(model)


@mcp.tool()
def p02_error() -> Annotated[CallToolResult, DataResult]:
    return error_result(
        InvalidArgumentError(
            details={"field": "page_size", "reason": "range", "maximum": 250}
        ),
        operation="fixture_error",
    )


@mcp.tool()
def p02_target() -> Annotated[CallToolResult, DataResult]:
    client_id = target.get_client_id()
    return success_result(
        DataResult(
            operation="fixture_target",
            status="FINISHED",
            warnings=[],
            data=[{"client_id": client_id, "resolution_queries": backend.queries}],
            pagination=Pagination(
                cursor="v1:0",
                next_cursor=None,
                page_size=50,
                returned=1,
                truncated=False,
            ),
        )
    )


if __name__ == "__main__":
    mcp.run()
