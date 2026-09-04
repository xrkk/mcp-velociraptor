from __future__ import annotations

import json
import unittest
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from velociraptor_dynamic_artifacts import ArtifactSpec
from velociraptor_fixed_tools import FIXED_TOOL_NAMES, register_fixed_tools
from velociraptor_mcp_core import TargetContext


REPO_ROOT = Path(__file__).resolve().parents[1]


class FakeBackend:
    def list_windows_clients(self):
        return [{"client_id": "C.one"}]

    def client_id_exists(self, client_id):
        return client_id == "C.one"


def _resolve(schema, root):
    if "$ref" not in schema:
        return schema
    node = root
    for part in schema["$ref"].removeprefix("#/").split("/"):
        node = node[part]
    return node


def _node(schema, root):
    schema = _resolve(schema, root)
    if "anyOf" in schema:
        branches = [_node(branch, root) for branch in schema["anyOf"]]
        result = {"types": sorted({kind for branch in branches for kind in branch["types"]})}
        for key in ("minimum", "maximum", "minLength", "open_object", "items", "fields", "required"):
            values = [branch[key] for branch in branches if key in branch]
            if values:
                result[key] = values[0]
        return result
    kind = schema.get("type")
    result = {"types": [kind]} if kind else {"types": []}
    for key in ("const", "minimum", "maximum", "minLength"):
        if key in schema:
            result[key] = schema[key]
    if kind == "array":
        result["items"] = _node(schema.get("items", {}), root)
    elif kind == "object":
        properties = schema.get("properties")
        if properties is not None:
            result["fields"] = {
                name: _node(value, root) for name, value in sorted(properties.items())
            }
            result["required"] = sorted(schema.get("required", []))
        elif schema.get("additionalProperties") is not False:
            result["open_object"] = True
    return result


def _contract(schema):
    root = schema
    normalized = _node(schema, root)
    return {"fields": normalized.get("fields", {}), "required": normalized.get("required", [])}


class FixedContractGoldenTests(unittest.TestCase):
    def test_independently_authored_fixed_schema_golden(self):
        server = MCPServer("p04-golden")
        backend = FakeBackend()
        specs = (
            ArtifactSpec(
                name="Windows.Test.Fixed",
                description="fixture",
                definition_sha256="0" * 64,
                parameters=(),
            ),
        )
        register_fixed_tools(
            server,
            specs,
            TargetContext(backend),
            backend,
            download_root=None,
        )
        actual = {}
        for name in FIXED_TOOL_NAMES:
            tool = server._tool_manager.get_tool(name)
            actual[name] = {
                "input": _contract(tool.parameters),
                "output": _contract(tool.fn_metadata.output_schema),
            }
        expected = json.loads(
            (REPO_ROOT / "tests" / "data" / "p04_fixed_tools_golden.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
