from __future__ import annotations

import hashlib
import unittest

from mcp.server.mcpserver import MCPServer

from velociraptor_dynamic_artifacts import (
    ArtifactRegistryError,
    definition_sha256,
    make_artifact_handler,
    register_dynamic_artifact_tools,
    validate_artifact_definitions,
)
from velociraptor_mcp_core import FlowReferenceResult, TargetContext
from velociraptor_api import normalize_env_dict, vql_identifier


RAW = "name: Windows.Test.One\ntype: CLIENT\n"
APPROVED = {"Windows.Test.One": hashlib.sha256(RAW.encode("utf-8")).hexdigest()}


class FakeBackend:
    def __init__(self) -> None:
        self.calls = []

    def list_windows_clients(self):
        return [{"client_id": "C.one"}]

    def client_id_exists(self, client_id):
        return client_id == "C.one"

    def start_collection(self, client_id, artifact, parameters=None, **_kwargs):
        self.calls.append((client_id, artifact, parameters))
        return FlowReferenceResult(
            operation="start_collection",
            status="RUNNING",
            warnings=[],
            flow_id="F.real",
        )


def parameter(name, kind="", **updates):
    value = {
        "name": name,
        "type": kind,
        "default": "backend-default",
        "description": f"Description for {name}",
        "friendly_name": f"Friendly {name}",
        "choices": [],
        "validating_regex": "",
    }
    value.update(updates)
    return value


def artifact_row(parameters=None, **updates):
    value = {
        "name": "Windows.Test.One",
        "type": "CLIENT",
        "description": "A test artifact.",
        "raw": RAW,
        "parameters": parameters or [],
    }
    value.update(updates)
    return value


class RegistryValidationTests(unittest.TestCase):
    def test_definition_hash_is_exact_utf8(self):
        self.assertEqual(definition_sha256(RAW), APPROVED["Windows.Test.One"])
        self.assertNotEqual(definition_sha256(RAW + "\n"), APPROVED["Windows.Test.One"])
        for changed_part in ("query", "default", "parameter", "description"):
            with self.subTest(changed_part=changed_part):
                with self.assertRaisesRegex(ArtifactRegistryError, "definition changed"):
                    validate_artifact_definitions(
                        [artifact_row(raw=RAW + f"{changed_part}: changed\n")],
                        APPROVED,
                    )

    def test_missing_duplicate_type_hash_and_parameter_fail_closed(self):
        cases = [
            ([], "missing approved"),
            ([artifact_row(), artifact_row()], "duplicate approved"),
            ([artifact_row(type="SERVER")], "not CLIENT"),
            ([artifact_row(raw=RAW + "changed")], "definition changed"),
            ([artifact_row(parameters=[parameter("X", "future")])], "unsupported type"),
            ([artifact_row(parameters=[parameter("X", "regex", validating_regex="[")])], "invalid validating_regex"),
            ([artifact_row(parameters=[parameter("X"), parameter("X")])], "duplicate parameter"),
            ([artifact_row(parameters=[parameter("Bad`Name")])], "unsafe parameter"),
            ([artifact_row(parameters=["not-an-object"])], "non-object parameter"),
        ]
        for rows, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ArtifactRegistryError, message):
                    validate_artifact_definitions(rows, APPROVED)

    def test_schema_maps_types_aliases_metadata_and_exclusions(self):
        parameters = [
            parameter("Plain", ""),
            parameter("String", "string", validating_regex="^x+$"),
            parameter("Regex", "regex"),
            parameter("YaraRule", "yara"),
            parameter("When", "timestamp"),
            parameter("CSV", "csv"),
            parameter("Flag", "bool"),
            parameter("Count", "int"),
            parameter("Big", "int64"),
            parameter("Ratio", "float"),
            parameter("Mode", "choices", choices=["A", "B"]),
            parameter("Tables", "multichoice", choices=["One", "Two"]),
            parameter("Boot execute", "bool"),
            parameter("Hidden", "hidden"),
            parameter("Upload", "upload"),
            parameter("UploadFile", "upload_file"),
        ]
        backend = FakeBackend()
        server = MCPServer("test")
        specs = register_dynamic_artifact_tools(
            server,
            [artifact_row(parameters)],
            TargetContext(backend),
            backend,
            approved=APPROVED,
        )
        self.assertEqual(len(specs), 1)
        tool = server._tool_manager.get_tool("Windows.Test.One")
        schema = tool.parameters
        properties = schema["properties"]
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema.get("required", []), [])
        self.assertEqual(
            set(properties),
            {p["name"] for p in parameters if p["type"] not in {"hidden", "upload", "upload_file"}},
        )
        self.assertEqual(properties["Flag"]["type"], "boolean")
        self.assertEqual(properties["Count"]["type"], "integer")
        self.assertEqual(properties["Ratio"]["type"], "number")
        self.assertEqual(properties["Mode"]["enum"], ["A", "B"])
        self.assertEqual(properties["Tables"]["items"]["enum"], ["One", "Two"])
        self.assertEqual(properties["Regex"]["format"], "regex")
        self.assertEqual(properties["String"]["pattern"], "^x+$")
        self.assertEqual(properties["Plain"]["x-velociraptor-default"], "backend-default")
        self.assertNotIn("default", properties["Plain"])
        self.assertEqual(tool.description, "A test artifact.")

    def test_handler_sends_only_explicit_alias_values_and_returns_structured_flow(self):
        backend = FakeBackend()
        spec = validate_artifact_definitions(
            [artifact_row([parameter("Boot execute", "bool"), parameter("Needle", "regex")])],
            APPROVED,
        )[0]
        handler = make_artifact_handler(spec, TargetContext(backend), backend, index=0)
        result = handler(**{"Boot execute": False})
        self.assertFalse(result.is_error)
        self.assertEqual(result.content, [])
        self.assertEqual(result.structured_content["flow_id"], "F.real")
        self.assertEqual(result.structured_content["operation"], "start_artifact_collection")
        self.assertEqual(
            backend.calls,
            [("C.one", "Windows.Test.One", {"Boot execute": False})],
        )

        omitted = handler(**{"Boot execute": None, "Needle": None})
        self.assertFalse(omitted.is_error)
        self.assertEqual(backend.calls[-1][2], None)

        invalid = handler(**{"Needle": "["})
        self.assertTrue(invalid.is_error)
        self.assertEqual(invalid.structured_content["code"], "INVALID_ARGUMENT")
        self.assertEqual(len(backend.calls), 2)

    def test_space_identifier_is_quoted_and_unsafe_identifier_is_rejected(self):
        self.assertEqual(normalize_env_dict({"Boot execute": False}), "`Boot execute`=FALSE")
        self.assertEqual(vql_identifier("Normal_Name"), "Normal_Name")
        for value in ("", "Bad`Name", "Bad\nName"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    vql_identifier(value)

    def test_tool_name_conflict_fails_before_registration(self):
        backend = FakeBackend()
        server = MCPServer("test")
        server.add_tool(lambda: None, name="Windows.Test.One")
        with self.assertRaisesRegex(ArtifactRegistryError, "conflicts"):
            register_dynamic_artifact_tools(
                server,
                [artifact_row()],
                TargetContext(backend),
                backend,
                approved=APPROVED,
            )


if __name__ == "__main__":
    unittest.main()
