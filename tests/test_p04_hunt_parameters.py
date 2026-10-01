"""Spec-bound Hunt validation with actual services and SDK, fake backend only."""
from __future__ import annotations

import unittest

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from tests.test_p03_dynamic import APPROVED, artifact_row, parameter
from tests.test_p04_fixed_tools import FakeBackend
from velociraptor_api import normalize_env_dict
from velociraptor_dynamic_artifacts import (
    make_artifact_handler, register_dynamic_artifact_tools, validate_artifact_definitions,
)
from velociraptor_fixed_tools import FixedToolService, register_fixed_tools
from velociraptor_mcp_core import InvalidArgumentError, TargetContext


PARAMETERS = [
    parameter('Plain'), parameter('Text', 'string'), parameter('Flag', 'bool'),
    parameter('Count', 'int'), parameter('Big', 'int64'), parameter('Ratio', 'float'),
    parameter('Mode', 'choices', choices=['Safe', 'Deep']),
    parameter('Tables', 'multichoice', choices=['One', 'Two']),
    parameter('Regex', 'regex'), parameter('Pattern', 'string', validating_regex='^x+$'),
    parameter('YaraRule', 'yara'), parameter('When', 'timestamp'), parameter('CSV', 'csv'),
    parameter('Boot execute', 'bool'), parameter('Hidden', 'hidden'),
    parameter('Upload', 'upload'), parameter('UploadFile', 'upload_file'),
]
SPEC = validate_artifact_definitions([artifact_row(PARAMETERS)], APPROVED)[0]
VALID = {
    'Plain': '', 'Text': '中文\\quoted', 'Flag': False, 'Count': 0, 'Big': 2**40,
    'Ratio': 1.25, 'Mode': 'Deep', 'Tables': ['One', 'Two'], 'Regex': '^x+$',
    'Pattern': 'xx', 'YaraRule': 'rule x { condition: true }',
    'When': '2026-10-01T00:00:00Z', 'CSV': 'A,B\n1,2', 'Boot execute': True,
}
INVALID = [
    ('Flag', 'false'), ('Flag', 1), ('Count', True), ('Count', '1'), ('Count', 1.5),
    ('Big', False), ('Big', '1'), ('Ratio', True), ('Ratio', '1.5'),
    ('Plain', 1), ('Text', []), ('Mode', 'Outside'), ('Mode', 1),
    ('Tables', ['Outside']), ('Tables', ['One', 1]), ('Tables', 'One'),
    ('Tables', ('One',)), ('Tables', [['One']]), ('Regex', '['), ('Regex', 1),
    ('Pattern', 'wrong'), ('YaraRule', {}), ('When', 1), ('CSV', True),
    ('Boot execute', 'true'), ('Hidden', 'x'), ('Upload', 'x'), ('UploadFile', 'x'),
    ('Unknown', 'x'), ('Unknown', None), ('Hidden', None), ('Upload', None),
] + [(p['name'], None) for p in PARAMETERS if p['type'] not in ('hidden', 'upload', 'upload_file')]


def service(backend):
    return FixedToolService([SPEC], TargetContext(backend), backend, download_root=None)


class HuntParameterTests(unittest.TestCase):
    def test_rejections_happen_before_any_backend_operation(self):
        for field, value in INVALID:
            with self.subTest(field=field, value=value):
                backend = FakeBackend()
                with self.assertRaises(InvalidArgumentError):
                    service(backend).start_hunt(SPEC.name, {field: value}, None)
                self.assertEqual(backend.calls, [])

    def test_omission_preserves_backend_defaults_and_explicit_values(self):
        for supplied in (None, {}, VALID, {'Tables': []}, {'Ratio': 1}):
            with self.subTest(supplied=supplied):
                backend = FakeBackend()
                result = service(backend).start_hunt(SPEC.name, supplied, None)
                creates = [c for c in backend.calls if c[0] == 'create_paused_hunt']
                flows = [c for c in backend.calls if c[0] == 'start_collection']
                adds = [c for c in backend.calls if c[0] == 'add_hunt_flow']
                self.assertEqual(len(creates), 1)
                self.assertEqual(creates[0][2], supplied or None)
                self.assertEqual(len(flows), 1)
                self.assertEqual(flows[0][1:4], ('C.one', SPEC.name, supplied or None))
                self.assertEqual(adds, [('add_hunt_flow', 'C.one', 'H.real', 'F.started')])
                self.assertLess(backend.calls.index(creates[0]), backend.calls.index(flows[0]))
                self.assertLess(backend.calls.index(flows[0]), backend.calls.index(adds[0]))
                self.assertEqual((result.state, result.flow_state), ('PAUSED', 'WAITING'))
        encoded = normalize_env_dict({'Flag': False, 'Count': 0, 'Tables': ['One', 'Two']})
        self.assertEqual(encoded, "Flag=FALSE,Count=0,Tables=['One', 'Two']")

    def test_dynamic_default_none_remains_omitted(self):
        backend = FakeBackend()
        handler = make_artifact_handler(SPEC, TargetContext(backend), backend, index=0)
        defaults = {p.name: None for p in SPEC.exposed_parameters}
        result = handler(**defaults)
        self.assertFalse(result.is_error)
        self.assertIsNone(backend.calls[-1][3])
        result = handler(**{'Unknown': None})
        self.assertTrue(result.is_error)
        self.assertEqual(result.structured_content['code'], 'INVALID_ARGUMENT')
        self.assertEqual(len(backend.calls), 1)


class HuntSdkTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.backend = FakeBackend()
        self.server = MCPServer('p04-hunt-parameters')
        target = TargetContext(self.backend)
        specs = register_dynamic_artifact_tools(
            self.server, [artifact_row(PARAMETERS)], target, self.backend, approved=APPROVED,
        )
        register_fixed_tools(self.server, specs, target, self.backend, download_root=None)

    async def test_nested_hunt_invalid_parameters_return_structured_error(self):
        tool = self.server._tool_manager.get_tool('start_hunt')
        for field, value in INVALID:
            # JSON arrays, rather than Python-only tuples, enter the SDK wire seam.
            if isinstance(value, tuple):
                continue
            with self.subTest(field=field, value=value):
                result = await tool.run({'artifact': SPEC.name, 'parameters': {field: value}}, context=None)
                self.assertTrue(result.is_error)
                self.assertEqual(result.content, [])
                self.assertEqual(result.structured_content['code'], 'INVALID_ARGUMENT')
                self.assertEqual(self.backend.calls, [])

    async def test_dynamic_sdk_still_rejects_explicit_null_before_handler(self):
        tool = self.server._tool_manager.get_tool(SPEC.name)
        with self.assertRaises(ToolError):
            await tool.run({'Flag': None}, context=None)
        self.assertEqual(self.backend.calls, [])
        result = await tool.run({'Flag': False, 'Tables': ['One', 'Two']}, context=None)
        self.assertFalse(result.is_error)
        self.assertEqual(self.backend.calls[-1][3], {'Flag': False, 'Tables': ['One', 'Two']})


if __name__ == '__main__':
    unittest.main()
