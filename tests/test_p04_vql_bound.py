"""Exercise production service -> backend -> protobuf, with no channel or VM."""
from __future__ import annotations

import json
import re
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import grpc
from mcp.server.mcpserver import MCPServer

import velociraptor_api as api
from velociraptor_fixed_tools import FixedToolService, register_fixed_tools
from velociraptor_mcp_core import (
    RESPONSE_BYTE_LIMIT, TargetContext, VelociraptorBackend, canonical_json_bytes,
    success_result,
)


class Stream:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.reads = 0
        self.cancels = 0

    def __iter__(self):
        return self

    def __next__(self):
        item = next(self.responses)
        self.reads += 1
        if isinstance(item, Exception):
            raise item
        return item

    def cancel(self):
        self.cancels += 1


def response(rows):
    return SimpleNamespace(Response=json.dumps(rows), error='', log='')


class Stub:
    def __init__(self, responses):
        self.stream = Stream(responses)
        self.requests = []

    def Query(self, request):
        self.requests.append(request)
        return self.stream


def service():
    backend = VelociraptorBackend()
    return FixedToolService([], TargetContext(backend), backend, download_root=None)


def unwrap(test, stub):
    test.assertEqual(len(stub.requests), 1)
    request = stub.requests[0]
    test.assertEqual(request.org_id, '')
    test.assertEqual(len(request.Query), 1)
    wrapped = request.Query[0].VQL
    prefix, suffix = 'SELECT * FROM query(query=', ') LIMIT 251'
    test.assertTrue(wrapped.startswith(prefix), wrapped)
    test.assertTrue(wrapped.endswith(suffix), wrapped)
    literal = wrapped[len(prefix):-len(suffix)]
    # Independent lexical boundary, matching upstream vfilter String grammar:
    # github.com/Velocidex/vfilter/blob/master/vfilter.go (String lexer).
    test.assertRegex(literal, r"(?s)\A'(?:[^'\\]|\\.)*'\Z")
    # Generated literals escape only backslash and single quote. Decode these
    # independently rather than calling the production serializer as oracle.
    return re.sub(r"\\([\\'])", lambda m: m[1], literal[1:-1])


class VqlRequestTests(unittest.TestCase):
    def test_complete_query_is_one_literal_in_one_root_wrapper(self):
        queries = [
            'SELECT * FROM scope()',
            "SELECT '中文' AS X, \"double\" AS Y FROM scope()\n-- comment",
            "LET X = '''a\nb'''\r\nSELECT X FROM scope()",
            r"SELECT 'C:\\path\\file' AS X FROM scope()",
            "SELECT '\\n\\t\\x41' AS X FROM scope()\n/* ) LIMIT 0 */",
            "SELECT * FROM query(query='SELECT * FROM scope()') LIMIT 1",
            "LET X = SELECT * FROM range(end=1000)\nSELECT * FROM X",
            " SELECT '\\' ) LIMIT 0' AS X FROM scope()\t\n",
        ]
        for query in queries:
            with self.subTest(query=query):
                stub = Stub([response([])])
                with patch.object(api, 'stub', stub), patch.object(api, 'DEFAULT_ORG_ID', 'O.wrong'):
                    result = service().run_vql(query)
                self.assertEqual(unwrap(self, stub), query)
                self.assertEqual(result.data, [])
                self.assertFalse(result.truncated)

    def test_row_bound_and_cancel_at_251_even_if_server_overproduces(self):
        for count in (0, 250, 251, 600):
            with self.subTest(count=count):
                rows = [{'row': n} for n in range(count)]
                stub = Stub([response(rows), response([{'unread': True}])])
                # Exhaust normally for <251 rows; extra response must be unread
                # at the cap even when the first server batch is oversized.
                if count < 251:
                    stub = Stub([response(rows)])
                with patch.object(api, 'stub', stub):
                    result = service().run_vql('SELECT * FROM range(end=600)')
                self.assertEqual(unwrap(self, stub), 'SELECT * FROM range(end=600)')
                self.assertEqual(result.data, rows[:250])
                self.assertEqual(result.truncated, count > 250)
                self.assertEqual(stub.stream.reads, 1)
                self.assertEqual(stub.stream.cancels, int(count >= 251))

    def test_split_stream_never_reads_after_sentinel(self):
        stub = Stub([response([{'row': n} for n in range(250)]),
                     response([{'row': 250}]), RuntimeError('must not read')])
        with patch.object(api, 'stub', stub):
            result = service().run_vql('SELECT * FROM range(end=1000)')
        self.assertEqual(len(result.data), 250)
        self.assertTrue(result.truncated)
        self.assertEqual((stub.stream.reads, stub.stream.cancels), (2, 1))
        unwrap(self, stub)

    def test_byte_bound_preserves_complete_rows_and_truncated(self):
        rows = [{'text': '中' * 40000}, {'text': '文' * 40000}, {'text': '字' * 40000}]
        stub = Stub([response(rows)])
        with patch.object(api, 'stub', stub):
            result = success_result(service().run_vql('SELECT * FROM scope()'))
        self.assertEqual(result.structured_content['data'], rows[:2])
        self.assertTrue(result.structured_content['truncated'])
        self.assertLessEqual(len(canonical_json_bytes(result.structured_content)), RESPONSE_BYTE_LIMIT)
        full = dict(result.structured_content, data=rows)
        self.assertGreater(len(canonical_json_bytes(full)), RESPONSE_BYTE_LIMIT)
        self.assertEqual(stub.stream.cancels, 0)
        unwrap(self, stub)


class VqlSdkTests(unittest.IsolatedAsyncioTestCase):
    async def test_errors_and_empty_success_keep_sdk_structured_envelopes(self):
        server = MCPServer('p04-vql-bound')
        backend = VelociraptorBackend()
        register_fixed_tools(server, (), TargetContext(backend), backend, download_root=None)
        tool = server._tool_manager.get_tool('run_vql')
        cases = [
            (response([]), None),
            (SimpleNamespace(Response='', error='backend detail', log=''), 'BACKEND_ERROR'),
            (SimpleNamespace(Response='', error='', log='VQL Error: invalid query'), 'BACKEND_ERROR'),
            (RuntimeError('transport detail'), 'BACKEND_ERROR'),
            (grpc.RpcError('RPC detail'), 'BACKEND_ERROR'),
            (SimpleNamespace(Response='not json', error='', log=''), 'BACKEND_ERROR'),
            (response([{'text': '中' * RESPONSE_BYTE_LIMIT}]), 'ROW_TOO_LARGE'),
        ]
        for item, code in cases:
            with self.subTest(code=code, item=type(item).__name__):
                stub = Stub([item])
                with patch.object(api, 'stub', stub):
                    result = await tool.run({'query': 'SELECT * FROM scope()'}, context=None)
                self.assertEqual(result.content, [])
                self.assertEqual(result.is_error, code is not None)
                if code:
                    self.assertEqual(result.structured_content['code'], code)
                else:
                    self.assertEqual(result.structured_content['data'], [])
                    self.assertFalse(result.structured_content['truncated'])
                self.assertEqual(stub.stream.cancels, 0)
                unwrap(self, stub)


if __name__ == '__main__':
    unittest.main()
