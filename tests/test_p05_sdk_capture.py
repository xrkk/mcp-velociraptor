"""Windows mock regressions for transparent P05 SDK message retention."""
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import ANY, AsyncMock, Mock

import anyio
from tests.p05_sdk_capture import SDKCapture


@unittest.skipUnless(os.name == 'nt', 'CON002: behavioral tests execute only on Windows')
class SDKCaptureTests(unittest.IsolatedAsyncioTestCase):
    async def test_send_and_receive_delegate_original_objects_once(self):
        document = {'jsonrpc': '2.0', 'id': 3, 'result': {'content': [], 'isError': False}}
        message = SimpleNamespace(message=Mock())
        message.message.model_dump.return_value = document
        reader, writer = Mock(), Mock()
        reader.receive = AsyncMock(return_value=message)
        writer.send = AsyncMock()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sdk.ndjson'
            capture = SDKCapture(path)
            read, write = capture.wrap(reader, writer)
            await write.send(message)
            self.assertIs(await read.receive(), message)
            capture.close()
            rows = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
        writer.send.assert_awaited_once_with(message)
        reader.receive.assert_awaited_once_with()
        self.assertEqual([row['sequence'] for row in rows], [1, 2])
        self.assertEqual([row['direction'] for row in rows], ['client_to_server', 'server_to_client'])
        self.assertTrue(all(row['message'] == document for row in rows))

    async def test_exception_object_is_forwarded_without_sensitive_text_capture(self):
        failure = RuntimeError('synthetic-secret-do-not-log')
        reader = Mock(receive=AsyncMock(return_value=failure))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sdk.ndjson'
            capture = SDKCapture(path)
            read, _ = capture.wrap(reader, Mock())
            self.assertIs(await read.receive(), failure)
            capture.close()
            self.assertEqual(path.read_bytes(), b'')

    async def test_end_of_stream_ends_iteration(self):
        reader = Mock(receive=AsyncMock(side_effect=anyio.EndOfStream))
        with tempfile.TemporaryDirectory() as directory:
            capture = SDKCapture(Path(directory) / 'sdk.ndjson')
            read, _ = capture.wrap(reader, Mock())
            with self.assertRaises(StopAsyncIteration):
                await read.__anext__()
            capture.close()

    async def test_existing_original_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sdk.ndjson'
            path.write_bytes(b'original-failed-attempt')
            with self.assertRaises(FileExistsError):
                SDKCapture(path)
            self.assertEqual(path.read_bytes(), b'original-failed-attempt')

    async def test_actual_sdk_session_message_keeps_jsonrpc_id_and_result(self):
        from mcp.shared.message import SessionMessage
        from mcp.types import JSONRPCResponse
        document = {'jsonrpc': '2.0', 'id': 42, 'result': {'content': [{'type': 'text', 'text': '原件'}]}}
        message = SessionMessage(JSONRPCResponse.model_validate(document))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sdk.ndjson'
            capture = SDKCapture(path)
            read, _ = capture.wrap(Mock(receive=AsyncMock(return_value=message)), Mock())
            self.assertIs(await read.receive(), message)
            capture.close()
            self.assertEqual(json.loads(path.read_text(encoding='utf-8'))['message'], document)

    async def test_four_chain_call_retains_sdk_result_and_prevents_label_reuse(self):
        from tests import p05_real_acceptance as acceptance
        raw = SimpleNamespace(is_error=False, structured_content={'flow_id': 'F.synthetic'},
                              model_dump=Mock(return_value={'isError': False, 'structuredContent': {'flow_id': 'F.synthetic'}}))
        session = Mock(call_tool=AsyncMock(return_value=raw))
        capture = SimpleNamespace(request_id_for=Mock(return_value=7))
        evidence = {'calls': {}}
        result = await acceptance.call(session, evidence, 'start', 'collect_file', {'path': 'synthetic'}, capture)
        self.assertEqual(result['structured'], raw.structured_content)
        self.assertEqual(evidence['calls']['start']['mcp_result'], raw.model_dump.return_value)
        self.assertEqual(evidence['calls']['start']['sdk_request_id'], 7)
        capture.request_id_for.assert_called_once_with(
            tool='collect_file', arguments={'path': 'synthetic'},
            started_at=ANY, ended_at=ANY)
        with self.assertRaises(ValueError):
            await acceptance.call(session, evidence, 'start', 'collect_file', {'path': 'synthetic'}, capture)
        session.call_tool.assert_awaited_once()

    async def test_request_id_for_joins_one_unique_call_window(self):
        document = {'jsonrpc': '2.0', 'id': 5, 'method': 'tools/call',
                    'params': {'name': 't', 'arguments': {'a': 1}}}
        message = SimpleNamespace(message=Mock())
        message.message.model_dump.return_value = document
        with tempfile.TemporaryDirectory() as directory:
            capture = SDKCapture(Path(directory) / 'sdk.ndjson')
            capture.record('client_to_server', '2026-09-14T00:00:00.100123Z', '2026-09-14T00:00:00.200Z', message)
            capture.close()
            self.assertEqual(
                capture.request_id_for(tool='t', arguments={'a': 1},
                                       started_at='2026-09-14T00:00:00Z', ended_at='2026-09-14T00:00:01Z'), 5)
            with self.assertRaises(ValueError):
                capture.request_id_for(tool='t', arguments={'a': 2},
                                       started_at='2026-09-14T00:00:00Z', ended_at='2026-09-14T00:00:01Z')
            with self.assertRaises(ValueError):
                capture.request_id_for(tool='t', arguments={'a': 1},
                                       started_at='2026-09-14T00:00:01Z', ended_at='2026-09-14T00:00:02Z')


if __name__ == '__main__':
    unittest.main()
