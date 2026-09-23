"""Raw MCP contract checks: no coercion, side effect or validation echo."""
import asyncio
import os
import unittest
from unittest import mock

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from velo_transfer import mcp_tools
from velo_transfer.errors import TransferContentError
from velo_transfer.protocol import prepare_receipt, publication_receipt
from tests.test_transfer_protocol import binding, destination


class TransferWireContractTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        calls = self.calls
        class Service:
            def transfer_finish(self, **kwargs):
                calls.append(kwargs)
                return {'accepted': True}
            def transfer_chunk(self, **kwargs):
                calls.append(kwargs)
                return {'accepted': True}
            def shutdown(self):
                pass
        self.server = MCPServer('author-contract-fixture')
        manager = mcp_tools.register_transfer_tools(self.server, factory=Service)
        self.addCleanup(manager.shutdown)

    def call(self, name, **arguments):
        return asyncio.run(self.server.call_tool(name, arguments))

    def test_null_presence_and_action_combinations_rejected_before_service(self):
        for extras in ({'publication_receipt': None}, {'prepare_receipt': None},
                       {'source_validation_receipt': None}):
            with self.subTest(extras=extras), self.assertRaises(ToolError):
                self.call('transfer_finish', transfer_id='trial', request_digest='0' * 64,
                          action='prepare', **extras)
        self.assertFalse(self.calls)

    def test_integer_true_receipt_is_not_coerced(self):
        receipt = prepare_receipt(binding(), 'b' * 64)
        pub = publication_receipt(binding(), receipt, destination(), {'device': 1, 'inode': 2})
        receipt['prepared'] = 1
        with self.assertRaises(ToolError):
            self.call('transfer_finish', transfer_id='trial', request_digest='0' * 64,
                      action='release', prepare_receipt=receipt, publication_receipt=pub)
        self.assertFalse(self.calls)

    def test_raw_string_receipt_is_not_json_preparsed(self):
        import json
        receipt = prepare_receipt(binding(), 'b' * 64)
        pub = publication_receipt(binding(), receipt, destination(), {'device': 1, 'inode': 2})
        with self.assertRaises(ToolError):
            self.call('transfer_finish', transfer_id='trial', request_digest='0' * 64,
                      action='release', prepare_receipt=json.dumps(receipt), publication_receipt=pub)
        self.assertFalse(self.calls)

    def test_malformed_payload_is_not_reflected(self):
        marker = 'SYNTHETIC_SECRET_MUST_NOT_ECHO'
        for extras in ({'extra': marker}, {'offset': marker}, {'count': marker}):
            args = {'transfer_id': 'trial', 'request_digest': '0' * 64,
                    'offset': 0, 'count': 1, **extras}
            with self.subTest(extras=extras), self.assertRaises(ToolError) as caught:
                self.call('transfer_chunk', **args)
            self.assertIn('invalid_transfer_arguments', str(caught.exception))
            self.assertNotIn(marker, str(caught.exception))
        self.assertFalse(self.calls)

    def test_nonempty_whitespace_policy_is_not_disabled(self):
        def factory():
            raise TransferContentError('invalid_local_path')
        with mock.patch.object(mcp_tools, 'GuestTransferService', factory), \
                mock.patch.dict(os.environ, {'VELOCIRAPTOR_TRANSFER_POLICY': '  '}):
            manager = mcp_tools.TransferToolService()
            response = manager.invoke('transfer_capabilities').model_dump(by_alias=True)
            manager.shutdown()
        self.assertEqual(response['status'], 'error')
        self.assertEqual(response['error']['code'], 'invalid_local_path')


if __name__ == '__main__':
    unittest.main()
