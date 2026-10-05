"""Binary requests retain the protocol selected by their existing SDK session."""
import base64
import hashlib
import time
import unittest
import httpx2
from velo_transfer import wire
from velo_transfer.adapters import _DirectChunkChannel, AdapterError

class ProtocolChannel(unittest.IsolatedAsyncioTestCase):
    async def test_negotiated_version_passes_same_session_binary_gate(self):
        seen=[];version='2025-11-25';payload=b'complete original bytes'
        def server(request):
            seen.append(request)
            if request.headers.get('mcp-protocol-version')!=version:
                return httpx2.Response(400,json={'error':{'code':'invalid_protocol'}})
            body=wire.encode({'status':'success','result':{'verified_offset':0,'chunks':[
                {'offset':0,'count':len(payload),'chunk_sha256':hashlib.sha256(payload).hexdigest()}]}},payload,'pull_response')
            return httpx2.Response(200,headers={'content-type':'application/octet-stream','x-mcp-server-instance':'fixed-instance'},content=body)
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(server)) as http:
            args={'transfer_id':'same-transfer','request_digest':'a'*64,'offset':0,'count_per_chunk':1024,'chunk_count':1}
            denied=_DirectChunkChannel(http,'http://localhost/mcp','same-sdk-session','fixed-instance',time.monotonic()+5,2)
            with self.assertRaises(AdapterError):await denied.call('transfer_chunks',args)
            channel=_DirectChunkChannel(http,'http://localhost/mcp','same-sdk-session','fixed-instance',time.monotonic()+5,2,version)
            value=await channel.call('transfer_chunks',args)
        self.assertEqual(base64.b64decode(value['chunks'][0]['data_base64']),payload)
        self.assertTrue(all(r.url.path=='/chunkbin' and r.headers['mcp-session-id']=='same-sdk-session' for r in seen))
