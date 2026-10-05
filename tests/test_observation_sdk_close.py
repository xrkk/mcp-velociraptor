"""Actual SDK stop/reconnect and actual DELETE status; local MODEL server only."""
import asyncio
from mcp import ClientSession
from tests.test_observation_maintenance import MaintenanceHTTP
from velociraptor_observation_maintenance import _settled_sdk
from velociraptor_observation_controller import ControllerError

class SDKClose(MaintenanceHTTP):
    async def test_get_loop_stops_before_delayed_real_delete(self):
        before=len(self.responses);identity=[None,None];actual=self.controller._close_session
        async def delayed(sid,owner,reason='DELETE'):
            if sid!=self.original:await asyncio.sleep(1.3)
            return await actual(sid,owner,reason)
        self.controller._close_session=delayed
        async with _settled_sdk(self.url,self.http,lambda:tuple(identity)) as (read,write):
            async with ClientSession(read,write) as sdk:
                initialized=await sdk.initialize()
                identity[:]=[next(r.headers['mcp-session-id'] for r in self.responses[before:]
                    if r.request.method=='POST' and r.headers.get('mcp-session-id')),initialized.protocol_version]
                result=await sdk.call_tool('echo',{'value':'settled'})
                self.assertFalse(result.is_error)
        responses=self.responses[before:]
        self.assertTrue(all(r.status_code<300 for r in responses))
        deletes=[r for r in responses if r.request.method=='DELETE']
        self.assertEqual(len(deletes),1);self.assertEqual(deletes[0].status_code,200)
        self.assertTrue(deletes[0].is_closed)
        self.assertIn('x-velo-observation-cut',deletes[0].headers)
        self.assertEqual(self.controller._sessions[identity[0]]['state'],'CLOSED')
    async def test_captured_get_closes_normally_before_sdk_cancellation(self):
        import json,tempfile,uuid
        from pathlib import Path
        import httpx2
        from tests.p06_http_body_capture import CaptureTransport,verify
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        run=Path(temp.name)/str(uuid.uuid4());run.mkdir(mode=0o700)
        capture=CaptureTransport(httpx2.AsyncHTTPTransport(),run,run.name)
        identity=[None,None]
        async with httpx2.AsyncClient(transport=capture,headers={'Authorization':'Bearer MODEL'},timeout=15) as http:
            async with _settled_sdk(self.url,http,lambda:tuple(identity),_capture=capture) as (read,write):
                async with ClientSession(read,write) as sdk:
                    initialized=await sdk.initialize();identity[1]=initialized.protocol_version
                    # The actual initialized response headers are read from the
                    # HTTP transport, rather than manufacturing a response.
                    identity[0]=next(iter(self.controller._sessions.keys()-{self.original}))
                    result=await sdk.call_tool('echo',{'value':'captured normal GET close'})
                    self.assertFalse(result.is_error)
                    await asyncio.sleep(.05)
        index=verify(run,run.name)
        gets=[row for row in index['exchanges'] if row['method']=='GET']
        self.assertEqual(len(gets),1)
        self.assertEqual(gets[0]['response_end'],'closed');self.assertIsNone(gets[0]['error'])
        deletes=[row for row in index['exchanges'] if row['method']=='DELETE']
        self.assertEqual(len(deletes),1);self.assertEqual(deletes[0]['response_status'],200)

    async def test_primary_failure_survives_captured_get_close_error(self):
        import tempfile,uuid
        from pathlib import Path
        import httpx2
        from tests.p06_http_body_capture import CaptureTransport,verify
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        run=Path(temp.name)/str(uuid.uuid4());run.mkdir(mode=0o700)
        capture=CaptureTransport(httpx2.AsyncHTTPTransport(),run,run.name)
        original=capture.close_original;faults=[];identity=[None,None]
        async def fail_once(stream):
            await original(stream)
            if not faults and any(s.original is stream and s.direction=='response' and s.row['method']=='GET' for s in capture.streams):
                faults.append('actual owned GET close error')
                raise httpx2.ReadError('MODEL captured GET close failure after actual socket close')
        capture.close_original=fail_once
        async with httpx2.AsyncClient(transport=capture,headers={'Authorization':'Bearer MODEL'},timeout=15) as http:
            try:
                async with _settled_sdk(self.url,http,lambda:tuple(identity),_capture=capture) as (read,write):
                    async with ClientSession(read,write) as sdk:
                        initialized=await sdk.initialize();identity[1]=initialized.protocol_version
                        identity[0]=next(iter(self.controller._sessions.keys()-{self.original}))
                        await sdk.call_tool('echo',{'value':'capture-close-first-error'})
                        await asyncio.sleep(.05)
                        raise ValueError('original operation before GET close failure')
            except BaseException as primary:
                pending=[primary];leaves=[];notes=[]
                while pending:
                    error=pending.pop();notes.extend(getattr(error,'__notes__',[]))
                    if isinstance(error,BaseExceptionGroup):pending.extend(error.exceptions)
                    else:leaves.append(error)
                self.assertEqual([(type(e),str(e)) for e in leaves],[(ValueError,'original operation before GET close failure')])
                self.assertIn('formal GET capture close failed: ReadError',notes)
                self.assertIn('formal DELETE failed: CaptureError',notes)
            else:self.fail('original operation failure was swallowed')
        self.assertEqual(faults,['actual owned GET close error'])
        index=verify(run,run.name)
        self.assertEqual(index['status'],'FAILED')
        self.assertTrue(any(row['error'] and row['error']['type']=='ReadError' for row in index['exchanges'] if row['method']=='GET'))
        self.assertEqual(len([row for row in index['exchanges'] if row['method']=='DELETE']),0)
        self.assertEqual(self.controller._sessions[identity[0]]['state'],'OPEN')
        # The failed capture refuses new network effects. No fake DELETE or
        # CLOSED proof is generated to hide that denial.

    async def test_actual_delete_503_is_not_swallowed(self):
        before=len(self.responses);identity=[None,None];actual=self.controller._close_session
        async def denied(sid,owner,reason='DELETE'):
            if sid!=self.original:raise ControllerError('MODEL_actual_close_denied',503)
            return await actual(sid,owner,reason)
        self.controller._close_session=denied
        import httpx2
        with self.assertRaises(httpx2.HTTPStatusError) as caught:
            async with _settled_sdk(self.url,self.http,lambda:tuple(identity)) as (read,write):
                async with ClientSession(read,write) as sdk:
                    initialized=await sdk.initialize()
                    identity[:]=[next(r.headers['mcp-session-id'] for r in self.responses[before:]
                        if r.request.method=='POST' and r.headers.get('mcp-session-id')),initialized.protocol_version]
        self.assertEqual(caught.exception.response.status_code,503)
        self.assertTrue(caught.exception.response.is_closed)
        self.assertEqual(len([r for r in self.responses[before:] if r.request.method=='DELETE']),1)
        self.controller._close_session=actual

    async def test_primary_sdk_failure_survives_actual_delete_503(self):
        before=len(self.responses);identity=[None,None];actual=self.controller._close_session
        async def denied(sid,owner,reason='DELETE'):
            if sid!=self.original:raise ControllerError('MODEL_actual_close_denied',503)
            return await actual(sid,owner,reason)
        self.controller._close_session=denied
        try:
            try:
                async with _settled_sdk(self.url,self.http,lambda:tuple(identity)) as (read,write):
                    async with ClientSession(read,write) as sdk:
                        initialized=await sdk.initialize()
                        identity[:]=[next(r.headers['mcp-session-id'] for r in self.responses[before:]
                            if r.request.method=='POST' and r.headers.get('mcp-session-id')),initialized.protocol_version]
                        raise ValueError('original SDK operation failure')
            except BaseException as primary:
                pending=[primary];leaves=[]
                while pending:
                    error=pending.pop()
                    if isinstance(error,BaseExceptionGroup):pending.extend(error.exceptions)
                    else:leaves.append(error)
                self.assertEqual([(type(e),str(e)) for e in leaves],[(ValueError,'original SDK operation failure')])
                self.assertIn('formal DELETE failed: HTTPStatusError',primary.__notes__)
            else:self.fail('primary SDK failure was swallowed')
            deletes=[r for r in self.responses[before:] if r.request.method=='DELETE']
            self.assertEqual(len(deletes),1);self.assertEqual(deletes[0].status_code,503)
        finally:self.controller._close_session=actual

def load_tests(loader,tests,pattern):
    import unittest
    return unittest.TestSuite(SDKClose(name) for name in (
        'test_get_loop_stops_before_delayed_real_delete',
        'test_captured_get_closes_normally_before_sdk_cancellation',
        'test_primary_failure_survives_captured_get_close_error',
        'test_actual_delete_503_is_not_swallowed',
        'test_primary_sdk_failure_survives_actual_delete_503'))
