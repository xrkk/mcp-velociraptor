"""Scoped model tests; real default-SDK HTTP proof is a separate loopback run."""
import asyncio
import hashlib
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

import velociraptor_observation as obs


def context(rid=1, session='MODEL-session', arguments=None, method='tools/call'):
    params={'name':'MODEL_tool'}
    if arguments is not None:
        params['arguments']=arguments
    return SimpleNamespace(method=method, request_id=rid, params=params,
                           request=SimpleNamespace(headers={'mcp-session-id':session}))


def observer(**limits):
    return obs.RequestObserver('MODEL-instance',max_requests=limits.get('requests',20),
                               max_events_per_request=limits.get('events',100),
                               max_event_bytes=limits.get('bytes',10000))


class ObservationTests(unittest.IsolatedAsyncioTestCase):
    async def test_exact_shape_arguments_hash_deep_copy_and_sealed_refusal(self):
        o=observer();args={'z':'中文','a':[1,True,None]};facts={'a':[{'v':1}]};held=[]
        async def call(ctx):
            held.append(obs.current_scope());obs.emit('MODEL.nested',facts);facts['a'][0]['v']=2
            with self.assertRaises(obs.ObservationError):held[0].snapshot()
            live=held[0].snapshot(allow_unsealed=True);self.assertFalse(live['sealed']);self.assertIsNone(live['outcome'])
            return 'same result'
        self.assertEqual(await o.middleware(context(arguments=args),call),'same result')
        row=o.snapshots()[0]
        self.assertEqual(set(row),{'key','tool','arguments_sha256','events','outcome','sealed'})
        self.assertEqual(set(row['key']),{'instance_id','session_id','request_id_type','request_id'})
        self.assertEqual(set(row['events'][0]),{'sequence','kind','facts'})
        self.assertEqual(row['events'][0]['facts'],{'a':[{'v':1}]})
        self.assertEqual(row['arguments_sha256'],hashlib.sha256(json.dumps(args,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest())
        before=o.snapshots();row['events'].clear();row['key']['instance_id']='changed'
        self.assertEqual(o.snapshots(),before)
        with self.assertRaises(obs.ObservationError):held[0].emit('MODEL.late',{})
        self.assertEqual(o.snapshots(),before)
        with self.assertRaises(obs.ObservationError):obs.emit('MODEL.none',{})

    async def test_typed_key_and_duplicate_preserve_original_before_business(self):
        o=observer();executed=[]
        async def call(ctx):executed.append(ctx.request_id)
        for rid in (7,'7'):await o.middleware(context(rid),call)
        before=o.snapshots()
        with self.assertRaises(obs.ObservationError):await o.middleware(context(7),call)
        self.assertEqual(o.snapshots(),before);self.assertEqual(executed,[7,'7'])
        self.assertEqual([r['key']['request_id_type'] for r in before],['integer','string'])

    async def test_invalid_parent_and_arguments_never_call_business(self):
        for rid in (None,True,False,7.0,[],{}):
            with self.subTest(rid=rid):
                o=observer()
                with self.assertRaises(obs.ObservationError):await o.middleware(context(rid),self.forbidden)
                self.assertEqual(o.snapshots(),[])
        cases=[context(session=''),context(session=None),context()]
        cases[-1].request=None
        c=context();c.params['name']='';cases.append(c)
        for args in ([],True,'bad',{'nan':float('nan')},{1:'bad'},{'v':object()}):
            c=context();c.params['arguments']=args;cases.append(c)
        c=context();c.params['arguments']=None;cases.append(c)
        for c in cases:
            with self.assertRaises(obs.ObservationError):await observer().middleware(c,self.forbidden)

    async def forbidden(self,ctx):self.fail('business reached after admission refusal')

    async def test_other_methods_pass_without_http_identity(self):
        o=observer();c=context(None,method='tools/list');c.request=None
        async def call(ctx):return ctx
        self.assertIs(await o.middleware(c,call),c);self.assertEqual(o.snapshots(),[])

    async def test_request_capacity_preserves_prefix(self):
        o=observer(requests=1)
        async def call(ctx):obs.emit('MODEL.first',{})
        await o.middleware(context(1),call);before=o.snapshots()
        with self.assertRaises(obs.ObservationError):await o.middleware(context(2),self.forbidden)
        self.assertEqual(o.snapshots(),before)

    async def test_event_capacity_is_sticky_even_if_caught(self):
        for limits in ({'events':1},{'bytes':65}):
            o=observer(**limits);held=[]
            async def call(ctx):
                s=obs.current_scope();held.append(s);obs.emit('a',{});before=s.snapshot(allow_unsealed=True)
                with self.assertRaises(obs.ObservationError):obs.emit('b',{'too_big':'x'*100})
                self.assertEqual(s.snapshot(allow_unsealed=True),before)
                return 'must not become success'
            with self.assertRaises(obs.ObservationError):await o.middleware(context(),call)
            row=o.snapshots()[0];self.assertEqual(row['outcome'],'raised');self.assertTrue(row['sealed']);self.assertEqual(len(row['events']),1)

    async def test_strict_facts_and_kind_validation_preserve_prefix(self):
        cyclic={};cyclic['self']=cyclic
        for facts in ([1],{1:'x'},{'n':float('inf')},{'x':object()},{'x':(1,)},cyclic,{'x':'\ud800'}):
            o=observer()
            async def call(ctx):
                obs.emit('a',{});s=obs.current_scope();before=s.snapshot(allow_unsealed=True)
                with self.assertRaises((obs.ObservationError,RecursionError)):obs.emit('b',facts)
                self.assertEqual(s.snapshot(allow_unsealed=True),before)
            with self.assertRaises(obs.ObservationError):await o.middleware(context(),call)
        for kind in ('','with space','a'*65,7):
            o=observer()
            async def call(ctx):obs.emit(kind,{})
            with self.assertRaises(obs.ObservationError):await o.middleware(context(),call)

    async def test_canonical_byte_boundary_and_no_runtime_io(self):
        import contextlib
        import io
        event={'sequence':1,'kind':'MODEL.bytes','facts':{'value':'中文'}}
        size=len(json.dumps(event,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode())
        o=observer(bytes=size);stdout=io.StringIO()
        async def call(ctx):obs.emit('MODEL.bytes',{'value':'中文'})
        with contextlib.redirect_stdout(stdout), patch('builtins.open',side_effect=AssertionError('unexpected I/O')):
            await o.middleware(context(),call)
        self.assertEqual(stdout.getvalue(),'');self.assertEqual(o.snapshots()[0]['events'],[event])
        o=observer(bytes=size-1)
        with self.assertRaises(obs.ObservationError):await o.middleware(context(),call)
        self.assertEqual(o.snapshots()[0]['events'],[])
        self.assertEqual(o.snapshots()[0]['outcome'],'raised')

    async def test_thread_safe_sequences(self):
        o=observer(events=200)
        async def call(ctx):
            scope=obs.current_scope()
            def writer(n):
                for i in range(25):scope.emit('MODEL.thread',{'writer':n,'i':i})
            with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(writer,range(4)))
        await o.middleware(context(),call)
        events=o.snapshots()[0]['events'];self.assertEqual([e['sequence'] for e in events],list(range(1,101)))
        self.assertEqual(len({(e['facts']['writer'],e['facts']['i']) for e in events}),100)

    async def test_concurrent_scopes_and_exception_cleanup(self):
        o=observer();ready=asyncio.Event();count=0
        async def call(ctx):
            nonlocal count
            scope=obs.current_scope();count+=1
            if count==2:ready.set()
            await ready.wait();self.assertIs(obs.current_scope(),scope);obs.emit('MODEL.current',{'id':ctx.request_id})
        await asyncio.gather(o.middleware(context('a'),call),o.middleware(context('b'),call))
        for row in o.snapshots():self.assertEqual(row['events'][0]['facts']['id'],row['key']['request_id'])
        error=RuntimeError('MODEL original')
        async def bad(ctx):obs.emit('MODEL.before',{});raise error
        with self.assertRaises(RuntimeError) as caught:await o.middleware(context('error'),bad)
        self.assertIs(caught.exception,error);self.assertEqual(o.snapshots()[-1]['outcome'],'raised')
        with self.assertRaises(obs.ObservationError):obs.current_scope()

    async def test_cancellation_classification_and_reset(self):
        o=observer();started=asyncio.Event()
        async def call(ctx):obs.emit('MODEL.begin',{});started.set();await asyncio.Event().wait()
        t=asyncio.create_task(o.middleware(context('cancel'),call));await started.wait();t.cancel()
        with self.assertRaises(asyncio.CancelledError):await t
        self.assertEqual(o.snapshots()[0]['outcome'],'cancelled')
        with self.assertRaises(obs.ObservationError):obs.current_scope()
        async def next_call(ctx):obs.emit('MODEL.next',{})
        await o.middleware(context('next'),next_call)
        self.assertEqual(o.snapshots()[-1]['events'][0]['kind'],'MODEL.next')

    async def test_finalization_failure_does_not_mask_primary_and_stays_unsealed(self):
        o=observer();original=RuntimeError('MODEL original')
        async def bad(ctx):raise original
        with patch.object(obs.ObservationScope,'_finish',side_effect=RuntimeError('MODEL finalize')):
            with self.assertRaises(RuntimeError) as caught:await o.middleware(context(),bad)
        self.assertIs(caught.exception,original)
        with self.assertRaises(obs.ObservationError):o.snapshots()
        self.assertFalse(o.snapshots(allow_unsealed=True)[0]['sealed'])
        with self.assertRaises(obs.ObservationError):obs.current_scope()

    async def test_nested_token_restores_outer_scope(self):
        o=observer();inner=observer()
        async def child(ctx):obs.emit('MODEL.inner',{})
        async def outer(ctx):
            old=obs.current_scope();await inner.middleware(context('child'),child)
            self.assertIs(obs.current_scope(),old);obs.emit('MODEL.outer',{})
        await o.middleware(context('outer'),outer)
        self.assertEqual(o.snapshots()[0]['events'][0]['kind'],'MODEL.outer')

    def test_explicit_constructor_limits(self):
        for instance in ('',None,True,1):
            with self.assertRaises(obs.ObservationError):obs.RequestObserver(instance,max_requests=1,max_events_per_request=1,max_event_bytes=100)
        for n in (0,-1,True,1.0,None):
            for field in ('max_requests','max_events_per_request','max_event_bytes'):
                kwargs=dict(max_requests=1,max_events_per_request=1,max_event_bytes=100);kwargs[field]=n
                with self.assertRaises(obs.ObservationError):obs.RequestObserver('MODEL-instance',**kwargs)



class SDKObservationTests(unittest.IsolatedAsyncioTestCase):
    async def test_default_sync_worker_cancel_tail_is_unsealed_until_exit(self):
        import socket
        import uuid
        import httpx2
        import uvicorn
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
        from mcp.server import MCPServer
        from mcp.shared.jsonrpc_dispatcher import JSONRPCDispatcher
        from mcp.types import CallToolResult, TextContent

        o=obs.RequestObserver(str(uuid.uuid4()),max_requests=3,
                              max_events_per_request=4,max_event_bytes=1000)
        app=MCPServer('MODEL_observation');app.middleware.append(o.middleware)
        entered=threading.Event();release=threading.Event();held=[];worker_thread=[]
        loop_thread=threading.get_ident()
        def model_tool(MODEL_wait:bool=False)->CallToolResult:
            held.append(obs.current_scope());worker_thread.append(threading.get_ident())
            obs.emit('MODEL.begin',{})
            if MODEL_wait:
                entered.set()
                if not release.wait(5):raise TimeoutError('MODEL deadline')
                obs.emit('MODEL.tail',{})
            return CallToolResult(content=[TextContent(type='text',text='MODEL result')])
        app.add_tool(model_tool,name='MODEL_tool',description='MODEL synchronous tool')
        sock=socket.socket();sock.bind(('127.0.0.1',0));sock.listen()
        self.assertNotEqual(sock.getsockname()[1],28790)
        server=uvicorn.Server(uvicorn.Config(app.streamable_http_app(),log_level='error',access_log=False))
        task=asyncio.create_task(server.serve(sockets=[sock]))
        try:
            async with asyncio.timeout(15):
                while not server.started:
                    if task.done():await task
                    await asyncio.sleep(.01)
                async with httpx2.AsyncClient(trust_env=False) as client:
                    async with streamable_http_client(f'http://127.0.0.1:{sock.getsockname()[1]}/mcp',http_client=client) as (read,write):
                        dispatcher=JSONRPCDispatcher(read,write)
                        async with ClientSession(dispatcher=dispatcher) as session:
                            await session.initialize()
                            call=asyncio.create_task(dispatcher.send_raw_request('tools/call',{'name':'MODEL_tool','arguments':{'MODEL_wait':True}},{'request_id':'cancel'}))
                            while not entered.is_set():await asyncio.sleep(.01)
                            call.cancel()
                            with self.assertRaises(asyncio.CancelledError):await call
                            self.assertFalse(held[0].snapshot(allow_unsealed=True)['sealed'])
                            with self.assertRaises(obs.ObservationError):o.snapshots()
                            release.set()
                            while not held[0].snapshot(allow_unsealed=True)['sealed']:await asyncio.sleep(.01)
                            self.assertEqual([e['kind'] for e in held[0].snapshot()['events']],['MODEL.begin','MODEL.tail'])
                            for rid in (7,'7'):
                                await dispatcher.send_raw_request('tools/call',{'name':'MODEL_tool','arguments':{}},{'request_id':rid})
                            rows=o.snapshots()
                            self.assertEqual([r['key']['request_id_type'] for r in rows],['string','integer','string'])
                            self.assertTrue(all(r['sealed'] for r in rows))
                            self.assertEqual([r['events'][0]['kind'] for r in rows],['MODEL.begin']*3)
                            self.assertTrue(all(t!=loop_thread for t in worker_thread))
                            with self.assertRaises(obs.ObservationError):obs.current_scope()
        finally:
            release.set();server.should_exit=True
            await asyncio.wait_for(task,10);sock.close()
        self.assertTrue(task.done());self.assertEqual(sock.fileno(),-1)

if __name__=='__main__':unittest.main()
