"""Real TargetContext with explicitly modeled backend and business operations."""
import asyncio
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import velociraptor_observation as obs
from velociraptor_mcp_core import TargetContext, ClientIdNotFoundError, ClientNotFoundError, ClientNotUniqueError


class ModelBackend:
    def __init__(self, clients=None, exists=None):
        self.clients=list(clients if clients is not None else [[{'client_id':'MODEL-old'}]])
        self.exists=list(exists if exists is not None else [True])
        self.list_calls=0;self.exists_calls=[]
    def list_windows_clients(self):
        self.list_calls+=1
        value=self.clients.pop(0) if len(self.clients)>1 else self.clients[0]
        if isinstance(value,BaseException):raise value
        return value
    def client_id_exists(self,client):
        self.exists_calls.append(client)
        value=self.exists.pop(0) if len(self.exists)>1 else self.exists[0]
        if isinstance(value,BaseException):raise value
        return value


def observer(events=100):
    return obs.RequestObserver('MODEL-instance',max_requests=20,max_events_per_request=events,max_event_bytes=1000)


def ctx(rid=1):
    return SimpleNamespace(method='tools/call',request_id=rid,params={'name':'MODEL_target','arguments':{}},request=SimpleNamespace(headers={'mcp-session-id':'MODEL-session'}))


class TargetObservationTests(unittest.IsolatedAsyncioTestCase):
    async def invoke(self, o, function, rid=1):
        async def call(context):return function()
        return await o.middleware(ctx(rid),call)

    def validate(self, o):
        rows=o.snapshots()
        for row in rows:
            for e in row['events']:
                self.assertEqual(set(e['facts']),obs._TARGET_FIELDS[e['kind']])
                identity=e['facts']['operation_id']
                if identity is not None:self.assertEqual(str(uuid.UUID(identity)),identity)
        return rows[-1]['events']

    async def test_independent_resolve_cache_and_actual_clear(self):
        b=ModelBackend();t=TargetContext(b);o=observer()
        def operation():
            self.assertEqual(t.get_client_id(),'MODEL-old');self.assertEqual(t.get_client_id(),'MODEL-old');t.clear();t.clear()
        await self.invoke(o,operation);events=self.validate(o)
        self.assertEqual([e['kind'] for e in events],['target.resolve','target.resolve','target.clear','target.clear'])
        self.assertEqual([e['facts'].get('mode') for e in events[:2]],['selected','cache_hit'])
        self.assertEqual([e['facts']['previous_client_id'] for e in events[2:]],['MODEL-old',None])
        self.assertTrue(all(e['facts']['operation_id'] is None for e in events));self.assertEqual(b.list_calls,1);self.assertEqual(b.exists_calls,[])

    async def test_success_multiple_and_nested_operation_ids(self):
        b=ModelBackend();t=TargetContext(b);o=observer()
        def run():
            self.assertEqual(t.run_with_client(lambda c:t.run_with_client(lambda nested:nested)), 'MODEL-old')
            t.run_with_client(lambda c:c)
        await self.invoke(o,run);events=self.validate(o)
        ids={e['facts']['operation_id'] for e in events};self.assertEqual(len(ids),3);self.assertNotIn(None,ids)
        for identity in ids:
            group=[e for e in events if e['facts']['operation_id']==identity]
            self.assertEqual([e['kind'] for e in group],['target.resolve','target.operation.begin','target.operation.end'])
            self.assertEqual(group[-1]['facts']['outcome'],'returned')
        self.assertEqual(b.list_calls,1);self.assertEqual(b.exists_calls,[])

    async def test_existing_failure_and_probe_failure_preserve_identity(self):
        for exists in (True,RuntimeError('MODEL probe failure')):
            b=ModelBackend(exists=[exists]);t=TargetContext(b);o=observer();error=RuntimeError('MODEL secret not recorded')
            def operation(c):raise error
            with self.assertRaises(RuntimeError) as caught:await self.invoke(o,lambda:t.run_with_client(operation))
            self.assertIs(caught.exception,error);events=self.validate(o)
            self.assertEqual(events[2]['facts']['outcome'],'raised')
            self.assertEqual([e['kind'] for e in events].count('target.exists'),int(exists is True))
            self.assertEqual(b.list_calls,1);self.assertEqual(b.exists_calls,['MODEL-old'])
            self.assertNotIn('MODEL secret',str(o.snapshots()))

    async def test_false_probe_reselection_keeps_both_attempts_same_or_new_id(self):
        for replacement in ('MODEL-old','MODEL-new'):
            b=ModelBackend([[{'client_id':'MODEL-old'}],[{'client_id':replacement}]], [False]);t=TargetContext(b);o=observer();calls=[]
            def operation(c):
                calls.append(c)
                if len(calls)==1:raise RuntimeError('MODEL vanished')
                return c
            self.assertEqual(await self.invoke(o,lambda:t.run_with_client(operation)),replacement)
            events=self.validate(o)
            self.assertEqual([e['kind'] for e in events],['target.resolve','target.operation.begin','target.operation.end','target.exists','target.clear','target.resolve','target.operation.begin','target.operation.end'])
            self.assertEqual(calls,['MODEL-old',replacement]);self.assertEqual(b.list_calls,2);self.assertEqual(b.exists_calls,['MODEL-old'])
            self.assertEqual(len({e['facts']['operation_id'] for e in events}),1)
            self.assertEqual([e['facts']['attempt'] for e in events if e['kind']=='target.operation.begin'],[1,2])

    async def test_second_failure_no_third_operation_or_selection(self):
        for exists in (False,True,RuntimeError('MODEL probe failure')):
            b=ModelBackend([[{'client_id':'MODEL-old'}],[{'client_id':'MODEL-new'}]], [False,exists]);t=TargetContext(b);o=observer();calls=[];errors=[RuntimeError('first'),RuntimeError('second')]
            def operation(c):calls.append(c);raise errors[len(calls)-1]
            with self.assertRaises((RuntimeError,ClientIdNotFoundError)) as caught:await self.invoke(o,lambda:t.run_with_client(operation))
            if exists is not False:self.assertIs(caught.exception,errors[1])
            else:self.assertIs(caught.exception.__cause__,errors[1])
            events=self.validate(o);self.assertEqual(calls,['MODEL-old','MODEL-new']);self.assertEqual(b.list_calls,2);self.assertEqual(b.exists_calls,calls)
            self.assertEqual(len([e for e in events if e['kind']=='target.operation.end']),2)
            self.assertEqual(len([e for e in events if e['kind']=='target.exists']),1+int(type(exists) is bool))

    async def test_initial_selection_and_reselection_failure_have_no_fabricated_resolve(self):
        for candidates in ([],[{'client_id':'MODEL-a'},{'client_id':'MODEL-b'}]):
            b=ModelBackend([candidates]);o=observer();t=TargetContext(b)
            with self.assertRaises((ClientNotFoundError,ClientNotUniqueError)):await self.invoke(o,lambda:t.run_with_client(lambda c:self.fail('operation reached')))
            self.assertEqual(self.validate(o),[])
        b=ModelBackend([[{'client_id':'MODEL-old'}],[]],[False]);t=TargetContext(b);o=observer();calls=[]
        def operation(c):calls.append(c);raise RuntimeError('first')
        with self.assertRaises(ClientIdNotFoundError):await self.invoke(o,lambda:t.run_with_client(operation))
        events=self.validate(o);self.assertEqual(calls,['MODEL-old']);self.assertEqual(len([e for e in events if e['kind']=='target.resolve']),1);self.assertEqual(events[-1]['kind'],'target.clear')

    async def test_budget_before_operation_zero_side_effects_and_after_no_replay(self):
        for limit,expected_ops in ((1,0),(2,1)):
            b=ModelBackend();t=TargetContext(b);o=observer(limit);calls=[]
            with self.assertRaises(obs.ObservationError):await self.invoke(o,lambda:t.run_with_client(lambda c:calls.append(c)))
            row=o.snapshots()[0];self.assertEqual(len(calls),expected_ops);self.assertEqual(b.exists_calls,[]);self.assertEqual(b.list_calls,1);self.assertEqual(len(row['events']),limit);self.assertEqual(row['outcome'],'raised')

    async def test_end_observation_failure_retains_business_exception_or_cancel(self):
        for original in (RuntimeError('MODEL original'),asyncio.CancelledError('MODEL cancel')):
            b=ModelBackend();t=TargetContext(b);o=observer(2);calls=[]
            def operation(c):calls.append(c);raise original
            with self.assertRaises(type(original)) as caught:await self.invoke(o,lambda:t.run_with_client(operation))
            self.assertIs(caught.exception,original);self.assertEqual(calls,['MODEL-old']);self.assertEqual(b.exists_calls,[]);self.assertEqual(len(o.snapshots()[0]['events']),2)
            self.assertEqual(o.snapshots()[0]['outcome'],'cancelled' if isinstance(original,asyncio.CancelledError) else 'raised')

    async def test_optional_diagnostic_failure_cannot_replace_business_error(self):
        class Original(RuntimeError):
            def add_note(self,note):raise RuntimeError('MODEL diagnostic fault')
        original=Original('MODEL business');b=ModelBackend();t=TargetContext(b);o=observer(2)
        def operation(c):raise original
        with self.assertRaises(Original) as caught:await self.invoke(o,lambda:t.run_with_client(operation))
        self.assertIs(caught.exception,original);self.assertEqual(b.exists_calls,[])

    async def test_cancel_end_recorded_no_probe(self):
        b=ModelBackend();t=TargetContext(b);o=observer();error=asyncio.CancelledError()
        def operation(c):raise error
        with self.assertRaises(asyncio.CancelledError) as caught:await self.invoke(o,lambda:t.run_with_client(operation))
        self.assertIs(caught.exception,error);self.assertEqual(self.validate(o)[-1]['facts']['outcome'],'cancelled');self.assertEqual(b.exists_calls,[])

    async def test_all_emission_failure_points_never_trigger_extra_recovery(self):
        kinds=['target.resolve','target.operation.begin','target.operation.end','target.exists','target.clear']
        for kind in kinds:
            b=ModelBackend([[{'client_id':'MODEL-old'}],[{'client_id':'MODEL-new'}]],[False]);t=TargetContext(b);o=observer();calls=[];original=RuntimeError('MODEL business')
            real=obs.ObservationScope.emit
            def injection(scope,event,facts):
                if event==kind:raise obs.ObservationError('MODEL injection')
                return real(scope,event,facts)
            def operation(c):
                calls.append(c)
                if kind in ('target.exists','target.clear'):raise original
                return c
            with patch.object(obs.ObservationScope,'emit',injection):
                with self.assertRaises(obs.ObservationError):await self.invoke(o,lambda:t.run_with_client(operation))
            self.assertEqual(len(calls),int(kind not in ('target.resolve','target.operation.begin')))
            self.assertEqual(len(b.exists_calls),int(kind in ('target.exists','target.clear')))
            self.assertEqual(b.list_calls,1);self.assertEqual(o.snapshots()[0]['outcome'],'raised')
            self.assertEqual(t._client_id,None if kind=='target.clear' else 'MODEL-old')

    async def test_whitelist_validation_sticky_noop_and_closed_scope_rejection(self):
        obs.emit_target_fact('not-valid',object())
        with self.assertRaises(obs.ObservationError):obs.emit('target.clear',{})
        o=observer();held=[]
        async def call(context):
            held.append(obs.current_scope())
            with self.assertRaises(obs.ObservationError):obs.emit_target_fact('target.exists',{'operation_id':str(uuid.uuid4()),'attempt':True,'client_id':'MODEL-old','exists':False})
            self.assertTrue(obs.observation_failed())
        with self.assertRaises(obs.ObservationError):await o.middleware(ctx(),call)
        token=obs._current.set(held[0])
        try:
            with self.assertRaises(obs.ObservationError):obs.emit_target_fact('target.clear',{'operation_id':None,'previous_client_id':None})
        finally:obs._current.reset(token)

    async def test_exact_whitelist_refuses_extras_and_invalid_values(self):
        identity=str(uuid.uuid4())
        invalid=[('target.resolve',{'operation_id':None,'mode':'selected','client_id':'MODEL-old','secret':'MODEL-not-retained'}),
                 ('target.resolve',{'operation_id':None,'mode':'guessed','client_id':'MODEL-old'}),
                 ('target.resolve',{'operation_id':'not-uuid','mode':'selected','client_id':'MODEL-old'}),
                 ('target.clear',{'operation_id':None,'previous_client_id':''}),
                 ('target.exists',{'operation_id':identity,'attempt':1,'client_id':'MODEL-old','exists':1}),
                 ('target.operation.end',{'operation_id':identity,'attempt':3,'client_id':'MODEL-old','outcome':'returned'}),
                 ('target.operation.end',{'operation_id':identity,'attempt':1,'client_id':'MODEL-old','outcome':'success'})]
        for kind,facts in invalid:
            o=observer()
            def call():obs.emit_target_fact(kind,facts)
            with self.assertRaises((obs.ObservationError,ValueError)):await self.invoke(o,call)
            self.assertEqual(o.snapshots()[0]['events'],[]);self.assertEqual(o.snapshots()[0]['outcome'],'raised')

    async def test_shared_cache_race_facts_use_actual_local_operation_argument(self):
        import threading
        b=ModelBackend();t=TargetContext(b);t.get_client_id();o=observer();barrier=threading.Barrier(2,timeout=3);actual={}
        async def call(context):
            def operation(client):
                actual[context.request_id]=client
                t._client_id='MODEL-changed-'+str(context.request_id)
                barrier.wait()
                return client
            return await asyncio.to_thread(t.run_with_client,operation)
        await asyncio.gather(o.middleware(ctx('a'),call),o.middleware(ctx('b'),call))
        for row in o.snapshots():
            value=actual[row['key']['request_id']]
            self.assertTrue(all(e['facts']['client_id']==value for e in row['events']))
        self.assertEqual(b.list_calls,1);self.assertEqual(b.exists_calls,[])
        # Deliberately do not require both operations to have the same client.

    async def test_no_scope_does_not_generate_uuid_and_keeps_old_exception_recovery(self):
        b=ModelBackend([[{'client_id':'MODEL-old'}],[{'client_id':'MODEL-new'}]],[False]);t=TargetContext(b);calls=[]
        def operation(c):
            calls.append(c)
            if len(calls)==1:raise obs.ObservationError('ordinary no-scope exception')
            return c
        with patch('velociraptor_mcp_core.uuid.uuid4',side_effect=AssertionError('unexpected UUID')):
            self.assertEqual(t.run_with_client(operation),'MODEL-new')
        self.assertEqual(calls,['MODEL-old','MODEL-new']);self.assertEqual(b.exists_calls,['MODEL-old'])

    async def test_concurrent_parent_facts_are_not_cross_linked(self):
        o=observer();ready=asyncio.Event();count=0
        async def call(context):
            nonlocal count
            b=ModelBackend([[{'client_id':'MODEL-'+str(context.request_id)}]]);t=TargetContext(b)
            count+=1
            if count==2:ready.set()
            await ready.wait();t.run_with_client(lambda c:c)
        await asyncio.gather(o.middleware(ctx('a'),call),o.middleware(ctx('b'),call))
        for row in o.snapshots():self.assertTrue(all(e['facts']['client_id']=='MODEL-'+row['key']['request_id'] for e in row['events']))

if __name__=='__main__':unittest.main()
