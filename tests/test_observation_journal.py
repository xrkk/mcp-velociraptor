"""10 actual journal/observer with explicit MODEL publishers; no Windows IO."""
import asyncio
import copy
import hashlib
import unittest
from unittest.mock import patch

import velociraptor_observation as obs
from velociraptor_observation_journal import RequestJournal, JournalError
from velociraptor_observation_archive import ArchiveCodec, ArchiveError
from tests.test_observation_archive import accept
from tests.test_velociraptor_observation import context


def codec(**kw):
    budgets=dict(max_record_bytes=2048,max_records=100,max_total_bytes=100000,max_json_depth=12)
    return ArchiveCodec(**{**budgets,**kw})


FACT=dict(operation_id=None,mode='selected',client_id='MODEL-client')
def event(sequence=1):return dict(sequence=sequence,kind='target.resolve',facts=copy.deepcopy(FACT))


class ModelPublisher:
    def __init__(self):
        self.records=[];self.calls=[];self.close_calls=0;self.hook=lambda raw:None
        self.result_hook=lambda result:result
    def publish(self,raw):
        self.calls.append(raw);self.hook(raw);self.records.append(raw)
        parsed=codec().parse(raw)
        return self.result_hook(dict(ref=dict(path=f"{parsed['sequence']:08d}.json",size=len(raw),sha256=hashlib.sha256(raw).hexdigest()),identity={'MODEL':'no source authority'}))
    def close(self):self.close_calls+=1


class Factory:
    def __init__(self,**budgets):self.publishers=[];self.journals=[];self.budgets=budgets;self.hook=lambda p:None
    def __call__(self,key,tool,sha):
        p=ModelPublisher();self.hook(p);self.publishers.append(p)
        j=RequestJournal(p,codec(**self.budgets),dict(key=key,tool=tool,arguments_sha256=sha,acceptance_sequence=len(self.publishers)),owns_publisher=True)
        self.journals.append(j);return j


def observer(factory,**kw):
    return obs.RequestObserver('MODEL-instance',max_requests=20,max_events_per_request=kw.get('events',100),max_event_bytes=kw.get('bytes',10000),journal_factory=factory)


class JournalTests(unittest.TestCase):
    def journal(self,**kw):
        p=ModelPublisher();j=RequestJournal(p,codec(**kw),accept()['payload']);return p,j
    def test_order_head_chain_and_bounded_state(self):
        p,j=self.journal();initial=j.diagnostics();self.assertEqual(initial['record_count'],1)
        j.append(event());j.seal('returned');summary=codec().verify(iter(p.records))
        self.assertEqual((summary['status'],summary['event_count']),('COMPLETE',1))
        self.assertEqual(j.diagnostics()['head_ref'],summary['head_ref'])
        self.assertFalse(any(isinstance(v,list) for v in j.__dict__.values()))
        with self.assertRaises(JournalError):j.append(event(2))
        with self.assertRaises(JournalError):j.seal('returned')
        self.assertEqual(len(p.calls),3)
    def test_accept_reserves_before_any_publish(self):
        raw=codec().encode(accept());total=len(raw)+2048
        for limits in [dict(max_records=1),dict(max_total_bytes=total-1),dict(max_record_bytes=len(raw)-1),dict(max_json_depth=1)]:
            p=ModelPublisher()
            with self.subTest(limits=limits),self.assertRaises((JournalError,ArchiveError)):RequestJournal(p,codec(**limits),accept()['payload'])
            self.assertEqual(p.calls,[])
        p=ModelPublisher();j=RequestJournal(p,codec(max_records=2,max_total_bytes=total),accept()['payload']);j.seal('raised');self.assertEqual(codec().verify(p.records)['event_count'],0)
    def test_event_count_and_total_reservation_known_failed_seal(self):
        raw=codec().encode(accept());ev=codec().encode(dict(schema_version=1,kind='pc026-observation-event-v1',sequence=1,previous=dict(size=len(raw),sha256=hashlib.sha256(raw).hexdigest()),payload=event()))
        for limits in [dict(max_records=2),dict(max_total_bytes=len(raw)+len(ev)+2048-1)]:
            p,j=self.journal(**limits)
            with self.assertRaises(JournalError):j.append(event())
            self.assertEqual(len(p.calls),1);self.assertFalse(j.diagnostics()['poisoned']);j.seal('returned',failed=True)
            self.assertEqual(codec().verify(p.records)['status'],'FAILED')
        p,j=self.journal(max_total_bytes=len(raw)+len(ev)+2048);j.append(event());j.seal('returned')
    def test_invalid_events_fail_known_head_not_dump_or_extra_publish(self):
        for value in [dict(sequence=1,kind='MODEL.any',facts={}),event(2),{**event(),'extra':True},dict(sequence=1,kind='target.resolve',facts={'bad':True})]:
            p,j=self.journal();head=j.diagnostics()['head_ref']
            with self.assertRaises((JournalError,ArchiveError)):j.append(value)
            self.assertEqual(j.diagnostics()['head_ref'],head);self.assertEqual(len(p.calls),1)
            with self.assertRaises(JournalError):j.append(event())
            j.seal('raised',failed=True);self.assertEqual(codec().verify(p.records)['status'],'FAILED')
    def test_publish_before_after_or_bad_ref_never_advances_or_replays(self):
        for mode in ['before','after','bad-ref','bad-size','extra-ref','wrong-path','wrong-sha']:
            p,j=self.journal();before=j.diagnostics()
            def hook(raw):
                if mode=='before':raise OSError('MODEL before/unknown')
                if mode=='after':p.records.append(raw);raise OSError('MODEL after/unknown')
            def result(r):
                if mode=='bad-ref':r['ref']['size']+=1
                if mode=='bad-size':r['ref']['size']=float(r['ref']['size'])
                if mode=='extra-ref':r['ref']['extra']=None
                if mode=='wrong-path':r['ref']['path']='unexpected.json'
                if mode=='wrong-sha':r['ref']['sha256']='0'*64
                return r
            p.hook=hook;p.result_hook=result
            with self.subTest(mode=mode),self.assertRaises((OSError,JournalError)):j.append(event())
            after=j.diagnostics();self.assertEqual(after['head_ref'],before['head_ref']);self.assertEqual(after['event_count'],0);self.assertTrue(after['poisoned'])
            for action in [lambda:j.append(event()),lambda:j.seal('raised',failed=True)]:
                with self.assertRaises(JournalError):action()
            self.assertEqual(len(p.calls),2)
    def test_seal_failure_poison_and_ownership_close_once(self):
        p,j=self.journal();p.hook=lambda raw:(_ for _ in ()).throw(OSError('MODEL seal'))
        with self.assertRaises(OSError):j.seal('returned')
        self.assertFalse(j.diagnostics()['sealed']);self.assertTrue(j.diagnostics()['poisoned'])
        with self.assertRaises(JournalError):j.seal('returned')
        j.close();j.close();self.assertEqual(p.close_calls,0)
        p=ModelPublisher();j=RequestJournal(p,codec(),accept()['payload'],owns_publisher=True);j.close();j.close();self.assertEqual(p.close_calls,1)
    def test_constructor_unknown_closes_owned_and_preserves_original(self):
        p=ModelPublisher();original=OSError('MODEL accept');p.hook=lambda raw:(_ for _ in ()).throw(original)
        p.close=lambda:(_ for _ in ()).throw(RuntimeError('MODEL close'))
        with self.assertRaises(OSError) as got:RequestJournal(p,codec(),accept()['payload'],owns_publisher=True)
        self.assertIs(got.exception,original);self.assertEqual(len(p.calls),1)
    def test_parent_copy_and_no_identity_authority(self):
        p,j=self.journal();parent=j.parent();parent['key']['instance_id']='changed';self.assertNotEqual(j.parent(),parent)
        self.assertFalse({'approved','durable','identity'}&set(j.diagnostics()))

    def test_oversized_event_refuses_before_publish_and_preserves_seal(self):
        p,j=self.journal()
        huge=event();huge['facts']['client_id']='MODEL-'+('x'*3000)
        with self.assertRaises(ArchiveError):j.append(huge)
        self.assertEqual(len(p.calls),1);self.assertFalse(j.diagnostics()['poisoned'])
        j.seal('returned',failed=True)
        self.assertEqual(codec().verify(p.records)['status'],'FAILED')

    def test_unknown_seal_after_model_write_is_terminal(self):
        p,j=self.journal();head=j.diagnostics()['head_ref']
        def after(raw):p.records.append(raw);raise OSError('MODEL seal after write')
        p.hook=after
        with self.assertRaises(OSError):j.seal('returned')
        self.assertEqual(j.diagnostics()['head_ref'],head)
        self.assertEqual(codec().verify(p.records)['status'],'COMPLETE')
        self.assertFalse(j.diagnostics()['sealed'])
        with self.assertRaises(JournalError):j.seal('raised',failed=True)
        self.assertEqual(len(p.calls),2)


class ObserverJournalTests(unittest.IsolatedAsyncioTestCase):
    async def invoke(self,o,fn,rid=1):
        async def call(ctx):return fn()
        return await o.middleware(context(rid),call)
    async def test_accept_before_business_event_before_memory_and_exact6(self):
        f=Factory();o=observer(f);held=[]
        def call():
            scope=obs.current_scope();held.append(scope);p=f.publishers[0]
            self.assertEqual(len(p.records),1)
            def check(raw):
                if codec().parse(raw)['kind'].endswith('event-v1'):self.assertEqual(len(scope._events),0)
            p.hook=check;obs.emit('target.resolve',FACT);return {'isError':True}
        self.assertEqual(await self.invoke(o,call),{'isError':True});row=o.snapshots()[0]
        self.assertEqual(set(row),{'key','tool','arguments_sha256','events','outcome','sealed'})
        self.assertEqual(codec().verify(f.publishers[0].records)['status'],'COMPLETE');self.assertEqual(f.publishers[0].close_calls,1)
        self.assertEqual(o.journal_diagnostics()[0]['journal']['event_count'],1)
    async def test_accept_failure_permanent_key_no_business(self):
        f=Factory();f.hook=lambda p:setattr(p,'hook',lambda raw:(_ for _ in ()).throw(OSError('MODEL accept')));o=observer(f);calls=[]
        with self.assertRaises(OSError):await self.invoke(o,lambda:calls.append(1))
        with self.assertRaises(obs.ObservationError):await self.invoke(o,lambda:calls.append(2))
        self.assertEqual(calls,[]);self.assertEqual(len(f.publishers),1);self.assertEqual(f.publishers[0].close_calls,1)
        self.assertFalse(o.snapshots(allow_unsealed=True)[0]['sealed']);self.assertFalse(o.journal_diagnostics()[0]['acceptance_confirmed'])
        with self.assertRaises(obs.ObservationError):obs.current_scope()
    async def test_factory_parent_mutation_mismatch_and_close(self):
        for field in ['key','tool','sha']:
            f=Factory()
            def factory(key,tool,sha):
                if field=='key':key['request_id']=99
                if field=='tool':tool='wrong'
                if field=='sha':sha='0'*64
                return f(key,tool,sha)
            o=observer(factory)
            with self.assertRaises(JournalError):await self.invoke(o,lambda:self.fail('business'))
            self.assertEqual(f.publishers[0].close_calls,1);self.assertEqual(o.snapshots(allow_unsealed=True)[0]['key']['request_id'],1)
    async def test_journal_cannot_reuse_across_observer_scopes(self):
        f=Factory();o=observer(f);await self.invoke(o,lambda:None);j=f.journals[0];calls=len(f.publishers[0].calls)
        other=observer(lambda *args:j)
        with self.assertRaises(JournalError):await self.invoke(other,lambda:self.fail('business'))
        self.assertEqual(len(f.publishers[0].calls),calls);self.assertEqual(f.publishers[0].close_calls,1)
    async def test_memory_capacity_and_whitelist_failed_seal(self):
        for mode in ['count','bytes','whitelist']:
            f=Factory();o=observer(f,events=1,bytes=10000 if mode!='bytes' else 1)
            def call():
                if mode=='count':obs.emit('target.resolve',FACT)
                try:obs.emit('MODEL.unknown' if mode=='whitelist' else 'target.resolve',FACT)
                except (obs.ObservationError,ArchiveError):pass
            with self.assertRaises(obs.ObservationError):await self.invoke(o,call)
            self.assertEqual(codec().verify(f.publishers[0].records)['status'],'FAILED');self.assertTrue(o.snapshots()[0]['sealed'])
    async def test_oserror_poison_sticky_no_seal_memory_or_replay(self):
        f=Factory();o=observer(f)
        def call():
            p=f.publishers[0];p.hook=lambda raw:(_ for _ in ()).throw(OSError('MODEL event'))
            try:obs.emit('target.resolve',FACT)
            except OSError:pass
            self.assertTrue(obs.observation_failed());self.assertEqual(obs.current_scope().snapshot(allow_unsealed=True)['events'],[])
        with self.assertRaises(JournalError):await self.invoke(o,call)
        self.assertEqual(len(f.publishers[0].calls),2);self.assertEqual(f.publishers[0].close_calls,1);self.assertFalse(o.snapshots(allow_unsealed=True)[0]['sealed'])
    async def test_primary_exception_cancel_and_bad_note_survive_seal_close(self):
        class Primary(RuntimeError):
            def add_note(self,n):raise RuntimeError('MODEL note')
        for error in [Primary('MODEL primary'),asyncio.CancelledError('MODEL primary')]:
            f=Factory();o=observer(f)
            def call():
                f.publishers[0].hook=lambda raw:(_ for _ in ()).throw(OSError('MODEL seal'))
                f.publishers[0].close=lambda:(_ for _ in ()).throw(OSError('MODEL close'))
                raise error
            with self.assertRaises(type(error)) as got:await self.invoke(o,call)
            self.assertIs(got.exception,error);self.assertFalse(o.snapshots(allow_unsealed=True)[0]['sealed'])
            with self.assertRaises(obs.ObservationError):obs.current_scope()
    async def test_close_failure_normal_return_is_not_success(self):
        f=Factory();o=observer(f)
        def call():f.publishers[0].close=lambda:(_ for _ in ()).throw(OSError('MODEL close'));return 1
        with self.assertRaises(OSError):await self.invoke(o,call)
        self.assertFalse(o.snapshots(allow_unsealed=True)[0]['sealed']);self.assertTrue(f.journals[0].diagnostics()['close_failed'])
        self.assertEqual(codec().verify(f.publishers[0].records)['status'],'COMPLETE')
    async def test_two_concurrent_typed_parents_isolate_chains_and_tokens(self):
        f=Factory();o=observer(f);ready=asyncio.Event();count=0
        async def call(ctx):
            nonlocal count
            scope=obs.current_scope();count+=1
            if count==2:ready.set()
            await ready.wait();self.assertIs(scope,obs.current_scope());obs.emit('target.resolve',{**FACT,'client_id':str(ctx.request_id)})
        await asyncio.gather(o.middleware(context(7),call),o.middleware(context('7'),call))
        results=[codec().verify(p.records) for p in f.publishers];self.assertEqual([r['key']['request_id_type'] for r in results],['integer','string']);self.assertTrue(all(r['status']=='COMPLETE' for r in results))
    async def test_factory_premature_emit_is_sticky_before_business(self):
        f=Factory()
        def factory(*args):
            try:obs.emit('target.resolve',FACT)
            except obs.ObservationError:pass
            return f(*args)
        o=observer(factory)
        with self.assertRaises(obs.ObservationError):await self.invoke(o,lambda:self.fail('business'))
        self.assertEqual(codec().verify(f.publishers[0].records)['status'],'FAILED')


class ChainJournalTests(unittest.IsolatedAsyncioTestCase):
    async def run_chain(self, function, factory=None, rid=1):
        f = factory or Factory(); o = observer(f)
        async def call(ctx): return function()
        value = await o.middleware(context(rid), call)
        chain = codec().verify(f.publishers[0].records)
        self.assertEqual(chain['event_count'], len(o.snapshots()[0]['events']))
        self.assertEqual(chain['status'], 'COMPLETE')
        return value, f, o

    async def test_real_target_create_and_read_chains_model_boundaries(self):
        from tests.test_flow_observation import QueryBoundary, api
        from velociraptor_mcp_core import TargetContext, VelociraptorBackend
        from tests.test_read_observation import ReadBackend, service, FLOW
        q = QueryBoundary(); backend = VelociraptorBackend(); target = TargetContext(backend)
        with patch.object(api, '_ensure_fresh_collection_channel'), patch.object(api, 'run_vql_query', q):
            value, f, o = await self.run_chain(lambda: target.run_with_client(
                lambda c: backend.start_collection(c, 'Windows.System.Pslist')))
        self.assertEqual(value.flow_id, 'MODEL-flow')
        self.assertEqual([x['kind'] for x in q.calls], ['select', 'create', 'metadata'])
        self.assertEqual([x['kind'] for x in o.snapshots()[0]['events'] if x['kind'].startswith('flow.')],
                         ['flow.create.begin', 'flow.create.return', 'flow.metadata.return'])
        for operation in ('get_flow_status', 'get_flow_results', 'list_flow_files'):
            b = ReadBackend(); s = service(b)
            fn = (lambda: s.get_flow_results(FLOW, None, None, 3)) if operation == 'get_flow_results' else lambda: getattr(s, operation)(FLOW)
            _, f, o = await self.run_chain(fn)
            self.assertTrue(any(e['kind'].startswith('flow.') for e in o.snapshots()[0]['events']))
            self.assertNotIn('exists', [x['kind'] for x in b.calls])
            for raw, e in zip(f.publishers[0].records[1:-1], o.snapshots()[0]['events']):
                self.assertEqual(codec().parse(raw)['payload'], e)

    async def test_journal_fault_points_block_create_read_and_recovery(self):
        from tests.test_flow_observation import QueryBoundary, api
        from velociraptor_mcp_core import TargetContext, VelociraptorBackend
        from tests.test_read_observation import ReadBackend, service, FLOW
        for kind, expected in [('flow.create.begin', ['select']), ('flow.create.return', ['select', 'create']),
                               ('flow.metadata.return', ['select', 'create', 'metadata'])]:
            q = QueryBoundary(); b = VelociraptorBackend(); t = TargetContext(b); f = Factory(); o = observer(f)
            def fault(p):
                def hook(raw):
                    r = codec().parse(raw)
                    if r['kind'].endswith('event-v1') and r['payload']['kind'] == kind:
                        raise OSError('MODEL unknown publication')
                p.hook = hook
            f.hook = fault
            async def call(ctx): return t.run_with_client(lambda c: b.start_collection(c, 'Windows.System.Pslist'))
            with patch.object(api, '_ensure_fresh_collection_channel'), patch.object(api, 'run_vql_query', q):
                with self.assertRaises(OSError): await o.middleware(context(), call)
            self.assertEqual([x['kind'] for x in q.calls], expected)
            self.assertTrue(f.journals[0].diagnostics()['poisoned'])
            self.assertFalse(o.snapshots(allow_unsealed=True)[0]['sealed'])
        for kind, expected in [('flow.results.plan', ['select', 'metadata']),
                               ('flow.results.window', ['select', 'metadata', 'count', 'count', 'window'])]:
            b = ReadBackend(); s = service(b); f = Factory(); f.hook = fault; o = observer(f)
            async def call(ctx): return s.get_flow_results(FLOW, None, None, 3)
            with self.assertRaises(OSError): await o.middleware(context(), call)
            self.assertEqual([x['kind'] for x in b.calls], expected)
            self.assertTrue(f.journals[0].diagnostics()['poisoned'])

if __name__ == '__main__':
    unittest.main()
