import unittest
import asyncio
import copy
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from tests.p06_resource_gate import GIB, ResourceRejected, admit, qualified_deadline, guarded_step, remaining_peak, freeze_measurements


def reading(free):
    return {'physical_memory_bytes': 4*GIB, 'available_memory_bytes': GIB,
            'c_total_bytes': 100*GIB, 'c_free_bytes': free,
            'datastore_bytes': GIB, 'download_root_bytes': 0, 'report_root_bytes': 0}


def synthetic_qualification():
    source = Path(__file__).parent/'data/p03_invocations.json'
    entries = [(row['artifact'],row['artifact'],3600 if row['artifact']=='Windows.Memory.Acquisition' else 1200)
               for row in json.loads(source.read_text(encoding='utf-8'))
               if row['risk_class']=='resource_sensitive' and row['artifact']!='Windows.Network.PacketCapture']
    entries += [('forensic-triage','collect_forensic_triage',2400),('fixture-file','collect_file',300),
                ('download','download_flow_file',300)]
    sequence, free = 0, 80*GIB
    def sample():
        nonlocal sequence
        sequence += 1
        return {'reading':reading(free),'sequence':sequence,'run_id':'unit-run','server_pid':10,'hostname':'unit-host'}
    initial = sample()
    rows = [{'id':'static-resource-gate','observation':initial,
             'admission':admit(initial['reading'],remaining_increment=0,evidence_reserve=0,static=True)}]
    for label,tool,upper in entries:
        before = sample()
        free -= GIB
        after = sample()
        rows.append({'id':label,'tool':tool,'kind':'resource-qualification','passed':True,
                     'previous_upper_seconds':upper,'before':before,'after':after,'samples':[],
                     'elapsed_seconds':3.5,'admission':admit(before['reading'],remaining_increment=0,
                                                           evidence_reserve=0,static=tool=='Windows.Memory.Acquisition')})
    return {'steps':rows,'run_id':'unit-run','server_identity':{'pid':10,'computer_name':'unit-host'}}


class ResourceGateTests(unittest.TestCase):
    def test_qualification_requires_real_call_chains_not_only_passed_summaries(self):
        from tests.p06_resource_gate import verify_qualification_calls
        report = synthetic_qualification()
        report['calls'] = []
        def add(label,tool,args,value):
            report['calls'].append({'sequence':len(report['calls'])+1,'step_id':label,'tool':tool,
                'arguments':args,'structured':value,'is_error':False,'ended_at':'2026-09-13T00:00:00Z',
                'mcp_result':{'isError':False,'content':[],'structuredContent':value}})
        fixture_flow = None
        for index,row in enumerate(report['steps'][1:]):
            if row['id']=='download':
                continue
            label,flow = row['id'],f'F.unit{index}'
            row['flow_id'] = flow
            add(label,row['tool'],{}, {'flow_id':flow})
            add(label+'-wait','get_flow_status',{'flow_id':flow},{'flow_id':flow,'state':'FINISHED'})
            add(label+'-results','get_flow_results',{'flow_id':flow},{'operation':'get_flow_results','data':[]})
            files = []
            if label=='fixture-file':
                fixture_flow = flow
                files = [{'file_id':'a'*64}]
            add(label+'-files','list_flow_files',{'flow_id':flow},{'operation':'list_flow_files','data':files})
        add('download','download_flow_file',{'flow_id':fixture_flow,'file_id':'a'*64},
            {'flow_id':fixture_flow,'file_id':'a'*64})
        verify_qualification_calls(report)
        for mutation in ('missing','wrong-flow','wrong-original'):
            bad = copy.deepcopy(report)
            if mutation=='missing':
                bad['calls'].pop(1)
            elif mutation=='wrong-flow':
                bad['calls'][2]['arguments']['flow_id']='F.foreign'
            else:
                bad['calls'][0]['mcp_result']['isError']=True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                verify_qualification_calls(bad)

    def test_freeze_counts_all_eleven_chains_and_cumulative_peak(self):
        budget = freeze_measurements(synthetic_qualification())
        self.assertEqual(len(budget['steps']),11)
        self.assertEqual(budget['observed_peak_bytes'],11*GIB)
        self.assertEqual(budget['steps']['Windows.Memory.Acquisition']['deadline_seconds'],3600)

    def test_freeze_rejects_missing_chain_foreign_identity_or_unproved_admission(self):
        source = synthetic_qualification()
        cases = []
        missing = copy.deepcopy(source)
        missing['steps'].pop()
        cases.append(missing)
        foreign = copy.deepcopy(source)
        foreign['steps'][1]['after']['server_pid'] = 11
        cases.append(foreign)
        rejected = copy.deepcopy(source)
        rejected['steps'][1]['admission']['admitted'] = False
        cases.append(rejected)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                freeze_measurements(value)
    def test_remaining_peak_includes_retained_bytes_from_prior_pending_flows(self):
        measurements = {'a':{'peak_increment_bytes':10,'retained_increment_bytes':8},
                        'b':{'peak_increment_bytes':7,'retained_increment_bytes':2}}
        self.assertEqual(remaining_peak(['a','b'],measurements),15)
        self.assertEqual(remaining_peak(['b'],measurements),7)
    def test_static_gate_includes_two_memory_copies_and_safety_reserve(self):
        required = 2*(4*GIB + 64*1024**2) + 4*GIB
        with self.assertRaises(ResourceRejected) as caught:
            admit(reading(required-1), remaining_increment=0, evidence_reserve=0, static=True)
        self.assertEqual(caught.exception.evidence['required_free_bytes'], required)
        self.assertTrue(admit(reading(required), remaining_increment=0, evidence_reserve=0, static=True)['admitted'])

    def test_remaining_increment_is_recomputed_not_just_four_gib(self):
        with self.assertRaises(ResourceRejected) as caught:
            admit(reading(9*GIB), remaining_increment=6*GIB, evidence_reserve=GIB)
        self.assertFalse(caught.exception.evidence['admitted'])
        self.assertEqual(caught.exception.evidence['required_free_bytes'], 10*GIB)

    def test_large_evidence_reserve_and_initial_peak_are_not_ignored(self):
        row = admit(reading(20*GIB), remaining_increment=GIB, evidence_reserve=3*GIB, initial_peak=8*GIB)
        self.assertEqual(row['required_free_bytes'], 14*GIB)

    def test_bad_readings_fail_closed(self):
        for invalid in ({}, {**reading(10*GIB), 'c_free_bytes': True}, reading(101*GIB)):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                admit(invalid, remaining_increment=0, evidence_reserve=0)

    def test_deadline_never_shrinks_previous_upper(self):
        self.assertEqual(qualified_deadline(3.1, 3600), 3600)
        self.assertEqual(qualified_deadline(2000.1, 3600), 4001)
        for elapsed in (float('nan'), float('inf'), -1, True):
            with self.assertRaises(ValueError):
                qualified_deadline(elapsed, 60)


class GuardedExecutionTests(unittest.IsolatedAsyncioTestCase):
    async def test_qualification_binds_p04_results_without_inventing_flow_fields(self):
        from mcp.types import CallToolResult
        from tests.p06_resource_qualification import run_flow
        values = [{'flow_id':'F.unit'}, {'flow_id':'F.unit','state':'FINISHED'},
                  {'operation':'get_flow_results','status':'success','data':[]},
                  {'operation':'list_flow_files','status':'success','data':[]}]
        session = SimpleNamespace(call_tool=AsyncMock(side_effect=[
            CallToolResult(content=[],structuredContent=value,isError=False) for value in values]))
        sampler = SimpleNamespace(sample=AsyncMock(return_value={'reading':reading(80*GIB)}))
        report = {'calls':[],'steps':[]}
        _,_,flow = await run_flow(session,report,sampler,'unit','Windows.System.PowerShell',{},60)
        self.assertEqual(flow,'F.unit')
        self.assertTrue(report['steps'][0]['passed'])
        self.assertEqual([row['arguments']['flow_id'] for row in report['calls'][-2:]],['F.unit','F.unit'])

    async def test_qualification_transport_failure_and_cancellation_keep_wire_attempts(self):
        from tests.p06_resource_qualification import call
        report = {'calls': []}
        for failure in (RuntimeError('transport lost'), asyncio.CancelledError()):
            session = SimpleNamespace(call_tool=AsyncMock(side_effect=failure))
            with self.assertRaises(type(failure)):
                await call(session, report, 'poll', 'get_flow_status', {'flow_id': 'F.unit'})
        self.assertEqual([row['attempt'] for row in report['calls']], [1, 2])
        self.assertEqual([row['sequence'] for row in report['calls']], [1, 2])
        for row in report['calls']:
            self.assertTrue(row['is_error'])
            self.assertIsNone(row['mcp_result'])
            self.assertTrue(row['ended_at'])
            self.assertGreaterEqual(row['duration_ms'], 0)

    async def test_rejected_space_never_invokes_product_operation(self):
        failure = ResourceRejected('low space',{'admitted':False})
        gate = SimpleNamespace(before=AsyncMock(side_effect=failure))
        operation = AsyncMock()
        with self.assertRaises(ResourceRejected):
            await guarded_step(gate,'big-step',operation)
        operation.assert_not_awaited()

    async def test_deadline_cancels_operation_and_retains_admission_evidence(self):
        admission = {'admission':{'admitted':True}}
        gate = SimpleNamespace(before=AsyncMock(return_value=admission),timeout=lambda _:0.001,
                               after=AsyncMock())
        async def slow():
            await asyncio.sleep(1)
        with self.assertRaises(TimeoutError) as caught:
            await guarded_step(gate,'big-step',slow)
        self.assertEqual(caught.exception.resource_evidence,admission)
        gate.after.assert_not_awaited()

    async def test_success_records_before_and_after_without_extra_product_call(self):
        gate = SimpleNamespace(before=AsyncMock(return_value={'admission':{'admitted':True}}),
                               timeout=lambda _:1,after=AsyncMock(return_value={'reading':'after'}))
        operation = AsyncMock(return_value='result')
        result,resource = await guarded_step(gate,'big-step',operation)
        operation.assert_awaited_once()
        self.assertEqual(result,'result')
        self.assertEqual(resource['after'],{'reading':'after'})

    async def test_http_identity_change_is_rejected_without_logging_authorization(self):
        from tests.scenario_runner import HttpHeaderCapture, ScenarioFailure
        response = SimpleNamespace(status_code=200,headers={'mcp-session-id':'wrong','x-mcp-server-instance':'server'})
        transport = SimpleNamespace(handle_async_request=AsyncMock(return_value=response))
        capture = HttpHeaderCapture(transport)
        capture.expected_identity = ('session','server')
        request = SimpleNamespace(method='POST',url=SimpleNamespace(path='/mcp'),
                                  headers={'mcp-session-id':'session','Authorization':'Bearer test-secret'})
        with self.assertRaises(ScenarioFailure):
            await capture.handle_async_request(request)
        self.assertNotIn('test-secret',repr(capture.responses))


if __name__ == '__main__':
    unittest.main()
