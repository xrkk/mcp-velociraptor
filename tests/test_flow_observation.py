"""Actual target/backend/API chain; MODEL substitutes only query/channel boundaries."""
import asyncio
import hashlib
import json
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import velociraptor_observation as obs
from velociraptor_mcp_core import BackendError, TargetContext, VelociraptorBackend
with patch('velociraptor_env.load_environment'):
    import velociraptor_api as api


def context(rid=1):
    return SimpleNamespace(method='tools/call', request_id=rid,
        params={'name': 'MODEL_flow', 'arguments': {}},
        request=SimpleNamespace(headers={'mcp-session-id': 'MODEL-session'}))


def observer(events=100, size=10000):
    return obs.RequestObserver('MODEL-instance', max_requests=20,
        max_events_per_request=events, max_event_bytes=size)


class QueryBoundary:
    """No live stub/config/channel; keep exact VQL and actual result objects."""
    def __init__(self, rows=None, metadata=None):
        self.rows = [{'flow_id': 'MODEL-flow'}] if rows is None else rows
        self.metadata = [{'state': 'RUNNING'}] if metadata is None else metadata
        self.calls = []
        self.lock = threading.Lock()
        self.on_create = None

    def __call__(self, vql, **kwargs):
        if 'collect_client(' in vql:
            kind, result = 'create', self.rows
        elif 'FROM flows(' in vql:
            kind, result = 'metadata', self.metadata
        elif 'ORDER BY client_id' in vql:
            kind, result = 'select', [{'client_id': 'MODEL-client', 'system': 'windows', 'hostname': 'MODEL'}]
        elif 'FROM clients()' in vql:
            kind, result = 'exists', [{'client_id': 'MODEL-client'}]
        else:
            raise AssertionError('unrecognized MODEL query')
        with self.lock:
            self.calls.append({'kind': kind, 'vql': vql, 'kwargs': kwargs,
                               'thread': threading.get_ident()})
        if kind == 'create' and self.on_create is not None:
            self.on_create()
        if isinstance(result, BaseException):
            raise result
        return result


class FlowObservationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.boundary = QueryBoundary()
        self.channel = patch.object(api, '_ensure_fresh_collection_channel').start()
        self.query = patch.object(api, 'run_vql_query', self.boundary).start()
        self.addCleanup(patch.stopall)
        self.backend = VelociraptorBackend()
        self.target = TargetContext(self.backend)

    async def invoke(self, o, function=None, rid=1):
        async def call(ctx):
            return (function or (lambda: self.target.run_with_client(
                lambda c: self.backend.start_collection(c, 'Windows.System.Pslist'))))()
        return await o.middleware(context(rid), call)

    def kinds(self):
        return [c['kind'] for c in self.boundary.calls]

    def flow(self, o):
        events = [e for e in o.snapshots()[-1]['events'] if e['kind'].startswith('flow.')]
        for e in events:
            self.assertEqual(set(e['facts']), obs._FLOW_FIELDS[e['kind']])
        return events

    async def test_actual_chain_normalization_original_vql_counts_and_public_result(self):
        rows = [{'flow_id': 'MODEL-first', 'artifacts': ['Server.actual'], 'timeout': 77,
                 'max_upload_bytes': 888, 'specs': {'z': ['秘密', False], 'a': None}, 'secret': 'excluded'},
                {'flow_id': 'MODEL-second', 'specs': None}, {}]
        self.boundary.rows = rows
        parameters = {'Boot execute': False, 'Count': 0, 'Names': ['One', 'Two']}
        o = observer()
        result = await self.invoke(o, lambda: self.target.run_with_client(lambda c:
            self.backend.start_collection(c, ' Windows.System.Pslist ', parameters)))
        self.assertEqual(result.model_dump(), {'operation': 'start_collection', 'status': 'RUNNING',
                                             'warnings': [], 'flow_id': 'MODEL-first'})
        self.assertEqual(self.kinds(), ['select', 'create', 'metadata'])
        vql = self.boundary.calls[1]['vql']
        env = api.normalize_env_dict(parameters)
        self.assertEqual(vql, "LET collection <= collect_client(urgent='TRUE',client_id='MODEL-client', "
            f"artifacts='Windows.System.Pslist', env=dict({env})) "
            'SELECT flow_id, request.artifacts as artifacts, request.timeout as timeout, '
            'request.max_upload_bytes as max_upload_bytes, request.specs[0] as specs FROM foreach(row=collection) ')
        self.assertEqual(self.boundary.calls[1]['kwargs'], {'org_id': None, 'root_org': True})
        events = self.flow(o); self.assertEqual([e['kind'] for e in events],
            ['flow.create.begin', 'flow.create.return', 'flow.metadata.return'])
        begin, returned, metadata = [e['facts'] for e in events]
        self.assertEqual(begin['parameters_sha256'], hashlib.sha256(env.encode()).hexdigest())
        self.assertEqual((begin['artifact'], begin['timeout'], begin['max_bytes']), ('Windows.System.Pslist', None, None))
        self.assertEqual(metadata['flow_id'], 'MODEL-first')
        self.assertEqual(len({f['creation_id'] for f in (begin, returned, metadata)}), 1)
        self.assertEqual(returned['rows'][0], dict(row_index=0, flow_id='MODEL-first', artifacts=['Server.actual'],
            timeout=77, max_upload_bytes=888, specs_sha256=hashlib.sha256(obs._canonical(rows[0]['specs'])).hexdigest()))
        self.assertEqual(returned['rows'][1]['specs_sha256'], hashlib.sha256(b'null').hexdigest())
        self.assertIsNone(returned['rows'][2]['specs_sha256'])
        self.assertEqual([r['row_index'] for r in returned['rows']], [0, 1, 2])
        rows[0]['artifacts'].append('later'); rows[0]['specs']['z'].append('later')
        self.assertEqual(self.flow(o), events)
        self.assertNotIn('excluded', str(o.snapshots())); self.assertNotIn('秘密', str(o.snapshots()))
        self.assertNotIn('Boot execute', str(o.snapshots()))

    async def test_direct_api_object_identity_and_no_metadata(self):
        o = observer(); rows = self.boundary.rows
        value = await self.invoke(o, lambda: self.target.run_with_client(lambda c:
            api.start_collection(c, 'Windows.System.Pslist', org_id='MODEL-org')))
        self.assertIs(value, rows)
        events = self.flow(o)
        self.assertEqual([e['kind'] for e in events], ['flow.create.begin', 'flow.create.return'])
        self.assertEqual(events[0]['facts']['org_id'], 'MODEL-org')
        self.assertFalse(events[0]['facts']['root_org'])
        self.assertEqual(self.kinds(), ['select', 'create'])

    async def test_memory_boost_and_explicit_resources(self):
        for artifact, timeout, limit, actual_timeout, actual_limit in (
            ('Windows.Memory.Acquisition', None, None, 3600, 8 * 1024**3),
            ('Windows.Memory.Acquisition', 4000, 2, 4000, 8 * 1024**3),
            ('Windows.System.Pslist', 5, 6, 5, 6)):
            with self.subTest(artifact=artifact, timeout=timeout):
                o = observer(); self.boundary.calls.clear()
                await self.invoke(o, lambda: self.target.run_with_client(lambda c:
                    self.backend.start_collection(c, artifact, timeout=timeout, max_upload_bytes=limit)))
                begin = self.flow(o)[0]['facts']
                self.assertEqual((begin['timeout'], begin['max_bytes']), (actual_timeout, actual_limit))
                vql = next(c['vql'] for c in self.boundary.calls if c['kind'] == 'create')
                self.assertIn(f', timeout={actual_timeout}, max_bytes={actual_limit}', vql)

    async def test_empty_and_missing_flow_keep_actual_return_no_metadata(self):
        for rows in ([], [{}], [{'flow_id': None}]):
            self.boundary.rows = rows; self.boundary.calls.clear(); o = observer()
            with self.assertRaises(BackendError): await self.invoke(o)
            self.assertEqual([e['kind'] for e in self.flow(o)], ['flow.create.begin', 'flow.create.return'])
            self.assertEqual(self.kinds(), ['select', 'create', 'exists'])
            self.assertEqual(len(self.flow(o)[1]['facts']['rows']), len(rows))
            self.target.clear()

    async def test_metadata_failure_retains_return_and_original_exception(self):
        for metadata in ([], [{'state': ''}], [{'state': 1}], RuntimeError('MODEL secret metadata')):
            self.boundary.metadata = metadata; self.boundary.calls.clear(); o = observer()
            with self.assertRaises((BackendError, RuntimeError)) as caught: await self.invoke(o)
            if isinstance(metadata, RuntimeError): self.assertIs(caught.exception, metadata)
            self.assertEqual([e['kind'] for e in self.flow(o)], ['flow.create.begin', 'flow.create.return'])
            self.assertEqual(self.kinds().count('create'), 1)
            self.assertEqual(self.kinds().count('metadata'), 1)
            self.assertEqual(self.kinds().count('exists'), 1)  # original business recovery
            self.assertNotIn('secret metadata', str(o.snapshots()))

    async def test_invalid_watched_rows_sticky_no_metadata_probe_or_repeat(self):
        invalid = ((), [1], [{'flow_id': 1}], [{'artifacts': 'bad'}], [{'artifacts': [1]}],
                   [{'timeout': True}], [{'max_upload_bytes': 1.2}], [{'specs': float('nan')}],
                   [{'specs': (1,)}], [{'specs': {1: 'bad'}}])
        cyclic = []; cyclic.append(cyclic)
        for rows in (*invalid, [{'specs': cyclic}]):
            self.boundary.rows = rows; self.boundary.calls.clear(); o = observer()
            with self.assertRaises(obs.ObservationError): await self.invoke(o)
            self.assertEqual([e['kind'] for e in self.flow(o)], ['flow.create.begin'])
            self.assertEqual(self.kinds().count('create'), 1)
            self.assertNotIn('exists', self.kinds()); self.assertNotIn('metadata', self.kinds())
            self.assertEqual(o.snapshots()[0]['outcome'], 'raised')

    async def test_missing_operation_cross_client_and_cross_scope_before_rpc(self):
        cases = (lambda: api.start_collection('MODEL-client', 'Windows.System.Pslist'),
                 lambda: self.target.run_with_client(lambda c: api.start_collection('MODEL-other', 'Windows.System.Pslist')))
        for run in cases:
            o = observer(); self.boundary.calls.clear()
            with self.assertRaises(obs.ObservationError): await self.invoke(o, run)
            self.assertNotIn('create', self.kinds()); self.assertNotIn('exists', self.kinds())
        outer = observer(); inner = observer()
        async def child(ctx):
            api.start_collection('MODEL-client', 'Windows.System.Pslist')
        async def parent(ctx):
            # Real outer TargetContext association, a distinct inner request scope.
            async def nested(): await inner.middleware(context('inner'), child)
            def operation(c):
                with self.assertRaises(obs.ObservationError):
                    asyncio.run(nested())
            await asyncio.to_thread(self.target.run_with_client, operation)
        await outer.middleware(context('outer'), parent)
        self.assertEqual(inner.snapshots()[0]['outcome'], 'raised')
        self.assertEqual(self.flow(outer), [])

    async def test_original_rpc_exception_cancel_and_context_cleanup(self):
        for error in (RuntimeError('MODEL original RPC'), asyncio.CancelledError('MODEL cancel')):
            self.boundary.rows = error; self.boundary.calls.clear(); o = observer()
            with self.assertRaises(type(error)) as caught: await self.invoke(o)
            self.assertIs(caught.exception, error)
            self.assertEqual([e['kind'] for e in self.flow(o)], ['flow.create.begin'])
            self.assertEqual(self.kinds().count('create'), 1)
            self.assertEqual(self.kinds().count('exists'), int(isinstance(error, RuntimeError)))
            self.assertIsNone(obs._operation_current.get()); self.assertIsNone(obs._creation_current.get())
            self.assertFalse(obs.observation_active())
        self.boundary.rows = [{'flow_id': 'MODEL-after'}]
        self.assertEqual((await self.invoke(observer())).flow_id, 'MODEL-after')

    async def test_each_flow_emitter_fault_before_and_after_append_no_recovery(self):
        real = obs.ObservationScope.emit
        for kind in obs._FLOW_FIELDS:
            for after in (False, True):
                self.boundary.calls.clear(); o = observer()
                def injection(scope, event, facts):
                    if event == kind:
                        if after: real(scope, event, facts)
                        raise obs.ObservationError('MODEL injected emitter')
                    return real(scope, event, facts)
                with patch.object(obs.ObservationScope, 'emit', injection):
                    with self.assertRaises(obs.ObservationError): await self.invoke(o)
                self.assertEqual(self.kinds().count('create'), int(kind != 'flow.create.begin'))
                self.assertEqual(self.kinds().count('metadata'), int(kind == 'flow.metadata.return'))
                self.assertNotIn('exists', self.kinds())
                expected = list(obs._FLOW_FIELDS)[:list(obs._FLOW_FIELDS).index(kind) + int(after)]
                self.assertEqual([e['kind'] for e in self.flow(o)], expected)
                self.assertEqual(o.snapshots()[0]['outcome'], 'raised')
                self.assertIsNone(obs._creation_current.get())

    async def test_budgets_before_and_after_creation_preserve_prefix(self):
        for budget, count in ((2, 0), (3, 1), (4, 1), (5, 1)):
            self.boundary.calls.clear(); o = observer(budget)
            with self.assertRaises(obs.ObservationError): await self.invoke(o)
            self.assertEqual(self.kinds().count('create'), count)
            self.assertNotIn('exists', self.kinds()); self.assertEqual(len(o.snapshots()[0]['events']), budget)
        self.boundary.rows = [{'flow_id': 'MODEL-flow', 'artifacts': ['x' * 10000]}]
        self.boundary.calls.clear(); o = observer(size=600)
        with self.assertRaises(obs.ObservationError): await self.invoke(o)
        self.assertEqual(self.kinds().count('create'), 1)
        self.assertEqual([e['kind'] for e in self.flow(o)], ['flow.create.begin'])

    async def test_nested_actual_backend_and_direct_api_restore_outer_creation(self):
        o = observer(); nested = False
        def on_create():
            nonlocal nested
            if nested: return
            nested = True
            self.target.run_with_client(lambda c: self.backend.start_collection(c, 'Windows.Nested'))
            # Same operation, separate API invocation; must not replace outer slot.
            api.start_collection('MODEL-client', 'Windows.Direct')
        self.boundary.on_create = on_create
        await self.invoke(o)
        events = self.flow(o); begins = [e['facts'] for e in events if e['kind'] == 'flow.create.begin']
        self.assertEqual(len({f['creation_id'] for f in begins}), 3)
        self.assertEqual(len({f['operation_id'] for f in begins}), 2)
        for begin in begins:
            group = [e['kind'] for e in events if e['facts']['creation_id'] == begin['creation_id']]
            self.assertEqual(group, ['flow.create.begin', 'flow.create.return'] +
                ([] if begin['artifact'] == 'Windows.Direct' else ['flow.metadata.return']))
        self.assertEqual(self.kinds().count('create'), 3); self.assertEqual(self.kinds().count('metadata'), 2)
        self.assertNotIn('exists', self.kinds())

    async def test_original_reselection_new_creation_same_operation_attempt_two(self):
        o = observer(); selected = 0; created = 0
        original = self.boundary
        def query(vql, **kw):
            nonlocal selected, created
            rows = original(vql, **kw)
            kind = original.calls[-1]['kind']
            if kind == 'select':
                selected += 1
                return [{'client_id': 'MODEL-old' if selected == 1 else 'MODEL-new', 'system': 'windows'}]
            if kind == 'exists': return []
            if kind == 'create':
                created += 1
                if created == 1: raise RuntimeError('MODEL vanished before return')
            return rows
        with patch.object(api, 'run_vql_query', query):
            await self.invoke(o)
        self.assertEqual(self.kinds(), ['select', 'create', 'exists', 'select', 'create', 'metadata'])
        events = self.flow(o)
        begins = [e['facts'] for e in events if e['kind'] == 'flow.create.begin']
        self.assertEqual([f['attempt'] for f in begins], [1, 2])
        self.assertEqual([f['client_id'] for f in begins], ['MODEL-old', 'MODEL-new'])
        self.assertEqual(len({f['operation_id'] for f in begins}), 1)
        self.assertEqual(len({f['creation_id'] for f in begins}), 2)
        self.assertEqual([e['kind'] for e in events],
            ['flow.create.begin', 'flow.create.begin', 'flow.create.return', 'flow.metadata.return'])

    async def test_metadata_cancel_original_identity_and_return_retained(self):
        error = asyncio.CancelledError('MODEL metadata cancel')
        self.boundary.metadata = error; o = observer()
        with self.assertRaises(asyncio.CancelledError) as caught: await self.invoke(o)
        self.assertIs(caught.exception, error)
        self.assertEqual(self.kinds(), ['select', 'create', 'metadata'])
        self.assertEqual([e['kind'] for e in self.flow(o)], ['flow.create.begin', 'flow.create.return'])
        self.assertIsNone(obs._creation_current.get()); self.assertIsNone(obs._operation_current.get())

    async def test_returned_strict_integer_has_no_invented_positive_constraint(self):
        self.boundary.rows = [{'flow_id': '', 'artifacts': [], 'timeout': -1, 'max_upload_bytes': 0}]
        o = observer()
        result = await self.invoke(o)
        self.assertEqual(result.flow_id, '')
        row = self.flow(o)[1]['facts']['rows'][0]
        self.assertEqual((row['timeout'], row['max_upload_bytes'], row['artifacts']), (-1, 0, []))
        self.assertIsNone(row['specs_sha256'])

    async def test_swallowed_observation_failure_stays_sticky_before_next_rpc(self):
        real = obs.ObservationScope.emit; o = observer()
        def injection(scope, kind, facts):
            if kind == 'flow.create.return': raise obs.ObservationError('MODEL fault')
            return real(scope, kind, facts)
        def operation(client):
            with self.assertRaises(obs.ObservationError): api.start_collection(client, 'Windows.First')
            api.start_collection(client, 'Windows.Second')
        with patch.object(obs.ObservationScope, 'emit', injection):
            with self.assertRaises(obs.ObservationError):
                await self.invoke(o, lambda: self.target.run_with_client(operation))
        self.assertEqual(self.kinds(), ['select', 'create'])
        self.assertEqual([e['kind'] for e in self.flow(o)], ['flow.create.begin'])

    async def test_two_concurrent_parents_actual_sync_chain(self):
        o = observer(); barrier = threading.Barrier(2, timeout=3)
        self.boundary.on_create = barrier.wait
        async def call(ctx):
            target = TargetContext(self.backend)
            return await asyncio.to_thread(target.run_with_client,
                lambda c: self.backend.start_collection(c, 'Windows.' + ctx.request_id))
        await asyncio.gather(o.middleware(context('a'), call), o.middleware(context('b'), call))
        ids = []
        for snap in o.snapshots():
            flows = [e['facts'] for e in snap['events'] if e['kind'].startswith('flow.')]
            self.assertEqual(flows[0]['artifact'], 'Windows.' + snap['key']['request_id'])
            self.assertEqual(len({f['creation_id'] for f in flows}), 1)
            self.assertEqual(len({f['operation_id'] for f in flows}), 1)
            ids.append(flows[0]['creation_id'])
        self.assertEqual(len(set(ids)), 2); self.assertEqual(self.kinds().count('create'), 2)
        self.assertNotIn('exists', self.kinds())

    async def test_no_scope_observer_validation_noop_original_object_and_query(self):
        rows = [{'flow_id': 123, 'artifacts': 'original unchecked', 'specs': object()}]
        self.boundary.rows = rows
        with patch.object(obs.uuid, 'uuid4', side_effect=AssertionError('unexpected UUID')):
            self.assertIs(api.start_collection('MODEL-client', 'Windows.System.Pslist', root_org=1), rows)
        self.assertEqual(self.kinds(), ['create'])
        self.assertIsNone(obs._operation_current.get()); self.assertIsNone(obs._creation_current.get())

    async def test_original_api_validation_precedes_begin(self):
        for kwargs in ({'timeout': True}, {'max_bytes': 0}, {'parameters': {'x': object()}}):
            o = observer(); self.boundary.calls.clear()
            with self.assertRaises((ValueError, TypeError)):
                await self.invoke(o, lambda: self.target.run_with_client(lambda c:
                    api.start_collection(c, 'Windows.System.Pslist', **kwargs)))
            self.assertEqual(self.flow(o), []); self.assertNotIn('create', self.kinds())
        for kwargs in ({'org_id': 1}, {'root_org': 1}):
            o = observer(); self.boundary.calls.clear()
            with self.assertRaises(obs.ObservationError):
                await self.invoke(o, lambda: self.target.run_with_client(lambda c:
                    api.start_collection(c, 'Windows.System.Pslist', **kwargs)))
            self.assertNotIn('create', self.kinds()); self.assertNotIn('exists', self.kinds())


if __name__ == '__main__':
    unittest.main()
