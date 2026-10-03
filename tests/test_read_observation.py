"""Real fixed service/TargetContext, only MODEL backend replaced; no RPC/config."""
import asyncio
import hashlib
import json
import threading
import unittest
from collections import UserDict
from types import SimpleNamespace
from unittest.mock import patch

import velociraptor_observation as obs
import velociraptor_fixed_tools as fixed
from velociraptor_mcp_core import BackendError, InvalidArgumentError, NotFoundError, RowTooLargeError, TargetContext, success_result

ARTIFACT = 'Windows.MODEL.Read'
FLOW = 'MODEL-flow'


def sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def upload(client='MODEL-client', name='one', *, kind='', size=0, stored=0):
    return {'Type': kind, 'Upload': {'Path': 'C:\\MODEL\\' + name + ('.idx' if kind else ''),
        'Size': size, 'StoredSize': stored, 'Components': ['clients', client, 'collections', FLOW,
        'uploads', 'auto', 'C:', 'MODEL', name], 'Accessor': 'auto', 'UploadId': 'MODEL-' + name}}


class ReadBackend:
    """MODEL interface fixture, without reproducing service pagination/dedup logic."""
    def __init__(self, client='MODEL-client'):
        self.client = client
        self.calls = []
        self.metadata = {'state': 'RUNNING', 'artifacts': [ARTIFACT],
                         'artifacts_with_results': [ARTIFACT + '/A', ARTIFACT + '/B']}
        self.sources = {'A': [{'source': 'A', 'n': i} for i in range(2)],
                        'B': [{'source': 'B', 'n': i} for i in range(3)]}
        self.counts = {}
        self.uploads = [upload(client)]
        self.before_metadata = None
        self.before_window = None

    def _call(self, kind, *args, **kwargs):
        self.calls.append({'kind': kind, 'args': list(args), 'kwargs': kwargs, 'thread': threading.get_ident()})

    def list_windows_clients(self):
        self._call('select'); return [{'client_id': self.client, 'system': 'windows'}]

    def client_id_exists(self, client):
        self._call('exists', client); return True

    def get_flow_details(self, client, flow):
        self._call('metadata', client, flow)
        if self.before_metadata: self.before_metadata()
        if isinstance(self.metadata, BaseException): raise self.metadata
        return self.metadata

    def get_flow_result_count(self, client, flow, artifact, *, source):
        self._call('count', client, flow, artifact, source=source)
        total = self.counts[source] if source in self.counts else len(self.sources.get(source, []))
        if isinstance(total, BaseException): raise total
        return total

    def get_flow_results_window(self, client, flow, artifact, *, source, start_row, count):
        self._call('window', client, flow, artifact, source=source, start_row=start_row, count=count)
        if self.before_window: self.before_window()
        rows = self.sources.get(source, [])
        if isinstance(rows, BaseException): raise rows
        return rows[start_row:start_row + count]

    def cancel_flow(self, client, flow):
        self._call('cancel', client, flow); self.metadata = {**self.metadata, 'state': 'CANCELLED'}

    def list_flow_uploads(self, client, flow):
        self._call('uploads', client, flow)
        if isinstance(self.uploads, BaseException): raise self.uploads
        return self.uploads


def context(rid=1):
    return SimpleNamespace(method='tools/call', request_id=rid,
        params={'name': 'MODEL_read', 'arguments': {}},
        request=SimpleNamespace(headers={'mcp-session-id': 'MODEL-session'}))


def observer(events=100, size=10000):
    return obs.RequestObserver('MODEL-instance', max_requests=30,
        max_events_per_request=events, max_event_bytes=size)


def service(backend):
    return fixed.FixedToolService([], TargetContext(backend), backend, download_root=None)


class ReadObservationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.b = ReadBackend(); self.s = service(self.b)

    async def invoke(self, o, function=None, rid=1):
        async def call(ctx):
            return (function or (lambda: self.s.get_flow_results(FLOW, None, None, 3)))()
        return await o.middleware(context(rid), call)

    def read(self, o):
        events = [e for e in o.snapshots()[-1]['events'] if e['kind'] in obs._READ_FIELDS]
        for e in events:
            self.assertEqual(set(e['facts']), obs._READ_FIELDS[e['kind']] | obs._READ_BASE)
            self.assertEqual(e['facts']['client_id'], 'MODEL-client')
            self.assertEqual(e['facts']['flow_id'], FLOW)
        return events

    def kinds(self): return [c['kind'] for c in self.b.calls]

    async def test_metadata_actual_rules_and_status_no_completed_inference(self):
        o = observer()
        self.b.metadata['artifacts'] = []
        self.b.metadata['request'] = {'artifacts': [ARTIFACT]}
        result = await self.invoke(o, lambda: self.s.get_flow_status(FLOW))
        event = self.read(o)[0]
        self.assertEqual(event['facts']['state'], 'RUNNING')
        self.assertEqual(event['facts']['artifacts'], [ARTIFACT])
        self.assertEqual(event['facts']['sources'], [ARTIFACT + '/A', ARTIFACT + '/B'])
        self.assertEqual(self.kinds(), ['select', 'metadata']); self.assertEqual(result.state, 'RUNNING')
        self.assertNotIn('complete', event['facts']); self.assertNotIn('transaction', event['facts'])

    async def test_multisource_original_count_window_order_prefetch_and_final_page(self):
        o = observer(); self.b.metadata['artifacts_with_results'].append(ARTIFACT + '/A')
        result = await self.invoke(o)
        events = self.read(o); facts = [e['facts'] for e in events]
        self.assertEqual([e['kind'] for e in events], ['flow.read.metadata', 'flow.results.plan',
            'flow.results.count', 'flow.results.count', 'flow.results.window', 'flow.results.window', 'flow.results.page'])
        self.assertEqual(facts[1]['selected_sources'], ['A', 'B'])
        self.assertIsNone(facts[1]['requested_source']); self.assertEqual((facts[1]['offset'], facts[1]['page_size']), (0, 3))
        self.assertEqual([f['total'] for f in facts[2:4]], [2, 3])
        self.assertEqual([f['source_index'] for f in facts[2:6]], [0, 1, 0, 1])
        self.assertEqual([(f['start_row'], f['requested_count'], f['returned']) for f in facts[4:6]], [(0, 4, 2), (0, 2, 2)])
        self.assertEqual(facts[4]['rows_sha256'], sha(self.b.sources['A']))
        self.assertEqual(facts[5]['rows_sha256'], sha(self.b.sources['B'][:2]))
        self.assertEqual(result.data, self.b.sources['A'] + self.b.sources['B'][:1])
        self.assertEqual(facts[-1]['data_sha256'], sha(result.data))
        self.assertEqual(facts[-1]['pagination'], result.pagination.model_dump(mode='json', exclude_none=False))
        self.assertEqual(self.kinds(), ['select', 'metadata', 'count', 'count', 'window', 'window'])
        self.assertEqual([c['kwargs'] for c in self.b.calls if c['kind'] == 'window'],
            [{'source': 'A', 'start_row': 0, 'count': 4}, {'source': 'B', 'start_row': 0, 'count': 2}])
        self.assertEqual(len({f['operation_id'] for f in facts}), 1)
        original = o.snapshots(); self.b.sources['A'][0]['n'] = 100
        self.assertEqual(o.snapshots(), original)
        self.assertNotIn("'source': 'A', 'n'", str(o.snapshots()))

    async def test_cross_offset_explicit_full_suffix_and_null_source(self):
        for source, cursor, expected in ((None, 'v1:3', ['B']), ('B', 'v1:1', ['B']),
                                       (ARTIFACT + '/B', None, ['B'])):
            self.b.calls.clear(); o = observer()
            await self.invoke(o, lambda: self.s.get_flow_results(FLOW, source, cursor, 1))
            fs = self.read(o)
            self.assertEqual(fs[1]['facts']['requested_source'], source)
            self.assertEqual([c['kwargs']['source'] for c in self.b.calls if c['kind'] == 'window'], expected)
            self.assertEqual(next(c['kwargs']['start_row'] for c in self.b.calls if c['kind'] == 'window'), 1 if cursor else 0)
        self.b.metadata['artifacts_with_results'] = [ARTIFACT]; self.b.sources[None] = [{'n': 1}]
        o = observer(); result = await self.invoke(o)
        self.assertEqual(self.read(o)[1]['facts']['selected_sources'], [None])
        self.assertIsNone(self.read(o)[2]['facts']['source']); self.assertIsNone(self.read(o)[-1]['facts']['pagination']['next_cursor'])
        self.assertEqual(set(self.read(o)[-1]['facts']['pagination']), {'cursor', 'next_cursor', 'page_size', 'returned', 'truncated'})

    async def test_empty_sources_and_zero_count_emit_actual_empty_page(self):
        for known in ([], [ARTIFACT + '/Empty']):
            self.b.metadata['artifacts_with_results'] = known; self.b.calls.clear(); o = observer()
            result = await self.invoke(o)
            self.assertEqual(result.data, []); self.assertIsNone(result.pagination.next_cursor)
            es = self.read(o); self.assertEqual(es[-1]['facts']['data_sha256'], sha([]))
            self.assertEqual(es[1]['facts']['selected_sources'], [] if not known else ['Empty'])
            self.assertNotIn('window', self.kinds())
            self.assertEqual(self.kinds().count('count'), int(bool(known)))

    async def test_byte_shrunk_page_and_single_row_limit_preserve_window(self):
        self.b.metadata['artifacts_with_results'] = [ARTIFACT + '/A']
        self.b.sources['A'] = [{'large': 'x' * 130000}, {'large': 'y' * 130000}]
        o = observer(); result = await self.invoke(o, lambda: self.s.get_flow_results(FLOW, None, None, 2))
        self.assertEqual(len(result.data), 1); self.assertTrue(result.pagination.truncated)
        self.assertEqual(self.read(o)[-2]['facts']['returned'], 2)
        self.assertEqual(self.read(o)[-1]['facts']['returned'], 1)
        self.assertEqual(self.kinds().count('window'), 1)
        self.b.sources['A'] = [{'large': 'x' * 260000}]; self.b.calls.clear(); o = observer()
        with self.assertRaises(RowTooLargeError): await self.invoke(o)
        self.assertEqual(self.read(o)[-1]['kind'], 'flow.results.window')
        self.assertNotIn('flow.results.page', [e['kind'] for e in self.read(o)])
        self.assertEqual(self.kinds().count('window'), 1)

    async def test_invalid_source_cursor_and_scope_mismatch_no_plan_before_validation(self):
        for source, cursor, known in (('Missing', None, [ARTIFACT + '/A']),
            (None, None, ['Wrong.Artifact/A']), (None, 'v1:100', [ARTIFACT + '/A'])):
            self.b.metadata['artifacts_with_results'] = known; self.b.calls.clear(); o = observer()
            with self.assertRaises((BackendError, InvalidArgumentError)):
                await self.invoke(o, lambda: self.s.get_flow_results(FLOW, source, cursor, 2))
            self.assertNotIn('window', self.kinds()); self.assertEqual(self.kinds().count('exists'), 1)
            if cursor: self.assertEqual(self.read(o)[-1]['kind'], 'flow.results.count')
            else: self.assertEqual([e['kind'] for e in self.read(o)], ['flow.read.metadata'])
        o = observer(); self.b.calls.clear()
        with self.assertRaises(InvalidArgumentError):
            await self.invoke(o, lambda: self.s.get_flow_results(FLOW, None, 'v1:00', 2))
        self.assertEqual(self.b.calls, []); self.assertEqual(o.snapshots()[0]['events'], [])

    async def test_count_error_immediate_prefix_and_invalid_total_sticky(self):
        for value in (RuntimeError('MODEL count failure'), -1, True, 1.2, '3'):
            self.b.counts['B'] = value; self.b.calls.clear(); o = observer()
            with self.assertRaises((BackendError, obs.ObservationError)): await self.invoke(o)
            self.assertEqual([e['kind'] for e in self.read(o)], ['flow.read.metadata', 'flow.results.plan', 'flow.results.count'])
            self.assertEqual(self.kinds().count('count'), 2); self.assertNotIn('window', self.kinds())
            self.assertEqual(self.kinds().count('exists'), int(isinstance(value, RuntimeError)))

    async def test_window_query_failure_cancel_and_invalid_json_preserve_prefix(self):
        for value in (RuntimeError('MODEL window secret'), asyncio.CancelledError('MODEL cancel'), [{'n': object()}], [{'n': float('nan')}], [{'n': (1,)}]):
            self.b.sources['B'] = value; self.b.counts['B'] = 3; self.b.calls.clear(); o = observer()
            with self.assertRaises((BackendError, asyncio.CancelledError, obs.ObservationError)) as caught: await self.invoke(o)
            if isinstance(value, asyncio.CancelledError): self.assertIs(caught.exception, value)
            self.assertEqual([e['kind'] for e in self.read(o)].count('flow.results.window'), 1)
            self.assertNotIn('flow.results.page', [e['kind'] for e in self.read(o)])
            self.assertEqual(self.kinds().count('window'), 2)
            self.assertEqual(self.kinds().count('exists'), int(isinstance(value, RuntimeError)))
            self.assertNotIn('window secret', str(o.snapshots()))
            self.assertIsNone(obs._operation_current.get()); self.assertFalse(obs.observation_active())

    async def test_metadata_null_absent_lists_and_invalid_observation_state(self):
        self.b.metadata = {'request': {'artifacts': [ARTIFACT]}}
        o = observer(); result = await self.invoke(o)
        self.assertEqual(result.data, []); f = self.read(o)[0]['facts']
        self.assertIsNone(f['state']); self.assertEqual(f['artifacts'], [ARTIFACT]); self.assertEqual(f['sources'], [])
        for row in ({'state': ''}, {'state': 1}, {'state': 'RUNNING', 'artifacts': [True]}, {'state': 'RUNNING', 'artifacts_with_results': 'bad'}):
            self.b.metadata = row; self.b.calls.clear(); o = observer()
            with self.assertRaises((BackendError, obs.ObservationError)): await self.invoke(o)
            self.assertEqual(self.read(o), []); self.assertNotIn('exists', self.kinds())
        self.b.metadata = None; o = observer(); self.b.calls.clear()
        with self.assertRaises(NotFoundError): await self.invoke(o)
        self.assertEqual(self.read(o), []); self.assertEqual(self.kinds().count('exists'), 1)

    async def test_files_raw_mapping_dedup_idx_inventory_and_result_hashes(self):
        rows = [upload(size=10, stored=4), upload(kind='idx', size=10, stored=4),
                upload(size=10, stored=4), upload(name='changed', size=10, stored=9), upload(name='empty')]
        self.b.uploads = [UserDict({**r, 'Upload': UserDict(r['Upload'])}) for r in rows]
        o = observer(); result = await self.invoke(o, lambda: self.s.list_flow_files(FLOW))
        events = self.read(o)
        self.assertEqual([e['kind'] for e in events], ['flow.read.metadata', 'flow.files.raw', 'flow.files.inventory', 'flow.files.result'])
        self.assertEqual(events[1]['facts']['rows_sha256'], sha(rows)); self.assertEqual(events[1]['facts']['row_count'], 5)
        inv = fixed._deduplicated_uploads(self.b.uploads, client_id=self.b.client, flow_id=FLOW)
        projected = [{'file_id': r.file_id, 'identity': r.identity, 'components': list(r.components),
                      'index_selector': list(r.index_selector) if r.index_selector else None} for r in inv.records]
        self.assertEqual(events[2]['facts']['identities_sha256'], sha(projected))
        self.assertEqual((events[2]['facts']['record_count'], events[2]['facts']['sparse_count'], events[2]['facts']['size_mismatch_count']), (3, 1, 1))
        self.assertEqual(events[-1]['facts']['data_sha256'], sha(result.model_dump(mode='json')['data'])); self.assertFalse(events[-1]['facts']['truncated'])
        self.assertEqual(self.kinds(), ['select', 'metadata', 'uploads']); self.assertEqual(result.data[-1].file_size, 0)
        self.assertNotIn('C:\\MODEL', str(o.snapshots())); self.assertNotIn('components', str(o.snapshots()))
        self.assertNotIn('pagination', events[-1]['facts'])

    async def test_files_empty_row_limit_byte_limit_and_single_row_failure(self):
        for rows in ([], [upload(name=str(i)) for i in range(251)], [upload(name='x' * 130000), upload(name='y' * 130000)]):
            self.b.uploads = rows; self.b.calls.clear(); o = observer()
            result = await self.invoke(o, lambda: self.s.list_flow_files(FLOW))
            facts = self.read(o)
            self.assertEqual(facts[1]['facts']['row_count'], len(rows))
            self.assertEqual(facts[2]['facts']['record_count'], len(rows))
            self.assertEqual(facts[-1]['facts']['returned'], len(result.data))
            self.assertEqual(facts[-1]['facts']['truncated'], result.truncated)
            self.assertEqual(len(result.data), 0 if not rows else 250 if len(rows) > 250 else 1)
            self.assertEqual(self.kinds().count('uploads'), 1)
        self.b.uploads = [upload(name='x' * 260000)]; o = observer()
        with self.assertRaises(RowTooLargeError): await self.invoke(o, lambda: self.s.list_flow_files(FLOW))
        self.assertEqual(self.read(o)[-1]['kind'], 'flow.files.inventory')

    async def test_upload_conflicts_validation_and_query_failures_prefix(self):
        rows = [upload(), {**upload(), 'Upload': {**upload()['Upload'], 'Size': 1}}]
        selector = upload(); selector['Upload']['UploadId'] = 'other'
        cases = [(rows, ['flow.read.metadata', 'flow.files.raw']),
                 ([upload(), selector], ['flow.read.metadata', 'flow.files.raw']),
                 ([upload(kind='idx')], ['flow.read.metadata', 'flow.files.raw']),
                 ([upload(client='MODEL-other')], ['flow.read.metadata', 'flow.files.raw']),
                 ([1], ['flow.read.metadata']),
                 (RuntimeError('MODEL uploads failure'), ['flow.read.metadata']),
                 ([{**upload(), 'secret': object()}], ['flow.read.metadata'])]
        for value, kinds in cases:
            self.b.uploads = value; self.b.calls.clear(); o = observer()
            with self.assertRaises((BackendError, obs.ObservationError)):
                await self.invoke(o, lambda: self.s.list_flow_files(FLOW))
            self.assertEqual([e['kind'] for e in self.read(o)], kinds)
            self.assertEqual(self.kinds().count('uploads'), 1)
            self.assertEqual(self.kinds().count('exists'), int(not (type(value) is list and value and type(value[0]) is dict and 'secret' in value[0])))

    async def test_each_emitter_pre_post_fault_zero_probe_and_no_repeated_query(self):
        real = obs.ObservationScope.emit
        for kind in obs._READ_FIELDS:
            for after in (False, True):
                self.b.calls.clear(); o = observer()
                def fault(scope, event, facts):
                    if event == kind:
                        if after: real(scope, event, facts)
                        raise obs.ObservationError('MODEL injected fault')
                    return real(scope, event, facts)
                with patch.object(obs.ObservationScope, 'emit', fault):
                    with self.assertRaises(obs.ObservationError):
                        await self.invoke(o, (lambda: self.s.list_flow_files(FLOW)) if kind.startswith('flow.files.') else None)
                self.assertEqual(self.kinds().count('metadata'), 1); self.assertNotIn('exists', self.kinds())
                expected_queries = {
                    'flow.read.metadata': ['metadata'], 'flow.results.plan': ['metadata'],
                    'flow.results.count': ['metadata', 'count'],
                    'flow.results.window': ['metadata', 'count', 'count', 'window'],
                    'flow.results.page': ['metadata', 'count', 'count', 'window', 'window'],
                    'flow.files.raw': ['metadata', 'uploads'], 'flow.files.inventory': ['metadata', 'uploads'],
                    'flow.files.result': ['metadata', 'uploads'],
                }
                self.assertEqual([k for k in self.kinds() if k != 'select'], expected_queries[kind])
                baseline = ['flow.read.metadata', 'flow.files.raw', 'flow.files.inventory', 'flow.files.result'] if kind.startswith('flow.files.') else ['flow.read.metadata', 'flow.results.plan', 'flow.results.count', 'flow.results.count', 'flow.results.window', 'flow.results.window', 'flow.results.page']
                kinds = [e['kind'] for e in self.read(o)]
                self.assertEqual(kinds, baseline[:baseline.index(kind) + int(after)])
                self.assertEqual(kinds.count(kind), int(after)); self.assertEqual(o.snapshots()[0]['outcome'], 'raised')
                self.assertIsNone(obs._operation_current.get())

    async def test_capacity_prefix_and_wrapped_observation_failure_still_sticky(self):
        for limit, expected in ((2, ['select', 'metadata']), (3, ['select', 'metadata']),
                                (4, ['select', 'metadata', 'count']), (6, ['select', 'metadata', 'count', 'count', 'window'])):
            self.b.calls.clear(); self.s = service(self.b); o = observer(limit)
            with self.assertRaises(obs.ObservationError): await self.invoke(o)
            self.assertEqual(self.kinds(), expected); self.assertEqual(len(o.snapshots()[0]['events']), limit)
        o = observer(); self.b.calls.clear(); self.b.metadata['state'] = 1
        with self.assertRaises(BackendError) as caught:
            await self.invoke(o, lambda: self.s._target.run_with_client(lambda c: fixed._backend_call('MODEL-wrap', lambda: self.s._flow(c, FLOW))))
        self.assertIsInstance(caught.exception.__cause__, obs.ObservationError)
        self.assertEqual(self.kinds(), ['metadata']); self.assertEqual(o.snapshots()[0]['outcome'], 'raised')

    async def test_missing_cross_client_and_cross_parent_guard_before_query(self):
        o = observer()
        with self.assertRaises(obs.ObservationError): await self.invoke(o, lambda: self.s._flow(self.b.client, FLOW))
        self.assertEqual(self.b.calls, [])
        o = observer(); self.b.calls.clear()
        with self.assertRaises(obs.ObservationError):
            await self.invoke(o, lambda: self.s._target.run_with_client(lambda c: self.s._file_records('MODEL-other', FLOW)))
        self.assertEqual(self.kinds(), ['select'])
        inner = observer(); outer = observer(); self.b.calls.clear(); self.s = service(self.b)
        async def child(ctx): self.s._flow(self.b.client, FLOW)
        async def parent(ctx):
            def operation(client):
                with self.assertRaises(obs.ObservationError): asyncio.run(inner.middleware(context('inner'), child))
            await asyncio.to_thread(self.s._target.run_with_client, operation)
        await outer.middleware(context('outer'), parent)
        self.assertEqual(self.b.calls, [{'kind': 'select', 'args': [], 'kwargs': {}, 'thread': self.b.calls[0]['thread']}])
        self.assertEqual(inner.snapshots()[0]['events'], [])

    async def test_concurrent_real_local_clients_and_operations_separate(self):
        o = observer(); barrier = threading.Barrier(2, timeout=3); backends = {}
        async def call(ctx):
            backend = ReadBackend('MODEL-' + ctx.request_id); backend.before_metadata = barrier.wait
            backends[ctx.request_id] = backend
            return await asyncio.to_thread(service(backend).list_flow_files, FLOW)
        await asyncio.gather(o.middleware(context('a'), call), o.middleware(context('b'), call))
        ids = set()
        for snap in o.snapshots():
            client = 'MODEL-' + snap['key']['request_id']
            facts = [e['facts'] for e in snap['events'] if e['kind'] in obs._READ_FIELDS]
            self.assertTrue(all(f['client_id'] == client for f in facts)); ids.add(facts[0]['operation_id'])
            self.assertTrue(all(c['args'][0] == client for c in backends[snap['key']['request_id']].calls if c['kind'] in ('metadata', 'uploads')))
        self.assertEqual(len(ids), 2)

    async def test_other_flow_paths_and_independent_read_operations(self):
        o = observer()
        result = await self.invoke(o, lambda: self.s.cancel_flow(FLOW))
        self.assertEqual(result.state_after, 'CANCELLED')
        self.assertEqual([e['facts']['state'] for e in self.read(o)], ['RUNNING', 'CANCELLED'])
        self.assertEqual(self.kinds(), ['select', 'metadata', 'cancel', 'metadata'])
        await self.invoke(o, lambda: self.s._target.run_with_client(lambda c: self.s._file_records(c, FLOW)), rid=2)
        self.assertEqual([e['kind'] for e in self.read(o)], ['flow.read.metadata', 'flow.files.raw', 'flow.files.inventory'])
        first, second = o.snapshots()
        self.assertNotEqual(first['events'][1]['facts']['operation_id'], second['events'][1]['facts']['operation_id'])

    async def test_same_counts_do_not_imply_stable_rows_or_snapshot(self):
        o = observer(); await self.invoke(o)
        self.b.sources['A'][0]['n'] = 999
        await self.invoke(o, rid=2)
        snapshots = o.snapshots()
        counts = [[e['facts']['total'] for e in s['events'] if e['kind'] == 'flow.results.count'] for s in snapshots]
        windows = [[e['facts']['rows_sha256'] for e in s['events'] if e['kind'] == 'flow.results.window'] for s in snapshots]
        self.assertEqual(counts[0], counts[1]); self.assertNotEqual(windows[0][0], windows[1][0])
        self.assertNotEqual(snapshots[0]['events'][1]['facts']['operation_id'], snapshots[1]['events'][1]['facts']['operation_id'])
        for snap in snapshots:
            self.assertTrue(all(set(e['facts']) == obs._READ_BASE | obs._READ_FIELDS[e['kind']] for e in snap['events'] if e['kind'] in obs._READ_FIELDS))

    async def test_observed_results_files_equal_original_no_scope_outputs_and_calls(self):
        for method in ('results', 'files', 'status'):
            def run(s):
                if method == 'results': return s.get_flow_results(FLOW, None, None, 3)
                if method == 'files': return s.list_flow_files(FLOW)
                return s.get_flow_status(FLOW)
            original_backend = ReadBackend(); original = run(service(original_backend))
            self.b = ReadBackend(); self.s = service(self.b)
            observed = await self.invoke(observer(), lambda: run(self.s))
            self.assertEqual(success_result(original).model_dump(mode='json'), success_result(observed).model_dump(mode='json'))
            self.assertEqual(original_backend.calls, self.b.calls)

    async def test_exact_whitelist_invalid_json_and_byte_capacity_sticky(self):
        for kind, facts in (('flow.results.count', {'artifact': ARTIFACT, 'source_index': 0, 'source': None, 'total': True}),
                            ('flow.results.count', {'artifact': ARTIFACT, 'source_index': 0, 'source': None, 'total': 1, 'extra': 'excluded'})):
            o = observer(); self.b.calls.clear()
            with self.assertRaises(obs.ObservationError):
                await self.invoke(o, lambda: self.s._target.run_with_client(lambda c: obs.emit_flow_read_fact(kind, c, FLOW, lambda: facts)))
            self.assertEqual(self.read(o), []); self.assertNotIn('exists', self.kinds())
        self.b.metadata['artifacts_with_results'] = [ARTIFACT + '/' + 'x' * 2000]
        self.b.calls.clear(); o = observer(size=500)
        with self.assertRaises(obs.ObservationError): await self.invoke(o)
        self.assertEqual(self.kinds(), ['metadata']); self.assertEqual(self.read(o), [])
        self.b.metadata = {'state': 'RUNNING', 'artifacts': [ARTIFACT], 'artifacts_with_results': []}
        cyclic = []; cyclic.append(cyclic)
        for value in ([{**upload(), 'bad': cyclic}], [UserDict({**upload(), 'bad': (1,)})]):
            self.b.uploads = value; self.b.calls.clear(); o = observer()
            with self.assertRaises(obs.ObservationError): await self.invoke(o, lambda: self.s.list_flow_files(FLOW))
            self.assertEqual(self.kinds(), ['metadata', 'uploads'])
            self.assertEqual([e['kind'] for e in self.read(o)], ['flow.read.metadata'])

    async def test_no_scope_no_observer_hash_uuid_validation_or_new_queries(self):
        self.b.metadata['state'] = ''
        self.b.sources['A'] = [{'n': (1,)}]
        self.b.uploads = [{**upload(), 'ignored': object()}]
        with patch.object(fixed, 'flow_rows_sha256', side_effect=AssertionError('new hash without scope')), patch.object(obs.uuid, 'uuid4', side_effect=AssertionError('new UUID without scope')):
            result = self.s.get_flow_results(FLOW, None, None, 3)
            files = self.s.list_flow_files(FLOW)
        self.assertEqual(result.data[0], {'n': [1]}); self.assertEqual(len(files.data), 1)
        self.assertEqual(self.kinds(), ['select', 'metadata', 'count', 'count', 'window', 'window', 'metadata', 'uploads'])
        self.assertFalse(obs.observation_active()); self.assertIsNone(obs._operation_current.get())


if __name__ == '__main__': unittest.main()
