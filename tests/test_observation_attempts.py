"""Ledger control flow with MODEL native I/O; no Windows qualification."""
import copy
import hashlib
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import PureWindowsPath
from types import SimpleNamespace
from unittest.mock import patch

import velociraptor_observation_attempts as a
import velociraptor_observation_config as cfg
import velociraptor_observation_namespace as n
import velociraptor_observation_windows as w
from tests.test_observation_namespace import DirectoryFS
from tests.test_observation_windows import ROOT, SID, sd, session
from tests.test_observation_archive import SHA

MODEL_TRACES = []
INSTANCE = 'a'*32

def key(number=1, session_id='MODEL-session'):
    return dict(instance_id=INSTANCE, session_id=session_id,
        request_id_type='integer' if type(number) is int else 'string', request_id=number)

def budgets():
    return dict(max_attempts=8,max_active=2,max_directories=10,max_catalog_records=26,
        max_catalog_record_bytes=4096,max_total_archive_bytes=446464,max_key_bytes=1024,
        max_seen_key_bytes=8192,max_json_depth=32,request_codec=dict(max_records=10,
            max_record_bytes=4096,max_total_bytes=40960,max_json_depth=32))

class ArchiveFS(DirectoryFS):
    def _names(self, handle, limit):
        self.invoke('enumerate', handle)
        path=PureWindowsPath(self.handles[handle]['node']['name'])
        count=0
        for row in list(self.nodes.values()):
            child=PureWindowsPath(row['name'])
            if child.parent==path and child!=path:
                count+=1
                if count>limit: raise RuntimeError('MODEL enumeration bound')
                if row['directory'] or row.get('reparse'): raise RuntimeError('MODEL unsafe member')
                yield child.name

class Group:
    def __init__(self):self.allowed={cfg.CONFIG:dict(path=cfg.CONFIG,size=1,sha256=SHA)};self.closed=0;self.checks=0
    def recheck(self):self.checks+=1
    def close(self):self.closed+=1

def configuration(fs):
    row=fs.nodes[str(ROOT)]
    identity=dict(platform='windows',volume_serial=f"{row['id'][0]:016x}",file_id=row['id'][1].hex(),
        owner_sid=SID,principal_sid=SID,acl_sha256=hashlib.sha256(row['sd']).hexdigest())
    limits=budgets();codec,catalog=cfg._budgets(limits)
    return cfg._Configuration(Group(),dict(guest_namespace_root=str(ROOT),root_identity=identity,
        implementation_freeze_ref=dict(path='MODEL/freeze.json',size=1,sha256=SHA),budgets=limits),row['sd'],codec,catalog)

class LedgerModels(unittest.TestCase):
    def ledger(self):
        fs=ArchiveFS();config=configuration(fs)
        patches=[patch.object(a,'load_approved',return_value=config),
            patch.object(n,'_session',side_effect=lambda:session(fs)),patch.object(n,'_directory_api',return_value=fs),
            patch.object(w,'_session',side_effect=lambda:session(fs)),patch.object(w,'_writer_api',return_value=fs),
            patch.object(a,'WindowsSession',side_effect=lambda:session(fs))]
        for p in patches:p.start();self.addCleanup(p.stop)
        ledger=a.ArchiveAttemptLedger.open_approved(INSTANCE)
        def cleanup():
            if not ledger._closed:
                for attempt in ledger._attempts.values():
                    if attempt.journal:attempt.journal.close()
                    ledger._retire(attempt)
                try:ledger.close()
                except BaseException:pass
        self.addCleanup(cleanup)
        return ledger,fs,config
    def catalog(self,l,fs):
        root=str(l._catalog_dir.path)+'\\'
        return [v['data'] for p,v in sorted(fs.nodes.items()) if p.startswith(root) and p.endswith('.json')]
    def terminal(self,l,lease,events=0,outcome='returned',failed=False):
        j=l.accept(lease);parent=j.parent();j.claim(object(),parent['key'],parent['tool'],parent['arguments_sha256'])
        for i in range(1,events+1):j.append(dict(sequence=i,kind='target.resolve',facts=dict(operation_id=None,mode='selected',client_id='MODEL-client')))
        j.seal(outcome,failed=failed);j.close();l.finish(lease,outcome);return j
    def test_full_budget_eight_real_request_chains_and_original_catalog(self):
        l,fs,c=self.ledger()
        for i in range(8):self.terminal(l,l.begin(key(i),'tool',SHA),events=8)
        l.close();raw=self.catalog(l,fs);s=c.catalog_codec.verify(iter(raw))
        self.assertEqual((len(raw),s['accepted_count'],s['status']),(26,8,'CLOSED_KNOWN'))
        self.assertEqual(len([v for v in fs.nodes.values() if not v['directory']]),106)
        self.assertEqual(len(fs.created),10);self.assertFalse(fs.handles);self.assertEqual(c.group.closed,1)
        self.assertEqual(len(fs.closed),len(set(fs.closed)))
    def test_typed_keys_sessions_duplicates_and_rejected_tombstones(self):
        l,fs,c=self.ledger();one=l.begin(key(),'tool',SHA);two=l.begin(key('1'),'tool',SHA)
        reject=l.begin(key(2),'tool',SHA);self.assertEqual((reject.decision,reject.reason),('REJECTED','ACTIVE_LIMIT'))
        self.terminal(l,one);self.terminal(l,two)
        self.assertEqual(l.begin(key(2),'tool',SHA).reason,'DUPLICATE')
        self.assertEqual(l.begin(key(),'tool',SHA).reason,'DUPLICATE')
        self.terminal(l,l.begin(key(1,'other'),'tool',SHA));l.close()
        s=c.catalog_codec.verify(self.catalog(l,fs));self.assertEqual((s['accepted_count'],s['rejected_count']),(3,3))
        self.assertEqual(len(fs.created),5)
    def test_pure_input_foreign_immutable_reentry_and_active_close(self):
        l,fs,c=self.ledger();before=list(fs.events)
        with self.assertRaises(Exception):l.begin(key(),'x'*5000,SHA)
        self.assertEqual(fs.events,before);self.assertEqual(l._attempt_count,0)
        lease=l.begin(key(),'tool',SHA)
        with self.assertRaises(AttributeError):lease._decision='NEW'
        with self.assertRaises(TypeError):a.AttemptLease()
        for action in (lambda:l.close(),lambda:l.accept(object()),lambda:l.finish(lease,'returned')):
            with self.assertRaises(a.LedgerError):action()
        j=l.accept(lease)
        with self.assertRaises(a.LedgerError):l.accept(lease)
        with self.assertRaises(a.LedgerError):l.finish(lease,'returned')
        j.claim(object(),key(),'tool',SHA);j.seal('returned');j.close();l.finish(lease,'returned');l.close()
    def test_actual_zero_event_outcomes_failed_and_order(self):
        for outcome,failed in [('returned',False),('returned',True),('raised',False),('cancelled',True)]:
            l,fs,c=self.ledger();lease=l.begin(key(),'tool',SHA)
            self.terminal(l,lease,outcome=outcome,failed=failed);l.close()
            rows=[c.catalog_codec.parse(x) for x in self.catalog(l,fs)]
            self.assertEqual([x['record_type'] for x in rows],['INSTANCE_BEGIN','ATTEMPT_BEGIN','ACCEPT_ACK','ATTEMPT_END','INSTANCE_END'])
            self.assertEqual(rows[3]['payload']['outcome'],outcome)
            self.assertEqual(rows[3]['payload']['disposition'],'FAILED' if failed else 'COMPLETE')
            self.assertEqual(rows[3]['payload']['event_count'],0)
    def test_unknown_ack_preserves_accept_and_stops_before_business(self):
        l,fs,c=self.ledger();lease=l.begin(key(),'tool',SHA);native=l._catalog.publish
        def fail(raw):
            result=native(raw)
            if c.catalog_codec.parse(raw)['record_type']=='ACCEPT_ACK':raise RuntimeError('MODEL post-rename ACK fault')
            return result
        with patch.object(l._catalog,'publish',side_effect=fail),self.assertRaises(RuntimeError):l.accept(lease)
        inventory={p:v['data'] for p,v in fs.nodes.items() if not v['directory']}
        self.assertTrue(any('r000000000001-' in p for p in inventory));before=len(fs.events)
        with self.assertRaises(a.LedgerError):l.begin(key(2),'tool',SHA)
        self.assertEqual(before,len(fs.events))
        with self.assertRaises(a.LedgerError):l.close()
        self.assertEqual(inventory,{p:v['data'] for p,v in fs.nodes.items() if not v['directory']});self.assertFalse(fs.handles)
    def test_readback_extra_pending_drift_tamper_fail_without_end(self):
        for fault in ('extra','pending','bytes','second_names'):
            l,fs,c=self.ledger();lease=l.begin(key(),'tool',SHA);j=l.accept(lease);j.claim(object(),key(),'tool',SHA);j.seal('returned');j.close()
            attempt=l._attempts[lease];root=attempt.directory.path
            if fault in ('extra','pending'):fs.node(root/('extra.json' if fault=='extra' else 'x.pending'))
            elif fault=='bytes':fs.nodes[str(root/'00000000.json')]['data']=b'bad'
            else:
                calls=0
                def hook(method,handle):
                    nonlocal calls
                    if method=='enumerate':
                        calls+=1
                        if calls==2:fs.node(root/'extra.json')
                fs.hook=hook
            with self.assertRaises(Exception):l.finish(lease,'returned')
            fs.hook=lambda *args:None
            self.assertEqual(len(self.catalog(l,fs)),3)
            with self.assertRaises(a.LedgerError):l.close()
            self.assertFalse(fs.handles)
    def test_concurrent_publish_and_state_callback_no_abba(self):
        l,fs,c=self.ledger();leases=[l.begin(key(i),'tool',SHA) for i in (1,2)]
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures=[pool.submit(self.terminal,l,x,8) for x in leases]
            for f in futures:f.result(timeout=20)
        l.close();self.assertEqual(c.catalog_codec.verify(self.catalog(l,fs))['accepted_count'],2)
    def test_primary_same_object_and_cancel_tail_worker_exit(self):
        import asyncio
        l,fs,c=self.ledger();lease=l.begin(key(),'tool',SHA);j=l.accept(lease);j.claim(object(),key(),'tool',SHA)
        primary=asyncio.CancelledError('MODEL primary')
        async def run():
            worker=asyncio.create_task(asyncio.sleep(.01))
            with self.assertRaises(a.LedgerError):l.finish(lease,'cancelled')
            await worker
            j.append(dict(sequence=1,kind='target.resolve',facts=dict(operation_id=None,mode='selected',client_id='MODEL-tail')))
            j.seal('cancelled');j.close();l.finish(lease,'cancelled')
        asyncio.run(run())
        with self.assertRaises(asyncio.CancelledError) as caught:
            with l:raise primary
        self.assertIs(caught.exception,primary);self.assertEqual(c.catalog_codec.verify(self.catalog(l,fs))['status'],'CLOSED_KNOWN')
    def test_each_transaction_fault_preserves_inventory_and_never_retries(self):
        for stage in ('INSTANCE_BEGIN','ATTEMPT_BEGIN','ACCEPT','ACCEPT_ACK','EVENT','SEAL','ATTEMPT_END','INSTANCE_END'):
            for native_point in ('create','write','flush','after_rename','read','close'):
                fs=ArchiveFS();config=configuration(fs);l=None;lease=None;j=None;armed=False;fired=False
                primary=RuntimeError('MODEL transaction fault')
                def hook(method,handle):
                    nonlocal fired
                    if armed and not fired and method==native_point:
                        if method=='close' and (handle is None or fs.handles[handle]['node']['directory']):return
                        if method=='read' and (handle is None or fs.handles[handle]['node']['directory']):return
                        fired=True
                        if method=='close':del fs.handles[handle]
                        raise primary
                fs.hook=hook
                with self.subTest(stage=stage,point=native_point),patch.object(a,'load_approved',return_value=config),patch.object(n,'_session',side_effect=lambda:session(fs)),patch.object(n,'_directory_api',return_value=fs),patch.object(w,'_session',side_effect=lambda:session(fs)),patch.object(w,'_writer_api',return_value=fs),patch.object(a,'WindowsSession',side_effect=lambda:session(fs)):
                    armed=stage=='INSTANCE_BEGIN'
                    try:
                        l=a.ArchiveAttemptLedger.open_approved(INSTANCE)
                        armed=stage=='ATTEMPT_BEGIN';lease=l.begin(key(),'tool',SHA)
                        armed=stage in ('ACCEPT','ACCEPT_ACK')
                        # ACK only follows accept publication; arm on catalog call.
                        if stage=='ACCEPT_ACK':
                            armed=False;original=l._catalog.publish
                            def ack(raw):
                                nonlocal armed
                                armed=True;return original(raw)
                            l._catalog.publish=ack
                        j=l.accept(lease);j.claim(object(),key(),'tool',SHA)
                        armed=stage=='EVENT'
                        j.append(dict(sequence=1,kind='target.resolve',facts=dict(operation_id=None,mode='selected',client_id='MODEL-client')))
                        armed=stage=='SEAL';j.seal('returned');armed=False;j.close()
                        armed=stage=='ATTEMPT_END';l.finish(lease,'returned')
                        armed=stage=='INSTANCE_END';l.close()
                        self.fail('injected fault did not reach target')
                    except BaseException as error:
                        if isinstance(error,AssertionError):raise
                        self.assertTrue(fired)
                        chain=[];seen=set();current=error
                        while current is not None and id(current) not in seen:
                            chain.append(current);seen.add(id(current));current=current.__cause__
                        self.assertIn(primary,chain)
                    armed=False
                    inventory={p:v['data'] for p,v in fs.nodes.items() if not v['directory']}
                    if j:j.close()
                    if l and not l._closed:
                        if lease:l._retire(l._attempts[lease])
                        with self.assertRaises(a.LedgerError):l.begin(key(9),'tool',SHA)
                        with self.assertRaises(a.LedgerError):l.close()
                    self.assertEqual(inventory,{p:v['data'] for p,v in fs.nodes.items() if not v['directory']})
                    self.assertFalse(fs.handles);self.assertEqual(len(fs.closed),len(set(fs.closed)))
                    MODEL_TRACES.append(dict(stage=stage,native_point=native_point,fired=fired,
                        native_actions=fs.events,closes=fs.closed,remaining_handles=list(fs.handles),
                        inventory={p:dict(size=len(raw),sha256=hashlib.sha256(raw).hexdigest(),bytes_hex=raw.hex()) for p,raw in inventory.items()}))
    def test_claim_failure_has_zero_business_and_can_finish_known_failed(self):
        l,fs,c=self.ledger();lease=l.begin(key(),'tool',SHA);j=l.accept(lease);business=[]
        with self.assertRaises(Exception):
            j.claim(object(),key(99),'tool',SHA)
            business.append('called')
        self.assertEqual(business,[]);j.seal('raised',failed=True);j.close();l.finish(lease,'raised');l.close()
        self.assertEqual(c.catalog_codec.parse(self.catalog(l,fs)[3])['payload']['disposition'],'FAILED')
    def test_actual_scope_retention_iserror_and_model_peak(self):
        import asyncio
        import tracemalloc
        import velociraptor_observation as obs
        from tests.test_velociraptor_observation import context
        l,fs,c=self.ledger();leases=[];handle_peak=len(fs.handles)
        def factory(parent,tool,sha):
            lease=l.begin(parent,tool,sha);leases.append(lease);return l.accept(lease)
        observer=obs.RequestObserver(INSTANCE,max_requests=8,max_events_per_request=8,max_event_bytes=4096,journal_factory=factory)
        def hook(*args):
            nonlocal handle_peak
            handle_peak=max(handle_peak,len(fs.handles))
        fs.hook=hook
        async def run():
            for i in range(8):
                async def business(ctx):
                    self.assertEqual(c.catalog_codec.parse(self.catalog(l,fs)[-1])['record_type'],'ACCEPT_ACK')
                    for _ in range(8):obs.emit('target.resolve',dict(operation_id=None,mode='selected',client_id='MODEL-client'))
                    return {'isError':True}
                self.assertEqual(await observer.middleware(context(i),business),{'isError':True})
                l.finish(leases[-1],'returned')
        tracemalloc.start()
        try:
            asyncio.run(run());snapshots=observer.snapshots();current,peak=tracemalloc.get_traced_memory()
        finally:tracemalloc.stop()
        self.assertEqual(sum(len(s['events']) for s in snapshots),64)
        self.assertTrue(all(set(s)=={'key','tool','arguments_sha256','events','outcome','sealed'} for s in snapshots))
        l.close();self.assertFalse(fs.handles)
        import json
        metrics=dict(boundary='MODEL_SCOPE_AND_MODEL_NATIVE_FS_NOT_PRODUCTION_RSS',python_traced_current=current,
            python_traced_peak=peak,model_native_handle_peak=handle_peak,completed_scope_events=64,
            canonical_retained_event_bytes=sum(len(json.dumps(event,sort_keys=True,separators=(',',':')).encode()) for s in snapshots for event in s['events']),
            seen_key_bytes=l._seen_bytes,directory_leases=len(fs.created),catalog_records=len(self.catalog(l,fs)),final_handles=len(fs.handles))
        MODEL_TRACES.append(metrics);print('MODEL_PEAK '+json.dumps(metrics,sort_keys=True))
    def test_final_owned_close_unknown_bounded_and_primary_bad_note_preserved(self):
        for primary in (None,RuntimeError('MODEL business primary')):
            l,fs,c=self.ledger();calls=[]
            def fail():calls.append(1);raise RuntimeError('MODEL secret secondary close text')
            c.group.close=fail
            if primary is None:
                with self.assertRaises(a.LedgerError) as caught:l.close()
                self.assertEqual(str(caught.exception),'archive_resource_close_failed')
                self.assertNotIn('secret',str(caught.exception))
            else:
                def bad_note(*args):raise RuntimeError('note unavailable')
                primary.add_note=bad_note
                with self.assertRaises(RuntimeError) as caught:
                    with l:raise primary
                self.assertIs(caught.exception,primary)
            before=list(fs.events)
            with self.assertRaises(a.LedgerError):l.close()
            self.assertEqual(fs.events,before);self.assertEqual(calls,[1]);self.assertFalse(fs.handles)
            self.assertTrue(l._unknown)
