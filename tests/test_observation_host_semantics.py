"""Actual typed SDK-wire calls and legal foreign live prefix, finite mutations."""
import asyncio
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import uuid
import unittest

import httpx2
from tests.test_observation_cut import CutHTTPTests,CUT_TRACES
from tests.p06_http_body_capture import CaptureTransport,verify
from tests.p06_mcp_raw_join import _Reader,messages
from velociraptor_observation_cut import canonical,ref
from velociraptor_observation_host import _occurrences


class HostSemantics(unittest.IsolatedAsyncioTestCase):
    asyncSetUp=CutHTTPTests.asyncSetUp
    records=CutHTTPTests.records
    initialize=CutHTTPTests.initialize
    call=CutHTTPTests.call

    async def asyncTearDown(self):
        await CutHTTPTests.asyncTearDown(self)
        root=Path(os.environ['PC026_MAINTENANCE_EVIDENCE_ROOT']);root.mkdir(parents=True,exist_ok=True)
        (root/'semantic-teardown.json').write_bytes(canonical(CUT_TRACES[-1]))

    async def test_typed_calls_foreign_unfinished_prefix_and_target_rejections(self):
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup)
        run=Path(directory.name)/str(uuid.uuid4());run.mkdir(mode=0o700)
        await self.http.aclose()
        capture=CaptureTransport(httpx2.AsyncHTTPTransport(),run,run.name)
        self.http=httpx2.AsyncClient(trust_env=False,timeout=8,transport=capture,
            headers={'authorization':'Bearer MODEL','accept':'application/json, text/event-stream','content-type':'application/json'})
        own=await self.initialize()
        # The foreign session uses a separate physical capture; its accepted
        # unfinished BEGIN belongs in the global prefix, not in own events/work.
        other=httpx2.AsyncClient(trust_env=False,timeout=8,headers={'authorization':'Bearer MODEL',
            'accept':'application/json, text/event-stream','content-type':'application/json'})
        foreign=await other.post(self.url,json=dict(jsonrpc='2.0',id=0,method='initialize',params=dict(
            protocolVersion='2025-11-25',capabilities={},clientInfo=dict(name='foreign',version='1'))))
        sid=foreign.headers['mcp-session-id'];other.headers.update({'mcp-session-id':sid,'mcp-protocol-version':'2025-11-25'})
        await other.post(self.url,json=dict(jsonrpc='2.0',method='notifications/initialized'))
        latched=asyncio.create_task(other.post(self.url,json=dict(jsonrpc='2.0',id=7,method='tools/call',
            params=dict(name='echo',arguments=dict(value='latch')))))
        try:
            until=time.monotonic()+2
            while not self.started.is_set() and time.monotonic()<until:await asyncio.sleep(.001)
            self.assertTrue(self.started.is_set())
            self.assertEqual((await self.call(7,'integer')).status_code,200)
            self.assertEqual((await self.call('7','string')).status_code,200)
            closed=await self.http.delete(self.url);self.assertEqual(closed.status_code,200,closed.text)
            self.assertFalse(latched.done());self.assertEqual(self.controller._sessions[sid]['state'],'OPEN')
            files=copy.deepcopy(self.exporter.files);codec=self.exporter.codec
            codec.verify(files,self.config.catalog_codec,self.config.codec,self.exporter.lifecycle_config_raw)
            await self.http.aclose();index=verify(run,run.name)
            reader=_Reader(run)
            try:
                requests=[];responses=[]
                for exchange in index['exchanges']:
                    requests.extend(messages(reader,exchange,'request'))
                    responses.extend(messages(reader,exchange,'response'))
                joined={'calls':[]}
                for request,location in requests:
                    if request.get('method')!='tools/call':continue
                    matches=[(message,where) for message,where in responses if type(message.get('id')) is type(request['id'])
                        and message.get('id')==request['id'] and 'result' in message]
                    self.assertEqual(len(matches),1)
                    joined['calls'].append(dict(tool=request['params']['name'],request_id=request['id'],
                        request_location=location,response_location=matches[0][1]))
                context=dict(archive=dict(budgets=self.config.document['budgets']),original_session=own,instance=self.ledger._instance)
                _occurrences(files,context,index,joined,reader)
                self.assertEqual([type(c['request_id']).__name__ for c in joined['calls']],['int','str'])
                outcomes=[]
                def occurrences_negative(name,mutate,code):
                    changed=copy.deepcopy(files);projected=copy.deepcopy(joined);mutate(changed,projected)
                    with self.assertRaisesRegex(Exception,code) as caught:_occurrences(changed,context,index,projected,reader)
                    outcomes.append(dict(case=name,target='host._occurrences',error=str(caught.exception)))
                def work_mutation(files,remove):
                    p=json.loads(files['lifecycle.json'])
                    if remove:p['sdk_work']['messages'].pop()
                    else:p['sdk_work']['messages'].append(copy.deepcopy(p['sdk_work']['messages'][0]))
                    files['lifecycle.json']=canonical(p)
                occurrences_negative('missing_sdk_message',lambda f,j:work_mutation(f,True),'host_sdk_work_bijection')
                occurrences_negative('extra_sdk_message',lambda f,j:work_mutation(f,False),'host_sdk_work_bijection')
                occurrences_negative('typed_alias_not_same_occurrence',lambda f,j:j['calls'][0].update(request_id='7'),'host_attempt_call_binding')
                def binary(files,joined):
                    proof=json.loads(files['lifecycle.json']);proof['binary_work']=[dict(unobserved=True)];files['lifecycle.json']=canonical(proof)
                occurrences_negative('unobserved_business_binary',binary,'host_unobserved_binary')
                projection=json.loads(files['attempts.json'])
                original_records=[self.config.catalog_codec.parse(files[r['path']]) for r in projection['catalog_prefix']]
                foreign_begin=next(r for r in original_records if r['record_type']=='ATTEMPT_BEGIN' and r['payload']['key']['session_id']==sid)
                foreign_seq=foreign_begin['payload']['attempt_sequence']
                self.assertFalse(any(r['record_type']=='ATTEMPT_END' and r['payload']['attempt_sequence']==foreign_seq for r in original_records))
                def cut_negative(name,changed,code):
                    # Rebind every outer content Ref that can be recomputed.
                    for filename in ('lifecycle.json','attempts.json','source-manifest.json','cut.json','export.json'):
                        value=json.loads(changed[filename])
                        if filename=='source-manifest.json':
                            for row in value['files']:
                                path=row['export_ref']['path']
                                if path in changed:
                                    row['source_ref']=ref(row['source_ref']['path'],changed[path])
                        def rebind(v):
                            if isinstance(v,list):return [rebind(x) for x in v]
                            if isinstance(v,dict):
                                if set(v)=={'path','size','sha256'} and v['path'] in changed:return ref(v['path'],changed[v['path']])
                                return {k:rebind(x) for k,x in v.items()}
                            return v
                        changed[filename]=canonical(rebind(value))
                    with self.assertRaisesRegex(Exception,code) as caught:codec.verify(changed,self.config.catalog_codec,self.config.codec,self.exporter.lifecycle_config_raw)
                    outcomes.append(dict(case=name,target='CutCodec.verify',error=str(caught.exception)))
                def without(kind):
                    changed=copy.deepcopy(files);rows=[copy.deepcopy(r) for r in original_records
                        if not (r['record_type']==kind and r['payload']['attempt_sequence']!=foreign_seq)]
                    previous=None;prefix=[]
                    for n,row in enumerate(rows):
                        row.update(sequence=n,previous=previous);raw=self.config.catalog_codec.encode(row)
                        path=f'originals/c/{n:08d}.json';changed[path]=raw;prefix.append(ref(path,raw))
                        previous=dict(size=len(raw),sha256=hashlib.sha256(raw).hexdigest())
                    p=json.loads(changed['attempts.json']);p['catalog_prefix']=prefix;changed['attempts.json']=canonical(p)
                    return changed
                cut_negative('own_ACK_missing_rechained',without('ACCEPT_ACK'),'catalog END head/ACK')
                cut_negative('own_END_missing_rechained',without('ATTEMPT_END'),'session_attempt_closure')
                changed=copy.deepcopy(files);p=json.loads(changed['attempts.json']);p['catalog_prefix'].pop(1);changed['attempts.json']=canonical(p)
                cut_negative('prefix_gap',changed,'fixed_ref_path')
                changed=copy.deepcopy(files);p=json.loads(changed['attempts.json']);p['attempt_sequences']=sorted([*p['attempt_sequences'],foreign_seq]);changed['attempts.json']=canonical(p)
                cut_negative('foreign_attempt_projection',changed,'session_attempt_closure')
                root=Path(os.environ['PC026_MAINTENANCE_EVIDENCE_ROOT']);root.mkdir(parents=True,exist_ok=True)
                (root/'semantic-originals.json').write_bytes(canonical(dict(original_session=own,foreign_session=sid,
                    joined=joined,index=index,records=original_records,proof=json.loads(files['lifecycle.json']),negatives=outcomes)))
                self.assertEqual(len(outcomes),8)
            finally:reader.close()
        finally:
            self.release.set();await latched
            await other.delete(self.url);await other.aclose()


def load_tests(loader,tests,pattern):return loader.loadTestsFromTestCase(HostSemantics)
