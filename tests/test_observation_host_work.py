"""Actual SDK-server transfer children against their captured public results.

Windows source/export authority remains MODEL; no qualifier returns fake PASS.
"""
import copy
import json
import os
from pathlib import Path
import unittest

from tests.test_observation_cut_transfer import TransferCut
from tests import test_observation_transfer_children as children
from velociraptor_observation_host import _transfer_workers
from velociraptor_observation_cut import canonical


class HostWorkHTTP(TransferCut):
    test_real_child_native_wait_and_binary_tail_are_in_final_cut_proof=None
    test_actual_binary_sha_and_true_retained_thread_are_exported_without_08_parent=None
    test_all_eight_actual_binary_operations_retained_and_ninth_denied_before_invoke=None

    async def asyncTearDown(self):
        await super().asyncTearDown()
        root=Path(os.environ['PC026_MAINTENANCE_EVIDENCE_ROOT']);root.mkdir(parents=True,exist_ok=True)
        (root/'work-teardown.json').write_bytes(canonical(dict(server_thread_exited=not self.thread.is_alive(),
            http_closed=self.http.is_closed,children=[dict(pid=c.pid,job=c.job,wait_status=c.wait_status,
                resources_closed=c.resources_closed,native_resources_closed=c.native_resources_closed,
                guard_closed=c.activation_closed) for c in self.controller._children.values()],
            close_io=[dict(joined=r.joined,thread_alive=r.thread.is_alive()) for r in self.controller._close_io.values()])))

    async def test_actual_begin_prepare_children_have_exact_request_result_identity(self):
        await self.initialize();calls=[];responses=[]
        async def tool(number,name,args):
            response=await self.http.post(self.url,json=dict(jsonrpc='2.0',id=number,
                method='tools/call',params=dict(name=name,arguments=args)))
            responses.append(dict(request=json.loads(response.request.content),status=response.status_code,
                response=response.text))
            self.assertEqual(response.status_code,200,response.text)
            envelope=json.loads(next(line[6:] for line in response.text.splitlines() if line.startswith('data: ')))['result']
            self.assertFalse(envelope.get('isError',False));calls.append((name,args,envelope));return envelope['structuredContent']['result']
        await tool(1,'transfer_begin',dict(request=self.request));await self.settled()
        await tool(2,'transfer_status',self.args)
        await tool(3,'transfer_finish',dict(self.args,action='prepare'));await self.settled()
        await tool(4,'transfer_status',self.args)
        response=await self.http.delete(self.url);self.assertEqual(response.status_code,200,response.text)
        proof=json.loads(self.exporter.files['lifecycle.json']);workers=proof['sdk_work']['transfer_workers']
        self.assertEqual([w['job'] for w in workers],['package','prepare'])
        _transfer_workers(calls,workers)
        outcomes=[]
        def reject(name,mutate,code):
            changed=copy.deepcopy(workers);mutate(changed)
            with self.assertRaisesRegex(Exception,code) as error:_transfer_workers(calls,changed)
            outcomes.append(dict(case=name,error=str(error.exception)))
        reject('missing_package',lambda w:w.pop(0),'host_transfer_worker_missing')
        reject('missing_prepare',lambda w:w.pop(1),'host_transfer_worker_missing')
        reject('extra_nonce',lambda w:w.append(dict(w[0],worker_nonce='f'*32)),'host_transfer_worker_unobserved')
        reject('duplicate',lambda w:w.append(w[0]),'host_transfer_worker_duplicate')
        reject('wrong_pid',lambda w:w[0].update(pid=w[0]['pid']+1),'host_transfer_worker_identity')
        reject('unknown_exit',lambda w:w[0].update(process_exited=False),'host_transfer_worker_unknown')
        reject('foreign_digest',lambda w:w[0].update(request_digest='f'*64),'host_transfer_worker_causality')
        root=Path(os.environ['PC026_MAINTENANCE_EVIDENCE_ROOT']);root.mkdir(parents=True,exist_ok=True)
        (root/'work-originals.json').write_bytes(canonical(dict(calls=calls,responses=responses,proof=proof,
            close=dict(status=response.status_code,headers=list(response.headers.multi_items()),body=response.text),negatives=outcomes)))

    async def test_finish_child_closes_without_an_additional_status_call(self):
        await self.initialize();calls=[]
        for number,name,args in ((1,'transfer_begin',dict(request=self.request)),
                (2,'transfer_finish',dict(self.args,action='prepare'))):
            response=await self.http.post(self.url,json=dict(jsonrpc='2.0',id=number,method='tools/call',
                params=dict(name=name,arguments=args)))
            self.assertEqual(response.status_code,200,response.text)
            envelope=json.loads(next(line[6:] for line in response.text.splitlines() if line.startswith('data: ')))['result']
            self.assertFalse(envelope.get('isError',False));calls.append((name,args,envelope))
            await self.settled()
        close=await self.http.delete(self.url);self.assertEqual(close.status_code,200,close.text)
        proof=json.loads(self.exporter.files['lifecycle.json'])
        _transfer_workers(calls,proof['sdk_work']['transfer_workers'])
        workers=proof['sdk_work']['transfer_workers']
        extra=copy.deepcopy(workers);prepare=next(w for w in workers if w['job']=='prepare')
        extra.append(dict(prepare,worker_nonce='f'*32))
        with self.assertRaisesRegex(Exception,'host_transfer_worker_unobserved'):_transfer_workers(calls,extra)
        with self.assertRaisesRegex(Exception,'host_transfer_worker_unobserved'):_transfer_workers(calls+[calls[-1]],workers)
        root=Path(os.environ['PC026_MAINTENANCE_EVIDENCE_ROOT'])
        (root/'finish-no-status-originals.json').write_bytes(canonical(dict(calls=calls,proof=proof,
            close=dict(status=close.status_code,headers=list(close.headers.multi_items()),body=close.text))))


def load_tests(loader,tests,pattern):return loader.loadTestsFromTestCase(HostWorkHTTP)
