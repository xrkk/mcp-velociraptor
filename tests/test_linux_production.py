import copy
import base64
import re
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch, MagicMock

import velociraptor_linux_backend as b
from velociraptor_linux_domain import LinuxDomainError, LinuxPlatformRouter, register_linux_domain_tools, compare_triage_runs, ScopeState, build_triage_plan


class Registry:
    def __init__(self): self.handlers={}
    def add_tool(self, fn, *, name, description): self.handlers[name]=fn


class API:
    def __init__(self, definitions, plan):
        self.definitions=definitions;self.plan=plan;self.calls=[];self.flows=[];self.bad=False;self.state='RUNNING'
    def query(self,q,evidence=None,mutation=False):
        self.calls.append((q,mutation))
        if 'artifact_definitions(' in q:return list(self.definitions.values())
        if 'collect_client(' in q:
            name=list(self.plan['parameters'])[len(self.flows)%len(self.plan['parameters'])]
            self.flows.append({'flow_id':'F.MODEL'+str(len(self.flows)), 'artifact':name})
            if self.bad:return []
            return [{'flow_id':self.flows[-1]['flow_id'],'request':{'artifacts':[name],
                'timeout':self.plan['timeout_seconds'],'max_upload_bytes':self.plan['max_bytes'],
                'specs':[{'parameters':{'env':[{'key':k,'value':'' if v=='N' else v} for k,v in self.plan['parameters'][name].items()]}}]}}]
        if 'FROM source(' in q:
            name=json.loads(re.search(r'artifact=("[^"]+")',q)[1])
            start=int(re.search(r'start_row=(\d+)',q)[1])
            source=re.search(r'source=("[^"]*")',q)
            source=json.loads(source[1]) if source else ''
            mapping={
                'Linux.Sys.Pslist':[{'Pid':i+1,'Exe':'/MODEL/exe'} for i in range(205)],
                'Linux.Search.FileFinder':[{'OSPath':'/MODEL/file','MTime':'MODEL','Hash':{'SHA256':b.sha(b'MODEL FILE')},
                    'Upload':{'Path':'/MODEL/file','sha256':b.sha(b'MODEL FILE')}}],
                'Linux.Network.Netstat':[{'ProcessInfo':{'Pid':1}}],
                'Linux.Sys.Services':[{'Unit':'MODEL.service'}],
                'Linux.Sys.Crontab':[{'Command':'MODEL READONLY'}],
                'Generic.Collectors.File':[{'SourceFile':'/MODEL/unit'}],
                'Linux.Forensics.Journal':[{'System':{'Timestamp':'MODEL'},'EventData':{'MESSAGE':'MODEL'}}],
            }
            return mapping.get(name,[{'MODEL':True}])[start:start+100]
        if 'FROM flow_logs(' in q:return [{'message':'MODEL log'}]
        if 'FROM uploads(' in q:
            f=next(x for x in self.flows if '"'+x['flow_id']+'"' in q)
            if f['artifact']!='Linux.Search.FileFinder':return []
            return [{'file_size':10,'uploaded_size':10,'client_path':'/MODEL/file',
                     '_Components':['clients','C.model','collections',f['flow_id'],'uploads','auto','MODEL','file']}]
        if 'read_file(' in q:return [{'Data':base64.b64encode(b'MODEL FILE').decode()}]
        if 'FROM flows(' in q:
            f=next(x for x in self.flows if '"'+x['flow_id']+'"' in q)
            return [{'session_id':f['flow_id'],'state':self.state}]
        if 'cancel_flow(' in q:self.state='CANCELLED';return [{'Result':{'state':'CANCELLED'}}]
        raise AssertionError(q)


class ProductionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.sid=str(uuid.uuid4());self.rid=str(uuid.uuid4());self.cid='C.model'
        self.definitions={x['name']:x for x in json.loads((Path(__file__).parent/'fixtures/linux_artifacts_v0773.json').read_text())}
        self.plan={'parameters':{k:{} for k in b.ARTIFACT_HASHES},'timeout_seconds':30,'max_bytes':1048576}
        self.plan['parameters']['Linux.Search.FileFinder']={'SearchFilesGlob':'/MODEL/file','SearchFilesGlobTable':'Glob\n','Upload_File':'Y','Calculate_Hash':'Y'}
        self.plan['parameters']['Generic.Collectors.File']={'Root':'/','collectionSpec':'Glob\nMODEL/unit\n','MaxFileSize':'1024'}
        self.plan['parameters']['Linux.Forensics.Journal']={'DateAfter':'2026-10-08T00:00:00Z','DateBefore':'2026-10-08T01:00:00Z','AlsoUpload':'N'}
        self.backend=b.LinuxTriageBackend.__new__(b.LinuxTriageBackend)
        self.backend.store=self.root;self.backend.binding={'client_id':self.cid,'vm_uuid':'MODEL','boot_id':'MODEL'}
        self.backend.route=lambda cid: b.require(cid==self.cid,'UNBOUND_CLIENT')
        self.api=API(self.definitions,self.plan);self.backend.api=self.api
        p=patch.object(b,'private_path',side_effect=lambda p,**k:Path(p));p.start();self.addCleanup(p.stop)

    def test_actual_mcp_registry_injects_backend(self):
        import velociraptor_linux_domain as domain
        import mcp_velociraptor_bridge as bridge
        with patch.dict('os.environ',{'VELOCIRAPTOR_LINUX_DOMAIN':'1','VELOCIRAPTOR_LINUX_ROOT':'MODEL'}), \
             patch.object(b,'LinuxTriageBackend',return_value=self.backend), \
             patch.object(bridge,'init_stub') as windows_init:
            server=bridge.create_server()
            self.assertEqual(set(server._tool_manager._tools),set(domain.LINUX_DOMAIN_TOOL_NAMES))
            self.assertIs(server._linux_backend,self.backend)
            windows_init.assert_not_called()
            tool=server._tool_manager.get_tool('linux_platform_route')
            self.assertIsNone(tool.fn(self.cid))

    def test_default_bridge_does_not_construct_linux_backend(self):
        import mcp_velociraptor_bridge as bridge
        with patch.dict('os.environ',{'VELOCIRAPTOR_LINUX_DOMAIN':'0'}), \
             patch.object(b,'LinuxTriageBackend') as linux, \
             patch.object(bridge,'init_stub'), \
             patch.object(bridge,'read_root_artifact_definitions',return_value=[]), \
             patch.object(bridge,'register_dynamic_artifact_tools',return_value=()) as dynamic, \
             patch.object(bridge,'register_fixed_tools') as fixed, \
             patch.object(bridge,'register_transfer_tools') as transfer, \
             patch.object(bridge,'validate_combined_registry') as validate:
            bridge.create_server()
            linux.assert_not_called();dynamic.assert_called_once();fixed.assert_called_once()
            transfer.assert_called_once();validate.assert_called_once()

    def test_registry_provider_and_backend_required(self):
        r=Registry();register_linux_domain_tools(r)
        with self.assertRaises(LinuxDomainError) as c:r.handlers['linux_platform_route'](self.cid)
        self.assertEqual(c.exception.code,'NO_CLIENTS_PROVIDER')
        with self.assertRaises(LinuxDomainError):r.handlers['linux_triage_status'](self.rid)
        r=Registry();register_linux_domain_tools(r,backend=self.backend)
        self.assertIsNone(r.handlers['linux_platform_route'](self.cid))
        with self.assertRaises(LinuxDomainError):r.handlers['linux_platform_route']('C.other')
        self.assertFalse(self.api.calls)

    def test_wrong_unknown_ambiguous_zero_mutation(self):
        clients=[{'client_id':'C.win','os':'windows'},{'client_id':self.cid,'os':'linux'}]
        router=LinuxPlatformRouter(lambda:clients)
        for cid,code in [('C.win','WRONG_PLATFORM'),('C.unknown','CLIENT_NOT_FOUND')]:
            with self.assertRaises(LinuxDomainError) as c:router.resolve_linux_target(cid)
            self.assertEqual(c.exception.code,code);self.assertEqual(c.exception.details['velociraptor_mutations_issued'],0)
        clients.append(dict(clients[-1]))
        with self.assertRaises(LinuxDomainError):router.resolve_linux_target(self.cid)
        self.assertFalse(self.api.calls)

    def test_original_definition_drift_refuses_before_launch(self):
        self.definitions['Linux.Sys.Pslist']['raw']+='\n# drift'
        with self.assertRaises(LinuxDomainError):self.backend.launch(self.sid,self.rid,self.cid,self.plan)
        self.assertFalse(any(m for _,m in self.api.calls));self.assertFalse((self.root/self.rid).exists())

    def test_unknown_parameters_refused_before_mutation(self):
        self.plan['parameters']['Linux.Search.FileFinder']['Globs']='WRONG OLD PARAM'
        with self.assertRaises(LinuxDomainError):self.backend.launch(self.sid,self.rid,self.cid,self.plan)
        self.assertFalse(any(m for _,m in self.api.calls))

    def test_actual_parameters_and_resources_in_launch(self):
        out=self.backend.launch(self.sid,self.rid,self.cid,self.plan)
        self.assertEqual(len(out['flows']),9)
        queries=[q for q,m in self.api.calls if m]
        self.assertTrue(all('timeout=30' in q and 'max_bytes=1048576' in q for q in queries))
        self.assertTrue(any('`SearchFilesGlob`="/MODEL/file"' in q for q in queries))
        before=len(queries)
        with self.assertRaises(FileExistsError):self.backend.launch(self.sid,self.rid,self.cid,self.plan)
        self.assertEqual(len([q for q,m in self.api.calls if m]),before)

    def test_unknown_launch_has_intent_no_latest_no_replay(self):
        self.api.bad=True
        with self.assertRaises(LinuxDomainError) as c:self.backend.launch(self.sid,self.rid,self.cid,self.plan)
        self.assertEqual(c.exception.code,'LAUNCH_UNKNOWN')
        self.assertTrue((self.root/self.rid/'intent-0.json').exists())
        self.assertFalse(list((self.root/self.rid).glob('flow-*')))
        self.assertFalse(any('FROM flows(' in q for q,_ in self.api.calls))
        with self.assertRaises(FileExistsError):self.backend.launch(self.sid,self.rid,self.cid,self.plan)
        self.assertEqual(sum(m for _,m in self.api.calls),1)

    def test_status_exact_flows_and_actual_cancel(self):
        self.backend.launch(self.sid,self.rid,self.cid,self.plan)
        self.assertFalse(self.backend.status(self.rid)['complete'])
        for q,_ in self.api.calls:
            if 'FROM flows(' in q:
                self.assertIn('WHERE session_id="F.MODEL',q)
                self.assertNotIn('ORDER BY',q)
        out=self.backend.cancel(self.rid)
        self.assertTrue(any('cancel_flow(' in q and m for q,m in self.api.calls))
        self.assertTrue(all(x['state']=='CANCELLED' for x in out['terminal']['flows']))

    def test_old_error_comparison_and_fake_products(self):
        old={'fingerprint':'same','client_id':self.cid,'category_results':{'process':{'state':'ERROR'}}}
        self.assertFalse(compare_triage_runs(old,old)['repeatable'])
        a=self.result(str(uuid.uuid4()));z=self.result(str(uuid.uuid4()))
        self.assertFalse(compare_triage_runs(a,z)['repeatable'])  # Fabricated summaries lack source originals.
        z['products'][0]['path']=str(self.root/'invented')
        self.assertFalse(compare_triage_runs(a,z)['repeatable'])

    def result(self,rid):
        p=self.root/rid;p.mkdir()
        product=dict(b.publish(p/'file.bin',b'MODEL EVIDENCE'),kind='file')
        flows=[{'flow_id':'F.'+str(i),'artifact':name} for i,name in enumerate(b.ARTIFACT_HASHES)]
        result={'run_id':rid,'status':'FINISHED','complete':True,'fingerprint':'MODEL SAME',
            'premise':{'model':True},'flows':flows,'flow_status':[dict(x,state='FINISHED') for x in flows],
            'category_results':{k:True for k in b.REQUIRED_CATEGORIES},'products':[product]}
        return dict(result,ref=b.publish(p/'result.json',b.canonical(result)))

    def test_returned_manifest_cannot_override_original_failure(self):
        a=self.result(str(uuid.uuid4()));z=self.result(str(uuid.uuid4()));z['status']='ERROR'
        self.assertFalse(compare_triage_runs(a,z)['repeatable'])
        z['status']='FINISHED';z['premise']={'invented':True}
        self.assertFalse(compare_triage_runs(a,z)['repeatable'])

    def test_legacy_plan_preserves_params_and_limits(self):
        p=build_triage_plan(ScopeState(self.sid),{'client_id':self.cid},max_timeout_seconds=7,max_collection_mb=2,
                           parameters={'Linux.Sys.Pslist':{'processRegex':'MODEL'}})
        spec=next(x for x in p.as_launch_specs() if x['artifact']=='Linux.Sys.Pslist')
        self.assertEqual(spec['parameters'],{'processRegex':'MODEL'});self.assertEqual(spec['timeout'],7)
        self.assertEqual(spec['max_bytes'],2097152)

    def test_real_reference_byte_tampering_refuses(self):
        a=self.result(str(uuid.uuid4()));z=self.result(str(uuid.uuid4()))
        Path(z['products'][0]['path']).write_bytes(b'TAMPER')
        self.assertFalse(compare_triage_runs(a,z)['repeatable'])

    def test_full_pages_download_and_original_comparison(self):
        self.api.state='FINISHED'
        a=self.backend.collect(self.sid,self.rid,self.cid,self.plan)
        second=str(uuid.uuid4())
        z=self.backend.collect(self.sid,second,self.cid,self.plan)
        self.assertTrue(a['complete']);self.assertTrue(z['complete'])
        self.assertTrue(self.backend.compare(self.rid,second)['repeatable'])
        pages=[x for x in a['products'] if x.get('artifact')=='Linux.Sys.Pslist' and x['kind']=='rows']
        self.assertEqual([x['offset'] for x in pages],[0,100,200])
        self.assertEqual([x['rows'] for x in pages],[100,100,5])
        file=next(x for x in a['products'] if x['kind']=='file')
        self.assertEqual(Path(file['path']).read_bytes(),b'MODEL FILE')
        self.assertEqual(file['sha256'],b.sha(b'MODEL FILE'))
        exported=self.backend.export(self.rid,include_bytes=True)
        self.assertTrue(any(x['name']=='result.json' for x in exported['originals']))

    def test_repeat_collect_never_cancels_existing_run(self):
        self.backend.launch(self.sid,self.rid,self.cid,self.plan)
        with patch.object(self.backend,'cancel') as cancel:
            with self.assertRaises(FileExistsError):
                self.backend.collect(self.sid,self.rid,self.cid,self.plan)
            cancel.assert_not_called()

    def test_concatenated_cli_arrays(self):
        self.assertEqual(b.parse_arrays(b'[{"x":1}]\n[{"x":2}]'),[{'x':1},{'x':2}])

if __name__=='__main__':unittest.main()
