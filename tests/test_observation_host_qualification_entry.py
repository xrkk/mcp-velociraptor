"""Real qualification CLI/SDK/gates with explicit local MODEL management backend."""
import copy
from datetime import datetime,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import inspect
import json
import os
from pathlib import Path
import threading

from tests.test_observation_host_entrypoint import ActualIndividual,IndividualBackend
from tests.test_p04_fixed_tools import flow_row
from velociraptor_mcp_core import FlowReferenceResult
from velociraptor_fixed_tools import TRIAGE_ARTIFACT
from velociraptor_observation_cut import canonical

class QualificationBackend(IndividualBackend):
    def __init__(self):
        super().__init__();self.counter=0;self.dependencies.add(TRIAGE_ARTIFACT)
    def start_collection(self,client_id,artifact,parameters=None,**options):
        self.counter+=1;flow='F.model'+str(self.counter)
        row=flow_row(flow,'FINISHED');row.update(artifacts=[artifact],
            artifacts_with_results=[artifact+'/Rows'],request={'artifacts':[artifact]})
        self.flows[flow]=row
        return FlowReferenceResult(operation='fixture',status='FINISHED',warnings=[],flow_id=flow)
    def list_flow_uploads(self,client_id,flow_id):
        result=copy.deepcopy(self.uploads)
        for row in result:row['Upload']['Components'][3]=flow_id
        return result

class ActualQualification(ActualIndividual):
    SCENARIO='resource-qualification'
    ENTRY_SCRIPT='p06_resource_qualification.py'
    backend_factory=QualificationBackend
    # A download emits nine events; ACCEPT and seal need their own two slots.
    # Twelve retains a finite spare without inflating the export reserve.
    MODEL_REQUEST_RECORDS=12
    MODEL_REQUEST_TIMEOUT=60
    MODEL_GUEST_LIMITS=dict(max_files=40000,max_metadata_bytes=4<<20,
        max_logical_bytes=64<<20,max_package_bytes=128<<20,
        max_state_bytes=65536,max_duration_seconds=60)
    test_actual_individual_entry_clock_binding_archive_and_failed_tool_contracts=None
    def configure_model_server(self,server,backend):
        self.model_backend=backend
        from velociraptor_dynamic_artifacts import _strict_tool_schema
        def make(artifact,parameters):
            def dynamic(**values)->FlowReferenceResult:
                return backend.start_collection('C.one',artifact,values)
            dynamic.__signature__=inspect.Signature([
                inspect.Parameter(key,inspect.Parameter.KEYWORD_ONLY,annotation=type(value))
                for key,value in parameters.items()],return_annotation=FlowReferenceResult)
            return dynamic
        invocations=json.loads(Path('tests/data/p03_invocations.json').read_bytes())
        for row in invocations:
            if row['risk_class']!='resource_sensitive' or row['artifact']=='Windows.Network.PacketCapture':continue
            name=row['artifact'];server.remove_tool(name)
            server.add_tool(make(name,row['parameters']),name=name,description='MODEL inert finished collection')
            _strict_tool_schema(server._tool_manager.get_tool(name))
    def start_model_management(self,identity):
        # Explicit MODEL control plane. The unmodified GuestResourceSampler
        # makes actual HTTP RPCs and retains its original responses. These
        # readings are fixture values, never evidence of Windows resources.
        readings=dict(physical_memory_bytes=1024**3,available_memory_bytes=512*1024**2,
            c_total_bytes=64*1024**3,c_free_bytes=32*1024**3,datastore_bytes=0,
            download_root_bytes=0,report_root_bytes=0)
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                request=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                method=request['method']
                if method=='notifications/initialized':
                    self.send_response(202);self.end_headers();return
                if method=='initialize':result={'protocolVersion':'2025-03-26','capabilities':{},'serverInfo':{'name':'explicit-resource-MODEL','version':'1'}}
                else:
                    assert method=='tools/call' and request['params']['name']=='PowerShell'
                    observation=dict(hostname=identity['computer_name'],server_pid=identity['pid'],
                        observed_at=datetime.now(timezone.utc).isoformat(),reading=readings,trace_status='MODEL inactive')
                    result={'isError':False,'structuredContent':{'result':'Response: '+json.dumps(observation)+'\nStatus Code: 0'},'content':[]}
                raw=canonical(dict(jsonrpc='2.0',id=request['id'],result=result))
                self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        server=ThreadingHTTPServer(('127.0.0.1',28787),Handler)
        thread=threading.Thread(target=server.serve_forever,name='R14-owned-MODEL-management')
        thread.start()
        def close():
            server.shutdown();server.server_close();thread.join(5)
            self.assertFalse(thread.is_alive(),'owned management backend still running')
        self.addCleanup(close)
        evidence=Path(os.environ['PC026_MAINTENANCE_EVIDENCE_ROOT'])
        evidence.mkdir(parents=True,exist_ok=True)
        (evidence/'management-nature.json').write_bytes(canonical(dict(nature='explicit local MODEL resource values; real unmodified HTTP sampler and admission',readings=readings)))
    async def test_actual_resource_qualification_entry_and_original_management_gate(self):
        self.assertEqual(self.entry_report['status'],'success',self.entry_report['failure'])
        self.assertEqual(len(self.controller._sessions),2)
        self.assertEqual(len(self.entry_report['calls']),41)
        self.assertEqual(len([r for r in self.entry_report['steps'] if r.get('kind')=='resource-qualification']),11)
        for name in ('mcp-observation-binding.json','archive/cut.json','maintenance/ledger.json',
                'resource-budget.json','qualification-payload.zip','package-manifest.json'):
            self.assertTrue((self.entry_run/name).is_file(),name)
        self.preserve(self.entry_run)

def load_tests(loader,tests,pattern):return loader.loadTestsFromTestCase(ActualQualification)
