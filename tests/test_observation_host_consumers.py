"""Fresh 137-registry SDK consumption, isolated C8 and restore MODEL, POSIX I/O."""
import json
import os
from pathlib import Path
import shutil
import tempfile
from unittest.mock import patch

from tests.test_observation_host import HostHTTP
from tests import p05_pc026_governance as gov,scenario_runner as runner
from tests import test_observation_maintenance as guest
from tests import test_observation_startup as startup
from tests.test_p05_pc026_governance import ApprovalFixture,reference
from tests.pc026_governance_fixture import build
from velociraptor_observation_cut import canonical
import velociraptor_observation_host as host


class CurrentHostHTTP(HostHTTP):
    SCENARIO='resource-qualification'
    FIXED_PORT=28790
    test_fresh_sdk_independent_derived_sidecar_and_missing_original=None

    def _prepare_authority(self):
        old=self.preflight.root
        self.current_tmp=tempfile.TemporaryDirectory(dir=os.environ.get('PC020_TEST_TEMP_ROOT'))
        self.addCleanup(self._retain_or_clean)
        root=Path(self.current_tmp.name)
        created=[];init=ApprovalFixture.__init__
        def construct(fixture,*args,**kwargs):
            init(fixture,*args,**kwargs);created.append(fixture)
        keys=('PC020_ACTIVATION188_FIXTURE','PC020_PREDECESSOR_FIXTURE','PC020_BASELINE_DIR_FIXTURE',
            'PC020_ACTIVATION_DIR_FIXTURE','PC020_REAL_SOURCE_ROOT')
        with patch.object(ApprovalFixture,'__init__',construct):
            self.activation=build(root,Path(os.environ['PC026_BOOTSTRAP_FIXTURE_ROOT']),
                {key:os.environ[key] for key in keys},gov.REPOSITORY)
        f=created[0];self.preflight.root=root;self.preflight.f=f
        self.preflight.fixture.root=root;self.preflight.fixture.f=f
        from velociraptor_observation_config import CONFIG,ROOT_RECORD
        rootdoc=json.loads((old/ROOT_RECORD).read_bytes());sd=rootdoc['sd_ref']['path']
        (root/sd).write_bytes((old/sd).read_bytes());f.refs[sd]=reference(root,sd)
        rootdoc['sd_ref']=f.refs[sd];(root/ROOT_RECORD).write_bytes(canonical(rootdoc));f.refs[ROOT_RECORD]=reference(root,ROOT_RECORD)
        self.preflight.fixture.doc.update(implementation_freeze_ref=f.refs[gov.FREEZE],deployment_ref=f.refs[gov.DEPLOYMENT])
        self.preflight.fixture.bind();self.preflight.doc.update(archive_config_ref=f.refs[CONFIG],
            implementation_freeze_ref=f.refs[gov.FREEZE],deployment_ref=f.refs[gov.DEPLOYMENT]);self.preflight.bind()
        from tests.p04_fixture_server import dynamic_candidate
        from tests.test_p04_fixed_tools import FakeBackend
        from velociraptor_mcp_core import TargetContext
        from velociraptor_fixed_tools import register_fixed_tools
        def server_factory(*args,**kwargs):
            server,specs=dynamic_candidate();backend=getattr(self,'backend_factory',FakeBackend)()
            configure=getattr(self,'configure_model_server',None)
            if configure is not None:configure(server,backend)
            download=None
            if getattr(self,'MODEL_DOWNLOAD_ROOT',False):
                download=self.root/'fixed-downloads';download.mkdir(mode=0o700)
                download=str(download)
            register_fixed_tools(server,specs,TargetContext(backend),backend,download_root=download)
            # The inherited fixture's echo is replaced by a real registered
            # fixed-tool call below, never an additional registry member.
            server.tool=lambda *args,**kwargs:lambda function:function
            return server
        self.patch(guest,'MCPServer',server_factory)

    def _retain_or_clean(self):
        if os.environ.get('PC026_HOST_RETAIN_INPUTS')=='1':
            self.current_tmp._finalizer.detach()
            root=Path(os.environ['PC026_MAINTENANCE_EVIDENCE_ROOT']);root.mkdir(parents=True,exist_ok=True)
            (root/'retained-isolated-root.json').write_bytes(canonical(dict(root=self.current_tmp.name,
                nature='isolated C8/restore MODEL; actual SDK and native POSIX')))
        else:self.current_tmp.cleanup()

    def _business_call(self,name,arguments):return 'run_vql',dict(query='SELECT 1',max_rows=1)

    def _candidate_inputs(self):
        from tests.test_p06_pc026_binding import CurrentConsumerTests
        from tests import p05_pc020_evidence as ev
        builder=CurrentConsumerTests('test_call_clock_actual_admission_matrix_and_tail_drift')
        builder.root=self.root;builder.A=self.activation;builder.received=self.report_root
        builder.canonical=(self.root/gov.CANONICAL).read_bytes();builder.state=json.loads(builder.canonical)
        builder.seal=lambda run:None  # MODEL input construction, no validator is replaced.
        for key in ('preparation_evidence','migration_evidence','activation_evidence'):
            relative=builder.state[key]['evidence_path']
            shutil.copytree((self.root/gov.EVIDENCE/relative).parent,(self.report_root/relative).parent)
        fixture,restore=builder.attempt('resource-qualification')
        snapshot=json.loads((fixture/'snapshot-evidence.json').read_bytes())
        restore['run_id']=self.run.name
        shutil.copyfile(fixture/'fixture-instance.json',self.run/'fixture-instance.json')
        (self.run/'tools-schema.json').write_bytes(canonical(runner.tools_schema_document(self.original_listing.tools)))
        report=self.report
        report.update(fixture_spec_sha256=ev._sha((self.root/'tests/data/p05_fixture_spec.json').read_bytes()),
            fixture_instance_sha256=ev._sha((self.run/'fixture-instance.json').read_bytes()),
            tools_schema_sha256=ev._sha((self.run/'tools-schema.json').read_bytes()),
            server_observation_sha256=ev._sha((self.run/'server-observation.json').read_bytes()),
            source_sha256=ev._sha((self.root/'tests/p06_resource_qualification.py').read_bytes()),
            index_sha256=ev._sha((self.root/'tests/data/p03_invocations.json').read_bytes()),
            authorization_configured=True,started_at=runner.utc_now(),ended_at=runner.utc_now(),duration_ms=1)
        snapshot.update(restore=restore,scenario_id=report['scenario'],source_sha256=report['source_sha256'],
            index_sha256=report['index_sha256'],mcp_session_id=report['mcp_session']['id'],
            server_instance_id=report['server_identity']['instance_id'],server_observation_sha256=report['server_observation_sha256'])
        (self.run/'snapshot-evidence.json').write_bytes(canonical(snapshot))
        report['snapshot_evidence_sha256']=ev._sha((self.run/'snapshot-evidence.json').read_bytes())
        (self.run/'report.json').write_bytes(canonical(report))
        shutil.rmtree(fixture)

    async def test_actual_candidate_package_receive_and_member_gate(self):
        # Existing validated transfer intent is reserved before actual producer.
        request=self.host_request();document=request.document
        (self.run/'maintenance-request.json').unlink()
        (self.report_root/'maintenance-request.json').write_bytes(canonical(document))
        response=next(r for r in self.responses if r.request.method=='DELETE')
        value=await host._complete_candidate(self.admission,self.run,response)
        self.assertEqual(value['status'],'BOUND');self.assertEqual(len(self.original_listing.tools),137)
        from tests import p06_package as package,p06_receive as receive,p06_pc026_binding as binding
        with patch.object(gov,'REPOSITORY',self.root):
            inventory=package.member_inventory(self.run,self.report_root)
            (self.run/'package-manifest.json').write_bytes(canonical(inventory))
            package.verify_manifest(self.run,self.report_root)
            adm=binding.load();adm.report(self.report,self.run,self.report_root)
            receive.receive(self.run,self.report_root)
            sources=package.member_sources(self.run,self.report_root)
            for path in (host.SIDECAR,'archive/cut.json','maintenance/ledger.json'):
                self.assertIn('run/'+path,sources)
        self.preserve(self.run)
        shutil.copytree(self.root,self.evidence/'complete-isolated-input',ignore=shutil.ignore_patterns('__pycache__'),dirs_exist_ok=False)


def load_tests(loader,tests,pattern):
    return loader.loadTestsFromName('CurrentHostHTTP.test_actual_candidate_package_receive_and_member_gate',
        module=__import__(__name__,fromlist=['']))
