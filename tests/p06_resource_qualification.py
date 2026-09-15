"""External HTTP P06 qualification; Windows observations are control-plane only."""
from __future__ import annotations

import argparse
import asyncio
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import sys
import time
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
INVOCATIONS = REPO_ROOT / 'tests' / 'data' / 'p03_invocations.json'
DATASTORE = Path(r'C:\VelociraptorMCP\datastore')
DOWNLOAD_ROOT = Path(os.environ.get('VELOCIRAPTOR_DOWNLOAD_ROOT', r'C:\VelociraptorMCP\downloads'))
OUT = REPO_ROOT / 'Logs' / 'P06' / 'wf-01a05d1d-p06-r3'


class MemoryStatusEx(ctypes.Structure):
    _fields_ = [('length', ctypes.c_ulong), ('memory_load', ctypes.c_ulong)] + [
        (name, ctypes.c_ulonglong) for name in (
            'total_physical', 'available_physical', 'total_page_file', 'available_page_file',
            'total_virtual', 'available_virtual', 'available_extended_virtual')]


def tree_bytes(path):
    if not path.is_dir() or path.is_symlink():
        raise ValueError('resource root must exist and be a plain directory')
    def fail(error):
        raise error
    total = 0
    for base, directories, files in os.walk(path, onerror=fail):
        for name in directories + files:
            candidate = Path(base) / name
            info = candidate.lstat()
            if candidate.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise ValueError('resource tree contains a link or reparse point')
            if name in files:
                total += info.st_size
    return total


def resources():
    """Executed only in the guest by the fixed read-only management observation."""
    if os.name != 'nt':
        raise RuntimeError('guest resource collection requires Windows')
    state = MemoryStatusEx()
    state.length = ctypes.sizeof(state)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(state)):
        raise ctypes.WinError()
    disk = shutil.disk_usage('C:\\')
    return {'physical_memory_bytes': int(state.total_physical),
            'available_memory_bytes': int(state.available_physical),
            'c_total_bytes': disk.total, 'c_free_bytes': disk.free,
            'datastore_bytes': tree_bytes(DATASTORE),
            'download_root_bytes': tree_bytes(DOWNLOAD_ROOT), 'report_root_bytes': tree_bytes(OUT)}


def prepare_download_root(path):
    if not path.is_absolute():
        raise ValueError('P06 download root must be absolute')
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir() or path.is_symlink():
        raise ValueError('P06 download root must be a plain directory')



async def call(session, report, step_id, tool, arguments):
    from tests.scenario_runner import utc_now
    started_at, started = utc_now(), time.monotonic()
    row = {'sequence': len(report['calls'])+1, 'step_id': step_id, 'tool': tool,
           'arguments': arguments,
           'attempt': 1+sum(item['step_id']==step_id for item in report['calls']),
           'started_at': started_at, 'is_error': True, 'structured': None, 'mcp_result': None}
    report['calls'].append(row)
    try:
        result = await session.call_tool(tool, arguments)
        row.update(is_error=bool(result.is_error), structured=result.structured_content,
                   mcp_result=result.model_dump(mode='json', by_alias=True, exclude_none=True))
    except BaseException as exc:
        row['error'] = {'type': type(exc).__name__, 'message': str(exc)}
        raise
    finally:
        row.update(ended_at=utc_now(), duration_ms=math.ceil((time.monotonic()-started)*1000))
    if result.is_error:
        raise RuntimeError(f'qualification tool failed: {tool}')
    return result.structured_content


async def run_flow(session, report, sampler, label, tool, arguments, timeout):
    from tests.p06_resource_gate import admit, ResourceRejected, require_trace_inactive
    before = await sampler.sample(label+'-before')
    if label=='packet-start':
        require_trace_inactive(before)
    row = {'id': label, 'tool': tool, 'kind': 'resource-qualification', 'passed': False,
           'before': before, 'samples': [], 'previous_upper_seconds': timeout}
    report['steps'].append(row)
    try:
        row['admission'] = admit(before['reading'], remaining_increment=0, evidence_reserve=0,
                                 static=tool == 'Windows.Memory.Acquisition')
    except ResourceRejected as exc:
        row['admission'] = exc.evidence
        raise
    started = time.monotonic()
    async with asyncio.timeout(timeout):
        created = await call(session, report, label, tool, arguments)
        flow_id = created.get('flow_id')
        if not isinstance(flow_id, str) or not flow_id.startswith('F.'):
            raise ValueError('qualification returned invalid flow identity')
        row['flow_id'] = flow_id
        while True:
            status = await call(session, report, label+'-wait', 'get_flow_status', {'flow_id': flow_id})
            row['samples'].append(await sampler.sample(label+'-poll'))
            if status.get('flow_id') != flow_id:
                raise ValueError('qualification flow identity changed')
            if status.get('state') == 'FINISHED':
                break
            if status.get('state') == 'ERROR':
                raise RuntimeError('qualification flow reached ERROR')
            await asyncio.sleep(5)
        results = await call(session, report, label+'-results', 'get_flow_results', {'flow_id': flow_id, 'page_size': 1})
        files = await call(session, report, label+'-files', 'list_flow_files', {'flow_id': flow_id})
        # P04 result/file models intentionally do not echo flow_id. Bind their
        # retained wire arguments to the owned Flow, not to an invented field.
        for value, operation in ((results,'get_flow_results'),(files,'list_flow_files')):
            if value.get('operation')!=operation or value.get('status')!='success' or not isinstance(value.get('data'),list):
                raise ValueError('qualification result/file response violates the frozen P04 model')
        if any(call_row['arguments'].get('flow_id')!=flow_id for call_row in report['calls'][-2:]):
            raise ValueError('qualification result/file requests changed flow')
    row['after'] = await sampler.sample(label+'-after')
    if label=='packet-stop':
        require_trace_inactive(row['after'])
    row['elapsed_seconds'] = time.monotonic()-started
    readings = [before, *row['samples'], row['after']]
    row['peak_increment_bytes'] = max(0, before['reading']['c_free_bytes']-min(x['reading']['c_free_bytes'] for x in readings))
    row['retained_increment_bytes'] = max(0, before['reading']['c_free_bytes']-row['after']['reading']['c_free_bytes'])
    row['passed'] = True
    return results, files, flow_id


async def qualify(endpoint, token_env):
    from tests import scenario_runner as runner
    from tests.p06_formal_session import formal_session
    from tests.p06_resource_gate import GuestResourceSampler, admit, freeze_measurements, ResourceRejected, require_trace_inactive
    from tests.p06_package import member_inventory, source_for_member, verify_manifest, verify_payload_zip
    evidence_root = OUT
    declaration = json.loads((evidence_root/'current-restore.json').read_text(encoding='utf-8'))
    run_id = declaration['run_id']
    restore = runner.load_current_restore(evidence_root, run_id)
    if restore['snapshot_stage'] != 'P06_ACTIVE':
        raise ValueError('qualification requires activated Snapshot188')
    spec_hash = runner.sha256_file(runner.FIXTURE_SPEC_PATH)
    fixture, fixture_hash = runner.load_fixture({'fixture_spec_sha256': spec_hash}, evidence_root/'fixture-instance.json')
    run_dir = runner.P06_REPORT_ROOT/'resource-qualification'/run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    (run_dir/'fixture-instance.json').write_bytes((evidence_root/'fixture-instance.json').read_bytes())
    source_hash, index_hash = runner.sha256_file(Path(__file__)), runner.sha256_file(INVOCATIONS)
    report = dict(schema_version=2, scenario='resource-qualification', source_sha256=source_hash,
                  index_sha256=index_hash, fixture_spec_sha256=spec_hash, fixture_instance_sha256=fixture_hash,
                  run_id=run_id, transport='streamable-http', endpoint=endpoint,
                  authorization_configured=bool(os.environ.get(token_env, '').strip()),
                  tools_schema_sha256=None, snapshot_evidence_sha256=None,
                  mcp_session={'id': None, 'initialized_at': None, 'closed_at': None},
                  server_identity=None, server_observation_sha256=None,
                  runner={'pid': os.getpid(), 'process_start_time_utc': runner._runner_start_time_utc(),
                          'executable_sha256': runner._runner_executable_sha256()},
                  started_at=runner.utc_now(), ended_at=None, duration_ms=0, status='running',
                  calls=[], steps=[], cleanup=[], failure=None, unexecuted_step_ids=[], coverage=[])
    invocations = [row for row in json.loads(INVOCATIONS.read_text(encoding='utf-8'))
                   if row['risk_class']=='resource_sensitive' and row['artifact']!='Windows.Network.PacketCapture']
    started = time.monotonic()
    report['steps'].append({'id':'implementation-identity','kind':'source-identity',
                            'files':{name:runner.sha256_file(REPO_ROOT/'tests'/name) for name in
                                     ('scenario_runner.py','p06_resource_gate.py','p06_formal_session.py',
                                      'p06_resource_qualification.py','p06_package.py','p06_evidence.py','p06_resource_policy.py',
                                      'p06_receive.py','p06_aggregate_reports.py','data/p06_scenario_index.json',
                                      'data/p06_resource_policy.json','data/p03_invocations.json')}})
    try:
        if len(invocations) != 8:
            raise ValueError('qualification must include all eight in-scope resource-sensitive invocations')
        async with formal_session(endpoint, token_env, evidence_root/'server-observation.json', run_dir, report) as session:
            sampler = GuestResourceSampler(endpoint, run_id, report['server_identity'], run_dir/'resources')
            before = await sampler.sample('qualification-start')
            require_trace_inactive(before)
            initial = {'id': 'static-resource-gate', 'kind': 'resource-gate', 'observation': before}
            report['steps'].append(initial)
            try:
                initial['admission'] = admit(before['reading'], remaining_increment=0, evidence_reserve=0, static=True)
            except ResourceRejected as exc:
                initial['admission'] = exc.evidence
                raise
            for invocation in invocations:
                tool = invocation['artifact']
                # PLAN-CHANGE-014: PacketCapture chain excluded from qualification.
                await run_flow(session, report, sampler, tool, tool, invocation['parameters'],
                               3600 if tool=='Windows.Memory.Acquisition' else 1200)
            await run_flow(session, report, sampler, 'forensic-triage', 'collect_forensic_triage', {}, 2400)
            _, files, flow_id = await run_flow(session, report, sampler, 'fixture-file', 'collect_file',
                                              {'path': fixture['files'][0]['path']}, 300)
            if not files['data']:
                raise ValueError('fixture collection has no downloadable file')
            before = await sampler.sample('download-before')
            download = {'id':'download', 'tool':'download_flow_file', 'kind':'resource-qualification',
                        'before':before, 'previous_upper_seconds':300, 'passed':False}
            report['steps'].append(download)
            try:
                download['admission'] = admit(before['reading'], remaining_increment=0, evidence_reserve=0)
            except ResourceRejected as exc:
                download['admission'] = exc.evidence
                raise
            clock = time.monotonic()
            async with asyncio.timeout(300):
                await call(session, report, 'download', 'download_flow_file', {'flow_id':flow_id,'file_id':files['data'][0]['file_id']})
            after = await sampler.sample('download-after')
            increment = max(0,before['reading']['c_free_bytes']-after['reading']['c_free_bytes'])
            download.update(after=after, elapsed_seconds=time.monotonic()-clock, passed=True,
                            peak_increment_bytes=increment, retained_increment_bytes=increment)
            admit(after['reading'], remaining_increment=0, evidence_reserve=0)
        report['status'] = 'success'
    except Exception as exc:
        report['status'] = 'failed'
        report['failure'] = {'type':type(exc).__name__,'message':str(exc),'chain':runner._exception_chain(exc)}
    finally:
        report['ended_at'], report['duration_ms'] = runner.utc_now(), math.ceil((time.monotonic()-started)*1000)
        snapshot = {'restore':restore,'scenario_id':report['scenario'],'source_sha256':source_hash,
                    'index_sha256':index_hash,'mcp_session_id':report['mcp_session']['id'],
                    'server_instance_id':(report['server_identity'] or {}).get('instance_id'),
                    'server_observation_sha256':report['server_observation_sha256']}
        raw = runner.canonical_bytes(snapshot)
        (run_dir/'snapshot-evidence.json').write_bytes(raw)
        report['snapshot_evidence_sha256'] = hashlib.sha256(raw).hexdigest()
        (run_dir/'report.json').write_bytes(runner.canonical_bytes(report))
    if report['status']=='success':
        # Measured payload precedes the budget, avoiding hash/size self-reference.
        manifest = member_inventory(run_dir, evidence_root, payload=True)
        (run_dir/'qualification-payload-manifest.json').write_bytes(runner.canonical_bytes(manifest))
        with zipfile.ZipFile(run_dir/'qualification-payload.zip','x',zipfile.ZIP_STORED) as archive:
            archive.write(run_dir/'qualification-payload-manifest.json','qualification-payload-manifest.json')
            for member in manifest['members']:
                archive.write(source_for_member(run_dir, evidence_root, member['path']), member['path'])
        budget = {'schema_version':1,'report_sha256':runner.sha256_file(run_dir/'report.json'),
                  **verify_payload_zip(run_dir,evidence_root),
                  **freeze_measurements(report)}
        (run_dir/'resource-budget.json').write_bytes(runner.canonical_bytes(budget))
    (run_dir/'package-manifest.json').write_bytes(runner.canonical_bytes(member_inventory(run_dir,evidence_root)))
    verify_manifest(run_dir,evidence_root)
    from tests.p06_receive import receive
    receive(run_dir,evidence_root)
    return report,run_dir


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--endpoint',required=True)
    parser.add_argument('--token-env',default='VELOCIRAPTOR_MCP_BEARER_TOKEN')
    args=parser.parse_args()
    report,path=asyncio.run(qualify(args.endpoint,args.token_env))
    print(json.dumps({'status':report['status'],'report':str(path/'report.json')}))
    return 0 if report['status']=='success' else 1


if __name__=='__main__':
    raise SystemExit(main())
