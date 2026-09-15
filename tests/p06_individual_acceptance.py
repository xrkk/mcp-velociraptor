"""External formal HTTP inventory and error-contract acceptance, coverage zero."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

from tests import scenario_runner as runner
from tests.p06_formal_session import formal_session
from tests.p06_package import member_inventory, verify_manifest
from tests.p06_receive import receive


def assert_error(result, code, details):
    value = result.structured_content
    if (not result.is_error or result.content or not isinstance(value,dict)
            or set(value)!={'code','message','retryable','details'}
            or value['code']!=code or value['retryable'] is not False
            or value['details']!=details or not isinstance(value['message'],str) or not value['message']):
        raise AssertionError('fixed error contract differs from the reviewed expectation')


async def acceptance(endpoint, token_env):
    root = runner.P06_REPORT_ROOT
    declaration = json.loads((root/'current-restore.json').read_bytes())
    run_id = declaration['run_id']
    restore = runner.load_current_restore(root,run_id)
    if restore['snapshot_stage']!='P06_ACTIVE':
        raise ValueError('individual acceptance requires activated Snapshot188')
    spec_hash = runner.sha256_file(runner.FIXTURE_SPEC_PATH)
    _,fixture_hash = runner.load_fixture({'fixture_spec_sha256':spec_hash},root/'fixture-instance.json')
    run_dir = root/'individual-acceptance'/run_id
    run_dir.mkdir(parents=True,exist_ok=False)
    (run_dir/'fixture-instance.json').write_bytes((root/'fixture-instance.json').read_bytes())
    report = dict(schema_version=2,scenario='individual-acceptance',run_id=run_id,
                  source_sha256=runner.sha256_file(Path(__file__)),index_sha256=runner.sha256_file(runner.P06_INDEX_PATH),
                  fixture_spec_sha256=spec_hash,fixture_instance_sha256=fixture_hash,
                  transport='streamable-http',endpoint=endpoint,authorization_configured=bool(os.environ.get(token_env,'')),
                  tools_schema_sha256=None,snapshot_evidence_sha256=None,
                  mcp_session={'id':None,'initialized_at':None,'closed_at':None},
                  server_identity=None,server_observation_sha256=None,
                  runner={'pid':os.getpid(),'process_start_time_utc':runner._runner_start_time_utc(),
                          'executable_sha256':runner._runner_executable_sha256()},
                  started_at=runner.utc_now(),ended_at=None,duration_ms=0,status='running',
                  calls=[],steps=[],cleanup=[],failure=None,unexecuted_step_ids=[],coverage=[])
    started = time.monotonic()

    async def call(session,label,tool,arguments):
        clock = time.monotonic()
        row = {'sequence':len(report['calls'])+1,'step_id':label,'tool':tool,'arguments':arguments,
               'attempt':1,'started_at':runner.utc_now(),'is_error':True,'structured':None,'mcp_result':None}
        report['calls'].append(row)
        try:
            async with asyncio.timeout(60):
                result = await session.call_tool(tool,arguments)
            row.update(is_error=bool(result.is_error),structured=result.structured_content,
                       mcp_result=result.model_dump(mode='json',by_alias=True,exclude_none=True))
            return result
        except BaseException as exc:
            row['error'] = {'type':type(exc).__name__,'message':str(exc)}
            raise
        finally:
            row.update(ended_at=runner.utc_now(),duration_ms=int((time.monotonic()-clock)*1000))

    try:
        async with formal_session(endpoint,token_env,root/'server-observation.json',run_dir,report) as session:
            listing = await session.list_tools()
            (run_dir/'tools-list-second.json').write_bytes(runner.canonical_bytes(
                listing.model_dump(mode='json',by_alias=True,exclude_none=True)))
            if runner.canonical_bytes(runner.tools_schema_document(listing.tools))!=(run_dir/'tools-schema.json').read_bytes():
                raise AssertionError('tools/list changed within one session')
            invocations = json.loads((ROOT/'tests/data/p03_invocations.json').read_bytes())
            fixed = json.loads((ROOT/'tests/data/p04_fixed_tools_golden.json').read_bytes())
            if {tool.name for tool in listing.tools}!={row['artifact'] for row in invocations}|set(fixed):
                raise AssertionError('tools/list differs from the reviewed 130-tool union')
            cases = (
                ('unknown-flow','get_flow_status',{'flow_id':'F.__p06_missing__'},'NOT_FOUND',
                 {'object_type':'flow','object_id':'F.__p06_missing__'}),
                ('unknown-hunt','get_hunt_status',{'hunt_id':'H.__p06_missing__'},'NOT_FOUND',
                 {'object_type':'hunt','object_id':'H.__p06_missing__'}),
                ('invalid-pid','kill_process',{'pid':0},'INVALID_ARGUMENT',
                 {'field':'pid','reason':'range','minimum':1,'maximum':2147483647}),
                ('hunt-not-allowlisted','start_hunt',{'artifact':'Windows.Not.Approved'},'NOT_FOUND',
                 {'object_type':'artifact','object_id':'Windows.Not.Approved'}),
                ('path-escape','collect_file',{'path':'..\\outside.txt'},'INVALID_ARGUMENT',
                 {'field':'path','reason':'absolute_windows'}),
                ('empty-vql','run_vql',{'query':''},'INVALID_ARGUMENT',{'field':'query','reason':'empty'}),
            )
            for label,tool,arguments,code,details in cases:
                assert_error(await call(session,label,tool,arguments),code,details)
                report['steps'].append({'id':label,'kind':'expected-error','passed':True,'code':code})
            result = await call(session,'terminal-start','Windows.System.PowerShell',
                                {'Command':'exit 0','Timeout':30,'Stateful':False})
            if result.is_error:
                raise AssertionError('terminal probe could not start')
            flow = result.structured_content['flow_id']
            async with asyncio.timeout(180):
                while True:
                    status = await call(session,'terminal-wait','get_flow_status',{'flow_id':flow})
                    value = status.structured_content
                    if status.is_error or value['flow_id']!=flow or value['state']=='ERROR':
                        raise AssertionError('terminal probe failed or changed Flow identity')
                    if value['state']=='FINISHED':
                        break
                    await asyncio.sleep(1)
            assert_error(await call(session,'terminal-cancel','cancel_flow',{'flow_id':flow}),
                         'NOT_CANCELLABLE',{'object_type':'flow','state':'FINISHED'})
            assert_error(await call(session,'unknown-file','download_flow_file',{'flow_id':flow,'file_id':'0'*64}),
                         'NOT_FOUND',{'object_type':'flow_file','object_id':'0'*64})
            report['steps'].extend([{'id':name,'kind':'expected-error','passed':True}
                                    for name in ('terminal-cancel','unknown-file')])
        report['status'] = 'success'
    except BaseException as exc:
        report['status'] = 'failed'
        report['failure'] = {'type':type(exc).__name__,'message':str(exc),'chain':runner._exception_chain(exc)}
        if not isinstance(exc,Exception):
            raise
    finally:
        report.update(ended_at=runner.utc_now(),duration_ms=int((time.monotonic()-started)*1000))
        snapshot = {'restore':restore,'scenario_id':report['scenario'],'source_sha256':report['source_sha256'],
                    'index_sha256':report['index_sha256'],'mcp_session_id':report['mcp_session']['id'],
                    'server_instance_id':(report['server_identity'] or {}).get('instance_id'),
                    'server_observation_sha256':report['server_observation_sha256']}
        (run_dir/'snapshot-evidence.json').write_bytes(runner.canonical_bytes(snapshot))
        report['snapshot_evidence_sha256'] = runner.sha256_file(run_dir/'snapshot-evidence.json')
        (run_dir/'report.json').write_bytes(runner.canonical_bytes(report))
        (run_dir/'package-manifest.json').write_bytes(runner.canonical_bytes(member_inventory(run_dir,root)))
        verify_manifest(run_dir,root)
        receive(run_dir,root)
    return report,run_dir


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--endpoint',required=True)
    parser.add_argument('--token-env',default='VELOCIRAPTOR_MCP_BEARER_TOKEN')
    args = parser.parse_args()
    report,path = asyncio.run(acceptance(args.endpoint,args.token_env))
    print(json.dumps({'status':report['status'],'report':str(path/'report.json')}))
    return 0 if report['status']=='success' else 1


if __name__=='__main__':
    raise SystemExit(main())
