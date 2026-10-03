"""Modeled wire originals for new isolated 191 fixtures, never real captures."""
import json
import shutil
from pathlib import Path
from mcp.types import CallToolResult, ListToolsResult
from tests import p06_http_body_capture as capture, p06_mcp_raw_join as raw, p06_http_binding as binding
from tests import p05_pc026_governance as gov, p06_pc026_binding as governed


def prepare(run, report):
    listing=ListToolsResult.model_validate(json.loads((run/'tools-list.json').read_bytes()))
    (run/'tools-list.json').write_bytes(capture.canonical(listing.model_dump(mode='json',by_alias=True,exclude_none=True)))
    for call in report['calls']:
        value=call.get('mcp_result') or {'content':[],'isError':call['is_error'],'structuredContent':call['structured']}
        call['mcp_result']=CallToolResult.model_validate(value).model_dump(mode='json',by_alias=True,exclude_none=True)


def construct(run):
    # Rebuilding is authorized only in synthetic fixture sealing, not runners.
    path=run/'raw-mcp'
    if path.exists():shutil.rmtree(path)
    path.mkdir()
    report=json.loads((run/'report.json').read_bytes());rows=[];headers=[]
    session=report['mcp_session']['id'];instance=report['server_identity']['instance_id']
    def exchange(request,response):
        seq=len(rows)+1
        refs={}
        for direction,body in [('request',request),('response',response)]:
            name=f'exchange-{seq:08d}-{direction}.bin';data=raw.canonical(body);(path/name).write_bytes(data)
            refs[direction]=binding.ref(name,data)
        rows.append(dict(sequence=seq,method='POST',request_ref=refs['request'],request_end='eof',response_ref=refs['response'],response_end='eof',response_status=200,response_content_type='application/json',response_content_encoding='',error=None))
        headers.append(dict(exchange_sequence=seq,method='POST',path='/mcp',status_code=200,mcp_session_id=session if seq==1 else None,
            request_session_id=None if seq==1 else session,server_instance_id=instance))
    def rpc(id,method,params,result):
        exchange({'jsonrpc':'2.0','id':id,'method':method,'params':params},{'jsonrpc':'2.0','id':id,'result':result})
    rpc(0,'initialize',{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'synthetic191','version':'1'}},
        {'protocolVersion':'2025-11-25','capabilities':{},'serverInfo':{'name':'synthetic191','version':'1'}})
    rpc(1,'tools/list',{},json.loads((run/'tools-list.json').read_bytes()))
    for i,call in enumerate(report['calls'],2):rpc(i,'tools/call',{'name':call['tool'],'arguments':call['arguments']},call['mcp_result'])
    (path/'capture.json').write_bytes(capture.canonical(dict(schema_version=1,kind=capture.KIND,run_id=report['run_id'],exchanges=rows,status='RECORDED',failure=None)))
    (run/'http-headers.json').write_bytes(capture.canonical(headers))
    for name in (binding.JOIN,binding.BINDING):(run/name).unlink(missing_ok=True)
    group=gov.GovernedGroup(Path.cwd(),{}, {},{}, {},{}, {},True)
    binding.publish(governed.Admission(group,b'',None),run)
