"""Finite failure diagnostics from actual raw originals; never a success gate.

Attempt numbers require independently authorized, fully verified source records.
Missing or ambiguous evidence remains unclassified, without invented accepts.
"""
from __future__ import annotations
from collections import Counter
from pathlib import Path

from velociraptor_observation_cut import canonical,ref,_require
from velociraptor_observation_maintenance import _json

FILE='mcp-observation-failure.json'
GATES={
    (401,'unauthorized'):'AUTH',(421,'bad_host'):'HOST',(403,'origin_denied'):'ORIGIN',
    (413,'body_budget'):'BODY',(413,'body_too_large'):'BODY',
    (400,'protocol'):'PROTOCOL',(400,'unsupported_protocol'):'PROTOCOL',(400,'invalid_protocol'):'PROTOCOL',
    (400,'invalid_frame'):'INVALID_REQUEST',(400,'session_required'):'SESSION',
    (404,'session_not_found'):'SESSION',(409,'closing'):'CLOSING',
    (503,'draining'):'DRAINING',
}


def _messages(reader,exchange,direction):
    """Parse finite actual bodies, including recorded HTTP rejection bodies."""
    from tests import p06_mcp_raw_join as raw
    original=exchange[direction+'_ref']
    if original is None:return []
    data=reader.read(original['path'],raw=True)
    if not data:return []
    if exchange[direction+'_end'] not in {'eof','closed'}:return []
    try:
        if direction=='response' and exchange['response_content_type'].split(';')[0]=='text/event-stream':
            values=list(raw.sse(raw.decoded([data],exchange['response_content_encoding'])))
        else:values=[raw.strict_json(data)]
    except (ValueError,TypeError,UnicodeError):return []
    return [(value,dict(exchange_sequence=exchange['sequence'],direction=direction,
        frame_index=n,body_ref=original)) for n,value in enumerate(values,1)]


def _classify(index,reader,headers,records,report):
    """Private pure derivation; records are supplied only after source validation."""
    from tests import p06_mcp_raw_join as raw
    begins={};acks=set();ends={}
    for record in records:
        p=record['payload'];kind=record['record_type']
        if kind=='ATTEMPT_BEGIN':begins[p['attempt_sequence']]=p
        elif kind=='ACCEPT_ACK':acks.add(p['attempt_sequence'])
        elif kind=='ATTEMPT_END':ends[p['attempt_sequence']]=p
    requests=[];responses={}
    for exchange in index['exchanges']:
        messages=_messages(reader,exchange,'request')
        if not messages and exchange['request_ref'] is not None:
            messages=[(None,dict(exchange_sequence=exchange['sequence'],direction='request',
                frame_index=1,body_ref=exchange['request_ref']))]
        for message,location in messages:requests.append((exchange,message,location))
        responses[exchange['sequence']]=_messages(reader,exchange,'response')
    identities=[]
    for exchange,message,_ in requests:
        sid=None
        entries=[h for h in headers if h.get('exchange_sequence')==exchange['sequence']]
        if len(entries)==1:
            values=[v for k,v in entries[0]['headers'] if k.lower()=='mcp-session-id']
            if len(values)==1:sid=values[0]
        rid=message.get('id') if isinstance(message,dict) else None
        identity=(sid,'integer' if type(rid) is int else 'string' if type(rid) is str else None,rid)
        identities.append(identity)
    counts=Counter(identities);rows=[]
    for (exchange,message,location),identity in zip(requests,identities):
        classification=reason='UNCLASSIFIED';sequences=[]
        replies=responses[exchange['sequence']]
        error=replies[0][0].get('error') if len(replies)==1 and isinstance(replies[0][0],dict) else None
        code=error.get('code') if isinstance(error,dict) else None
        gate=GATES.get((exchange['response_status'],code))
        if gate is not None:
            classification='PRE_OBSERVER_REJECT';reason=gate
        elif exchange['method']=='DELETE' and (exchange['response_status']!=200 or exchange['response_end']!='eof'):
            classification='ACCEPT_UNKNOWN';reason='CLOSE_UNKNOWN'
        elif isinstance(message,dict) and message.get('method')=='tools/call' and identity[0] is not None:
            params=message.get('params',{});candidates=[]
            for n,begin in begins.items():
                key=begin['key']
                if (key['session_id'],key['request_id_type'],key['request_id'])==identity and key['instance_id']==(report.get('server_identity') or {}).get('instance_id'):
                    if begin['tool']==params.get('name') and begin['arguments_sha256']==raw.digest(params.get('arguments',{})):
                        candidates.append((n,begin))
            # Raw start order alone does not prove sequential execution.
            # A unique actual rejection versus a unique actual result can
            # disambiguate one NEW and one REJECTED; repetitions stay unknown.
            if counts[identity]>1:
                rejected=isinstance(error,dict) and error.get('message') in {
                    'DUPLICATE','ACTIVE_LIMIT','SEEN_LIMIT','BYTE_LIMIT'}
                response_result=any(isinstance(v,dict) and 'result' in v for v,_ in replies)
                if rejected:
                    candidates=[item for item in candidates if item[1]['decision']=='REJECTED'
                        and item[1]['reason']==error['message']]
                elif response_result:candidates=[item for item in candidates if item[1]['decision']=='NEW']
                else:candidates=[]
                relevant=[]
                for other,ident in zip(requests,identities):
                    if ident!=identity:continue
                    values=responses[other[0]['sequence']]
                    e=values[0][0].get('error') if len(values)==1 and isinstance(values[0][0],dict) else None
                    if rejected and isinstance(e,dict) and e.get('message')==error['message']:relevant.append(other)
                    elif not rejected and any(isinstance(v,dict) and 'result' in v for v,_ in values):relevant.append(other)
                if len(relevant)!=1:candidates=[]
            if len(candidates)==1:
                n,begin=candidates[0];end=ends.get(n)
                if begin['decision']=='REJECTED' and end is not None and end['disposition']=='REJECTED':
                    reason=begin['reason']
                    classification='DUPLICATE_REJECT' if reason=='DUPLICATE' else 'PRE_OBSERVER_REJECT'
                    sequences=[n]
                elif n not in acks:
                    classification='ACCEPT_UNKNOWN';reason='ACK_UNKNOWN';sequences=[n]
                elif end is None:
                    classification='ACCEPT_UNKNOWN';reason='JOURNAL_UNKNOWN';sequences=[n]
                elif end['disposition']=='FAILED' or end.get('outcome') in {'raised','cancelled'}:
                    classification='ACCEPTED_FAILED'
                    reason='INVALID_REQUEST' if code in {-32600,-32602} else 'UNCLASSIFIED'
                    sequences=[n]
                elif end['disposition']=='COMPLETE' and (exchange['error'] is not None or exchange['response_end']!='eof'
                        or exchange['response_status']!=200 or error is not None):
                    classification='ACCEPTED_COMPLETE_WITH_WIRE_ERROR';reason='WIRE_ERROR';sequences=[n]
        rows.append(dict(location=location,classification=classification,reason=reason,attempt_sequences=sequences))
    for call in report.get('calls',[]):
        if isinstance(call.get('monotonic'),dict) and call['monotonic'].get('invoked') is False:
            _require(type(call['sequence']) is int and call['sequence']>0,'failure_report_sequence')
            rows.append(dict(location=dict(report_call_sequence=call['sequence']),classification='NOT_INVOKED',
                reason='NOT_INVOKED',attempt_sequences=[]))
    _require(len({canonical(row['location']) for row in rows})==len(rows),'failure_location_duplicate')
    return dict(schema_version=1,kind='pc026-observation-failure-v1',run_id=report['run_id'],
        capture_ref=ref('raw-mcp/capture.json',reader.read('capture.json',raw=True)),rows=rows,status='FAILED')


def derive(admission,run_dir):
    from tests.p06_pc026_binding import Admission
    from tests.p05_pc026_governance import GovernedGroup
    from tests import scenario_runner,p06_http_binding as http,p06_http_body_capture as capture
    from velociraptor_observation_config import _configuration,_budgets
    from velociraptor_observation_startup import _precheck_loaded
    from velociraptor_observation_maintenance import _read_authority,_verify_export
    from velo_transfer.errors import TransferContentError
    run=Path(run_dir)
    _require(type(admission) is Admission and type(admission.group) is GovernedGroup,'failure_admission')
    admission.recheck();configuration=_configuration(admission.group);_precheck_loaded(configuration)
    _require(run.is_relative_to(scenario_runner.P06_REPORT_ROOT),'failure_run_root')
    report=_json(admission.read(run/'report.json'))
    _require(report['status']=='failed' and report['coverage']==[] and report['run_id']==run.name
        and report['scenario']==run.parent.name,'failure_report_binding')
    reader=http._AdmissionReader(admission,run);index=capture.verify(run,run.name,_reader=reader)
    headers=_json(admission.read(run/'request-headers.json'));records=[]
    # Only a complete authorized source can establish known attempt numbers.
    # Missing source evidence is diagnostic uncertainty, never an invented ACK.
    try:
        context,request=_read_authority(admission,run);files=_verify_export(context,request,context['descriptor'])
        _,codec=_budgets(context['archive']['budgets']);projection=_json(files['attempts.json'])
        records=[codec.parse(files[r['path']]) for r in projection['catalog_prefix']]
    except (ValueError,OSError,KeyError,TypeError,TransferContentError):pass
    value=_classify(index,reader,headers,records,report);admission.recheck();return value


def publish(admission,run_dir):
    from tests.p06_http_binding import _exclusive
    value=derive(admission,run_dir)
    _exclusive(run_dir,FILE,value)
    _require(admission.read(Path(run_dir)/FILE)==canonical(derive(admission,run_dir)),'failure_readback')
    return value
