"""Fixed current P06 raw/session binding; no admission bypass or production CLI."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
from mcp.types import ListToolsResult
from tests import p06_http_body_capture as capture, p06_mcp_raw_join as raw

KIND = 'pc026-p06-http-binding-v1'
JOIN = 'mcp-raw-join.json'
BINDING = 'mcp-http-binding.json'
HEADER_KEYS = {'method','path','status_code','mcp_session_id','server_instance_id',
               'request_session_id','exchange_sequence'}


class _AdmissionReader:
    """All content goes through the original governed security reader."""
    def __init__(self, admission, run):
        self.admission, self.run = admission, Path(run)

    def path(self, name, original=False):
        raw.require(isinstance(name,str) and Path(name).name == name and name not in {'.','..'},
                    'binding file name unsafe')
        return self.run / ('raw-mcp' if original else '') / name

    def chunks(self, name, ref=None, *, raw=False):
        digest=hashlib.sha256();size=0
        for chunk in self.admission.group.stream_path(self.path(name,raw)):
            digest.update(chunk);size+=len(chunk);yield chunk
        if ref is not None:
            require({'path':name,'size':size,'sha256':digest.hexdigest()} == ref,'body Ref drift')

    def read(self, name, *, raw=False):
        return self.admission.read(self.path(name,raw))

    def recheck(self): self.admission.recheck()


def require(condition,message): raw.require(condition,message)


def ref(name,data):
    return {'path':name,'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}


def _derive(run, reader):
    joined=raw.join(run,_reader=reader)
    index=capture.verify(run,_reader=reader)
    report_raw=reader.read('report.json');report=raw.strict_json(report_raw)
    headers_raw=reader.read('http-headers.json');headers=capture._json(headers_raw)
    require(isinstance(headers,list),'headers array required')
    init=[]; listings=[]
    for row in index['exchanges']:
        for value,loc in raw.messages(reader,row,'request'):
            kind,key=raw.envelope(value,'request')
            if kind=='notification':continue
            if value['method']=='initialize':init.append(loc['exchange_sequence'])
            if value['method']=='tools/list':listings.append(key)
    require(len(init)==1 and len(listings)==1,'current binding needs one initialize and one tools/list')
    listed=None
    for row in index['exchanges']:
        for value,_ in raw.messages(reader,row,'response'):
            kind,key=raw.envelope(value,'response')
            if kind=='response' and key==listings[0]:listed=raw.sdk(ListToolsResult,value['result'])
    require(raw.canonical(listed)==raw.canonical(raw.strict_json(reader.read('tools-list.json'))),
            'raw tools/list differs from actual tools-list.json')
    by_seq={}
    for row in headers:
        require(isinstance(row,dict) and set(row)==HEADER_KEYS,'current header exact fields differ')
        seq=row['exchange_sequence']
        require(type(seq) is int and seq>0 and seq not in by_seq,'header sequence duplicate/invalid')
        by_seq[seq]=row
    exchanges={r['sequence']:r for r in index['exchanges'] if r['response_status'] is not None}
    require(set(by_seq)==set(exchanges),'headers/capture exchange coverage differs')
    session=report['mcp_session']['id'];instance=report['server_identity']['instance_id']
    require(isinstance(session,str) and session and isinstance(instance,str) and instance,
            'live session/instance missing')
    for seq,exchange in exchanges.items():
        header=by_seq[seq]
        require(header['method']==exchange['method'] and type(header['status_code']) is int
                and header['status_code']==exchange['response_status'] and header['path']=='/mcp',
                'header method/status/path binding differs')
        require(200<=header['status_code']<300,'non-success HTTP binding')
        require(header['server_instance_id']==instance,'HTTP instance differs')
        require(header['mcp_session_id'] is None or header['mcp_session_id']==session,'HTTP response session differs')
        if seq==init[0]:
            require(header['request_session_id'] is None and header['mcp_session_id']==session,
                    'initialize actual session binding differs')
        else:
            require(seq>init[0] and header['request_session_id']==session,'HTTP request session/lifecycle differs')
    capture_raw=reader.read('capture.json',raw=True)
    binding=dict(schema_version=1,kind=KIND,run_id=report['run_id'],report_ref=ref('report.json',report_raw),
        capture_ref=ref('raw-mcp/capture.json',capture_raw),headers_ref=ref('http-headers.json',headers_raw),
        join_ref=ref(JOIN,capture.canonical(joined)),status='BOUND')
    reader.recheck()
    return joined,binding


def validate(admission, run):
    reader=_AdmissionReader(admission,run)
    joined,binding=_derive(run,reader)
    require(reader.read(JOIN)==capture.canonical(joined),'saved raw join differs from recomputation')
    require(reader.read(BINDING)==capture.canonical(binding),'saved HTTP binding differs from recomputation')
    reader.recheck()
    return binding


def _exclusive(run, name, value):
    directory=capture._Directory(run)
    try:
        fd=directory.open(name,os.O_CREAT|os.O_EXCL|os.O_WRONLY)
        try:
            view=memoryview(capture.canonical(value))
            while view:
                count=os.write(fd,view)
                if count<=0:raise OSError('binding publication made no progress')
                view=view[count:]
            os.fsync(fd)
        finally:os.close(fd)
        directory.check()
    finally:directory.close()


def publish(admission,run):
    admission.recheck()
    joined,binding=_derive(run,_AdmissionReader(admission,run))
    admission.recheck();_exclusive(run,JOIN,joined)
    admission.recheck();_exclusive(run,BINDING,binding)
    return validate(admission,run)


def initialized_header(body_capture, headers):
    """Live initialization comes from its recorded request, not completion order."""
    sequences=[]
    for row in body_capture.rows:
        if row['method']!='POST' or row['request_ref'] is None:continue
        require(row['request_end']=='eof','initialization request incomplete')
        fd=body_capture.directory.open(row['request_ref']['path'],os.O_RDONLY)
        try:
            chunks=[]
            while part:=os.read(fd,65536):chunks.append(part)
            message=raw.strict_json(b''.join(chunks))
        finally:os.close(fd)
        if message.get('method')=='initialize':sequences.append(row['sequence'])
    require(len(sequences)==1,'unique live initialize request missing')
    rows=[r for r in headers if r['exchange_sequence']==sequences[0]]
    require(len(rows)==1 and rows[0]['request_session_id'] is None
            and rows[0]['mcp_session_id'] and rows[0]['server_instance_id'],
            'live initialize header missing/ambiguous')
    return rows[0]
