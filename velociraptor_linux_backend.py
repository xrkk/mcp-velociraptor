"""Bounded guest-local Linux triage through the real Velociraptor CLI API.

No listener, model, arbitrary VQL interface, or high-granularity scope control.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid

from velociraptor_linux_domain import LinuxDomainError, LinuxPlatformRouter

PINNED_VERSION = '0.77.3'
BINARY_SHA = '93171158fa081c07e3dd6b2cfc194f1a1db3eb30861639ad16eae6092afa42f7'
ARTIFACT_HASHES = {
    'Generic.Client.Info': '9f194fcca7f4c1d9c62e5a956dddaf33d02af069ae808ddc08ec6035cf261877',
    'Linux.Sys.Users': '8cb669ffa32e2c98562b23116df4ed2b7e22bc40bd4ef89cc9c696224cdd517e',
    'Linux.Sys.Pslist': '6d5fea761db18afe7934597ddeb0d5920d758f52d15f1c81f5f67de82dfa404a',
    'Linux.Network.Netstat': '790adddf8a71b664a7d8204c76eeaa9fd7419055996b986787c1e8ccc3ce42ef',
    'Linux.Sys.Services': '475332b2b5edae99585c5d1ebf746a202639d1a298f5ef17dc8c83490a0dc555',
    'Linux.Sys.Crontab': 'c055b91c872adf9d47938942bede3edb56d138deef149ebc1892004a1f8c8da6',
    'Linux.Forensics.Journal': '4a23362a50fb1b4b179438b72cc51c2f7f7e1bb5a9c1e5082869cb6895266e7b',
    'Linux.Search.FileFinder': '52429c5bb8919bdbae5938f0382d73bf58be91a0aafd2e0ac2d46578a20af5ba',
    'Generic.Collectors.File': 'c61bde39247b56069dbf4b9744035d589f6edd484b2180ca41abc37434d575fd',
}
REQUIRED_CATEGORIES = ('process', 'file', 'network', 'persistence', 'logs', 'metadata', 'acquisition')
LIMITATIONS = ['snapshot facts, not realtime fork/exec or file-change telemetry',
               'high-granularity scope effects and causality are not implemented here',
               'empty optional artifact sources remain explicit; no Windows endpoint was collected']


def require(ok, code):
    if not ok:
        raise LinuxDomainError(code, code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def literal(value):
    return json.dumps(value, ensure_ascii=True)


def parse_arrays(data):
    text = data.decode('utf-8'); decoder = json.JSONDecoder(); rows = []
    while text.strip():
        text = text.lstrip(); value, end = decoder.raw_decode(text); text = text[end:]
        require(isinstance(value, list) and all(isinstance(x, dict) for x in value), 'API_FORMAT')
        rows.extend(value)
    return rows


def private_path(path, directory=False):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, 'UNSAFE_PATH')
    for parent in [*path.parents, path]:
        st = parent.lstat()
        require(not stat.S_ISLNK(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022, 'UNSAFE_OWNER')
    st = path.stat()
    require(stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode), 'UNSAFE_TYPE')
    require(stat.S_IMODE(st.st_mode) == (0o700 if directory else 0o600), 'UNSAFE_MODE')
    return path


def publish(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    return {'path': str(path), 'size': len(data), 'sha256': sha(data)}


def verify_ref(ref, root):
    path = Path(ref['path'])
    require(path.is_relative_to(root) and path.resolve() == path and not path.is_symlink(), 'REF_PATH')
    with path.open('rb') as f:
        st = os.fstat(f.fileno()); require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, 'REF_TYPE')
        require(0 <= ref['size'] <= 32*1024*1024 and st.st_size == ref['size'], 'REF_SIZE')
        data = f.read(ref['size'] + 1)
    require(len(data) == ref['size'] and sha(data) == ref['sha256'], 'REF_HASH')
    return data


class CliAPI:
    def __init__(self, binary, api_config):
        self.binary = str(binary); self.api_config = str(api_config)

    def query(self, query, evidence=None, mutation=False):
        argv = [self.binary, '--api_config', self.api_config, 'query', query,
                '--format', 'json', '--timeout', '25']
        tag = str(uuid.uuid4())
        if evidence is not None:
            publish(evidence / (tag + '-request.json'), canonical({'argv': argv, 'mutation': mutation}))
        try:
            r = subprocess.run(argv, capture_output=True, timeout=30)
        except subprocess.TimeoutExpired:
            if evidence is not None:
                publish(evidence / (tag + '-unknown.json'), canonical({'outcome': 'UNKNOWN', 'mutation': mutation}))
            raise LinuxDomainError('LAUNCH_UNKNOWN' if mutation else 'API_TIMEOUT', 'No automatic replay') from None
        if evidence is not None:
            publish(evidence / (tag + '-stdout.json'), r.stdout)
            publish(evidence / (tag + '-stderr.txt'), r.stderr)
        require(r.returncode == 0 and len(r.stdout) <= 8*1024*1024, 'API_FAILED')
        return parse_arrays(r.stdout)


class LinuxTriageBackend:
    def __init__(self, deployment_root, *, api=None):
        self.root = private_path(deployment_root, directory=True)
        self.deployment = json.loads(private_path(self.root/'deployment-complete.json').read_text())
        self.binding = self.deployment['ready']
        require(self.deployment['status'] == 'READY' and self.deployment['version'] == PINNED_VERSION, 'DEPLOYMENT_NOT_READY')
        require(sha((self.root/'velociraptor').read_bytes()) == BINARY_SHA, 'BINARY_DRIFT')
        private_path(self.root/'api-access', directory=True)
        private_path(self.root/'api-access/api_client.yaml')
        self.api = api or CliAPI(self.root/'velociraptor', self.root/'api-access/api_client.yaml')
        self.store = self.root/'triage'
        if not self.store.exists(): self.store.mkdir(mode=0o700)
        private_path(self.store, directory=True)
        self.router = LinuxPlatformRouter(self.clients)
        self.identity()

    def identity(self):
        require(Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() == self.binding['vm_uuid'], 'VM_DRIFT')
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == self.binding['boot_id'], 'BOOT_DRIFT')
        raw = private_path(self.root/'client.writeback.yaml').read_text()
        ids = re.findall(r'^client_id: (C\.[0-9a-f]+)\s*$', raw, re.M)
        require(ids == [self.binding['client_id']], 'WRITEBACK_DRIFT')

    def clients(self):
        self.identity()
        rows = self.api.query('SELECT client_id, os_info.system AS os, os_info.hostname AS hostname FROM clients() LIMIT 251')
        require(len(rows) < 251, 'CLIENT_INVENTORY_LIMIT')
        return rows

    def route(self, client_id):
        result = self.router.resolve_linux_target(client_id)
        require(result['client_id'] == self.binding['client_id'], 'UNBOUND_CLIENT')
        return dict(result, vm_uuid=self.binding['vm_uuid'], boot_id=self.binding['boot_id'], writeback_bound=True)

    def definitions(self, evidence=None):
        rows = self.api.query('SELECT * FROM artifact_definitions(names='+literal(list(ARTIFACT_HASHES))+')', evidence)
        require(len(rows) == len(ARTIFACT_HASHES) and {x['name'] for x in rows} == set(ARTIFACT_HASHES), 'ARTIFACT_SET')
        for row in rows:
            require(row['type'].lower() == 'client' and isinstance(row.get('raw'), str)
                    and sha(row['raw'].encode()) == ARTIFACT_HASHES[row['name']], 'ARTIFACT_DRIFT')
        return {x['name']: x for x in rows}

    def validate_plan(self, plan, definitions):
        require(set(plan) == {'parameters', 'timeout_seconds', 'max_bytes'}, 'PLAN_FIELDS')
        require(type(plan['timeout_seconds']) is int and 1 <= plan['timeout_seconds'] <= 120, 'TIMEOUT_BOUND')
        require(type(plan['max_bytes']) is int and 1 <= plan['max_bytes'] <= 32*1024*1024, 'SIZE_BOUND')
        require(set(plan['parameters']) == set(ARTIFACT_HASHES), 'PLAN_ARTIFACT_SET')
        for artifact, parameters in plan['parameters'].items():
            require(isinstance(parameters, dict), 'PARAMETERS_TYPE')
            schema = {p['name']: p for p in definitions[artifact]['parameters']}
            require(set(parameters) <= set(schema), 'UNKNOWN_PARAMETER')
            for key, value in parameters.items():
                spec = schema[key]
                require(type(value) is str and len(value) <= 16384 and '\x00' not in value, 'PARAMETER_TYPE')
                require(spec['type'] not in ('hidden', 'upload'), 'HIDDEN_PARAMETER')
                require(not spec.get('choices') or value in spec['choices'], 'PARAMETER_CHOICE')
                if spec['type'] == 'int': require(re.fullmatch(r'[0-9]+', value), 'PARAMETER_INT')
                if spec['type'] == 'bool': require(value in ('Y', 'N'), 'PARAMETER_BOOL')
        # Potentially broad/private default acquisitions must be explicitly scoped.
        for artifact, keys in {
            'Linux.Search.FileFinder': ['SearchFilesGlob','SearchFilesGlobTable','Upload_File','Calculate_Hash'],
            'Generic.Collectors.File': ['Root','collectionSpec','MaxFileSize'],
            'Linux.Forensics.Journal': ['DateAfter','DateBefore','AlsoUpload'],
        }.items(): require(all(k in plan['parameters'][artifact] for k in keys), 'EXPLICIT_SCOPE_REQUIRED')
        require(plan['parameters']['Linux.Forensics.Journal']['AlsoUpload'] == 'N', 'RAW_JOURNAL_DISABLED')

    def run_dir(self, run_id):
        require(str(uuid.UUID(run_id)) == run_id, 'RUN_ID')
        return private_path(self.store/run_id, directory=True)

    def _read(self, directory, name):
        return json.loads(private_path(directory/name).read_text())

    def launch(self, session_id, run_id, client_id, plan):
        require(str(uuid.UUID(session_id)) == session_id and str(uuid.UUID(run_id)) == run_id, 'SESSION_ID')
        self.route(client_id)
        definitions = self.definitions(); self.validate_plan(plan, definitions)
        directory = self.store/run_id; directory.mkdir(mode=0o700)  # reservation forbids uncertain replay
        self._last_reservation = (run_id, object())
        publish(directory/'definitions.json', canonical(definitions))
        premise = {'client_id':client_id,'session_id':session_id,'identity':self.binding,
                   'definitions':ARTIFACT_HASHES,'version':PINNED_VERSION,'plan':plan}
        publish(directory/'plan.json', canonical(premise))
        flows = []
        for artifact, parameters in plan['parameters'].items():
            self.route(client_id)
            intent = {'artifact':artifact,'client_id':client_id,'parameters':parameters,
                      'timeout':plan['timeout_seconds'],'max_bytes':plan['max_bytes']}
            publish(directory/('intent-'+str(len(flows))+'.json'), canonical(intent))
            env = ','.join('`'+k+'`='+literal(v) for k,v in parameters.items())
            q = ('LET collection <= collect_client(urgent=TRUE, client_id='+literal(client_id)+
                 ', artifacts='+literal(artifact)+', env=dict('+env+'), timeout='+str(plan['timeout_seconds'])+
                 ', max_bytes='+str(plan['max_bytes'])+') SELECT flow_id, request FROM foreach(row=collection)')
            rows = self.api.query(q, directory, mutation=True)
            require(len(rows) == 1 and re.fullmatch(r'F\.[A-Za-z0-9_-]+', rows[0].get('flow_id','')), 'LAUNCH_UNKNOWN')
            flow = dict(intent, flow_id=rows[0]['flow_id'], launch=rows[0])
            publish(directory/('flow-'+str(len(flows))+'.json'), canonical(flow)); flows.append(flow)
            request=rows[0].get('request',{})
            require(request.get('artifacts')==[artifact] and request.get('timeout')==plan['timeout_seconds']
                    and request.get('max_upload_bytes')==plan['max_bytes'],'LAUNCH_REQUEST_MISMATCH')
            envs={x['key']:x['value'] for spec in request.get('specs',[]) for x in spec.get('parameters',{}).get('env',[])}
            schema={p['name']:p for p in definitions[artifact]['parameters']}
            require(all(envs.get(k)==v or (schema[k]['type']=='bool' and v=='N' and envs.get(k)=='')
                        for k,v in parameters.items()),'LAUNCH_PARAMETERS_LOST')
        result = {'run_id':run_id,'session_id':session_id,'client_id':client_id,'flows':flows,
                  'fingerprint':sha(canonical(premise)),'premise':premise}
        publish(directory/'launched.json', canonical(result))
        return result

    def _flows(self, directory):
        # Only explicit creation responses retained by this exact run, never latest flow.
        return [self._read(directory,p.name) for p in sorted(directory.glob('flow-*.json'))]

    def status(self, run_id):
        directory = self.run_dir(run_id); plan = self._read(directory,'plan.json')
        self.route(plan['client_id']); states = []
        for flow in self._flows(directory):
            q = ('SELECT session_id,state,status,total_collected_rows,total_logs,total_uploaded_files,request,artifacts_with_results '
                 'FROM flows(client_id='+literal(flow['client_id'])+') WHERE session_id='+literal(flow['flow_id'])+' LIMIT 2')
            rows = self.api.query(q,directory)
            require(len(rows) == 1 and rows[0]['session_id'] == flow['flow_id'], 'FLOW_NOT_UNIQUE')
            states.append(dict(rows[0], artifact=flow['artifact'], flow_id=flow['flow_id']))
        publish(directory/('status-'+str(uuid.uuid4())+'.json'),canonical(states))
        return {'run_id':run_id,'flows':states,'complete':len(states)==len(ARTIFACT_HASHES) and all(x['state']=='FINISHED' for x in states)}

    def cancel(self, run_id):
        directory=self.run_dir(run_id);plan=self._read(directory,'plan.json');self.route(plan['client_id'])
        before=self.status(run_id); results=[]
        for flow in before['flows']:
            if flow['state'] not in ('FINISHED','ERROR','CANCELLED','CANCELED'):
                rows=self.api.query('SELECT cancel_flow(client_id='+literal(plan['client_id'])+', flow_id='+literal(flow['flow_id'])+') AS Result FROM scope()',directory,mutation=True)
                require(len(rows)==1 and rows[0].get('Result') is not None,'CANCEL_UNKNOWN');results.append(rows[0])
        deadline=time.monotonic()+30
        while True:
            after=self.status(run_id)
            if all(x['state'] in ('FINISHED','ERROR','CANCELLED','CANCELED') for x in after['flows']):break
            require(time.monotonic()<deadline,'CANCEL_NOT_TERMINAL');time.sleep(1)
        result={'run_id':run_id,'responses':results,'terminal':after,'unknown_launch':len(self._flows(directory))!=len(list(directory.glob('intent-*.json')))}
        publish(directory/('cancel-'+str(uuid.uuid4())+'.json'),canonical(result));return result

    def results(self, run_id):
        directory=self.run_dir(run_id);launched=self._read(directory,'launched.json')
        require(not (directory/'result.json').exists(),'RESULT_ALREADY_EXPORTED')
        current=self.status(run_id);require(current['complete'],'FLOW_NOT_FINISHED')
        definitions=self._read(directory,'definitions.json');products=[];data={};files=[];total_bytes=0
        for flow in launched['flows']:
            artifact=flow['artifact'];cid=flow['client_id'];fid=flow['flow_id'];data[artifact]={}
            for source in definitions[artifact]['sources']:
                name=source['name'];offset=0;all_rows=[]
                while True:
                    query=('SELECT * FROM source(client_id='+literal(cid)+',flow_id='+literal(fid)+',artifact='+literal(artifact)+
                           (',source='+literal(name) if name else '')+',start_row='+str(offset)+',count=100)')
                    rows=self.api.query(query,directory);require(len(rows)<=100,'PAGE_OVERFLOW')
                    product=publish(directory/('rows-'+str(uuid.uuid4())+'.json'),canonical(rows))
                    total_bytes+=product['size'];require(total_bytes<=32*1024*1024,'RESULT_BYTE_BOUND')
                    products.append(dict(product,kind='rows',artifact=artifact,source=name,flow_id=fid,client_id=cid,offset=offset,rows=len(rows)))
                    all_rows.extend(rows);offset+=len(rows)
                    require(offset<=5000,'ROW_BOUND')
                    if len(rows)<100:break
                data[artifact][name]=all_rows
            logs=self.api.query('SELECT * FROM flow_logs(client_id='+literal(cid)+',flow_id='+literal(fid)+') LIMIT 5001',directory)
            require(len(logs)<=5000,'LOG_BOUND')
            log_ref=publish(directory/('logs-'+fid+'-'+str(uuid.uuid4())+'.json'),canonical(logs))
            total_bytes+=log_ref['size'];require(total_bytes<=32*1024*1024,'RESULT_BYTE_BOUND')
            products.append(dict(log_ref,kind='logs',artifact=artifact,flow_id=fid,client_id=cid,rows=len(logs)))
            inventory=self.api.query('SELECT * FROM uploads(client_id='+literal(cid)+',flow_id='+literal(fid)+') LIMIT 251',directory)
            require(len(inventory)<251,'FILE_COUNT_BOUND')
            products.append(dict(publish(directory/('uploads-'+fid+'-'+str(uuid.uuid4())+'.json'),canonical(inventory)),kind='inventory',flow_id=fid,client_id=cid))
            for item in inventory:
                require(item.get('Type','')!='idx' and item.get('type','')!='idx','SPARSE_UNSUPPORTED')
                size=item.get('file_size');require(type(size)is int and 0<=size<=4*1024*1024 and size==item.get('uploaded_size'),'UPLOAD_SIZE')
                components=item.get('_Components') or item.get('Upload',{}).get('Components')
                require(isinstance(components,list) and len(components)>4 and components[:4]==['clients',cid,'collections',fid]
                        and all(type(x)is str and x not in ('','..','.') and '/' not in x for x in components),'UPLOAD_PATH')
                content=bytearray();offset=0
                while offset<size:
                    length=min(65536,size-offset)
                    query=('SELECT base64encode(string=read_file(accessor="fs",filename='+literal('fs:/'+ '/'.join(components))+
                           ',offset='+str(offset)+',length='+str(length)+')) AS Data FROM scope()')
                    rows=self.api.query(query,directory);require(len(rows)==1 and type(rows[0].get('Data'))is str,'DOWNLOAD_RESPONSE')
                    block=base64.b64decode(rows[0]['Data'],validate=True);require(len(block)==length,'DOWNLOAD_SHORT')
                    content.extend(block);offset+=length
                total_bytes+=len(content);require(total_bytes<=32*1024*1024,'RESULT_BYTE_BOUND')
                expected_hashes=[]
                for row in [r for source in data[artifact].values() for r in source]:
                    upload=row.get('Upload')
                    if isinstance(upload,dict) and upload.get('Path')==item.get('client_path') and upload.get('sha256'):
                        expected_hashes.append(upload['sha256'])
                    if row.get('SourceFile')==item.get('client_path') and row.get('SourceFileSha256'):
                        expected_hashes.append(row['SourceFileSha256'])
                require(expected_hashes and set(expected_hashes)=={sha(content)},'SOURCE_HASH_MISMATCH')
                ref=publish(directory/('file-'+str(uuid.uuid4())+'.bin'),bytes(content))
                product=dict(ref,kind='file',artifact=artifact,client_id=cid,flow_id=fid,components=components,source_path=item.get('client_path'),inventory=item)
                products.append(product);files.append(product)
        categories=classify(data,files)
        result=dict(launched,status='FINISHED',flow_status=current['flows'],products=products,category_results=categories,
                    limitations=LIMITATIONS,complete=all(categories.values()))
        publish(directory/'result.json',canonical(result))
        return self.export(run_id)

    def export(self, run_id, include_bytes=False):
        directory=self.run_dir(run_id);result=self._read(directory,'result.json')
        self.route(result['client_id'])
        for ref in result['products']:verify_ref(ref,directory)
        if include_bytes:
            names=sorted(p for p in directory.iterdir() if p.is_file())
            require(sum(p.stat().st_size for p in names)<=64*1024*1024,'EXPORT_BYTE_BOUND')
            bundle=[]
            for path in names:
                raw=private_path(path).read_bytes()
                bundle.append({'name':path.name,'size':len(raw),'sha256':sha(raw),'data_base64':base64.b64encode(raw).decode()})
            return {'run_id':run_id,'originals':bundle}
        return {'ref':{'path':str(directory/'result.json'),'size':(directory/'result.json').stat().st_size,'sha256':sha((directory/'result.json').read_bytes())},**result}

    def collect(self, session_id, run_id, client_id, plan):
        previous_reservation = getattr(self, '_last_reservation', None)
        try:
            self.launch(session_id,run_id,client_id,plan)
            deadline=time.monotonic()+plan['timeout_seconds']+90
            while True:
                result=self.status(run_id)
                require(not any(x['state'] in ('ERROR','CANCELLED','CANCELED') for x in result['flows']),'COLLECTION_FAILED')
                if result['complete']:break
                require(time.monotonic()<deadline,'COLLECTION_DEADLINE');time.sleep(2)
            return self.results(run_id)
        except BaseException as error:
            reservation = getattr(self, '_last_reservation', None)
            if (reservation is not previous_reservation and reservation[0] == run_id
                    and (self.store/run_id/'plan.json').exists()):
                try:self.cancel(run_id)
                except BaseException as cleanup:error.add_note('Cancellation incomplete: '+type(cleanup).__name__)
            raise

    def compare(self, first, second):
        require(first!=second,'SAME_RUN')
        a=self.export(first);b=self.export(second)
        return compare_verified(a,b)


def classify(data,files):
    def rows(name):return [r for source in data.get(name,{}).values() for r in source]
    finder=rows('Linux.Search.FileFinder')
    units=rows('Generic.Collectors.File');cron=rows('Linux.Sys.Crontab')
    return {
        'process':any(r.get('Pid') and r.get('Exe') for r in rows('Linux.Sys.Pslist')),
        'file':any(r.get('OSPath') and r.get('MTime') for r in finder),
        'network':any(r.get('ProcessInfo',{}).get('Pid') for r in rows('Linux.Network.Netstat') if isinstance(r.get('ProcessInfo'),dict)),
        'persistence':bool(rows('Linux.Sys.Services') and cron and units),
        'logs':any(r.get('System') and r.get('EventData') for r in rows('Linux.Forensics.Journal')),
        'metadata':any(isinstance(r.get('Hash'),dict) and r['Hash'].get('SHA256') for r in finder),
        'acquisition':any(r['artifact']=='Linux.Search.FileFinder' and r['size']>0 for r in files),
    }


def compare_verified(a,b):
    def valid(run):
        try:
            require(run['status']=='FINISHED' and run['complete'] is True,'RUN_FAILED')
            require(set(run['category_results'])==set(REQUIRED_CATEGORIES) and all(v is True for v in run['category_results'].values()),'CATEGORY_MISSING')
            require(len(run['flows'])==len(ARTIFACT_HASHES) and len(run['flow_status'])==len(ARTIFACT_HASHES)
                    and all(x['state']=='FINISHED' for x in run['flow_status']),'FLOW_FAILED')
            require({x['artifact'] for x in run['flows']}==set(ARTIFACT_HASHES),'FLOW_ARTIFACT_SET')
            require(run['products'] and any(x['kind']=='file' for x in run['products']),'PRODUCT_MISSING')
            root=private_path(Path(run['ref']['path']).parent,directory=True)
            original=json.loads(verify_ref(run['ref'],root))
            require(original=={k:v for k,v in run.items() if k!='ref'},'REF_BINDING')
            require({(x['flow_id'],x['artifact']) for x in run['flows']}=={(x['flow_id'],x['artifact']) for x in run['flow_status']},'FLOW_BINDING')
            require(json.loads(private_path(root/'plan.json').read_text())==run['premise'],'PLAN_BINDING')
            require(sha(canonical(run['premise']))==run['fingerprint'],'PREMISE_HASH')
            definitions=json.loads(private_path(root/'definitions.json').read_text())
            require(set(definitions)==set(ARTIFACT_HASHES),'DEFINITION_SET')
            require(all(sha(definitions[n]['raw'].encode())==h for n,h in ARTIFACT_HASHES.items()),'DEFINITION_HASH')
            data={n:{} for n in ARTIFACT_HASHES};files=[];seen=set()
            flow_ids={x['flow_id']:x['artifact'] for x in run['flows']}
            require(len(flow_ids)==len(ARTIFACT_HASHES),'FLOW_DUPLICATE')
            for ref in run['products']:
                raw=verify_ref(ref,root)
                require(ref['client_id']==run['client_id'] and ref['flow_id'] in flow_ids,'PRODUCT_FLOW')
                if ref['kind']=='rows':
                    require(ref['artifact']==flow_ids[ref['flow_id']],'PRODUCT_ARTIFACT')
                    key=(ref['artifact'],ref['source']);rows=json.loads(raw)
                    target=data[ref['artifact']].setdefault(ref['source'],[])
                    require(ref['offset']==len(target) and ref['rows']==len(rows),'PAGE_BINDING')
                    target.extend(rows);seen.add(ref['artifact'])
                elif ref['kind']=='file':files.append(ref)
            require(seen==set(ARTIFACT_HASHES),'PRODUCT_SET')
            require(classify(data,files)==run['category_results'],'CATEGORY_ORIGINALS')
            return True
        except (KeyError,TypeError,ValueError,OSError,LinuxDomainError):return False
    good=valid(a) and valid(b)
    same=bool(a.get('fingerprint')) and a.get('fingerprint')==b.get('fingerprint') and a.get('premise')==b.get('premise')
    return {'repeatable':bool(good and same and a.get('run_id')!=b.get('run_id')),'both_verified':good,'same_premise':same,
            'run_ids':[a.get('run_id'),b.get('run_id')],'limitations':LIMITATIONS}
