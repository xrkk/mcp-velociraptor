"""PC026 C2/C3 exact models. Content verification grants no source/close authority."""
from __future__ import annotations
import base64
import hashlib
import json
import re
import unicodedata

from velociraptor_observation_archive import _encoding_shape, _depth, _pairs, _constant
from velociraptor_observation_catalog import _identity, _directory
from velociraptor_observation_sdk import PIN_REF


class CutError(ValueError):
    pass


def _require(ok, code):
    if not ok:raise CutError(code)


def _exact(value, fields):
    _require(type(value) is dict and set(value)==set(fields.split()),'exact_fields')


def _integer(value, minimum=0):
    _require(type(value) is int and value>=minimum,'integer')


def _string(value):
    _require(type(value) is str and bool(value),'string')
    value.encode('utf-8')


def _sha(value):
    _require(type(value) is str and re.fullmatch('[0-9a-f]{64}',value),'sha256')


def canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode('utf-8')


def ref(path, raw):
    result=dict(path=path,size=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    _ref(result)
    return result


def _ref(value, path=None):
    _exact(value,'path size sha256');_integer(value['size'],1);_sha(value['sha256'])
    name=value['path'];_string(name)
    parts=name.split('/')
    _require(len(parts)<=64 and all(p and not re.search(r'[<>:"|?*\\\x00-\x1f]',p)
        and p not in ('.','..') and not p.endswith(('.', ' ')) and unicodedata.normalize('NFC',p)==p and not re.fullmatch(
            r'(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?',p,re.I) for p in parts),'ref_path')
    if path is not None:_require(name==path,'fixed_ref_path')


def _refs(value, *, ordered=True):
    _require(type(value) is list,'ref_array')
    for r in value:_ref(r)
    names=[r['path'] for r in value]
    _require(len(names)==len({n.casefold() for n in names}) and (not ordered or names==sorted(names)),'ref_order_unique')


def _sequences(value):
    _require(type(value) is list,'sequence_array')
    for n in value:_integer(n,1)
    _require(value==sorted(set(value)),'sequence_order_unique')


_FIELDS={
'projection':'catalog_prefix attempt_sequences request_records lifecycle_ref',
'lifecycle':'sdk_pin_ref close_reason admission_watermark sdk_work binary_work attempt_sequences cleanup status',
'source':'config_ref catalog_head files status',
'cut':'instance_ref config_ref catalog_head attempts_ref members close_reason worker_count status',
'export':'cut_ref cut_identity members status'}
_KINDS=dict(projection='pc026-observation-session-projection-v1',
    lifecycle='pc026-observation-session-lifecycle-v1',source='pc026-observation-export-source-v1',
    cut='pc026-observation-session-cut-v1',export='pc026-observation-session-export-v1')


class CutCodec:
    def __init__(self, budgets):
        from velociraptor_observation_startup import _BUDGETS
        _require(type(budgets) is dict and set(budgets)==_BUDGETS
            and all(type(n) is int and n>0 for n in budgets.values()),'budgets')
        self.limits=dict(budgets)

    def _limit(self, kind):
        return self.limits['max_proof_bytes' if kind=='lifecycle' else
            'max_source_manifest_bytes' if kind=='source' else 'max_cut_bytes']

    def parse(self, raw, kind):
        try:
            _require(kind in _FIELDS and type(raw) is bytes and len(raw)<=self._limit(kind),'byte_budget')
            _depth(raw,64)
            value=json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs,parse_constant=_constant)
            self.validate(value,kind)
            _require(canonical(value)==raw,'canonical_original')
            return value
        except CutError:raise
        except (ValueError,TypeError,UnicodeError,RecursionError) as error:
            raise CutError('invalid_original') from error

    def encode(self, value, kind):
        try:
            _encoding_shape(value,64)
            return canonical(self.parse(canonical(value),kind))
        except CutError:raise
        except (ValueError,TypeError,UnicodeError,RecursionError) as error:
            raise CutError('invalid_encoding') from error

    def validate(self, v, kind):
        _exact(v,'schema_version kind instance_id session_id '+_FIELDS[kind])
        _require(type(v['schema_version']) is int and v['schema_version']==1 and v['kind']==_KINDS[kind],'version_kind')
        _require(type(v['instance_id']) is str and re.fullmatch('[0-9a-f]{32}',v['instance_id']),'instance')
        _string(v['session_id'])
        if kind in ('cut','lifecycle'):_require(v['close_reason'] in ('DELETE','SERVICE_STOP','IDLE'),'close_reason')
        if kind in ('source','cut'):
            _ref(v['config_ref']);_ref(v['catalog_head'])
            _require(re.fullmatch(r'c/[0-9]{8}\.json',v['catalog_head']['path']),'catalog_head_path')
        if kind=='projection':
            _refs(v['catalog_prefix'],ordered=False);_require(bool(v['catalog_prefix']),'empty_catalog')
            for n,r in enumerate(v['catalog_prefix']):_ref(r,f'originals/c/{n:08d}.json')
            _sequences(v['attempt_sequences']);_ref(v['lifecycle_ref'],'lifecycle.json')
            _require(type(v['request_records']) is list,'request_records')
            seen=[]
            for row in v['request_records']:
                _exact(row,'attempt_sequence records');_integer(row['attempt_sequence'],1)
                _refs(row['records'],ordered=False);_require(len(row['records'])>=2,'request_chain')
                for n,r in enumerate(row['records']):
                    _require(re.fullmatch(r'originals/r[0-9]{12}-[0-9a-f]{64}/'+f'{n:08d}'+r'\.json',r['path']),'request_path')
                seen.append(row['attempt_sequence'])
            _sequences(seen);_require(set(seen)<=set(v['attempt_sequences']),'request_attempts')
        elif kind=='lifecycle':
            _ref(v['sdk_pin_ref']);_require(v['sdk_pin_ref']==PIN_REF,'sdk_pin')
            _integer(v['admission_watermark']);_sequences(v['attempt_sequences'])
            _exact(v['sdk_work'],'messages transfer_workers')
            _require(all(type(v['sdk_work'][k]) is list for k in ('messages','transfer_workers')),'sdk_arrays')
            sequences=[]
            for row in v['sdk_work']['messages']:
                _exact(row,'operation_sequence request_id_type request_id method handler_outcome worker_exited')
                _string(row['method']);_require(row['handler_outcome'] in ('returned','raised','cancelled','not_dispatched'),'handler_outcome')
                rid=row['request_id'];typ=row['request_id_type']
                _require((rid is None and typ is None) or (type(rid) is int and typ=='integer')
                    or (type(rid) is str and typ=='string'),'typed_id')
                _require(row['worker_exited'] is True,'worker_exited');sequences.append(row['operation_sequence'])
            for row in v['sdk_work']['transfer_workers']:
                _exact(row,'operation_sequence transfer_id request_digest worker_nonce pid birth job process_exited resources_closed')
                _string(row['transfer_id']);_require(len(row['transfer_id'])<=128,'transfer_id')
                _sha(row['request_digest']);_require(type(row['worker_nonce']) is str and re.fullmatch('[0-9a-f]{32}',row['worker_nonce']),'nonce')
                _integer(row['pid'],1);_string(row['birth'])
                _require(row['job'] in ('package','verify_partial','prepare','commit','release')
                    and row['process_exited'] is True and row['resources_closed'] is True,'child_exit')
                sequences.append(row['operation_sequence'])
            _require(type(v['binary_work']) is list,'binary_work')
            for row in v['binary_work']:
                _exact(row,'operation_sequence request_sha256 outcome thread_exited resources_closed')
                _sha(row['request_sha256']);_require(row['outcome'] in ('returned','raised','cancelled')
                    and row['thread_exited'] is True and row['resources_closed'] is True,'binary_exit')
                sequences.append(row['operation_sequence'])
            for n in sequences:_integer(n,1);_require(n<=v['admission_watermark'],'watermark')
            _require(len(sequences)==len(set(sequences)),'work_sequence_unique')
            _exact(v['cleanup'],'runner_exited dispatcher_joined connection_closed transport_closed journals_closed export_io_closed')
            _require(all(n is True for n in v['cleanup'].values()) and v['status']=='CLOSED_KNOWN','cleanup')
        elif kind=='source':
            _require(type(v['files']) is list and v['status']=='OBSERVED','source_files')
            names=[]
            for row in v['files']:
                _exact(row,'source_ref export_ref identity sd_ref')
                _ref(row['source_ref']);_ref(row['export_ref'],'originals/'+row['source_ref']['path'])
                _require({k:row['source_ref'][k] for k in ('size','sha256')}==
                    {k:row['export_ref'][k] for k in ('size','sha256')},'copy_bytes')
                _identity(row['identity']);_ref(row['sd_ref'],'sd/'+row['identity']['acl_sha256']+'.bin')
                _require(row['sd_ref']['sha256']==row['identity']['acl_sha256'],'source_sd')
                names.append(row['source_ref']['path'])
            _require(len(names)==len({n.casefold() for n in names}),'source_unique')
        elif kind=='cut':
            _ref(v['instance_ref'],'c/00000000.json');_ref(v['attempts_ref'],'attempts.json');_refs(v['members'])
            _require(type(v['worker_count']) is int and v['worker_count']==0 and v['status']=='CLOSED_KNOWN','cut_closed')
        elif kind=='export':
            _ref(v['cut_ref'],'cut.json');_identity(v['cut_identity']);_refs(v['members'])
            _require(v['status']=='PUBLISHED','export_status')

    def verify(self, files, catalog_codec, archive_codec, lifecycle_config_raw):
        """Verify supplied full bytes; caller separately proves safe storage EOF."""
        _require(type(files) is dict,'file_map')
        from velociraptor_observation_startup import CONFIG, CONTRACT_REF
        _depth(lifecycle_config_raw,64)
        configuration=json.loads(lifecycle_config_raw.decode('utf-8'),object_pairs_hook=_pairs,parse_constant=_constant)
        _exact(configuration,'schema_version kind profile_id workflow_id contract_ref archive_config_ref deployment_ref implementation_freeze_ref budgets metadata_policy status')
        _require(canonical(configuration)==lifecycle_config_raw and type(configuration['schema_version']) is int
            and configuration['schema_version']==1 and configuration['kind']=='pc026-observation-lifecycle-configuration-v1'
            and configuration['contract_ref']==CONTRACT_REF and configuration['budgets']==self.limits
            and configuration['metadata_policy']=='GLOBAL_PREFIX_NO_OTHER_SESSION_EVENTS'
            and configuration['status']=='AUTHORIZED','lifecycle_configuration')
        for k in ('profile_id','workflow_id'):_string(configuration[k])
        for k in ('contract_ref','archive_config_ref','deployment_ref','implementation_freeze_ref'):_ref(configuration[k])
        CutCodec(configuration['budgets'])  # Equality cannot admit true as integer 1.
        config_ref=ref(CONFIG,lifecycle_config_raw)
        p=self.parse(files['attempts.json'],'projection');l=self.parse(files['lifecycle.json'],'lifecycle')
        s=self.parse(files['source-manifest.json'],'source');c=self.parse(files['cut.json'],'cut')
        e=self.parse(files['export.json'],'export')
        for v in (l,s,c,e):_require((v['instance_id'],v['session_id'])==(p['instance_id'],p['session_id']),'identity_drift')
        def original(r):
            _ref(r);raw=files[r['path']];_require(ref(r['path'],raw)==r,'member_content');return raw
        catalog=[original(r) for r in p['catalog_prefix']]
        summary=catalog_codec.verify(catalog)
        instance_begin=catalog_codec.parse(catalog[0])['payload']
        _require(instance_begin['config_ref']==configuration['archive_config_ref']
            and instance_begin['freeze_ref']==configuration['implementation_freeze_ref'],'archive_configuration_binding')
        _require(summary['instance_id']==p['instance_id'],'catalog_instance')
        begins={};ends={};acks={}
        for raw in catalog:
            r=catalog_codec.parse(raw);payload=r['payload']
            if r['record_type']=='ATTEMPT_BEGIN':begins[payload['attempt_sequence']]=payload
            elif r['record_type']=='ATTEMPT_END':ends[payload['attempt_sequence']]=payload
            elif r['record_type']=='ACCEPT_ACK':acks[payload['attempt_sequence']]=payload
        own=sorted(n for n,b in begins.items() if b['key']['session_id']==p['session_id'])
        _require(own==p['attempt_sequences']==l['attempt_sequences'] and all(n in ends for n in own),'session_attempt_closure')
        expected=[]
        for n in own:
            b=begins[n];end=ends[n]
            if b['decision']=='REJECTED':continue
            directory=_directory(n,b['key'])
            records=[ref('originals/'+directory+f'/{i:08d}.json',files['originals/'+directory+f'/{i:08d}.json'])
                for i in range(end['record_count'])]
            raws=[original(r) for r in records];chain=archive_codec.verify(raws)
            first=archive_codec.parse(raws[0]);last=archive_codec.parse(raws[-1])
            _require(first['payload']['key']==b['key'] and first['payload']['tool']==b['tool']
                and first['payload']['arguments_sha256']==b['arguments_sha256']
                and first['payload']['acceptance_sequence']==n,'request_parent')
            _require(chain['status']==end['disposition'] and last['payload']['outcome']==end['outcome']
                and len(raws)==end['record_count'] and chain['event_count']==end['event_count']
                and sum(map(len,raws))==end['total_bytes'],'request_end')
            _require(ref(directory+'/00000000.json',raws[0])==acks[n]['accept_ref']
                and ref(directory+f'/{len(raws)-1:08d}.json',raws[-1])==end['head_ref'],'ack_head')
            expected.append(dict(attempt_sequence=n,records=records))
        _require(p['request_records']==expected,'derived_projection')
        source_refs=p['catalog_prefix']+[r for a in expected for r in a['records']]
        _require({r['path'] for r in source_refs}=={r['export_ref']['path'] for r in s['files']},'source_closure')
        sds={}
        for row in s['files']:
            _require(row['export_ref'] in source_refs,'source_copy_ref');original(row['export_ref'])
            raw=original(row['sd_ref']);_require(hashlib.sha256(raw).hexdigest()==row['identity']['acl_sha256'],'source_sd_bytes')
            sds[row['sd_ref']['path']]=row['sd_ref']
        members=sorted(source_refs+list(sds.values())+[ref(n,files[n]) for n in
            ('source-manifest.json','lifecycle.json','attempts.json')],key=lambda r:r['path'])
        _require(c['members']==members and e['members']==sorted(members+[ref('cut.json',files['cut.json'])],key=lambda r:r['path']),'members_closure')
        _require(set(files)=={r['path'] for r in e['members']}|{'export.json'},'storage_exact_closure')
        _require(c['attempts_ref']==ref('attempts.json',files['attempts.json']) and
            p['lifecycle_ref']==ref('lifecycle.json',files['lifecycle.json']) and
            e['cut_ref']==ref('cut.json',files['cut.json']),'derived_refs')
        head=ref(f'c/{len(catalog)-1:08d}.json',catalog[-1])
        _require(c['catalog_head']==s['catalog_head']==head and
            c['instance_ref']==ref('c/00000000.json',catalog[0]) and c['config_ref']==s['config_ref']==config_ref
            and c['close_reason']==l['close_reason'],'cut_source_binding')
        for r in e['members']:original(r)
        return c


def close_headers(descriptor):
    _ref(descriptor)
    _require(re.fullmatch(r'e[0-9a-f]{32}/s[0-9a-f]{64}/cut\.json',descriptor['path']),'descriptor_path')
    value=base64.urlsafe_b64encode(canonical(descriptor)).rstrip(b'=').decode('ascii')
    _require(len(value)<=2048,'header_budget')
    return {'X-Velo-Observation-Close':'pc026-session-close-v1','X-Velo-Observation-Cut':value}
