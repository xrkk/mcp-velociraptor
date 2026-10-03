"""08 format models only: no durable source, SDK calls or Windows qualification."""
import copy
import hashlib
import io
import json
import tracemalloc
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import velociraptor_observation_archive as a

UUID = '184a9076-bb09-4449-9df6-68286a55cadd'
SHA = 'a' * 64
KEY = dict(instance_id='instance', session_id='session', request_id_type='integer', request_id=7)
BASE = dict(operation_id=UUID, attempt=1, client_id='MODEL-client')
READ = dict(BASE, flow_id='MODEL-flow')


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)+'\n').encode()


def reference(raw):
    return dict(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def codec(**overrides):
    limits = dict(max_records=20000, max_record_bytes=1000000, max_total_bytes=20000000, max_json_depth=12)
    return a.ArchiveCodec(**(limits | overrides))


def accept(key=None):
    return dict(schema_version=1, kind=a.ACCEPT, sequence=0, previous=None,
                payload=dict(key=copy.deepcopy(KEY if key is None else key), tool='tool', arguments_sha256=SHA, acceptance_sequence=1))


def event(previous, sequence=1, kind='target.resolve', facts=None):
    return dict(schema_version=1, kind=a.EVENT, sequence=sequence, previous=reference(previous),
                payload=dict(sequence=sequence, kind=kind, facts=facts or dict(operation_id=None, mode='selected', client_id='MODEL-client')))


def seal(previous, events=0, status='COMPLETE', outcome='returned'):
    return dict(schema_version=1, kind=a.SEAL, sequence=events+1, previous=reference(previous),
                payload=dict(event_count=events, archive_status=status, outcome=outcome))


def all_facts():
    return {
        'target.resolve': dict(operation_id=None, mode='cache_hit', client_id='MODEL-client'),
        'target.operation.begin': dict(BASE),
        'target.operation.end': dict(BASE, outcome='cancelled'),
        'target.exists': dict(BASE, exists=False),
        'target.clear': dict(operation_id=None, previous_client_id=None),
        'flow.create.begin': dict(BASE, creation_id=UUID, artifact='Windows.Artifact', parameters_sha256=SHA, timeout=None, max_bytes=1, org_id=None, root_org=True),
        'flow.create.return': dict(BASE, creation_id=UUID, rows=[dict(row_index=0, flow_id=None, artifacts=None, timeout=None, max_upload_bytes=None, specs_sha256=None), dict(row_index=1, flow_id='MODEL-flow', artifacts=['x'], timeout=1, max_upload_bytes=1, specs_sha256=SHA)]),
        'flow.metadata.return': dict(BASE, creation_id=UUID, flow_id='MODEL-flow', state='RUNNING'),
        'flow.read.metadata': dict(READ, state=None, artifacts=[], sources=['a']),
        'flow.results.plan': dict(READ, artifact='Windows.Artifact', requested_source=None, selected_sources=[None, 'a'], offset=0, page_size=1),
        'flow.results.count': dict(READ, artifact='Windows.Artifact', source_index=0, source=None, total=0),
        'flow.results.window': dict(READ, artifact='Windows.Artifact', source_index=0, source=None, start_row=0, requested_count=2, returned=1, rows_sha256=SHA),
        'flow.results.page': dict(READ, returned=0, data_sha256=SHA, pagination=dict(cursor='v1:0', next_cursor=None, page_size=1, returned=0, truncated=False)),
        'flow.files.raw': dict(READ, row_count=0, rows_sha256=SHA),
        'flow.files.inventory': dict(READ, record_count=0, identities_sha256=SHA, sparse_count=0, size_mismatch_count=0),
        'flow.files.result': dict(READ, returned=0, data_sha256=SHA, truncated=True),
    }


class ArchiveTests(unittest.TestCase):
    def test_zero_event_status_and_business_outcome_are_independent(self):
        c=codec();first=c.encode(accept())
        for status in ('COMPLETE','FAILED'):
            for outcome in ('returned','raised','cancelled'):
                with self.subTest(status=status,outcome=outcome):
                    last=c.encode(seal(first,status=status,outcome=outcome));s=c.verify(iter((first,last)))
                    self.assertEqual(set(s), {'key','tool','arguments_sha256','acceptance_sequence','event_count','status','outcome','head_ref'})
                    self.assertEqual((s['status'],s['outcome'],s['event_count']), (status,outcome,0))
                    self.assertEqual(s['head_ref'],reference(last))

    def test_all_sixteen_whitelist_events_and_legal_prefixes(self):
        c=codec();records=[c.encode(accept())]
        self.assertEqual(c.verify(iter(records))['status'],'INCOMPLETE')
        for i,(kind,facts) in enumerate(all_facts().items(),1):
            records.append(c.encode(event(records[-1],i,kind,facts)))
            s=c.verify(iter(records));self.assertEqual((s['status'],s['outcome'],s['event_count']),('INCOMPLETE',None,i))
        records.append(c.encode(seal(records[-1],16)))
        self.assertEqual(c.verify(iter(records))['event_count'],16)

    def test_key_copy_and_typed_digest(self):
        c=codec();v=accept();raw=c.encode(v);s=c.verify((raw,));s['key']['request_id']=99
        self.assertEqual(c.verify((raw,))['key'],KEY);self.assertEqual(v['payload']['key'],KEY)
        other=dict(KEY,request_id_type='string',request_id='7')
        self.assertNotEqual(a.request_key_sha256(KEY),a.request_key_sha256(other))
        expected=hashlib.sha256(canonical(KEY)[:-1]).hexdigest()
        self.assertEqual(a.request_key_sha256(KEY),expected)
        for identity in (True,None,7.0):
            with self.subTest(identity=identity),self.assertRaises(a.ArchiveError):c.encode(accept(dict(KEY,request_id=identity)))
        c.encode(accept(dict(KEY,request_id=-7)));c.encode(accept(dict(KEY,request_id_type='string',request_id='')))

    def test_bad_encoding_originals_not_repaired(self):
        c=codec();raw=c.encode(accept());text=raw.decode()
        bad=[raw[:-1],raw+b'\n',b' '+raw,raw.replace(b'"sequence":0',b'"sequence": 0'),b'\xef\xbb\xbf'+raw,b'\xff'+raw,
             text.replace('"schema_version":1','"schema_version":1,"schema_version":1').encode(),
             text.replace('"acceptance_sequence":1','"acceptance_sequence":NaN').encode(),
             text.replace('"acceptance_sequence":1','"acceptance_sequence":Infinity').encode(),
             text.replace('"acceptance_sequence":1','"acceptance_sequence":1e999').encode(),
             text.replace('"tool":"tool"','"tool":"\\ud800"').encode(),raw[:-5]]
        for i,b in enumerate(bad):
            with self.subTest(case=i), self.assertRaises(a.ArchiveError):c.verify((b,))
        unicode=accept();unicode['payload']['tool']='工具\\"{}[]';self.assertEqual(c.parse(c.encode(unicode)),unicode)
        with self.assertRaises(a.ArchiveError):c.verify(())

    def test_exact_fields_types_and_unknown_kinds(self):
        c=codec();raw=c.encode(accept());v=accept()
        mutations=[('schema_version',True),('sequence',False),('kind','unknown'),('extra',1),('previous',{})]
        for field,value in mutations:
            x=copy.deepcopy(v);x[field]=value
            with self.subTest(field=field),self.assertRaises(a.ArchiveError):c.verify((canonical(x),))
        for field,value in [('tool',''),('arguments_sha256','A'*64),('acceptance_sequence',True),('acceptance_sequence',0),('extra',1)]:
            x=copy.deepcopy(v);x['payload'][field]=value
            with self.subTest(field=field),self.assertRaises(a.ArchiveError):c.encode(x)
        for field,value in [('instance_id',''),('session_id',''),('request_id_type','integerx'),('request_id','7'),('extra',1)]:
            x=copy.deepcopy(v);x['payload']['key'][field]=value
            with self.subTest(field=field),self.assertRaises(a.ArchiveError):c.encode(x)
        with self.assertRaises(a.ArchiveError):c.encode(event(raw,kind='MODEL'))
        with self.assertRaises(a.ArchiveError):c.verify((bytearray(raw),))

    def test_whitelist_field_negative_matrix(self):
        c=codec();first=c.encode(accept())
        for kind,facts in all_facts().items():
            for field in facts:
                x=copy.deepcopy(facts);del x[field]
                with self.subTest(kind=kind,missing=field),self.assertRaises(a.ArchiveError):c.encode(event(first,kind=kind,facts=x))
            x=dict(facts,unapproved='secret')
            with self.subTest(kind=kind,extra=True),self.assertRaises(a.ArchiveError):c.encode(event(first,kind=kind,facts=x))
        bad=[('target.resolve','mode','other'),('target.operation.begin','operation_id',None),('target.operation.begin','attempt',True),('target.operation.begin','attempt',3),
             ('target.exists','exists',1),('target.clear','previous_client_id',''),('target.operation.end','outcome','success'),
             ('flow.create.begin','parameters_sha256','x'),('flow.create.begin','timeout',0),('flow.create.begin','max_bytes',False),('flow.create.begin','root_org',1),
             ('flow.create.return','rows',[dict(row_index=True,flow_id=None,artifacts=None,timeout=None,max_upload_bytes=None,specs_sha256=None)]),
             ('flow.metadata.return','state',''),('flow.metadata.return','creation_id','bad'),('flow.read.metadata','state',''),('flow.read.metadata','sources',[None]),
             ('flow.results.count','total',-1),('flow.results.window','rows_sha256','x'),('flow.results.plan','offset',True),('flow.files.result','truncated',1)]
        for kind,field,value in bad:
            x=copy.deepcopy(all_facts()[kind]);x[field]=value
            with self.subTest(kind=kind,field=field),self.assertRaises(a.ArchiveError):c.encode(event(first,kind=kind,facts=x))
        for field,value in [('extra',1),('returned',1),('page_size',0),('cursor',None),('next_cursor',False),('truncated',1)]:
            f=copy.deepcopy(all_facts()['flow.results.page']);f['pagination'][field]=value
            with self.subTest(pagination=field),self.assertRaises(a.ArchiveError):c.encode(event(first,kind='flow.results.page',facts=f))

    def test_original_chain_corruption_and_terminal_boundary(self):
        c=codec();first=c.encode(accept());ev=c.encode(event(first));last=c.encode(seal(ev,1))
        for chain in ((first,first),(ev,),(first,last),(first,ev,ev),(first,ev,last,last),(first,ev,last,ev)):
            with self.subTest(length=len(chain)),self.assertRaises(a.ArchiveError):c.verify(iter(chain))
        for field,value in [('size',True),('size',0),('size',len(first)-1),('sha256','A'*64),('sha256','b'*64),('extra',1)]:
            e=event(first);e['previous'][field]=value
            with self.subTest(previous=field,value=value),self.assertRaises(a.ArchiveError):c.verify((first,canonical(e)))
        e=event(first);e['previous']=reference(first[:-1])
        with self.assertRaises(a.ArchiveError):c.verify((first,canonical(e)))
        for n in (0,2,True):
            e=event(first);e['sequence']=n
            with self.subTest(sequence=n),self.assertRaises(a.ArchiveError):c.verify((first,canonical(e)))
        for field,value in [('event_count',0),('event_count',True),('archive_status','INCOMPLETE'),('outcome','success')]:
            s=seal(ev,1);s['payload'][field]=value
            with self.subTest(seal=field),self.assertRaises(a.ArchiveError):c.verify((first,ev,canonical(s)))
        # A foreign request acceptance cannot be inserted, even with a repaired previous.
        other=accept(dict(KEY,session_id='other'));other['sequence']=1;other['previous']=reference(first)
        with self.assertRaises(a.ArchiveError):c.verify((first,canonical(other)))

    def test_budget_exact_boundaries_and_preparse_refusal(self):
        c=codec();records=[c.encode(accept())];records.append(c.encode(event(records[-1])));records.append(c.encode(seal(records[-1],1)))
        maximum=max(map(len,records));total=sum(map(len,records))
        self.assertEqual(codec(max_records=3,max_record_bytes=maximum,max_total_bytes=total,max_json_depth=3).verify(iter(records))['status'],'COMPLETE')
        for limits in (dict(max_records=2),dict(max_record_bytes=maximum-1),dict(max_total_bytes=total-1),dict(max_json_depth=2)):
            with self.subTest(limits=limits),self.assertRaises(a.ArchiveError):codec(**limits).verify(iter(records))
        for field in ('max_records','max_record_bytes','max_total_bytes','max_json_depth'):
            for invalid in (0,-1,True,None,1.0):
                with self.subTest(field=field,invalid=invalid),self.assertRaises(a.ArchiveError):codec(**{field:invalid})
        with patch.object(a.json,'loads',side_effect=AssertionError('must not parse')):
            with self.assertRaises(a.ArchiveError):codec(max_record_bytes=1).verify((records[0],))
            with self.assertRaises(a.ArchiveError):codec(max_total_bytes=1).verify((records[0],))
            with self.assertRaises(a.ArchiveError):codec(max_json_depth=2).verify((records[0],))

    def test_depth_scanning_and_nested_record_boundaries(self):
        c=codec();first=c.encode(accept());rec=event(first,kind='flow.create.return',facts=all_facts()['flow.create.return']);raw=c.encode(rec)
        self.assertEqual(codec(max_json_depth=6).parse(raw),rec)
        with self.assertRaises(a.ArchiveError):codec(max_json_depth=5).parse(raw)
        for raw in (b'['*3000+b'0'+b']'*3000+b'\n',b'{"x":'+b'['*3000+b'0'+b']'*3000+b'}\n'):
            with self.assertRaises(a.ArchiveError):codec(max_json_depth=20).parse(raw)
        with self.assertRaises(a.ArchiveError):codec(max_json_depth=5000).parse(b'['*3000+b'0'+b']'*3000+b'\n')

    def test_large_record_and_no_scope_or_stdout(self):
        c=codec();r=accept();r['payload']['tool']='工具'*100000;raw=c.encode(r)
        self.assertEqual(codec(max_record_bytes=len(raw),max_total_bytes=len(raw)).verify((raw,))['status'],'INCOMPLETE')
        with self.assertRaises(a.ArchiveError):codec(max_record_bytes=len(raw)-1).encode(r)
        output=io.StringIO()
        with redirect_stdout(output),patch('builtins.open',side_effect=AssertionError('I/O forbidden')):
            c.verify((raw,));c.encode(accept())
        self.assertEqual(output.getvalue(),'')

    def test_many_records_single_iteration_bounded_memory(self):
        c=codec();count=10000
        class Once:
            iterations=0
            def __iter__(self):
                self.iterations+=1
                if self.iterations!=1:raise AssertionError('iterated twice')
                previous=c.encode(accept());yield previous
                for n in range(1,count+1):
                    previous=c.encode(event(previous,n));yield previous
                yield c.encode(seal(previous,count))
        source=Once();tracemalloc.start()
        try:
            s=c.verify(source);_,peak=tracemalloc.get_traced_memory()
        finally:tracemalloc.stop()
        self.assertEqual(s['event_count'],count);self.assertEqual(source.iterations,1)
        self.assertLess(peak,1000000)  # Materializing 10k events exceeds this by megabytes.

    def test_encoder_rejects_custom_containers_cycles_and_invalid_unicode(self):
        c=codec()
        class CustomString(str):
            pass
        for value in (CustomString('tool'), object(), float('nan'), '\ud800'):
            r=accept();r['payload']['tool']=value
            with self.subTest(type=type(value)),self.assertRaises(a.ArchiveError):c.encode(r)
        r=accept();r['payload']['extra']=r
        with self.assertRaises(a.ArchiveError):c.encode(r)
        r=accept();r['payload']['extra']={1:'coercible'}
        with self.assertRaises(a.ArchiveError):c.encode(r)

    def test_iterator_failure_does_not_turn_into_incomplete(self):
        def source():
            yield codec().encode(accept())
            raise RuntimeError('external EOF unknown')
        with self.assertRaisesRegex(RuntimeError,'external EOF unknown'):codec().verify(source())


if __name__ == '__main__':
    unittest.main()
