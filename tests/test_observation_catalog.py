"""Pure catalog and real ctypes enumeration adapter MODEL regressions."""
import copy
import ctypes
import json
import unittest
from unittest.mock import patch
from velociraptor_observation_catalog import CatalogCodec, CatalogError, KIND, _directory
from tests import p05_pc026_windows_reader as r
from tests.test_observation_attempts import INSTANCE, key, configuration, ArchiveFS
from tests.test_observation_archive import SHA, reference

class CatalogTests(unittest.TestCase):
    def setUp(self):self.c=CatalogCodec(max_records=30,max_record_bytes=4096,max_total_bytes=122880,max_json_depth=32)
    def chain(self, modifications=None):
        identity=configuration(ArchiveFS()).document['root_identity'];ref=dict(path='MODEL/config',size=1,sha256=SHA)
        directory=_directory(1,key())
        rows=[('INSTANCE_BEGIN',dict(config_ref=ref,freeze_ref=ref,root_identity=identity)),
            ('ATTEMPT_BEGIN',dict(attempt_sequence=1,key=key(),tool='tool',arguments_sha256=SHA,decision='NEW',reason='NONE')),
            ('ACCEPT_ACK',dict(attempt_sequence=1,accept_ref=dict(ref,path=directory+'/00000000.json'))),
            ('ATTEMPT_END',dict(attempt_sequence=1,disposition='COMPLETE',outcome='returned',head_ref=dict(ref,path=directory+'/00000001.json'),record_count=2,event_count=0,total_bytes=2)),
            ('INSTANCE_END',dict(attempt_count=1,accepted_count=1,rejected_count=0,state='CLOSED_KNOWN'))]
        if modifications:modifications(rows)
        raw=[]
        for index,(kind,payload) in enumerate(rows):
            raw.append(self.c.encode(dict(schema_version=1,kind=KIND,sequence=index,previous=reference(raw[-1]) if raw else None,record_type=kind,instance_id=INSTANCE,payload=payload)))
        return raw
    def test_single_pass_eof_prefix_and_actual_reference(self):
        raw=self.chain()
        class Once:
            used=False
            def __iter__(self):
                if self.used:raise AssertionError('second traversal')
                self.used=True;return iter(raw)
        self.assertEqual(self.c.verify(Once())['status'],'CLOSED_KNOWN')
        self.assertEqual(self.c.verify(raw[:3])['status'],'INCOMPLETE')
        self.assertEqual(self.c.verify(raw)['head_ref'],reference(raw[-1]))
        def fault():
            yield from raw
            raise RuntimeError('actual storage EOF fault')
        with self.assertRaisesRegex(RuntimeError,'EOF'):self.c.verify(fault())
        with self.assertRaises(CatalogError):self.c.verify(raw+[raw[-1]])
    def test_chain_semantic_negative_matrix_rebound_hashes(self):
        mutations=[lambda rows:rows[2][1]['accept_ref'].update(path='other/00000000.json'),
            lambda rows:rows[3][1]['head_ref'].update(path='other/00000001.json'),
            lambda rows:rows.insert(4,copy.deepcopy(rows[3])),lambda rows:rows.pop(1),
            lambda rows:rows.insert(2,copy.deepcopy(rows[1])),lambda rows:rows[1][1].update(attempt_sequence=2),
            lambda rows:rows[4][1].update(attempt_count=2,accepted_count=2)]
        for mutation in mutations:
            with self.subTest(mutation=mutation),self.assertRaises(CatalogError):self.c.verify(self.chain(mutation))
        raw=self.chain();row=self.c.parse(raw[2]);row['previous']['sha256']='0'*64;raw[2]=self.c.encode(row)
        with self.assertRaises(CatalogError):self.c.verify(raw)
        with self.assertRaises(CatalogError):self.c.verify([raw[0],raw[2],raw[1]])
    def test_exact_canonical_payload_types_and_limits(self):
        raw=self.chain()[0]
        for bad in (raw[:-1],b'\xef\xbb\xbf'+raw,raw+b' ',raw.replace(b'"schema_version":1',b'"schema_version":true'),raw.replace(b'"sequence":0',b'"sequence":0,"sequence":0'),raw.replace(b'"sequence":0',b'"sequence":NaN')):
            with self.subTest(raw=bad),self.assertRaises(CatalogError):self.c.parse(bad)
        row=self.c.parse(raw)
        for change in (lambda x:x.update(extra=1),lambda x:x.update(record_type='seal'),lambda x:x['payload'].update(extra=1),lambda x:x['payload']['config_ref'].update(size=True)):
            changed=copy.deepcopy(row);change(changed)
            with self.assertRaises(CatalogError):self.c.encode(changed)
        for limits in (dict(max_record_bytes=len(raw)-1),dict(max_json_depth=2),dict(max_total_bytes=len(raw)-1)):
            c=CatalogCodec(**(dict(max_records=30,max_record_bytes=4096,max_total_bytes=122880,max_json_depth=32)|limits))
            with self.assertRaises(CatalogError):c.parse(raw)
        c=CatalogCodec(max_records=4,max_record_bytes=4096,max_total_bytes=122880,max_json_depth=32)
        with self.assertRaises(CatalogError):c.verify(self.chain())
        self.assertEqual(self.c.verify(self.chain())['record_count'],5)

class EnumerationAdapterModels(unittest.TestCase):
    def api(self,names,attrs=0,next_offset=0):
        api=r.NativeIO.__new__(r.NativeIO);calls=[];pages=iter(names)
        def info(handle,kind,buffer,size):
            calls.append((handle,kind,size))
            try:name=next(pages)
            except StopIteration:return 0
            row=r._DirectoryInfo.from_buffer(buffer);row.name_length=len(name.encode('utf-16-le'));row.attributes=attrs;row.next=next_offset
            ctypes.memmove(ctypes.addressof(buffer)+r._DirectoryInfo.name.offset,name.encode('utf-16-le'),row.name_length);return 1
        api.info=info;return api,calls
    def test_same_handle_resume_bounded_eof_and_layout(self):
        api,calls=self.api(['.','..','00000000.json'])
        with patch.object(ctypes,'get_last_error',return_value=18,create=True):self.assertEqual(list(api._names(123,2)),['00000000.json'])
        self.assertEqual([x[:2] for x in calls],[(123,11),(123,10),(123,10),(123,10)])
        self.assertEqual(r._DirectoryInfo.name.offset,104)
    def test_unsafe_member_bounds_and_errors_do_not_mean_eof(self):
        for names,attrs,offset,error in [(['x'],0x10,0,18),(['x'],0x400,0,18),(['../x'],0,0,18),(['x'],0,3,18),([],0,0,5),(['x']*5,0,0,18)]:
            api,_=self.api(names,attrs,offset)
            with self.subTest(names=names,attrs=attrs,offset=offset,error=error),patch.object(ctypes,'get_last_error',return_value=error,create=True),self.assertRaises(r.NativeReadError):list(api._names(123,1))
    def test_private_leaf_release_and_directory_rechecks_real_reader(self):
        from tests.test_observation_attempts import ArchiveFS
        from tests.test_observation_windows import ROOT, session
        fs=ArchiveFS();leaf=ROOT/'00000000.json';node=fs.node(leaf);node.update(data=b'abc',meta=(3,1,20,30,0x20))
        reader=session(fs)
        self.assertEqual(reader._directory_names(ROOT,2),frozenset({'00000000.json'}))
        self.assertEqual(reader._record_bytes(leaf,3),b'abc')
        self.assertNotIn(str(leaf),reader.objects)
        before=len(fs.closed)
        with self.assertRaises(r.NativeReadError):reader._record_bytes(leaf,2)
        self.assertGreater(len(fs.closed),before);self.assertNotIn(str(leaf),reader.objects)
        self.assertFalse(any(row['node']['name']==str(leaf) for row in fs.handles.values()))
        reader.close();self.assertFalse(fs.handles);self.assertEqual(len(fs.closed),len(set(fs.closed)))
    def test_native_governance_new_fixed_documents_are_private(self):
        from tests import p05_pc026_governance as gov
        from pathlib import PureWindowsPath
        class Reader:
            def read(self,path,*,private):return private
        with patch.object(gov.os,'name','nt'):
            for name in ('observation-archive-configuration.json','observation-namespace-root.json'):
                self.assertIs(gov._read(PureWindowsPath('C:/approved')/name,reader=Reader()),True)
