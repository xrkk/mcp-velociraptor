"""Real ledger/native-reader flow with MODEL Windows objects, never a cut."""
import hashlib
import json

PREFIX_TRACES=[]
import unittest
from tests import test_observation_attempts as model


class PrefixModels(unittest.TestCase):
    def setUp(self):
        self.fixture=model.LedgerModels();self.addCleanup(self.fixture.doCleanups)
        self.ledger,self.fs,self.config=self.fixture.ledger()

    def collect(self,session='one',**limits):
        prefix=self.ledger._session_prefix(session,max_files=limits.get('max_files',100),
            max_bytes=limits.get('max_bytes',1000000))
        PREFIX_TRACES.append(dict(test=self.id(),boundary='MODEL_WINDOWS_NATIVE_READER_FLOW_NOT_NATIVE_QUALIFICATION',
            session=session,attempts=prefix.attempts,catalog_count=prefix.catalog_count,
            catalog_head=json.loads(prefix.catalog_head),originals=[dict(path=r.path,size=len(r.raw),
                sha256=hashlib.sha256(r.raw).hexdigest(),bytes_hex=r.raw.hex(),
                identity=json.loads(r.identity),sd_hex=r.sd.hex()) for r in prefix.originals]))
        return prefix

    def test_global_prefix_includes_other_open_metadata_excludes_its_events(self):
        one=self.ledger.begin(model.key(1,'one'),'tool',model.SHA)
        self.fixture.terminal(self.ledger,one,events=1)
        other=self.ledger.begin(model.key(2,'other'),'tool',model.SHA)
        journal=self.ledger.accept(other)
        journal.claim(object(),model.key(2,'other'),'tool',model.SHA)
        journal.append(dict(sequence=1,kind='target.resolve',facts=dict(operation_id=None,mode='selected',client_id='MODEL-other-secret')))
        before=len(self.fs.handles)
        prefix=self.collect()
        self.assertEqual(prefix.attempts,(1,))
        self.assertEqual(prefix.catalog_count,6)
        self.assertEqual(len(prefix.originals),9)
        rows=[self.config.catalog_codec.parse(row.raw) for row in prefix.originals if row.path.startswith('c/')]
        self.assertTrue(any(r.get('payload',{}).get('key',{}).get('session_id')=='other' for r in rows))
        self.assertFalse(any(b'MODEL-other-secret' in row.raw for row in prefix.originals))
        self.assertEqual(before,len(self.fs.handles),'temporary snapshot handles must close')
        for row in prefix.originals:
            import json
            self.assertEqual(hashlib.sha256(row.sd).hexdigest(),json.loads(row.identity)['acl_sha256'])
        journal.seal('returned');journal.close();self.ledger.finish(other,'returned')
        self.ledger.close();self.assertFalse(self.fs.handles)

    def test_rejected_tombstone_has_no_fake_request_directory_and_closed_handle_tail(self):
        one=self.ledger.begin(model.key(1,'one'),'tool',model.SHA)
        self.fixture.terminal(self.ledger,one)
        self.assertEqual(self.ledger.begin(model.key(1,'one'),'tool',model.SHA).decision,'REJECTED')
        prefix=self.collect()
        self.assertEqual(prefix.attempts,(1,2))
        self.assertEqual(len([r for r in prefix.originals if not r.path.startswith('c/')]),2)
        self.ledger.close();self.assertFalse(self.fs.handles)

    def test_own_unended_refuses_while_other_unended_is_legal(self):
        self.ledger.begin(model.key(1,'one'),'tool',model.SHA)
        with self.assertRaisesRegex(Exception,'prefix_session_unended'):self.collect()
        self.assertTrue(self.ledger._unknown)

    def test_real_missing_leaf_extra_pending_tamper_and_second_enumeration_refuse(self):
        for fault in ('missing','extra','pending','tamper','second_names'):
            fixture=model.LedgerModels()
            try:
                ledger,fs,config=fixture.ledger()
                lease=ledger.begin(model.key(1,'one'),'tool',model.SHA)
                fixture.terminal(ledger,lease)
                root=ledger._catalog_dir.path
                if fault=='missing':del fs.nodes[str(root/'00000001.json')]
                elif fault in ('extra','pending'):fs.node(root/('extra.json' if fault=='extra' else 'bad.pending'))
                elif fault=='tamper':fs.nodes[str(root/'00000001.json')]['data']=b'broken'
                else:
                    enumerations=0
                    def drift(method,handle):
                        nonlocal enumerations
                        if method=='enumerate':
                            enumerations+=1
                            if enumerations==2:fs.node(root/'extra.json')
                    fs.hook=drift
                with self.subTest(fault=fault),self.assertRaises(Exception):
                    ledger._session_prefix('one',max_files=100,max_bytes=1000000)
                self.assertTrue(ledger._unknown)
                fs.hook=lambda *args:None
            finally:fixture.doCleanups()
            self.assertFalse(fs.handles)

    def test_budget_refusal_before_export_no_writer_and_retains_originals(self):
        lease=self.ledger.begin(model.key(1,'one'),'tool',model.SHA)
        self.fixture.terminal(self.ledger,lease)
        originals={p:r['data'] for p,r in self.fs.nodes.items() if not r['directory']}
        with self.assertRaisesRegex(Exception,'prefix_file_budget'):self.collect(max_files=1)
        self.assertEqual(originals,{p:r['data'] for p,r in self.fs.nodes.items() if not r['directory']})
        self.assertTrue(self.ledger._unknown)

    def test_snapshot_leaf_close_failure_is_unknown_and_primary_not_replaced(self):
        lease=self.ledger.begin(model.key(1,'one'),'tool',model.SHA)
        self.fixture.terminal(self.ledger,lease)
        primary=OSError('MODEL-prefix-leaf-close')
        fired=False
        def fail(method,handle):
            nonlocal fired
            if method=='close' and not fired and handle in self.fs.handles and not self.fs.handles[handle]['node']['directory']:
                fired=True
                del self.fs.handles[handle]
                raise primary
        self.fs.hook=fail
        with self.assertRaises(OSError) as caught:self.collect()
        self.assertIs(caught.exception,primary)
        self.assertTrue(fired and self.ledger._unknown)
        self.fs.hook=lambda *args:None
