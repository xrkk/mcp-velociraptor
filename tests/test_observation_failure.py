"""Finite classifier MODEL inputs; physical HTTP gate cases are separate."""
import copy
import unittest
from velociraptor_observation_failure import _classify
from velociraptor_observation_cut import ref
from tests.p06_mcp_raw_join import canonical,digest


class Reader:
    def __init__(self):self.files={}
    def read(self,name,raw=False):return self.files[name]


class FailureTests(unittest.TestCase):
    def setUp(self):
        self.reader=Reader();self.index=dict(exchanges=[]);self.headers=[];self.records=[]
        self.report=dict(run_id='6ed3d647-4489-4bc7-bc9c-860e2bde6c1e',server_identity=dict(instance_id='a'*32),calls=[])
        self.reader.files['capture.json']=canonical(self.index)

    def exchange(self,rid,response,*,sid='session',status=200,end='eof'):
        seq=len(self.index['exchanges'])+1
        message=dict(jsonrpc='2.0',id=rid,method='tools/call',params=dict(name='tool',arguments={}))
        row=dict(sequence=seq,method='POST',request_end='eof',response_end=end,response_status=status,
            response_content_type='application/json',response_content_encoding='',error=None)
        for direction,data in (('request',message),('response',response)):
            name=f'exchange-{seq:08d}-{direction}.bin';raw=canonical(data);self.reader.files[name]=raw;row[direction+'_ref']=ref(name,raw)
        self.index['exchanges'].append(row);self.headers.append(dict(exchange_sequence=seq,headers=[['mcp-session-id',sid]]))
        self.reader.files['capture.json']=canonical(self.index)
        return row

    def attempt(self,n,rid,*,sid='session',decision='NEW',reason='NONE',ack=True,end='COMPLETE'):
        begin=dict(attempt_sequence=n,key=dict(instance_id='a'*32,session_id=sid,
            request_id_type='integer' if type(rid)is int else 'string',request_id=rid),tool='tool',
            arguments_sha256=digest({}),decision=decision,reason=reason)
        self.records.append(dict(record_type='ATTEMPT_BEGIN',payload=begin))
        if ack:self.records.append(dict(record_type='ACCEPT_ACK',payload=dict(attempt_sequence=n)))
        if end:self.records.append(dict(record_type='ATTEMPT_END',payload=dict(attempt_sequence=n,disposition=end)))

    def result(self):return _classify(self.index,self.reader,self.headers,self.records,self.report)

    def test_actual_shape_gate_not_invoked_and_no_invented_sequence(self):
        self.exchange(1,{'error':{'code':'unauthorized'}},status=401)
        self.report['calls']=[dict(sequence=1,monotonic=dict(invoked=False))]
        value=self.result();self.assertEqual(len(value),6)
        self.assertEqual(value['rows'][0]['classification'],'PRE_OBSERVER_REJECT')
        self.assertEqual(value['rows'][0]['reason'],'AUTH');self.assertEqual(value['rows'][0]['attempt_sequences'],[])
        self.assertEqual(value['rows'][1]['location'],dict(report_call_sequence=1))
        self.assertEqual(value['rows'][1]['classification'],'NOT_INVOKED')
        self.assertTrue(all(len(row)==4 for row in value['rows']))

    def test_typed_and_cross_session_numbers_never_merge(self):
        for n,(rid,sid) in enumerate(((7,'session'),('7','session'),(7,'other')),1):
            self.exchange(rid,dict(jsonrpc='2.0',id=rid,error=dict(code=-1,message='wire')),sid=sid)
            self.attempt(n,rid,sid=sid,end='FAILED')
        self.assertEqual([r['attempt_sequences'] for r in self.result()['rows']],[[1],[2],[3]])
        self.assertTrue(all(r['classification']=='ACCEPTED_FAILED' for r in self.result()['rows']))

    def test_ack_unknown_and_wire_error_have_only_observed_numbers(self):
        self.exchange(1,dict(error=dict(code='invalid_or_unknown')));self.attempt(1,1,ack=False,end=None)
        self.exchange(2,dict(jsonrpc='2.0',id=2,error=dict(code=-1,message='wire')));self.attempt(2,2)
        rows=self.result()['rows'];self.assertEqual(rows[0]['reason'],'ACK_UNKNOWN')
        self.assertEqual(rows[0]['classification'],'ACCEPT_UNKNOWN')
        self.assertEqual(rows[1]['classification'],'ACCEPTED_COMPLETE_WITH_WIRE_ERROR')
        self.assertEqual(rows[1]['reason'],'WIRE_ERROR')

    def test_duplicate_unique_rejection_and_extra_raw_ambiguity(self):
        self.exchange(7,dict(jsonrpc='2.0',id=7,result={}))
        self.exchange(7,dict(jsonrpc='2.0',id=7,error=dict(code=-32600,message='DUPLICATE')))
        self.attempt(1,7);self.attempt(2,7,decision='REJECTED',reason='DUPLICATE',ack=False,end='REJECTED')
        rows=self.result()['rows'];self.assertEqual(rows[1]['classification'],'DUPLICATE_REJECT')
        self.assertEqual(rows[1]['attempt_sequences'],[2])
        self.exchange(7,dict(jsonrpc='2.0',id=7,result={}))
        rows=self.result()['rows'];self.assertEqual(rows[0]['classification'],'UNCLASSIFIED')
        self.assertEqual(rows[2]['attempt_sequences'],[])

    def test_no_source_does_not_guess_ack_or_accept(self):
        self.exchange(7,dict(error=dict(code='invalid_or_unknown')),status=503)
        row=self.result()['rows'][0];self.assertEqual(row['classification'],'UNCLASSIFIED')
        self.assertEqual(row['attempt_sequences'],[])
