"""Context-selected codec rejection precedes every business entry."""
import hashlib
import json
import unittest
from velo_transfer import wire


class CodecTests(unittest.TestCase):
    def raw(self, header, payload=b''):
        if not isinstance(header, bytes):
            header = json.dumps(header).encode()
        return b'VBT1' + len(header).to_bytes(4, 'little') + header + payload

    def test_push_and_pull_response_roundtrip(self):
        payload = b'abcdef'
        meta = [{'count': 3, 'chunk_sha256': hashlib.sha256(p).hexdigest()} for p in (b'abc', b'def')]
        header = {'chunks': meta}
        self.assertEqual(wire.decode(wire.encode(header, payload, 'push_request'), 'push_request'), (header, payload))
        items = [dict(m, offset=i*3) for i, m in enumerate(meta)]
        header = {'status': 'success', 'result': {'verified_offset': 6, 'chunks': items}}
        self.assertEqual(wire.decode(wire.encode(header, payload, 'pull_response'), 'pull_response'), (header, payload))

    def test_strict_header_and_payload_rejection(self):
        good = {'chunks': [{'count': 3, 'chunk_sha256': hashlib.sha256(b'abc').hexdigest()}]}
        bad = [b'{"chunks":[],"chunks":[]}', b'{"chunks":NaN}', b'{"chunks":Infinity}', b'\xff', b'[]', b'{}',
               {'chunks': [{'count': True, 'chunk_sha256': 'a'*64}]},
               {'chunks': [{'count': 3.0, 'chunk_sha256': 'a'*64}]},
               dict(good, extra=0), {'chunks': good['chunks'] + [{'count': 1, 'chunk_sha256': 'a'*64}]}]
        for header in bad:
            with self.subTest(header=header), self.assertRaises(wire.WireError):
                wire.decode(self.raw(header, b'abc'), 'push_request')
        for payload in (b'ab', b'abcd', b'xxx'):
            with self.assertRaises(wire.WireError):wire.decode(self.raw(good,payload),'push_request')
        for body in (b'', b'XXXX'+b'\0'*4, b'VBT1'+(wire.HEADER_LIMIT+1).to_bytes(4,'little')):
            with self.assertRaises(wire.WireError):wire.decode(body,'push_request')

    def test_pull_requires_empty_frame_and_response_contiguity(self):
        self.assertEqual(wire.decode(self.raw({}), 'pull_request'), ({}, b''))
        for body in (b'', self.raw({}, b'x'), self.raw({'offset':0})):
            with self.assertRaises(wire.WireError):wire.decode(body, 'pull_request')
        h={'status':'success','result':{'verified_offset':2,'chunks':[{'offset':0,'count':1,'chunk_sha256':hashlib.sha256(b'x').hexdigest()}]}}
        with self.assertRaises(wire.WireError):wire.decode(self.raw(h,b'x'),'pull_response')

    def test_exact_headers(self):
        headers=[(b'x-velo-direction', b'pull'),(b'x-velo-transfer-id',b't'),(b'x-velo-request-digest',b'a'*64),
                 (b'x-velo-offset',b'0'),(b'x-velo-count-per-chunk',b'3'),(b'x-velo-chunk-count',b'2')]
        self.assertEqual(wire.request_headers(headers)[1]['chunk_count'],2)
        for value in (b'00',b' 0',b'0 ',b'+0',b'0,0',b'-1',b'0.0'):
            with self.subTest(value=value), self.assertRaises(wire.WireError):
                wire.request_headers(headers[:3]+[(b'x-velo-offset',value)]+headers[4:])
        with self.assertRaises(wire.WireError):wire.request_headers(headers+[(b'X-Velo-Offset',b'0')])
        with self.assertRaises(wire.WireError):wire.request_headers([(k,b'push' if k==b'x-velo-direction' else v) for k,v in headers])

    def test_error_codes_never_details(self):
        for h in ({'status':'error','error':{'code':'internal_error','detail':'secret'}},
                  {'status':'error','error':{'code':'arbitrary'}}):
            with self.assertRaises(wire.WireError):wire.decode(self.raw(h),'error_response')
        h={'status':'error','error':{'code':'internal_error'}}
        self.assertEqual(wire.decode(wire.encode(h,b'','error_response'),'error_response'),(h,b''))
