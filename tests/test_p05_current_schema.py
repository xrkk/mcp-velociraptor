"""Replay captured public schemas; no VM, credentials or Phase qualification."""
import copy
import hashlib
import json
import unittest
from pathlib import Path
from tests import p05_current_schema as schema_policy


def digest(data):
    return hashlib.sha256(data).hexdigest()


class RealSchemaTests(unittest.TestCase):
    def setUp(self):
        self.formal = (Path(__file__).parent / 'fixtures' / 'p05_current_136_tools_schema.json').read_bytes()
        self.listing = {'tools': json.loads(self.formal)}
        projected = [{'name': row['name'], 'input': row['inputSchema'], 'output': row['outputSchema']}
                     for row in self.listing['tools']]
        self.diagnostic = json.dumps(projected, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    def reject(self,change):
        data=copy.deepcopy(self.listing);change(data)
        with self.assertRaises(ValueError):schema_policy.validate_current(data,self.formal)
    def test_real_136_two_domains(self):
        schema_policy.validate_current(self.listing,self.formal,diagnostic_bytes=self.diagnostic)
        self.assertEqual(digest(self.formal),schema_policy.PHASE_SHA256)
        self.assertEqual(digest(self.diagnostic),schema_policy.DIAGNOSTIC_SHA256)
        self.assertNotEqual(self.formal,self.diagnostic)
    def test_wrong_input(self):self.reject(lambda d:d['tools'][0].update(inputSchema={'type':'null'}))
    def test_wrong_output(self):self.reject(lambda d:d['tools'][0].update(outputSchema={'type':'null'}))
    def test_missing_tool(self):self.reject(lambda d:d['tools'].pop())
    def test_extra_tool(self):self.reject(lambda d:d['tools'].append({**d['tools'][0],'name':'extra_name'}))
    def test_duplicate_name(self):self.reject(lambda d:d['tools'][1].update(name=d['tools'][0]['name']))
    def test_diagnostic_not_phase(self):
        with self.assertRaises(ValueError):schema_policy.validate_current(self.listing,self.diagnostic)
    def test_wrong_lf(self):
        with self.assertRaises(ValueError):schema_policy.validate_current(self.listing,self.formal.rstrip(b'\n'))

    def test_order_does_not_change_identity(self):
        self.listing['tools'].reverse()
        schema_policy.validate_current(self.listing, self.formal, diagnostic_bytes=self.diagnostic)

    def test_formal_not_diagnostic(self):
        with self.assertRaises(ValueError):
            schema_policy.validate_current(self.listing, self.formal, diagnostic_bytes=self.formal)

    def test_missing_output_schema(self):
        self.reject(lambda data: data['tools'][0].pop('outputSchema'))
