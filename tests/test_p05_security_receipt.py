"""Synthetic offline receipt tests. No collector, VM, HTTP or Phase activation."""
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from tests import p05_security_receipt as receipt


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


class SecurityReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        h = lambda ch: ch * 64
        self.trust = {'receipt_sha256': h('0'), 'collector_sha256': h('a'),
                      'collector_instance': 'collector-fictional',
                      'run_id': 'run-fictional', 'restore_attempt_id': 'restore-fictional',
                      'vm_uuid': 'vm-fictional', 'boot_id': 'boot-fictional',
                      'server_identity': {'pid': 123, 'instance_id': 'server-fictional'},
                      'network_evidence_sha256': h('b'), 'ready_sha256': h('c'),
                      'source_inputs_sha256': h('d'), 'implementation_sources_sha256': h('e'),
                      'tools_schema_sha256': h('f'), 'acl_sha256': h('1'),
                      'guest_root_sha256': h('2'), 'transfer_policy_enabled': False,
                      'transfer_policy_sha256': None, 'fixed_ip': '192.0.2.12',
                      'host_source': '192.0.2.1', 'guest_port': 28790, 'tools_count': 136,
                      'command_argv': {label: ['collector-fictional', label]
                                       for label in receipt.LABELS}}
        originals = {}
        for name in ('sdk', 'wfp'):
            content = f'FICTIONAL {name} original; integrity only'.encode()
            (self.root / f'{name}.raw').write_bytes(content)
            originals[name] = {'path': f'{name}.raw', 'size': len(content), 'sha256': sha(content)}
        t = self.trust
        values = {
            'service': {'running': True, 'pid': 123, 'instance_id': 'server-fictional',
                        'vm_uuid': t['vm_uuid'], 'boot_id': t['boot_id']},
            'policy': {'transfer_enabled': False, 'transfer_policy_sha256': None},
            'acl': {'approved': True, 'acl_sha256': t['acl_sha256'],
                    'root_sha256': t['guest_root_sha256']},
            'entry': {'allowed_status': 200, 'missing_bearer_status': 401,
                      'wrong_bearer_status': 401, 'wrong_host_status': 421,
                      'wrong_origin_status': 403},
            'schema': {'http_sha256': t['tools_schema_sha256'],
                       'stdio_sha256': t['tools_schema_sha256'], 'count': 136, 'unique': 136},
            'network': {'fixed_ip': t['fixed_ip'], 'host_source': t['host_source'],
                        'guest_port': 28790, 'rule_enabled': True,
                        'network_evidence_sha256': t['network_evidence_sha256']}}
        commands = []
        for sequence, label in enumerate(receipt.LABELS, 1):
            stdout = encoded(values[label]).decode()
            commands.append({'sequence': sequence, 'label': label,
                             'argv': ['collector-fictional', label], 'exit_code': 0,
                             'stdout': stdout, 'stdout_sha256': sha(stdout.encode()),
                             'stderr': '', 'collector_instance': 'collector-fictional',
                             'run_id': t['run_id'], 'restore_attempt_id': t['restore_attempt_id']})
        self.raw = {'schema_version': 1, 'kind': 'p05-security-command-receipt-v1',
                    'run_id': t['run_id'], 'restore_attempt_id': t['restore_attempt_id'],
                    'collector_sha256': t['collector_sha256'], 'collector_instance': 'collector-fictional',
                    'vm_uuid': t['vm_uuid'], 'boot_id': t['boot_id'],
                    'server_identity': t['server_identity'],
                    **{name: t[name] for name in ('network_evidence_sha256', 'ready_sha256',
                                                   'source_inputs_sha256', 'implementation_sources_sha256',
                                                   'tools_schema_sha256')},
                    'native_originals': originals, 'commands': commands}

    def check(self, raw=None, trust=None, *, keep_hash=False):
        content = encoded(self.raw if raw is None else raw)
        (self.root / 'receipt.json').write_bytes(content)
        ref = {'path': 'receipt.json', 'size': len(content), 'sha256': sha(content)}
        policy = copy.deepcopy(self.trust if trust is None else trust)
        if not keep_hash:
            policy['receipt_sha256'] = ref['sha256']
        return receipt.inspect_receipt(self.root, ref, trust=policy)

    def reject(self, edit, *, trust_edit=None):
        raw = copy.deepcopy(self.raw)
        edit(raw)
        trust = copy.deepcopy(self.trust)
        if trust_edit:
            trust_edit(trust)
        with self.assertRaises(receipt.ReceiptError):
            self.check(raw, trust)

    def test_schema_and_absent_transfer_policy(self):
        Draft202012Validator.check_schema(json.loads(receipt.SCHEMA.read_text()))
        result = self.check()
        self.assertEqual(result['observations']['entry']['wrong_host_status'], 421)
        self.assertFalse(result['observations']['policy']['transfer_enabled'])
        self.assertFalse(result['native_provenance_verified'])
        self.assertFalse(result['phase_admission'])

    def test_enabled_transfer_policy_when_explicitly_trusted(self):
        raw = copy.deepcopy(self.raw)
        raw['commands'][1]['stdout'] = encoded({'transfer_enabled': True,
                                                  'transfer_policy_sha256': '3'*64}).decode()
        raw['commands'][1]['stdout_sha256'] = sha(raw['commands'][1]['stdout'].encode())
        trust = copy.deepcopy(self.trust)
        trust['transfer_policy_enabled'] = True
        trust['transfer_policy_sha256'] = '3'*64
        self.assertTrue(self.check(raw, trust)['observations']['policy']['transfer_enabled'])

    def test_wrong_host_403_rejected_even_after_rehash(self):
        def change(raw):
            value = json.loads(raw['commands'][3]['stdout'])
            value['wrong_host_status'] = 403
            raw['commands'][3]['stdout'] = encoded(value).decode()
            raw['commands'][3]['stdout_sha256'] = sha(raw['commands'][3]['stdout'].encode())
        self.reject(change)

    def test_acl_false_rejected_even_after_rehash(self):
        def change(raw):
            value = json.loads(raw['commands'][2]['stdout'])
            value['approved'] = False
            raw['commands'][2]['stdout'] = encoded(value).decode()
            raw['commands'][2]['stdout_sha256'] = sha(raw['commands'][2]['stdout'].encode())
        self.reject(change)

    def test_boolean_integer_spoof_rejected_after_rehash(self):
        def change(raw):
            value = json.loads(raw['commands'][2]['stdout'])
            value['approved'] = 1
            raw['commands'][2]['stdout'] = encoded(value).decode()
            raw['commands'][2]['stdout_sha256'] = sha(raw['commands'][2]['stdout'].encode())
        self.reject(change)

    def test_external_pin_is_mandatory(self):
        with self.assertRaises(receipt.ReceiptError):
            self.check(keep_hash=True)
        self.reject(lambda raw: None, trust_edit=lambda trust: trust.pop('collector_sha256'))
        self.reject(lambda raw: None, trust_edit=lambda trust: trust.update(boot_id='wrong'))
        self.reject(lambda raw: None, trust_edit=lambda trust: trust.update(source_inputs_sha256='9'*64))

    def test_identity_and_command_refusals(self):
        self.reject(lambda raw: raw.update(boot_id='wrong'))
        self.reject(lambda raw: raw.update(source_inputs_sha256='9'*64))
        self.reject(lambda raw: raw['commands'][0].update(exit_code=1))
        self.reject(lambda raw: raw['commands'][0].update(sequence=True))
        self.reject(lambda raw: raw['server_identity'].update(pid=True))
        self.reject(lambda raw: raw['commands'][0].update(unexpected='yes'))
        self.reject(lambda raw: raw['commands'][0].update(stdout_sha256='9'*64))
        self.reject(lambda raw: raw['commands'][0].update(label='acl'))
        self.reject(lambda raw: raw['commands'][0].update(argv=['another-collector']))
        self.reject(lambda raw: raw['commands'][0].update(stdout='{"ok":true}'))

    def test_ref_and_duplicate_json_refusals(self):
        self.reject(lambda raw: raw['native_originals']['wfp'].update(sha256='9'*64))
        self.reject(lambda raw: raw['native_originals']['sdk'].update(path='../sdk.raw'))
        self.reject(lambda raw: raw.update(extra='yes'))
        raw = copy.deepcopy(self.raw)
        raw['commands'][0]['stdout'] = '{"running":true,"running":true}'
        raw['commands'][0]['stdout_sha256'] = sha(raw['commands'][0]['stdout'].encode())
        with self.assertRaises(receipt.ReceiptError):
            self.check(raw)
        content = encoded(self.raw).replace(b'"run_id":"run-fictional"',
                                            b'"run_id":"run-fictional","run_id":"run-fictional"', 1)
        (self.root / 'receipt.json').write_bytes(content)
        ref = {'path': 'receipt.json', 'size': len(content), 'sha256': sha(content)}
        trust = copy.deepcopy(self.trust)
        trust['receipt_sha256'] = ref['sha256']
        with self.assertRaises(receipt.ReceiptError):
            receipt.inspect_receipt(self.root, ref, trust=trust)

    def test_no_side_effects(self):
        self.check()
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        self.check()
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_cli_uses_same_offline_gate(self):
        self.check()
        data = (self.root / 'receipt.json').read_bytes()
        reference = {'path': 'receipt.json', 'size': len(data), 'sha256': sha(data)}
        (self.root / 'ref.json').write_bytes(encoded(reference))
        trust = copy.deepcopy(self.trust)
        trust['receipt_sha256'] = reference['sha256']
        (self.root / 'trust.json').write_bytes(encoded(trust))
        command = [sys.executable, '-m', 'tests.p05_security_receipt', '--bundle', str(self.root),
                   '--receipt-ref', str(self.root / 'ref.json'),
                   '--trusted-context', str(self.root / 'trust.json')]
        ok = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertFalse(json.loads(ok.stdout)['phase_admission'])
        trust['boot_id'] = 'other-boot'
        (self.root / 'trust.json').write_bytes(encoded(trust))
        refused = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(refused.returncode, 2)
        self.assertIn('boot_id', refused.stderr)


if __name__ == '__main__':
    unittest.main()
