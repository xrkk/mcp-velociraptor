import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('linux_deploy', Path(__file__).parents[1] / 'deploy/linux/deploy_remnux.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class DeployTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory(); self.addCleanup(self.t.cleanup)
        self.base = Path(self.t.name); self.root = self.base / 'vr'; self.data = self.base / 'data'
        self.binary = self.base / 'binary'; self.binary.write_bytes(b'MODEL')
        self.units = self.base / 'units'; self.units.mkdir()
        self.calls = []; self.fault = None
        self.tx = 'd0ac04b5-5c05-408c-b13c-58d578799c58'
        for name, value in [('secure_path', lambda p, **k: Path(p)), ('identity', lambda *a: None),
                            ('digest', lambda p: m.BINARY_SHA256), ('UNIT_DIRECTORY', self.units),
                            ('run', self.run_command), ('ready', self.ready)]:
            p = patch.object(m, name, value); p.start(); self.addCleanup(p.stop)
        p = patch.object(m.os, 'geteuid', return_value=0); p.start(); self.addCleanup(p.stop)
        p = patch.object(m.socket, 'socket'); self.socket = p.start(); self.addCleanup(p.stop)

    def run_command(self, argv, timeout=30):
        a = list(map(str, argv)); self.calls.append(a)
        if a[-1] == 'version': return b'version: 0.77.3\n'
        if a[0] == 'systemctl':
            if 'show' in a: return b'not-found\n'
            if 'enable' in a and self.fault == 'start': raise m.Refused('COMMAND_FAILED')
            return b''
        if 'generate' in a:
            v = m.settings(self.root, self.data); v['Monitoring'] = {}; v['CA'] = {'private_key': 'MODEL'}
            v['Client'].update(ca_certificate='MODEL', nonce='MODEL'); return json.dumps(v).encode()
        if 'show' in a:
            if self.fault == 'missing-config' and 'server.config.yaml' in a[a.index('--config')+1]: return b'{}'
            return Path(a[a.index('--config')+1]).read_bytes()
        if a[-1] == 'client': return (self.root / 'server.config.yaml').read_bytes()
        if 'api_client' in a: Path(a[-1]).write_text('MODEL'); return b''
        self.fail(a)

    def ready(self, *a):
        if self.fault == 'ready': raise m.Refused('NOT_READY')
        return {'client_id': 'C.123', 'services_ready': True, 'api_ready': True}

    def deploy(self):
        return m.deploy(self.binary, self.root, self.data, self.tx, 'uuid', 'boot', 5)

    def test_success_and_readonly_reentry(self):
        self.assertEqual(self.deploy()['status'], 'READY'); before = list(self.calls)
        self.assertIsNone(json.loads((self.root/'server.config.yaml').read_text())['Monitoring'])
        self.assertEqual(self.deploy()['status'], 'READY')
        self.assertFalse(any('enable' in a for a in self.calls[len(before):]))
        self.assertEqual(stat.S_IMODE((self.root/'server.config.yaml').stat().st_mode), 0o600)

    def test_bad_hash_before_write(self):
        with patch.object(m, 'digest', return_value='0'*64), self.assertRaisesRegex(m.Refused, 'BINARY_HASH'):
            self.deploy()
        self.assertFalse(self.root.exists()); self.assertFalse(self.calls)

    def test_path_and_overlap_before_write(self):
        for root, data in [(Path('relative'), self.data), (self.root, self.root/'data')]:
            with self.assertRaises(m.Refused):
                m.deploy(self.binary, root, data, self.tx, 'uuid', 'boot')
        self.assertFalse(self.root.exists())

    def test_existing_datastore_and_units_preserved(self):
        self.data.mkdir(); (self.data/'old').write_bytes(b'original')
        with self.assertRaisesRegex(m.Refused, 'DATASTORE_CONFLICT'): self.deploy()
        self.assertEqual((self.data/'old').read_bytes(), b'original'); self.assertFalse(self.root.exists())
        self.data.joinpath('old').unlink(); self.data.rmdir()
        (self.units/m.UNITS[0]).write_bytes(b'foreign')
        with self.assertRaisesRegex(m.Refused, 'UNIT_CONFLICT'): self.deploy()
        self.assertEqual((self.units/m.UNITS[0]).read_bytes(), b'foreign')

    def test_missing_config_and_partial_reentry(self):
        self.fault = 'missing-config'
        with self.assertRaises(m.Refused): self.deploy()
        self.assertFalse(any('enable' in a for a in self.calls))
        original = (self.root/'server.config.yaml').read_bytes()
        with self.assertRaises(FileNotFoundError): self.deploy()
        self.assertEqual((self.root/'server.config.yaml').read_bytes(), original)
        self.assertTrue((self.root/f'deployment-{self.tx}/failure.json').is_file())

    def test_start_failure_stops_only_owned_unit(self):
        self.fault = 'start'
        with self.assertRaises(m.Refused): self.deploy()
        stops = [a for a in self.calls if 'disable' in a]
        self.assertEqual(stops, [['systemctl','disable','--now',m.UNITS[0]]])
        self.assertFalse((self.root/'deployment-complete.json').exists())

    def test_ready_failure_never_publishes_ready(self):
        self.fault = 'ready'
        with patch.object(m.time, 'monotonic', side_effect=[0,6]), self.assertRaisesRegex(m.Refused, 'READY_TIMEOUT'):
            self.deploy()
        self.assertEqual(len([a for a in self.calls if 'disable' in a]), 2)
        self.assertFalse((self.root/'deployment-complete.json').exists())

    def test_port_conflict_before_write(self):
        self.socket.return_value.__enter__.return_value.bind.side_effect = OSError('MODEL busy')
        with self.assertRaisesRegex(m.Refused, 'PORT_CONFLICT'): self.deploy()
        self.assertFalse(self.root.exists())

    def test_owner_gate_before_mutation(self):
        with patch.object(m, 'secure_path', side_effect=m.Refused('PATH_OWNER_OR_MODE')):
            with self.assertRaisesRegex(m.Refused, 'PATH_OWNER_OR_MODE'): self.deploy()
        self.assertFalse(self.root.exists()); self.assertFalse(self.calls)


class PathTests(unittest.TestCase):
    def test_actual_unprotected_directory_refused(self):
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaises(m.Refused): m.secure_path(Path(name), directory=True)

    def test_concatenated_query_pages(self):
        self.assertEqual(m.json_stream(b'[{"a":1}]\n[{"a":2}]\n'), [{'a':1},{'a':2}])
        with self.assertRaises(m.Refused): m.json_stream(b'{}')

if __name__ == '__main__': unittest.main()
