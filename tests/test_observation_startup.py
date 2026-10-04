"""Installed host SDK and complete isolated approval trees; no native authority."""
import copy
from contextlib import redirect_stderr, redirect_stdout
import inspect
from io import StringIO
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import mcp_velociraptor_bridge as bridge
import velociraptor_observation_sdk as sdk
import velociraptor_observation_startup as startup
from tests import p05_pc026_governance as gov
from tests import test_observation_config as config_fixture
from tests.test_p05_pc026_governance import write, inventory


def model_budgets():
    return dict(max_sessions=2, max_sdk_work=32, max_binary_work=8, max_pending_work=8,
        max_request_body_bytes=65536, max_export_files=434, max_export_bytes=15482880,
        max_export_directories=25, max_cut_bytes=65536, max_proof_bytes=65536,
        max_source_manifest_bytes=65536, max_maintenance_calls=64,
        max_maintenance_bytes=1048576, max_retained_state_bytes=1048576,
        close_timeout_ns=300000000000, min_free_bytes=1048576)


class InstalledSDKTests(unittest.TestCase):
    def setUp(self):
        self.raw = (gov.REPOSITORY / sdk.PIN_PATH).read_bytes()

    def test_actual_installed_sources_versions_signatures_and_protocols(self):
        seen = []
        def read(path):
            seen.append(path)
            return path.read_bytes()
        pin = sdk._verify_installed(self.raw, read)
        self.assertEqual(len(seen), 15)
        self.assertEqual(len(set(seen)), 15)
        self.assertEqual(pin['versions']['mcp'], '2.1.1')
        mapping = json.loads((gov.REPOSITORY/'docs/observation-sdk-source-map.json').read_bytes())
        self.assertEqual(len(mapping['boundaries']), 8)
        self.assertEqual(mapping['total_source_lines'], 591)
        self.assertLessEqual(mapping['total_source_lines'], 700)
        for row in mapping['boundaries']:
            self.assertIn(dict(module=row['module'],symbol=row['symbol'],ast_sha256=row['ast_sha256']), pin['signatures'])

    def test_changed_pin_never_reads_dependency_sources(self):
        read = Mock()
        with self.assertRaisesRegex(sdk.SDKQualificationError, 'sdk_pin_drift'):
            sdk._verify_installed(self.raw + b' ', read)
        read.assert_not_called()

    def test_actual_version_comparison_rejects_before_source_read(self):
        version = sdk.importlib.metadata.version
        read = Mock()
        with patch.object(sdk.importlib.metadata, 'version',
                side_effect=lambda key: '2.1.2' if key == 'mcp' else version(key)), \
                self.assertRaisesRegex(sdk.SDKQualificationError, 'sdk_version_drift'):
            sdk._verify_installed(self.raw, read)
        read.assert_not_called()

    def test_each_actual_source_byte_drift_rejects_with_same_versions(self):
        for row in json.loads(self.raw)['modules']:
            target = Path(sdk.importlib.util.find_spec(row['module']).origin).absolute()
            def read(path):
                return path.read_bytes() + (b'\n# drift\n' if path == target else b'')
            with self.subTest(module=row['module']), \
                    self.assertRaisesRegex(sdk.SDKQualificationError, 'sdk_source_drift'):
                sdk._verify_installed(self.raw, read)


@unittest.skipUnless(os.name == 'posix', 'actual isolated POSIX approval graph')
class LifecyclePreflightTests(unittest.TestCase):
    def setUp(self):
        self.fixture = config_fixture.ConfigurationGraphTests('test_actual_fixed_loader_keeps_owned_group_and_input_outside_freeze')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.f = self.fixture.root, self.fixture.f
        from velociraptor_observation_config import CONFIG
        self.doc = dict(schema_version=1, kind='pc026-observation-lifecycle-configuration-v1',
            profile_id=gov.PROFILE, workflow_id=gov.evidence.WORKFLOW_ID,
            contract_ref=startup.CONTRACT_REF, archive_config_ref=self.f.refs[CONFIG],
            deployment_ref=self.f.refs[gov.DEPLOYMENT], implementation_freeze_ref=self.f.refs[gov.FREEZE],
            budgets=model_budgets(), metadata_policy='GLOBAL_PREFIX_NO_OTHER_SESSION_EVENTS', status='AUTHORIZED')
        # Positive read-only qualification follows the actual 1 MiB Reader
        # gate. Keep model_budgets() unchanged for historical MODEL cut tests.
        self.doc['budgets']['max_export_bytes'] = 224870400
        self.bind()

    def bind(self):
        self.f.refs[startup.CONFIG] = write(self.root, startup.CONFIG, self.doc)
        self.f.runtime()

    def precheck(self):
        archive = self.fixture.load()
        try:
            return startup._precheck_loaded(archive)
        finally:
            archive.group.close()

    def test_real_complete_loader_reads_actual_sdk_and_rechecks_without_writer(self):
        before = inventory(self.root)
        self.assertEqual(self.precheck(), self.doc)
        self.assertEqual(inventory(self.root), before)

    def test_config_exact_bindings_and_reserve_boundary(self):
        original = copy.deepcopy(self.doc)
        mutations = [lambda d: d.update(extra=1), lambda d: d.update(schema_version=True),
            lambda d: d.update(metadata_policy='FILTERED'),
            lambda d: d['archive_config_ref'].update(sha256='0'*64),
            lambda d: d['budgets'].update(max_sdk_work=True),
            lambda d: d['budgets'].update(max_export_bytes=224870399),
            lambda d: d['budgets'].update(max_export_files=433),
            lambda d: d['budgets'].update(max_export_directories=24)]
        for mutation in mutations:
            self.doc = copy.deepcopy(original)
            mutation(self.doc)
            self.bind()
            before = inventory(self.root)
            with self.subTest(mutation=mutation), self.assertRaises(Exception):
                self.precheck()
            self.assertEqual(inventory(self.root), before)

    def test_production_refuses_even_valid_model_graph_and_never_calls_backend_or_sdk_constructor(self):
        from velociraptor_transport import build_formal_http_app, TransportConfig
        config = TransportConfig('http', host='127.0.0.1', bearer_token='MODEL')
        server = Mock()
        before = inventory(self.root)
        with patch.object(gov, 'REPOSITORY', self.root), \
                self.assertRaisesRegex(startup.ObservationStartupError, 'native_exporter_unavailable'):
            build_formal_http_app(server, config)
        server.streamable_http_app.assert_not_called()
        failures, out, err = Mock(), StringIO(), StringIO()
        with patch.object(gov, 'REPOSITORY', self.root), \
                patch.object(bridge, 'resolve_transport_config', return_value=config), \
                patch.object(bridge, 'create_server') as create, patch.object(bridge, 'run_formal_http') as run, \
                redirect_stderr(err), redirect_stdout(out):
            self.assertEqual(bridge.main(on_failure=failures), 2)
        create.assert_not_called()
        run.assert_not_called()
        failures.assert_called_once_with('OBSERVATION_STARTUP_REJECTED')
        self.assertEqual(out.getvalue(), '')
        self.assertNotIn('MODEL', err.getvalue())
        self.assertEqual(inventory(self.root), before)

    def test_missing_approval_and_illegal_archive_root_reject_before_rpc(self):
        for failure in ('approval', 'root'):
            if failure == 'approval':
                path = self.root/gov.APPROVAL
                original = path.read_bytes()
                path.unlink()
            else:
                self.fixture.doc['guest_namespace_root'] = r'Q:\alias\..\root'
                self.fixture.bind()
            before = inventory(self.root)
            with patch.object(gov, 'REPOSITORY', self.root), \
                    patch.object(bridge, 'resolve_transport_config', return_value=SimpleNamespace(mode='http')), \
                    patch.object(bridge, 'create_server') as create, \
                    redirect_stderr(StringIO()), self.subTest(failure=failure):
                self.assertEqual(bridge.main(), 2)
            create.assert_not_called()
            self.assertEqual(inventory(self.root), before)
            if failure == 'approval':
                path.write_bytes(original)

    def test_fixed_production_entry_has_no_override_parameters(self):
        self.assertFalse(inspect.signature(startup.precheck_formal_http).parameters)

    def test_actual_reader_sd_bound_and_exact_export_reserve_before_sdk_reads(self):
        from tests.p05_pc026_windows_reader import MAX_SD_BYTES
        self.assertEqual(MAX_SD_BYTES,1048576)
        self.assertEqual(self.precheck(),self.doc)  # Actual complete graph/pin.
        for size in (15482880,224870399):
            self.doc['budgets']['max_export_bytes']=size;self.bind()
            before=inventory(self.root)
            with patch.object(startup,'_verify_approved_sdk') as sdk_gate,self.assertRaisesRegex(gov.GovernanceError,'reserves insufficient'):
                self.precheck()
            sdk_gate.assert_not_called();self.assertEqual(inventory(self.root),before)

    def test_rebound_omissions_and_cyclic_lifecycle_input_refuse(self):
        for path in (sdk.PIN_PATH, 'velociraptor_observation_sdk.py', startup.CONTRACT):
            saved = self.f.freeze.pop(path)
            self.f.refresh()
            self.fixture.doc['implementation_freeze_ref'] = self.f.refs[gov.FREEZE]
            self.fixture.bind()
            from velociraptor_observation_config import CONFIG
            self.doc['archive_config_ref'] = self.f.refs[CONFIG]
            self.doc['implementation_freeze_ref'] = self.f.refs[gov.FREEZE]
            self.bind()
            before = inventory(self.root)
            with self.subTest(path=path), self.assertRaises(Exception):
                self.precheck()
            self.assertEqual(inventory(self.root), before)
            self.f.freeze[path] = saved
        self.f.freeze[startup.CONFIG] = self.f.refs[startup.CONFIG]
        self.f.refresh()
        self.fixture.doc['implementation_freeze_ref'] = self.f.refs[gov.FREEZE]
        self.fixture.bind()
        self.doc['archive_config_ref'] = self.f.refs[CONFIG]
        self.doc['implementation_freeze_ref'] = self.f.refs[gov.FREEZE]
        self.bind()
        with self.assertRaisesRegex(gov.GovernanceError, 'cyclic'):
            self.precheck()


class StdioAndCloseTests(unittest.TestCase):
    def test_stdio_never_loads_lifecycle_or_archive(self):
        server = Mock()
        with patch.object(bridge, 'resolve_transport_config', return_value=SimpleNamespace(mode='stdio')), \
                patch.object(bridge, 'create_server', return_value=server), \
                patch.object(startup, 'load_approved', side_effect=AssertionError('archive I/O')):
            self.assertEqual(bridge.main(), 0)
        server.run.assert_called_once_with('stdio')

    def test_primary_is_preserved_when_read_only_governance_close_fails(self):
        primary = RuntimeError('MODEL-primary')
        group = Mock()
        group.close.side_effect = OSError('MODEL-close')
        with patch.object(startup, 'load_approved', return_value=SimpleNamespace(group=group)), \
                patch.object(startup, '_precheck_loaded', side_effect=primary), \
                self.assertRaises(RuntimeError) as caught:
            startup.precheck_formal_http()
        self.assertIs(caught.exception, primary)
        group.close.assert_called_once_with()
        self.assertIn('archive_governance_close_failed', primary.__notes__)
