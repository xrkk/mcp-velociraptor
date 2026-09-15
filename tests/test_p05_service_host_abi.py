"""Windows-only ABI checks without installing or starting an SCM service."""
import ctypes
from contextlib import nullcontext
from ctypes import wintypes
import os
import json
import sys
import threading
import types
import unittest
from unittest.mock import MagicMock, Mock, mock_open, patch

_SETTINGS = {
    'VELOCIRAPTOR_MCP_TRANSPORT': 'http',
    'VELOCIRAPTOR_MCP_HOST': '192.0.2.10',
    'VELOCIRAPTOR_MCP_BEARER_TOKEN': 'synthetic-unit-test-value-not-a-credential',
    'VELOCIRAPTOR_API_CONFIG': 'deployment-api.yaml',
    'VELOCIRAPTOR_DOWNLOAD_ROOT': 'deployment-downloads',
}
_CONFIG_TEXT = '\n'.join(f'{key}={value}' for key, value in _SETTINGS.items())


@unittest.skipUnless(os.name == 'nt', 'requires the real Windows ctypes ABI')
class ServiceHostABITests(unittest.TestCase):
    def setUp(self):
        from tests import p05_service_host
        self.host = p05_service_host
        old_handle, old_exit = self.host._status_handle, self.host._exit_code
        self.addCleanup(setattr, self.host, '_status_handle', old_handle)
        self.addCleanup(setattr, self.host, '_exit_code', old_exit)

    def test_handler_matches_non_extended_windows_prototype(self):
        self.assertEqual(self.host._HANDLER._argtypes_, (wintypes.DWORD,))
        self.assertIsNone(self.host._HANDLER._restype_)

    def test_service_main_takes_argument_vector_not_single_string(self):
        self.assertEqual(self.host._SERVICE_MAIN._argtypes_,
                         (wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR)))
        self.assertIs(self.host.SERVICE_TABLE_ENTRYW._fields_[1][1], self.host._SERVICE_MAIN)

    def test_stop_callback_dispatches_one_control_value(self):
        with patch.object(self.host, '_stop_requested', threading.Event()), patch.object(self.host, '_report') as report:
            self.host._service_handler(1)
            self.assertTrue(self.host._stop_requested.is_set())
            report.assert_called_once_with(self.host.SERVICE_STATUS['STOP_PENDING'])

    def test_failed_registration_cannot_report_ready(self):
        api = Mock()
        api.RegisterServiceCtrlHandlerW.return_value = None
        with patch.object(self.host, 'advapi32', api), patch.object(self.host, '_report') as report:
            self.host._service_main(0, None)
        report.assert_not_called()
        self.assertNotEqual(self.host._exit_code, 0)
        self.assertIs(api.RegisterServiceCtrlHandlerW.call_args.args[1], self.host._service_handler)

    def test_dispatcher_returns_service_failure_instead_of_zero(self):
        api = Mock()
        api.StartServiceCtrlDispatcherW.return_value = True
        with patch.object(self.host, 'advapi32', api), patch.object(self.host, '_exit_code', 10):
            self.assertEqual(self.host.main(), 10)

    def test_missing_configuration_file_does_not_fall_through(self):
        path = Mock()
        path.is_file.return_value = False
        with patch.dict(os.environ, {'VELOCIRAPTOR_ENV_FILE': 'missing.env'}, clear=True), \
                patch.object(self.host, 'Path', return_value=path):
            with self.assertRaisesRegex(ValueError, 'file is unavailable'):
                self.host._load_protected_env()
        path.read_text.assert_not_called()

    def test_missing_registry_reference_fails_closed(self):
        registry = Mock()
        registry.OpenKey.side_effect = OSError('synthetic-sensitive-diagnostic')
        with patch.dict(os.environ, {}, clear=True), \
                patch.dict(sys.modules, {'winreg': registry}):
            with self.assertRaisesRegex(RuntimeError, '^Service configuration reference is unavailable$'):
                self.host._load_protected_env()

    def test_registry_reads_only_the_string_reference(self):
        registry = Mock()
        registry.REG_SZ = 1
        registry.QueryValueEx.return_value = ('deployment.env', 1)
        path = Mock()
        path.is_file.return_value = True
        path.read_text.return_value = _CONFIG_TEXT
        with patch.dict(os.environ, {}, clear=True), \
                patch.dict(sys.modules, {'winreg': registry}), \
                patch.object(self.host, 'Path', return_value=path):
            self.host._load_protected_env()
            self.assertEqual(dict(os.environ), {
                'VELOCIRAPTOR_ENV_FILE': 'deployment.env',
                **_SETTINGS,
            })
        registry.QueryValueEx.assert_called_once_with(
            registry.OpenKey.return_value, 'VELOCIRAPTOR_ENV_FILE')
        registry.EnumValue.assert_not_called()
        registry.CloseKey.assert_called_once_with(registry.OpenKey.return_value)

    def test_missing_required_key_does_not_partially_load_environment(self):
        path = Mock()
        path.is_file.return_value = True
        path.read_text.return_value = '\n'.join(f'{key}={value}' for key, value in _SETTINGS.items()
                                              if key != 'VELOCIRAPTOR_DOWNLOAD_ROOT')
        original = {'VELOCIRAPTOR_ENV_FILE': 'deployment.env'}
        with patch.dict(os.environ, original, clear=True), patch.object(self.host, 'Path', return_value=path):
            with self.assertRaisesRegex(ValueError, 'required formal service settings'):
                self.host._load_protected_env()
            self.assertEqual(dict(os.environ), original)

    def test_duplicate_and_conflicting_configuration_are_rejected(self):
        path = Mock()
        path.is_file.return_value = True
        for content, extra in ((_CONFIG_TEXT + '\nVELOCIRAPTOR_MCP_HOST=192.0.2.11', {}),
                               (_CONFIG_TEXT, {'VELOCIRAPTOR_MCP_HOST': '192.0.2.11'})):
            with self.subTest(extra=bool(extra)), \
                    patch.dict(os.environ, {'VELOCIRAPTOR_ENV_FILE': 'deployment.env', **extra}, clear=True), \
                    patch.object(self.host, 'Path', return_value=path):
                path.read_text.return_value = content
                with self.assertRaises(ValueError):
                    self.host._load_protected_env()

    def test_registry_array_reference_is_rejected_and_handle_closed(self):
        registry = Mock()
        registry.REG_SZ = 1
        registry.QueryValueEx.return_value = (['deployment.env'], 7)
        with patch.dict(os.environ, {}, clear=True), \
                patch.dict(sys.modules, {'winreg': registry}):
            with self.assertRaisesRegex(ValueError, 'reference type'):
                self.host._load_protected_env()
        registry.CloseKey.assert_called_once_with(registry.OpenKey.return_value)

    def test_failed_bridge_diagnostics_are_not_persisted(self):
        api = Mock()
        api.RegisterServiceCtrlHandlerW.return_value = 1
        root = MagicMock()
        bridge = Mock()

        def fail_bridge(**kwargs):
            kwargs['on_failure']('ARTIFACT_REGISTRY_INVALID')
            print('synthetic-sensitive-diagnostic', file=sys.stderr)
            return 2

        bridge.main.side_effect = fail_bridge
        sink = mock_open()
        observation = types.ModuleType('p05_service_observation')
        observation.observe_dispatch = Mock(return_value=nullcontext())
        with patch.object(self.host, 'advapi32', api), \
                patch.object(self.host, '_report'), \
                patch.object(self.host, '_load_protected_env'), \
                patch.object(self.host, 'REPO_ROOT', root), \
                patch.object(sys, 'path', list(sys.path)), \
                patch.dict(sys.modules, {
                    'mcp_velociraptor_bridge': bridge,
                    'p05_service_observation': observation,
                }), \
                patch('builtins.open', sink):
            self.host._service_main(0, None)
        sink.assert_called_once_with(os.devnull, 'w', encoding='utf-8')
        log = root.__truediv__.return_value.__truediv__.return_value
        log.write_text.assert_called_once()
        payload = json.loads(log.write_text.call_args.args[0])
        self.assertEqual(payload['code'], 'ARTIFACT_REGISTRY_INVALID')
        self.assertEqual(payload['exit_code'], 2)
        self.assertIn('artifact', payload['message'])
        self.assertNotIn('synthetic-sensitive-diagnostic', log.write_text.call_args.args[0])
        observation.observe_dispatch.assert_called_once_with(root.__truediv__.return_value)
        self.assertEqual(self.host._exit_code, 2)

    def test_observation_setup_failure_has_only_the_fixed_public_classification(self):
        api = Mock()
        api.RegisterServiceCtrlHandlerW.return_value = 1
        root = MagicMock()
        observation = types.ModuleType('p05_service_observation')

        class FailingObservation:
            def __enter__(self):
                raise RuntimeError('synthetic-sensitive-observation-detail')

            def __exit__(self, *unused):
                return False

        observation.observe_dispatch = Mock(return_value=FailingObservation())
        with patch.object(self.host, 'advapi32', api), \
                patch.object(self.host, '_report'), \
                patch.object(self.host, '_load_protected_env'), \
                patch.object(self.host, 'REPO_ROOT', root), \
                patch.object(sys, 'path', list(sys.path)), \
                patch.dict(sys.modules, {'p05_service_observation': observation}):
            self.host._service_main(0, None)
        log = root.__truediv__.return_value.__truediv__.return_value
        payload = json.loads(log.write_text.call_args.args[0])
        self.assertEqual(payload['code'], 'SERVICE_OBSERVATION_INVALID')
        self.assertNotIn('synthetic-sensitive-observation-detail', log.write_text.call_args.args[0])

    def test_unknown_failure_text_cannot_enter_structured_log(self):
        root = MagicMock()
        with patch.object(self.host, 'REPO_ROOT', root):
            self.host._write_failure('synthetic-sensitive-diagnostic', 10)
        log = root.__truediv__.return_value.__truediv__.return_value
        raw = log.write_text.call_args.args[0]
        self.assertNotIn('synthetic-sensitive-diagnostic', raw)
        self.assertEqual(json.loads(raw)['code'], 'BRIDGE_EXIT_FAILED')


if __name__ == '__main__':
    unittest.main()
