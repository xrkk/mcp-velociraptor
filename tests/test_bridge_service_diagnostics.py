"""Service diagnostic classifications without backend or socket operations."""
from contextlib import redirect_stderr
from io import StringIO
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import mcp_velociraptor_bridge as bridge


class BridgeServiceDiagnosticsTests(unittest.TestCase):
    def test_invalid_configuration_is_classified_before_registration(self):
        failure = Mock()
        with patch.object(bridge, 'resolve_transport_config', side_effect=bridge.TransportConfigError('synthetic')), \
                patch.object(bridge, 'create_server') as create, redirect_stderr(StringIO()):
            self.assertEqual(bridge.main(on_failure=failure), 2)
        failure.assert_called_once_with('TRANSPORT_CONFIG_INVALID')
        create.assert_not_called()

    def test_stdio_service_hooks_are_rejected_before_registration(self):
        failure = Mock()
        with patch.object(bridge, 'resolve_transport_config', return_value=SimpleNamespace(mode='stdio')), \
                patch.object(bridge, 'create_server') as create, redirect_stderr(StringIO()):
            self.assertEqual(bridge.main(on_ready=Mock(), on_failure=failure), 2)
        failure.assert_called_once_with('SERVICE_TRANSPORT_INVALID')
        create.assert_not_called()

    def test_registry_failure_has_a_fixed_public_classification(self):
        failure = Mock()
        with patch.object(bridge, 'resolve_transport_config', return_value=SimpleNamespace(mode='http')), \
                patch.object(bridge, 'create_server', side_effect=bridge.ArtifactRegistryError('synthetic-sensitive-value')), \
                patch.object(bridge, 'run_formal_http') as run, redirect_stderr(StringIO()):
            self.assertEqual(bridge.main(on_failure=failure), 2)
        failure.assert_called_once_with('ARTIFACT_REGISTRY_INVALID')
        run.assert_not_called()

    def test_backend_exception_text_is_not_passed_to_service(self):
        failure = Mock()
        with patch.object(bridge, 'resolve_transport_config', return_value=SimpleNamespace(mode='http')), \
                patch.object(bridge, 'create_server', side_effect=RuntimeError('synthetic-sensitive-value')), \
                patch.object(bridge, 'run_formal_http') as run, redirect_stderr(StringIO()):
            self.assertEqual(bridge.main(on_failure=failure), 2)
        failure.assert_called_once_with('BACKEND_INITIALIZATION_FAILED')
        run.assert_not_called()

    def test_success_preserves_single_existing_http_runner(self):
        config, server = SimpleNamespace(mode='http'), Mock()
        ready, stop, failure = Mock(), Mock(), Mock()
        with patch.object(bridge, 'resolve_transport_config', return_value=config), \
                patch.object(bridge, 'create_server', return_value=server) as create, \
                patch.object(bridge, 'run_formal_http') as run:
            self.assertEqual(bridge.main(on_ready=ready, stop_requested=stop, on_failure=failure), 0)
        create.assert_called_once_with()
        run.assert_called_once_with(server, config, on_ready=ready, stop_requested=stop)
        failure.assert_not_called()


if __name__ == '__main__':
    unittest.main()
