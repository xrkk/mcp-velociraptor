"""Replay the deployed SCM stop callback without starting a Windows service."""

import ast
from contextlib import nullcontext
import os
from pathlib import Path
import sys
import threading
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch


HOST = Path(__file__).with_name("p05_service_host.py")


def load_host_function(name, namespace):
    """Compile one deployed function with fake SCM primitives."""
    tree = ast.parse(HOST.read_text(encoding="utf-8"), filename=str(HOST))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == name)
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(HOST), "exec"), namespace)
    return namespace[name]


class ServiceStopOrderTests(unittest.TestCase):
    def test_pending_is_reported_before_bridge_observes_stop(self):
        events = []
        status = {"STOP_PENDING": 3, "STOPPED": 1}

        def report(value):
            events.append(value)

        class StopEvent:
            def set(self):
                # The HTTP main thread can finish immediately when this is set.
                report(status["STOPPED"])

        callback = load_host_function("_service_handler", {"_HANDLER": lambda function: function,
                                       "SERVICE_STATUS": status,
                                       "_stop_requested": StopEvent(),
                                       "_report": report})
        callback(1)
        self.assertEqual(events, [status["STOP_PENDING"], status["STOPPED"]])

    def test_stop_signal_survives_failed_pending_report(self):
        event = threading.Event()

        def failed_report(_status):
            raise OSError(5, "SetServiceStatus failed")

        callback = load_host_function("_service_handler", {"_HANDLER": lambda function: function,
                                       "SERVICE_STATUS": {"STOP_PENDING": 3},
                                       "_stop_requested": event,
                                       "_report": failed_report})
        with self.assertRaises(OSError):
            callback(1)
        self.assertTrue(event.is_set())

    def test_status_report_checks_native_failure(self):
        native = SimpleNamespace(SetServiceStatus=lambda *_: 0)
        failed = threading.Event()
        report = load_host_function("_report", {"SERVICE_STATUS_STRUCT": SimpleNamespace,
                               "SERVICE_STATUS": {"RUNNING": 4},
                               "advapi32": native, "_status_handle": 1,
                               "_status_report_failed": failed,
                               "ctypes": SimpleNamespace(byref=lambda value: value,
                                                         get_last_error=lambda: 123)})
        with self.assertRaises(OSError):
            report(4)
        self.assertTrue(failed.is_set())

    def test_stopped_status_is_reported_only_once_if_native_call_fails(self):
        status = {"START_PENDING": 2, "RUNNING": 4, "STOPPED": 1}
        reported = []
        failures = []

        def report(value, exit_code=0):
            reported.append(value)
            if value == status["STOPPED"]:
                raise OSError(5, "SetServiceStatus failed")

        namespace = {"advapi32": SimpleNamespace(RegisterServiceCtrlHandlerW=lambda *_: 1),
                     "SERVICE_NAME": "mcp-velociraptor", "_service_handler": lambda *_: None,
                     "_report": report, "_load_protected_env": lambda: None,
                     "_write_failure": lambda *args: failures.append(args), "_status_handle": None,
                     "_exit_code": 0, "_stop_requested": threading.Event(),
                     "_status_report_failed": threading.Event(),
                     "SERVICE_STATUS": status,
                     "REPO_ROOT": HOST.parent.parent, "Path": Path, "__file__": str(HOST),
                     "sys": sys, "os": os, "ctypes": SimpleNamespace(get_last_error=lambda: 0)}
        service_main = load_host_function("_service_main", namespace)
        observation = ModuleType("p05_service_observation")
        observation.observe_dispatch = lambda _: nullcontext()
        bridge = ModuleType("mcp_velociraptor_bridge")
        bridge.main = Mock(return_value=0)
        with patch.dict(sys.modules, {"p05_service_observation": observation,
                                      "mcp_velociraptor_bridge": bridge}):
            service_main(0, None)
        bridge.main.assert_called_once()
        self.assertEqual(reported.count(status["STOPPED"]), 1)
        self.assertEqual(namespace["_exit_code"], 10)
        self.assertIn(("SERVICE_STATUS_FAILED", 10), failures)


if __name__ == "__main__":
    unittest.main()
