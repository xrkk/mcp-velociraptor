"""Replay the deployed SCM stop callback without starting a Windows service."""

import ast
from pathlib import Path
import unittest


HOST = Path(__file__).with_name("p05_service_host.py")


def load_stop_callback(namespace):
    """Compile the deployed callback body with a fake SCM decorator."""
    tree = ast.parse(HOST.read_text(encoding="utf-8"), filename=str(HOST))
    callback = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "_service_handler")
    exec(compile(ast.Module(body=[callback], type_ignores=[]), str(HOST), "exec"), namespace)
    return namespace["_service_handler"]


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

        callback = load_stop_callback({"_HANDLER": lambda function: function,
                                       "SERVICE_STATUS": status,
                                       "_stop_requested": StopEvent(),
                                       "_report": report})
        callback(1)
        self.assertEqual(events, [status["STOP_PENDING"], status["STOPPED"]])


if __name__ == "__main__":
    unittest.main()
