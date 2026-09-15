"""Future Windows-only contracts for P05's SDK dispatch observation.

These tests use injected PowerShell-result mappings; they never connect to a
VM, service port, or deployment host.  The one real process-identity test is
Windows read-only and is deliberately gated with the rest of the file.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest


COUNTER_ID = "8e1a79d0-348a-4b06-87d4-6b7d0ff7ebcd"
START = "2026-09-14T00:00:00.000000Z"
END = "2026-09-14T00:00:01.000000Z"
INSTANCE = "dispatch-instance-1"
PID = 4321
SHA256 = "a" * 64
OLD_COUNTER_ID = "63f9e798-a017-4fb9-b64b-5c14d4a2187f"
DISPATCH_DIRECTORY = r"C:\mcp-velociraptor\Logs\p05-dispatch"


def _service(*, pid: int = PID, start: str = START, executable_sha256: str = SHA256) -> dict:
    return {
        "name": "mcp-velociraptor",
        "pid": pid,
        "process_start_time_utc": start,
        "executable_sha256": executable_sha256,
    }


def _counter(counter_id: str = COUNTER_ID, *, pid: int = PID, count: int = 7) -> dict:
    return {
        "schema_version": 1,
        "kind": "p05-service-dispatch-counter-v1",
        "counter_id": counter_id,
        "server_instance_id": INSTANCE,
        "pid": pid,
        "process_start_time_utc": START,
        "executable_sha256": SHA256,
        "count": count,
        "observed_at": END,
    }


def _candidate(counter: dict) -> dict:
    content = json.dumps(counter, separators=(",", ":")).encode("utf-8")
    return {
        "path": DISPATCH_DIRECTORY + "\\" + counter["counter_id"] + ".json",
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "body_base64": base64.b64encode(content).decode("ascii"),
    }


def _projection(
    candidates: list[dict] | None = None,
    *,
    before: dict | None = None,
    after: dict | None = None,
    excluded: list[dict] | None = None,
) -> dict:
    return {
        "service_before": before or _service(),
        "candidates": candidates if candidates is not None else [_candidate(_counter())],
        "excluded": excluded or [],
        "service_after": after or _service(),
    }


@unittest.skipUnless(os.name == "nt", "P05 dispatch observation tests require Windows")
class ServiceObservationWindowsTests(unittest.TestCase):
    def _reader(self, projection: dict | None = None):
        from tests import p05_service_observation as observation

        captured: list[tuple[str, ...]] = []

        def execute(argv: tuple[str, ...]) -> dict:
            captured.append(argv)
            stdout = json.dumps(projection or _projection(), separators=(",", ":"))
            return {
                "argv": list(argv),
                "command_line": " ".join(argv[:4]) + " <fixed projection>",
                "started_at": START,
                "ended_at": END,
                "exit_status": {"code": 0},
                "stdout": stdout,
                "stderr": "",
            }

        reader = observation.make_http_counter_reader(
            execute,
            dispatch_directory=DISPATCH_DIRECTORY,
            run_id="run-observation",
            restore_attempt_id="restore-observation",
        )
        return reader, captured

    def test_all_candidates_are_raw_read_and_only_the_unique_live_service_counter_is_selected(self) -> None:
        from tests import p05_service_observation as observation

        old = _counter(OLD_COUNTER_ID, pid=PID + 1)
        projection = _projection([_candidate(_counter()), _candidate(old)])
        selected, counter_path, exclusions = observation._dispatch_payload(
            projection, directory=DISPATCH_DIRECTORY
        )
        self.assertEqual(selected["counter_id"], COUNTER_ID)
        self.assertEqual(counter_path, DISPATCH_DIRECTORY + "\\" + COUNTER_ID + ".json")
        self.assertEqual(exclusions, [{
            "counter_id": OLD_COUNTER_ID,
            "path": DISPATCH_DIRECTORY + "\\" + OLD_COUNTER_ID + ".json",
            "reason": "process_identity_mismatch",
        }])

        reader, captured = self._reader(projection)
        result = reader()
        self.assertEqual(result["kind"], "p05-http-handler-counter-v1")
        self.assertEqual(result["count"], 7)
        self.assertEqual(result["instance"], INSTANCE)
        self.assertEqual(result["time"], END)
        self.assertIn(OLD_COUNTER_ID, result["output"]["stdout"])
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0][:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
        self.assertIn("Get-ChildItem", captured[0][4])
        self.assertNotIn("LastWriteTime", captured[0][4])
        self.assertNotIn("Sort-Object", captured[0][4])
        self.assertEqual(
            result["output"]["stdout_sha256"],
            hashlib.sha256(result["output"]["stdout"].encode("utf-8")).hexdigest(),
        )

    def test_zero_or_multiple_live_counter_matches_keep_raw_candidates_and_fail_closed(self) -> None:
        from tests import p05_service_observation as observation

        for candidates, expected_count in (
            ([_candidate(_counter(OLD_COUNTER_ID, pid=PID + 1))], 0),
            ([_candidate(_counter()), _candidate(_counter(OLD_COUNTER_ID, count=8))], 2),
        ):
            with self.subTest(expected_count=expected_count):
                reader, _ = self._reader(_projection(candidates))
                with self.assertRaises(observation.DispatchCounterSelectionError) as raised:
                    reader()
                self.assertIn(str(expected_count), str(raised.exception.__cause__))
                original = raised.exception.raw_original
                self.assertEqual(original["kind"], "p05-service-dispatch-discovery-v1")
                self.assertIn(OLD_COUNTER_ID, original["output"]["stdout"])

    def test_reparse_exclusion_and_service_restart_between_before_after_are_rejected(self) -> None:
        from tests import p05_service_observation as observation

        unsafe = [{
            "path": DISPATCH_DIRECTORY + "\\" + OLD_COUNTER_ID + ".json",
            "name": OLD_COUNTER_ID + ".json",
            "reason": "reparse_point",
        }]
        for projection in (
            _projection(excluded=unsafe),
            _projection(after=_service(pid=PID + 1)),
        ):
            with self.subTest(projection=projection["excluded"] or projection["service_after"]):
                reader, _ = self._reader(projection)
                with self.assertRaises(observation.DispatchCounterSelectionError) as raised:
                    reader()
                self.assertEqual(raised.exception.raw_original["kind"], "p05-service-dispatch-discovery-v1")

    def test_executor_failure_retains_its_complete_raw_original_when_available(self) -> None:
        from tests import p05_service_observation as observation

        original = {
            "schema_version": 1,
            "kind": "p05-powershell-execution-failure-v1",
            "request": {"argv": ["powershell.exe", "-NoProfile"]},
            "response": {"stdout": "", "stderr": "service unavailable"},
        }

        class ExecutorFailure(RuntimeError):
            raw_original = original

        def execute(unused_argv: tuple[str, ...]) -> dict:
            del unused_argv
            raise ExecutorFailure("synthetic executor detail")

        reader = observation.make_http_counter_reader(
            execute,
            dispatch_directory=DISPATCH_DIRECTORY,
            run_id="run-observation",
            restore_attempt_id="restore-observation",
        )
        with self.assertRaises(observation.DispatchCounterSelectionError) as raised:
            reader()
        self.assertEqual(raised.exception.raw_original, original)

    def test_current_process_identity_is_read_only_and_hashes_the_running_executable(self) -> None:
        from tests import p05_service_observation as observation

        identity = observation._process_identity()
        self.assertEqual(identity["pid"], os.getpid())
        self.assertTrue(identity["process_start_time_utc"].endswith("Z"))
        self.assertEqual(
            identity["executable_sha256"], hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
        )

    def test_old_single_counter_fixture_no_longer_uses_an_explicit_counter_id_argument(self) -> None:
        reader, captured = self._reader()
        result = reader()
        self.assertEqual(result["count"], 7)
        self.assertEqual(len(captured), 1)


class ServiceObservationStaticTests(unittest.TestCase):
    def test_module_is_parseable_without_importing_sdk_or_powershell(self) -> None:
        source = Path(__file__).with_name("p05_service_observation.py")
        ast.parse(source.read_text(encoding="utf-8"), filename=str(source))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
