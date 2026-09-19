"""Windows seams for the frozen PC006/stdio network evidence producers."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import p05_network_collect as collect
from tests import p06_evidence as gate
from tests.test_p06_semantic_gates import NetworkGateFixture, _ref, _write_json


VMX = "/approved/Win10MalBox-Velo.vmx"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(os.name == "nt", "CON002: producer process seams execute only on Windows")
class NetworkCollectTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _fixture(root: Path) -> NetworkGateFixture:
        fixture = NetworkGateFixture(root)
        fixture.ready.update({
            "run_id": fixture.run_id,
            "restore_attempt_id": fixture.attempt,
        })
        _write_json(fixture.ready_path, fixture.ready)
        return fixture

    def _pc_executor(self, fixture: NetworkGateFixture, *, code: int = 0,
                     invalid: bool = False, calls: list[list[str]] | None = None):
        def execute(argv: list[str], timeout: float) -> subprocess.CompletedProcess[bytes]:
            self.assertGreater(timeout, 0)
            if calls is not None:
                calls.append(list(argv))
            mode, source, comparison = argv[-3:]
            self.assertEqual(argv, gate.pc006_collector_argv(mode, source, int(comparison)))
            if invalid:
                return subprocess.CompletedProcess(argv, code, b"not-json", b"collector diagnostic")
            with patch("subprocess.run", side_effect=fixture._stub_curl):
                document = gate._pc006_collect([mode, source, comparison])
            stdout = json.dumps(
                document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            return subprocess.CompletedProcess(argv, code, stdout, b"collector diagnostic")
        return execute

    def _collect_pc006(self, root: Path, fixture: NetworkGateFixture,
                       output_name: str = "produced-pc006", executor=None):
        return collect.collect_pc006(
            approved_root=root,
            bundle_root=root,
            output_root=root / output_name,
            ready_path=fixture.ready_path,
            run_id=fixture.run_id,
            restore_attempt_id=fixture.attempt,
            probe_source_address=fixture.probe_source,
            comparison_port=fixture.comparison_port,
            vmx=VMX,
            timeout=10,
            executor=executor or self._pc_executor(fixture),
        )

    def _synthetic_repo(self, root: Path, listing: dict, mode: str = "success") -> tuple[Path, Path, Path]:
        repo = root / f"synthetic-repo-{mode}"
        scripts = repo / ".venv" / "Scripts"
        scripts.mkdir(parents=True)
        python = scripts / "python.exe"
        shutil.copy2(sys.executable, python)
        source_venv = Path(sys.executable).parents[1]
        shutil.copy2(source_venv / "pyvenv.cfg", repo / ".venv" / "pyvenv.cfg")
        bridge = repo / "mcp_velociraptor_bridge.py"
        bridge.write_text(
            "import json,sys,time\n"
            f"MODE={mode!r}\n"
            f"LISTING={json.dumps(listing, ensure_ascii=False)!r}\n"
            "LISTING=json.loads(LISTING)\n"
            "for line in sys.stdin:\n"
            " m=json.loads(line); method=m.get('method')\n"
            " if method=='initialize':\n"
            "  version=m.get('params',{}).get('protocolVersion')\n"
            "  if MODE=='unsupported': version='1900-01-01'\n"
            "  print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':"
            "{'protocolVersion':version,'capabilities':{},"
            "'serverInfo':{'name':'synthetic-stdio-seam','version':'1'}}}),flush=True)\n"
            " elif method=='tools/list':\n"
            "  if MODE=='hang': time.sleep(120)\n"
            "  else: print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':LISTING}),flush=True)\n"
            "sys.exit(7 if MODE=='nonzero' else 0)\n",
            encoding="utf-8",
        )
        return repo, python, bridge

    async def _collect_stdio(self, root: Path, fixture: NetworkGateFixture, *,
                             mode: str = "success", listing: dict | None = None,
                             output_name: str | None = None, timeout: float = 10,
                             observer=None):
        listing = listing or fixture.listing
        repo, python, bridge = self._synthetic_repo(root, listing, mode)
        return await collect.collect_stdio(
            approved_root=root,
            bundle_root=root,
            output_root=root / (output_name or f"produced-stdio-{mode}"),
            repository_root=repo,
            python_executable=python,
            bridge_script=bridge,
            host_name="DESKTOP-3FI41GR",
            http_run_id=fixture.run_id,
            stdio_run_id=f"stdio-{fixture.run_id}-{mode}",
            restore_attempt_id=fixture.attempt,
            expected_http_tools=fixture.run_dir / "tools-list.json",
            environment={"PYTHONUTF8": "1"},
            timeout=timeout,
            spawn_observer=observer,
        )

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        import ctypes
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            if not ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == 259  # STILL_ACTIVE
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)

    def test_pc006_executes_exact_frozen_argv_and_publishes_raw_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = self._fixture(root)
            calls: list[list[str]] = []
            artifacts = self._collect_pc006(root, fixture, executor=self._pc_executor(fixture, calls=calls))
            self.assertEqual(calls, [
                gate.pc006_collector_argv("bound", fixture.probe_source, fixture.comparison_port),
                gate.pc006_collector_argv("dual", fixture.probe_source, fixture.comparison_port),
            ])
            boundary = json.loads(artifacts.boundary.read_text(encoding="utf-8"))
            self.assertEqual(boundary["firewall_rule"], fixture.ready["observations"]["firewall"])
            bound = json.loads(artifacts.bound_source.read_text(encoding="utf-8"))
            self.assertEqual(bound["request"]["argv"], calls[0])
            self.assertEqual(bound["exit_status"], {"code": 0})
            self.assertEqual(bound["response"]["stderr"], "collector diagnostic")

    def test_pc006_failure_127_invalid_output_and_timeout_never_publish_boundary(self) -> None:
        cases = {
            "exit127": self._pc_executor,
            "invalid": self._pc_executor,
            "timeout": None,
        }
        for name in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fixture = self._fixture(root)
                if name == "exit127":
                    executor = self._pc_executor(fixture, code=127)
                elif name == "invalid":
                    executor = self._pc_executor(fixture, invalid=True)
                else:
                    def executor(argv, timeout):
                        raise subprocess.TimeoutExpired(argv, timeout, output=b"partial", stderr=b"timed out")
                with self.assertRaisesRegex(collect.CollectionError, "no boundary"):
                    self._collect_pc006(root, fixture, output_name=f"pc006-{name}", executor=executor)
                self.assertFalse((root / f"pc006-{name}" / "pc006.json").exists())
                self.assertTrue((root / f"pc006-{name}" / "collection-failure.json").is_file())

    def test_pc006_rejects_cross_attempt_and_wrong_firewall_original(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = self._fixture(root)
            ready = json.loads(fixture.ready_path.read_text(encoding="utf-8"))
            ready["restore_attempt_id"] = "another-attempt"
            _write_json(fixture.ready_path, ready)
            with self.assertRaisesRegex(collect.CollectionError, "another run or restore"):
                self._collect_pc006(root, fixture)
            self.assertFalse((root / "produced-pc006").exists())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = self._fixture(root)
            firewall = json.loads(fixture.firewall_path.read_text(encoding="utf-8"))
            payload = json.loads(firewall["response"]["stdout"])
            payload["rules"][0]["remote_address"] = "192.168.204.99"
            stdout = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            raw = stdout.encode()
            firewall["response"].update({
                "stdout": stdout, "stdout_size": len(raw),
                "stdout_sha256": hashlib.sha256(raw).hexdigest(),
            })
            _write_json(fixture.firewall_path, firewall)
            fixture.ready["observations"]["firewall"] = _ref(root, fixture.firewall_path)
            _write_json(fixture.ready_path, fixture.ready)
            with self.assertRaisesRegex(collect.CollectionError, "firewall"):
                self._collect_pc006(root, fixture)
            self.assertFalse((root / "produced-pc006" / "pc006.json").exists())

    def test_output_collision_escape_and_input_bytes_are_protected(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            fixture = self._fixture(root)
            before = _sha(fixture.ready_path)
            (root / "collision").mkdir()
            with self.assertRaisesRegex(collect.CollectionError, "already exists"):
                self._collect_pc006(root, fixture, output_name="collision")
            with self.assertRaisesRegex(collect.CollectionError, "outside"):
                collect.collect_pc006(
                    approved_root=root, bundle_root=root, output_root=Path(outside) / "new",
                    ready_path=fixture.ready_path, run_id=fixture.run_id,
                    restore_attempt_id=fixture.attempt,
                    probe_source_address=fixture.probe_source,
                    comparison_port=fixture.comparison_port, vmx=VMX,
                    executor=self._pc_executor(fixture),
                )
            self.assertEqual(_sha(fixture.ready_path), before)

    def test_dotdot_outputs_are_rejected_before_side_effects_or_execution(self) -> None:
        for relative, escaped_name in (("../escaped", "escaped"),
                                       ("nested/../../nested-escaped", "nested-escaped")):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                root = base / "approved"
                root.mkdir()
                (root / "nested").mkdir()
                fixture = self._fixture(root)
                calls: list[list[str]] = []
                with self.assertRaises(collect.CollectionError):
                    self._collect_pc006(
                        root, fixture, output_name=relative,
                        executor=self._pc_executor(fixture, calls=calls),
                    )
                self.assertEqual(calls, [])
                self.assertFalse((base / escaped_name).exists())

    async def test_all_public_entries_preflight_roots_inputs_and_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "approved"
            root.mkdir()
            nested = root / "nested"
            nested.mkdir()
            fixture = self._fixture(root)
            calls: list[list[str]] = []
            disguised_ready = nested / ".." / fixture.ready_path.relative_to(root)
            with self.assertRaisesRegex(collect.CollectionError, "dotdot"):
                collect.collect_pc006(
                    approved_root=root, bundle_root=root, output_root=root / "unused",
                    ready_path=disguised_ready, run_id=fixture.run_id,
                    restore_attempt_id=fixture.attempt,
                    probe_source_address=fixture.probe_source,
                    comparison_port=fixture.comparison_port, vmx=VMX,
                    executor=self._pc_executor(fixture, calls=calls),
                )
            self.assertEqual(calls, [])
            self.assertFalse((root / "unused").exists())

            with self.assertRaisesRegex(collect.CollectionError, "dotdot"):
                collect.collect_pc006(
                    approved_root=nested / "..", bundle_root=root,
                    output_root=root / "unused-approved", ready_path=fixture.ready_path,
                    run_id=fixture.run_id, restore_attempt_id=fixture.attempt,
                    probe_source_address=fixture.probe_source,
                    comparison_port=fixture.comparison_port, vmx=VMX,
                    executor=self._pc_executor(fixture, calls=calls),
                )
            self.assertEqual(calls, [])
            self.assertFalse((root / "unused-approved").exists())

            repo, python, bridge = self._synthetic_repo(root, fixture.listing, "preflight")
            spawned: list[int] = []
            with self.assertRaisesRegex(collect.CollectionError, "dotdot"):
                await collect.collect_stdio(
                    approved_root=root, bundle_root=root,
                    output_root=root / "nested" / ".." / ".." / "stdio-escaped",
                    repository_root=repo, python_executable=python, bridge_script=bridge,
                    host_name="DESKTOP-3FI41GR", http_run_id=fixture.run_id,
                    stdio_run_id="stdio-preflight", restore_attempt_id=fixture.attempt,
                    expected_http_tools=fixture.run_dir / "tools-list.json",
                    environment={"PYTHONUTF8": "1"}, spawn_observer=spawned.append,
                )
            self.assertEqual(spawned, [])
            self.assertFalse((base / "stdio-escaped").exists())

            with self.assertRaisesRegex(collect.CollectionError, "dotdot"):
                collect.assemble_network_evidence(
                    approved_root=root, bundle_root=nested / "..", output_root=root / "assembled",
                    run_id=fixture.run_id, restore_attempt_id=fixture.attempt,
                    report_path=fixture.report_path, ready_path=fixture.ready_path,
                    http_tools_path=fixture.run_dir / "tools-list.json",
                    http_headers_path=fixture.run_dir / "http-headers.json",
                    service_observation_path=fixture.observation_path,
                    pc006_boundary_path=fixture.pc006_path,
                    stdio_launch_path=root / "stdio" / "launch.json",
                    stdio_capture_path=root / "stdio" / "capture.ndjson",
                )
            self.assertFalse((root / "assembled").exists())

    def test_reparse_output_parent_is_rejected_without_writing_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            link = root / "link"
            real.mkdir()
            completed = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(real)],
                capture_output=True, check=False,
            )
            if completed.returncode != 0:
                self.skipTest("junction creation unavailable; dotdot/absolute bounds remain covered")
            try:
                fixture = self._fixture(root)
                calls: list[list[str]] = []
                with self.assertRaisesRegex(collect.CollectionError, "link|reparse"):
                    self._collect_pc006(
                        root, fixture, output_name="link/new",
                        executor=self._pc_executor(fixture, calls=calls),
                    )
                self.assertEqual(calls, [])
                self.assertFalse((real / "new").exists())
            finally:
                os.rmdir(link)

    async def test_stdio_real_sdk_pipeline_records_owned_zero_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = self._fixture(root)
            artifacts = await self._collect_stdio(root, fixture)
            launch = json.loads(artifacts.launch.read_text(encoding="utf-8"))
            self.assertEqual(launch["exit_status"], {"code": 0})
            self.assertEqual(len(artifacts.listing["tools"]), 130)
            rows = [json.loads(line) for line in artifacts.capture.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(
                [row["message"].get("method") for row in rows if row["direction"] == "client_to_server"],
                ["initialize", "notifications/initialized", "tools/list"],
            )
            self.assertIn('"protocolVersion"', launch["response"]["stdout"])

    async def test_stdio_rejects_unsupported_version_nonzero_exit_and_schema_drift(self) -> None:
        for mode, listing in (
            ("unsupported", None),
            ("nonzero", None),
            ("success", {"tools": [{"name": f"drift_{i:03d}", "inputSchema": {"type": "object"}}
                                    for i in range(130)]}),
        ):
            with self.subTest(mode=mode, drift=listing is not None), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fixture = self._fixture(root)
                with self.assertRaises(collect.CollectionError):
                    await self._collect_stdio(
                        root, fixture, mode=mode, listing=listing,
                        output_name=f"stdio-{mode}", timeout=5,
                    )
                output = root / f"stdio-{mode}"
                self.assertTrue((output / "collection-failure.json").is_file())
                self.assertFalse((output / "schema-identity.json").exists())

    async def test_stdio_timeout_and_cancellation_reap_owned_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = self._fixture(root)
            pids: list[int] = []
            with self.assertRaises(collect.CollectionError):
                await self._collect_stdio(root, fixture, mode="hang", timeout=.3, observer=pids.append)
            self.assertEqual(len(pids), 1)
            self.assertFalse(self._pid_alive(pids[0]))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = self._fixture(root)
            pids = []
            spawned = asyncio.Event()
            def observe(pid: int) -> None:
                pids.append(pid)
                spawned.set()
            task = asyncio.create_task(self._collect_stdio(
                root, fixture, mode="hang", output_name="stdio-cancel", timeout=30, observer=observe
            ))
            await asyncio.wait_for(spawned.wait(), 5)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertFalse(self._pid_alive(pids[0]))

    async def test_producers_assemble_and_pass_existing_network_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = self._fixture(root)
            inputs = [fixture.report_path, fixture.ready_path, fixture.run_dir / "tools-list.json",
                      fixture.run_dir / "http-headers.json", fixture.observation_path]
            before = {path: _sha(path) for path in inputs}
            pc006 = self._collect_pc006(root, fixture)
            stdio = await self._collect_stdio(root, fixture)
            artifacts = collect.assemble_network_evidence(
                approved_root=root, bundle_root=root, output_root=root / "produced-network",
                run_id=fixture.run_id, restore_attempt_id=fixture.attempt,
                report_path=fixture.report_path, ready_path=fixture.ready_path,
                http_tools_path=fixture.run_dir / "tools-list.json",
                http_headers_path=fixture.run_dir / "http-headers.json",
                service_observation_path=fixture.observation_path,
                pc006_boundary_path=pc006.boundary,
                stdio_launch_path=stdio.launch, stdio_capture_path=stdio.capture,
            )
            self.assertTrue(artifacts.network_evidence.is_file())
            phase = {
                "run_id": fixture.run_id, "restore_attempt_id": fixture.attempt,
                "report": _ref(root, fixture.report_path), "ready": _ref(root, fixture.ready_path),
                "network_evidence": _ref(root, artifacts.network_evidence),
            }
            gate._verify_network_evidence(root, phase, {})
            self.assertEqual({path: _sha(path) for path in inputs}, before)

    async def test_assembler_rejects_missing_notification_and_cross_attempt_without_success_doc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = self._fixture(root)
            pc006 = self._collect_pc006(root, fixture)
            stdio = await self._collect_stdio(root, fixture)
            broken = root / "broken-capture.ndjson"
            rows = [json.loads(line) for line in stdio.capture.read_text(encoding="utf-8").splitlines()]
            rows = [row for row in rows if row["message"].get("method") != "notifications/initialized"]
            broken.write_text("".join(json.dumps(
                {**row, "sequence": index}, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
                for index, row in enumerate(rows, start=1)), encoding="utf-8")
            with self.assertRaisesRegex(collect.CollectionError, "existing gate"):
                collect.assemble_network_evidence(
                    approved_root=root, bundle_root=root, output_root=root / "broken-network",
                    run_id=fixture.run_id, restore_attempt_id=fixture.attempt,
                    report_path=fixture.report_path, ready_path=fixture.ready_path,
                    http_tools_path=fixture.run_dir / "tools-list.json",
                    http_headers_path=fixture.run_dir / "http-headers.json",
                    service_observation_path=fixture.observation_path,
                    pc006_boundary_path=pc006.boundary,
                    stdio_launch_path=stdio.launch, stdio_capture_path=broken,
                )
            self.assertFalse((root / "broken-network" / "network-evidence.json").exists())
            self.assertFalse((root / "broken-network" / "schema-identity.json").exists())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = self._fixture(root)
            pc006 = self._collect_pc006(root, fixture)
            stdio = await self._collect_stdio(root, fixture)
            launch = json.loads(stdio.launch.read_text(encoding="utf-8"))
            launch["restore_attempt_id"] = "another-attempt"
            altered = root / "altered-launch.json"
            _write_json(altered, launch)
            with self.assertRaisesRegex(collect.CollectionError, "same restore"):
                collect.assemble_network_evidence(
                    approved_root=root, bundle_root=root, output_root=root / "cross-attempt",
                    run_id=fixture.run_id, restore_attempt_id=fixture.attempt,
                    report_path=fixture.report_path, ready_path=fixture.ready_path,
                    http_tools_path=fixture.run_dir / "tools-list.json",
                    http_headers_path=fixture.run_dir / "http-headers.json",
                    service_observation_path=fixture.observation_path,
                    pc006_boundary_path=pc006.boundary,
                    stdio_launch_path=altered, stdio_capture_path=stdio.capture,
                )
            self.assertFalse((root / "cross-attempt").exists())

    def test_assembler_contains_unexpected_gate_error_without_published_graph(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = self._fixture(root)
            capture = root / "stdio" / "capture.ndjson"
            rows = [json.loads(line) for line in capture.read_text(encoding="utf-8").splitlines()]
            rows[0]["message"]["method"] = []
            capture.write_text("".join(
                json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
                for row in rows
            ), encoding="utf-8")
            target = root / "malformed-network"
            with self.assertRaisesRegex(collect.CollectionError, "existing gate"):
                collect.assemble_network_evidence(
                    approved_root=root, bundle_root=root, output_root=target,
                    run_id=fixture.run_id, restore_attempt_id=fixture.attempt,
                    report_path=fixture.report_path, ready_path=fixture.ready_path,
                    http_tools_path=fixture.run_dir / "tools-list.json",
                    http_headers_path=fixture.run_dir / "http-headers.json",
                    service_observation_path=fixture.observation_path,
                    pc006_boundary_path=fixture.pc006_path,
                    stdio_launch_path=root / "stdio" / "launch.json",
                    stdio_capture_path=capture,
                )
            self.assertFalse((target / "network-evidence.json").exists())
            self.assertFalse((target / "schema-identity.json").exists())
            self.assertTrue((target / "collection-failure.json").is_file())

    def test_assembler_write_failure_removes_only_its_final_documents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = self._fixture(root)
            target = root / "write-failure-network"
            original_write = collect._write_json

            def fail_final_network(path: Path, value: object) -> None:
                if path.name == "network-evidence.json":
                    raise OSError("synthetic final network write failure")
                original_write(path, value)

            with patch.object(collect, "_write_json", side_effect=fail_final_network):
                with self.assertRaisesRegex(collect.CollectionError, "final network write"):
                    collect.assemble_network_evidence(
                        approved_root=root, bundle_root=root, output_root=target,
                        run_id=fixture.run_id, restore_attempt_id=fixture.attempt,
                        report_path=fixture.report_path, ready_path=fixture.ready_path,
                        http_tools_path=fixture.run_dir / "tools-list.json",
                        http_headers_path=fixture.run_dir / "http-headers.json",
                        service_observation_path=fixture.observation_path,
                        pc006_boundary_path=fixture.pc006_path,
                        stdio_launch_path=root / "stdio" / "launch.json",
                        stdio_capture_path=root / "stdio" / "capture.ndjson",
                    )
            self.assertFalse((target / "network-evidence.json").exists())
            self.assertFalse((target / "schema-identity.json").exists())
            self.assertTrue((target / "collection-failure.json").is_file())

    def _install_produced_network_in_activation(
        self, bundle: Path, activation_path: Path, *, corrupt_pc006: bool = False
    ) -> str:
        activation = json.loads(activation_path.read_text(encoding="utf-8"))
        cycle = activation["candidate_cycles"][0]
        phase_root = bundle / "cycle-1"
        report_path = bundle / cycle["report"]["path"]
        ready_path = bundle / cycle["ready"]["path"]
        old_network_path = bundle / cycle["network_evidence"]["path"]
        old_network = json.loads(old_network_path.read_text(encoding="utf-8"))
        service_path = bundle / old_network["service_observation"]["path"]
        executor_fixture = NetworkGateFixture(bundle / "producer-executor-fixture", ref_root=bundle)
        pc006 = collect.collect_pc006(
            approved_root=bundle, bundle_root=bundle,
            output_root=phase_root / "producer-pc006", ready_path=ready_path,
            run_id=cycle["run_id"], restore_attempt_id=cycle["restore_attempt_id"],
            probe_source_address=executor_fixture.probe_source,
            comparison_port=executor_fixture.comparison_port, vmx=VMX,
            executor=self._pc_executor(executor_fixture),
        )
        listing = json.loads((report_path.parent / "tools-list.json").read_text(encoding="utf-8"))
        repo, python, bridge = self._synthetic_repo(bundle, listing, "activation-producer")
        stdio = asyncio.run(collect.collect_stdio(
            approved_root=bundle, bundle_root=bundle,
            output_root=phase_root / "producer-stdio", repository_root=repo,
            python_executable=python, bridge_script=bridge,
            host_name="DESKTOP-3FI41GR", http_run_id=cycle["run_id"],
            stdio_run_id="stdio-cycle-one-produced",
            restore_attempt_id=cycle["restore_attempt_id"],
            expected_http_tools=report_path.parent / "tools-list.json",
            environment={"PYTHONUTF8": "1"}, timeout=10,
        ))
        assembled = collect.assemble_network_evidence(
            approved_root=bundle, bundle_root=bundle,
            output_root=phase_root / "producer-network", run_id=cycle["run_id"],
            restore_attempt_id=cycle["restore_attempt_id"], report_path=report_path,
            ready_path=ready_path, http_tools_path=report_path.parent / "tools-list.json",
            http_headers_path=report_path.parent / "http-headers.json",
            service_observation_path=service_path, pc006_boundary_path=pc006.boundary,
            stdio_launch_path=stdio.launch, stdio_capture_path=stdio.capture,
        )
        if corrupt_pc006:
            bound = json.loads(pc006.bound_source.read_text(encoding="utf-8"))
            bound["exit_status"]["code"] = 127
            _write_json(pc006.bound_source, bound)
            boundary = json.loads(pc006.boundary.read_text(encoding="utf-8"))
            boundary["bound_source_failure"] = _ref(bundle, pc006.bound_source)
            _write_json(pc006.boundary, boundary)
            network = json.loads(assembled.network_evidence.read_text(encoding="utf-8"))
            network["non_allowed_source"] = _ref(bundle, pc006.boundary)
            _write_json(assembled.network_evidence, network)
        cycle["network_evidence"] = _ref(bundle, assembled.network_evidence)
        manifest_path = bundle / cycle["package_manifest"]["path"]
        members = sorted(
            (_ref(bundle, member) for member in phase_root.rglob("*")
             if member.is_file() and member != manifest_path),
            key=lambda item: str(item["path"]).encode("utf-8"),
        )
        _write_json(manifest_path, {"schema_version": 1, "members": members})
        cycle["package_manifest"] = _ref(bundle, manifest_path)
        _write_json(activation_path, activation)
        return cycle["network_evidence"]["path"]

    async def test_public_activation_entry_consumes_producer_graph_without_mocking_gate(self) -> None:
        from tests.test_p06_semantic_gates import FullSyntheticActivationBundleTests

        case = FullSyntheticActivationBundleTests(
            "test_verify_activation_bundle_accepts_a_fully_closed_synthetic_pack"
        )
        consumed: list[str] = []

        def install(bundle: Path, activation_path: Path) -> None:
            consumed.append(self._install_produced_network_in_activation(bundle, activation_path))

        facts = await asyncio.to_thread(case._closed_synthetic_bundle, install)
        self.assertEqual(facts["candidate"], gate.SNAPSHOT_188)
        self.assertEqual(consumed, ["cycle-1/producer-network/network-evidence.json"])

    async def test_public_activation_entry_rejects_hash_recomputed_producer_semantic_damage(self) -> None:
        from tests.test_p06_semantic_gates import FullSyntheticActivationBundleTests

        case = FullSyntheticActivationBundleTests(
            "test_verify_activation_bundle_accepts_a_fully_closed_synthetic_pack"
        )

        def install_and_corrupt(bundle: Path, activation_path: Path) -> None:
            self._install_produced_network_in_activation(
                bundle, activation_path, corrupt_pc006=True
            )

        with self.assertRaisesRegex(gate.EvidenceError, "did not exit successfully"):
            await asyncio.to_thread(case._closed_synthetic_bundle, install_and_corrupt)


if __name__ == "__main__":
    unittest.main()
