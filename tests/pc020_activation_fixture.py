"""Synthetic Snapshot189 activation package builder used only by Windows tests."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import uuid
from pathlib import Path

from tests import p05_pc020_activation as activation
from tests import p05_pc021_package as pkg
from tests import p05_pc020_evidence as evidence
from tests import p06_evidence as legacy
from tests.test_p05_pc020_evidence import Fixture, blob, ref, sha
from tests.test_p05_pc020_restore import guest_command, host_command


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(evidence.canonical_json(value))


def identity(data: bytes) -> evidence.FrozenIdentity:
    return evidence.FrozenIdentity(len(data), sha(data), blob(data))


def refresh_ref(root: Path, reference: dict[str, object]) -> None:
    path = root / str(reference["path"])
    data = path.read_bytes()
    reference["size"] = len(data)
    reference["sha256"] = sha(data)


def read_transcript(path: Path) -> tuple[dict[str, object], dict[str, object]]:
    document = json.loads(path.read_bytes())
    return document, json.loads(document["response"]["stdout"])


def write_transcript(path: Path, document: dict[str, object], payload: dict[str, object]) -> bytes:
    stdout = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    raw = stdout.encode("utf-8")
    response = document["response"]
    response["stdout"] = stdout
    response["stdout_size"] = len(raw)
    response["stdout_sha256"] = sha(raw)
    write(path, document)
    return raw


class ActivationFixture:
    def __init__(
        self, root: Path, historical: Path, predecessor: bytes,
        baseline: Path, old_activation: Path, real_source_root: Path, repo: Path,
    ) -> None:
        self.root = root
        shutil.copytree(historical, root, dirs_exist_ok=True)
        old = json.loads((root / "activation-evidence.json").read_bytes())

        phase_source_data = {
            row["repo_path"]: (root / row["content"]["path"]).read_bytes()
            for row in old["source_inputs"]
        }
        # Preparation/migration are current PC020 evidence and therefore bind
        # the current frozen source set, not merely the historical activation's
        # older P05 subset.
        source_data = {
            name: (real_source_root / name).read_bytes()
            for name in evidence.PC020_REQUIRED_SOURCE_PATHS
        }
        candidate_path = activation.SCENARIOS["p05-flow-triage-repair-candidate"][0]
        candidate = json.loads(phase_source_data[candidate_path])
        candidate["required_snapshot"] = evidence.SNAPSHOT_189
        phase_source_data[candidate_path] = evidence.canonical_json(candidate)
        for scenario_path, _, _ in activation.SCENARIOS.values():
            scenario = json.loads(phase_source_data[scenario_path])
            extended = []
            for step in scenario["steps"]:
                extended.append(step)
                for label, file_index in (("ascii", 0), ("utf8", 1)):
                    if step["id"] == f"{label}_files":
                        extended.append({
                            "id": f"{label}_download", "kind": "tool",
                            "tool": "download_flow_file",
                            "arguments": {
                                "flow_id": {"$ref": f"/steps/collect_{label}/structuredContent/flow_id"},
                                "file_id": {"$ref": f"/steps/{label}_files/structuredContent/data/0/file_id"},
                            },
                            "assertions": [
                                {"actual": "/isError", "expected": False, "op": "is_error"},
                                {"actual": "/structuredContent/size", "expected": {"$fixture": f"/files/{file_index}/size"}, "op": "eq"},
                                {"actual": "/structuredContent/sha256", "expected": {"$fixture": f"/files/{file_index}/sha256"}, "op": "eq"},
                            ],
                        })
            scenario["steps"] = extended
            phase_source_data[scenario_path] = evidence.canonical_json(scenario)
        index = json.loads(phase_source_data[activation.INDEX])
        for row in index["scenarios"]:
            if row["scenario_id"] == "p05-flow-triage-repair-candidate":
                row["required_snapshot"] = evidence.SNAPSHOT_189
            row["sha256"] = sha(phase_source_data[activation.SCENARIOS[row["scenario_id"]][0]])
        phase_source_data[activation.INDEX] = evidence.canonical_json(index)

        # PC022 source layering: the activation root's source_inputs carries
        # the complete P05 representative graph (PC020 frozen set plus the
        # scenario/index/schema decisions), while implementation_sources
        # carries only actual code and test bytes.  Preparation/migration
        # bundles keep the unmodified PC020 frozen policy.
        required_graph = {
            activation.INDEX, activation.FIXTURE, activation.SCHEMA,
            *(row[0] for row in activation.SCENARIOS.values()),
        }
        root_source_data = dict(source_data)
        for name in sorted(required_graph - set(source_data)):
            root_source_data[name] = phase_source_data[name]
        for name, data in phase_source_data.items():
            # the historical P05 data sources (dependency manifest and peers)
            # are frozen decisions and move up to the root source layer too
            root_source_data.setdefault(name, data)
        implementation_data = {
            row["repo_path"]: (root / row["content"]["path"]).read_bytes()
            for row in old["implementation_sources"]
            if row["repo_path"] not in required_graph
        }
        for name in (
            "tests/p05_pc020_activation.py", "tests/pc020_activation_fixture.py",
            "tests/test_p05_pc020_activation.py", "tests/p05_pc021_package.py",
            "tests/pc022_windows_refresh.py",
            "tests/fixtures/artifacts/Generic.Utils.KillProcess.yaml",
        ):
            implementation_data[name] = (repo / name).read_bytes()
        self.policy = evidence.FrozenSourcePolicy(
            source_inputs={name: identity(data) for name, data in source_data.items()},
            implementation_sources={name: identity(data) for name, data in implementation_data.items()},
            synthetic_fixture=True,
        )
        self.root_policy = evidence.FrozenSourcePolicy(
            source_inputs={name: identity(data) for name, data in root_source_data.items()},
            implementation_sources={name: identity(data) for name, data in implementation_data.items()},
            synthetic_fixture=True,
        )
        self.root_source_data = root_source_data
        fixture = Fixture(root, source_data)
        fixture.implementation_data = implementation_data
        fixture.policy = self.policy
        self.preparation = fixture.preparation().resolve()
        self.migration = fixture.migration(self.preparation, predecessor, baseline, old_activation).resolve()
        self.canonical_bytes = evidence.canonical_json(self._canonical())

        shutil.rmtree(root / "source")
        for name, data in {**root_source_data, **implementation_data}.items():
            path = root / "source" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        source_refs = [self._source_ref(name, data) for name, data in root_source_data.items()]
        impl_refs = [self._source_ref(name, data) for name, data in implementation_data.items()]

        marker = "Win10MalBox-Velo-Snapshot27.vmsn"
        creation_path = self._creation(marker)
        phases = [old["initial"], *old["candidate_cycles"]]
        for position, phase in enumerate(phases):
            phase_dir = ["initial", "cycle-1", "cycle-2"][position]
            stage = "P05_REPAIR_INITIAL" if position == 0 else "P05_REPAIR_CANDIDATE"
            snapshot = evidence.SNAPSHOT_187 if position == 0 else evidence.SNAPSHOT_189
            phase_marker = evidence.MARKER_187 if position == 0 else marker
            report_path = root / phase["report"]["path"]
            report = json.loads(report_path.read_bytes())
            self._add_download_chains(phase_dir, report)
            source_path = activation.SCENARIOS[report["scenario"]][0]
            report["source_sha256"] = sha(phase_source_data[source_path])
            report["index_sha256"] = sha(phase_source_data[activation.INDEX])
            write(report_path, report)
            snapshot_path = root / phase["snapshot_evidence"]["path"]
            snapshot_doc = json.loads(snapshot_path.read_bytes())
            snapshot_doc["source_sha256"] = report["source_sha256"]
            snapshot_doc["index_sha256"] = report["index_sha256"]
            snapshot_doc["restore"] = self._restore(phase_dir, phase["run_id"], phase["restore_attempt_id"], stage, snapshot, phase_marker)
            write(snapshot_path, snapshot_doc)
            report["snapshot_evidence_sha256"] = sha(snapshot_path.read_bytes())
            write(report_path, report)
            ready_path = root / phase["ready"]["path"]
            ready = json.loads(ready_path.read_bytes())
            ready.update(snapshot_stage=stage, snapshot_name=snapshot, checkpoint_marker=phase_marker)
            host_ref = ready["observations"]["host_processes"]
            host_path = root / host_ref["path"]
            host = json.loads(host_path.read_bytes())
            payload = json.loads(host["response"]["stdout"])
            for row in payload["processes"]:
                if row["pid"] == report["runner"]["pid"]:
                    row["creation_time_utc"] = report["runner"]["process_start_time_utc"]
            stdout = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            host["response"]["stdout"] = stdout
            host["response"]["stdout_size"] = len(stdout.encode())
            host["response"]["stdout_sha256"] = sha(stdout.encode())
            write(host_path, host)
            refresh_ref(root, host_ref)
            write(ready_path, ready)
            dependency_path = root / phase["dependency_acceptance"]["path"]
            dependency = json.loads(dependency_path.read_bytes())
            chains_ref = dependency["four_chains"]
            chains_path = root / chains_ref["path"]
            chain_fixture = repo / ".tmp/velo-codex-20260921-pc020-activation/evidence/four-chain-fixtures" / str(position)
            chains = json.loads((chain_fixture / "p05-real-acceptance.json").read_bytes())
            chains["attempt_id"] = phase["restore_attempt_id"]
            shutil.copy2(chain_fixture / "sdk-messages.ndjson", chains_path.parent / "sdk-messages.ndjson")
            shutil.copy2(chain_fixture / "bridge-stderr.log", chains_path.parent / "bridge-stderr.log")
            shutil.copytree(chain_fixture / "raw-observations", chains_path.parent / "raw-observations", dirs_exist_ok=True)
            self._bind_ready_to_chain(ready, chains, chains_path)
            write(ready_path, ready)
            write(chains_path, chains)
            refresh_ref(root, chains_ref)
            network_reference = dependency["network_observations"]
            network_path = root / network_reference["path"]
            network_path.write_text(
                "[00]0138.0440::2026-09-15 04:00:00.000000000 [MSNT_SystemTrace] "
                "Event: Header, BufferSize: 16777216, EventsLost: 0, BuffersLost: 0, LogFileMode: 0x4010001\n"
                "[1]1108.0B7C::2026-09-15 04:00:01.000000000 [Microsoft-Windows-Kernel-Network]"
                "TCPv4: Connection attempted between 127.0.0.1:50041 and 127.0.0.1:8001. \n"
                "[2]2210.0A00::2026-09-15 04:00:02.000000000 [Microsoft-Windows-Kernel-Network]"
                "TCPv4: Connection attempted between 127.0.0.1:50100 and 127.0.0.1:8000. \n",
                encoding="utf-8", newline="\n",
            )
            refresh_ref(root, network_reference)
            write(dependency_path, dependency)
            self._pc006(phase, ready, report)
            self._schema_identity(phase, report, chains, chains_path)
            for key in legacy.PHASE_KEYS - {"run_id", "restore_attempt_id", "package_manifest"}:
                refresh_ref(root, phase[key])
            self._manifest(phase_dir, phase)
            refresh_ref(root, phase["package_manifest"])

        root_doc = {
            "schema_version": 1, "kind": "snapshot189-activation-evidence-v1",
            "workflow_id": evidence.WORKFLOW_ID, "candidate": evidence.SNAPSHOT_189,
            "checkpoint_marker": marker,
            "migration_evidence": ref(root, self.migration.relative_to(root).as_posix()),
            "preparation_evidence": ref(root, self.preparation.relative_to(root).as_posix()),
            "creation_metadata": ref(root, creation_path.relative_to(root).as_posix()),
            "initial": phases[0], "candidate_cycles": phases[1:],
            "source_inputs": source_refs, "implementation_sources": impl_refs,
            "issued_at": "2026-09-15T04:12:00Z",
        }
        self.activation = root / "activation-evidence.json"
        write(self.activation, root_doc)
        self._receipt(root_doc)

    def _add_download_chains(self, phase_dir: str, report: dict[str, object]) -> None:
        """Add the two frozen file downloads and their retained logical bytes."""
        fixture = json.loads((self.root / "source" / activation.FIXTURE).read_bytes())
        calls = report["calls"]
        steps = report["steps"]
        for label, file_index in (("ascii", 0), ("utf8", 1)):
            start = next(call for call in calls if call["step_id"] == f"collect_{label}")
            first_status = next(call for call in calls if call["step_id"] == f"wait_{label}")
            start["structured"]["state"] = first_status["structured"]["state"]
            start["mcp_result"]["structuredContent"]["state"] = first_status["structured"]["state"]
            listing = next(call for call in calls if call["step_id"] == f"{label}_files")
            listed = listing["structured"]["data"][0]
            item = fixture["files"][file_index]
            payload = item["payload"].encode(item["encoding"])
            if len(payload) != item["size"] or sha(payload) != item["sha256"]:
                raise ValueError("fixture payload identity differs")
            flow_id, file_id = start["structured"]["flow_id"], listed["file_id"]
            path = self.root / phase_dir / "downloads" / hashlib.sha256(flow_id.encode()).hexdigest() / file_id / "content.bin"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            structured = {
                "operation": "download_flow_file", "status": "success", "warnings": [],
                "flow_id": flow_id, "file_id": file_id, "local_path": str(path.resolve()),
                "size": len(payload), "sha256": sha(payload), "original_path": listed["original_path"],
            }
            call = {
                "arguments": {"flow_id": flow_id, "file_id": file_id}, "attempt": 1,
                "is_error": False, "step_id": f"{label}_download", "structured": structured,
                "mcp_result": {"content": [], "isError": False, "resultType": "complete", "structuredContent": copy.deepcopy(structured)},
                "tool": "download_flow_file", "started_at": listing["ended_at"],
                "ended_at": listing["ended_at"], "duration_ms": 0,
            }
            call_index = calls.index(listing) + 1
            calls.insert(call_index, call)
            step_index = next(i for i, row in enumerate(steps) if row["id"] == f"{label}_files") + 1
            steps.insert(step_index, {
                "id": f"{label}_download", "kind": "tool", "passed": True,
                "assertions": [
                    {"actual": False, "actual_exists": True, "expected": False, "op": "is_error", "passed": True},
                    {"actual": len(payload), "actual_exists": True, "expected": len(payload), "op": "eq", "passed": True},
                    {"actual": sha(payload), "actual_exists": True, "expected": sha(payload), "op": "eq", "passed": True},
                ],
            })
        triage = next(call for call in calls if call["step_id"] == "start_triage")
        triage_status = next(call for call in calls if call["step_id"] == "wait_triage")
        triage["structured"]["state"] = triage_status["structured"]["state"]
        triage["mcp_result"]["structuredContent"]["state"] = triage_status["structured"]["state"]
        for sequence, call in enumerate(calls, start=1):
            call["sequence"] = sequence

    def _bind_ready_to_chain(
        self, ready: dict[str, object], chains: dict[str, object], chains_path: Path,
    ) -> None:
        """Make the synthetic ready process graph and retained kill originals one run.

        The historical package and the three complete chain captures came from
        different accepted runs.  A synthetic fixture must join their decoded
        process facts instead of merely relabelling their outer references.
        """
        target_pid = chains["calls"]["kill-process"]["arguments"]["pid"]
        raw_refs = chains["raw_observations"]
        pre_path = chains_path.parent / raw_refs["kill-pre-processes"]["path"]
        pre = json.loads(pre_path.read_bytes())
        pre_rows = json.loads(pre["stdout"])
        target_source = next(row for row in pre_rows if row["ProcessId"] == target_pid)
        target_creation = target_source["CreationDate"]

        observations = ready["observations"]
        fixture_path = self.root / observations["fixture_instance"]["path"]
        fixture_doc, fixture_payload = read_transcript(fixture_path)
        old_pid = fixture_payload["process"]["pid"]
        fixture_payload["process"]["pid"] = target_pid
        fixture_payload["process"]["creation_time_utc"] = target_creation
        fixture_stdout = write_transcript(fixture_path, fixture_doc, fixture_payload)

        static_path = self.root / observations["fixture_static"]["path"]
        static_doc, static_payload = read_transcript(static_path)
        static_payload["fixture_instance"]["sha256"] = sha(fixture_stdout)
        write_transcript(static_path, static_doc, static_payload)

        processes_path = self.root / observations["guest_processes"]["path"]
        processes_doc, processes_payload = read_transcript(processes_path)
        target = next(row for row in processes_payload["processes"] if row["ProcessId"] == old_pid)
        processes_payload["processes"] = [
            row for row in processes_payload["processes"]
            if row["ProcessId"] not in {old_pid, target_pid}
        ]
        target["ProcessId"] = target_pid
        target["CreationDate"] = target_creation
        processes_payload["processes"].append(target)
        write_transcript(processes_path, processes_doc, processes_payload)

        bindings_path = self.root / observations["parent_bindings"]["path"]
        bindings_doc, bindings_payload = read_transcript(bindings_path)
        fixture_record = next(row for row in bindings_payload["launch_records"] if row["role"] == "fixture")
        binding = fixture_record["fixture_binding"]
        binding["instance_sha256"] = sha(fixture_stdout)
        binding["process_identity"]["ProcessId"] = target_pid
        binding["process_identity"]["CreationDate"] = target_creation
        write_transcript(bindings_path, bindings_doc, bindings_payload)

        for key in ("fixture_instance", "fixture_static", "guest_processes", "parent_bindings"):
            refresh_ref(self.root, observations[key])

        # The complete chain's before/after snapshots must carry the ready
        # protected identities.  Merge those actual synthetic ready rows into
        # both snapshots and omit only the kill target from the after image.
        ready_rows = {row["ProcessId"]: row for row in processes_payload["processes"]}
        for label, include_target in (("kill-pre-processes", True), ("kill-post-processes", False)):
            reference = raw_refs[label]
            path = chains_path.parent / reference["path"]
            document = json.loads(path.read_bytes())
            rows = {row["ProcessId"]: row for row in json.loads(document["stdout"])}
            rows.update({pid: copy.deepcopy(row) for pid, row in ready_rows.items() if include_target or pid != target_pid})
            if not include_target:
                rows.pop(target_pid, None)
            document["stdout"] = json.dumps(list(rows.values()), ensure_ascii=False, separators=(",", ":"))
            write(path, document)
            refresh_ref(chains_path.parent, reference)

        # The retained SDK projection was serialized by a client version that
        # added ``resultType`` after decoding.  Keep the synthetic raw stream
        # byte-for-byte joined to each retained mcp_result instead of treating
        # that version-only projection gap as a successful original.
        sdk_reference = chains["raw_originals"]["sdk_messages"]
        sdk_path = chains_path.parent / sdk_reference["path"]
        rows = [json.loads(line) for line in sdk_path.read_text(encoding="utf-8-sig").splitlines()]
        calls_by_id = {call["sdk_request_id"]: call for call in chains["calls"].values()}
        for row in rows:
            message = row["message"]
            call = calls_by_id.get(message.get("id"))
            if call is not None:
                row["started_at"] = call["started_at"]
                row["ended_at"] = call["ended_at"]
                if row["direction"] == "server_to_client":
                    message["result"] = copy.deepcopy(call["mcp_result"])
        sdk_path.write_text(
            "".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in rows),
            encoding="utf-8", newline="\n",
        )
        refresh_ref(chains_path.parent, sdk_reference)

    @staticmethod
    def _streams(stdout: str = "", stderr: str = "") -> dict[str, object]:
        return {
            "stdout": stdout, "stdout_size": len(stdout.encode()), "stdout_sha256": sha(stdout.encode()),
            "stderr": stderr, "stderr_size": len(stderr.encode()), "stderr_sha256": sha(stderr.encode()),
        }

    def _pc006(
        self, phase: dict[str, object], ready: dict[str, object], report: dict[str, object],
    ) -> None:
        source, comparison = "192.168.204.99", 28787
        started, ended = report["started_at"], report["ended_at"]
        network_path = self.root / phase["network_evidence"]["path"]
        network = json.loads(network_path.read_bytes())
        directory = network_path.parent

        def execution(role: str, bind: str, port: int) -> dict[str, object]:
            argv = legacy._pc006_curl_argv(bind, port)
            if role == "probe_source":
                code, stdout = 28, ""
                stderr = f"curl: (28) Failed to connect to 192.168.204.232 port {port} after 5001 ms: Timeout was reached"
            else:
                code, stdout, stderr = 0, ("401" if port == 28790 else "406"), ""
            return {
                "role": role, "port": port,
                "request": {"argv": argv, "command_line": " ".join(argv)},
                "started_at": started, "ended_at": ended, "exit_status": {"code": code},
                "response": self._streams(stdout, stderr),
            }

        for mode in (legacy.PC006_BOUND_MODE, legacy.PC006_DUAL_MODE):
            executions = [execution("probe_source", source, 28790)]
            if mode == legacy.PC006_DUAL_MODE:
                executions = [
                    execution(role, bind, port)
                    for port in (28790, comparison)
                    for role, bind in (("probe_source", source), ("allowed_source", "192.168.204.1"))
                ]
            payload = {
                "schema_version": 1, "kind": legacy.PC006_PROBE_KIND, "mode": mode,
                "probe_source_address": source, "target_host": "192.168.204.232",
                "comparison_port": comparison, "executions": executions,
            }
            stdout = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            argv = legacy.pc006_collector_argv(mode, source, comparison)
            envelope = {
                "schema_version": 1, "kind": legacy.PC006_COMMAND_KIND,
                "workflow_id": evidence.WORKFLOW_ID, "run_id": phase["run_id"],
                "restore_attempt_id": phase["restore_attempt_id"],
                "operation_id": f"pc006-{mode}", "observation": f"pc006-{mode}-synthetic",
                "vmx": evidence.VMX, "request": {"argv": argv, "command_line": " ".join(argv)},
                "started_at": started, "ended_at": ended, "exit_status": {"code": 0},
                "response": self._streams(stdout),
            }
            path = directory / f"pc006-{mode}.json"
            write(path, envelope)
            if mode == legacy.PC006_BOUND_MODE:
                bound = ref(self.root, path.relative_to(self.root).as_posix())
            else:
                dual = ref(self.root, path.relative_to(self.root).as_posix())

        boundary_path = directory / "pc006.json"
        boundary = {
            "schema_version": 1, "kind": legacy.PC006_BOUNDARY_KIND,
            "workflow_id": evidence.WORKFLOW_ID, "run_id": phase["run_id"],
            "restore_attempt_id": phase["restore_attempt_id"],
            "probe_source_address": source, "comparison_port": comparison,
            "bound_source_failure": bound, "dual_port_control": dual,
            "firewall_rule": copy.deepcopy(ready["observations"]["firewall"]),
        }
        write(boundary_path, boundary)
        network["non_allowed_source"] = ref(self.root, boundary_path.relative_to(self.root).as_posix())
        write(network_path, network)

    def _schema_identity(
        self, phase: dict[str, object], report: dict[str, object],
        chains: dict[str, object], chains_path: Path,
    ) -> None:
        network_path = self.root / phase["network_evidence"]["path"]
        network = json.loads(network_path.read_bytes())
        report_parent = phase["report"]["path"].rsplit("/", 1)[0]
        capture_reference = chains["raw_originals"]["sdk_messages"]
        capture_path = chains_path.parent / capture_reference["path"]
        rows = [json.loads(line) for line in capture_path.read_text(encoding="utf-8").splitlines()]
        # The four-chain capture retains the calls' individual wall-clock
        # windows.  Schema identity needs a passive lifecycle capture whose
        # file order is also time order, so keep a separate projection rather
        # than weakening either validator.
        schema_capture_path = network_path.parent / "stdio-messages.ndjson"
        for row in rows:
            row["started_at"] = report["started_at"]
            row["ended_at"] = report["started_at"]
        schema_capture_path.write_text(
            "".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in rows),
            encoding="utf-8", newline="\n",
        )
        launch_path = network_path.parent / "stdio-launch.json"
        argv = [
            r"C:\mcp-velociraptor\.venv\Scripts\python.exe",
            r"C:\mcp-velociraptor\mcp_velociraptor_bridge.py",
        ]
        launch = {
            "schema_version": 1, "kind": legacy.STDIO_LAUNCH_KIND,
            "workflow_id": evidence.WORKFLOW_ID, "run_id": f"{phase['run_id']}-stdio",
            "restore_attempt_id": phase["restore_attempt_id"],
            "host": {"scope": "guest", "computer_name": "DESKTOP-3FI41GR"},
            "request": {"argv": argv, "command_line": " ".join(argv)},
            "started_at": report["started_at"], "ended_at": report["ended_at"],
            "exit_status": {"code": 0}, "response": self._streams('{"synthetic":"stdio-diagnostic"}'),
        }
        write(launch_path, launch)
        schema_path = network_path.parent / "schema-identity.json"
        schema = {
            "schema_version": 1, "kind": legacy.SCHEMA_IDENTITY_KIND,
            "workflow_id": evidence.WORKFLOW_ID, "run_id": phase["run_id"],
            "restore_attempt_id": phase["restore_attempt_id"],
            "http": {
                "transport": "http",
                "headers": ref(self.root, f"{report_parent}/http-headers.json"),
                "tools_list": ref(self.root, f"{report_parent}/tools-list.json"),
            },
            "stdio": {
                "transport": "stdio", "launch": ref(self.root, launch_path.relative_to(self.root).as_posix()),
                "capture": ref(self.root, schema_capture_path.relative_to(self.root).as_posix()),
            },
        }
        write(schema_path, schema)
        network["schema_identity"] = ref(self.root, schema_path.relative_to(self.root).as_posix())
        write(network_path, network)

    def _source_ref(self, name: str, data: bytes) -> dict[str, object]:
        return {"repo_path": name, "blob": blob(data), "content": ref(self.root, f"source/{name}")}

    def _canonical(self) -> dict[str, object]:
        prep = json.loads(self.preparation.read_bytes())
        migration = json.loads(self.migration.read_bytes())
        return {
            "schema_version": 6, "workflow_id": evidence.WORKFLOW_ID, "epoch": 7,
            "phase": "PREPARATION_BASELINE",
            "active_snapshot": {"name": evidence.SNAPSHOT_187, "checkpoint_marker": evidence.MARKER_187,
                "purpose": "P05 preparation only; not product readiness or P06 authorization"},
            "automatic_restore_allowlist": [evidence.SNAPSHOT_187],
            "retired_snapshots": [{"name": name, "status": evidence.MANUAL_ONLY} for name in (
                "Snapshot 183-FakenetNG测试专用", "Snapshot 184-Velociraptor-MCP测试基线",
                "Snapshot 1-开启Windows-MCP", "Snapshot 186-Velociraptor-MCP网络部署基线", evidence.SNAPSHOT_188)],
            "migration_evidence": {"kind": "pc020-requalification-migration-v1", "source": "pc020-migration",
                "evidence_path": self.migration.relative_to(self.root).as_posix(), "evidence_sha256": sha(self.migration.read_bytes()),
                "predecessor_sha256": evidence.PREDECESSOR_SHA256, "migrated_at": migration["migrated_at"]},
            "preparation_evidence": {"kind": "pc020-snapshot187-preparation-v1", "source": "pc020-preparation-admission",
                "evidence_path": self.preparation.relative_to(self.root).as_posix(), "evidence_sha256": sha(self.preparation.read_bytes()),
                "qualified_at": prep["qualified_at"]}, "activation_evidence": None,
        }

    def _creation(self, marker: str) -> Path:
        directory = self.root / "creation-189"
        tree_before = f"Total snapshots: 2\n{evidence.SNAPSHOT_187}\n  {evidence.SNAPSHOT_188}\n"
        tree_after = tree_before.replace("Total snapshots: 2", "Total snapshots: 3") + f"  {evidence.SNAPSHOT_189}\n"
        metadata = "\n".join([
            'snapshot.numSnapshots = "3"', 'snapshot.lastUID = "8"', 'snapshot.current = "8"',
            f'snapshot0.displayName = "{evidence.SNAPSHOT_187}"', 'snapshot0.uid = "3"', f'snapshot0.filename = "{evidence.MARKER_187}"',
            f'snapshot1.displayName = "{evidence.SNAPSHOT_188}"', 'snapshot1.uid = "4"', 'snapshot1.parent = "3"', 'snapshot1.filename = "Win10MalBox-Velo-Snapshot4.vmsn"',
            f'snapshot2.displayName = "{evidence.SNAPSHOT_189}"', 'snapshot2.uid = "8"', 'snapshot2.parent = "3"', f'snapshot2.filename = "{marker}"', "",
        ])
        base = ["/usr/bin/vmrun", "-T", "ws"]
        values = {
            "tree_before": host_command("unused", "create-189", "tree_before", base + ["listSnapshots", evidence.VMX, "showTree"], tree_before, 0),
            "create_operation": host_command("unused", "create-189", "create_operation", base + ["snapshot", evidence.VMX, evidence.SNAPSHOT_189], "", 2),
            "tree_after": host_command("unused", "create-189", "tree_after", base + ["listSnapshots", evidence.VMX, "showTree"], tree_after, 4),
            "metadata_readback": host_command("unused", "create-189", "metadata_readback", ["/usr/bin/cat", str(Path(evidence.VMX).with_suffix(".vmsd")).replace("\\", "/")], metadata, 6),
        }
        times = [("2026-09-15T03:50:00Z", "2026-09-15T03:50:01Z"), ("2026-09-15T03:50:02Z", "2026-09-15T03:50:03Z"), ("2026-09-15T03:50:04Z", "2026-09-15T03:50:05Z"), ("2026-09-15T03:50:06Z", "2026-09-15T03:50:07Z")]
        doc: dict[str, object] = {"schema_version": 1, "workflow_id": evidence.WORKFLOW_ID, "candidate": evidence.SNAPSHOT_189, "checkpoint_marker": marker, "vmx": evidence.VMX}
        for (name, value), (start, end) in zip(values.items(), times, strict=True):
            value.pop("restore_attempt_id")
            value["started_at"], value["ended_at"] = start, end
            write(directory / f"{name}.json", value)
            doc[name] = ref(directory, f"{name}.json")
        path = directory / "creation.json"
        write(path, doc)
        return path

    def _restore(self, phase_dir: str, run: str, attempt: str, stage: str, snapshot: str, marker: str) -> dict[str, object]:
        directory = self.root / phase_dir / "restore"
        names = [evidence.SNAPSHOT_187, evidence.SNAPSHOT_188] + ([] if snapshot == evidence.SNAPSHOT_187 else [evidence.SNAPSHOT_189])
        tree = f"Total snapshots: {len(names)}\n" + "\n".join(names) + "\n"
        base = ["/usr/bin/vmrun", "-T", "ws"]
        records: dict[str, Path] = {}
        values = {
            "snapshot_metadata": host_command(attempt, "snapshot-metadata", "snapshot-tree-readonly", base + ["listSnapshots", evidence.VMX], tree, 0),
            "revert_operation": host_command(attempt, "revert-operation", "single-revert", base + ["revertToSnapshot", evidence.VMX, snapshot], "", 2),
            "pre_start_marker": host_command(attempt, "pre-start-marker", "vmx-checkpoint-marker-before-start", ["/bin/grep", "^checkpoint.vmState", evidence.VMX], f'checkpoint.vmState = "{marker}"\n', 4),
            "post_restore_hostname": guest_command(attempt),
        }
        for kind, value in values.items():
            path = directory / f"{kind}.json"; write(path, value); records[kind] = path
        canonical = directory / "canonical.json"; canonical.write_bytes(self.canonical_bytes); records["canonical_readback"] = canonical
        records["pc020_migration"] = self.migration; records["pc020_preparation"] = self.preparation
        return {"workflow_id": evidence.WORKFLOW_ID, "run_id": run, "restore_attempt_id": attempt,
            "snapshot_stage": stage, "snapshot_name": snapshot, "checkpoint_marker": marker,
            "canonical_schema_version": 6, "canonical_epoch": 7, "canonical_phase": "PREPARATION_BASELINE",
            "canonical_sha256": sha(self.canonical_bytes),
            "restore_records": [{"kind": kind, "path": path.relative_to(self.root).as_posix(), "sha256": sha(path.read_bytes())} for kind, path in records.items()]}

    def _manifest(self, phase_dir: str, phase: dict[str, object]) -> None:
        directory = self.root / phase_dir
        report = json.loads((directory / "report.json").read_bytes())
        manifest_doc = pkg.build_phase_manifest(
            phase_root=directory,
            phase_prefix=phase_dir,
            workflow_id=evidence.WORKFLOW_ID,
            report=report,
            report_ref_path=f"{phase_dir}/report.json",
        )
        (directory / "package-manifest.json").write_bytes(evidence.canonical_json(manifest_doc))

    def _receipt(self, root_doc: dict[str, object]) -> None:
        write(
            self.root / "issuance-receipt.json",
            build_issuance_receipt(self.root, root_doc, self.canonical_bytes),
        )


def build_issuance_receipt(root: Path, root_doc: dict[str, object], canonical_bytes: bytes) -> dict[str, object]:
    issued_at = root_doc["issued_at"]
    events = [
        {"sequence": 1, "event": "PRE_ISSUE_GRAPH_VALIDATED", "at": "2026-09-15T04:10:00Z"},
        {"sequence": 2, "event": "ISSUED_AT_SAMPLED", "at": issued_at},
        {"sequence": 3, "event": "ROOT_WRITTEN", "at": "2026-09-15T04:12:01Z"},
        {"sequence": 4, "event": "ROOT_FILE_FSYNCED", "at": "2026-09-15T04:12:02Z"},
        {"sequence": 5, "event": "ROOT_DIRECTORY_FSYNCED", "at": "2026-09-15T04:12:03Z"},
        {"sequence": 6, "event": "ROOT_READBACK_VALIDATED", "at": "2026-09-15T04:12:04Z"},
    ]
    second = root_doc["candidate_cycles"][1]
    receipt = {
        "schema_version": 2, "kind": "snapshot189-activation-issuance-receipt-v2",
        "workflow_id": evidence.WORKFLOW_ID, "issuance_id": root.name,
        "operation": "P05_ACTIVATION_ISSUE",
        "source": {
            "source_inputs_sha256": sha(evidence.canonical_json(root_doc["source_inputs"])),
            "implementation_sources_sha256": sha(evidence.canonical_json(root_doc["implementation_sources"])),
        },
        "epoch7": {
            "canonical_sha256": sha(canonical_bytes), "schema_version": 6,
            "epoch": 7, "phase": "PREPARATION_BASELINE", "active_snapshot": evidence.SNAPSHOT_187,
        },
        "cycle2": {
            "restore_attempt_id": second["restore_attempt_id"], "run_id": second["run_id"],
            "report": copy.deepcopy(second["report"]),
            "package_manifest": copy.deepcopy(second["package_manifest"]),
        },
        "activation_root": {
            "path": "activation-evidence.json",
            "size": (root / "activation-evidence.json").stat().st_size,
            "sha256": sha((root / "activation-evidence.json").read_bytes()),
        },
        "issued_at": issued_at, "events": events,
        "status": "ROOT_VALIDATED", "error": None,
    }
    return receipt
