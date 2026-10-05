"""Fixed, read-only PC026 governance reader. No signing or publication API.

The production root is code-owned. ``_load_at`` is an explicit isolated-file
test seam; it is never selected through command-line arguments or environment.
Historical archive coordinates are authenticated by the pinned bootstrap list.
"""
from __future__ import annotations

import ast
import contextvars
from functools import wraps
import inspect
from dataclasses import dataclass, field
import errno
import json
import os
from pathlib import Path, PureWindowsPath, PurePosixPath
import re
import stat
import struct
import uuid

from jsonschema import Draft202012Validator
from tests import p05_pc020_evidence as evidence
from tests import p05_pc021_readonly as readonly

REPOSITORY = Path(__file__).absolute().parents[1]
BASE = "PLAN/2026.10.02/"
RUNTIME = BASE + "controller-runtime-record.json"
APPROVAL = BASE + "controller-approval.json"
FREEZE = BASE + "implementation-freeze.json"
DEPLOYMENT = BASE + "deployment-configuration.json"
COMPLETION = BASE + "p06-completion-record.json"
CONTRACT = BASE + "2026.10.02-04-PC026-运行信任锚读取契约.md"
CONTRACT_SHA = "5336acb8ed4a1536f2aac71792b976d849b1cc8cab0234063e735a1b5e28ad71"
NATIVE_CONTRACT = BASE + "2026.10.02-05-PC026-Windows固定原生读取补充.md"
NATIVE_CONTRACT_SHA = "c5c9f1291bbe0bee4e40b642482b28ac62aa28fed98305fb42448ee5c962d300"
HANDOFF_CONTRACT = BASE + "2026.10.02-06-PC026-P07固定交接读取契约.md"
HANDOFF_CONTRACT_SHA = "dc3b548d8e2741c5773df669962fdab51af41ca7db204655a3a2302bcf12676c"
CALL_CLOCK_CONTRACT = BASE + "2026.10.02-07-PC026-P06调用单调钟原件补充.md"
CALL_CLOCK_CONTRACT_SHA = "b55e5faee6b5b01f7a0d556a131dc77f73fe911c3df0d5042f57bc9a3ccb1f76"
BODY_CONTRACT = 'PLAN/2026.10.03-01-PC026-原始HTTP消息体捕获接口.md'
BODY_CONTRACT_SHA = '69349f4a18530ee1bbd32dabcb0a051287442c56fee26968134ba3258fa1790b'
JOIN_CONTRACT = 'PLAN/2026.10.03-02-PC026-原始MCP调用关联接口.md'
JOIN_CONTRACT_SHA = 'b3a8dd1a6e69b838d164a07807e9747e8996bccbe882db55ac7c893af42f0a0a'
HTTP_BINDING_CONTRACT = 'PLAN/2026.10.03-03-PC026-P06原始消息正式消费接口.md'
HTTP_BINDING_CONTRACT_SHA = '15f7ebaf2c2fa552ad91f4baabc69c00d54da308183a09d7d7086cb2c4315cc0'
RAW_CONTRACTS = ((BODY_CONTRACT,6354,BODY_CONTRACT_SHA),
                 (JOIN_CONTRACT,7359,JOIN_CONTRACT_SHA),
                 (HTTP_BINDING_CONTRACT,7999,HTTP_BINDING_CONTRACT_SHA))
ARCHIVE_CONTRACT = 'PLAN/2026.10.04-01-PC026-正式归档attempt账契约.md'
ARCHIVE_CONTRACT_SHA = 'd9ba3b368bc70e300fbead2f4e3ffe7af354158659d450bdae4f485000365ceb'
LIFECYCLE_CONTRACT = 'PLAN/2026.10.04-02-PC026-归档生命周期与结束消费契约.md'
LIFECYCLE_CONTRACT_SHA = 'b739f989632d86fe71084cdbcb2c0291b49198330b69b1595cd171d6e5f5a1d8'
NORMATIVE = BASE + "pc026-r01/current-normative-inputs-pc026-r01.json"
NORMATIVE_SHA = "47cbe9278b252b396d7f69a31bec2b4e29c72f2933a7410142735909877484fb"
MODEL = BASE + "pc026-r01/attachments/controller-model.schema.json"
BOOTSTRAP = BASE + "pc026-r01/attachments/bootstrap-publication-manifest.json"
EVIDENCE = "Logs/P05/wf-01a05d1d-p05"
SELECTOR = "PLAN/2026.09.02/2026.09.02-02-总纲-mcp-velociraptor-Windows-DFIR二次开发-长程执行/快照恢复选择器.py"
CANONICAL = SELECTOR.rsplit("/", 1)[0] + "/快照恢复状态.json"
PROFILE = "pc026-snapshot191-v1"
VM_UUID = "55804d56-262e-33b0-9e8f-fa0bb583b865"
SID = re.compile(r"S-1-(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*)){1,15}")
# Explicit deployment entrypoints and resources. Local imports below are also
# required, including lazily imported modules; this is not a directory scan.
ENTRIES = frozenset({SELECTOR, "tests/p05_pc026_governance.py",
    "tests/p05_selector_readonly.py", "tests/p06_pc021_consumer.py",
    "mcp_velociraptor_bridge.py", "velociraptor_api.py",
    "velo_transfer/adapters.py", "velo_transfer/wire.py",
    "tests/test_p05_pc020_activation.py",
    "tests/test_p05_pc026_governance.py", "tests/pc026_governance_fixture.py",
    "tests/test_p05_selector_schema6.py", "tests/test_p05_pc021_transition_output.py"})
ENTRIES = ENTRIES | frozenset({"tests/scenario_runner.py", "tests/p06_evidence.py",
    "tests/p06_receive.py", "tests/p06_aggregate_reports.py", "tests/p07_cost_measurement.py",
    "tests/p07_cost_measurement_r232.py", "tests/p06_pc026_binding.py",
    "tests/test_p06_pc026_binding.py", "tests/p06_resource_qualification.py",
    "tests/p06_formal_session.py", "tests/p06_contracts.py", "tests/test_p06_contracts.py",
    "tests/test_p06_resource_gate.py", "tests/test_p06_aggregate.py",
    "tests/p05_pc026_windows_reader.py", "tests/test_p05_pc026_windows_reader.py",
    "tests/p07_handoff.py", "tests/test_p07_handoff.py",
    "tests/p06_call_clock.py", "tests/test_p06_call_clock.py"})
ENTRIES = ENTRIES | frozenset({'tests/p06_http_body_capture.py','tests/p06_mcp_raw_join.py',
    'tests/p06_http_binding.py','tests/test_p06_http_body_capture.py','tests/test_p06_mcp_raw_join.py',
    'tests/test_p06_http_binding.py'})
RESOURCES = frozenset({BODY_CONTRACT,JOIN_CONTRACT,HTTP_BINDING_CONTRACT,NATIVE_CONTRACT, HANDOFF_CONTRACT, CALL_CLOCK_CONTRACT, "requirements.txt", "requirements.lock",
    "velo_transfer/transfer_tools_schema.json",
    "tests/data/p05_scenario_index.json", "tests/data/p05_fixture_spec.json",
    "tests/data/p05_dependency_manifest.json", "tests/p05_prepare_fixtures.ps1",
    "tests/p05_service_install.ps1", "docs/p05-security-receipt.schema.json",
    "tests/fixtures/artifacts/Generic.Utils.KillProcess.yaml",
    "tests/scenarios/schema-v1.json",
    "tests/scenarios/representative/p05-flow-triage-repair-initial.json",
    "tests/scenarios/representative/p05-flow-triage-repair-candidate.json"})
RESOURCES = RESOURCES | frozenset({"tests/data/p06_scenario_index.json",
    "tests/data/p06_coverage_manifest.json", "tests/data/p06_resource_policy.json",
    "tests/data/p03_invocations.json", "tests/data/p04_fixed_tools_golden.json",
    *('tests/scenarios/full/' + name + '.json' for name in (
        'p06-compromise-scope', 'p06-ransomware-root-cause', 'p06-credential-lateral-movement',
        'p06-data-exfiltration', 'p06-remediation-validation'))})
RESOURCES = RESOURCES | frozenset({ARCHIVE_CONTRACT, LIFECYCLE_CONTRACT,
    'docs/observation-sdk-pin.json', 'docs/observation-sdk-source-map.json',
    'docs/observation-sdk-LICENSE.txt', 'README.md', 'agent_poc/README.md',
    'PLAN/2026.10.03-08-PC026-观察归档记录格式契约.md',
    'PLAN/2026.10.03-09-PC026-Windows观察记录发布原语.md',
    'PLAN/2026.10.03-10-PC026-请求归档写入接缝契约.md',
    'PLAN/2026.10.03-11-PC026-Windows私有目录分配原语.md'})
SOURCE_RESOURCES = frozenset(path for path in RESOURCES
    if path in {LIFECYCLE_CONTRACT, 'docs/observation-sdk-pin.json',
        'docs/observation-sdk-source-map.json', 'docs/observation-sdk-LICENSE.txt',
        ARCHIVE_CONTRACT, BODY_CONTRACT, JOIN_CONTRACT, HTTP_BINDING_CONTRACT, NATIVE_CONTRACT, HANDOFF_CONTRACT, CALL_CLOCK_CONTRACT} or path.startswith(('PLAN/2026.10.03-08-', 'PLAN/2026.10.03-09-',
        'PLAN/2026.10.03-10-', 'PLAN/2026.10.03-11-', 'tests/data/', 'tests/scenarios/')))

# Reviewed local module catalog: omissions cannot be mistaken for installed
# third-party imports when this reader itself runs in an incomplete tree.
# Includes parent __init__ files, the fixture's path-read test helper, and
# PS1 service installer -> service host -> path-selected dispatch observer.
LOCAL_MODULES = frozenset({
    'PLAN/2026.09.02/2026.09.02-02-总纲-mcp-velociraptor-Windows-DFIR二次开发-长程执行/快照恢复选择器.py',
    'mcp_velociraptor_bridge.py',
    'tests/__init__.py',
    'tests/p05_baseline_adoption.py',
    'tests/p05_candidate_creation.py',
    'tests/p05_four_chain_evidence.py',
    'tests/p05_http_evidence.py',
    'tests/p05_network_window.py',
    'tests/p05_pc020_activation.py',
    'tests/p05_pc020_creation.py',
    'tests/p05_pc020_evidence.py',
    'tests/p05_pc020_restore.py',
    'tests/p05_pc020_transition.py',
    'tests/p05_pc021_activation_writer.py',
    'tests/p05_pc021_issuer.py',
    'tests/p05_pc021_package.py',
    'tests/p05_pc021_readback.py',
    'tests/p05_pc021_readonly.py',
    'tests/p05_pc021_stage_rules.py',
    'tests/p05_pc021_streaming.py',
    'tests/p05_pc021_transition_evidence.py',
    'tests/p05_pc026_governance.py',
    'tests/p05_pc026_profile.py',
    'tests/p05_process_parent.py',
    'tests/p05_ready_evidence.py',
    'tests/p05_real_acceptance.py',
    'tests/p05_security_receipt.py',
    'tests/p05_service_host.py',
    'tests/p05_service_observation.py',
    'tests/p05_sdk_capture.py',
    'tests/p05_selector_readonly.py',
    'tests/p05_snapshot_raw.py',
    'tests/p06_aggregate_reports.py',
    'tests/p06_evidence.py',
    'tests/p06_package.py',
    'tests/p06_call_clock.py',
    'tests/test_p06_call_clock.py',
    'tests/p06_pc021_consumer.py',
    'tests/p06_receive.py',
    'tests/p06_resource_gate.py',
    'tests/p06_resource_policy.py',
    'tests/pc020_activation_fixture.py',
    'tests/pc022_windows_refresh.py',
    'tests/pc026_governance_fixture.py',
    'tests/scenario_runner.py',
    'tests/test_p05_pc020_activation.py',
    'tests/test_p05_pc020_evidence.py',
    'tests/test_p05_pc020_restore.py',
    'tests/test_p05_pc021_activation_writer.py',
    'tests/test_p05_pc021_capability.py',
    'tests/test_p05_pc021_transition_output.py',
    'tests/test_p05_pc026_governance.py',
    'tests/test_p05_recovery_contract.py',
    'tests/test_p05_selector_schema6.py',
    'velo_transfer/__init__.py',
    'velo_transfer/adapters.py',
    'velo_transfer/bundle.py',
    'velo_transfer/connection.py',
    'velo_transfer/errors.py',
    'velo_transfer/filesystem.py',
    'velo_transfer/guest_service.py',
    'velo_transfer/guest_worker.py',
    'velo_transfer/http_budget.py',
    'velo_transfer/http_wire.py',
    'velo_transfer/manifest.py',
    'velo_transfer/mcp_tools.py',
    'velo_transfer/policy.py',
    'velo_transfer/protocol.py',
    'velo_transfer/storage.py',
    'velo_transfer/windows_commands.py',
    'velo_transfer/windows_platform.py',
    'velo_transfer/wire.py',
    'velociraptor_api.py',
    'velociraptor_dynamic_artifacts.py',
    'velociraptor_env.py',
    'velociraptor_fixed_tools.py',
    'velociraptor_mcp_core.py',
    'velociraptor_observation.py',
    'velociraptor_observation_journal.py',
    'velociraptor_observation_archive.py',
    'velociraptor_transport.py',
})
LOCAL_MODULES = LOCAL_MODULES | frozenset({'velociraptor_observation_namespace.py',
    'velociraptor_observation_windows.py', 'tests/test_observation_namespace.py',
    'tests/test_observation_windows.py', 'tests/test_observation_archive.py',
    'tests/test_p05_pc026_windows_reader.py'})

LOCAL_MODULES = LOCAL_MODULES | frozenset({'tests/pc026_raw_fixture.py'}) | ENTRIES | frozenset({"tests/test_p06_evidence_schema5.py", "tests/p06_individual_acceptance.py"})


# Diagnostic SCM entry and its explicit MODEL lifecycle verification; no approval.
LOCAL_MODULES = LOCAL_MODULES | frozenset({'tests/p05_service_qualification.py',
    'tests/test_p05_service_qualification.py', 'tests/test_observation_namespace.py',
    'tests/test_observation_windows.py', 'tests/test_observation_archive.py'})

LOCAL_MODULES = LOCAL_MODULES | frozenset({
    'velociraptor_observation_sdk.py', 'velociraptor_observation_startup.py',
    'tests/test_observation_startup.py', 'velociraptor_observation_workers.py',
    'tests/test_observation_workers.py', 'velociraptor_observation_sdk_adapter.py',
    'tests/test_observation_sdk_adapter.py',
    'velociraptor_observation_controller.py', 'tests/test_observation_controller.py',
    'tests/test_observation_transfer_children.py', 'tests/test_observation_responses.py',
    'tests/test_observation_prefix.py', 'tests/test_observation_close_io.py',
    'tests/test_observation_allocations.py',
    'velociraptor_observation_cut.py', 'tests/observation_model_export.py',
    'tests/test_observation_cut.py', 'tests/test_observation_cut_transfer.py',
    'tests/test_transfer_guest.py',
    'velo_transfer/guest_cli.py',
    'velociraptor_observation_attempts.py', 'velociraptor_observation_catalog.py',
    'velociraptor_observation_config.py', 'tests/test_observation_attempts.py',
    'tests/test_observation_catalog.py', 'tests/test_observation_config.py',
    'tests/test_velociraptor_observation.py'})
ENTRIES = ENTRIES | frozenset({'velociraptor_observation_attempts.py',
    'tests/test_observation_attempts.py', 'tests/test_observation_catalog.py', 'tests/test_observation_config.py'})

# Production native export and its directly executed qualification seams.
ENTRIES = ENTRIES | frozenset({'velociraptor_observation_export.py',
    'tests/test_observation_native_export.py', 'tests/test_observation_native_startup.py',
    'tests/test_observation_startup_cleanup.py'})
LOCAL_MODULES = LOCAL_MODULES | ENTRIES

# Closed-export maintenance source activation, with actual SDK verification.
ENTRIES = ENTRIES | frozenset({'velociraptor_observation_maintenance_plan.py',
    'tests/test_observation_maintenance.py'})
LOCAL_MODULES = LOCAL_MODULES | ENTRIES

ENTRIES = ENTRIES | frozenset({'tests/test_transfer_protocol_channel.py'})
LOCAL_MODULES = LOCAL_MODULES | ENTRIES

# Admitted host acquisition and its complete existing transfer consumer seam.
ENTRIES = ENTRIES | frozenset({'velociraptor_observation_maintenance.py',
    'tests/test_observation_maintenance_acquisition.py',
    'tests/test_observation_maintenance_admission.py'})
LOCAL_MODULES = LOCAL_MODULES | ENTRIES | frozenset({
    'velo_transfer/request.py', 'velo_transfer/host_coordinator.py',
    'velo_transfer/host_journal.py', 'velo_transfer/host_content.py',
    'velo_transfer/host_partial.py', 'velo_transfer/host_publication.py',
    'velo_transfer/result.py', 'velo_transfer/host_cleanup.py'})

# Independent fixed-admission original-session consumption and actual SDK tests.
ENTRIES = ENTRIES | frozenset({'velociraptor_observation_host.py',
    'tests/test_observation_host.py','tests/test_observation_host_consumers.py',
    'tests/p04_fixture_server.py','tests/test_p04_fixed_tools.py'})
LOCAL_MODULES = LOCAL_MODULES | ENTRIES

# Finite independent failure diagnostics and actual HTTP MODEL source tests.
ENTRIES = ENTRIES | frozenset({'velociraptor_observation_failure.py',
    'tests/test_observation_failure.py','tests/test_observation_failure_http.py'})
LOCAL_MODULES = LOCAL_MODULES | ENTRIES

# Historical coordinate consistency and actual host producer/consumer closure.
ENTRIES = ENTRIES | frozenset({
    'tests/test_p05_source_layouts.py',
    'tests/test_observation_host_work.py','tests/test_observation_host_semantics.py',
    'tests/test_observation_host_producer.py','tests/test_observation_host_public.py',
    'tests/test_observation_host_selected.py','tests/test_observation_host_finalization.py',
    'tests/test_observation_host_failure_producer.py'})
LOCAL_MODULES = LOCAL_MODULES | ENTRIES

# Actual SDK/capture stream close ownership and primary-error preservation.
ENTRIES = ENTRIES | frozenset({'tests/test_observation_sdk_close.py'})
LOCAL_MODULES = LOCAL_MODULES | ENTRIES

_CONSUMPTION = contextvars.ContextVar("pc026_read_consumption", default=None)


def consumption(function):
    """Close native retained handles at the outer actual consumer boundary."""
    def begin():
        groups = _CONSUMPTION.get()
        if groups is not None:
            return groups, None
        groups = []
        return groups, _CONSUMPTION.set(groups)
    def finish(groups, token, primary):
        if token is not None:
            errors = []
            try:
                for group in reversed(groups):
                    try:
                        group.close()
                    except Exception as exc:
                        errors.append(str(exc))
            finally:
                _CONSUMPTION.reset(token)
            if errors:
                if primary is not None:
                    primary.add_note('native close failures: ' + repr(errors))
                else:
                    raise GovernanceError('native close failures: ' + repr(errors))
    if inspect.iscoroutinefunction(function):
        @wraps(function)
        async def asynchronous(*args, **kwargs):
            groups, token = begin()
            primary = None
            try:
                return await function(*args, **kwargs)
            except BaseException as exc:
                primary = exc
                raise
            finally:
                finish(groups, token, primary)
        return asynchronous
    @wraps(function)
    def synchronous(*args, **kwargs):
        groups, token = begin()
        primary = None
        try:
            return function(*args, **kwargs)
        except BaseException as exc:
            primary = exc
            raise
        finally:
            finish(groups, token, primary)
    return synchronous


def before_effect():
    for group in _CONSUMPTION.get() or ():
        group.recheck()


class GovernanceError(evidence.Pc020EvidenceError):
    pass


def require(condition, message):
    if not condition:
        raise GovernanceError(message)


def relative(value):
    value = evidence._safe_relative(value, "governance coordinate")
    require(":" not in value and "\0" not in value, "unsafe governance coordinate")
    return value


def ref(value):
    require(isinstance(value, dict) and set(value) == evidence.REF_KEYS,
            "governance Ref must have exactly three keys")
    relative(value["path"])
    require(type(value["size"]) is int and value["size"] >= 0
            and evidence._valid_sha(value["sha256"]), "invalid governance Ref identity")
    require(value["path"] != RUNTIME, "runtime record must remain outside dependency closure")
    return value


def refs(values):
    require(isinstance(values, list) and bool(values), "nonempty Ref array required")
    result = {}
    for value in values:
        ref(value)
        require(value["path"] not in result, "duplicate governance Ref path")
        result[value["path"]] = value
    require(list(result) == sorted(result, key=lambda p: p.encode("utf-8")),
            "Ref array is not UTF8-path sorted")
    return result


def nested_refs(value):
    """Manifest rows may add provenance fields; byte identities remain exact."""
    if isinstance(value, dict):
        if evidence.REF_KEYS <= set(value):
            yield ref({key: value[key] for key in evidence.REF_KEYS})
        for child in value.values():
            yield from nested_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from nested_refs(child)


def exact(value, keys, kind, status=None):
    require(set(value) == set(keys.split()) and type(value.get("schema_version")) is int
            and value["schema_version"] == 1 and value.get("kind") == kind,
            "governance exact model differs: " + kind)
    if "profile_id" in value:
        require(value["profile_id"] == PROFILE and value["workflow_id"] == evidence.WORKFLOW_ID,
                "governance profile/workflow differs")
    if status is not None:
        require(value.get("status") == status, "governance status differs")


def _acl(fd, info):
    # Linux fgetxattr reports absence distinctly from inability to read ACLs.
    # Save the complete kernel ACL byte arrays, not a mode-only approximation.
    require(os.name == "posix" and hasattr(os, "getxattr"), "unsupported host ACL reader")
    rows = []
    for name in ("system.posix_acl_access", "system.posix_acl_default"):
        try:
            value = os.getxattr(fd, name)
        except OSError as exc:
            if exc.errno != errno.ENODATA:
                raise GovernanceError("host ACL observation unavailable") from exc
            value = None
        rows.append({"name": name, "value_hex": None if value is None else value.hex()})
    return evidence.canonical_json({"mode": f"{stat.S_IMODE(info.st_mode):04o}",
        "owner_uid": str(info.st_uid), "owner_gid": str(info.st_gid), "extended_acl": rows})


def _read(path, *, reader=None):
    if os.name == "nt":
        from tests.p05_pc026_windows_reader import WindowsSession
        owned = reader is None
        reader = reader or WindowsSession()
        try:
            return reader.read(path, private=path.name in {
                'observation-lifecycle-configuration.json',
                "observation-archive-configuration.json", "observation-namespace-root.json",
                "controller-runtime-record.json", "controller-approval.json",
                "deployment-configuration.json", "p06-completion-record.json", ".env", "api.config.yaml"})
        except Exception as exc:
            raise GovernanceError("native governance read failed: " + str(exc)) from exc
        finally:
            if owned:
                reader.close()
    return _read_posix(path)


def _read_posix(path):
    stream = _stream_posix(path)
    chunks = []
    while True:
        try: chunks.append(next(stream))
        except StopIteration as end:
            return b''.join(chunks), *end.value


def _stream_posix(path):
    """Retain no-follow ancestor handles through bytes, owner and full ACL read."""
    require(os.name == "posix", "production governance reader requires a POSIX host")
    handles = []
    try:
        bound = readonly._walk(path, handles)
        security = []
        for fd, directory, _, _ in bound:
            info = os.fstat(fd)
            security.append((info.st_uid, info.st_gid, _acl(fd, info)))
        leaf = os.fstat(bound[-1][0])
        count = 0
        while chunk := os.read(bound[-1][0], 65536):
            count += len(chunk)
            yield chunk
        fresh = readonly._walk(path, handles)
        for original, current, sec in zip(bound, fresh, security):
            info = os.fstat(original[0])
            require(original[2] == current[2]
                and (original[1] or original[3] == current[3] == readonly._metadata(info))
                and sec == (info.st_uid, info.st_gid, _acl(original[0], info)),
                "governance path identity/content/ACL drift")
        require(count == leaf.st_size, "governance read length differs")
        identity = {"platform": "posix", "device": str(leaf.st_dev), "inode": str(leaf.st_ino),
            "owner_uid": str(leaf.st_uid), "owner_gid": str(leaf.st_gid),
            "principal_uid": str(os.geteuid()), "mode": f"{stat.S_IMODE(leaf.st_mode):04o}",
            "acl_sha256": evidence._sha(security[-1][2])}
        return (tuple(row[2] for row in bound), tuple(security), bound[-1][3]), identity
    except (OSError, readonly.ContentReadError) as exc:
        raise GovernanceError("safe governance read failed: " + str(exc)) from exc
    finally:
        for fd in reversed(handles):
            os.close(fd)


@dataclass
class GovernedGroup:
    repository: Path
    approval: dict
    allowed: dict
    locked: dict
    normative_refs: dict
    freeze_refs: dict
    bootstrap_refs: dict
    synthetic_fixture: bool
    validators: dict = field(default_factory=dict)
    reader: object | None = None
    consumer_inputs: dict = field(default_factory=dict)
    consumer_streams: dict = field(default_factory=dict)

    @property
    def endpoint(self):
        return "guest" if self.reader is not None else "host"

    def read_path(self, path):
        return _read(path, reader=self.reader)

    def stream_path(self, path):
        """Same security reader, bounded bytes and locked content/identity."""
        import hashlib
        stream = self.reader.stream(path) if self.reader is not None else _stream_posix(path)
        digest = hashlib.sha256(); size = 0
        try:
            while True:
                try: chunk = next(stream)
                except StopIteration as end:
                    identity, _ = end.value
                    value = (size, digest.hexdigest(), identity)
                    prior = self.consumer_streams.setdefault(path, value)
                    require(prior == value, 'consumer streamed input drift: ' + str(path))
                    if path in self.consumer_inputs:
                        raw, old_identity = self.consumer_inputs[path]
                        require((len(raw), evidence._sha(raw), old_identity) == value,
                                'consumer input/stream drift')
                    return
                digest.update(chunk); size += len(chunk)
                yield chunk
        finally:
            stream.close()

    def close(self):
        if self.reader is not None:
            self.reader.close()


    def read(self, reference):
        reference = ref(reference)
        require(self.allowed.get(reference["path"]) == reference,
                "Ref absent or different in independent allowlist")
        data, identity, _ = self.read_path(self.repository / reference["path"])
        require(len(data) == reference["size"] and evidence._sha(data) == reference["sha256"],
                "governance Ref bytes drift: " + reference["path"])
        require(reference["path"] not in self.locked
                or self.locked[reference["path"]] == (data, identity), "governance identity drift")
        self.locked[reference["path"]] = (data, identity)
        return data

    def document(self, reference, *, canonical=True):
        return evidence._json_bytes(self.read(reference), "governance document", canonical=canonical)

    def recheck(self):
        for path in list(self.consumer_streams):
            for _ in self.stream_path(path): pass
        for path, (data, identity) in self.locked.items():
            current, current_identity, _ = self.read_path(self.repository / path)
            require((current, current_identity) == (data, identity), "governance consumption drift: " + path)
        for path, expected in self.consumer_inputs.items():
            data, identity, _ = self.read_path(path)
            require(expected == (data, identity), "consumer input drift: " + str(path))


def implementation_closure(group):
    pending, found = list(ENTRIES | LOCAL_MODULES), set()
    for path in sorted(RESOURCES):
        require(path in group.freeze_refs, "implementation freeze omits required resource: " + path)
        group.read(group.freeze_refs[path])
        found.add(path)
    while pending:
        path = pending.pop()
        if path in found:
            continue
        require(path in group.freeze_refs, "implementation freeze omits required entry/import: " + path)
        found.add(path)
        tree = ast.parse(group.read(group.freeze_refs[path]), filename=path)
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [item.name for item in node.names]
            elif isinstance(node, ast.ImportFrom):
                prefix = node.module or ""
                if node.level:
                    parts = path[:-3].split("/")[:-node.level]
                    prefix = ".".join(parts + ([prefix] if prefix else []))
                names = [prefix] + [prefix + "." + item.name for item in node.names]
            for name in names:
                candidate = name.replace(".", "/") + ".py"
                package = name.replace(".", "/") + "/__init__.py"
                # Resolve only the reviewed catalog, never caller-directory discovery.
                for local in (candidate, package):
                    if local in LOCAL_MODULES and local not in found:
                        pending.append(local)
    require(found <= set(group.freeze_refs), "implementation freeze omits required resources")
    require(any(path.startswith("tests/test_") for path in group.freeze_refs),
            "implementation freeze omits verification tests")
    return frozenset(found)


def _model(group, value, name):
    # JSON Schema numeric equality alone admits true==1; reject bool everywhere.
    def no_bool_generation(item):
        if isinstance(item, dict):
            if "schema_version" in item:
                require(type(item["schema_version"]) is int, "bool schema generation forbidden")
            for child in item.values():
                no_bool_generation(child)
        elif isinstance(item, list):
            for child in item:
                no_bool_generation(child)
    no_bool_generation(value)
    try:
        if name not in group.validators:
            schema = group.document(group.allowed[MODEL], canonical=False)
            schema["$ref"] = "#/$defs/" + name
            group.validators[name] = Draft202012Validator(schema)
        group.validators[name].validate(value)
    except Exception as exc:
        raise GovernanceError("governance schema differs: " + name) from exc


def _publication(group, deployment):
    approval = group.approval
    receipt = group.document(approval["publication_receipt"])
    _model(group, receipt, "publication_receipt")
    require(str(uuid.UUID(receipt["publication_id"])) == receipt["publication_id"], "publication UUID differs")
    for key in ("normative_manifest", "implementation_freeze", "bootstrap_manifest"):
        require(receipt[key] == approval[key], "publication approval bundle differs")
    root_hash = evidence._sha(evidence.canonical_json(approval["root_mapping"])[:-1])
    require(receipt["root_mapping_sha256"] == root_hash
            and receipt["guest_principal_sid"] == deployment["guest_principal_sid"],
            "publication root/principal binding differs")
    times = [receipt[key] for key in ("published_at", "guest_directory_fsynced_at", "guest_readback_at", "host_readback_at")]
    for value in times:
        evidence._utc(value, "publication action time")
    expected = dict(group.normative_refs | group.freeze_refs | group.bootstrap_refs)
    for key in ("normative_manifest", "implementation_freeze", "bootstrap_manifest"):
        expected[approval[key]["path"]] = approval[key]
    mapping_ref = approval["root_mapping"]["deployment_configuration"]
    expected[mapping_ref["path"]] = mapping_ref
    rows = receipt["members"]
    require([row["relative_path"] for row in rows] == sorted(expected, key=lambda p: p.encode("utf-8")),
            "publication is not exact unique complete dependency coverage")
    identities = {}
    for row in rows:
        path = row["relative_path"]
        reference = {"path": path, "size": row["size"], "sha256": row["sha256"]}
        require(reference == expected[path], "publication member content binding differs")
        group.read(reference)
        _, _, actual = group.read_path(group.repository / path)
        require(row[group.endpoint + "_identity"] == actual, "local publication identity differs from actual file")
        require(row["guest_identity"]["principal_sid"] == deployment["guest_principal_sid"],
                "guest publication principal differs")
        for endpoint in ("host", "guest"):
            identities[(path, endpoint)] = row[endpoint + "_identity"]
    archive = group.document(receipt["identity_evidence"])
    _model(group, archive, "identity_evidence")
    seen = set()
    for row in archive["members"]:
        key = (row["relative_path"], row["endpoint"])
        require(key not in seen and key in identities and row["identity"] == identities[key],
                "identity archive duplicate/extra/cross-platform binding")
        seen.add(key)
        observation = group.document(row["observation_ref"])
        _model(group, observation, "identity_observation")
        require((observation["relative_path"], observation["endpoint"]) == key
                and observation["identity"] == row["identity"], "identity observation binding differs")
        evidence._utc(observation["observed_at"], "identity observation action time")
        acl = group.read(observation["acl_original"])
        require(evidence._sha(acl) == row["identity"]["acl_sha256"], "ACL original hash differs")
        if key[1] == "guest":
            _windows_descriptor(acl, row["identity"]["owner_sid"])
        else:
            _host_descriptor(acl, row["identity"])
    require(seen == set(identities), "identity archive misses endpoint coverage")


def _host_descriptor(data, identity):
    value = evidence._json_bytes(data, "host full ACL original")
    require(set(value) == {"mode", "owner_uid", "owner_gid", "extended_acl"}
        and all(value[key] == identity[key] for key in ("mode", "owner_uid", "owner_gid")),
        "host ACL original fields differ")
    rows = value["extended_acl"]
    require(isinstance(rows, list) and len(rows) == 2, "host extended ACL originals missing")
    for row, name in zip(rows, ("system.posix_acl_access", "system.posix_acl_default")):
        require(isinstance(row, dict) and set(row) == {"name", "value_hex"} and row["name"] == name,
                "host full ACL original shape differs")
        raw = row["value_hex"]
        require(raw is None or isinstance(raw, str) and re.fullmatch(r"(?:[0-9a-f]{2})+", raw),
                "host ACL original encoding differs")
        if raw is not None:
            decoded = bytes.fromhex(raw)
            require(len(decoded) >= 4 and (len(decoded) - 4) % 8 == 0
                and struct.unpack_from("<I", decoded)[0] == 2, "host kernel ACL original malformed")


def _deployment_binding(group, deployment):
    host = deployment["host_project_root"]
    require(isinstance(host, str) and PurePosixPath(host).is_absolute()
        and ".." not in host.split("/") and str(PurePosixPath(host)) == host,
        "host deployment coordinate is not canonical")
    if group.endpoint == "host":
        require(host == str(group.repository), "deployment root/VM/principal binding differs: host root")
    else:
        from tests.p05_pc026_windows_reader import check_path
        guest = PureWindowsPath(deployment["guest_deployment_base"]) / deployment["guest_project_coordinate"]
        check_path(guest)
        require(str(guest) == str(group.repository), "deployment guest root differs")
        require(group.reader.sid == deployment["guest_principal_sid"], "actual TokenUser principal differs")
        from velo_transfer.windows_platform import observe_windows
        require(observe_windows().vm_uuid == deployment["vm_uuid"], "actual guest VM identity differs")


def _validate_deployment(group, deployment):
    exact(deployment, "schema_version kind profile_id workflow_id host_project_root guest_deployment_base guest_project_coordinate guest_canonical_coordinate vm_uuid guest_principal_sid",
          "pc026-deployment-configuration-v1")
    require(isinstance(deployment["guest_project_coordinate"], str)
            and deployment["guest_project_coordinate"] == relative(deployment["guest_project_coordinate"])
            and deployment["guest_canonical_coordinate"] == CANONICAL
            and deployment["vm_uuid"] == VM_UUID
            and isinstance(deployment["guest_principal_sid"], str)
            and SID.fullmatch(deployment["guest_principal_sid"]), "deployment root/VM/principal binding differs")
    sid_parts = deployment["guest_principal_sid"].split("-")[2:]
    require(int(sid_parts[0]) < 2 ** 48 and all(int(part) < 2 ** 32 for part in sid_parts[1:]),
            "deployment principal SID numeric range differs")
    base = deployment["guest_deployment_base"]
    require(isinstance(base, str) and re.fullmatch(r"[A-Za-z]:\\[^:]+", base)
            and PureWindowsPath(base).is_absolute()
            and all(part not in {"", ".", ".."} for part in base[3:].split("\\"))
            and "/" not in base and "\0" not in base, "unsafe Windows deployment base")
    _deployment_binding(group, deployment)


def _windows_descriptor(data, owner_sid):
    """Validate archived raw self-relative SD bytes, without native API claims."""
    require(len(data) >= 20, "Windows ACL original lacks security descriptor header")
    revision, reserved, control, owner, group, sacl, dacl = struct.unpack_from("<BBHIIII", data)
    require(revision == 1 and reserved == 0 and control & 0x8000,
            "Windows ACL original is not a self-relative security descriptor")
    def sid(offset):
        require(offset >= 20 and offset % 4 == 0 and offset + 8 <= len(data), "SD SID offset differs")
        version, count = data[offset:offset + 2]
        require(version == 1 and 1 <= count <= 15 and offset + 8 + count * 4 <= len(data), "SD SID bounds differ")
        authority = int.from_bytes(data[offset + 2:offset + 8], "big")
        values = struct.unpack_from("<" + "I" * count, data, offset + 8)
        return "S-1-" + str(authority) + "".join("-" + str(value) for value in values)
    require(sid(owner) == owner_sid, "Windows ACL original owner SID differs")
    if group:
        sid(group)
    for offset in (sacl, dacl):
        if offset:
            require(offset >= 20 and offset % 4 == 0 and offset + 8 <= len(data), "SD ACL offset differs")
            version, _, size, count, _ = struct.unpack_from("<BBHHH", data, offset)
            require(version in (2, 4) and size >= 8 and offset + size <= len(data), "SD ACL bounds differ")
            position = offset + 8
            for _ in range(count):
                require(position + 4 <= offset + size, "SD ACE header unavailable")
                length = struct.unpack_from("<H", data, position + 2)[0]
                require(length >= 4 and length % 4 == 0 and position + length <= offset + size,
                        "SD ACE bounds differ")
                position += length


def _load_at(repository: Path, *, synthetic_fixture=False):
    # Platform is automatic, never a caller-supplied selector or environment.
    reader = None
    if os.name == "nt":
        from tests.p05_pc026_windows_reader import WindowsSession
        reader = WindowsSession()
    try:
        group = _load_group(repository, synthetic_fixture=synthetic_fixture, reader=reader)
        if _CONSUMPTION.get() is not None:
            _CONSUMPTION.get().append(group)
        return group
    except BaseException:
        if reader is not None:
            reader.close()
        raise


def private_host_boundary(repository, identity, host):
    require(host["owner_uid"] in {"0", str(os.geteuid())}
            and not (int(host["mode"], 8) & 0o022), "runtime owner/ACL trust boundary differs")
    for index, (identity, security) in enumerate(zip(identity[0][:-1], identity[1][:-1])):
        mode = identity[2]
        # OS-owned ancestors above the code root can use mapped/container UIDs.
        # The controlled repository and its governance descendants must retain
        # the reader/root owner boundary; do not infer UID 0 for filesystem /.
        controlled = index >= len(repository.parts) - 1
        require((not controlled or security[0] in {0, os.geteuid()})
                and (not mode & 0o002 or not controlled and mode & stat.S_ISVTX)
                and (not controlled or not mode & 0o020 or security[1] == os.getegid()),
                "runtime ancestor owner/ACL trust boundary differs")


def _load_group(repository: Path, *, synthetic_fixture, reader):
    """Internal file-tree seam; all fixed model/hash/path gates still apply."""
    require(repository.is_absolute() and str(repository) == str(repository.absolute())
            and ".." not in repository.parts, "repository root must be canonical absolute")
    contract, _, _ = _read(repository / CONTRACT, reader=reader)
    require(len(contract) == 6559 and evidence._sha(contract) == CONTRACT_SHA, "adopted contract version anchor differs")
    native_contract, _, _ = _read(repository / NATIVE_CONTRACT, reader=reader)
    require(len(native_contract) == 6343 and evidence._sha(native_contract) == NATIVE_CONTRACT_SHA,
            "adopted native contract version anchor differs")
    runtime_bytes, runtime_identity, runtime_host = _read(repository / RUNTIME, reader=reader)
    if reader is None:
        private_host_boundary(repository, runtime_identity, runtime_host)
    runtime = evidence._json_bytes(runtime_bytes, "fixed runtime record")
    exact(runtime, "schema_version kind profile_id workflow_id contract_ref approval_ref allowed_refs status",
          "pc026-controller-runtime-record-v1", "ADOPTED")
    allowed = refs(runtime["allowed_refs"])
    require(COMPLETION not in allowed, "completion must stay outside original allowlist")
    require(runtime["contract_ref"] == {"path": CONTRACT, "size": 6559, "sha256": CONTRACT_SHA}
            and runtime["approval_ref"]["path"] == APPROVAL, "fixed runtime trust anchors differ")
    group = GovernedGroup(repository, {}, allowed, {RUNTIME: (runtime_bytes, runtime_identity)}, {}, {}, {}, synthetic_fixture, reader=reader)
    for path in allowed:
        relative(path)
        require(not path.startswith(".tmp/") and "candidate" not in path.split("/")[:-1], "unadopted governance source")
    require(allowed.get(NATIVE_CONTRACT) == {"path": NATIVE_CONTRACT, "size":6343,
            "sha256":NATIVE_CONTRACT_SHA}, "native contract allowlist anchor missing")
    require(allowed.get(HANDOFF_CONTRACT) == {"path":HANDOFF_CONTRACT, "size":9234,
            "sha256":HANDOFF_CONTRACT_SHA}, "handoff contract allowlist anchor missing")
    require(allowed.get(CALL_CLOCK_CONTRACT) == {'path': CALL_CLOCK_CONTRACT, 'size': 6933,
            'sha256': CALL_CLOCK_CONTRACT_SHA}, 'call-clock contract allowlist anchor missing')
    require(allowed.get(ARCHIVE_CONTRACT) == {'path': ARCHIVE_CONTRACT, 'size': 23088,
            'sha256': ARCHIVE_CONTRACT_SHA}, 'archive contract allowlist anchor missing')
    require(allowed.get(LIFECYCLE_CONTRACT) == {'path': LIFECYCLE_CONTRACT, 'size': 57074,
            'sha256': LIFECYCLE_CONTRACT_SHA}, 'lifecycle contract allowlist anchor missing')
    for path,size,sha in RAW_CONTRACTS:
        require(allowed.get(path)=={'path':path,'size':size,'sha256':sha},
                'raw HTTP contract allowlist anchor missing: ' + path)
    require(DEPLOYMENT in allowed, "fixed deployment Ref absent")
    deployment = group.document(allowed[DEPLOYMENT])
    _validate_deployment(group, deployment)
    # The fixed normative anchor authenticates the historical path exception.
    require(allowed.get(NORMATIVE, {}).get("sha256") == NORMATIVE_SHA, "normative manifest version anchor missing")
    normative = group.document(allowed[NORMATIVE], canonical=False)
    group.normative_refs = {row["path"]: row for row in nested_refs(normative)}
    for row in group.normative_refs.values():
        group.read(row)
    require(BOOTSTRAP in group.normative_refs, "adopted bootstrap Ref missing")
    bootstrap = group.document(group.normative_refs[BOOTSTRAP], canonical=False)
    group.bootstrap_refs = refs([{"path": row["relative_path"], "size": row["size"],
                                 "sha256": row["sha256"]} for row in bootstrap["members"]])
    require(len(group.bootstrap_refs) == 452 and bootstrap["historical_recursive_member_count"] == 448
            and bootstrap["fixed_bootstrap_anchor_count"] == 4, "historical 448+4 bootstrap differs")
    for path, row in allowed.items():
        if ".tmp" in path.split("/"):
            historical = group.bootstrap_refs.get(path)
            # A carries immutable preparation/migration copies. Admit only an
            # independently listed copy of an exact approved bootstrap member,
            # inside the fixed current A UUID; never repository .tmp sources.
            prefix = EVIDENCE + "/activation-191/"
            if historical is None and path.startswith(prefix):
                parts = path[len(prefix):].split("/")
                require(str(uuid.UUID(parts[0])) == parts[0], "historical copy A UUID differs")
                historical = group.bootstrap_refs.get(EVIDENCE + "/" + "/".join(parts[1:]))
            require(historical is not None and path.startswith(EVIDENCE + "/")
                    and (row["size"], row["sha256"]) == (historical["size"], historical["sha256"]),
                    "unapproved historical archive coordinate")
        group.read(row)  # Includes extra unused entries: dangling allowlists fail.
    for row in (runtime["contract_ref"], runtime["approval_ref"]):
        group.read(row)
    approval = group.document(runtime["approval_ref"])
    _model(group, approval, "approval")
    group.approval = approval
    require(approval["normative_manifest"] == allowed[NORMATIVE]
            and approval["bootstrap_manifest"] == group.normative_refs[BOOTSTRAP]
            and approval["implementation_freeze"]["path"] == FREEZE,
            "fixed approval bundle coordinates differ")
    freeze = group.document(approval["implementation_freeze"])
    exact(freeze, "schema_version kind profile_id workflow_id normative_manifest members status",
          "pc026-implementation-freeze-v1", "FROZEN")
    require(freeze["normative_manifest"] == approval["normative_manifest"], "freeze normative binding differs")
    group.freeze_refs = refs(freeze["members"])
    forbidden = {BASE+'observation-lifecycle-configuration.json', BASE+'observation-archive-configuration.json', BASE+'observation-namespace-root.json', RUNTIME, APPROVAL, FREEZE, COMPLETION, approval["publication_receipt"]["path"]}
    require(not forbidden & set(group.freeze_refs)
            and not any(path.startswith("Logs/") for path in group.freeze_refs),
            "cyclic implementation freeze or future evidence member")
    for row in group.freeze_refs.values():
        group.read(row)
    implementation_closure(group)
    mapping = approval["root_mapping"]
    require(mapping["deployment_configuration"]["path"] == DEPLOYMENT
            and mapping["guest_canonical_coordinate"] == CANONICAL, "fixed deployment/canonical mapping differs")
    require(group.document(mapping["deployment_configuration"]) == deployment
        and mapping["deployment_configuration"] == allowed[DEPLOYMENT]
        and deployment["guest_project_coordinate"] == mapping["guest_project_coordinate"],
        "deployment mapping differs from fixed early binding")
    _publication(group, deployment)
    group.recheck()
    return group


def load():
    """Production entry: neither CLI, environment nor cwd can choose a root."""
    return _load_at(REPOSITORY)


def bindings_for(group, canonical_bytes):
    """Build the two disjoint policies from independently authenticated bytes."""
    from tests import p05_selector_readonly as selector
    prefix = EVIDENCE + "/bootstrap-pc020/epoch7/"
    c7 = group.read(group.bootstrap_refs[prefix + "epoch7-canonical.json"])
    policy_doc = group.document(group.bootstrap_refs[prefix + "historical-policy.json"], canonical=False)
    require(set(policy_doc) == {"source_inputs", "implementation_sources", "synthetic_fixture"}
            and policy_doc["synthetic_fixture"] is False, "historical policy exact keys differ")
    policies = {}
    for key, values in policy_doc.items():
        if key == "synthetic_fixture":
            continue
        require(isinstance(values, dict) and bool(values), "historical frozen policy empty")
        policies[key] = {}
        for path, value in values.items():
            evidence._safe_relative(path, "historical source coordinate")
            require(isinstance(value, list) and len(value) == 3 and type(value[0]) is int
                    and value[0] >= 0 and evidence._valid_sha(value[1])
                    and isinstance(value[2], str) and re.fullmatch(r"[0-9a-f]{40}", value[2]),
                    "historical source frozen identity differs")
            policies[key][path] = evidence.FrozenIdentity(*value)
    historical = evidence.FrozenSourcePolicy(**policies, synthetic_fixture=group.synthetic_fixture)
    intent = group.document(group.bootstrap_refs[prefix + "epoch7-intent.json"])
    receipt = group.document(group.bootstrap_refs[prefix + "epoch7-receipt.json"])
    require(set(intent) == {"schema_version", "kind", "workflow_id", "transition_id",
                            "from_sha256", "next_sha256", "created_at"}
            and type(intent["schema_version"]) is int and intent["schema_version"] == 1
            and intent["kind"] == "pc020-canonical-transition-intent-v1"
            and intent["workflow_id"] == evidence.WORKFLOW_ID
            and intent["from_sha256"] == evidence.PREDECESSOR_SHA256
            and intent["next_sha256"] == evidence._sha(c7)
            and intent["transition_id"] == receipt.get("transition_id"), "historical intent/receipt binding differs")
    evidence._utc(intent["created_at"], "historical intent created_at")
    resource_sources = SOURCE_RESOURCES
    current_sources = {path: row for path, row in group.normative_refs.items()
                       if path != BOOTSTRAP}
    current_sources[NORMATIVE] = group.allowed[NORMATIVE]
    current_sources[CONTRACT] = group.allowed[CONTRACT]
    current_sources[NATIVE_CONTRACT] = group.allowed[NATIVE_CONTRACT]
    current_sources.update({path: group.freeze_refs[path] for path in resource_sources})
    def identities(values):
        return {path: evidence.FrozenIdentity(row["size"], row["sha256"], evidence._blob(group.read(row)))
                for path, row in values.items()}
    current = evidence.FrozenSourcePolicy(identities(current_sources),
        identities({path: row for path, row in group.freeze_refs.items() if path not in resource_sources}),
        synthetic_fixture=group.synthetic_fixture)
    canonical_path = group.repository / CANONICAL
    data, identity, _ = group.read_path(canonical_path)
    require(data == canonical_bytes, "selector did not read the fixed canonical bytes")
    group.locked[CANONICAL] = (data, identity)
    state = evidence._json_bytes(data, "fixed canonical")
    evidence.verify_schema6_shape(data, expected_epoch=state["epoch"], profile_id=PROFILE)
    if state["epoch"] == 7:
        require(data == c7, "initial canonical differs from immutable C7")
    else:
        # Every actual A member must be independently allowed before the legacy
        # content helpers resolve their own package-relative coordinates.
        activation = state["activation_evidence"]["evidence_path"]
        evidence._fixed_evidence_path(activation, "activation-191", "activation-evidence.json", "current activation")
        directory = group.repository / EVIDENCE / activation.rsplit("/", 1)[0]
        for name, path in evidence._walk(directory).items():
            coordinate = path.relative_to(group.repository).as_posix()
            require(coordinate in group.allowed, "activation member absent from independent closure: " + coordinate)
            group.read(group.allowed[coordinate])
    return selector.ControllerBindings(group.repository / EVIDENCE, historical, c7,
        group.repository / prefix / "epoch7-receipt.json", current, PROFILE, group)


def load_bindings(canonical_bytes):
    return bindings_for(load(), canonical_bytes)
