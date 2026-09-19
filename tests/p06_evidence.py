"""Byte and semantic validation shared by formal P06 producers and consumers."""

from __future__ import annotations

import hashlib
import inspect
import json
import stat
import textwrap
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any


class EvidenceError(ValueError):
    pass


WORKFLOW_ID = 'wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2'
SNAPSHOT_183 = 'Snapshot 183-FakenetNG测试专用'
SNAPSHOT_184 = 'Snapshot 184-Velociraptor-MCP测试基线'
SNAPSHOT_1 = 'Snapshot 1-开启Windows-MCP'
SNAPSHOT_186 = 'Snapshot 186-Velociraptor-MCP网络部署基线'
SNAPSHOT_187 = 'Snapshot 187-固定IP+WindowsMCP开机自启'
SNAPSHOT_188 = 'Snapshot 188-Velociraptor-MCP可恢复验收基线'
MANUAL_ONLY = 'MANUAL_ONLY_REQUIRES_NEW_USER_AUTHORIZATION'
# The one origin the deployed service explicitly allows; the collected
# entry-gate originals used exactly this value, and verify_entry_gate_raw
# recomputes the allowed_origin case against it.
ENTRY_ALLOWED_ORIGIN = 'https://p05-approved-origin.internal'
# Carried restore/network originals extend the P05 host-command envelope with
# the restore attempt id so an in-package copy cannot be spliced across
# attempts (P05 §0.7 self-contained Ref-graph rule).
RESTORE_ATTEMPT_KEYS = {'restore_attempt_id'}
RESTORE_HOST_COMMAND_KIND = 'p05-snapshot-command-v1'
RESTORE_GUEST_IDENTITY_KIND = 'p05-guest-identity-observation-v1'
RESTORE_OPERATION_IDS = {
    'snapshot_metadata': 'snapshot-metadata',
    'revert_operation': 'revert-operation',
    'pre_start_marker': 'pre-start-marker',
    'post_restore_hostname': 'post-restore-identity',
}
PC006_BOUNDARY_KEYS = {
    'schema_version', 'kind', 'workflow_id', 'run_id', 'restore_attempt_id',
    'probe_source_address', 'comparison_port',
    'bound_source_failure', 'dual_port_control', 'firewall_rule',
}
PC006_BOUNDARY_KIND = 'p05-pc006-boundary-v1'
# The carried PC006 originals are executions of this one frozen host collector.
# Its script identity is verified by full content, so its structured stdout is
# collector output that can be recomputed, not a hand-written conclusion (B03).
PC006_PROBE_KIND = 'p06-pc006-probe-v1'
PC006_COMMAND_KIND = 'p06-pc006-command-v1'
PC006_BOUND_MODE = 'bound'
PC006_DUAL_MODE = 'dual'
PC006_EXECUTION_KEYS = {
    'role', 'port', 'request', 'started_at', 'ended_at', 'exit_status', 'response',
}
NETWORK_FAILURE_CLASSES = {'connection-refused', 'no-route-to-host', 'connection-timeout'}
STDIO_LAUNCH_KIND = 'p06-stdio-launch-v1'
SCHEMA_IDENTITY_KEYS = {
    'schema_version', 'kind', 'workflow_id', 'run_id', 'restore_attempt_id',
    'http', 'stdio',
}
SCHEMA_IDENTITY_KIND = 'p06-schema-identity-v1'
# The fixed guest identity query that every real restore attempt recorded
# (Logs/P05/wf-01a05d1d-p05/restore-attempts/*/post-restore-identity.json).
# A script that merely mentions the same terms is not that query (B06).
RESTORE_GUEST_IDENTITY_SCRIPT = (
    "$ErrorActionPreference='Stop'; $rows=@(Get-CimInstance Win32_NetworkAdapterConfiguration "
    "-Filter 'IPEnabled=True' | ForEach-Object { [ordered]@{ MACAddress=[string]$_.MACAddress; "
    "IPAddress=@($_.IPAddress); DHCPEnabled=[bool]$_.DHCPEnabled; IPEnabled=[bool]$_.IPEnabled } }); "
    "[ordered]@{ computer_name=$env:COMPUTERNAME; adapters=$rows } | ConvertTo-Json -Depth 4 -Compress"
)


def _pc006_curl_argv(bind, port):
    """The one approved curl probe command (frozen inside the collector script)."""
    return [
        '/usr/bin/curl', '--interface', str(bind),
        '--connect-timeout', '5', '--max-time', '12',
        '-sS', '-o', '/dev/null', '-w', '%{http_code}',
        f'http://192.168.204.232:{int(port)}/mcp',
    ]


def _pc006_collect(argv):
    """Approved host-side PC006 collector: run the fixed curl probes and report
    only their raw executions.

    A real collection executes this function as
    ``/usr/bin/python3 -c PC006_COLLECTOR_SCRIPT bound|dual <probe-source> <port>``
    and wraps the captured stdout/stderr and exit status in the attempt-bound
    ``PC006_COMMAND_KIND`` envelope.  Windows seam fixtures call this same
    function with a controlled ``subprocess.run`` stub, so every synthetic
    positive uses this collector's format and control flow rather than a
    separately hand-written expectation.  Passing this unit test still proves
    only the parser; it never claims a Windows restore or network probe ran.
    """
    import hashlib
    import json
    import subprocess
    from datetime import UTC, datetime

    def utc():
        return datetime.now(UTC).isoformat(timespec='milliseconds').replace('+00:00', 'Z')

    def run(command):
        started = utc()
        try:
            completed = subprocess.run(
                command, check=False, capture_output=True, timeout=60)
            stdout = completed.stdout.decode('utf-8')
            stderr = completed.stderr.decode('utf-8')
            code = completed.returncode
        except subprocess.TimeoutExpired as exc:
            stdout = (exc.stdout or b'').decode('utf-8')
            stderr = (exc.stderr or b'').decode('utf-8') + '\ncollector timeout after 60 seconds'
            code = 124
        except OSError as exc:
            stdout, stderr, code = '', f'{type(exc).__name__}: {exc}', 127
        stdout_bytes, stderr_bytes = stdout.encode('utf-8'), stderr.encode('utf-8')
        return {
            'request': {'argv': list(command), 'command_line': ' '.join(command)},
            'started_at': started,
            'ended_at': utc(),
            'exit_status': {'code': code},
            'response': {
                'stdout': stdout, 'stdout_size': len(stdout_bytes),
                'stdout_sha256': hashlib.sha256(stdout_bytes).hexdigest(),
                'stderr': stderr, 'stderr_size': len(stderr_bytes),
                'stderr_sha256': hashlib.sha256(stderr_bytes).hexdigest(),
            },
        }

    if len(argv) != 3 or argv[0] not in {'bound', 'dual'}:
        raise ValueError('usage: collector bound|dual <probe-source> <comparison-port>')
    import ipaddress
    mode, probe_source, comparison_port = argv[0], str(ipaddress.ip_address(argv[1])), int(argv[2])
    executions = []
    if mode == 'bound':
        executions.append({
            'role': 'probe_source', 'port': 28790,
            **run(_pc006_curl_argv(probe_source, 28790)),
        })
    else:
        for port in (28790, comparison_port):
            for role, bind in (('probe_source', probe_source), ('allowed_source', '192.168.204.1')):
                executions.append({
                    'role': role, 'port': port,
                    **run(_pc006_curl_argv(bind, port)),
                })
    return {
        'schema_version': 1,
        'kind': 'p06-pc006-probe-v1',
        'mode': mode,
        'probe_source_address': probe_source,
        'target_host': '192.168.204.232',
        'comparison_port': comparison_port,
        'executions': executions,
    }


PC006_COLLECTOR_SCRIPT = (
    textwrap.dedent(inspect.getsource(_pc006_curl_argv))
    + textwrap.dedent(inspect.getsource(_pc006_collect))
    + "\nif __name__ == '__main__':\n"
    + "    import json as _json, sys as _sys\n"
    + "    _json.dump(_pc006_collect(_sys.argv[1:]), _sys.stdout, ensure_ascii=False, "
      "sort_keys=True, separators=(',', ':'), allow_nan=False)\n"
)


def pc006_collector_argv(mode, source, comparison_port):
    """Return the exact approved collector command for one PC006 element."""
    return [
        '/usr/bin/python3', '-c', PC006_COLLECTOR_SCRIPT,
        mode, str(source), str(int(comparison_port)),
    ]

ACTIVATION_KEYS = {
    'schema_version', 'kind', 'workflow_id', 'candidate', 'checkpoint_marker',
    'creation_metadata', 'initial', 'candidate_cycles', 'source_inputs',
    'implementation_sources',
}
REF_KEYS = {'path', 'size', 'sha256'}
PHASE_KEYS = {
    'restore_attempt_id', 'run_id', 'report', 'snapshot_evidence', 'ready',
    'dependency_acceptance', 'entry_gate', 'network_evidence', 'package_manifest',
}
SOURCE_KEYS = {'repo_path', 'blob', 'content'}
RESTORE_KEYS = {
    'workflow_id', 'run_id', 'restore_attempt_id', 'snapshot_stage',
    'snapshot_name', 'checkpoint_marker', 'canonical_schema_version',
    'canonical_epoch', 'canonical_phase', 'canonical_sha256', 'restore_records',
}
RESTORE_KINDS = {
    'snapshot_metadata', 'revert_operation', 'pre_start_marker',
    'post_restore_hostname', 'canonical_readback', 'baseline_adoption',
    'activation_evidence',
}
PHASE_RESTORE_KINDS = RESTORE_KINDS - {'activation_evidence'}
CANONICAL_KEYS = {
    'schema_version', 'workflow_id', 'epoch', 'phase', 'active_snapshot',
    'automatic_restore_allowlist', 'retired_snapshots', 'baseline_evidence',
    'activation_evidence',
}
SNAPSHOT_KEYS = {'name', 'checkpoint_marker', 'purpose'}
RETIRED_KEYS = {'name', 'status'}
BASELINE_EVIDENCE_KEYS = {'source', 'evidence_path', 'evidence_sha256', 'recorded_at'}
ACTIVATION_EVIDENCE_KEYS = {'source', 'evidence_path', 'evidence_sha256', 'activated_at'}
SNAPSHOT_EVIDENCE_KEYS = {
    'restore', 'scenario_id', 'source_sha256', 'index_sha256', 'mcp_session_id',
    'server_instance_id', 'server_observation_sha256',
}
REPORT_KEYS = {
    'schema_version', 'scenario', 'source_sha256', 'index_sha256',
    'fixture_spec_sha256', 'fixture_instance_sha256', 'run_id', 'transport',
    'endpoint', 'authorization_configured', 'tools_schema_sha256',
    'snapshot_evidence_sha256', 'mcp_session', 'server_identity',
    'server_observation_sha256', 'runner', 'started_at', 'ended_at',
    'duration_ms', 'status', 'calls', 'steps', 'cleanup', 'failure',
    'unexecuted_step_ids', 'coverage',
}
P05_INDEX_SOURCE = 'tests/data/p05_scenario_index.json'
P05_FIXTURE_SOURCE = 'tests/data/p05_fixture_spec.json'
P05_SCHEMA_SOURCE = 'tests/scenarios/schema-v1.json'
P05_INDEX_SHA256 = 'c9c3e5146e0f5bb238926e5b2d1c681926ccd21693231e6862193b28e3956c4c'
P05_FIXTURE_SPEC_SHA256 = 'bba83db333962ef57140a75a405cf82ec85c51593124f6324d55f89da15cef4c'
P05_SCHEMA_SHA256 = 'a4841c62141be1806d304667cc442ff31a4969b1063af8fe2abaea895f250821'
P05_SCENARIOS = {
    'p05-flow-triage-repair-initial': {
        'path': 'tests/scenarios/representative/p05-flow-triage-repair-initial.json',
        'stage': 'P05_REPAIR_INITIAL',
        'snapshot': SNAPSHOT_187,
        'sha256': '1fe32b71979d54fb04417e27cc5ca94c792004b9fcdb6dff6d7d5457852961cd',
    },
    'p05-flow-triage-repair-candidate': {
        'path': 'tests/scenarios/representative/p05-flow-triage-repair-candidate.json',
        'stage': 'P05_REPAIR_CANDIDATE',
        'snapshot': SNAPSHOT_188,
        'sha256': '843551b8b6b4fb6dc48fb4f1fc2808d4105a052a63fd7dddc0a53f7a95a24358',
    },
}

# These are source-text allowlists, not file discovery rules.  A future
# self-evaluation supplement must be added here before it can support an
# activation; accepting arbitrary PLAN files would weaken the bundle boundary.
SOURCE_INPUT_ALLOWLIST = {
    'PLAN/2026.09.02/2026.09.02-01-需求提炼-mcp-velociraptor全阶段设计.md',
    'PLAN/2026.09.02/2026.09.02-02-总纲-mcp-velociraptor-Windows-DFIR二次开发.md',
    'PLAN/2026.09.02/2026.09.05-22-实施子方案-P05测试数据与情景基础设施.md',
    'PLAN/2026.09.02/2026.09.05-29-实施子方案-P06逐工具与连续情景全量执行.md',
    'PLAN/2026.09.02/2026.09.12-18-实施子方案-P07清理与终检.md',
    'PLAN/2026.09.02/2026.09.13-19-无人值守职责与自评实施门授权.md',
    'PLAN/2026.09.02/2026.09.13-20-主会话自评-PLAN-CHANGE-011及P05至P07承接.md',
    'PLAN/2026.09.02/2026.09.14-01-PLAN-CHANGE-012-用户重置唯一187基线.md',
    'PLAN/2026.09.02/2026.09.14-08-执行授权-宿主与目标虚拟机文件互传.md',
    'PLAN/2026.09.02/2026.09.14-10-方案自评-PLAN-CHANGE-012新基线契约.md',
    'PLAN/2026.09.02/2026.09.14-11-实施自评补充-P05原件解析与Windows首轮纠偏.md',
    'PLAN/2026.09.02/2026.09.14-12-执行交接-velo-mcp剩余七步与验收门.md',
    'PLAN/2026.09.02/2026.09.14-13-实施自评补充-接手执行静态修复与allowlist登记.md',
    'PLAN/2026.09.02/2026.09.14-14-G0保护门评估-恢复前置证据闭合.md',
    'PLAN/2026.09.02/2026.09.14-15-PLAN-CHANGE-013裁决-依赖前驱行恢复可达基线.md',
    'PLAN/2026.09.02/2026.09.14-16-PLAN-CHANGE-014裁决-移除Velo方案中FakeNetNG撞车网络机制.md',
    'tests/data/p05_dependency_manifest.json',
    'tests/data/p05_fixture_spec.json',
    'tests/data/p05_scenario_index.json',
    'tests/scenarios/schema-v1.json',
    'tests/scenarios/representative/p05-flow-triage-repair-initial.json',
    'tests/scenarios/representative/p05-flow-triage-repair-candidate.json',
}
IMPLEMENTATION_SOURCE_ALLOWLIST = {
    'mcp_velociraptor_bridge.py',
    'velociraptor_api.py',
    'velociraptor_mcp_core.py',
    'velociraptor_dynamic_artifacts.py',
    'velociraptor_fixed_tools.py',
    'velociraptor_env.py',
    'tests/p05_dependency_acceptance.py',
    'tests/p05_external_acceptance.py',
    'tests/p05_prepare_fixtures.ps1',
    'tests/p05_process_parent.py',
    'tests/p05_real_acceptance.py',
    'tests/p05_ready_collect.py',
    'tests/p05_http_evidence.py',
    'tests/p05_sdk_capture.py',
    'tests/p05_service_observation.py',
    'tests/p05_candidate_creation.py',
    'tests/p05_four_chain_evidence.py',
    'tests/p05_service_host.py',
    'tests/p05_service_install.ps1',
    'tests/p05_ready_evidence.py',
    'tests/p05_baseline_adoption.py',
    'tests/p05_snapshot_raw.py',
    'tests/p05_activation_raw.py',
    'tests/scenario_runner.py',
    'tests/p06_evidence.py',
    'tests/test_p05_recovery_contract.py',
    'tests/test_p05_baseline_adoption.py',
    'tests/test_p05_snapshot_raw.py',
    'tests/test_p05_recovery_namespace.py',
    'tests/test_p05_ready_evidence.py',
    'tests/test_p05_activation_raw.py',
    'tests/test_p05_ready_collect.py',
    'tests/test_p05_http_evidence.py',
    'tests/test_p05_sdk_capture.py',
    'tests/test_p05_service_observation.py',
    'tests/test_p05_candidate_creation.py',
    'tests/test_p05_four_chain_evidence.py',
    'tests/test_bridge_service_diagnostics.py',
    'tests/test_p05_service_host_abi.py',
    'tests/test_service_transport_lifecycle.py',
    'tests/test_p06_evidence_schema5.py',
    'velociraptor_transport.py',
    'PLAN/2026.09.02/2026.09.02-02-总纲-mcp-velociraptor-Windows-DFIR二次开发-长程执行/快照恢复选择器.py',
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def plain_file(root: Path, relative: str) -> Path:
    if (not isinstance(relative, str) or not relative or '\\' in relative
            or any(part in {'', '.', '..'} for part in relative.split('/'))):
        raise EvidenceError('evidence path must use contained POSIX relative components')
    rel = Path(relative)
    if rel.is_absolute() or PureWindowsPath(relative).drive or '..' in rel.parts:
        raise EvidenceError('evidence path escapes its root')
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise EvidenceError('evidence root is unavailable') from exc
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or stat.S_ISLNK(root_info.st_mode)
        or getattr(root_info, 'st_file_attributes', 0) & 0x400
    ):
        raise EvidenceError('evidence root is not a plain directory')
    current = root
    try:
        for part in rel.parts:
            current = current / part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise EvidenceError('evidence path contains a link or reparse point')
    except OSError as exc:
        raise EvidenceError('evidence path is unavailable') from exc
    if not stat.S_ISREG(current.lstat().st_mode):
        raise EvidenceError('evidence is not a regular file')
    return current


def _sha256_is_valid(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in '0123456789abcdef' for character in value)
    )


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EvidenceError(f'{label} must be a non-empty string')
    return value


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding='utf-8-sig'))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f'{label} must be valid UTF-8 JSON') from exc
    if not isinstance(document, dict):
        raise EvidenceError(f'{label} must be a JSON object')
    return document


def _resolve_ref(
    bundle_root: Path,
    value: Any,
    label: str,
    seen: dict[str, tuple[int, str]],
) -> Path:
    if not isinstance(value, dict) or set(value) != REF_KEYS:
        raise EvidenceError(f'{label} must have exact path/size/sha256 keys')
    relative = _nonempty_string(value['path'], f'{label}.path')
    if type(value['size']) is not int or value['size'] < 0:
        raise EvidenceError(f'{label}.size must be a non-negative integer')
    if not _sha256_is_valid(value['sha256']):
        raise EvidenceError(f'{label}.sha256 is invalid')
    previous = seen.setdefault(relative, (value['size'], value['sha256']))
    if previous != (value['size'], value['sha256']):
        raise EvidenceError(f'{label} repeats a path with different byte identity')
    path = plain_file(bundle_root, relative)
    if path.stat().st_size != value['size'] or digest(path) != value['sha256']:
        raise EvidenceError(f'{label} byte identity differs')
    return path


def _verify_source_list(
    bundle_root: Path,
    sources: Any,
    allowlist: set[str],
    label: str,
    seen: dict[str, tuple[int, str]],
) -> dict[str, Path]:
    if not isinstance(sources, list) or not sources:
        raise EvidenceError(f'{label} must be a non-empty list')
    paths: set[str] = set()
    copies: dict[str, Path] = {}
    for position, source in enumerate(sources):
        item_label = f'{label}[{position}]'
        if not isinstance(source, dict) or set(source) != SOURCE_KEYS:
            raise EvidenceError(f'{item_label} has invalid keys')
        repo_path = _nonempty_string(source['repo_path'], f'{item_label}.repo_path')
        if repo_path not in allowlist or repo_path in paths:
            raise EvidenceError(f'{item_label} is outside the fixed source allowlist')
        paths.add(repo_path)
        blob = source['blob']
        if not isinstance(blob, str) or len(blob) != 40 or any(
            character not in '0123456789abcdef' for character in blob
        ):
            raise EvidenceError(f'{item_label}.blob is not a SHA-1 Git blob id')
        path = _resolve_ref(bundle_root, source['content'], f'{item_label}.content', seen)
        if source['content']['path'] != f'source/{repo_path}':
            raise EvidenceError(f'{item_label} source copy path differs from repo_path')
        payload = path.read_bytes()
        try:
            payload.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise EvidenceError(f'{item_label} source copy is not text') from exc
        header = f'blob {len(payload)}\0'.encode('ascii')
        if hashlib.sha1(header + payload).hexdigest() != blob:
            raise EvidenceError(f'{item_label} Git blob identity differs')
        copies[repo_path] = path
    if not allowlist.issubset(paths):
        missing = sorted(allowlist - paths)
        raise EvidenceError(f'{label} lacks required source copies: {missing}')
    return copies


def _valid_marker(value: Any, label: str) -> str:
    marker = _nonempty_string(value, label)
    if not marker.endswith('.vmsn') or '/' in marker or '\\' in marker:
        raise EvidenceError(f'{label} is invalid')
    return marker


def _verify_evidence_reference(
    value: Any,
    expected_keys: set[str],
    record: dict[str, Any],
    label: str,
) -> None:
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise EvidenceError(f'{label} shape is invalid')
    _nonempty_string(value.get('source'), f'{label}.source')
    _nonempty_string(value.get('recorded_at', value.get('activated_at')), f'{label}.recorded_at')
    # Canonical bytes retain the original absolute P05 location.  A carried
    # copy is relocated under a package root; never rewrite canonical bytes or
    # dereference that original host path. Bind its immutable UUID tail and
    # content hash to the contained record instead.
    original = value.get('evidence_path')
    if not isinstance(original, str) or not original:
        raise EvidenceError(f'{label} path is invalid')
    identity = PureWindowsPath(original) if PureWindowsPath(original).drive else PurePosixPath(original)
    directory, filename = (
        ('baseline-adoption', 'adoption.json')
        if expected_keys == BASELINE_EVIDENCE_KEYS
        else ('activation-188', 'activation-evidence.json')
    )
    parts = identity.parts
    carried = record['path'].split('/')
    if (
        not identity.is_absolute() or '..' in parts or len(parts) < 4
        or parts[-3] != directory or parts[-1] != filename
        or carried[-3:] != list(parts[-3:])
    ):
        raise EvidenceError(f'{label} path does not bind the carried original')
    try:
        if str(uuid.UUID(parts[-2])) != parts[-2]:
            raise ValueError('noncanonical UUID')
    except ValueError as exc:
        raise EvidenceError(f'{label} path lacks a canonical bundle UUID') from exc
    if value.get('evidence_sha256') != record['sha256']:
        raise EvidenceError(f'{label} SHA does not bind the carried original')


def _verify_baseline_adoption(path: Path) -> dict[str, Any]:
    """Use P05's read-only verifier without creating a P05→P06 dependency."""
    try:
        from tests.p05_baseline_adoption import verify_baseline_adoption
    except ImportError as exc:
        raise EvidenceError('baseline adoption verifier is unavailable') from exc
    try:
        document = verify_baseline_adoption(path)
    except ValueError as exc:
        raise EvidenceError(f'baseline adoption is invalid: {exc}') from exc
    if not isinstance(document, dict) or document.get('workflow_id') != WORKFLOW_ID:
        raise EvidenceError('baseline adoption verifier returned an invalid document')
    return document


def _verify_preparation_canonical(
    canonical: dict[str, Any],
    baseline_record: dict[str, Any],
    baseline_path: Path,
) -> tuple[str, str, str]:
    if set(canonical) != CANONICAL_KEYS:
        raise EvidenceError('preparation canonical root keys are invalid')
    if (
        canonical.get('schema_version') != 5
        or canonical.get('epoch') != 5
        or canonical.get('phase') != 'PREPARATION_BASELINE'
        or canonical.get('workflow_id') != WORKFLOW_ID
    ):
        raise EvidenceError('phase canonical is not schema5/epoch5 PREPARATION_BASELINE')
    active = canonical.get('active_snapshot')
    if not isinstance(active, dict) or set(active) != SNAPSHOT_KEYS:
        raise EvidenceError('preparation canonical active snapshot shape is invalid')
    if active.get('name') != SNAPSHOT_187 or not isinstance(active.get('purpose'), str) or not active['purpose']:
        raise EvidenceError('preparation canonical does not retain Snapshot187')
    _valid_marker(active.get('checkpoint_marker'), 'preparation canonical marker')
    if canonical.get('automatic_restore_allowlist') != [SNAPSHOT_187]:
        raise EvidenceError('preparation canonical allowlist differs')
    retired = canonical.get('retired_snapshots')
    expected_retired = [SNAPSHOT_183, SNAPSHOT_184, SNAPSHOT_1, SNAPSHOT_186]
    if (
        not isinstance(retired, list)
        or [item.get('name') if isinstance(item, dict) else None for item in retired]
        != expected_retired
        or any(
            not isinstance(item, dict) or set(item) != RETIRED_KEYS
            or item.get('status') != MANUAL_ONLY
            for item in retired
        )
    ):
        raise EvidenceError('preparation canonical retired snapshots differ')
    _verify_evidence_reference(
        canonical.get('baseline_evidence'),
        BASELINE_EVIDENCE_KEYS,
        baseline_record,
        'preparation canonical baseline evidence',
    )
    if canonical.get('activation_evidence') is not None:
        raise EvidenceError('preparation canonical must not claim activation evidence')
    adoption = _verify_baseline_adoption(baseline_path)
    return (
        canonical['baseline_evidence']['evidence_path'],
        canonical['baseline_evidence']['evidence_sha256'],
        adoption['adoption_id'],
    )


def _verify_phase_restore(
    snapshot_evidence: dict[str, Any],
    bundle_root: Path,
    phase: dict[str, Any],
    expected_stage: str,
    expected_snapshot: str,
    seen: dict[str, tuple[int, str]],
) -> tuple[dict[str, Any], tuple[str, str, str]]:
    if set(snapshot_evidence) != SNAPSHOT_EVIDENCE_KEYS:
        raise EvidenceError('phase snapshot evidence keys are invalid')
    restore = snapshot_evidence.get('restore')
    if not isinstance(restore, dict) or set(restore) != RESTORE_KEYS:
        raise EvidenceError('phase current restore keys are invalid')
    if (
        restore.get('workflow_id') != WORKFLOW_ID
        or restore.get('run_id') != phase['run_id']
        or restore.get('restore_attempt_id') != phase['restore_attempt_id']
        or restore.get('snapshot_stage') != expected_stage
        or restore.get('snapshot_name') != expected_snapshot
        or restore.get('canonical_schema_version') != 5
        or restore.get('canonical_epoch') != 5
        or restore.get('canonical_phase') != 'PREPARATION_BASELINE'
        or not _sha256_is_valid(restore.get('canonical_sha256'))
    ):
        raise EvidenceError('phase restore identity differs')
    marker = _valid_marker(restore.get('checkpoint_marker'), 'phase restore marker')
    records = restore.get('restore_records')
    if not isinstance(records, list) or len(records) != len(PHASE_RESTORE_KINDS):
        raise EvidenceError('phase restore records are incomplete')
    record_paths: set[str] = set()
    by_kind: dict[str, Path] = {}
    declared_records: dict[str, dict[str, Any]] = {}
    originals_root = bundle_root / 'p05-originals'
    for record in records:
        if not isinstance(record, dict) or set(record) != {'kind', 'path', 'sha256'}:
            raise EvidenceError('phase restore record shape is invalid')
        kind = record.get('kind')
        path_value = record.get('path')
        checksum = record.get('sha256')
        if kind not in PHASE_RESTORE_KINDS or kind in by_kind or path_value in record_paths:
            raise EvidenceError('phase restore record is unknown or duplicated')
        if not isinstance(path_value, str) or not _sha256_is_valid(checksum):
            raise EvidenceError('phase restore record identity is invalid')
        path = plain_file(originals_root, path_value)
        if digest(path) != checksum:
            raise EvidenceError(f'phase restore record bytes differ: {kind}')
        by_kind[kind] = path
        declared_records[kind] = record
        record_paths.add(path_value)
    if set(by_kind) != PHASE_RESTORE_KINDS:
        raise EvidenceError('phase restore lacks original record kinds')
    canonical_path = by_kind['canonical_readback']
    if digest(canonical_path) != restore['canonical_sha256']:
        raise EvidenceError('phase canonical SHA differs from original bytes')
    canonical = _read_json(canonical_path, 'phase canonical')
    baseline_identity = _verify_preparation_canonical(
        canonical,
        declared_records['baseline_adoption'],
        by_kind['baseline_adoption'],
    )
    if expected_snapshot == SNAPSHOT_187 and marker != canonical['active_snapshot']['checkpoint_marker']:
        raise EvidenceError('initial restore marker differs from Snapshot187 preparation canonical')
    _verify_restore_action_originals(
        phase['restore_attempt_id'], expected_snapshot, marker, by_kind
    )
    return restore, baseline_identity


def _parse_utc(value: Any, label: str) -> datetime:
    text = _nonempty_string(value, label)
    try:
        instant = datetime.fromisoformat(text.replace('Z', '+00:00'))
    except ValueError as exc:
        raise EvidenceError(f'{label} is not RFC3339 UTC') from exc
    if instant.tzinfo is None or instant.utcoffset() != UTC.utcoffset(instant):
        raise EvidenceError(f'{label} is not UTC')
    return instant.astimezone(UTC)


def _phase_source_json(source_copies: dict[str, Path], repo_path: str, label: str) -> tuple[dict[str, Any], Path]:
    path = source_copies.get(repo_path)
    if path is None:
        raise EvidenceError(f'{label} source copy is absent from the frozen source set')
    return _read_json(path, label), path


def _load_p05_phase_source(
    source_copies: dict[str, Path],
    expected_scenario: str,
    expected_stage: str,
    expected_snapshot: str,
) -> tuple[dict[str, Any], dict[str, Any], str, str, str]:
    expected = P05_SCENARIOS.get(expected_scenario)
    if (
        expected is None
        or expected['stage'] != expected_stage
        or expected['snapshot'] != expected_snapshot
    ):
        raise EvidenceError('phase does not name one of the two fixed P05 representative sources')
    index, index_path = _phase_source_json(source_copies, P05_INDEX_SOURCE, 'frozen P05 scenario index')
    if set(index) != {'schema_version', 'scenarios'} or index.get('schema_version') != 1 or not isinstance(index.get('scenarios'), list):
        raise EvidenceError('frozen P05 scenario index shape is invalid')
    if digest(index_path) != P05_INDEX_SHA256:
        raise EvidenceError('frozen P05 scenario index bytes differ from the fixed representative index')
    expected_ids = list(P05_SCENARIOS)
    if len(index['scenarios']) != len(expected_ids):
        raise EvidenceError('frozen P05 scenario index does not retain both representative rows')
    selected: dict[str, Any] | None = None
    for position, row in enumerate(index['scenarios']):
        if not isinstance(row, dict) or set(row) != {
            'fixture_spec_sha256', 'path', 'required_snapshot', 'scenario_id', 'sha256', 'snapshot_stage',
        }:
            raise EvidenceError('frozen P05 scenario index row shape is invalid')
        scenario_id = row.get('scenario_id')
        fixed = P05_SCENARIOS.get(scenario_id) if isinstance(scenario_id, str) else None
        if (
            fixed is None
            or scenario_id != expected_ids[position]
            or row.get('path') != fixed['path'].removeprefix('tests/scenarios/')
            or row.get('snapshot_stage') != fixed['stage']
            or row.get('required_snapshot') != fixed['snapshot']
            or row.get('sha256') != fixed['sha256']
            or row.get('fixture_spec_sha256') != P05_FIXTURE_SPEC_SHA256
        ):
            raise EvidenceError('frozen P05 scenario index row identity differs')
        scenario_path = source_copies.get(fixed['path'])
        if scenario_path is None or digest(scenario_path) != row['sha256']:
            raise EvidenceError('frozen P05 scenario index does not bind its source bytes')
        if scenario_id == expected_scenario:
            selected = row
    if selected is None:
        raise EvidenceError('frozen P05 scenario index lacks the requested representative source')
    scenario, scenario_path = _phase_source_json(source_copies, expected['path'], 'frozen P05 scenario')
    if (
        set(scenario) != {
            'business_purpose', 'cleanup', 'fixture_spec_sha256', 'required_snapshot',
            'scenario_id', 'schema_version', 'steps',
        }
        or scenario.get('schema_version') != 1
        or scenario.get('scenario_id') != expected_scenario
        or scenario.get('required_snapshot') != expected_snapshot
        or scenario.get('fixture_spec_sha256') != selected['fixture_spec_sha256']
        or not isinstance(scenario.get('steps'), list)
        or not isinstance(scenario.get('cleanup'), list)
    ):
        raise EvidenceError('frozen P05 scenario source differs from its fixed index row')
    schema, schema_path = _phase_source_json(source_copies, P05_SCHEMA_SOURCE, 'frozen scenario schema')
    if (
        digest(schema_path) != P05_SCHEMA_SHA256
        or schema.get('$schema') != 'https://json-schema.org/draft/2020-12/schema'
        or not isinstance(schema.get('$defs'), dict)
    ):
        raise EvidenceError('frozen scenario schema source is invalid')
    fixture_spec, fixture_path = _phase_source_json(source_copies, P05_FIXTURE_SOURCE, 'frozen P05 fixture spec')
    if (
        fixture_spec.get('schema_version') != 1
        or digest(fixture_path) != P05_FIXTURE_SPEC_SHA256
        or selected['fixture_spec_sha256'] != digest(fixture_path)
    ):
        raise EvidenceError('frozen fixture spec does not bind the P05 source/index pair')
    return scenario, fixture_spec, digest(scenario_path), digest(index_path), digest(fixture_path)


def _runner_functions():
    """Import the exact scenario semantics lazily to avoid an import cycle."""
    try:
        from tests.scenario_runner import evaluate_assertion, resolve_value
    except Exception as exc:  # no fallback may silently fork P05 report semantics
        raise EvidenceError(f'scenario-runner assertion semantics are unavailable: {type(exc).__name__}') from exc
    return evaluate_assertion, resolve_value


def _verify_phase_identities(report: dict[str, Any], snapshot_evidence: dict[str, Any]) -> None:
    session = report.get('mcp_session')
    if (
        not isinstance(session, dict)
        or set(session) != {'id', 'initialized_at', 'closed_at'}
        or not all(isinstance(session.get(key), str) and session[key] for key in session)
    ):
        raise EvidenceError('phase report has no complete formal MCP session identity')
    initialized = _parse_utc(session['initialized_at'], 'phase session initialized_at')
    closed = _parse_utc(session['closed_at'], 'phase session closed_at')
    if closed < initialized:
        raise EvidenceError('phase session closed before it initialized')
    report_started = _parse_utc(report.get('started_at'), 'phase report started_at')
    report_ended = _parse_utc(report.get('ended_at'), 'phase report ended_at')
    # The runner opens the report before initialize and seals it after closing
    # the session. The session is inside the report, not the reverse.
    if not (report_started <= initialized <= closed <= report_ended):
        raise EvidenceError('phase session is outside its formal report interval')
    server = report.get('server_identity')
    server_keys = {
        'computer_name', 'service_name', 'pid', 'process_start_time_utc', 'instance_id', 'executable_sha256',
    }
    if (
        not isinstance(server, dict)
        or set(server) != server_keys
        or not all(isinstance(server.get(key), str) and server[key]
                   for key in ('computer_name', 'service_name', 'instance_id', 'executable_sha256'))
        or type(server.get('pid')) is not int
        or server['pid'] <= 4
        or server.get('computer_name') != 'DESKTOP-3FI41GR'
        or server.get('service_name') != 'mcp-velociraptor'
        or not _sha256_is_valid(server.get('executable_sha256'))
    ):
        raise EvidenceError('phase report has no complete formal service instance identity')
    if _parse_utc(server['process_start_time_utc'], 'phase service process start time') > report_started:
        raise EvidenceError('phase service instance began after the reported execution')
    if not _sha256_is_valid(report.get('server_observation_sha256')):
        raise EvidenceError('phase report lacks the service-observation byte identity')
    runner = report.get('runner')
    if (not isinstance(runner, dict)
            or set(runner) != {'pid', 'process_start_time_utc', 'executable_sha256'}
            or type(runner.get('pid')) is not int or runner['pid'] <= 0
            or not _sha256_is_valid(runner.get('executable_sha256'))
            or _parse_utc(runner.get('process_start_time_utc'), 'phase runner start') > report_started):
        raise EvidenceError('phase report lacks a valid pre-existing runner identity')
    if (
        snapshot_evidence.get('mcp_session_id') != session['id']
        or snapshot_evidence.get('server_instance_id') != server['instance_id']
        or snapshot_evidence.get('server_observation_sha256') != report['server_observation_sha256']
    ):
        raise EvidenceError('phase snapshot evidence does not join the non-empty session and service instance')


def _verify_fixture_instance(
    bundle_root: Path,
    report_parent: str,
    report: dict[str, Any],
    scenario: dict[str, Any],
    fixture_spec_sha256: str,
) -> dict[str, Any]:
    path = plain_file(bundle_root, f'{report_parent}/fixture-instance.json')
    if digest(path) != report.get('fixture_instance_sha256'):
        raise EvidenceError('phase run directory fixture-instance bytes differ from its report hash')
    fixture = _read_json(path, 'phase run fixture instance')
    required = {
        'schema_version', 'fixture_spec_sha256', 'workflow_id', 'attempt_id', 'ownership_marker',
        'hostname', 'fixture_root', 'files', 'registry', 'event', 'task', 'process',
    }
    if (
        set(fixture) != required
        or fixture.get('schema_version') != 1
        or fixture.get('workflow_id') != WORKFLOW_ID
        or fixture.get('fixture_spec_sha256') != scenario['fixture_spec_sha256']
        or fixture['fixture_spec_sha256'] != fixture_spec_sha256
    ):
        raise EvidenceError('phase fixture-instance does not bind the frozen fixture specification')
    return fixture


def _verify_phase_execution(
    report: dict[str, Any],
    scenario: dict[str, Any],
    fixture: dict[str, Any],
) -> None:
    evaluate_assertion, resolve_value = _runner_functions()
    if scenario['cleanup'] != [] or report.get('cleanup') != []:
        raise EvidenceError('fixed P05 representative cleanup must be exactly the successful empty cleanup')
    steps = report.get('steps')
    calls = report.get('calls')
    if not isinstance(steps, list) or not isinstance(calls, list) or not calls or len(steps) != len(scenario['steps']):
        raise EvidenceError('phase report has empty, omitted, or excess P05 execution rows')
    report_started = _parse_utc(report.get('started_at'), 'phase report started_at')
    report_ended = _parse_utc(report.get('ended_at'), 'phase report ended_at')
    session_started = _parse_utc(report['mcp_session']['initialized_at'], 'phase initialize time')
    session_closed = _parse_utc(report['mcp_session']['closed_at'], 'phase close time')
    if report_ended < report_started or type(report.get('duration_ms')) is not int or report['duration_ms'] < 0:
        raise EvidenceError('phase report timing is invalid')
    call_keys = {
        'arguments', 'attempt', 'sequence', 'is_error', 'step_id', 'structured', 'mcp_result',
        'tool', 'started_at', 'ended_at', 'duration_ms',
    }
    cursor = 0
    previous_end = report_started
    completed: dict[str, Any] = {}
    for position, source_step in enumerate(scenario['steps']):
        if source_step.get('kind') != 'tool':
            raise EvidenceError('fixed P05 representative contains an unsupported non-tool execution step')
        step = steps[position]
        if (
            not isinstance(step, dict)
            or set(step) != {'assertions', 'id', 'kind', 'passed'}
            or step.get('id') != source_step.get('id')
            or step.get('kind') != 'tool'
            or step.get('passed') is not True
            or not isinstance(step.get('assertions'), list)
        ):
            raise EvidenceError('phase report step order or success shape differs from the frozen P05 source')
        group: list[dict[str, Any]] = []
        while cursor < len(calls):
            candidate = calls[cursor]
            if not isinstance(candidate, dict) or candidate.get('step_id') != source_step['id']:
                break
            group.append(candidate)
            cursor += 1
        if not group:
            raise EvidenceError('phase report omits a frozen P05 tool call')
        max_attempts = source_step.get('repeat_until', {}).get('max_attempts', 1)
        assertion_specs = source_step.get('repeat_until', {}).get('assertions', source_step.get('assertions'))
        if not isinstance(max_attempts, int) or not isinstance(assertion_specs, list) or not 1 <= len(group) <= max_attempts:
            raise EvidenceError('phase report repeat count differs from the frozen P05 source')
        try:
            expected_arguments = resolve_value(source_step['arguments'], completed, fixture)
        except Exception as exc:
            raise EvidenceError(
                f'phase resolved arguments cannot be reconstructed from the frozen scenario: {type(exc).__name__}'
            ) from exc
        final_evaluated: list[dict[str, Any]] = []
        for attempt, call in enumerate(group, start=1):
            if (
                not isinstance(call, dict)
                or set(call) != call_keys
                or call.get('sequence') != cursor - len(group) + attempt
                or call.get('attempt') != attempt
                or type(call.get('sequence')) is not int
                or type(call.get('attempt')) is not int
                or call.get('tool') != source_step['tool']
                or call.get('arguments') != expected_arguments
                or type(call.get('is_error')) is not bool
                or type(call.get('duration_ms')) is not int
                or call['duration_ms'] < 0
                or not isinstance(call.get('mcp_result'), dict)
            ):
                raise EvidenceError('phase report call sequence, attempt, tool, or resolved arguments differ')
            call_started = _parse_utc(call['started_at'], 'phase call started_at')
            call_ended = _parse_utc(call['ended_at'], 'phase call ended_at')
            if not (session_started <= call_started <= call_ended <= session_closed) or call_started < previous_end:
                raise EvidenceError('phase call UTC bounds or sequence order differs from the report')
            if attempt > 1:
                interval = source_step['repeat_until']['interval_seconds']
                if call_started < previous_end + timedelta(seconds=max(0, interval - 0.002)):
                    raise EvidenceError('phase repeat did not preserve its frozen wait interval')
            previous_end = call_ended
            result = {'isError': call['is_error'], 'structuredContent': call['structured']}
            if (
                call['mcp_result'].get('isError') is not call['is_error']
                or call['mcp_result'].get('structuredContent') != call['structured']
            ):
                raise EvidenceError('phase SDK mcp_result disagrees with structured/is_error call fields')
            try:
                evaluated = [evaluate_assertion(assertion, result, fixture) for assertion in assertion_specs]
            except Exception as exc:
                raise EvidenceError(f'phase call cannot be re-evaluated with scenario-runner semantics: {type(exc).__name__}') from exc
            if attempt < len(group) and all(row['passed'] for row in evaluated):
                raise EvidenceError('phase repeat has a previous attempt that already satisfied the terminal assertions')
            final_evaluated = evaluated
        if not final_evaluated or not all(row['passed'] for row in final_evaluated) or step['assertions'] != final_evaluated:
            raise EvidenceError('phase final step assertions do not re-evaluate from the last raw SDK result')
        completed[source_step['id']] = {
            'isError': group[-1]['is_error'],
            'structuredContent': group[-1]['structured'],
        }
    if cursor != len(calls):
        raise EvidenceError('phase report contains an excess or out-of-order call')


def _normalized_tools_bytes(listing: dict[str, Any]) -> bytes:
    """Normalize a raw tools/list result with the one frozen algorithm.

    Both the HTTP and the stdio schema-identity originals must normalize with
    this exact projection (name/inputSchema/outputSchema, name-sorted, sorted
    compact JSON plus trailing newline) before their bytes may be compared.
    """
    if not isinstance(listing.get('tools'), list):
        raise EvidenceError('tools/list does not contain tools')
    normalized = []
    for tool in listing['tools']:
        if not isinstance(tool, dict) or not isinstance(tool.get('name'), str) or 'inputSchema' not in tool:
            raise EvidenceError('tools/list lacks name or inputSchema')
        normalized.append({
            'name': tool['name'],
            'inputSchema': tool['inputSchema'],
            'outputSchema': tool.get('outputSchema'),
        })
    normalized.sort(key=lambda item: item['name'])
    if len(normalized) != 130 or len({item['name'] for item in normalized}) != 130:
        raise EvidenceError('tools/list does not contain 130 unique tools')
    return (
        json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
        + '\n'
    ).encode('utf-8')


def _verify_restore_action_originals(
    restore_attempt_id: str,
    snapshot_name: str,
    marker: str,
    paths: dict[str, Path],
) -> None:
    """Parse the four restore action originals as real command transcripts.

    Each carried original must be the actual command envelope (argv or control
    script, UTC bracket, exit status, complete stdout/stderr with hashes)
    bound to this restore attempt, and the four commands must form one
    chronologically ordered attempt whose parsed facts — snapshot list,
    revertToSnapshot argv, vmx checkpoint marker, guest identity — equal the
    declared restore.  Text that merely contains the expected strings, or a
    ``p05-restore-record-summary-v1`` without the carried envelope, is
    rejected (CHK-034).
    """
    from tests import p05_snapshot_raw

    def stream_identity(document: dict[str, Any], label: str) -> tuple[str, str]:
        response = document.get('response')
        response_keys = {
            'stdout', 'stdout_size', 'stdout_sha256',
            'stderr', 'stderr_size', 'stderr_sha256',
        }
        if not isinstance(response, dict) or set(response) != response_keys:
            raise EvidenceError(f'{label} does not retain complete stdout/stderr')
        for stream in ('stdout', 'stderr'):
            text = response[stream]
            if not isinstance(text, str):
                raise EvidenceError(f'{label} {stream} is not text')
            raw = text.encode('utf-8')
            if (
                type(response[f'{stream}_size']) is not int
                or response[f'{stream}_size'] != len(raw)
                or response[f'{stream}_sha256'] != hashlib.sha256(raw).hexdigest()
            ):
                raise EvidenceError(f'{label} {stream} bytes differ from their identity')
        return response['stdout'], response['stderr']

    records: dict[str, tuple[dict[str, Any], str]] = {}
    vmx_values: set[str] = set()
    for kind in ('snapshot_metadata', 'revert_operation', 'pre_start_marker', 'post_restore_hostname'):
        path = paths[kind]
        document = _read_json(path, f'restore original {kind}')
        shared_keys = {
            'schema_version', 'kind', 'workflow_id', 'operation_id',
            'observation', 'request', 'started_at', 'ended_at', 'exit_status',
            'response', 'vmx',
        }
        if document.get('kind') == RESTORE_GUEST_IDENTITY_KIND:
            shared_keys = shared_keys | {'endpoint', 'transport'}
        if set(document) != shared_keys | RESTORE_ATTEMPT_KEYS:
            raise EvidenceError(f'{kind} is not an attempt-bound raw command original')
        if (
            document.get('schema_version') != 1
            or document.get('workflow_id') != WORKFLOW_ID
            or document.get('restore_attempt_id') != restore_attempt_id
            or document.get('operation_id') != RESTORE_OPERATION_IDS[kind]
            or not _nonempty_string(document.get('observation'), f'{kind}.observation')
        ):
            raise EvidenceError(f'{kind} original identity or operation differs')
        request = document.get('request')
        if document.get('kind') == RESTORE_HOST_COMMAND_KIND:
            if (
                not isinstance(request, dict) or set(request) != {'argv', 'command_line'}
                or not isinstance(request['argv'], list) or not request['argv']
                or any(not isinstance(item, str) or not item for item in request['argv'])
                or not _nonempty_string(request['command_line'], f'{kind}.command_line')
            ):
                raise EvidenceError(f'{kind} original request is not a complete command')
            # Both recorded request fields must tell one story; an argv whose
            # items the recorded command line does not contain is not one
            # executed original (B06).
            if any(item not in request['command_line'] for item in request['argv']):
                raise EvidenceError(f'{kind} command_line contradicts its argv')
        elif document.get('kind') == RESTORE_GUEST_IDENTITY_KIND:
            if (
                not isinstance(request, dict)
                or set(request) != {'script', 'script_sha256', 'tool'}
                or not _nonempty_string(request['script'], f'{kind}.script')
                or not _sha256_is_valid(request.get('script_sha256'))
                or request['script_sha256'] != hashlib.sha256(request['script'].encode('utf-8')).hexdigest()
                or not _nonempty_string(request['tool'], f'{kind}.tool')
            ):
                raise EvidenceError(f'{kind} original control request is not a complete script transcript')
            if request['script'] != RESTORE_GUEST_IDENTITY_SCRIPT:
                raise EvidenceError(
                    f'{kind} control script is not the fixed approved guest identity query; '
                    'a term that merely mentions COMPUTERNAME or an adapter class is not the executed query'
                )
            endpoint = document.get('endpoint')
            if (
                not isinstance(endpoint, str) or not endpoint.startswith('http://192.168.204.232:')
                or not _nonempty_string(document.get('transport'), f'{kind}.transport')
            ):
                raise EvidenceError(f'{kind} original is not a control-plane guest observation')
        else:
            raise EvidenceError(f'{kind} original is not a recognized raw command kind')
        try:
            vmx = str(p05_snapshot_raw.host_vmx(document.get('vmx')))
        except p05_snapshot_raw.SnapshotRawError as exc:
            raise EvidenceError(f'{kind} original vmx identity is invalid') from exc
        vmx_values.add(vmx)
        started = _parse_utc(document.get('started_at'), f'{kind}.started_at')
        ended = _parse_utc(document.get('ended_at'), f'{kind}.ended_at')
        if ended < started:
            raise EvidenceError(f'{kind} command ends before it starts')
        exit_status = document.get('exit_status')
        if (
            not isinstance(exit_status, dict) or set(exit_status) != {'code'}
            or type(exit_status['code']) is not int or exit_status['code'] != 0
        ):
            raise EvidenceError(f'{kind} command did not exit successfully')
        stdout, _ = stream_identity(document, f'restore original {kind}')
        records[kind] = (document, stdout)
    if len(vmx_values) != 1:
        raise EvidenceError('restore originals do not share one host VMX identity')
    snapshot_metadata, metadata_stdout = records['snapshot_metadata']
    revert_operation, _ = records['revert_operation']
    pre_start_marker, marker_stdout = records['pre_start_marker']
    post_restore_hostname, hostname_stdout = records['post_restore_hostname']
    try:
        names = p05_snapshot_raw.snapshot_names(metadata_stdout)
    except p05_snapshot_raw.SnapshotRawError as exc:
        raise EvidenceError('snapshot metadata original is not the actual vmrun snapshot tree') from exc
    if snapshot_name not in names:
        raise EvidenceError('snapshot metadata original does not list the selected snapshot')
    # B06: each action must be the real executable with the fixed action and
    # parameter syntax; a stray executable whose argv happens to carry the
    # right strings (echo/false) is not the recorded operation.
    vmx_value = next(iter(vmx_values))
    metadata_argv = snapshot_metadata['request']['argv']
    if PurePosixPath(metadata_argv[0]).name != 'vmrun' or metadata_argv not in (
        [metadata_argv[0], 'listSnapshots', vmx_value],
        [metadata_argv[0], '-T', 'ws', 'listSnapshots', vmx_value],
    ):
        raise EvidenceError('snapshot metadata original is not the actual vmrun listSnapshots command')
    revert_argv = revert_operation['request']['argv']
    if PurePosixPath(revert_argv[0]).name != 'vmrun' or revert_argv not in (
        [revert_argv[0], 'revertToSnapshot', vmx_value, snapshot_name],
        [revert_argv[0], '-T', 'ws', 'revertToSnapshot', vmx_value, snapshot_name],
    ):
        raise EvidenceError('revert original is not the actual vmrun revertToSnapshot command for the selected snapshot')
    marker_argv = pre_start_marker['request']['argv']
    if (
        len(marker_argv) < 2
        or PurePosixPath(marker_argv[0]).name not in {'grep', 'cat'}
        or marker_argv[-1] != vmx_value
        or (PurePosixPath(marker_argv[0]).name == 'grep' and 'checkpoint.vmState' not in marker_argv[1])
    ):
        raise EvidenceError('pre-start marker original is not the actual vmx checkpoint readback command')
    try:
        fields = p05_snapshot_raw.vmsd_fields(marker_stdout)
    except p05_snapshot_raw.SnapshotRawError as exc:
        raise EvidenceError('pre-start marker original is not the actual vmx/vmsd readback') from exc
    if fields.get('checkpoint.vmState') != marker:
        raise EvidenceError('pre-start marker original does not parse to the declared checkpoint marker')
    try:
        p05_snapshot_raw.guest_adapter(hostname_stdout)
    except p05_snapshot_raw.SnapshotRawError as exc:
        raise EvidenceError('post-restore hostname original is not the actual guest identity readback') from exc
    order = (
        _parse_utc(snapshot_metadata['ended_at'], 'snapshot metadata end'),
        _parse_utc(revert_operation['started_at'], 'revert start'),
        _parse_utc(revert_operation['ended_at'], 'revert end'),
        _parse_utc(pre_start_marker['started_at'], 'pre-start start'),
        _parse_utc(pre_start_marker['ended_at'], 'pre-start end'),
        _parse_utc(post_restore_hostname['started_at'], 'hostname start'),
    )
    if not (order[0] <= order[1] <= order[2] <= order[3] <= order[4] <= order[5]):
        raise EvidenceError('restore originals are not one chronologically ordered attempt')


def _verify_phase(
    bundle_root: Path,
    phase: Any,
    expected_scenario: str,
    expected_stage: str,
    expected_snapshot: str,
    seen: dict[str, tuple[int, str]],
    source_copies: dict[str, Path],
) -> tuple[dict[str, Any], tuple[str, str, str]]:
    if not isinstance(phase, dict) or set(phase) != PHASE_KEYS:
        raise EvidenceError('activation phase has invalid keys')
    _nonempty_string(phase.get('restore_attempt_id'), 'phase restore_attempt_id')
    _nonempty_string(phase.get('run_id'), 'phase run_id')
    scenario, _, source_sha256, index_sha256, fixture_spec_sha256 = _load_p05_phase_source(
        source_copies, expected_scenario, expected_stage, expected_snapshot
    )
    refs = {
        name: _resolve_ref(bundle_root, phase[name], f'phase.{name}', seen)
        for name in PHASE_KEYS - {'restore_attempt_id', 'run_id'}
    }
    report = _read_json(refs['report'], 'phase report')
    if (
        set(report) != REPORT_KEYS
        or report.get('schema_version') != 2
        or report.get('status') != 'success'
        or report.get('scenario') != expected_scenario
        or report.get('run_id') != phase['run_id']
        or report.get('source_sha256') != source_sha256
        or report.get('index_sha256') != index_sha256
        or report.get('fixture_spec_sha256') != fixture_spec_sha256
        or report.get('transport') != 'streamable-http'
        or report.get('endpoint') != 'http://192.168.204.232:28790/mcp'
        # P05 reports carry the runner's distinct-tool coverage (one row per
        # actually called tool for this scenario); it is not the P06 129-tool
        # relation matrix and must join the report's own calls exactly.
        or not isinstance(report.get('coverage'), list)
        or not report['coverage']
        or any(set(row) != {'scenario_id', 'tool'} or row['scenario_id'] != expected_scenario
               for row in report['coverage'] if isinstance(row, dict))
        or len({row.get('tool') for row in report['coverage']}) != len(report['coverage'])
        or report.get('authorization_configured') is not True
        or report.get('failure') is not None
        or report.get('unexecuted_step_ids') != []
        or not isinstance(report.get('steps'), list)
        or any(step.get('passed') is not True for step in report['steps'] if isinstance(step, dict))
        or any(not isinstance(step, dict) for step in report['steps'])
        or not isinstance(report.get('cleanup'), list)
        or any(not isinstance(step, dict) or step.get('passed') is not True
               for step in report['cleanup'])
        or not _sha256_is_valid(report.get('snapshot_evidence_sha256'))
    ):
        raise EvidenceError('phase report is not the required complete schema2 success report')
    report_ref = phase['report']['path']
    report_parent = report_ref.rsplit('/', 1)[0] if '/' in report_ref else ''
    if not report_parent:
        raise EvidenceError('phase report must be retained below its original run directory')
    fixture = _verify_fixture_instance(
        bundle_root, report_parent, report, scenario, fixture_spec_sha256
    )
    tools_list = plain_file(bundle_root, f'{report_parent}/tools-list.json')
    tools_schema = plain_file(bundle_root, f'{report_parent}/tools-schema.json')
    listing = _read_json(tools_list, 'phase tools/list')
    normalized_bytes = _normalized_tools_bytes(listing)
    if not {step['tool'] for step in scenario['steps']}.issubset(
        {tool['name'] for tool in listing['tools']}
    ):
        raise EvidenceError('phase tools/list omits a tool required by the frozen P05 scenario')
    if tools_schema.read_bytes() != normalized_bytes or digest(tools_schema) != report.get('tools_schema_sha256'):
        raise EvidenceError('phase tools/list, tools-schema, and report hash do not agree')
    snapshot_evidence = _read_json(refs['snapshot_evidence'], 'phase snapshot evidence')
    if digest(refs['snapshot_evidence']) != report['snapshot_evidence_sha256']:
        raise EvidenceError('phase report does not bind its snapshot evidence bytes')
    if (
        set(snapshot_evidence) != SNAPSHOT_EVIDENCE_KEYS
        or snapshot_evidence.get('scenario_id') != report['scenario']
        or snapshot_evidence.get('source_sha256') != source_sha256
        or snapshot_evidence.get('index_sha256') != index_sha256
    ):
        raise EvidenceError('phase snapshot evidence does not join the report identity')
    _verify_phase_identities(report, snapshot_evidence)
    verify_observation(report, bundle_root / report_parent)
    _verify_phase_execution(report, scenario, fixture)
    return _verify_phase_restore(
        snapshot_evidence, bundle_root, phase, expected_stage, expected_snapshot, seen
    )


def _verify_creation_metadata(
    bundle_root: Path,
    reference: Any,
    marker: str,
    seen: dict[str, tuple[int, str]],
) -> None:
    document = _read_json(
        _resolve_ref(bundle_root, reference, 'creation_metadata', seen),
        'creation metadata',
    )
    expected = {
        'schema_version', 'workflow_id', 'candidate', 'checkpoint_marker', 'vmx',
        'tree_before', 'create_operation', 'tree_after', 'metadata_readback',
    }
    # PLAN-CHANGE-016: the pre-existing Snapshot188 creation is evidenced as a
    # bounded historical reconstruction and declares that mode explicitly.
    if document.get('evidence_mode') == 'historical-reconstruction':
        expected = expected | {'evidence_mode', 'create_time_utc'}
    if (
        set(document) != expected
        or document.get('schema_version') != 1
        or document.get('workflow_id') != WORKFLOW_ID
        or document.get('candidate') != SNAPSHOT_188
        or document.get('checkpoint_marker') != marker
        or not isinstance(document.get('vmx'), str)
        or not document['vmx'].endswith('Win10MalBox-Velo.vmx')
    ):
        raise EvidenceError('creation metadata shape or identity is invalid')
    for key in ('tree_before', 'create_operation', 'tree_after', 'metadata_readback'):
        _resolve_ref(bundle_root, document[key], f'creation_metadata.{key}', seen)


def _verify_ready(
    bundle_root: Path,
    phase: dict[str, Any],
    seen: dict[str, tuple[int, str]],
    expected_restore: dict[str, Any] | None = None,
) -> None:
    """Join the ready wrapper to its phase restore identity and raw transcripts.

    Byte-correct Refs alone prove nothing (CHK-028): the twelve observation
    originals are re-parsed by the P05 ready collector parser, joined to the
    phase report, and the wrapper's stage/snapshot/marker must equal the
    already verified phase restore.
    """
    document = _read_json(_resolve_ref(bundle_root, phase['ready'], 'phase.ready', seen), 'ready')
    expected = {
        'schema_version', 'workflow_id', 'run_id', 'restore_attempt_id',
        'snapshot_stage', 'snapshot_name', 'checkpoint_marker', 'observations',
    }
    observation_names = {
        'host_clock', 'guest_identity', 'fixture_static', 'fixture_instance',
        'guest_processes', 'host_processes', 'parent_bindings', 'dependencies',
        'service', 'acl', 'firewall', 'resources',
    }
    if (
        set(document) != expected
        or document.get('schema_version') != 1
        or document.get('workflow_id') != WORKFLOW_ID
        or document.get('run_id') != phase['run_id']
        or document.get('restore_attempt_id') != phase['restore_attempt_id']
        or not isinstance(document.get('observations'), dict)
        or set(document['observations']) != observation_names
    ):
        raise EvidenceError('ready shape or phase identity is invalid')
    for name, reference in document['observations'].items():
        _resolve_ref(bundle_root, reference, f'ready.observations.{name}', seen)
    if expected_restore is not None:
        for field in ('snapshot_stage', 'snapshot_name', 'checkpoint_marker'):
            if document.get(field) != expected_restore.get(field):
                raise EvidenceError(f'ready {field} differs from the verified phase restore')
    report_reference = phase.get('report')
    if not isinstance(report_reference, dict) or set(report_reference) != REF_KEYS:
        raise EvidenceError('ready verification requires the phase report Ref join')
    report = _read_json(
        _resolve_ref(bundle_root, report_reference, 'phase.report', seen), 'ready report join'
    )
    from tests.p05_ready_evidence import ReadyEvidenceError, verify_ready_raw_evidence
    try:
        verify_ready_raw_evidence(document, bundle_root=bundle_root, report=report)
    except ReadyEvidenceError as exc:
        raise EvidenceError(f'ready raw evidence is invalid: {exc}') from exc


def _verify_creation_binding(
    bundle_root: Path, activation: dict[str, Any], initial_restore: dict[str, Any],
    seen: dict[str, tuple[int, str]],
) -> None:
    """Bind creation to the already verified adoption VM and phase chronology."""
    from tests.p05_candidate_creation import SnapshotRawError, verify_creation

    baseline = next(record for record in initial_restore['restore_records']
                    if record['kind'] == 'baseline_adoption')
    adoption = _read_json(plain_file(bundle_root / 'p05-originals', baseline['path']), 'creation baseline binding')
    # _verify_phase_restore has already validated this full self-contained
    # adoption and its hash. No old canonical absolute host path is opened.
    creation = _read_json(
        _resolve_ref(bundle_root, activation['creation_metadata'], 'creation_metadata', seen),
        'creation metadata',
    )
    try:
        facts = verify_creation(
            creation, expected_vmx=adoption['vmx'], expected_marker=activation['checkpoint_marker'],
            resolve=lambda reference, label: _resolve_ref(bundle_root, reference, label, seen),
        )
    except (SnapshotRawError, KeyError) as exc:
        raise EvidenceError('candidate creation originals do not bind the adopted VM') from exc
    initial_report = _read_json(
        _resolve_ref(bundle_root, activation['initial']['report'], 'initial.report', seen), 'initial report'
    )
    # A reconstructed creation (PLAN-CHANGE-016) brackets a historical event;
    # a re-collected initial phase binds to Snapshot187 by restore identity,
    # not by wall-clock precedence over that past instant. Candidate cycles
    # must still begin after the creation bracket closed.
    if facts.get('evidence_mode') != 'historical-reconstruction':
        if _parse_utc(initial_report['ended_at'], 'initial end') > _parse_utc(facts['started_at'], 'creation begin'):
            raise EvidenceError('candidate creation preceded completion of the initial representative run')
    previous_end = _parse_utc(facts['ended_at'], 'creation end')
    for phase in activation['candidate_cycles']:
        report = _read_json(_resolve_ref(bundle_root, phase['report'], 'candidate.report', seen), 'candidate report')
        if _parse_utc(report['started_at'], 'candidate begin') < previous_end:
            raise EvidenceError('candidate report chronology overlaps creation or a preceding full cycle')
        previous_end = _parse_utc(report['ended_at'], 'candidate end')


def _verify_dependency_acceptance(
    bundle_root: Path,
    phase: dict[str, Any],
    seen: dict[str, tuple[int, str]],
) -> None:
    """Recompute the dependency predicates from the carried originals.

    ``inventory_artifacts`` must be the actual dependencies transcript and
    re-verify the locked manifest rows; ``four_chains`` must parse as the
    complete three-chain record joined to this phase's ready/report; the
    carried ``network_observations`` window is parsed fail-closed with the
    PC014-adjusted window parser (complete window proof stays optional
    supporting evidence, but a malformed or lossy original is rejected).
    """
    document = _read_json(
        _resolve_ref(bundle_root, phase['dependency_acceptance'], 'phase.dependency_acceptance', seen),
        'dependency acceptance',
    )
    expected = {
        'schema_version', 'workflow_id', 'run_id', 'restore_attempt_id',
        'inventory_artifacts', 'four_chains', 'network_observations',
    }
    if (
        set(document) != expected
        or document.get('schema_version') != 1
        or document.get('workflow_id') != WORKFLOW_ID
        or document.get('run_id') != phase['run_id']
        or document.get('restore_attempt_id') != phase['restore_attempt_id']
    ):
        raise EvidenceError('dependency acceptance shape or phase identity is invalid')
    report_reference = phase.get('report')
    ready_reference = phase.get('ready')
    if (
        not isinstance(report_reference, dict) or set(report_reference) != REF_KEYS
        or not isinstance(ready_reference, dict) or set(ready_reference) != REF_KEYS
    ):
        raise EvidenceError('dependency verification requires the phase ready and report Ref joins')
    report = _read_json(
        _resolve_ref(bundle_root, report_reference, 'phase.report', seen),
        'dependency report join',
    )
    inventory_path = _resolve_ref(
        bundle_root, document['inventory_artifacts'],
        'dependency_acceptance.inventory_artifacts', seen,
    )
    from tests.p05_ready_evidence import (
        ReadyEvidenceError, _load_transcript, _verify_dependencies,
    )
    try:
        transcript = _load_transcript(
            inventory_path, 'dependencies', document, 'guest',
        )
        _verify_dependencies(transcript, bundle_root)
    except ReadyEvidenceError as exc:
        raise EvidenceError(f'dependency inventory originals are invalid: {exc}') from exc
    from tests.p05_four_chain_evidence import FourChainEvidenceError, verify_three_chain_core
    try:
        verify_three_chain_core(bundle_root, document['four_chains'], ready_reference, report)
    except FourChainEvidenceError as exc:
        raise EvidenceError(f'four-chain originals are invalid: {exc}') from exc
    chain = _read_json(
        _resolve_ref(bundle_root, document['four_chains'], 'dependency_acceptance.four_chains', seen),
        'dependency four chains',
    )
    window_path = _resolve_ref(
        bundle_root, document['network_observations'],
        'dependency_acceptance.network_observations', seen,
    )
    try:
        window_text = window_path.read_text(encoding='utf-8-sig')
    except (OSError, UnicodeError) as exc:
        raise EvidenceError('network window original is not readable UTF-8 text') from exc
    from tests.p05_network_window import NetworkWindowError, parse_events, verify_window
    try:
        verify_window(
            parse_events(window_text),
            header_text=window_text,
            window_started_at=chain['started_at'],
            window_ended_at=chain['ended_at'],
        )
    except NetworkWindowError as exc:
        raise EvidenceError(f'network window original is invalid: {exc}') from exc


def _verify_entry_gate(
    bundle_root: Path,
    phase: dict[str, Any],
    seen: dict[str, tuple[int, str]],
) -> None:
    """Recompute the seven HTTP entry predicates from the raw case originals.

    A byte-correct Ref to a ``p05-entry-gate-case-v1`` file is still rejected
    unless the recorded status, handler-counter delta, and initialize result
    prove each case's actual outcome (CHK-028).
    """
    document = _read_json(
        _resolve_ref(bundle_root, phase['entry_gate'], 'phase.entry_gate', seen),
        'entry gate',
    )
    cases = {
        'no_origin', 'allowed_origin', 'missing_bearer', 'wrong_bearer',
        'missing_host', 'wrong_host', 'wrong_origin',
    }
    if (
        set(document) != {'schema_version', 'workflow_id', 'run_id', 'restore_attempt_id', 'cases'}
        or document.get('schema_version') != 1
        or document.get('workflow_id') != WORKFLOW_ID
        or document.get('run_id') != phase['run_id']
        or document.get('restore_attempt_id') != phase['restore_attempt_id']
        or not isinstance(document.get('cases'), dict)
        or set(document['cases']) != cases
    ):
        raise EvidenceError('entry gate shape or phase identity is invalid')
    for name, reference in document['cases'].items():
        _resolve_ref(bundle_root, reference, f'entry_gate.cases.{name}', seen)
    from tests.p05_http_evidence import (
        EXPECTED_ENDPOINT, EntryGateEvidenceError, verify_entry_gate_raw,
    )
    try:
        verify_entry_gate_raw(
            document,
            bundle_root=bundle_root,
            run_id=phase['run_id'],
            restore_attempt_id=phase['restore_attempt_id'],
            endpoint=EXPECTED_ENDPOINT,
            allowed_origin=ENTRY_ALLOWED_ORIGIN,
        )
    except EntryGateEvidenceError as exc:
        raise EvidenceError(f'entry-gate originals are invalid: {exc}') from exc


def _network_element_original(
    bundle_root: Path,
    phase: dict[str, Any],
    reference: Any,
    label: str,
    seen: dict[str, tuple[int, str]],
    *,
    expect_success: bool,
    not_before: datetime,
) -> dict[str, Any]:
    """Validate one PC006 collector execution as an attempt-bound envelope.

    The envelope must be this phase's own run/restore identity and a real
    command execution: it cannot precede the service instance whose boundary
    it probes.  No formal clause fixes an upper end for the round's security
    probes (see the PLAN-CHANGE candidate in the result), so only the
    decidable precedence is enforced here instead of the withdrawn
    report-interval containment.
    """
    path = _resolve_ref(bundle_root, reference, label, seen)
    document = _read_json(path, label)
    shared_keys = {
        'schema_version', 'kind', 'workflow_id', 'run_id',
        'restore_attempt_id', 'operation_id', 'observation',
        'request', 'started_at', 'ended_at', 'exit_status', 'response', 'vmx',
    }
    if document.get('kind') != PC006_COMMAND_KIND:
        raise EvidenceError(f'{label} is not an approved PC006 collector execution')
    if (
        set(document) != shared_keys
        or document.get('schema_version') != 1
        or document.get('workflow_id') != WORKFLOW_ID
        or document.get('run_id') != phase['run_id']
        or document.get('restore_attempt_id') != phase['restore_attempt_id']
        or not _nonempty_string(document.get('operation_id'), f'{label}.operation_id')
        or not _nonempty_string(document.get('observation'), f'{label}.observation')
    ):
        raise EvidenceError(f'{label} envelope shape or phase identity is invalid')
    try:
        from tests import p05_snapshot_raw

        p05_snapshot_raw.host_vmx(document.get('vmx'))
    except (p05_snapshot_raw.SnapshotRawError, TypeError) as exc:
        raise EvidenceError(f'{label} host VMX identity is invalid') from exc
    request = document.get('request')
    if (
        not isinstance(request, dict) or set(request) != {'argv', 'command_line'}
        or not isinstance(request['argv'], list) or not request['argv']
        or any(not isinstance(item, str) or not item for item in request['argv'])
        or not _nonempty_string(request['command_line'], f'{label}.command_line')
    ):
        raise EvidenceError(f'{label} request is not a complete command')
    if any(item not in request['command_line'] for item in request['argv']):
        raise EvidenceError(f'{label} command_line contradicts its argv')
    started = _parse_utc(document.get('started_at'), f'{label}.started_at')
    ended = _parse_utc(document.get('ended_at'), f'{label}.ended_at')
    if ended < started:
        raise EvidenceError(f'{label} command ends before it starts')
    if started < not_before:
        raise EvidenceError(
            f'{label} precedes the service instance it probes; a spliced transcript is not this round'
        )
    exit_status = document.get('exit_status')
    if not isinstance(exit_status, dict) or set(exit_status) != {'code'} or type(exit_status['code']) is not int:
        raise EvidenceError(f'{label} lacks an actual command exit code')
    if expect_success and exit_status['code'] != 0:
        raise EvidenceError(f'{label} command did not exit successfully')
    if not expect_success and exit_status['code'] == 0:
        raise EvidenceError(f'{label} probe unexpectedly succeeded; it proves no boundary')
    response = document.get('response')
    response_keys = {
        'stdout', 'stdout_size', 'stdout_sha256',
        'stderr', 'stderr_size', 'stderr_sha256',
    }
    if not isinstance(response, dict) or set(response) != response_keys:
        raise EvidenceError(f'{label} does not retain complete stdout/stderr')
    for stream in ('stdout', 'stderr'):
        text = response[stream]
        if not isinstance(text, str):
            raise EvidenceError(f'{label} {stream} is not text')
        raw = text.encode('utf-8')
        if (
            type(response[f'{stream}_size']) is not int
            or response[f'{stream}_size'] != len(raw)
            or response[f'{stream}_sha256'] != hashlib.sha256(raw).hexdigest()
        ):
            raise EvidenceError(f'{label} {stream} bytes differ from their identity')
    return document


def _pc006_collector_document(
    element: dict[str, Any],
    label: str,
    mode: str,
    source: str,
    comparison_port: int,
) -> dict[str, Any]:
    """Recompute one PC006 element from the frozen collector's own stdout.

    The recorded command must be the exact approved collector invocation
    (full script content), so its structured stdout is collector output and
    not a hand-written ``p06-connect-probe-v1`` conclusion.
    """
    request = element['request']
    expected_argv = pc006_collector_argv(mode, source, comparison_port)
    if request['argv'] != expected_argv or request['command_line'] != ' '.join(expected_argv):
        raise EvidenceError(f'{label} is not the approved fixed PC006 collector command')
    if element['exit_status']['code'] != 0:
        raise EvidenceError(f'{label} PC006 collector itself did not exit successfully')
    try:
        document = json.loads(element['response']['stdout'])
    except json.JSONDecodeError as exc:
        raise EvidenceError(f'{label} stdout is not the frozen collector result') from exc
    if (
        not isinstance(document, dict)
        or set(document) != {
            'schema_version', 'kind', 'mode', 'probe_source_address',
            'target_host', 'comparison_port', 'executions',
        }
        or document.get('schema_version') != 1
        or document.get('kind') != PC006_PROBE_KIND
        or document.get('mode') != mode
        or document.get('probe_source_address') != source
        or document.get('target_host') != '192.168.204.232'
        or document.get('comparison_port') != comparison_port
    ):
        raise EvidenceError(f'{label} collector result identity differs')
    executions = document.get('executions')
    expected_rows = 4 if mode == PC006_DUAL_MODE else 1
    if not isinstance(executions, list) or len(executions) != expected_rows:
        raise EvidenceError(
            f'{label} collector result must retain every per-port execution; '
            'a derived summary line alone is not accepted'
        )
    return document


def _pc006_execution_row(
    row: Any,
    label: str,
    role: str,
    port: int,
    bind: str,
    *,
    clock: tuple[datetime, datetime],
) -> tuple[datetime, datetime]:
    """Validate one raw curl execution row produced by the frozen collector."""
    if not isinstance(row, dict) or set(row) != PC006_EXECUTION_KEYS:
        raise EvidenceError(f'{label} execution row shape is invalid')
    if row.get('role') != role or row.get('port') != port:
        raise EvidenceError(f'{label} execution row does not bind role {role!r} port {port}')
    request = row.get('request')
    expected_argv = _pc006_curl_argv(bind, port)
    if (
        not isinstance(request, dict) or set(request) != {'argv', 'command_line'}
        or request.get('argv') != expected_argv
        or request.get('command_line') != ' '.join(expected_argv)
    ):
        raise EvidenceError(f'{label} execution row is not the approved bound-source curl probe')
    started = _parse_utc(row.get('started_at'), f'{label}.started_at')
    ended = _parse_utc(row.get('ended_at'), f'{label}.ended_at')
    if ended < started or started < clock[0]:
        raise EvidenceError(f'{label} execution time order or service-instance precedence differs')
    if ended > clock[1]:
        raise EvidenceError(f'{label} execution outlives its collector envelope')
    status = row.get('exit_status')
    if not isinstance(status, dict) or set(status) != {'code'} or type(status['code']) is not int:
        raise EvidenceError(f'{label} execution lacks a real curl exit code')
    response = row.get('response')
    response_keys = {
        'stdout', 'stdout_size', 'stdout_sha256',
        'stderr', 'stderr_size', 'stderr_sha256',
    }
    if not isinstance(response, dict) or set(response) != response_keys:
        raise EvidenceError(f'{label} execution does not retain complete curl stdout/stderr')
    for stream in ('stdout', 'stderr'):
        text = response[stream]
        if not isinstance(text, str):
            raise EvidenceError(f'{label} execution {stream} is not text')
        raw = text.encode('utf-8')
        if (
            type(response[f'{stream}_size']) is not int
            or response[f'{stream}_size'] != len(raw)
            or response[f'{stream}_sha256'] != hashlib.sha256(raw).hexdigest()
        ):
            raise EvidenceError(f'{label} execution {stream} bytes differ from their identity')
    return started, ended


def _pc006_curl_failure_class(row: dict[str, Any], label: str) -> str:
    """Derive the failure class from curl's own exit code and raw stderr."""
    code = row['exit_status']['code']
    stderr = row['response']['stderr']
    if code == 7 and 'Connection refused' in stderr:
        failure_class = 'connection-refused'
    elif code == 7 and 'No route to host' in stderr:
        failure_class = 'no-route-to-host'
    elif code == 28 and ('Timeout was reached' in stderr or 'timed out' in stderr.lower()):
        failure_class = 'connection-timeout'
    else:
        raise EvidenceError(
            f'{label} is not a classified curl network failure (exit {code}); '
            'a missing command, syntax error, or arbitrary non-zero status is not a boundary'
        )
    if failure_class not in NETWORK_FAILURE_CLASSES:
        raise EvidenceError(f'{label} failure class is not approved')
    return failure_class


def _pc006_allowed_response(row: dict[str, Any], label: str) -> int:
    """Derive the live HTTP response from curl's own output."""
    if row['exit_status']['code'] != 0:
        raise EvidenceError(f'{label} did not respond from the allowed source')
    status_text = row['response']['stdout'].strip()
    if not status_text.isdigit() or len(status_text) != 3 or not 100 <= int(status_text) <= 599:
        raise EvidenceError(f'{label} does not retain a real HTTP status code from curl')
    return int(status_text)


def _verify_pc006_boundary(
    bundle_root: Path,
    phase: dict[str, Any],
    report: dict[str, Any],
    reference: Any,
    seen: dict[str, tuple[int, str]],
) -> None:
    """Verify the PC006 three-element originals (PLAN-CHANGE-006 closure).

    A verdict summary is rejected, and so is a probe whose facts do not prove
    the boundary: the bound source must be recoverable from the executed curl
    command (B02), each failure must be a classified network fact recomputed
    from curl's own exit code and stderr rather than any non-zero exit (B03),
    command-not-found, syntax errors, and echo transcripts are rejected, and
    the firewall original must be the same-round ready collector transcript
    whose unique rule is re-parsed by the ready parser (B01).
    """
    import ipaddress

    from tests.p05_ready_evidence import GUEST_FIXED_ADDRESS, HOST_FIXED_ADDRESS, SERVICE_PORT

    path = _resolve_ref(bundle_root, reference, 'network_evidence.non_allowed_source', seen)
    document = _read_json(path, 'non-allowed source boundary')
    if (
        set(document) != PC006_BOUNDARY_KEYS
        or document.get('schema_version') != 1
        or document.get('kind') != PC006_BOUNDARY_KIND
        or document.get('workflow_id') != WORKFLOW_ID
        or document.get('run_id') != phase['run_id']
        or document.get('restore_attempt_id') != phase['restore_attempt_id']
    ):
        raise EvidenceError('PC006 boundary document shape or phase identity is invalid')
    source = document.get('probe_source_address')
    try:
        parsed_source = ipaddress.ip_address(source)
    except ValueError as exc:
        raise EvidenceError('PC006 bound source address is not an IP address') from exc
    if (
        parsed_source.version != 4
        or str(parsed_source) in {GUEST_FIXED_ADDRESS, HOST_FIXED_ADDRESS}
    ):
        raise EvidenceError('PC006 bound source address is not a non-allowed source')
    comparison_port = document.get('comparison_port')
    if (
        type(comparison_port) is not int or isinstance(comparison_port, bool)
        or not 1 <= comparison_port <= 65535 or comparison_port == SERVICE_PORT
    ):
        raise EvidenceError('PC006 comparison port is invalid')

    not_before = _parse_utc(
        report.get('server_identity', {}).get('process_start_time_utc'),
        'PC006 service instance start',
    )

    bound = _network_element_original(
        bundle_root, phase, document['bound_source_failure'],
        'PC006 bound source probe', seen, expect_success=True, not_before=not_before,
    )
    bound_clock = (
        _parse_utc(bound['started_at'], 'PC006 bound source probe.started_at'),
        _parse_utc(bound['ended_at'], 'PC006 bound source probe.ended_at'),
    )
    bound_facts = _pc006_collector_document(
        bound, 'PC006 bound source probe', PC006_BOUND_MODE, str(parsed_source), comparison_port,
    )
    # B02/B03: the only accepted facts are the collector's own raw curl rows.
    # The curl argv carries the bound source (--interface), and the failure
    # class is recomputed from curl's exit code and stderr.
    bound_row = bound_facts['executions'][0]
    _pc006_execution_row(
        bound_row, 'PC006 bound source probe', 'probe_source', SERVICE_PORT,
        str(parsed_source), clock=bound_clock,
    )
    _pc006_curl_failure_class(bound_row, 'PC006 bound source probe')

    dual = _network_element_original(
        bundle_root, phase, document['dual_port_control'],
        'PC006 dual port control', seen, expect_success=True, not_before=not_before,
    )
    dual_clock = (
        _parse_utc(dual['started_at'], 'PC006 dual port control.started_at'),
        _parse_utc(dual['ended_at'], 'PC006 dual port control.ended_at'),
    )
    dual_facts = _pc006_collector_document(
        dual, 'PC006 dual port control', PC006_DUAL_MODE, str(parsed_source), comparison_port,
    )
    by_execution: dict[tuple[str, int], dict[str, Any]] = {}
    for position, row in enumerate(dual_facts['executions']):
        row_label = f'PC006 dual port control execution {position}'
        if not isinstance(row, dict) or set(row) != PC006_EXECUTION_KEYS:
            raise EvidenceError(f'{row_label} shape is invalid')
        role, port = row.get('role'), row.get('port')
        if role not in {'probe_source', 'allowed_source'} or port not in {SERVICE_PORT, comparison_port}:
            raise EvidenceError(f'{row_label} does not name an approved role and port')
        bind = str(parsed_source) if role == 'probe_source' else HOST_FIXED_ADDRESS
        _pc006_execution_row(row, row_label, role, port, bind, clock=dual_clock)
        if (role, port) in by_execution:
            raise EvidenceError('PC006 dual port control repeats a role/port execution')
        by_execution[(role, port)] = row
    if set(by_execution) != {
        ('probe_source', SERVICE_PORT), ('probe_source', comparison_port),
        ('allowed_source', SERVICE_PORT), ('allowed_source', comparison_port),
    }:
        raise EvidenceError('PC006 dual port control must retain both ports from both sources')
    # The per-port rows are derived from the raw executions here; a merged
    # summary line carried in the document is neither trusted nor required.
    for port in (SERVICE_PORT, comparison_port):
        _pc006_curl_failure_class(
            by_execution[('probe_source', port)], f'PC006 dual port control port {port}')
    _pc006_allowed_response(
        by_execution[('allowed_source', comparison_port)],
        'PC006 unprotected comparison port',
    )
    _pc006_allowed_response(
        by_execution[('allowed_source', SERVICE_PORT)],
        'PC006 formal port from the allowed source',
    )

    _verify_pc006_firewall(bundle_root, phase, document, seen)


def _verify_pc006_firewall(
    bundle_root: Path,
    phase: dict[str, Any],
    boundary: dict[str, Any],
    seen: dict[str, tuple[int, str]],
) -> None:
    """Bind the PC006 firewall element to the approved ready collector bytes.

    The rule readback must be the exact same-round ready ``firewall`` original
    already parsed by the P05 ready collector/parser; a re-labelled echo or
    hand-written rules JSON is not that observation, and the unique rule
    predicates are re-checked here through the same parser (B01).
    """
    from tests.p05_ready_evidence import (
        GUEST_COMPUTER_NAME,
        GUEST_FIXED_ADDRESS,
        ReadyEvidenceError,
        SERVICE_PORT,
        _load_transcript,
        _verify_firewall,
    )

    ready_reference = phase.get('ready')
    if not isinstance(ready_reference, dict) or set(ready_reference) != REF_KEYS:
        raise EvidenceError('PC006 firewall verification requires the phase ready Ref join')
    ready = _read_json(
        _resolve_ref(bundle_root, ready_reference, 'phase.ready', seen),
        'phase ready for the PC006 firewall join',
    )
    observations = ready.get('observations')
    if not isinstance(observations, dict) or not isinstance(observations.get('firewall'), dict):
        raise EvidenceError('phase ready does not retain a firewall observation')
    if observations['firewall'] != boundary['firewall_rule']:
        raise EvidenceError(
            'PC006 firewall original is not the same-round ready firewall observation; '
            're-writing the rule bytes under a PC006 label does not prove the rule was read'
        )
    firewall_path = _resolve_ref(
        bundle_root, boundary['firewall_rule'], 'PC006 firewall rule', seen)
    try:
        transcript = _load_transcript(firewall_path, 'firewall', boundary, 'guest')
        if transcript.computer_name != GUEST_COMPUTER_NAME:
            raise ReadyEvidenceError('firewall transcript does not come from the approved guest host')
        _verify_firewall(
            transcript,
            {'listener': {'LocalPort': SERVICE_PORT, 'LocalAddress': GUEST_FIXED_ADDRESS}},
        )
    except ReadyEvidenceError as exc:
        raise EvidenceError(f'PC006 firewall rule original is invalid: {exc}') from exc


def _verify_http_header_capture(
    path: Path,
    session_id: str,
    instance_id: str,
) -> None:
    """Require this run's raw response-header capture to carry its identity.

    The HTTP tools/list identity must come from the recorded ``Mcp-Session-Id``
    and ``X-MCP-Server-Instance`` response headers, not from a shell-declared
    ``session_id`` field (P05 §0.3).
    """
    try:
        rows = json.loads(path.read_text(encoding='utf-8-sig'))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError('HTTP header capture is not valid UTF-8 JSON') from exc
    if not isinstance(rows, list) or not rows:
        raise EvidenceError('HTTP header capture does not retain the response exchanges')
    row_keys = {
        'method', 'path', 'status_code', 'mcp_session_id',
        'server_instance_id', 'request_session_id',
    }
    proven = False
    for position, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != row_keys:
            raise EvidenceError(f'HTTP header capture row {position} shape is invalid')
        if (
            row['path'] != '/mcp'
            or type(row['status_code']) is not int
            or not 100 <= row['status_code'] <= 599
            or not isinstance(row['method'], str) or not row['method']
        ):
            raise EvidenceError(f'HTTP header capture row {position} is not a real MCP exchange')
        for field, expected in (
            ('mcp_session_id', session_id),
            ('server_instance_id', instance_id),
            ('request_session_id', session_id),
        ):
            if row[field] is not None and row[field] != expected:
                raise EvidenceError(
                    f'HTTP header capture row {position} contradicts this report identity'
                )
        if (
            row['method'] == 'POST'
            and row['mcp_session_id'] == session_id
            and row['server_instance_id'] == instance_id
        ):
            proven = True
    if not proven:
        raise EvidenceError(
            'HTTP header capture does not prove this report session and service instance; '
            'a declared session_id is not a response header'
        )


def _verify_stdio_capture(
    path: Path,
    expected_normalized: bytes,
) -> list[dict[str, Any]]:
    """Recompute the stdio tools/list from a completed SDK lifecycle.

    The stdio adapter has no HTTP-style ``Mcp-Session-Id``; its identity is the
    captured request/response exchange itself, so a copy of the HTTP listing
    under a new file name cannot stand in for it (P05 §0.3, CHK-028).  The
    lifecycle is causal, not a bag of messages: initialize request, successful
    initialize response, initialized notification, tools/list request, and
    successful tools/list response must occur once in that order.
    """
    try:
        text = path.read_text(encoding='utf-8-sig')
    except (OSError, UnicodeError) as exc:
        raise EvidenceError('stdio capture is not readable UTF-8 text') from exc
    rows: list[dict[str, Any]] = []
    previous_started: datetime | None = None
    for position, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            raise EvidenceError(f'stdio capture line {position} is empty')
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EvidenceError(f'stdio capture line {position} is not a raw SDK message') from exc
        if (
            not isinstance(row, dict)
            or set(row) != {'sequence', 'direction', 'started_at', 'ended_at', 'message'}
            or type(row['sequence']) is not int
            or row['sequence'] != len(rows) + 1
            or row['direction'] not in {'client_to_server', 'server_to_client'}
        ):
            raise EvidenceError(f'stdio capture line {position} is not the passive SDK message format')
        started = _parse_utc(row['started_at'], f'stdio capture line {position} started_at')
        ended = _parse_utc(row['ended_at'], f'stdio capture line {position} ended_at')
        if ended < started or (previous_started is not None and started < previous_started):
            raise EvidenceError('stdio capture message times are not ordered UTC instants')
        previous_started = started
        message = row['message']
        if not isinstance(message, dict) or message.get('jsonrpc') != '2.0':
            raise EvidenceError(f'stdio capture line {position} is not a JSON-RPC 2.0 message')
        rows.append(row)
    if not rows:
        raise EvidenceError('stdio capture retains no protocol messages')
    requests: dict[Any, dict[str, Any]] = {}
    responses: dict[Any, dict[str, Any]] = {}
    initialized_notifications: list[dict[str, Any]] = []
    lifecycle_methods = {'initialize', 'notifications/initialized', 'tools/list'}
    for row in rows:
        message = row['message']
        method = message.get('method')
        if method in lifecycle_methods and row['direction'] != 'client_to_server':
            raise EvidenceError('stdio lifecycle message has the wrong protocol direction')
        if method is not None:
            if not isinstance(method, str) or not method:
                raise EvidenceError('stdio capture JSON-RPC method is invalid')
            if row['direction'] == 'client_to_server' and method == 'notifications/initialized':
                if 'id' in message:
                    raise EvidenceError('stdio initialized message is not a JSON-RPC notification')
                initialized_notifications.append(row)
            if row['direction'] == 'client_to_server' and 'id' in message:
                request_id = message['id']
                if (not isinstance(request_id, (str, int)) or isinstance(request_id, bool)
                        or request_id in requests):
                    raise EvidenceError('stdio capture repeats or has an invalid JSON-RPC request id')
                requests[request_id] = row
        elif row['direction'] == 'server_to_client' and 'id' in message:
            response_id = message['id']
            if (not isinstance(response_id, (str, int)) or isinstance(response_id, bool)
                    or response_id in responses):
                raise EvidenceError('stdio capture repeats or has an invalid JSON-RPC response id')
            responses[response_id] = row
    initialize_ids = [
        request_id for request_id, row in requests.items()
        if row['message'].get('method') == 'initialize'
    ]
    tools_list_ids = [
        request_id for request_id, row in requests.items()
        if row['message'].get('method') == 'tools/list'
    ]
    if (len(initialize_ids) != 1 or len(tools_list_ids) != 1
            or len(initialized_notifications) != 1):
        raise EvidenceError(
            'stdio capture must retain exactly one initialize exchange, initialized notification, '
            'and tools/list exchange'
        )
    initialize_id, tools_list_id = initialize_ids[0], tools_list_ids[0]
    initialize_request = requests[initialize_id]
    initialize_response = responses.get(initialize_id)
    initialized = initialized_notifications[0]
    tools_list_request = requests[tools_list_id]
    tools_list_response = responses.get(tools_list_id)
    if initialize_response is None or tools_list_response is None:
        raise EvidenceError('stdio capture lacks the unique matching response for a real exchange')
    if not (
        initialize_request['sequence'] < initialize_response['sequence']
        < initialized['sequence'] < tools_list_request['sequence']
        < tools_list_response['sequence']
    ):
        raise EvidenceError('stdio initialize/initialized/tools-list lifecycle order is invalid')
    initialize_request_end = _parse_utc(
        initialize_request['ended_at'], 'stdio initialize request ended_at')
    initialize_response_end = _parse_utc(
        initialize_response['ended_at'], 'stdio initialize response ended_at')
    initialized_start = _parse_utc(
        initialized['started_at'], 'stdio initialized notification started_at')
    initialized_end = _parse_utc(
        initialized['ended_at'], 'stdio initialized notification ended_at')
    tools_list_request_start = _parse_utc(
        tools_list_request['started_at'], 'stdio tools/list request started_at')
    tools_list_request_end = _parse_utc(
        tools_list_request['ended_at'], 'stdio tools/list request ended_at')
    tools_list_response_end = _parse_utc(
        tools_list_response['ended_at'], 'stdio tools/list response ended_at')
    if not (
        initialize_request_end <= initialize_response_end <= initialized_start
        <= initialized_end <= tools_list_request_start
        <= tools_list_request_end <= tools_list_response_end
    ):
        raise EvidenceError('stdio lifecycle timestamps contradict its causal order')

    initialize_params = initialize_request['message'].get('params')
    client_info = initialize_params.get('clientInfo') if isinstance(initialize_params, dict) else None
    if (
        not isinstance(initialize_params, dict)
        or not _nonempty_string(initialize_params.get('protocolVersion'), 'stdio initialize protocolVersion')
        or not isinstance(initialize_params.get('capabilities'), dict)
        or not isinstance(client_info, dict)
        or not _nonempty_string(client_info.get('name'), 'stdio initialize client name')
        or not _nonempty_string(client_info.get('version'), 'stdio initialize client version')
    ):
        raise EvidenceError('stdio initialize request lacks required MCP fields')

    initialize_message = initialize_response['message']
    if 'result' not in initialize_message or 'error' in initialize_message:
        raise EvidenceError('stdio initialize did not return one successful result')
    initialize_result = initialize_message['result']
    server_info = initialize_result.get('serverInfo') if isinstance(initialize_result, dict) else None
    if (
        not isinstance(initialize_result, dict)
        or not _nonempty_string(initialize_result.get('protocolVersion'), 'stdio initialize result protocolVersion')
        or not isinstance(initialize_result.get('capabilities'), dict)
        or not isinstance(server_info, dict)
        or not _nonempty_string(server_info.get('name'), 'stdio initialize server name')
        or not isinstance(server_info.get('version'), str)
    ):
        raise EvidenceError('stdio initialize result lacks required MCP fields')

    tools_list_message = tools_list_response['message']
    if 'result' not in tools_list_message or 'error' in tools_list_message:
        raise EvidenceError('stdio tools/list did not return one successful result')
    tools_list_result = tools_list_message['result']
    if not isinstance(tools_list_result, dict) or _normalized_tools_bytes(tools_list_result) != expected_normalized:
        raise EvidenceError('stdio capture tools/list response does not normalize to the HTTP schema')
    return rows


def _verify_stdio_launch(
    path: Path,
    phase: dict[str, Any],
    capture_rows: list[dict[str, Any]],
) -> None:
    """Bind the stdio diagnostic transcript to its recorded transport launch."""
    from tests.p05_ready_evidence import GUEST_COMPUTER_NAME

    document = _read_json(path, 'stdio transport launch')
    document_keys = {
        'schema_version', 'kind', 'workflow_id', 'run_id', 'restore_attempt_id',
        'host', 'request', 'started_at', 'ended_at', 'exit_status', 'response',
    }
    if (
        set(document) != document_keys
        or document.get('schema_version') != 1
        or document.get('kind') != STDIO_LAUNCH_KIND
        or document.get('workflow_id') != WORKFLOW_ID
        or document.get('restore_attempt_id') != phase['restore_attempt_id']
        or not _nonempty_string(document.get('run_id'), 'stdio launch run_id')
    ):
        raise EvidenceError('stdio launch transcript shape or same-round identity is invalid')
    host = document.get('host')
    if (
        not isinstance(host, dict)
        or set(host) != {'scope', 'computer_name'}
        or host.get('scope') != 'guest'
        or host.get('computer_name') != GUEST_COMPUTER_NAME
    ):
        raise EvidenceError('stdio launch transcript is not the approved guest observation')
    request = document.get('request')
    if (
        not isinstance(request, dict) or set(request) != {'argv', 'command_line'}
        or not isinstance(request['argv'], list) or not request['argv']
        or any(not isinstance(item, str) or not item for item in request['argv'])
        or not _nonempty_string(request.get('command_line'), 'stdio launch command_line')
    ):
        raise EvidenceError('stdio launch request is not a complete command')
    argv = request['argv']
    if request['command_line'] != ' '.join(argv):
        raise EvidenceError('stdio launch command_line contradicts its exact argv expression')
    if len(argv) != 2:
        raise EvidenceError(
            'stdio launch does not start the bridge over stdio as the fixed direct script invocation'
        )
    interpreter_path = PureWindowsPath(argv[0])
    bridge_path = PureWindowsPath(argv[1])
    if (
        not interpreter_path.is_absolute()
        or not bridge_path.is_absolute()
        or interpreter_path.name.lower() != 'python.exe'
        or bridge_path.name != 'mcp_velociraptor_bridge.py'
        or interpreter_path != bridge_path.parent / '.venv' / 'Scripts' / 'python.exe'
    ):
        raise EvidenceError(
            'stdio launch must execute the project bridge directly with its repository virtualenv python'
        )
    exit_status = document.get('exit_status')
    if (
        not isinstance(exit_status, dict) or set(exit_status) != {'code'}
        or type(exit_status['code']) is not int or exit_status['code'] != 0
    ):
        raise EvidenceError('stdio launch did not close successfully')
    response = document.get('response')
    response_keys = {
        'stdout', 'stdout_size', 'stdout_sha256',
        'stderr', 'stderr_size', 'stderr_sha256',
    }
    if not isinstance(response, dict) or set(response) != response_keys:
        raise EvidenceError('stdio launch does not retain complete stdout/stderr')
    for stream in ('stdout', 'stderr'):
        text = response[stream]
        if not isinstance(text, str):
            raise EvidenceError(f'stdio launch {stream} is not text')
        raw = text.encode('utf-8')
        if (
            type(response[f'{stream}_size']) is not int
            or response[f'{stream}_size'] != len(raw)
            or response[f'{stream}_sha256'] != hashlib.sha256(raw).hexdigest()
        ):
            raise EvidenceError(f'stdio launch {stream} bytes differ from their identity')
    started = _parse_utc(document.get('started_at'), 'stdio launch started_at')
    ended = _parse_utc(document.get('ended_at'), 'stdio launch ended_at')
    if ended < started:
        raise EvidenceError('stdio launch ends before it starts')
    first = _parse_utc(capture_rows[0]['started_at'], 'stdio capture first message')
    last = _parse_utc(capture_rows[-1]['ended_at'], 'stdio capture last message')
    if not (started <= first and last <= ended):
        raise EvidenceError('stdio capture messages are not inside the recorded transport launch')


def _verify_schema_identity_originals(
    bundle_root: Path,
    phase: dict[str, Any],
    report: dict[str, Any],
    reference: Any,
    seen: dict[str, tuple[int, str]],
) -> None:
    """Require both HTTP and stdio tools/list originals and equal schemas.

    A single ``tools-schema.json`` digest cannot prove dual-adapter identity
    (CHK-028): the HTTP listing must be this run's own ``tools-list.json``
    joined to the raw response-header capture, and the stdio listing must be
    recomputed from the passive SDK protocol transcript of a recorded bridge
    launch.  A copy of the HTTP list under another path, or an invented
    HTTP-style stdio session id, is rejected (B05).
    """
    path = _resolve_ref(bundle_root, reference, 'network_evidence.schema_identity', seen)
    document = _read_json(path, 'schema identity')
    if (
        set(document) != SCHEMA_IDENTITY_KEYS
        or document.get('schema_version') != 1
        or document.get('kind') != SCHEMA_IDENTITY_KIND
        or document.get('workflow_id') != WORKFLOW_ID
        or document.get('run_id') != phase['run_id']
        or document.get('restore_attempt_id') != phase['restore_attempt_id']
    ):
        raise EvidenceError('schema identity document shape or phase identity is invalid')
    session = report.get('mcp_session')
    server = report.get('server_identity')
    if (
        not isinstance(session, dict) or not _nonempty_string(session.get('id'), 'report mcp_session.id')
        or not isinstance(server, dict)
        or not _nonempty_string(server.get('instance_id'), 'report server_identity.instance_id')
    ):
        raise EvidenceError('schema identity requires the report session and service identity')
    report_reference = phase.get('report')
    if not isinstance(report_reference, dict) or set(report_reference) != REF_KEYS or '/' not in report_reference['path']:
        raise EvidenceError('schema identity requires the phase report from its run directory')
    report_parent = report_reference['path'].rsplit('/', 1)[0]
    http = document.get('http')
    if not isinstance(http, dict) or set(http) != {'transport', 'headers', 'tools_list'} or http.get('transport') != 'http':
        raise EvidenceError('schema identity http adapter shape is invalid')
    if (
        not isinstance(http['tools_list'], dict) or set(http['tools_list']) != REF_KEYS
        or not isinstance(http['headers'], dict) or set(http['headers']) != REF_KEYS
    ):
        raise EvidenceError('schema identity http adapter Ref shape is invalid')
    if http['tools_list']['path'] != f'{report_parent}/tools-list.json':
        raise EvidenceError("HTTP tools/list original is not this run's own tools-list.json")
    if http['headers']['path'] != f'{report_parent}/http-headers.json':
        raise EvidenceError("HTTP identity is not bound to this run's response-header capture")
    tools_path = _resolve_ref(
        bundle_root, http['tools_list'], 'network_evidence.schema_identity.http.tools_list', seen)
    headers_path = _resolve_ref(
        bundle_root, http['headers'], 'network_evidence.schema_identity.http.headers', seen)
    listing = _read_json(tools_path, 'HTTP tools/list original')
    normalized = _normalized_tools_bytes(listing)
    tools_hash = report.get('tools_schema_sha256')
    if (
        not _sha256_is_valid(tools_hash)
        or hashlib.sha256(normalized).hexdigest() != tools_hash
    ):
        raise EvidenceError("dual-adapter schema does not equal this report's tools_schema_sha256")
    _verify_http_header_capture(headers_path, session['id'], server['instance_id'])
    stdio = document.get('stdio')
    if (
        not isinstance(stdio, dict) or set(stdio) != {'transport', 'launch', 'capture'}
        or stdio.get('transport') != 'stdio'
    ):
        raise EvidenceError(
            'schema identity stdio adapter shape is invalid: a captured protocol transcript and '
            'its transport launch are required, and an invented HTTP-style session identity is not accepted'
        )
    capture_path = _resolve_ref(
        bundle_root, stdio['capture'], 'network_evidence.schema_identity.stdio.capture', seen)
    launch_path = _resolve_ref(
        bundle_root, stdio['launch'], 'network_evidence.schema_identity.stdio.launch', seen)
    if len({path for path in (str(tools_path), str(headers_path), str(capture_path), str(launch_path))}) != 4:
        raise EvidenceError('HTTP and stdio schema originals must be distinct carried files')
    capture_rows = _verify_stdio_capture(capture_path, normalized)
    _verify_stdio_launch(launch_path, phase, capture_rows)


def _verify_network_evidence(
    bundle_root: Path,
    phase: dict[str, Any],
    seen: dict[str, tuple[int, str]],
) -> None:
    """Recompute the three network predicates from carried originals."""
    document = _read_json(
        _resolve_ref(bundle_root, phase['network_evidence'], 'phase.network_evidence', seen),
        'network evidence',
    )
    expected = {
        'schema_version', 'workflow_id', 'run_id', 'restore_attempt_id',
        'non_allowed_source', 'schema_identity', 'service_observation',
    }
    if (
        set(document) != expected
        or document.get('schema_version') != 1
        or document.get('workflow_id') != WORKFLOW_ID
        or document.get('run_id') != phase['run_id']
        or document.get('restore_attempt_id') != phase['restore_attempt_id']
    ):
        raise EvidenceError('network evidence shape or phase identity is invalid')
    report_reference = phase.get('report')
    if not isinstance(report_reference, dict) or set(report_reference) != REF_KEYS:
        raise EvidenceError('network originals require the phase report Ref join')
    report = _read_json(
        _resolve_ref(bundle_root, report_reference, 'phase.report', seen),
        'network service report join',
    )
    _verify_pc006_boundary(bundle_root, phase, report, document['non_allowed_source'], seen)
    _verify_schema_identity_originals(bundle_root, phase, report, document['schema_identity'], seen)
    observation_path = _resolve_ref(
        bundle_root, document['service_observation'],
        'network_evidence.service_observation', seen,
    )
    observation = _read_json(observation_path, 'network service observation')
    if any(
        observation.get(key) != value
        for key, value in report['server_identity'].items()
    ):
        raise EvidenceError('network service observation does not join the report identity')
    if not observation.get('observed_at'):
        raise EvidenceError('network service observation lacks collection time')


def _verify_package_manifest(
    bundle_root: Path,
    phase: dict[str, Any],
    seen: dict[str, tuple[int, str]],
) -> None:
    path = _resolve_ref(bundle_root, phase['package_manifest'], 'phase.package_manifest', seen)
    document = _read_json(path, 'phase package manifest')
    if set(document) != {'schema_version', 'members'} or document.get('schema_version') != 1:
        raise EvidenceError('phase package manifest root is invalid')
    members = document.get('members')
    if not isinstance(members, list) or not members:
        raise EvidenceError('phase package manifest members are invalid')
    member_paths: list[str] = []
    for member in members:
        member_path = _resolve_ref(bundle_root, member, 'phase package member', seen)
        relative = member['path']
        if relative == phase['package_manifest']['path']:
            raise EvidenceError('phase package manifest must exclude itself')
        member_paths.append(relative)
        if member_path.is_symlink():
            raise EvidenceError('phase package member cannot be a link')
    if member_paths != sorted(member_paths, key=lambda value: value.encode('utf-8')):
        raise EvidenceError('phase package manifest members are not canonically ordered')
    direct_files = {
        phase[name]['path']
        for name in PHASE_KEYS - {'restore_attempt_id', 'run_id', 'package_manifest'}
    }
    if not direct_files.issubset(set(member_paths)):
        raise EvidenceError('phase package manifest omits a direct phase original')


def verify_activation_bundle(
    activation_path: Path,
    *,
    require_p05_layout: bool = False,
    expected_baseline: tuple[str, str] | None = None,
    forbidden_identity: tuple[str, str] | None = None,
) -> dict[str, Any]:
    """Validate a Snapshot188 activation bundle without trusting a passed summary.

    References are always rooted at ``activation_path.parent``. P06 may copy
    that entire directory byte-for-byte under its own restore package, while
    P05's original report-relative restore records are resolved only below the
    bundle's ``p05-originals`` directory.  When P06 supplies
    ``expected_baseline``, every P05 phase must retain that same immutable
    adoption path and byte identity. ``forbidden_identity`` prevents a P06
    restore attempt/run pair from being replayed as one of the P05 phases.
    """
    if not activation_path.is_absolute() or activation_path.is_symlink():
        raise EvidenceError('activation evidence must be an absolute plain file')
    bundle_root = activation_path.parent
    try:
        bundle_info = bundle_root.lstat()
        activation_info = activation_path.lstat()
    except OSError as exc:
        raise EvidenceError('activation evidence is unavailable') from exc
    if (
        not stat.S_ISDIR(bundle_info.st_mode)
        or stat.S_ISLNK(bundle_info.st_mode)
        or getattr(bundle_info, 'st_file_attributes', 0) & 0x400
        or not stat.S_ISREG(activation_info.st_mode)
    ):
        raise EvidenceError('activation evidence must be in a plain directory')
    if require_p05_layout:
        if bundle_root.parent.name != 'activation-188':
            raise EvidenceError('activation evidence is outside the fixed activation-188 root')
        try:
            uuid.UUID(bundle_root.name)
        except (ValueError, AttributeError) as exc:
            raise EvidenceError('activation bundle directory is not a UUID') from exc
    document = _read_json(activation_path, 'activation evidence')
    if set(document) != ACTIVATION_KEYS:
        raise EvidenceError('activation evidence root keys are invalid')
    if (
        document.get('schema_version') != 1
        or document.get('kind') != 'snapshot188-activation-evidence-v1'
        or document.get('workflow_id') != WORKFLOW_ID
        or document.get('candidate') != SNAPSHOT_188
    ):
        raise EvidenceError('activation evidence identity is invalid')
    marker = _nonempty_string(document.get('checkpoint_marker'), 'activation marker')
    if not marker.endswith('.vmsn') or '/' in marker or '\\' in marker:
        raise EvidenceError('activation marker is invalid')
    seen: dict[str, tuple[int, str]] = {}
    _verify_creation_metadata(bundle_root, document['creation_metadata'], marker, seen)
    source_copies = _verify_source_list(
        bundle_root, document['source_inputs'], SOURCE_INPUT_ALLOWLIST, 'source_inputs', seen
    )
    _verify_source_list(
        bundle_root,
        document['implementation_sources'],
        IMPLEMENTATION_SOURCE_ALLOWLIST,
        'implementation_sources',
        seen,
    )
    initial_restore, baseline_identity = _verify_phase(
        bundle_root,
        document['initial'],
        'p05-flow-triage-repair-initial',
        'P05_REPAIR_INITIAL',
        SNAPSHOT_187,
        seen,
        source_copies,
    )
    if expected_baseline is not None:
        if (
            not isinstance(expected_baseline, tuple)
            or len(expected_baseline) != 2
            or baseline_identity[:2] != expected_baseline
        ):
            raise EvidenceError('activation does not retain the P06 baseline adoption identity')
    cycles = document['candidate_cycles']
    if not isinstance(cycles, list) or len(cycles) != 2:
        raise EvidenceError('activation requires exactly two candidate cycles')
    attempt_ids: set[str] = set()
    run_ids: set[str] = set()
    cycle_restores: list[dict[str, Any]] = []
    for cycle in cycles:
        restore, cycle_baseline = _verify_phase(
            bundle_root,
            cycle,
            'p05-flow-triage-repair-candidate',
            'P05_REPAIR_CANDIDATE',
            SNAPSHOT_188,
            seen,
            source_copies,
        )
        if restore['checkpoint_marker'] != marker:
            raise EvidenceError('candidate restore marker differs from creation metadata')
        if cycle_baseline != baseline_identity:
            raise EvidenceError('candidate cycle does not retain the immutable baseline adoption')
        if cycle['restore_attempt_id'] in attempt_ids or cycle['run_id'] in run_ids:
            raise EvidenceError('candidate cycles reuse restore_attempt_id or run_id')
        attempt_ids.add(cycle['restore_attempt_id'])
        run_ids.add(cycle['run_id'])
        cycle_restores.append(restore)
    if document['initial']['restore_attempt_id'] in attempt_ids or document['initial']['run_id'] in run_ids:
        raise EvidenceError('initial phase reuses a candidate identity')
    if forbidden_identity is not None:
        if (
            not isinstance(forbidden_identity, tuple)
            or len(forbidden_identity) != 2
            or forbidden_identity[0] in attempt_ids | {document['initial']['restore_attempt_id']}
            or forbidden_identity[1] in run_ids | {document['initial']['run_id']}
        ):
            raise EvidenceError('P06 restore identity is reused by an activation phase')
    for phase, phase_restore in zip(
        [document['initial'], *cycles], [initial_restore, *cycle_restores], strict=True
    ):
        _verify_ready(bundle_root, phase, seen, expected_restore=phase_restore)
        _verify_dependency_acceptance(bundle_root, phase, seen)
        _verify_entry_gate(bundle_root, phase, seen)
        _verify_network_evidence(bundle_root, phase, seen)
        _verify_package_manifest(bundle_root, phase, seen)
    _verify_creation_binding(bundle_root, document, initial_restore, seen)
    return {
        'workflow_id': document['workflow_id'],
        'candidate': document['candidate'],
        'checkpoint_marker': marker,
        'initial_run_id': document['initial']['run_id'],
        'cycle_run_ids': [cycle['run_id'] for cycle in cycles],
    }


def _verify_active_canonical(
    canonical: dict[str, Any],
    restore: dict[str, Any],
    records: dict[str, dict[str, Any]],
    paths: dict[str, Path],
) -> None:
    if set(canonical) != CANONICAL_KEYS:
        raise EvidenceError('active canonical root keys are invalid')
    if (
        canonical.get('schema_version') != 5
        or canonical.get('epoch') != 6
        or canonical.get('phase') != 'NETWORK_ACTIVE'
        or canonical.get('workflow_id') != WORKFLOW_ID
    ):
        raise EvidenceError('formal P06 restore is not schema5/epoch6 NETWORK_ACTIVE')
    active = canonical.get('active_snapshot')
    if not isinstance(active, dict) or set(active) != SNAPSHOT_KEYS:
        raise EvidenceError('active canonical snapshot shape is invalid')
    if (
        active.get('name') != SNAPSHOT_188
        or active.get('checkpoint_marker') != restore.get('checkpoint_marker')
        or not isinstance(active.get('purpose'), str)
        or not active['purpose']
        or canonical.get('automatic_restore_allowlist') != [SNAPSHOT_188]
    ):
        raise EvidenceError('active canonical does not bind Snapshot188 uniquely')
    _valid_marker(active.get('checkpoint_marker'), 'active canonical marker')
    retired = canonical.get('retired_snapshots')
    expected_retired = [SNAPSHOT_183, SNAPSHOT_184, SNAPSHOT_1, SNAPSHOT_186, SNAPSHOT_187]
    if (
        not isinstance(retired, list)
        or [item.get('name') if isinstance(item, dict) else None for item in retired]
        != expected_retired
        or any(
            not isinstance(item, dict) or set(item) != RETIRED_KEYS
            or item.get('status') != MANUAL_ONLY
            for item in retired
        )
    ):
        raise EvidenceError('active canonical retired snapshots differ')
    _verify_evidence_reference(
        canonical.get('baseline_evidence'),
        BASELINE_EVIDENCE_KEYS,
        records['baseline_adoption'],
        'active canonical baseline evidence',
    )
    _verify_evidence_reference(
        canonical.get('activation_evidence'),
        ACTIVATION_EVIDENCE_KEYS,
        records['activation_evidence'],
        'active canonical activation evidence',
    )
    _verify_baseline_adoption(paths['baseline_adoption'])


def _verify_restore_raw_records(
    restore: dict[str, Any],
    paths: dict[str, Path],
) -> None:
    """Parse the four P06 restore originals as actual command transcripts.

    Substring presence proves nothing (CHK-034): an original that merely
    contains the attempt/snapshot/marker/hostname strings — or explicitly says
    NOT EXECUTED — is rejected unless it is the attempt-bound envelope whose
    parsed facts equal the declared restore.
    """
    attempt = _nonempty_string(restore.get('restore_attempt_id'), 'restore attempt id')
    _nonempty_string(restore.get('snapshot_name'), 'restore snapshot name')
    _valid_marker(restore.get('checkpoint_marker'), 'formal restore marker')
    _verify_restore_action_originals(
        attempt, restore['snapshot_name'], restore['checkpoint_marker'], paths
    )


def verify_restore(restore: dict, root: Path) -> dict[str, Path]:
    """Validate only an activated schema5 Snapshot188 P06 restore record.

    Every record is resolved relative to ``root`` and must be an in-package,
    ordinary file.  In particular, evidence_path fields only bind those carried
    relative originals: they never authorise a fallback read from a P05 host
    path or a repository path named in a copied JSON document.
    """
    if not isinstance(restore, dict) or set(restore) != RESTORE_KEYS:
        raise EvidenceError('formal restore root keys are invalid')
    if (
        restore.get('workflow_id') != WORKFLOW_ID
        or restore.get('snapshot_stage') != 'P06_ACTIVE'
        or restore.get('snapshot_name') != SNAPSHOT_188
        or restore.get('canonical_schema_version') != 5
        or restore.get('canonical_epoch') != 6
        or restore.get('canonical_phase') != 'NETWORK_ACTIVE'
        or not _sha256_is_valid(restore.get('canonical_sha256'))
    ):
        raise EvidenceError('formal P06 restore is not the activated schema5 Snapshot188 state')
    _valid_marker(restore.get('checkpoint_marker'), 'formal restore marker')
    _nonempty_string(restore.get('run_id'), 'formal restore run id')
    records = restore.get('restore_records')
    if not isinstance(records, list) or len(records) != len(RESTORE_KINDS):
        raise EvidenceError('formal restore must contain all seven original record kinds')
    by_kind: dict[str, Path] = {}
    declared_records: dict[str, dict[str, Any]] = {}
    record_paths: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {'kind', 'path', 'sha256'}:
            raise EvidenceError('formal restore record shape is invalid')
        kind = record.get('kind')
        relative = record.get('path')
        checksum = record.get('sha256')
        if kind not in RESTORE_KINDS or kind in by_kind or relative in record_paths:
            raise EvidenceError('formal restore record is unknown or duplicated')
        if not isinstance(relative, str) or not _sha256_is_valid(checksum):
            raise EvidenceError('formal restore record identity is invalid')
        path = plain_file(root, relative)
        if digest(path) != checksum:
            raise EvidenceError(f'formal restore bytes differ: {kind}')
        by_kind[kind] = path
        declared_records[kind] = record
        record_paths.add(relative)
    if set(by_kind) != RESTORE_KINDS:
        raise EvidenceError('formal restore lacks all seven original record kinds')
    canonical_path = by_kind['canonical_readback']
    if digest(canonical_path) != restore['canonical_sha256']:
        raise EvidenceError('canonical SHA does not match original canonical bytes')
    canonical = _read_json(canonical_path, 'formal canonical')
    for source, target in (
        ('schema_version', 'canonical_schema_version'),
        ('epoch', 'canonical_epoch'),
        ('phase', 'canonical_phase'),
        ('workflow_id', 'workflow_id'),
    ):
        if canonical.get(source) != restore.get(target):
            raise EvidenceError(f'canonical identity differs: {source}')
    _verify_active_canonical(canonical, restore, declared_records, by_kind)
    _verify_restore_raw_records(restore, by_kind)
    verify_activation_bundle(
        by_kind['activation_evidence'],
        require_p05_layout=True,
        expected_baseline=(
            canonical['baseline_evidence']['evidence_path'],
            canonical['baseline_evidence']['evidence_sha256'],
        ),
        forbidden_identity=(restore['restore_attempt_id'], restore['run_id']),
    )
    return by_kind


def verify_observation(report: dict, run_dir: Path) -> None:
    path = plain_file(run_dir, 'server-observation.json')
    if digest(path) != report.get('server_observation_sha256'):
        raise EvidenceError('server observation bytes differ')
    observation = json.loads(path.read_text(encoding='utf-8-sig'))
    if any(observation.get(k) != v for k, v in report['server_identity'].items()):
        raise EvidenceError('server observation does not join report identity')
    if not observation.get('observed_at'):
        raise EvidenceError('server observation lacks collection time')
