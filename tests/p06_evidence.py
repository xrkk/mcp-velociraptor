"""Byte and semantic validation shared by formal P06 producers and consumers."""

from __future__ import annotations

import hashlib
import json
import stat
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
    for kind in PHASE_RESTORE_KINDS - {'canonical_readback', 'baseline_adoption'}:
        raw = by_kind[kind].read_text(encoding='utf-8-sig')
        if phase['restore_attempt_id'] not in raw:
            raise EvidenceError(f'phase original record is not attempt-bound: {kind}')
    if expected_snapshot not in by_kind['snapshot_metadata'].read_text(encoding='utf-8-sig'):
        raise EvidenceError('phase snapshot metadata does not identify the selected snapshot')
    if marker not in by_kind['pre_start_marker'].read_text(encoding='utf-8-sig'):
        raise EvidenceError('phase pre-start marker differs')
    if 'DESKTOP-3FI41GR' not in by_kind['post_restore_hostname'].read_text(encoding='utf-8-sig'):
        raise EvidenceError('phase restored hostname differs')
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
    if not isinstance(listing.get('tools'), list):
        raise EvidenceError('phase tools/list does not contain tools')
    normalized_tools = []
    for tool in listing['tools']:
        if not isinstance(tool, dict) or not isinstance(tool.get('name'), str) or 'inputSchema' not in tool:
            raise EvidenceError('phase tools/list lacks name or inputSchema')
        normalized_tools.append({
            'name': tool['name'],
            'inputSchema': tool['inputSchema'],
            'outputSchema': tool.get('outputSchema'),
        })
    normalized_tools.sort(key=lambda item: item['name'])
    if len(normalized_tools) != 130 or len({item['name'] for item in normalized_tools}) != 130:
        raise EvidenceError('phase tools/list does not contain 130 unique tools')
    if not {step['tool'] for step in scenario['steps']}.issubset({item['name'] for item in normalized_tools}):
        raise EvidenceError('phase tools/list omits a tool required by the frozen P05 scenario')
    normalized_bytes = (
        json.dumps(normalized_tools, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
        + '\n'
    ).encode('utf-8')
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
) -> None:
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
    for key in ('inventory_artifacts', 'four_chains', 'network_observations'):
        _resolve_ref(bundle_root, document[key], f'dependency_acceptance.{key}', seen)


def _verify_entry_gate(
    bundle_root: Path,
    phase: dict[str, Any],
    seen: dict[str, tuple[int, str]],
) -> None:
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


def _verify_network_evidence(
    bundle_root: Path,
    phase: dict[str, Any],
    seen: dict[str, tuple[int, str]],
) -> None:
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
    for key in ('non_allowed_source', 'schema_identity', 'service_observation'):
        _resolve_ref(bundle_root, document[key], f'network_evidence.{key}', seen)


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
    for phase in [document['initial'], *cycles]:
        _verify_ready(bundle_root, phase, seen)
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
    attempt = _nonempty_string(restore.get('restore_attempt_id'), 'restore attempt id')
    for kind in {'snapshot_metadata', 'revert_operation', 'pre_start_marker', 'post_restore_hostname'}:
        try:
            raw = paths[kind].read_text(encoding='utf-8-sig')
        except (OSError, UnicodeError) as exc:
            raise EvidenceError(f'original restore record is not readable: {kind}') from exc
        if attempt not in raw:
            raise EvidenceError(f'original record is not bound to this restore attempt: {kind}')
    if restore['snapshot_name'] not in paths['snapshot_metadata'].read_text(encoding='utf-8-sig'):
        raise EvidenceError('snapshot metadata does not identify the selected snapshot')
    if restore['checkpoint_marker'] not in paths['pre_start_marker'].read_text(encoding='utf-8-sig'):
        raise EvidenceError('original pre-start marker differs')
    if 'DESKTOP-3FI41GR' not in paths['post_restore_hostname'].read_text(encoding='utf-8-sig'):
        raise EvidenceError('original restored hostname differs')


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
