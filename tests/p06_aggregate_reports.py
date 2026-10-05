"""Strictly aggregate the five selected P06 reports without executing tools.

Consumes schema2 reports produced by the shared scenario runner on the
formal Streamable HTTP transport.  Every identity check required by P05 0.3
and 0.5 (tools-schema binding, snapshot evidence, server observation join,
session identity) is recomputed from the run directories; schema1 reports
and stdio diagnostics are rejected as formal evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any

try:
    from .p06_evidence import EvidenceError, verify_historical_restore as verify_restore, verify_observation
except ImportError:
    from p06_evidence import EvidenceError, verify_historical_restore as verify_restore, verify_observation


ROOT = Path(__file__).resolve().parents[1]
if not __package__:
    # Preserve the historical direct-script entry point for lazy verifiers.
    sys.path.insert(0, str(ROOT))
EVIDENCE_ROOT = ROOT / "Logs" / "P06" / "wf-01a05d1d-p06-r3"
LEDGER = EVIDENCE_ROOT / "接收清单.jsonl"
SELECTION = EVIDENCE_ROOT / "final-selection.json"
MANIFEST = ROOT / "tests" / "data" / "p06_coverage_manifest.json"
OUTPUT = EVIDENCE_ROOT / "aggregate.json"

SNAPSHOT_188 = "Snapshot 188-Velociraptor-MCP可恢复验收基线"
ENDPOINT_PATTERN = re.compile(r"^http://(\d{1,3}(?:\.\d{1,3}){3}):28790/mcp$")
REPORT_KEYS = {
    "schema_version",
    "scenario",
    "source_sha256",
    "index_sha256",
    "fixture_spec_sha256",
    "fixture_instance_sha256",
    "run_id",
    "transport",
    "endpoint",
    "authorization_configured",
    "tools_schema_sha256",
    "snapshot_evidence_sha256",
    "mcp_session",
    "server_identity",
    "server_observation_sha256",
    "runner",
    "started_at",
    "ended_at",
    "duration_ms",
    "status",
    "calls",
    "steps",
    "cleanup",
    "failure",
    "unexecuted_step_ids",
    "coverage",
}
# PLAN-CHANGE-025 schema3: the adopted .232 baseline binding replaces the
# Snapshot-189 evidence; every other schema2 field keeps its exact contract.
SCHEMA3_REPORT_KEYS = (REPORT_KEYS - {"snapshot_evidence_sha256"}) | {"baseline_binding"}
BASELINE_BINDING_SCHEMA = "velo.p06.baseline-binding.v1"
LEDGER_IDENTITY_FIELDS = (
    "source_sha256",
    "index_sha256",
    "fixture_instance_sha256",
    "fixture_spec_sha256",
    "tools_schema_sha256",
)


class AggregateError(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def contained_plain_file(root: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise AggregateError("report path must be relative and contained")
    path = root / candidate
    if not path.is_file() or path.is_symlink():
        raise AggregateError("report must be a plain file")
    resolved_root = root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise AggregateError("report escapes evidence root") from exc
    return resolved


LEDGER_STATUSES = {"success", "failed", "superseded"}


def ledger_identity(report: dict[str, Any]) -> dict[str, Any]:
    server = report.get('server_identity') or {}
    runner = report.get('runner') or {}
    session = report.get('mcp_session') or {}
    return {
        **{field: report.get(field) for field in LEDGER_IDENTITY_FIELDS},
        'snapshot_evidence_sha256': report.get('snapshot_evidence_sha256'),
        'baseline_binding_sha256': (report.get('baseline_binding') or {}).get('observation_sha256'),
        'server_instance_id': server.get('instance_id'),
        'server_pid': server.get('pid'),
        'server_process_start_time_utc': server.get('process_start_time_utc'),
        'server_observation_sha256': report.get('server_observation_sha256'),
        'runner_pid': runner.get('pid'),
        'mcp_session_id': session.get('id'),
        'mcp_session_lifecycle': session,
    }


def package_hash(run_dir: Path, evidence_root: Path | None = None) -> str:
    """Compute the reviewed canonical manifest identity without writing it."""
    from tests.p06_package import member_inventory
    try:
        return sha256_bytes(canonical_bytes(member_inventory(run_dir,evidence_root or run_dir)))
    except (EvidenceError, OSError, KeyError, TypeError) as exc:
        raise AggregateError(f'original package evidence validation failed: {exc}') from exc


def load_ledger(path: Path = LEDGER, evidence_root: Path | None = None) -> list[dict[str, Any]]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    attempts = [row.get("monotonic_attempt") for row in rows]
    if attempts != list(range(1, len(rows) + 1)):
        raise AggregateError("ledger attempt numbers are not continuous and monotonic")
    paths = [row.get("report_relative_path") for row in rows]
    report_hashes = [row.get("report_sha256") for row in rows]
    package_hashes = [row.get("package_sha256") for row in rows]
    if len(paths) != len(set(paths)) or len(report_hashes) != len(set(report_hashes)):
        raise AggregateError("ledger contains duplicate report identity")
    if len(package_hashes) != len(set(package_hashes)):
        raise AggregateError("ledger contains duplicate evidence package")
    root = evidence_root or path.parent
    for row in rows:
        if row.get("status") not in LEDGER_STATUSES:
            raise AggregateError(
                f"ledger attempt {row.get('monotonic_attempt')} lacks a valid status"
            )
        report_path = contained_plain_file(root, row["report_relative_path"])
        if sha256_file(report_path) != row["report_sha256"]:
            raise AggregateError(
                f"ledger attempt {row['monotonic_attempt']} report bytes differ"
            )
        if package_hash(report_path.parent, root) != row["package_sha256"]:
            raise AggregateError(
                f"ledger attempt {row['monotonic_attempt']} package bytes differ"
            )
        from tests.p06_package import verify_manifest
        expected_path = (report_path.parent/'package-manifest.json').relative_to(root).as_posix()
        try:
            actual_manifest_sha = verify_manifest(report_path.parent, root)
        except (EvidenceError, OSError, KeyError, TypeError) as exc:
            raise AggregateError(f'original package manifest validation failed: {exc}') from exc
        if (row.get('manifest_relative_path')!=expected_path
                or row.get('manifest_sha256')!=row['package_sha256']
                or actual_manifest_sha!=row['manifest_sha256']):
            raise AggregateError('ledger package manifest identity differs')
        report = json.loads(report_path.read_bytes())
        if row['status']!=report['status'] or row['scenario']!=report['scenario']:
            raise AggregateError('ledger status or scenario differs from original report')
        if any(row.get(key)!=value or key not in row for key,value in ledger_identity(report).items()):
            raise AggregateError('ledger metadata differs from original report')
        if not row.get('received_at'):
            raise AggregateError('ledger lacks receipt timestamp')
    return rows


def verify_tools_schema_binding(report: dict[str, Any], run_dir: Path, *, current=False) -> None:
    """tools-schema.json bytes, recomputed hash, and report hash must agree."""
    tools_path = run_dir / "tools-schema.json"
    if not tools_path.is_file() or tools_path.is_symlink():
        raise AggregateError("run directory lacks tools-schema.json")
    raw = tools_path.read_bytes()
    if sha256_bytes(raw) != report["tools_schema_sha256"]:
        raise AggregateError("tools-schema.json bytes differ from the report hash")
    document = json.loads(raw.decode("utf-8"))
    recomputed = sha256_bytes(canonical_bytes(document))
    if recomputed != report["tools_schema_sha256"]:
        raise AggregateError("tools-schema canonical recomputation differs")
    count = 137 if current else 130
    if len(document) != count:
        raise AggregateError("tools-schema inventory does not contain 130 tools")
    listing = json.loads(contained_plain_file(run_dir,'tools-list.json').read_bytes())
    actual = sorted(({'name':row['name'],'inputSchema':row['inputSchema'],
                      'outputSchema':row.get('outputSchema')} for row in listing['tools']),key=lambda row:row['name'])
    if actual!=document or len({row['name'] for row in actual})!=count:
        raise AggregateError('tools-schema differs from original tools/list')
    if current:
        from velo_transfer.mcp_tools import TRANSFER_TOOL_NAMES
        if {row['name'] for row in actual if row['name'].startswith('transfer_')} != set(TRANSFER_TOOL_NAMES):
            raise AggregateError('current tools/list lacks the exact seven transfer tools')


def verify_snapshot_evidence(report: dict[str, Any], run_dir: Path,
                             evidence_root: Path | None = None) -> dict[str, Any]:
    """Recompute snapshot-evidence.json and enforce the P06_ACTIVE restore."""
    evidence_path = run_dir / "snapshot-evidence.json"
    if not evidence_path.is_file() or evidence_path.is_symlink():
        raise AggregateError("run directory lacks snapshot-evidence.json")
    raw = evidence_path.read_bytes()
    if sha256_bytes(raw) != report["snapshot_evidence_sha256"]:
        raise AggregateError("snapshot-evidence.json bytes differ from the report hash")
    evidence = json.loads(raw.decode("utf-8"))
    if set(evidence) != {
        "restore",
        "scenario_id",
        "source_sha256",
        "index_sha256",
        "mcp_session_id",
        "server_instance_id",
        "server_observation_sha256",
    }:
        raise AggregateError("snapshot evidence keys are invalid")
    restore = evidence["restore"]
    if evidence["scenario_id"] != report["scenario"]:
        raise AggregateError("snapshot evidence scenario differs")
    if evidence["source_sha256"] != report["source_sha256"]:
        raise AggregateError("snapshot evidence source hash differs")
    if evidence["index_sha256"] != report["index_sha256"]:
        raise AggregateError("snapshot evidence index hash differs")
    if evidence["mcp_session_id"] != report["mcp_session"]["id"]:
        raise AggregateError("snapshot evidence session id differs")
    if evidence["server_instance_id"] != report["server_identity"]["instance_id"]:
        raise AggregateError("snapshot evidence instance id differs")
    if evidence["server_observation_sha256"] != report["server_observation_sha256"]:
        raise AggregateError("snapshot evidence observation hash differs")
    if restore.get("run_id") != report["run_id"]:
        raise AggregateError("snapshot evidence is bound to another run id")
    if restore.get("snapshot_stage") != "P06_ACTIVE" or restore.get("snapshot_name") != SNAPSHOT_188:
        raise AggregateError("formal P06 report is not bound to the activated Snapshot188 baseline")
    if (
        restore.get("canonical_schema_version") != 5
        or restore.get("canonical_epoch") != 6
        or restore.get("canonical_phase") != "NETWORK_ACTIVE"
    ):
        raise AggregateError("restore does not reference the activated schema5 state")
    try:
        verify_restore(restore, evidence_root or run_dir)
        verify_observation(report, run_dir)
    except (EvidenceError, OSError, ValueError, KeyError, TypeError) as exc:
        raise AggregateError(f'original evidence validation failed: {exc}') from exc
    return restore


def verify_baseline_evidence(report: dict[str, Any], run_dir: Path) -> dict[str, Any]:
    """Recompute baseline-binding.json for a schema3 run and cross-check it."""
    from tests import scenario_runner
    if Path(run_dir).is_relative_to(scenario_runner.P06_REPORT_ROOT):
        raise AggregateError('historical baseline cannot consume current report root')
    binding_path = run_dir / "baseline-binding.json"
    if not binding_path.is_file() or binding_path.is_symlink():
        raise AggregateError("run directory lacks baseline-binding.json")
    raw = binding_path.read_bytes()
    binding = report["baseline_binding"]
    if sha256_bytes(raw) != binding["observation_sha256"]:
        raise AggregateError("baseline-binding.json bytes differ from the report hash")
    document = json.loads(raw.decode("utf-8"))
    expected = {key: value for key, value in binding.items() if key != "observation_sha256"}
    if document != expected:
        raise AggregateError("baseline-binding.json content differs from the report binding")
    try:
        verify_observation(report, run_dir)
    except (EvidenceError, OSError, ValueError, KeyError, TypeError) as exc:
        raise AggregateError(f'original observation validation failed: {exc}') from exc
    return document


def verify_baseline_binding(report: dict[str, Any]) -> None:
    """Validate the schema3 baseline binding and its report cross-links."""
    binding = report.get("baseline_binding")
    if not isinstance(binding, dict):
        raise AggregateError("schema3 report lacks a baseline binding object")
    expected = {"schema", "produced_at", "computer_name", "vm_uuid", "mac", "host_only_ip",
                "policy_sha256", "deployed_tree", "observation_sha256"}
    if set(binding) != expected or binding["schema"] != BASELINE_BINDING_SCHEMA:
        raise AggregateError("baseline binding keys or schema are invalid")
    import re as _re
    if not _re.fullmatch(r"[0-9a-f]{64}", str(binding["observation_sha256"])):
        raise AggregateError("baseline binding observation hash is malformed")
    if not _re.fullmatch(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", str(binding["vm_uuid"])):
        raise AggregateError("baseline binding vm_uuid is malformed")
    if not _re.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", str(binding["mac"])):
        raise AggregateError("baseline binding mac is malformed")
    if not _re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", str(binding["host_only_ip"])):
        raise AggregateError("baseline binding host-only ip is malformed")
    if not _re.fullmatch(r"[0-9a-f]{64}", str(binding["policy_sha256"])):
        raise AggregateError("baseline binding policy hash is malformed")
    tree = binding["deployed_tree"]
    if not isinstance(tree, dict) or not tree:
        raise AggregateError("baseline binding deployed tree is empty")
    for name, digest in tree.items():
        if (not isinstance(name, str) or not name or ".." in name
                or name.startswith(("/", "\\")) or not name.endswith(".py")):
            raise AggregateError("baseline binding deployed tree entry name is invalid")
        if not _re.fullmatch(r"[0-9a-f]{64}", str(digest)):
            raise AggregateError("baseline binding deployed tree hash is malformed")
    server = report.get("server_identity") or {}
    if str(binding["computer_name"]).casefold() != str(server.get("computer_name", "")).casefold():
        raise AggregateError("baseline binding computer name differs from the server identity")


def verify_report_shape(report: dict[str, Any]) -> None:
    if report.get("schema_version") == 3:
        if set(report) != SCHEMA3_REPORT_KEYS:
            raise AggregateError("report root keys do not match schema3")
        verify_baseline_binding(report)
    else:
        if set(report) != REPORT_KEYS:
            raise AggregateError("report root keys do not match schema2")
        if report["schema_version"] != 2:
            raise AggregateError("formal P06 evidence must be schema2 or schema3; schema1 is history-only")
    if report["transport"] != "streamable-http":
        raise AggregateError("formal P06 evidence must use the formal HTTP transport")
    if not report["endpoint"] or not ENDPOINT_PATTERN.match(report["endpoint"]):
        raise AggregateError("endpoint is not the sanitized formal entry URL")
    if report["authorization_configured"] is not True:
        raise AggregateError("formal report must record authorization_configured=true")
    session = report["mcp_session"]
    if set(session) != {"id", "initialized_at", "closed_at"}:
        raise AggregateError("mcp_session keys are invalid")
    if not session["id"] or not session["initialized_at"] or not session["closed_at"]:
        raise AggregateError("mcp_session lifecycle is incomplete")
    identity = report["server_identity"]
    if set(identity) != {
        "computer_name",
        "service_name",
        "pid",
        "process_start_time_utc",
        "instance_id",
        "executable_sha256",
    }:
        raise AggregateError("server_identity keys are invalid")
    if identity["computer_name"] != "DESKTOP-3FI41GR" or not identity["instance_id"]:
        raise AggregateError("server_identity is incomplete")
    if set(report["runner"]) != {"pid", "process_start_time_utc", "executable_sha256"}:
        raise AggregateError("runner identity keys are invalid")
    if not report["server_observation_sha256"]:
        raise AggregateError("server observation hash is missing")


def verify_resource_evidence(report: dict[str, Any], run_dir: Path, evidence_root: Path, *, _admission=None) -> None:
    """Join every declared large step to its qualification and raw observation."""
    from tests.p06_resource_gate import ScenarioResourceGate, admit, remaining_peak
    from tests.p06_evidence import plain_file
    source_root = _admission.group.repository if _admission is not None else ROOT
    index_path = source_root/'tests/data/p06_scenario_index.json'
    if sha256_file(index_path)!=report['index_sha256']:
        raise AggregateError('scenario index differs from the frozen source')
    index = json.loads(index_path.read_text(encoding='utf-8'))
    rows = [row for row in index['scenarios'] if row['scenario_id']==report['scenario']]
    if len(rows)!=1:
        raise AggregateError('scenario source is not uniquely indexed')
    source = plain_file(source_root/'tests/scenarios',rows[0]['path'])
    if sha256_file(source)!=rows[0]['sha256'] or rows[0]['sha256']!=report['source_sha256']:
        raise AggregateError('scenario source hash differs')
    scenario = json.loads(source.read_text(encoding='utf-8'))
    gate = ScenarioResourceGate(evidence_root,scenario,None,_admission=_admission)
    steps = {row['id']:row for row in report['steps']}
    if len(steps)!=len(report['steps']):
        raise AggregateError('report step ids are duplicated')
    seen = set()

    def observation(value, expected_step):
        if (value['run_id']!=report['run_id'] or value['step_id']!=expected_step
                or value['hostname']!=report['server_identity']['computer_name']
                or value['server_pid']!=report['server_identity']['pid'] or value['sequence'] in seen):
            raise AggregateError('resource observation identity or sequence differs')
        seen.add(value['sequence'])
        raw = json.loads(plain_file(run_dir,value['transcript']).read_text(encoding='utf-8'))
        if raw['run_id']!=report['run_id'] or raw['step_id']!=expected_step or raw['control_plane_only'] is not True:
            raise AggregateError('resource original is bound to another observation')
        response = raw['transcript'][-1]['response']
        if response.startswith('event:') or response.startswith('data:'):
            response = next(line[6:] for line in response.splitlines() if line.startswith('data: '))
        envelope = json.loads(response)['result']
        if envelope.get('isError'):
            raise AggregateError('resource control observation failed')
        text = envelope['structuredContent']['result']
        if not text.rstrip().endswith('Status Code: 0'):
            raise AggregateError('resource original has a nonzero exit')
        original = json.loads(text.removeprefix('Response: ').rsplit('Status Code:',1)[0].strip())
        if any(value[key]!=original[key] for key in ('hostname','server_pid','observed_at','reading')):
            raise AggregateError('resource summary differs from original control response')

    first = steps['p06-resource-start']['resource']
    observation(first['observation'],'p06-resource-start-before')
    if first['qualification']!=gate.identity or first['scenario_deadline_seconds']!=gate.scenario_seconds:
        raise AggregateError('scenario resource budget identity or deadline differs')
    expected = admit(first['observation']['reading'],
                     remaining_increment=remaining_peak(list(gate.labels.values()),gate.budget['steps']),
                     evidence_reserve=gate.budget['evidence_reserve_bytes'],initial_peak=gate.budget['observed_peak_bytes'])
    if first['admission']!=expected:
        raise AggregateError('scenario initial resource admission differs')
    pending = list(gate.labels)
    for step in scenario['steps']:
        step_id = step['id']
        if step_id not in gate.related:
            continue
        row = steps[step_id]['resource']
        if row['qualification']!=gate.identity:
            raise AggregateError('step qualification identity differs')
        if step_id in gate.labels:
            observation(row['observation'],step_id+'-before')
            expected = admit(row['observation']['reading'],
                             remaining_increment=remaining_peak([gate.labels[key] for key in pending],gate.budget['steps']),
                             evidence_reserve=gate.budget['evidence_reserve_bytes'])
            if row['admission']!=expected or row['step_deadline_seconds']!=gate.deadlines[step_id]:
                raise AggregateError('large-step admission or deadline differs')
            pending.remove(step_id)
        observation(row['after'],step_id+'-after')
    if report['duration_ms']>gate.scenario_seconds*1000:
        raise AggregateError('scenario exceeded its frozen deadline')


def aggregate_historical(
    *,
    evidence_root: Path = EVIDENCE_ROOT,
    ledger_path: Path = LEDGER,
    selection_path: Path = SELECTION,
    manifest_path: Path = MANIFEST,
    _admission=None,
) -> dict[str, Any]:
    from tests import scenario_runner
    if _admission is None and Path(evidence_root).is_relative_to(scenario_runner.P06_REPORT_ROOT):
        raise AggregateError('historical aggregate cannot consume current report root')
    ledger = load_ledger(ledger_path, evidence_root=evidence_root)
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_scenarios = manifest["scenario_ids"]
    if (
        set(selection) != {"schema_version", "all_attempts", "selected", "rejected"}
        or selection["schema_version"] not in (2, 3)
    ):
        raise AggregateError("invalid final selection shape")
    if selection["all_attempts"] != [row["monotonic_attempt"] for row in ledger]:
        raise AggregateError("final selection omits or reorders attempt history")
    selected = selection["selected"]
    if set(selected) != set(expected_scenarios) or len(selected) != 5:
        raise AggregateError("final selection must choose each reviewed scenario exactly once")
    ledger_by_attempt = {row["monotonic_attempt"]: row for row in ledger}
    rejected = selection["rejected"]
    selected_attempts = {chosen["monotonic_attempt"] for chosen in selected.values()}
    expected_rejected = {
        str(attempt)
        for attempt in (row["monotonic_attempt"] for row in ledger)
        if attempt not in selected_attempts
    }
    if set(rejected) != expected_rejected:
        raise AggregateError("final selection does not adjudicate every unselected attempt")
    for attempt, reason in rejected.items():
        if not isinstance(reason, str) or not reason.strip():
            raise AggregateError(f"rejection reason is empty for attempt {attempt}")
    for scenario, chosen in selected.items():
        ledger_row = ledger_by_attempt.get(chosen["monotonic_attempt"])
        if ledger_row is None or ledger_row["scenario"] != scenario:
            raise AggregateError("selected attempt belongs to another scenario")
        if ledger_row["status"] != "success":
            raise AggregateError("final selection must choose successful attempts")
    reports: list[dict[str, Any]] = []
    input_hashes: list[dict[str, Any]] = []
    coverage: set[tuple[str, str]] = set()
    tools_hashes: set[str] = set()
    fixture_specs: set[str] = set()
    session_ids: set[str] = set()
    run_ids: set[str] = set()
    restore_attempts: set[str] = set()
    baseline_documents: list[dict[str, Any]] = []
    report_versions: set[int] = set()
    server_instances: set[str] = set()
    runner_identities: set[tuple[Any, Any]] = set()
    for scenario_id in expected_scenarios:
        chosen = selected[scenario_id]
        if set(chosen) != {"monotonic_attempt", "report_sha256", 'manifest_relative_path','manifest_sha256','package_sha256'}:
            raise AggregateError("selected report identity is incomplete")
        ledger_row = ledger_by_attempt.get(chosen["monotonic_attempt"])
        if ledger_row is None or ledger_row["scenario"] != scenario_id:
            raise AggregateError("selected attempt belongs to another scenario")
        if ledger_row["report_sha256"] != chosen["report_sha256"]:
            raise AggregateError("selected report hash differs from ledger")
        if any(chosen[key]!=ledger_row[key] for key in ('manifest_relative_path','manifest_sha256','package_sha256')):
            raise AggregateError('selected package manifest differs from ledger')
        report_path = contained_plain_file(evidence_root, ledger_row["report_relative_path"])
        actual_hash = sha256_file(report_path)
        if actual_hash != ledger_row["report_sha256"]:
            raise AggregateError("report bytes differ from the host receive ledger")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        verify_report_shape(report)
        report_versions.add(report["schema_version"])
        if report["scenario"] != scenario_id or report["status"] != "success":
            raise AggregateError("selected report is not a successful matching scenario")
        sequences = [row.get("sequence") for row in report.get("calls", [])]
        if sequences != list(range(1, len(sequences) + 1)):
            raise AggregateError("report call sequence is not continuous")
        if report["unexecuted_step_ids"] or report["failure"]:
            raise AggregateError("successful report contains failure or unexecuted steps")
        if any(row.get("is_error") for row in report["calls"]):
            raise AggregateError("formal scenario contains an MCP error call")
        # PLAN-CHANGE-014: one registered tool (netsh PacketCapture) is a
        # documented exclusion; executed coverage is 129 relations.
        if len(report["coverage"]) != 129:
            raise AggregateError("selected report does not provide 129 relations")
        for row in report["coverage"]:
            key = (row.get("scenario_id"), row.get("tool"))
            if key in coverage:
                raise AggregateError("coverage relation is duplicated")
            coverage.add(key)
        run_dir = report_path.parent
        verify_tools_schema_binding(report, run_dir, current=_admission is not None)
        if report.get("schema_version") == 3:
            baseline_documents.append(verify_baseline_evidence(report, run_dir))
            restore = None
        else:
            restore = (_admission.report(report, run_dir, evidence_root) if _admission is not None
                       else verify_snapshot_evidence(report, run_dir, evidence_root))
        try:
            verify_resource_evidence(report,run_dir,evidence_root,_admission=_admission)
        except (ValueError,OSError,KeyError,TypeError,StopIteration) as exc:
            raise AggregateError(f'formal resource evidence failed: {exc}') from exc
        expected_identity = ledger_identity(report)
        for field, value in expected_identity.items():
            if field not in ledger_row or ledger_row[field] != value:
                raise AggregateError(f'ledger identity differs from report: {field}')
        if not ledger_row.get('received_at'):
            raise AggregateError('ledger lacks host receipt timestamp')
        session_ids.add(report["mcp_session"]["id"])
        run_ids.add(report["run_id"])
        if restore is not None:
            restore_attempts.add(restore["restore_attempt_id"])
        server_instances.add(report["server_identity"]["instance_id"])
        runner = report["runner"]
        runner_identity = (runner.get("pid"), runner.get("process_start_time_utc"))
        if None in runner_identity:
            raise AggregateError("runner process identity is incomplete")
        runner_identities.add(runner_identity)
        tools_hashes.add(report["tools_schema_sha256"])
        fixture_specs.add(report["fixture_spec_sha256"])
        for field in LEDGER_IDENTITY_FIELDS:
            if report.get(field) != ledger_row.get(field):
                raise AggregateError(f"report identity field differs from ledger: {field}")
        reports.append(report)
        input_hashes.append(
            {
                "monotonic_attempt": ledger_row["monotonic_attempt"],
                "package_sha256": ledger_row["package_sha256"],
                "report_relative_path": ledger_row["report_relative_path"],
                "report_sha256": actual_hash,
                "restore_attempt_id": restore["restore_attempt_id"] if restore is not None else None,
                "baseline_binding_sha256": (report.get("baseline_binding") or {}).get("observation_sha256"),
                "run_id": report["run_id"],
                "scenario": scenario_id,
            }
        )
    expected_relations = {(row["scenario_id"], row["tool"]) for row in manifest["relations"]}
    if coverage != expected_relations or len(coverage) != 645:
        raise AggregateError("manifest, scenario, and report coverage sets differ")
    if len(tools_hashes) != 1 or None in tools_hashes or len(fixture_specs) != 1:
        raise AggregateError("selected reports do not share tool and fixture identities")
    if len(session_ids) != 5 or len(run_ids) != 5:
        raise AggregateError("selected reports do not have five distinct sessions and runs")
    if len(report_versions) != 1:
        raise AggregateError("selected reports mix schema versions in one evidence root")
    if report_versions == {2} and len(restore_attempts) != 5:
        raise AggregateError("selected reports must prove five independent restore attempts")
    if report_versions == {3}:
        # PLAN-CHANGE-025: the five runs share one adopted baseline binding
        # (VM identity, deployed tree, policy); distinctness lives in the
        # five sessions and run ids checked above.
        distinct_bindings = {canonical_bytes(doc) for doc in baseline_documents}
        if len(baseline_documents) != 5 or len(distinct_bindings) != 1:
            raise AggregateError("schema3 reports must share exactly one adopted baseline binding")
    if len(runner_identities) != 5:
        raise AggregateError("selected scenarios do not have five distinct runner lifecycles")
    return {
        "schema_version": next(iter(report_versions)),
        "status": "success",
        "scenario_count": 5,
        "tool_count": 129,
        "relation_count": 645,
        "manifest_sha256": sha256_file(manifest_path),
        "ledger_sha256": sha256_file(ledger_path),
        "selection_sha256": sha256_file(selection_path),
        "tools_schema_sha256": next(iter(tools_hashes)),
        "fixture_spec_sha256": next(iter(fixture_specs)),
        "distinct_session_count": len(session_ids),
        "distinct_restore_attempt_count": len(restore_attempts),
        "distinct_baseline_binding_count": len({canonical_bytes(doc) for doc in baseline_documents}),
        "runner_lifecycle_count": len(runner_identities),
        "server_instance_count": len(server_instances),
        "unexpected_error_count": 0,
        "unexecuted_step_count": 0,
        "inputs": input_hashes,
        "total_duration_ms": sum(row["duration_ms"] for row in reports),
    }


def _aggregate_current(admission, *, evidence_root=None, ledger_path=None,
                       selection_path=None, manifest_path=None):
    evidence_root = evidence_root or admission.group.repository / EVIDENCE_ROOT.relative_to(ROOT)
    ledger_path = ledger_path or evidence_root / '接收清单.jsonl'
    selection_path = selection_path or evidence_root / 'final-selection.json'
    manifest_path = manifest_path or admission.group.repository / MANIFEST.relative_to(ROOT)
    for path in (ledger_path, selection_path, manifest_path):
        admission.read(path)
    reference = admission.group.freeze_refs['tests/data/p06_coverage_manifest.json']
    if sha256_file(manifest_path) != reference['sha256']:
        raise AggregateError('coverage manifest differs from approval')
    result = aggregate_historical(evidence_root=evidence_root, ledger_path=ledger_path,
        selection_path=selection_path, manifest_path=manifest_path, _admission=admission)
    admission.recheck()
    return result


from tests.p05_pc026_governance import consumption


@consumption
def aggregate(*, evidence_root=EVIDENCE_ROOT, ledger_path=LEDGER,
              selection_path=SELECTION, manifest_path=MANIFEST):
    from tests import p06_pc026_binding
    return _aggregate_current(p06_pc026_binding.load(), evidence_root=evidence_root,
        ledger_path=ledger_path, selection_path=selection_path, manifest_path=manifest_path)


@consumption
def main() -> int:
    from tests import p06_pc026_binding
    admission = p06_pc026_binding.load()
    result = _aggregate_current(admission)
    admission.recheck()
    OUTPUT.write_bytes(canonical_bytes(result))
    print(json.dumps({"output": str(OUTPUT), "status": result["status"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
