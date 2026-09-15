"""P06 test-control observations and fail-closed resource admission.

The management channel observes Windows only. It never proxies a product
tool call, supplies coverage, or replaces the formal HTTP ClientSession.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import math
import re
import time
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit


GIB = 1024 ** 3
RESERVE = 4 * GIB
RESOURCE_FIELDS = {
    'physical_memory_bytes', 'available_memory_bytes', 'c_total_bytes',
    'c_free_bytes', 'datastore_bytes', 'download_root_bytes', 'report_root_bytes',
}


class ResourceRejected(RuntimeError):
    def __init__(self, reason: str, evidence: dict):
        super().__init__(reason)
        self.evidence = evidence


def require_trace_inactive(observation):
    # PLAN-CHANGE-014 removed the netsh-trace chain; keep the guard as a
    # no-op compatibility shim for historical report shapes.
    return None


def validate_reading(reading: dict) -> None:
    if not isinstance(reading, dict) or set(reading) != RESOURCE_FIELDS:
        raise ValueError('incomplete resource observation')
    if any(type(value) is not int or value < 0 for value in reading.values()):
        raise ValueError('resource observations must be nonnegative integer bytes')
    if (reading['physical_memory_bytes'] == 0 or reading['c_total_bytes'] == 0
            or reading['available_memory_bytes'] > reading['physical_memory_bytes']
            or reading['c_free_bytes'] > reading['c_total_bytes']):
        raise ValueError('inconsistent resource observation')


def admit(reading: dict, *, remaining_increment: int, evidence_reserve: int,
          initial_peak: int = 0, static: bool = False) -> dict:
    validate_reading(reading)
    if any(type(value) is not int or value < 0
           for value in (remaining_increment, evidence_reserve, initial_peak)):
        raise ValueError('invalid frozen resource budget')
    margin = max(RESERVE, 2 * evidence_reserve)
    required = max(initial_peak, remaining_increment) + margin
    if static:
        required = max(required, 2 * (reading['physical_memory_bytes'] + 64 * 1024**2) + RESERVE)
    row = {'reading': reading, 'remaining_increment_bytes': remaining_increment,
           'evidence_reserve_bytes': evidence_reserve, 'initial_peak_bytes': initial_peak,
           'margin_bytes': margin, 'required_free_bytes': required,
           'static_gate': static, 'admitted': reading['c_free_bytes'] >= required,
           'formula': 'max(initial_peak,remaining_increment)+max(4GiB,2*evidence_reserve)',
           'rejection_reason': None}
    if not row['admitted']:
        row['rejection_reason'] = 'insufficient free C-volume bytes before product call'
        raise ResourceRejected(row['rejection_reason'], row)
    return row


def qualified_deadline(elapsed_seconds: float, previous_upper_seconds: float) -> int:
    if (isinstance(elapsed_seconds, bool) or isinstance(previous_upper_seconds, bool)
            or not math.isfinite(elapsed_seconds) or not math.isfinite(previous_upper_seconds)
            or elapsed_seconds < 0 or previous_upper_seconds <= 0):
        raise ValueError('invalid qualification duration or original upper bound')
    return math.ceil(max(2 * elapsed_seconds, previous_upper_seconds))


def freeze_measurements(report: dict) -> dict:
    """Recompute the budget from observations, never trust precomputed deltas."""
    repo = Path(__file__).resolve().parents[1]
    invocations = json.loads((repo/'tests/data/p03_invocations.json').read_text(encoding='utf-8'))
    expected = {row['artifact']: (row['artifact'], 3600 if row['artifact']=='Windows.Memory.Acquisition' else 1200)
                for row in invocations if row['risk_class']=='resource_sensitive'
                and row['artifact']!='Windows.Network.PacketCapture'}
    expected.update({'forensic-triage':('collect_forensic_triage',2400),
                     'fixture-file':('collect_file',300), 'download':('download_flow_file',300)})
    rows = [row for row in report['steps'] if row.get('kind')=='resource-qualification']
    if len(rows)!=len(expected) or {row['id'] for row in rows}!=set(expected):
        raise ValueError('qualification omits or duplicates a required resource chain')
    starts = [row for row in report['steps'] if row['id']=='static-resource-gate']
    if len(starts)!=1:
        raise ValueError('qualification lacks one initial resource gate')
    initial = starts[0]['observation']
    validate_reading(initial['reading'])
    if starts[0]['admission']!=admit(initial['reading'],remaining_increment=0,evidence_reserve=0,static=True):
        raise ValueError('qualification static admission cannot be recomputed')
    all_free = [initial['reading']['c_free_bytes']]
    measured, sequences = {}, set()
    for row in rows:
        label = row['id']
        tool, upper = expected[label]
        if row.get('passed') is not True or row['tool']!=tool or row['previous_upper_seconds']!=upper:
            raise ValueError('qualification chain or original upper bound differs')
        admission = admit(row['before']['reading'],remaining_increment=0,evidence_reserve=0,
                          static=tool=='Windows.Memory.Acquisition')
        if row['admission']!=admission:
            raise ValueError('qualification pre-call admission cannot be recomputed')
        samples = [row['before'], *row.get('samples',[]), row['after']]
        for sample in samples:
            validate_reading(sample['reading'])
            if (sample['run_id']!=report['run_id'] or sample['server_pid']!=report['server_identity']['pid']
                    or sample['hostname']!=report['server_identity']['computer_name']
                    or sample['sequence'] in sequences):
                raise ValueError('qualification observation identity or sequence differs')
            sequences.add(sample['sequence'])
        free = [sample['reading']['c_free_bytes'] for sample in samples]
        all_free.extend(free)
        measured[label] = {'tool':tool, 'peak_increment_bytes':max(0,free[0]-min(free)),
                           'retained_increment_bytes':max(0,free[0]-free[-1]),
                           'deadline_seconds':qualified_deadline(row['elapsed_seconds'],upper)}
    return {'observed_peak_bytes':max(0,initial['reading']['c_free_bytes']-min(all_free)), 'steps':measured}


def remaining_peak(labels, measurements):
    retained, peak = 0, 0
    for label in labels:
        row = measurements[label]
        peak = max(peak, retained+row['peak_increment_bytes'])
        retained += row['retained_increment_bytes']
    return peak


def verify_qualification_calls(report):
    """A passed resource summary is insufficient without its actual Flow chain."""
    calls = report['calls']
    if [row['sequence'] for row in calls]!=list(range(1,len(calls)+1)):
        raise ValueError('qualification call sequence is incomplete')
    by_step = {}
    for call in calls:
        raw = call.get('mcp_result')
        if (call.get('is_error') or not isinstance(raw,dict) or raw.get('isError') is not False
                or raw.get('structuredContent')!=call.get('structured') or not call.get('ended_at')):
            raise ValueError('qualification lacks successful original MCP results')
        by_step.setdefault(call['step_id'],[]).append(call)
    consumed = set()
    flows = {}
    for row in report['steps']:
        if row.get('kind')!='resource-qualification' or row['id']=='download':
            continue
        label, flow = row['id'],row['flow_id']
        if not isinstance(flow,str) or not flow.startswith('F.') or flow in flows.values():
            raise ValueError('qualification reuses or omits Flow identity')
        flows[label] = flow
        start = by_step[label]
        waits = by_step[label+'-wait']
        results, files = by_step[label+'-results'],by_step[label+'-files']
        if (len(start)!=1 or start[0]['tool']!=row['tool'] or start[0]['structured'].get('flow_id')!=flow
                or not waits or waits[-1]['structured'].get('state')!='FINISHED'
                or len(results)!=1 or len(files)!=1):
            raise ValueError('qualification Flow chain did not finish completely')
        for call in waits+results+files:
            if call['arguments'].get('flow_id')!=flow:
                raise ValueError('qualification Flow request identity differs')
        for call in waits:
            if call['tool']!='get_flow_status' or call['structured'].get('flow_id')!=flow or call['structured'].get('state')=='ERROR':
                raise ValueError('qualification Flow status identity or state differs')
        for call, tool in ((results[0],'get_flow_results'),(files[0],'list_flow_files')):
            if call['tool']!=tool or call['structured'].get('operation')!=tool or not isinstance(call['structured'].get('data'),list):
                raise ValueError('qualification lacks result or file-list response')
        ordered = start+waits+results+files
        if [call['sequence'] for call in ordered]!=sorted(call['sequence'] for call in ordered):
            raise ValueError('qualification Flow chain order differs')
        consumed.update(call['sequence'] for call in ordered)
    download = by_step['download']
    if len(download)!=1:
        raise ValueError('qualification download is missing or duplicated')
    call = download[0]
    uploaded = by_step['fixture-file-files'][0]['structured']['data']
    if (call['tool']!='download_flow_file' or call['arguments'].get('flow_id')!=flows['fixture-file']
            or call['arguments'].get('file_id') not in {row['file_id'] for row in uploaded}
            or call['structured'].get('flow_id')!=flows['fixture-file']
            or call['structured'].get('file_id')!=call['arguments'].get('file_id')):
        raise ValueError('qualification download is not bound to its collected fixture file')
    consumed.add(call['sequence'])
    if consumed!={row['sequence'] for row in calls}:
        raise ValueError('qualification contains unexplained extra calls')


def verify_resource_original(value, report, run_dir, expected_step, seen):
    from tests.p06_evidence import plain_file
    validate_reading(value['reading'])
    if (value['run_id']!=report['run_id'] or value['step_id']!=expected_step
            or value['hostname']!=report['server_identity']['computer_name']
            or value['server_pid']!=report['server_identity']['pid']
            or type(value['sequence']) is not int or value['sequence']<=0 or value['sequence'] in seen):
        raise ValueError('resource observation identity or sequence differs')
    seen.add(value['sequence'])
    raw = json.loads(plain_file(run_dir,value['transcript']).read_bytes())
    if raw['run_id']!=report['run_id'] or raw['step_id']!=expected_step or raw['control_plane_only'] is not True:
        raise ValueError('resource original belongs to another observation')
    final = raw['transcript'][-1]
    request = final['request']
    if request['method']!='tools/call' or request['params']['name']!='PowerShell':
        raise ValueError('resource original is not a management observation')
    response = final['response']
    if response.startswith('event:') or response.startswith('data:'):
        response = next(line[6:] for line in response.splitlines() if line.startswith('data: '))
    envelope = json.loads(response)['result']
    if envelope.get('isError'):
        raise ValueError('resource control observation failed')
    text = envelope['structuredContent']['result']
    if not text.rstrip().endswith('Status Code: 0'):
        raise ValueError('resource control observation returned nonzero status')
    original = json.loads(text.removeprefix('Response: ').rsplit('Status Code:',1)[0].strip())
    if any(value[key]!=original[key] for key in ('hostname','server_pid','observed_at','reading','trace_status')):
        raise ValueError('resource summary differs from original control response')


async def guarded_step(gate, step_id, operation):
    """The runner's only resource-gated execution seam; reject before invoking."""
    resource = await gate.before(step_id)
    try:
        async with asyncio.timeout(gate.timeout(step_id)):
            result = await operation()
        after = await gate.after(step_id)
        if resource is not None:
            resource['after'] = after
        elif after is not None:
            resource = {'after':after, 'qualification':gate.identity}
        return result,resource
    except Exception as exc:
        exc.resource_evidence = resource
        raise


class ScenarioResourceGate:
    def __init__(self, root: Path, scenario: dict, sampler):
        from tests.p06_evidence import plain_file, digest
        from tests.p06_package import verify_manifest, verify_payload_zip
        from tests.p06_resource_policy import load_policy
        policy = load_policy(scenario)
        from tests.p06_aggregate_reports import verify_report_shape, verify_tools_schema_binding, verify_snapshot_evidence
        selection = json.loads(plain_file(root,'resource-qualification-selection.json').read_text(encoding='utf-8'))
        report_path = plain_file(root, selection['report_relative_path'])
        if digest(report_path)!=selection['report_sha256']:
            raise ValueError('qualification selection bytes differ')
        report = json.loads(report_path.read_text(encoding='utf-8'))
        source = next(row['files'] for row in report['steps'] if row['id']=='implementation-identity')
        expected_sources = {'scenario_runner.py','p06_resource_gate.py','p06_formal_session.py',
                            'p06_resource_qualification.py','p06_package.py','p06_evidence.py','p06_resource_policy.py',
                            'p06_receive.py','p06_aggregate_reports.py','data/p06_scenario_index.json',
                            'data/p06_resource_policy.json','data/p03_invocations.json'}
        if set(source)!=expected_sources or any(digest(Path(__file__).parent/name)!=value for name,value in source.items()):
            raise ValueError('qualification implementation changed; requalification required')
        verify_report_shape(report)
        if (report['scenario']!='resource-qualification' or report['status']!='success'
                or report['failure'] or report['coverage'] or any(call.get('is_error') for call in report['calls'])):
            raise ValueError('selected qualification is not a successful formal attempt')
        verify_tools_schema_binding(report,report_path.parent)
        verify_snapshot_evidence(report,report_path.parent,root)
        verify_qualification_calls(report)
        seen = set()
        initial = next(row['observation'] for row in report['steps'] if row['id']=='static-resource-gate')
        verify_resource_original(initial,report,report_path.parent,'qualification-start',seen)
        for row in report['steps']:
            if row.get('kind')=='resource-qualification':
                verify_resource_original(row['before'],report,report_path.parent,row['id']+'-before',seen)
                for sample in row.get('samples',[]):
                    verify_resource_original(sample,report,report_path.parent,row['id']+'-poll',seen)
                verify_resource_original(row['after'],report,report_path.parent,row['id']+'-after',seen)
        verify_manifest(report_path.parent,root)
        payload_identity = verify_payload_zip(report_path.parent,root)
        budget_path = plain_file(report_path.parent,'resource-budget.json')
        budget = json.loads(budget_path.read_text(encoding='utf-8'))
        payload = report_path.parent/'qualification-payload.zip'
        if (budget['report_sha256']!=digest(report_path)
                or any(budget.get(key)!=value for key,value in payload_identity.items())):
            raise ValueError('qualification payload identity or actual size differs')
        measured = freeze_measurements(report)
        if budget['steps']!=measured['steps'] or budget['observed_peak_bytes']!=measured['observed_peak_bytes']:
            raise ValueError('frozen qualification cannot be recomputed')
        self.budget, self.sampler = budget, sampler
        self.identity = {'report_sha256':digest(report_path), 'budget_sha256':digest(budget_path),
                         'payload_sha256':digest(payload)}
        self.labels = {key:row['qualification_label'] for key,row in policy.items() if row['class']=='admission'}
        if sorted(self.labels.values())!=sorted(budget['steps']):
            raise ValueError('scenario resource chains differ from qualification')
        self.pending = list(self.labels)
        self.deadlines = {}
        self.trace_end_steps = {key for key,row in policy.items()
                               if row['qualification_label']=='packet-stop' and row['tool']=='list_flow_files'}
        self.related = dict(self.labels)
        for step in scenario['steps']:
            repeat = step.get('repeat_until',{})
            upper = max(60,repeat.get('max_attempts',1)*repeat.get('interval_seconds',0)+60)
            label = policy.get(step['id'],{}).get('qualification_label')
            if label:
                self.related[step['id']] = label
            self.deadlines[step['id']] = max(upper,budget['steps'][label]['deadline_seconds'] if label else upper)
        self.scenario_seconds = math.ceil(sum(self.deadlines.values())*1.1)
        self.expires = time.monotonic()+self.scenario_seconds

    async def before(self, step_id, *, initial=False):
        if not initial and step_id not in self.labels:
            return None
        observation = await self.sampler.sample(step_id+'-before')
        if initial or self.labels.get(step_id)=='packet-start':
            require_trace_inactive(observation)
        row = {'qualification':self.identity,'observation':observation,
               'scenario_deadline_seconds':self.scenario_seconds,
               'step_deadline_seconds':self.deadlines.get(step_id)}
        try:
            row['admission'] = admit(observation['reading'],
                remaining_increment=remaining_peak([self.labels[key] for key in self.pending],self.budget['steps']),
                evidence_reserve=self.budget['evidence_reserve_bytes'],
                initial_peak=self.budget['observed_peak_bytes'] if initial else 0)
        except ResourceRejected as exc:
            row['admission'] = exc.evidence
            raise ResourceRejected(str(exc),row) from exc
        return row

    async def after(self, step_id):
        if step_id not in self.related:
            return None
        observed = await self.sampler.sample(step_id+'-after')
        if step_id in self.trace_end_steps:
            require_trace_inactive(observed)
        if step_id in self.pending:
            self.pending.remove(step_id)
        return observed

    def timeout(self, step_id):
        remaining = self.expires-time.monotonic()
        if remaining<=0:
            raise TimeoutError('qualified scenario deadline exhausted')
        return min(self.deadlines[step_id],remaining)


class GuestResourceSampler:
    """Fixed read-only management operation; no caller-provided shell or paths."""

    def __init__(self, endpoint: str, run_id: str, server_identity: dict, output: Path):
        parsed = urlsplit(endpoint)
        if (parsed.scheme != 'http' or parsed.port != 28790 or parsed.path != '/mcp'
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise ValueError('resource observer requires the formal endpoint')
        host = str(ipaddress.IPv4Address(parsed.hostname))
        if str(uuid.UUID(run_id)) != run_id:
            raise ValueError('resource observer requires a reserved run UUID')
        self.url = f'http://{host}:28787/mcp'
        self.run_id, self.identity, self.output = run_id, dict(server_identity), output
        self.sequence = 0

    async def sample(self, step_id: str) -> dict:
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', step_id):
            raise ValueError('invalid resource observation step id')
        self.sequence += 1
        return await asyncio.to_thread(self._sample, step_id, self.sequence)

    def _sample(self, step_id: str, sequence: int) -> dict:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'}
        transcript = []

        def rpc(payload):
            request = urllib.request.Request(self.url, json.dumps(payload).encode(), headers)
            with opener.open(request, timeout=75) as response:
                session = response.headers.get('mcp-session-id')
                if session:
                    headers['mcp-session-id'] = session
                raw = response.read().decode('utf-8')
            transcript.append({'request': payload, 'response': raw})
            if not raw.strip():
                return None
            for line in raw.splitlines():
                if line.startswith('data: '):
                    return json.loads(line[6:])
            return json.loads(raw)

        command = (
            "$ErrorActionPreference='Stop'; "
            "$svc=Get-CimInstance Win32_Service | Where-Object Name -eq 'mcp-velociraptor'; "
            "if ($svc.State -ne 'Running') { throw 'formal service not running' }; "
            "$m=[regex]::Match($svc.PathName, '^\"([^\"]+)\"\\s+\"([^\"]+)\"'); "
            "if (-not $m.Success) { throw 'unrecognized deployed service command' }; "
            "$py=$m.Groups[1].Value; $repo=Split-Path (Split-Path $m.Groups[2].Value -Parent) -Parent; "
            "Push-Location $repo; try { "
            "$raw=& $py -c 'import json; from tests.p06_resource_qualification import resources; print(json.dumps(resources()))'; "
            "if ($LASTEXITCODE -ne 0) { throw 'resource observer failed' }; "
            # netsh exits 1 for the benign "no trace session currently in
            # progress" reply; that is the expected inactive state, not loss.
            "$trace=(& netsh trace show status 2>&1 | Out-String).Trim(); "
            "if ($LASTEXITCODE -ne 0 -and $trace -notmatch 'no trace session currently in progress') "
            "{ throw 'trace state observation failed' }; "
            "[pscustomobject]@{hostname=$env:COMPUTERNAME; server_pid=$svc.ProcessId; "
            "observed_at=[DateTime]::UtcNow.ToString('o'); reading=($raw | ConvertFrom-Json); trace_status=$trace} | ConvertTo-Json -Depth 5 -Compress "
            "} finally { Pop-Location }"
        )
        started = datetime.now(UTC)
        try:
            rpc({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                'protocolVersion': '2025-03-26', 'capabilities': {},
                'clientInfo': {'name': 'p06-resource-observer', 'version': '1'}}})
            rpc({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
            envelope = rpc({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {
                'name': 'PowerShell', 'arguments': {'command': command, 'timeout': 60}}})
            result = envelope['result']
            if result.get('isError'):
                raise ValueError('management resource observation failed')
            text = result['structuredContent']['result']
            if not text.rstrip().endswith('Status Code: 0'):
                raise ValueError('resource observer returned nonzero status')
            body = text.removeprefix('Response: ').rsplit('Status Code:', 1)[0].strip()
            observed = json.loads(body)
            validate_reading(observed['reading'])
            if (observed['hostname'] != self.identity['computer_name']
                    or observed['server_pid'] != self.identity['pid']):
                raise ValueError('resource observation belongs to another formal service')
            instant = datetime.fromisoformat(observed['observed_at'].replace('Z', '+00:00'))
            if abs((datetime.now(UTC) - instant).total_seconds()) > 120:
                raise ValueError('resource observation clock is stale or unsynchronized')
            return {**observed, 'run_id': self.run_id, 'step_id': step_id,
                    'sequence': sequence, 'control_plane': True,
                    'started_at': started.isoformat(), 'transcript': f'resources/{sequence:04d}.json'}
        finally:
            self.output.mkdir(parents=True, exist_ok=True)
            destination = self.output / f'{sequence:04d}.json'
            with destination.open('xb') as stream:
                stream.write(json.dumps({'run_id': self.run_id, 'step_id': step_id,
                                         'control_plane_only': True, 'transcript': transcript},
                                        ensure_ascii=False, sort_keys=True).encode('utf-8'))
