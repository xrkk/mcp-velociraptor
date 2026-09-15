"""Frozen per-step admission classification; no runtime fallback category."""

import hashlib
import json
from pathlib import Path

from tests.p06_evidence import plain_file

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'tests/data/p06_resource_policy.json'


def policy_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))+'\n').encode('utf-8')


def build_policy(scenarios, invocations):
    sensitive = {row['artifact'] for row in invocations if row['risk_class']=='resource_sensitive'}
    rows = []
    for scenario in scenarios:
        labels = {}
        for step in scenario['steps']:
            tool = step.get('tool')
            cancel_probe = (step['id']=='fixed-cancel-target' and tool=='Windows.System.PowerShell'
                            and step['arguments']=={'Command':'Start-Sleep -Seconds 300',
                                                    'Timeout':330,'Stateful':False})
            if tool in sensitive and not cancel_probe:
                # PLAN-CHANGE-014: the netsh-trace PacketCapture chain is out
                # of scope (network capture is the FakeNet-NG domain).
                label = tool
            else:
                label = {'collect_forensic_triage':'forensic-triage','collect_file':'fixture-file',
                         'download_flow_file':'download'}.get(tool)
            if label:
                labels[step['id']] = label
        if len(labels)!=11 or len(set(labels.values()))!=11:
            raise ValueError('scenario must have exactly eleven distinct admission chains')
        for step in scenario['steps']:
            if step['kind']!='tool':
                continue
            label = labels.get(step['id'])
            owner = step['id'] if label else None
            category = 'admission' if label else 'bounded'
            reference = step['arguments'].get('flow_id')
            if not label and isinstance(reference,dict) and set(reference)=={'$ref'}:
                parts = reference['$ref'].split('/')
                if len(parts)>=4 and parts[1]=='steps' and parts[2] in labels:
                    owner, label = parts[2], labels[parts[2]]
                    category = 'dependent'
            argument_sha = hashlib.sha256(policy_bytes(step['arguments'])).hexdigest()
            reason = {
                'admission':'Qualified resource-sensitive collection or fixture download; admit before invoking.',
                'dependent':'Status/results/files of the named admission owner; observe the same Flow after this step.',
                'bounded':'Reviewed non-resource-sensitive invocation or fixed lifecycle probe; source-locked arguments, no resource-category fallback.',
            }[category] + ' arguments_sha256=' + argument_sha
            if step['id']=='fixed-cancel-target':
                reason = 'Owned cancellation probe: fixed 300-second sleep, 330-second bound, no collection command; cancel and verify terminal state. arguments_sha256=' + argument_sha
            rows.append({'scenario_id':scenario['scenario_id'],'step_id':step['id'],'tool':step['tool'],
                         'class':category,'reason':reason,'qualification_label':label,'owner_step_id':owner})
    return {'schema_version':1,'steps':rows}


def load_policy(scenario):
    index_path = ROOT/'tests/data/p06_scenario_index.json'
    index = json.loads(index_path.read_bytes())
    binding = index['resource_policy']
    if binding.get('path')!='p06_resource_policy.json' or set(binding)!={'path','sha256'}:
        raise ValueError('resource policy must use its fixed indexed path')
    raw = plain_file(ROOT/'tests/data',binding['path']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=binding['sha256']:
        raise ValueError('resource policy hash differs from reviewed index')
    value = json.loads(raw)
    invocations = json.loads((ROOT/'tests/data/p03_invocations.json').read_bytes())
    expected = build_policy([scenario],invocations)['steps']
    rows = [row for row in value['steps'] if row['scenario_id']==scenario['scenario_id']]
    if value['schema_version']!=1 or rows!=expected:
        raise ValueError('resource policy omits, reclassifies or misbinds a scenario step')
    return {row['step_id']:row for row in rows}
