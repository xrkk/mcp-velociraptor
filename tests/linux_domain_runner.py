#!/usr/bin/env python3
# Copyright 2026 Google LLC
"""LNX-VR guest acceptance runner: executes Linux-domain plans against the
live REMnux Velociraptor server using the velociraptor binary's query API.

Evidence lands in /tmp/lnxvr-accept/*.json for host-side sealing.
"""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, '/opt/velociraptor-linux-domain')

from velociraptor_linux_domain import (
    LinuxDomainError,
    LinuxPlatformRouter,
    ScopeState,
    build_triage_plan,
    compare_triage_runs,
    fingerprint_artifacts,
)

VELO = '/opt/velociraptor/velociraptor'
API = '/opt/velociraptor/api-access/api_client.yaml'
E = '/tmp/lnxvr-accept'
os.makedirs(E, exist_ok=True)

REAL_TRIAGE = [
    # (artifact, category) — small, fast built-ins for a real twice-run
    ('Generic.Client.Info', 'host_info'),
    ('Linux.Sys.Users', 'users'),
    ('Linux.Network.Netstat', 'netstat'),
    ('Linux.Sys.Crontab', 'cron'),
]


def velo_vql(query: str) -> list:
    result = subprocess.run(
        [VELO, '--api_config', API, 'query', query, '--format', 'json'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180)
    if result.returncode != 0:
        raise RuntimeError('VQL failed: %s' % result.stderr[-300:])
    return json.loads(result.stdout or '[]')


def collect_artifact(client_id: str, artifact: str, timeout: int = 240):
    """Launch a collect via VQL collect_client() and poll for completion."""
    launch = ("SELECT collect_client(client_id='%s', artifacts='%s', "
              "timeout=%d) AS flow FROM scope()" % (client_id, artifact, timeout))
    rows = velo_vql(launch)
    flow = rows[0]['flow'] if rows else {}
    flow_id = flow.get('flow_id') or flow.get('request', {}).get('session_id')
    if not flow_id:
        # collect_client returns FlowDetails; fall back to scanning flows
        flows = velo_vql(
            "SELECT session_id FROM flows(client_id='%s') "
            "ORDER BY timestamp DESC LIMIT 1" % client_id)
        flow_id = flows[0]['session_id'] if flows else None
    deadline = time.time() + timeout
    state = 'RUNNING'
    while time.time() < deadline:
        rows = velo_vql(
            "SELECT state, session_id FROM flows(client_id='%s') "
            "WHERE session_id='%s'" % (client_id, flow_id))
        if rows:
            state = rows[0].get('state') or state
            if state in ('FINISHED', 'ERROR', 'CANCELLED'):
                break
        time.sleep(3)
    return {'flow_id': flow_id, 'state': state}


def save(name, payload):
    with open(f'{E}/{name}.json', 'w') as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=1, default=str)
    print(f'== {name}: {json.dumps(payload, default=str)[:150]}')


def main():
    # 1 platform routing from live client table
    clients = velo_vql('SELECT client_id, os_info.system AS os, '
                       'os_info.hostname AS hostname FROM clients()')
    save('01-clients', clients)
    router = LinuxPlatformRouter(lambda: clients)

    # 1a Windows/absent target refusal with no-mutation proof
    refused = None
    try:
        router.resolve_linux_target('C.nonexistent-win-like')
    except LinuxDomainError as error:
        refused = {'code': error.code, 'details': error.details}
    save('02-unknown-refusal', refused)
    target = router.resolve_linux_target()
    save('03-linux-target', target)
    if target.get('os') != 'linux':
        raise SystemExit('expected Linux client')

    # 2 default scope + fingerprint
    scope = ScopeState('lnxvr-acc-1')
    effective = scope.effective_scope()
    save('04-default-scope', effective)

    # 3 two same-premise triage runs (real collections, small artifact set)
    def run_triage(tag: str) -> dict:
        results = {}
        for artifact, category in REAL_TRIAGE:
            flow = collect_artifact(target['client_id'], artifact)
            results[category] = flow
        return {
            'tag': tag,
            'client_id': target['client_id'],
            'fingerprint': fingerprint_artifacts(
                a for a, _ in REAL_TRIAGE),
            'category_results': results,
        }

    run_a = run_triage('first')
    save('05-triage-first', run_a)
    run_b = run_triage('second')
    save('06-triage-second', run_b)
    comparison = compare_triage_runs(run_a, run_b)
    save('07-repeat-comparison', comparison)

    # 4 temporary extension with reason, observable, then withdrawal
    extended = scope.extend_temporarily(
        ['Linux.Search.FileFinder'], reason='acceptance: verify gap fill',
        expires_in_seconds=300)
    save('08-extended-scope', extended)
    withdrawn = scope.withdraw()
    save('09-withdrawn-scope', withdrawn)
    stopped = scope.stop()
    save('10-stopped-scope', stopped)

    print('VERDICT repeatable=%s' % comparison['repeatable'])


if __name__ == '__main__':
    main()
