"""Code-owned PC026 P06 handoff. Completion is an outer controlled record.

The internal Admission seam supports isolated file-tree tests only. Public
entrypoints never accept a repository, approval flag or aggregation bypass.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess

from tests import p05_pc020_evidence as ev
from tests import p05_pc026_governance as gov
from tests import p06_pc026_binding as binding
from tests import p06_aggregate_reports as aggregate
from tests import p06_package as package
from tests.p06_evidence import plain_file

ROOT_REL = 'Logs/P06/wf-01a05d1d-p06-r3'
OUTPUT = 'p06-handoff.json'
FIXED = ('historical-roots.json', '接收清单.jsonl',
         'resource-qualification-selection.json', 'final-selection.json', 'aggregate.json')


def _git(repository, *args):
    # Ignore inherited repository/index/object overrides and replacement refs.
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_NO_REPLACE_OBJECTS='1', GIT_OPTIONAL_LOCKS='0')
    result = subprocess.run(['git', '--no-replace-objects', '-C', str(repository), *args],
                            env=env, check=True, capture_output=True)
    return result.stdout


def _commit(repository, oid):
    gov.require(isinstance(oid, str) and re.fullmatch('[0-9a-f]{40}', oid), 'invalid commit OID')
    gov.require(_git(repository, 'cat-file', '-t', oid) == b'commit\n', 'OID is not a commit')


def _git_ref(repository, oid, reference):
    reference = gov.ref(reference)
    entry = _git(repository, 'ls-tree', '-z', oid, '--', ':(literal)' + reference['path'])
    rows = entry.split(b'\0')
    gov.require(len(rows) == 2 and rows[-1] == b'', 'Git path missing or ambiguous')
    header, name = rows[0].split(b'\t', 1)
    mode, kind, blob = header.split(b' ')
    gov.require(mode in {b'100644', b'100755'} and kind == b'blob'
                and name.decode('utf-8') == reference['path'], 'Git path is not an ordinary blob')
    gov.require(int(_git(repository, 'cat-file', '-s', blob.decode())) == reference['size'],
                'Git blob size differs')
    data = _git(repository, 'cat-file', 'blob', blob.decode())
    gov.require(len(data) == reference['size'] and ev._sha(data) == reference['sha256'],
                'Git blob bytes differ: ' + reference['path'])


def _ref(admission, path):
    relative = path.relative_to(admission.group.repository).as_posix()
    gov.relative(relative)
    # Preserve small parsed originals in consumed; stream body/large archives.
    if path.suffix == '.bin' or path.suffix == '.zip':
        size,sha = admission.content_identity(path)
    else:
        data=admission.read(path);size,sha=len(data),ev._sha(data)
    return {'path':relative,'size':size,'sha256':sha}


def _completion(admission, selection_ref):
    group = admission.group
    path = group.repository / gov.COMPLETION
    raw = admission.read(path)
    fresh, identity, host = group.read_path(path)
    gov.require(admission.consumed[path] == (fresh, identity), 'completion identity drift')
    if group.reader is None:
        gov.private_host_boundary(group.repository, identity, host)
    record = ev._json_bytes(raw, 'fixed P06 completion')
    gov.exact(record, 'schema_version kind profile_id workflow_id approval_ref implementation_head '
              'implementation_record independent_check_record final_selection_ref status',
              'pc026-p06-completion-v1', 'ACCEPTED')
    gov.require(gov.ref(record['approval_ref']) == group.allowed[gov.APPROVAL]
                and gov.ref(record['final_selection_ref']) == selection_ref,
                'completion approval/selection binding differs')
    oid = record['implementation_head']
    _commit(group.repository, oid)
    for reference in group.freeze_refs.values():
        _git_ref(group.repository, oid, reference)
    records = []
    for key in ('implementation_record', 'independent_check_record'):
        value = record[key]
        gov.require(isinstance(value, dict) and set(value) == {'ref', 'commit_oid'},
                    'completion record exact keys differ')
        reference = gov.ref(value['ref'])
        # Existing governance and old evidence cannot be repurposed as the two
        # new records. Their substantive acceptance is the controller's duty.
        coordinate = reference['path']
        gov.require(coordinate not in group.allowed and coordinate != gov.COMPLETION
                    and not coordinate.startswith(('Logs/P05/', 'Logs/P06/wf-01a05d1d-p06/',
                                                   'Logs/P06/wf-01a05d1d-p06-r2/', '.tmp/'))
                    and coordinate not in {row['path'] for row in records},
                    'completion records must be distinct new originals')
        gov.require(_ref(admission, group.repository / coordinate) == reference,
                    'completion record Ref bytes differ')
        _commit(group.repository, value['commit_oid'])
        _git_ref(group.repository, value['commit_oid'], reference)
        records.append(reference)
    return _ref(admission, path), records


def _history(raw):
    value = ev._json_bytes(raw, 'historical root index')
    expected = [f'{root}/{name}' for root in ('wf-01a05d1d-p06', 'wf-01a05d1d-p06-r2')
                for name in ('接收清单.jsonl', 'final-selection.json', 'aggregate.json')]
    gov.require(set(value) == {'schema_version', 'roots', 'open_chk'}
                and type(value['schema_version']) is int and value['schema_version'] == 1
                and value['open_chk'] == ['CHK-024', 'CHK-025', 'CHK-026', 'CHK-027']
                and isinstance(value['roots'], list) and len(value['roots']) == 6,
                'historical root index shape differs')
    for row, coordinate in zip(value['roots'], expected):
        gov.require(isinstance(row, dict) and row.get('path') == coordinate
                    and type(row.get('exists')) is bool, 'historical root index coordinate differs')
        if row['exists']:
            gov.require(set(row) == {'path', 'exists', 'size', 'sha256'}, 'historical Ref shape differs')
            gov.ref({k: row[k] for k in ev.REF_KEYS})
        else:
            gov.require(set(row) == {'path', 'exists', 'reason'}
                        and row['reason'] == 'absent when the new evidence epoch was initialized',
                        'historical absence shape differs')


def _selected_run_members(admission, run, root, add):
    """Private shared selected-member mechanism; no completion or publication.

    Every actual run still goes through the public current package admission.
    The outer handoff alone owns selection, completion and output authority.
    """
    gov.require(type(admission) is binding.Admission and type(admission.group) is gov.GovernedGroup,
                'selected member admission differs')
    manifest_path = plain_file(run, package.FINAL_MANIFEST)
    manifest = ev._json_bytes(admission.read(manifest_path), 'package manifest')
    sources = package.member_sources(run, root)
    gov.require(set(sources) == {row['path'] for row in manifest['members']}
                and len(sources) == len(manifest['members']), 'package closure member set differs')
    gov.require(admission.read(manifest_path) == package.canonical_bytes(package.member_inventory(run, root)),
                'package closure inventory differs')
    for row in manifest['members']:
        actual = add(sources[row['path']])
        gov.require((actual['size'], actual['sha256']) == (row['size'], row['sha256']),
                    'package closure member bytes differ')
    return add(manifest_path)


def _derive(admission):
    group = admission.group
    root = group.repository / ROOT_REL
    contract = {'path': gov.HANDOFF_CONTRACT, 'size': 9234, 'sha256': gov.HANDOFF_CONTRACT_SHA}
    group.read(contract)
    selection_path = plain_file(root, 'final-selection.json')
    selection_ref = _ref(admission, selection_path)
    completion_ref, records = _completion(admission, selection_ref)
    fixed = {name: _ref(admission, plain_file(root, name)) for name in FIXED}
    _history(admission.read(root / FIXED[0]))
    for name in ('resource-qualification-selection.json', 'final-selection.json', 'aggregate.json'):
        ev._json_bytes(admission.read(root / name), name)
    for line in admission.read(root / '接收清单.jsonl').splitlines():
        if line:
            row = ev._json_bytes(line, 'receipt ledger line', canonical=False)
            # The strict ledger verifier also reads rejected/failed originals.
            # Retain those read inputs without copying them into selected members.
            report_path = plain_file(root, row['report_relative_path'])
            admission.read(report_path)
            admission.read(plain_file(root, row['manifest_relative_path']))
            for source in package.member_sources(report_path.parent, root).values():
                admission.content_identity(source)
    result = aggregate._aggregate_current(admission)
    gov.require(admission.read(root / 'aggregate.json') == aggregate.canonical_bytes(result),
                'aggregate original bytes differ from current recomputation')
    members = {row['path']: row for row in fixed.values()}

    def add(path):
        reference = _ref(admission, path)
        gov.require(reference['path'] != ROOT_REL + '/' + OUTPUT
                    and (path.is_relative_to(root) or reference in records), 'member outside selected closure')
        previous = members.setdefault(reference['path'], reference)
        gov.require(previous == reference, 'member path conflict')
        return reference

    def run_members(run):
        return _selected_run_members(admission,run,root,add)

    qualification = ev._json_bytes(admission.read(root / 'resource-qualification-selection.json'), 'qualification selection')
    qreport = plain_file(root, qualification['report_relative_path'])
    gov.require(qreport.parent.parent == root / 'resource-qualification' and qreport.name == 'report.json',
                'qualification selected path differs')
    run_members(qreport.parent)
    for name in ('report.json', 'qualification-payload-manifest.json', 'qualification-payload.zip', 'resource-budget.json'):
        add(plain_file(qreport.parent, name))
    index = group.document(group.freeze_refs['tests/data/p06_scenario_index.json'])
    selection = []
    gov.require(len(result['inputs']) == 5, 'current selection must contain five runs')
    by_scenario = {row['scenario']: row for row in result['inputs']}
    gov.require(len(by_scenario) == 5, 'duplicate selected scenario')
    for scenario in index['scenarios']:
        row = by_scenario[scenario['scenario_id']]
        report_path = plain_file(root, row['report_relative_path'])
        gov.require(report_path.relative_to(root).as_posix() == f"{row['scenario']}/{row['run_id']}/report.json",
                    'selected report path/run differs')
        report_ref = add(report_path)
        gov.require(report_ref['sha256'] == row['report_sha256'], 'selected report original differs')
        report = ev._json_bytes(admission.read(report_path), 'selected report', canonical=False)
        snapshot = ev._json_bytes(admission.read(plain_file(report_path.parent, 'snapshot-evidence.json')),
                                  'selected snapshot', canonical=False)
        restore = snapshot['restore']
        gov.require(report['scenario'] == row['scenario'] and report['run_id'] == restore['run_id'] == row['run_id']
                    and restore['restore_attempt_id'] == row['restore_attempt_id'], 'selected run/restore differs')
        manifest_ref = run_members(report_path.parent)
        gov.require(manifest_ref['sha256'] == row['package_sha256'], 'selected package original differs')
        selection.append({'scenario': row['scenario'], 'run_id': row['run_id'],
                          'restore_attempt_id': row['restore_attempt_id'], 'report_ref': report_ref,
                          'package_manifest_ref': manifest_ref})
    gov.require(len(selection) == 5 and len({r['run_id'] for r in selection}) == 5
                and len({r['restore_attempt_id'] for r in selection}) == 5, 'selected identities reused')
    for reference in records:
        add(group.repository / reference['path'])
    state = ev._json_bytes(admission.canonical, 'epoch8 canonical')
    value = {'schema_version': 1, 'kind': 'pc026-p07-handoff-v1', 'profile_id': gov.PROFILE,
             'workflow_id': ev.WORKFLOW_ID, 'contract_ref': contract,
             'approval_ref': group.allowed[gov.APPROVAL], 'implementation_freeze_ref': group.allowed[gov.FREEZE],
             'completion_record_ref': completion_ref, 'epoch8_sha256': ev._sha(admission.canonical),
             'activation_root_sha256': state['activation_evidence']['evidence_sha256'],
             'final_selection_ref': selection_ref, 'aggregate_ref': fixed['aggregate.json'],
             'consumed_selection': selection, 'members': sorted(members.values(), key=lambda r: r['path'].encode('utf-8')),
             'status': 'VERIFIED'}
    admission.recheck()
    return value


def _use(admission, *, create):
    value = _derive(admission)
    raw = ev.canonical_json(value)
    path = admission.group.repository / ROOT_REL / OUTPUT
    package._plain_directory(path.parent)
    if path.exists() or path.is_symlink():
        gov.require(admission.read(path) == raw, 'existing handoff conflicts with derived bytes')
    else:
        gov.require(create, 'fixed handoff is missing')
        admission.recheck()
        gov.before_effect()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
        # POSIX pins the checked parent through the exclusive creation. Windows
        # Admission retains no-delete ancestor handles through publication.
        if os.name == 'posix':
            handles, identities = [], []
            try:
                parent = None
                for name in (path.anchor,) + path.parent.parts[1:]:
                    parent = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                     | os.O_CLOEXEC, dir_fd=parent)
                    handles.append(parent)
                    identities.append(gov.readonly._identity(os.fstat(parent)))
                # Tie the retained publication directory to a consumed ordinary
                # file in that same directory, before creating any output.
                parent_identity = admission.consumed[path.parent / 'aggregate.json'][1][0][-2]
                gov.require(identities[-1] == parent_identity, 'publication parent identity drift')
                admission.recheck()
                with os.fdopen(os.open(OUTPUT, flags, 0o600, dir_fd=parent), 'wb') as stream:
                    stream.write(raw); stream.flush(); os.fsync(stream.fileno())
                os.fsync(parent)
                gov.require(all(gov.readonly._identity(os.fstat(fd)) == identity
                                for fd, identity in zip(handles, identities)), 'publication ancestor drift')
            finally:
                for fd in reversed(handles):
                    os.close(fd)
        else:
            with os.fdopen(os.open(path, flags, 0o600), 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        gov.require(admission.read(path) == raw, 'published handoff bytes differ')
    admission.recheck()
    return value


@gov.consumption
def create():
    return _use(binding.load(), create=True)


@gov.consumption
def verify():
    return _use(binding.load(), create=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true', help='read-only verification of the fixed handoff')
    args = parser.parse_args()
    (verify if args.verify else create)()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
