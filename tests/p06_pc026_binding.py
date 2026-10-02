"""Fixed dual-platform current P06 admission, retaining one fixed approval through use.

No transport token or Windows approval handoff is minted here. The private
group seam is solely for isolated tests; production always uses governance.load.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import uuid

from tests import p05_pc020_evidence as evidence
from tests import p05_pc020_restore as originals
from tests import p05_pc026_governance as governance
from tests import p05_pc026_profile as profiles
from tests import p05_selector_readonly as selector


@dataclass
class Admission:
    group: governance.GovernedGroup
    canonical: bytes
    bindings: selector.ControllerBindings
    consumed: dict = field(default_factory=dict)

    def read(self, path: Path) -> bytes:
        data, identity, _ = self.group.read_path(path)
        previous = self.consumed.setdefault(path, (data, identity))
        governance.require(previous == (data, identity), 'consumer input drift')
        shared = self.group.consumer_inputs.setdefault(path, (data, identity))
        governance.require(shared == (data, identity), 'consumer input drift')
        return data

    def recheck(self):
        self.group.recheck()
        for path, expected in self.consumed.items():
            data, identity, _ = self.group.read_path(path)
            governance.require(expected == (data, identity), 'consumer input drift: ' + str(path))

    def finish_report(self, report):
        try:
            self.recheck()
        except Exception as exc:
            report.update(status='failed', coverage=[], failure={
                'type':type(exc).__name__, 'message':str(exc), 'previous_failure':report.get('failure')})

    def report(self, report, run_dir, root):
        from tests.p06_aggregate_reports import verify_report_shape, verify_tools_schema_binding
        from tests.p06_evidence import plain_file, verify_observation
        from tests.p06_package import member_inventory, member_sources, canonical_bytes
        governance.require(json.loads(self.read(plain_file(run_dir, 'report.json'))) == report,
                           'report changed before consumption')
        governance.require(report.get('schema_version') == 2 and 'baseline_binding' not in report,
                           'current P06 requires restore-bound schema2, not schema3')
        verify_report_shape(report)
        verify_tools_schema_binding(report, run_dir, current=True)
        tools = json.loads(self.read(plain_file(run_dir, 'tools-schema.json')))
        transfer_ref = self.group.freeze_refs['velo_transfer/transfer_tools_schema.json']
        transfer = json.loads(self.group.read(transfer_ref))
        actual_transfer = {row['name']: {k: row[k] for k in ('inputSchema', 'outputSchema')}
                           for row in tools if row['name'].startswith('transfer_')}
        governance.require(actual_transfer == {name: {k: schema[k] for k in ('inputSchema', 'outputSchema')}
            for name, schema in transfer.items()}, 'current transfer schema differs from approval')
        fixture = self.read(plain_file(run_dir, 'fixture-instance.json'))
        governance.require(evidence._sha(fixture) == report['fixture_instance_sha256'],
                           'report fixture-instance hash differs')
        snapshot_bytes = self.read(plain_file(run_dir, 'snapshot-evidence.json'))
        governance.require(evidence._sha(snapshot_bytes) == report['snapshot_evidence_sha256'],
                           'snapshot evidence report hash differs')
        snapshot = json.loads(snapshot_bytes)
        pairs = {'scenario_id': report['scenario'], 'source_sha256': report['source_sha256'],
                 'index_sha256': report['index_sha256'], 'mcp_session_id': report['mcp_session']['id'],
                 'server_instance_id': report['server_identity']['instance_id'],
                 'server_observation_sha256': report['server_observation_sha256']}
        governance.require(set(snapshot) == set(pairs) | {'restore'}
            and all(snapshot[k] == v for k, v in pairs.items()), 'snapshot/report identity differs')
        governance.require(snapshot['restore']['run_id'] == report['run_id']
            and run_dir.name == report['run_id'] and run_dir.parent.name == report['scenario'],
            'report path/run/scenario differs')
        if report['scenario'] in {'resource-qualification', 'individual-acceptance'}:
            name = 'p06_resource_qualification.py' if report['scenario'] == 'resource-qualification' else 'p06_individual_acceptance.py'
            source = self.group.freeze_refs['tests/' + name]
            index_name = 'p03_invocations.json' if report['scenario'] == 'resource-qualification' else 'p06_scenario_index.json'
            index = self.group.freeze_refs['tests/data/' + index_name]
            governance.require(report['coverage'] == [], 'non-scenario acceptance must have zero coverage')
            fixture = self.group.freeze_refs['tests/data/p05_fixture_spec.json']
            governance.require(report['source_sha256'] == source['sha256']
                and report['index_sha256'] == index['sha256']
                and report['fixture_spec_sha256'] == fixture['sha256'],
                'qualification source/index/fixture differs from approval')
        else:
            index_ref = self.group.freeze_refs['tests/data/p06_scenario_index.json']
            index = json.loads(self.group.read(index_ref))
            rows = [row for row in index['scenarios'] if row['scenario_id'] == report['scenario']]
            governance.require(len(rows) == 1 and rows[0]['snapshot_stage'] == 'P06_ACTIVE'
                and rows[0]['required_snapshot'] == profiles.CURRENT.snapshot,
                'current scenario/index does not require 191')
            row = rows[0]
            source = self.group.freeze_refs['tests/scenarios/' + row['path']]
            governance.require(report['index_sha256'] == index_ref['sha256']
                and report['source_sha256'] == row['sha256'] == source['sha256']
                and report['fixture_spec_sha256'] == row['fixture_spec_sha256'],
                'report source/index/fixture differs from approval')
            scenario = json.loads(self.group.read(source))
            governance.require(scenario['required_snapshot'] == profiles.CURRENT.snapshot,
                               'scenario source does not require 191')
        self.restore(snapshot['restore'], root)
        verify_observation(report, run_dir)
        inventory = member_inventory(run_dir, root)
        governance.require(self.read(plain_file(run_dir, 'package-manifest.json')) == canonical_bytes(inventory),
                           'current package identity differs')
        sources = member_sources(run_dir, root)
        governance.require(set(sources) == {row['path'] for row in inventory['members']},
                           'package source set differs')
        for member in inventory['members']:
            data = self.read(sources[member['path']])
            governance.require(len(data) == member['size'] and evidence._sha(data) == member['sha256'],
                               'current package member drift')
        self.recheck()
        return snapshot['restore']

    def restore(self, value: dict, root: Path):
        from tests.p06_evidence import RESTORE_KEYS, plain_file
        state = json.loads(self.canonical)
        governance.require(isinstance(value, dict) and set(value) == RESTORE_KEYS,
                           'current restore exact keys differ')
        expected = {'workflow_id': evidence.WORKFLOW_ID, 'snapshot_stage': 'P06_ACTIVE',
                    'snapshot_name': profiles.CURRENT.snapshot, 'canonical_schema_version': 6,
                    'canonical_epoch': 8, 'canonical_phase': 'NETWORK_ACTIVE',
                    'canonical_sha256': evidence._sha(self.canonical),
                    'checkpoint_marker': state['active_snapshot']['checkpoint_marker']}
        governance.require(all(type(value.get(k)) is type(v) and value[k] == v
                               for k, v in expected.items()), 'current restore identity differs')
        for key in ('run_id', 'restore_attempt_id'):
            governance.require(isinstance(value.get(key), str)
                and str(uuid.UUID(value[key])) == value[key], 'current restore UUID differs')
        kinds = originals.RESTORE_KINDS | {'activation_evidence'}
        records = value['restore_records']
        governance.require(isinstance(records, list) and len(records) == 8,
                           'current restore requires exactly eight kinds')
        paths, declarations, names = {}, {}, set()
        for row in records:
            governance.require(isinstance(row, dict) and set(row) == {'kind', 'path', 'sha256'},
                               'current restore record shape differs')
            kind = row['kind']
            governance.require(kind in kinds and kind not in paths and row['path'] not in names,
                               'duplicate or unknown restore kind/path')
            path = plain_file(root, row['path'])
            governance.require(evidence._sha(self.read(path)) == row['sha256'],
                               'current restore original hash differs')
            paths[kind], declarations[kind] = path, row
            names.add(row['path'])
        governance.require(self.read(paths['canonical_readback']) == self.canonical,
                           'carried canonical differs from governed C8')
        for kind, key in (('pc020_preparation', 'preparation_evidence'),
                          ('pc020_migration', 'migration_evidence'),
                          ('activation_evidence', 'activation_evidence')):
            ref = state[key]
            governance.require(declarations[kind]['path'] == ref['evidence_path']
                and declarations[kind]['sha256'] == ref['evidence_sha256'],
                'carried package does not bind canonical Ref')
            # Complete carried subtrees, including R/S and COMMITTED originals,
            # must equal the already qualified independent governance mirror.
            expected_root = self.bindings.evidence_root / ref['evidence_path']
            expected_tree = evidence._walk(expected_root.parent)
            actual_tree = evidence._walk(paths[kind].parent)
            governance.require(set(actual_tree) == set(expected_tree), 'carried package closure differs')
            for relative, source in expected_tree.items():
                coordinate = source.relative_to(self.group.repository).as_posix()
                governance.require(coordinate in self.group.allowed, 'unapproved carried member')
                governance.require(self.read(actual_tree[relative]) == self.group.read(self.group.allowed[coordinate]),
                                   'carried member differs from approved graph')
        c7 = json.loads(self.bindings.epoch7_canonical)
        originals._bind_epoch7_packages(c7, paths, declarations, self.bindings.policy)
        originals._verify_raw(value, paths, profiles.CURRENT.snapshot, profiles.CURRENT)
        activation = json.loads(self.read(paths['activation_evidence']))
        for phase in [activation['initial'], *activation['candidate_cycles']]:
            governance.require(value['run_id'] != phase['run_id']
                and value['restore_attempt_id'] != phase['restore_attempt_id'], 'P06 reuses a P05 identity')
        self.recheck()
        return paths


def _from_group(group):
    canonical, _, _ = group.read_path(group.repository / governance.CANONICAL)
    bindings = governance.bindings_for(group, canonical)
    selector.qualify(canonical, bindings=bindings, stage='P06_ACTIVE')
    return Admission(group, canonical, bindings)


def load():
    return _from_group(governance.load())
