"""Fixed approved archive inputs, outside the implementation freeze.

No environment/root/principal overrides or signing API. Loading owns a complete
GovernedGroup; callers retain it until all archive resources have closed.
"""
from __future__ import annotations

from dataclasses import dataclass
import copy

from tests import p05_pc026_governance as gov
from velociraptor_observation_archive import ArchiveCodec
from velociraptor_observation_catalog import CatalogCodec, _exact, _identity, _int
from velociraptor_observation_namespace import _path

CONTRACT = 'PLAN/2026.10.04-01-PC026-正式归档attempt账契约.md'
CONTRACT_REF = dict(path=CONTRACT, size=23088,
    sha256='d9ba3b368bc70e300fbead2f4e3ffe7af354158659d450bdae4f485000365ceb')
CONFIG = gov.BASE + 'observation-archive-configuration.json'
ROOT_RECORD = gov.BASE + 'observation-namespace-root.json'


@dataclass(frozen=True, slots=True)
class _Configuration:
    group: object
    document: dict
    root_sd: bytes
    codec: ArchiveCodec
    catalog_codec: CatalogCodec


def _budgets(value):
    _exact(value, 'max_attempts max_active max_directories max_catalog_records max_catalog_record_bytes '
           'max_total_archive_bytes max_key_bytes max_seen_key_bytes max_json_depth request_codec')
    for key, count in value.items():
        if key != 'request_codec': _int(count, 1)
    q = value['request_codec']
    _exact(q, 'max_records max_record_bytes max_total_bytes max_json_depth')
    codec = ArchiveCodec(**q)
    A, B, T, C = (value['max_attempts'], q['max_record_bytes'], q['max_total_bytes'], value['max_catalog_record_bytes'])
    gov.require(2 <= q['max_records'] <= 100000000 and T >= 2 * B, 'archive request seal reserve')
    gov.require(value['max_active'] <= A and value['max_directories'] >= A + 2
        and 3*A + 2 <= value['max_catalog_records'] <= 100000000
        and value['max_seen_key_bytes'] >= A * value['max_key_bytes'], 'archive count/key reserves')
    minimum = (3*A + 2)*C + A*T + value['max_active']*B + C
    gov.require(value['max_total_archive_bytes'] >= minimum, 'archive total/pending reserve')
    catalog = CatalogCodec(max_records=value['max_catalog_records'], max_record_bytes=C,
        max_total_bytes=value['max_catalog_records'] * C, max_json_depth=value['max_json_depth'])
    return codec, catalog


def _configuration(group):
    gov.require(group.allowed.get(CONTRACT) == CONTRACT_REF, 'archive adopted contract anchor differs')
    group.read(CONTRACT_REF)
    gov.require(CONFIG in group.allowed and ROOT_RECORD in group.allowed, 'archive fixed inputs absent')
    doc = group.document(group.allowed[CONFIG])
    gov.exact(doc, 'schema_version kind profile_id workflow_id contract_ref deployment_ref '
              'implementation_freeze_ref guest_namespace_root root_identity budgets retention status',
              'pc026-observation-archive-configuration-v1', 'AUTHORIZED')
    gov.require(doc['contract_ref'] == CONTRACT_REF and doc['deployment_ref'] == group.allowed[gov.DEPLOYMENT]
        and doc['implementation_freeze_ref'] == group.approval['implementation_freeze']
        and doc['retention'] == 'KEEP_ALL_NO_AUTO_RECOVERY', 'archive input bindings')
    deployment = group.document(doc['deployment_ref'])
    _identity(doc['root_identity'])
    gov.require(doc['root_identity']['principal_sid'] == deployment['guest_principal_sid'], 'archive principal differs')
    path = _path(doc['guest_namespace_root'])
    gov.require(str(path) == doc['guest_namespace_root'], 'archive root alias')
    # Check the longest possible generated leaf before creating any namespace.
    instance = path / ('i' + '0'*32)
    for directory in (instance, instance/'c', instance/('r'+'9'*12+'-'+'0'*64)):
        _path(directory); _path(directory/('0'*36+'.pending')); _path(directory/'99999999.json')
    root = group.document(group.allowed[ROOT_RECORD])
    gov.exact(root, 'schema_version kind profile_id workflow_id root identity sd_ref',
              'pc026-observation-namespace-root-v1')
    gov.require(root['root'] == str(path) and root['identity'] == doc['root_identity'], 'archive root evidence differs')
    gov.ref(root['sd_ref'])
    sd = group.read(root['sd_ref'])
    gov._windows_descriptor(sd, root['identity']['owner_sid'])
    gov.require(gov.evidence._sha(sd) == root['identity']['acl_sha256'], 'archive root full SD differs')
    gov.require(not {CONFIG, ROOT_RECORD, root['sd_ref']['path']} & set(group.freeze_refs), 'archive cyclic freeze')
    codec, catalog = _budgets(doc['budgets'])
    group.recheck()
    return _Configuration(group, copy.deepcopy(doc), sd, codec, catalog)


def load_approved():
    """Production fixed-root loader; never registers a second close owner."""
    token = gov._CONSUMPTION.set(None)
    group = None
    try:
        group = gov.load()
        return _configuration(group)
    except BaseException as primary:
        if group is not None:
            try: group.close()
            except BaseException: _close_note(primary)
        raise
    finally:
        gov._CONSUMPTION.reset(token)


def _close_note(primary):
    from tests.p05_pc026_windows_reader import _note
    _note(primary, 'archive_governance_close_failed')
