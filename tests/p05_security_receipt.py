"""Offline consistency check for a pinned P05 security command receipt.

This module never executes the recorded commands or grants Phase admission.
The caller must supply a receipt hash and trusted identities from outside the
package. Native SDK/WFP file Refs are integrity checked but not interpreted.
"""
from __future__ import annotations

import hashlib
import json
import re
import argparse
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

SCHEMA = Path(__file__).parent.parent / 'docs' / 'p05-security-receipt.schema.json'
LABELS = ('service', 'policy', 'acl', 'entry', 'schema', 'network')
HEX = re.compile(r'[0-9a-f]{64}\Z')


class ReceiptError(ValueError):
    """The receipt cannot be used as a consistent offline observation."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(data: bytes, label: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReceiptError(f'{label}: duplicate JSON key')
            result[key] = value
        return result
    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=unique,
                           parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ReceiptError(f'{label}: invalid UTF-8 JSON') from exc
    if type(value) is not dict:
        raise ReceiptError(f'{label}: object required')
    return value


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise ReceiptError(f'{label}: exact keys required')
    return value


def _hash(value: Any, label: str) -> str:
    if type(value) is not str or not HEX.fullmatch(value):
        raise ReceiptError(f'{label}: SHA-256 required')
    return value


def _ref_bytes(root: Path, ref: Any, label: str) -> bytes:
    _exact(ref, {'path', 'size', 'sha256'}, label)
    relative = ref['path']
    if (type(relative) is not str or not relative or '\\' in relative or
            Path(relative).is_absolute() or any(part in ('', '.', '..') for part in relative.split('/'))):
        raise ReceiptError(f'{label}: unsafe relative path')
    if type(ref['size']) is not int or ref['size'] < 0:
        raise ReceiptError(f'{label}: invalid size')
    _hash(ref['sha256'], label)
    path = root
    for part in relative.split('/'):
        path = path / part
        if path.is_symlink():
            raise ReceiptError(f'{label}: symlink')
    if not path.is_file():
        raise ReceiptError(f'{label}: missing regular file')
    data = path.read_bytes()
    if len(data) != ref['size'] or _sha(data) != ref['sha256']:
        raise ReceiptError(f'{label}: byte identity differs')
    return data


def inspect_receipt(bundle_root: Path, receipt_ref: dict[str, Any], *, trust: dict[str, Any]) -> dict[str, Any]:
    """Return checked *receipt observations*, not native provenance or admission.

    ``trust`` must be supplied by an independent caller, never copied from the
    receipt. There is no implicit trust or optional identity field.
    """
    required = {'receipt_sha256', 'collector_sha256', 'collector_instance', 'run_id', 'restore_attempt_id',
                'vm_uuid', 'boot_id', 'server_identity', 'network_evidence_sha256',
                'ready_sha256', 'source_inputs_sha256', 'implementation_sources_sha256',
                'tools_schema_sha256', 'acl_sha256', 'guest_root_sha256',
                'transfer_policy_enabled', 'transfer_policy_sha256', 'fixed_ip',
                'host_source', 'guest_port', 'tools_count', 'command_argv'}
    _exact(trust, required, 'external trust')
    for name in ('receipt_sha256', 'collector_sha256', 'network_evidence_sha256',
                 'ready_sha256', 'source_inputs_sha256', 'implementation_sources_sha256',
                 'tools_schema_sha256', 'acl_sha256', 'guest_root_sha256'):
        _hash(trust[name], f'trust.{name}')
    if type(trust['transfer_policy_enabled']) is not bool:
        raise ReceiptError('trust.transfer_policy_enabled: boolean required')
    if trust['transfer_policy_enabled']:
        _hash(trust['transfer_policy_sha256'], 'trust.transfer_policy_sha256')
    elif trust['transfer_policy_sha256'] is not None:
        raise ReceiptError('disabled transfer policy must have null hash')
    for name in ('collector_instance', 'run_id', 'restore_attempt_id', 'vm_uuid', 'boot_id', 'fixed_ip', 'host_source'):
        if type(trust[name]) is not str or not trust[name]:
            raise ReceiptError(f'trust.{name}: nonempty string required')
    _exact(trust['server_identity'], {'pid', 'instance_id'}, 'trust.server_identity')
    if (type(trust['server_identity']['pid']) is not int or trust['server_identity']['pid'] <= 0 or
            type(trust['server_identity']['instance_id']) is not str or not trust['server_identity']['instance_id'] or
            type(trust['guest_port']) is not int or not 1 <= trust['guest_port'] <= 65535 or
            type(trust['tools_count']) is not int or trust['tools_count'] <= 0):
        raise ReceiptError('external identity/count is invalid')
    _exact(trust['command_argv'], set(LABELS), 'trust.command_argv')
    for label in LABELS:
        argv = trust['command_argv'][label]
        if type(argv) is not list or not argv or any(type(part) is not str or not part for part in argv):
            raise ReceiptError(f'trust.command_argv.{label}: exact nonempty argv required')
    root = Path(bundle_root).resolve(strict=True)
    data = _ref_bytes(root, receipt_ref, 'receipt')
    if receipt_ref['sha256'] != trust['receipt_sha256']:
        raise ReceiptError('receipt is not independently pinned')
    raw = _json(data, 'receipt')
    schema = _json(SCHEMA.read_bytes(), 'receipt schema')
    failures = list(Draft202012Validator(schema).iter_errors(raw))
    if failures:
        raise ReceiptError(f'receipt schema: {failures[0].message}')
    if raw['kind'] != 'p05-security-command-receipt-v1' or type(raw['schema_version']) is not int:
        raise ReceiptError('receipt kind/version differs')
    for name in ('collector_sha256', 'collector_instance', 'run_id', 'restore_attempt_id', 'vm_uuid', 'boot_id',
                 'server_identity', 'network_evidence_sha256', 'ready_sha256',
                 'source_inputs_sha256', 'implementation_sources_sha256', 'tools_schema_sha256'):
        if raw[name] != trust[name]:
            raise ReceiptError(f'{name}: external identity differs')
    originals = raw['native_originals']
    for name in ('sdk', 'wfp'):
        _ref_bytes(root, originals[name], f'native_originals.{name}')
    parsed = {}
    for number, (label, command) in enumerate(zip(LABELS, raw['commands']), 1):
        if (command['sequence'] != number or command['label'] != label or
                command['argv'] != trust['command_argv'][label] or
                command['collector_instance'] != raw['collector_instance'] or
                command['run_id'] != raw['run_id'] or
                command['restore_attempt_id'] != raw['restore_attempt_id'] or
                command['exit_code'] != 0 or command['stderr'] != '' or
                _sha(command['stdout'].encode('utf-8')) != command['stdout_sha256']):
            raise ReceiptError(f'{label}: command envelope differs')
        parsed[label] = _json(command['stdout'].encode('utf-8'), label)
    for label, field in (('service', 'running'), ('policy', 'transfer_enabled'),
                         ('acl', 'approved'), ('network', 'rule_enabled')):
        if type(parsed[label].get(field)) is not bool:
            raise ReceiptError(f'{label}.{field}: boolean required')
    for label, fields in (('service', ('pid',)),
                          ('entry', ('allowed_status', 'missing_bearer_status',
                                     'wrong_bearer_status', 'wrong_host_status', 'wrong_origin_status')),
                          ('schema', ('count', 'unique')),
                          ('network', ('guest_port',))):
        if any(type(parsed[label].get(field)) is not int for field in fields):
            raise ReceiptError(f'{label}: integer field required')
    if parsed['service'] != {'running': True, 'pid': trust['server_identity']['pid'],
                             'instance_id': trust['server_identity']['instance_id'],
                             'vm_uuid': trust['vm_uuid'], 'boot_id': trust['boot_id']}:
        raise ReceiptError('service observation differs')
    if parsed['policy'] != {'transfer_enabled': trust['transfer_policy_enabled'],
                            'transfer_policy_sha256': trust['transfer_policy_sha256']}:
        raise ReceiptError('transfer policy observation differs')
    if parsed['acl'] != {'approved': True, 'acl_sha256': trust['acl_sha256'],
                         'root_sha256': trust['guest_root_sha256']}:
        raise ReceiptError('ACL/root observation differs')
    if parsed['entry'] != {'allowed_status': 200, 'missing_bearer_status': 401,
                           'wrong_bearer_status': 401, 'wrong_host_status': 421,
                           'wrong_origin_status': 403}:
        raise ReceiptError('HTTP status observations differ')
    if parsed['schema'] != {'http_sha256': trust['tools_schema_sha256'],
                            'stdio_sha256': trust['tools_schema_sha256'],
                            'count': trust['tools_count'], 'unique': trust['tools_count']}:
        raise ReceiptError('dual transport schema observation differs')
    if parsed['network'] != {'fixed_ip': trust['fixed_ip'],
                             'host_source': trust['host_source'],
                             'guest_port': trust['guest_port'], 'rule_enabled': True,
                             'network_evidence_sha256': trust['network_evidence_sha256']}:
        raise ReceiptError('network observation differs')
    return {'kind': 'checked-command-receipt-v1', 'run_id': raw['run_id'],
            'restore_attempt_id': raw['restore_attempt_id'], 'observations': parsed,
            'native_original_refs_integrity_checked': True,
            'native_provenance_verified': False, 'phase_admission': False}


def main() -> int:
    parser = argparse.ArgumentParser(description='Inspect a pinned P05 receipt offline')
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--receipt-ref', type=Path, required=True)
    parser.add_argument('--trusted-context', type=Path, required=True)
    args = parser.parse_args()
    try:
        reference = _json(args.receipt_ref.read_bytes(), 'receipt Ref')
        trust = _json(args.trusted_context.read_bytes(), 'trusted context')
        result = inspect_receipt(args.bundle, reference, trust=trust)
    except (OSError, ReceiptError, ValueError) as exc:
        parser.exit(2, f'receipt inspection refused: {exc}\n')
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
