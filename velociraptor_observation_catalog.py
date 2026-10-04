"""Strict bounded attempt catalog, separate from the unchanged PC026 08 codec.

Pure verification proves the supplied chain, not storage EOF or worker exit.
The Windows writer uses the private 09 transaction and accepts only this codec.
"""
from __future__ import annotations

import hashlib
import json
import re

from velociraptor_observation_archive import (
    _encoding_shape, _depth, _pairs, _constant, _key, request_key_sha256,
)
from velociraptor_observation_windows import _RecordTransaction

KIND = 'pc026-observation-attempt-catalog-v1'
REASONS = ('DUPLICATE', 'ACTIVE_LIMIT', 'SEEN_LIMIT', 'BYTE_LIMIT')


class CatalogError(ValueError):
    pass


def _require(ok, message):
    if not ok:
        raise CatalogError(message)


def _exact(value, fields):
    _require(type(value) is dict and set(value) == set(fields.split()), 'catalog exact fields')


def _int(value, minimum=0):
    _require(type(value) is int and value >= minimum, 'catalog integer')


def _sha(value):
    _require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'catalog SHA')


def _ref(value, *, path=True):
    _exact(value, 'path size sha256' if path else 'size sha256')
    _int(value['size']); _sha(value['sha256'])
    if path:
        name = value['path']
        _require(type(name) is str and bool(name) and not any(c in name for c in '\\:\0')
                 and all(p not in ('', '.', '..') for p in name.split('/')), 'catalog Ref path')


def _identity(value):
    _exact(value, 'platform volume_serial file_id owner_sid principal_sid acl_sha256')
    _require(value['platform'] == 'windows', 'catalog Windows identity')
    for field, count in (('volume_serial', 16), ('file_id', 32)):
        _require(type(value[field]) is str and re.fullmatch('[0-9a-f]{'+str(count)+'}', value[field]),
                 'catalog identity encoding')
    from velo_transfer.windows_platform import _canonical_sid
    for field in ('owner_sid', 'principal_sid'):
        _require(type(value[field]) is str and _canonical_sid(value[field]) == value[field], 'catalog SID')
    _sha(value['acl_sha256'])


def _canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode('utf-8')


def _directory(sequence, key):
    return f'r{sequence:012d}-' + request_key_sha256(key)


def _record(value):
    _exact(value, 'schema_version kind sequence previous record_type instance_id payload')
    _require(type(value['schema_version']) is int and value['schema_version'] == 1
             and value['kind'] == KIND, 'catalog version/kind')
    _int(value['sequence']); _require(value['sequence'] <= 99999999, 'catalog filename limit')
    _require(type(value['instance_id']) is str and re.fullmatch('[0-9a-f]{32}', value['instance_id']), 'catalog instance')
    if value['sequence'] == 0:
        _require(value['previous'] is None and value['record_type'] == 'INSTANCE_BEGIN', 'catalog first record')
    else:
        _ref(value['previous'], path=False)
        _require(value['record_type'] != 'INSTANCE_BEGIN', 'catalog repeated instance begin')
    p = value['payload']; kind = value['record_type']
    if kind == 'INSTANCE_BEGIN':
        _exact(p, 'config_ref freeze_ref root_identity')
        _ref(p['config_ref']); _ref(p['freeze_ref']); _identity(p['root_identity'])
    elif kind == 'ATTEMPT_BEGIN':
        _exact(p, 'attempt_sequence key tool arguments_sha256 decision reason')
        _int(p['attempt_sequence'], 1)
        _require(p['attempt_sequence'] <= 999999999999, 'catalog attempt limit')
        _key(p['key']); _require(p['key']['instance_id'] == value['instance_id'], 'catalog parent instance')
        _require(type(p['tool']) is str and bool(p['tool']), 'catalog tool')
        _sha(p['arguments_sha256'])
        _require((p['decision'] == 'NEW' and p['reason'] == 'NONE') or
                 (p['decision'] == 'REJECTED' and p['reason'] in REASONS), 'catalog decision')
    elif kind == 'ACCEPT_ACK':
        _exact(p, 'attempt_sequence accept_ref'); _int(p['attempt_sequence'], 1); _ref(p['accept_ref'])
    elif kind == 'ATTEMPT_END':
        _exact(p, 'attempt_sequence disposition outcome head_ref record_count event_count total_bytes')
        _int(p['attempt_sequence'], 1)
        for field in ('record_count', 'event_count', 'total_bytes'): _int(p[field])
        if p['disposition'] == 'REJECTED':
            _require(p['outcome'] is None and p['head_ref'] is None
                     and not any(p[k] for k in ('record_count', 'event_count', 'total_bytes')), 'catalog rejection end')
        else:
            _require(p['disposition'] in ('COMPLETE', 'FAILED') and p['outcome'] in ('returned', 'raised', 'cancelled'), 'catalog known end')
            _ref(p['head_ref'])
            _require(p['record_count'] <= 100000000 and p['record_count'] == p['event_count'] + 2 and p['total_bytes'] >= p['head_ref']['size'] > 0,
                     'catalog chain counters')
    elif kind == 'INSTANCE_END':
        _exact(p, 'attempt_count accepted_count rejected_count state')
        for field in ('attempt_count', 'accepted_count', 'rejected_count'): _int(p[field])
        _require(p['state'] == 'CLOSED_KNOWN' and p['attempt_count'] == p['accepted_count'] + p['rejected_count'], 'catalog instance end')
    else:
        raise CatalogError('catalog unknown record type')


class CatalogCodec:
    def __init__(self, *, max_records, max_record_bytes, max_total_bytes, max_json_depth):
        for value in (max_records, max_record_bytes, max_total_bytes, max_json_depth): _int(value, 1)
        _require(max_records <= 100000000, 'catalog count filename limit')
        self.max_records, self.max_record_bytes = max_records, max_record_bytes
        self.max_total_bytes, self.max_json_depth = max_total_bytes, max_json_depth

    def parse(self, raw):
        try:
            _require(type(raw) is bytes and len(raw) <= min(self.max_record_bytes, self.max_total_bytes), 'catalog byte budget')
            _depth(raw, self.max_json_depth)
            value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=_constant)
            _record(value); _require(_canonical(value) == raw, 'catalog canonical original')
            return value
        except CatalogError:
            raise
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise CatalogError('catalog invalid original') from exc

    def encode(self, value):
        try:
            _encoding_shape(value, self.max_json_depth); _record(value)
            raw = _canonical(value); self.parse(raw)
            return raw
        except CatalogError:
            raise
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise CatalogError('catalog invalid encoding') from exc

    def verify(self, records):
        head = instance = None
        total = count = accepted = rejected = 0
        attempts, seen = {}, set()
        ended = False
        for raw in records:
            count += 1
            _require(count <= self.max_records and not ended, 'catalog count/terminal boundary')
            row = self.parse(raw); total += len(raw)
            _require(total <= self.max_total_bytes and row['sequence'] == count - 1 and row['previous'] == head, 'catalog chain order/budget')
            if instance is None: instance = row['instance_id']
            _require(instance == row['instance_id'], 'catalog instance drift')
            p, kind = row['payload'], row['record_type']
            if kind == 'ATTEMPT_BEGIN':
                seq = p['attempt_sequence']; _require(seq == len(attempts) + 1, 'catalog attempt sequence')
                key = _canonical(p['key'])
                duplicate = key in seen
                _require((p['reason'] == 'DUPLICATE') == duplicate, 'catalog duplicate classification')
                _require(not duplicate or p['decision'] == 'REJECTED', 'catalog repeated NEW')
                seen.add(key)
                attempts[seq] = [p['decision'], _directory(seq, p['key']), False, False]
                if p['decision'] == 'REJECTED': rejected += 1
            elif kind in ('ACCEPT_ACK', 'ATTEMPT_END'):
                a = attempts.get(p['attempt_sequence'])
                _require(a is not None and not a[3], 'catalog missing BEGIN/repeated END')
                if kind == 'ACCEPT_ACK':
                    _require(a[0] == 'NEW' and not a[2] and p['accept_ref']['path'] == a[1] + '/00000000.json', 'catalog ACK scope/order')
                    a[2] = True; accepted += 1
                else:
                    _require((p['disposition'] == 'REJECTED') == (a[0] == 'REJECTED'), 'catalog END decision')
                    if a[0] == 'NEW':
                        _require(a[2] and p['head_ref']['path'] == a[1] + f"/{p['record_count']-1:08d}.json", 'catalog END head/ACK')
                    a[3] = True
            elif kind == 'INSTANCE_END':
                _require(all(a[3] for a in attempts.values()) and p['attempt_count'] == len(attempts)
                         and p['accepted_count'] == accepted and p['rejected_count'] == rejected, 'catalog incomplete/counts')
                ended = True
            head = dict(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        _require(count > 0, 'catalog empty chain')
        return dict(status='CLOSED_KNOWN' if ended else 'INCOMPLETE', instance_id=instance,
                    head_ref=head, record_count=count, total_bytes=total, attempt_count=len(attempts),
                    accepted_count=accepted, rejected_count=rejected)


class WindowsCatalogPublisher(_RecordTransaction):
    """Finite catalog originals only; a directory input is no approval grant."""
    def __init__(self, directory, *, max_records, max_record_bytes, max_total_bytes, max_json_depth):
        super().__init__(directory, CatalogCodec(max_records=max_records,
            max_record_bytes=max_record_bytes, max_total_bytes=max_total_bytes, max_json_depth=max_json_depth))
