"""Frozen 136-tool schema evidence: diagnostic and P05 Phase byte domains differ."""
from __future__ import annotations
import hashlib
import json

COUNT = 136
PHASE_SHA256 = 'c9ac2929b125c16391810c196222e6e93730ff1828c841e2ee4aa4be42955575'
DIAGNOSTIC_SHA256 = 'f2dee4a593bc6158c4576cd8e5b36929487901c5e95b7049b40b888765465b57'

def _rows(listing: dict) -> list[dict]:
    if type(listing) is not dict or type(listing.get('tools')) is not list:
        raise ValueError('tools/list shape differs')
    rows=[]
    for item in listing['tools']:
        if type(item) is not dict or type(item.get('name')) is not str or not item['name'] or 'inputSchema' not in item or 'outputSchema' not in item:
            raise ValueError('tools/list row lacks exact dual schema')
        rows.append(item)
    if len(rows)!=COUNT or len({x['name'] for x in rows})!=COUNT:
        raise ValueError('tools/list has missing, extra or duplicate names')
    return sorted(rows,key=lambda x:x['name'])

def _encode(rows: list[dict], *, phase: bool) -> bytes:
    if phase:
        projected=[{'name':x['name'],'inputSchema':x['inputSchema'],'outputSchema':x['outputSchema']} for x in rows]
    else:
        projected=[{'name':x['name'],'input':x['inputSchema'],'output':x['outputSchema']} for x in rows]
    data=json.dumps(projected,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
    return data+b'\n' if phase else data

def validate_current(listing: dict, phase_bytes: bytes, *, diagnostic_bytes: bytes | None = None) -> None:
    rows=_rows(listing)
    phase=_encode(rows,phase=True)
    diagnostic=_encode(rows,phase=False)
    if phase_bytes!=phase or hashlib.sha256(phase).hexdigest()!=PHASE_SHA256:
        raise ValueError('formal Phase schema bytes/identity differ')
    if hashlib.sha256(diagnostic).hexdigest()!=DIAGNOSTIC_SHA256:
        raise ValueError('current diagnostic projection differs')
    if diagnostic_bytes is not None and diagnostic_bytes!=diagnostic:
        raise ValueError('diagnostic projection bytes differ')
