"""Fixed SDK source qualification; no SDK patching or production override.

The private byte checker is also exercised on the actual installed host SDK.
Only the governed caller supplies the retained native security reader. A host
hash match alone does not grant deployment or archive authority.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import sys

PIN_PATH = 'docs/observation-sdk-pin.json'
PIN_REF = dict(path=PIN_PATH, size=4196,
    sha256='254cebe59f841d1487b98c9dfcb55fbeebef3a7ff5ab7095549921a88edc4b37')


class SDKQualificationError(Exception):
    """Fixed dependency/source qualification failed, before admission."""


def _require(condition, code):
    if not condition:
        raise SDKQualificationError(code)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _symbol(tree, qualified):
    node = tree
    for name in qualified.split('.'):
        matches = [item for item in node.body
                   if isinstance(item, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                   and item.name == name]
        _require(len(matches) == 1, 'sdk_symbol_missing')
        node = matches[0]
    return node


def _verify_installed(raw, read_source):
    """Internal checker; reader must retain exact source identity and bytes."""
    _require(len(raw) == PIN_REF['size'] and _sha(raw) == PIN_REF['sha256'], 'sdk_pin_drift')
    pin = json.loads(raw)
    _require(set(pin) == set('schema_version kind versions modules protocols signatures status'.split())
             and pin['schema_version'] == 1 and pin['kind'] == 'pc026-observation-sdk-pin-v1'
             and pin['status'] == 'PINNED', 'sdk_pin_schema')
    versions = {key: importlib.metadata.version(key.replace('_', '-'))
                for key in ('mcp', 'mcp_types', 'anyio', 'starlette', 'httpx2')}
    versions['python'] = sys.version.split()[0]
    _require(versions == pin['versions'], 'sdk_version_drift')
    trees = {}
    for row in pin['modules']:
        spec = importlib.util.find_spec(row['module'])
        _require(spec is not None and spec.origin is not None
                 and spec.origin.endswith('.py'), 'sdk_origin_invalid')
        # Do not resolve aliases before the security reader sees the origin:
        # it must itself reject reparse/symlink and ancestor identity changes.
        source = read_source(Path(spec.origin).absolute())
        _require(len(source) == row['size'] and _sha(source) == row['sha256'], 'sdk_source_drift')
        trees[row['module']] = ast.parse(source)
    for row in pin['signatures']:
        symbol = _symbol(trees[row['module']], row['symbol'])
        _require(_sha(ast.dump(symbol, include_attributes=False).encode()) == row['ast_sha256'],
                 'sdk_signature_drift')
    from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS
    _require(sorted(HANDSHAKE_PROTOCOL_VERSIONS) == pin['protocols'], 'sdk_protocol_drift')
    return pin


def _verify_approved_sdk(group):
    """Retain deployed source handles in the one already-owned governed group."""
    _require(group.freeze_refs.get(PIN_PATH) == PIN_REF, 'sdk_pin_not_frozen')
    raw = group.read(PIN_REF)

    def read_source(path):
        data, identity, _ = group.read_path(path)
        prior = group.consumer_inputs.setdefault(path, (data, identity))
        _require(prior == (data, identity), 'sdk_consumption_drift')
        return data

    pin = _verify_installed(raw, read_source)
    group.recheck()
    return pin
