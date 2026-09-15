"""Canonical evidence member inventory for the reviewed P06 r3 contract.

This module never writes, selects attempts, or declares scenario acceptance.
Callers freeze the returned bytes only after their report lifecycle has ended.
"""

from __future__ import annotations

import hashlib
import json
import stat
import uuid
import zipfile
from pathlib import Path

from tests.p06_evidence import EvidenceError, plain_file


FINAL_MANIFEST = 'package-manifest.json'
PAYLOAD_MANIFEST = 'qualification-payload-manifest.json'
PAYLOAD_EXCLUSIONS = frozenset({
    FINAL_MANIFEST, PAYLOAD_MANIFEST, 'qualification-payload.zip', 'resource-budget.json',
})


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')


def file_identity(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
            size += len(block)
    return size, digest.hexdigest()


def _plain_directory(root: Path) -> None:
    # Check ancestors too: a plain leaf beneath a linked root is not evidence.
    for path in (root, *root.parents):
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or getattr(info, 'st_file_attributes', 0) & 0x400):
            raise EvidenceError('package root contains a link or is not a directory')


def _activation_directory(evidence_root: Path, record_path: str) -> Path:
    """Return the P05 activation bundle directory named by a restore record."""
    activation = plain_file(evidence_root, record_path)
    bundle = activation.parent
    if activation.name != 'activation-evidence.json' or bundle.parent.name != 'activation-188':
        raise EvidenceError('activation restore record is outside the reviewed activation-188 layout')
    try:
        uuid.UUID(bundle.name)
    except (ValueError, AttributeError) as exc:
        raise EvidenceError('activation restore record is not in a UUID bundle directory') from exc
    _plain_directory(bundle)
    try:
        bundle.resolve(strict=True).relative_to(evidence_root.resolve(strict=True))
    except ValueError as exc:
        raise EvidenceError('activation bundle escapes the evidence root') from exc
    return bundle


def _baseline_adoption_directory(evidence_root: Path, record_path: str) -> Path:
    """Return the self-contained user187 adoption bundle named by a restore record."""
    adoption = plain_file(evidence_root, record_path)
    bundle = adoption.parent
    if adoption.name != 'adoption.json' or bundle.parent.name != 'baseline-adoption':
        raise EvidenceError('baseline adoption restore record is outside the reviewed baseline-adoption layout')
    try:
        uuid.UUID(bundle.name)
    except (ValueError, AttributeError) as exc:
        raise EvidenceError('baseline adoption restore record is not in a UUID bundle directory') from exc
    _plain_directory(bundle)
    try:
        bundle.resolve(strict=True).relative_to(evidence_root.resolve(strict=True))
    except ValueError as exc:
        raise EvidenceError('baseline adoption bundle escapes the evidence root') from exc
    return bundle


def _add_activation_members(
    members: dict[str, dict[str, object]],
    bundle: Path,
    restore_attempt_id: object,
) -> None:
    """Carry every P05 activation original under its fixed P06 restore prefix."""
    if (
        not isinstance(restore_attempt_id, str)
        or not restore_attempt_id
        or '/' in restore_attempt_id
        or '\\' in restore_attempt_id
        or restore_attempt_id in {'.', '..'}
    ):
        raise EvidenceError('restore attempt id is not a safe package path component')
    for name, original in _activation_member_sources(bundle, restore_attempt_id).items():
        size, sha = file_identity(original)
        value = {'path': name, 'size': size, 'sha256': sha}
        if name in members and members[name] != value:
            raise EvidenceError('duplicate package member has different bytes')
        members[name] = value


def _add_baseline_adoption_members(
    members: dict[str, dict[str, object]],
    bundle: Path,
    restore_attempt_id: object,
) -> None:
    """Carry every user187 adoption original under its fixed P06 restore prefix."""
    if (
        not isinstance(restore_attempt_id, str)
        or not restore_attempt_id
        or '/' in restore_attempt_id
        or '\\' in restore_attempt_id
        or restore_attempt_id in {'.', '..'}
    ):
        raise EvidenceError('restore attempt id is not a safe package path component')
    for name, original in _baseline_adoption_member_sources(bundle, restore_attempt_id).items():
        size, sha = file_identity(original)
        value = {'path': name, 'size': size, 'sha256': sha}
        if name in members and members[name] != value:
            raise EvidenceError('duplicate package member has different bytes')
        members[name] = value


def _activation_member_sources(bundle: Path, restore_attempt_id: object) -> dict[str, Path]:
    """Map fixed P06 archive names to the original P05 activation bytes."""
    if (
        not isinstance(restore_attempt_id, str)
        or not restore_attempt_id
        or '/' in restore_attempt_id
        or '\\' in restore_attempt_id
        or restore_attempt_id in {'.', '..'}
    ):
        raise EvidenceError('restore attempt id is not a safe package path component')
    sources: dict[str, Path] = {}
    for path in bundle.rglob('*'):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise EvidenceError('activation bundle contains a link or reparse point')
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise EvidenceError('activation bundle contains a special file')
        relative = path.relative_to(bundle).as_posix()
        original = plain_file(bundle, relative)
        name = f'restore/{restore_attempt_id}/activation/{relative}'
        if name in sources and sources[name] != original:
            raise EvidenceError('activation bundle has duplicate member paths')
        sources[name] = original
    return sources


def _baseline_adoption_member_sources(bundle: Path, restore_attempt_id: object) -> dict[str, Path]:
    """Map fixed P06 archive names to the original user187 adoption bytes."""
    if (
        not isinstance(restore_attempt_id, str)
        or not restore_attempt_id
        or '/' in restore_attempt_id
        or '\\' in restore_attempt_id
        or restore_attempt_id in {'.', '..'}
    ):
        raise EvidenceError('restore attempt id is not a safe package path component')
    sources: dict[str, Path] = {}
    for path in bundle.rglob('*'):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise EvidenceError('baseline adoption bundle contains a link or reparse point')
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise EvidenceError('baseline adoption bundle contains a special file')
        relative = path.relative_to(bundle).as_posix()
        original = plain_file(bundle, relative)
        name = f'restore/{restore_attempt_id}/baseline-adoption/{relative}'
        if name in sources and sources[name] != original:
            raise EvidenceError('baseline adoption bundle has duplicate member paths')
        sources[name] = original
    return sources


def source_for_member(run_dir: Path, evidence_root: Path, name: str) -> Path:
    """Resolve a frozen archive member to its original source without extraction."""
    if not isinstance(name, str) or name.startswith('/') or '\\' in name:
        raise EvidenceError('package member path is invalid')
    namespace, separator, relative = name.partition('/')
    if not separator or not relative:
        raise EvidenceError('package member path lacks a namespace or relative path')
    if namespace == 'run':
        return plain_file(run_dir, relative)
    if namespace != 'restore':
        raise EvidenceError('package member has an unknown namespace')
    snapshot = plain_file(run_dir, 'snapshot-evidence.json')
    document = json.loads(snapshot.read_bytes())
    restore = document.get('restore')
    if not isinstance(restore, dict):
        raise EvidenceError('snapshot evidence restore is invalid')
    attempt = restore.get('restore_attempt_id')
    records = restore.get('restore_records')
    if not isinstance(records, list):
        raise EvidenceError('snapshot evidence restore records are invalid')
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get('path'), str):
            raise EvidenceError('restore record is invalid')
        original = plain_file(evidence_root, record['path'])
        if record.get('kind') == 'activation_evidence':
            source = _activation_member_sources(
                _activation_directory(evidence_root, record['path']), attempt
            ).get(name)
            if source is not None:
                return source
        elif record.get('kind') == 'baseline_adoption':
            source = _baseline_adoption_member_sources(
                _baseline_adoption_directory(evidence_root, record['path']), attempt
            ).get(name)
            if source is not None:
                return source
        elif name == 'restore/' + record['path']:
            return original
    raise EvidenceError('package member is not declared by the restore evidence')


def member_inventory(run_dir: Path, evidence_root: Path, *, payload: bool = False) -> dict:
    """Inventory all run bytes and declared original restore files.

    Structural completeness and success requirements are checked by the report
    verifier, not inferred here from the existence of a package manifest.
    """
    _plain_directory(run_dir)
    _plain_directory(evidence_root)
    run_dir.resolve().relative_to(evidence_root.resolve())
    excluded = PAYLOAD_EXCLUSIONS if payload else {FINAL_MANIFEST}
    members = {}

    def add(name: str, path: Path) -> None:
        size, sha = file_identity(path)
        value = {'path': name, 'size': size, 'sha256': sha}
        if name in members and members[name] != value:
            raise EvidenceError('duplicate package member has different bytes')
        members[name] = value

    for path in run_dir.rglob('*'):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise EvidenceError('package contains a link or reparse point')
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise EvidenceError('package contains a special file')
        relative = path.relative_to(run_dir).as_posix()
        original = plain_file(run_dir, relative)
        if relative not in excluded:
            add('run/' + relative, original)

    snapshot = run_dir / 'snapshot-evidence.json'
    if snapshot.exists():
        document = json.loads(plain_file(run_dir, 'snapshot-evidence.json').read_bytes())
        for record in document['restore']['restore_records']:
            original = plain_file(evidence_root, record['path'])
            if file_identity(original)[1] != record['sha256']:
                raise EvidenceError('restore original differs from declared SHA')
            if record.get('kind') == 'activation_evidence':
                _add_activation_members(
                    members,
                    _activation_directory(evidence_root, record['path']),
                    document['restore'].get('restore_attempt_id'),
                )
            elif record.get('kind') == 'baseline_adoption':
                _add_baseline_adoption_members(
                    members,
                    _baseline_adoption_directory(evidence_root, record['path']),
                    document['restore'].get('restore_attempt_id'),
                )
            else:
                add('restore/' + record['path'], original)
    return {'schema_version': 1, 'members': [members[name] for name in
            sorted(members, key=lambda value: value.encode('utf-8'))]}


def verify_manifest(run_dir: Path, evidence_root: Path, *, payload: bool = False) -> str:
    name = PAYLOAD_MANIFEST if payload else FINAL_MANIFEST
    raw = plain_file(run_dir, name).read_bytes()
    expected = canonical_bytes(member_inventory(run_dir, evidence_root, payload=payload))
    if raw != expected:
        raise EvidenceError('package manifest differs from canonical original member inventory')
    return hashlib.sha256(raw).hexdigest()


def verify_payload_zip(run_dir: Path, evidence_root: Path) -> dict:
    """Verify the frozen qualification ZIP without extracting any member."""
    manifest_sha = verify_manifest(run_dir, evidence_root, payload=True)
    manifest_path = plain_file(run_dir, PAYLOAD_MANIFEST)
    document = json.loads(manifest_path.read_bytes())
    size, _ = file_identity(manifest_path)
    expected = {row['path']: row for row in document['members']}
    expected[PAYLOAD_MANIFEST] = {
        'path': PAYLOAD_MANIFEST, 'size': size, 'sha256': manifest_sha,
    }
    archive_path = plain_file(run_dir, 'qualification-payload.zip')
    try:
        with zipfile.ZipFile(archive_path) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            if len(names) != len(set(names)) or set(names) != set(expected):
                raise EvidenceError('qualification ZIP member set differs from payload manifest')
            for entry in entries:
                mode = (entry.external_attr >> 16) & 0xFFFF
                if (entry.is_dir() or stat.S_ISLNK(mode) or entry.flag_bits & 1
                        or stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
                    raise EvidenceError('qualification ZIP member is not an ordinary file')
                declared = expected[entry.filename]
                if entry.file_size != declared['size']:
                    raise EvidenceError('qualification ZIP member length differs')
                digest = hashlib.sha256()
                actual_size = 0
                with archive.open(entry) as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b''):
                        actual_size += len(block)
                        if actual_size > declared['size']:
                            raise EvidenceError('qualification ZIP member exceeds declared length')
                        digest.update(block)
                if actual_size != declared['size'] or digest.hexdigest() != declared['sha256']:
                    raise EvidenceError('qualification ZIP member bytes differ')
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
        raise EvidenceError('qualification ZIP cannot be verified') from exc
    size, sha = file_identity(archive_path)
    return {'payload_sha256': sha, 'evidence_reserve_bytes': size,
            'payload_manifest_sha256': manifest_sha}
