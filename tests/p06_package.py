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


def _activation_directory(evidence_root: Path, record_path: str, *, current: bool = False) -> Path:
    """Return the P05 activation bundle directory named by a restore record."""
    activation = plain_file(evidence_root, record_path)
    bundle = activation.parent
    namespace = 'activation-191' if current else 'activation-188'
    if activation.name != 'activation-evidence.json' or bundle.parent.name != namespace:
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


from tests.p05_pc026_governance import consumption


@consumption
def source_for_member(run_dir: Path, evidence_root: Path, name: str) -> Path:
    """Resolve a frozen archive member to its original source without extraction."""
    _admit_success(run_dir,evidence_root)
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
                _activation_directory(evidence_root, record['path'], current=_current_restore(restore)), attempt
            ).get(name)
            if source is not None:
                return source
        elif record.get('kind') == 'baseline_adoption':
            source = _baseline_adoption_member_sources(
                _baseline_adoption_directory(evidence_root, record['path']), attempt
            ).get(name)
            if source is not None:
                return source
        elif _current_restore(restore) and record.get('kind') in {'pc020_preparation', 'pc020_migration'}:
            prefix = 'restore/' + str(original.parent.relative_to(evidence_root).as_posix()) + '/'
            if name.startswith(prefix):
                return plain_file(original.parent, name[len(prefix):])
        elif name == 'restore/' + record['path']:
            return original
    raise EvidenceError('package member is not declared by the restore evidence')


def _member_sources(run_dir: Path, evidence_root: Path) -> dict[str, Path]:
    """Resolve the complete original set once for a consumption transaction.

    No cross-call cache: later reads still verify bytes and path identities.
    Enumerating an activation tree per member makes full closure reads quadratic.
    """
    _plain_directory(run_dir)
    _plain_directory(evidence_root)
    sources = {}
    for path in run_dir.rglob('*'):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            continue
        relative = path.relative_to(run_dir).as_posix()
        if relative != FINAL_MANIFEST:
            sources['run/' + relative] = plain_file(run_dir, relative)
    snapshot = run_dir / 'snapshot-evidence.json'
    if snapshot.exists():
        restore = json.loads(plain_file(run_dir, snapshot.name).read_bytes())['restore']
        for row in restore['restore_records']:
            original = plain_file(evidence_root, row['path'])
            if row['kind'] == 'activation_evidence':
                sources.update(_activation_member_sources(_activation_directory(
                    evidence_root, row['path'], current=_current_restore(restore)),
                    restore['restore_attempt_id']))
            elif row['kind'] == 'baseline_adoption':
                sources.update(_baseline_adoption_member_sources(_baseline_adoption_directory(
                    evidence_root, row['path']), restore['restore_attempt_id']))
            elif _current_restore(restore) and row['kind'] in {'pc020_preparation', 'pc020_migration'}:
                from tests.p05_pc020_evidence import _walk
                sources.update({'restore/' + p.relative_to(evidence_root).as_posix(): p
                                for p in _walk(original.parent).values()})
            else:
                sources['restore/' + row['path']] = original
    return sources


def _member_inventory(run_dir: Path, evidence_root: Path, *, payload: bool = False) -> dict:
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
                    _activation_directory(evidence_root, record['path'], current=_current_restore(document['restore'])),
                    document['restore'].get('restore_attempt_id'),
                )
            elif record.get('kind') == 'baseline_adoption':
                _add_baseline_adoption_members(
                    members,
                    _baseline_adoption_directory(evidence_root, record['path']),
                    document['restore'].get('restore_attempt_id'),
                )
            elif _current_restore(document['restore']) and record.get('kind') in {'pc020_preparation', 'pc020_migration'}:
                from tests.p05_pc020_evidence import _walk
                for relative, source in _walk(original.parent).items():
                    add('restore/' + source.relative_to(evidence_root).as_posix(), source)
            else:
                add('restore/' + record['path'], original)
    return {'schema_version': 1, 'members': [members[name] for name in
            sorted(members, key=lambda value: value.encode('utf-8'))]}


def _admit_success(run_dir, evidence_root):
    """Fixed current authority; historical coordinates cannot alias current runs."""
    from tests import scenario_runner, p06_pc026_binding
    path=Path(run_dir)/'report.json'
    if not path.exists():return
    report=json.loads(plain_file(run_dir,'report.json').read_bytes())
    if report.get('status') != 'success':return
    current=Path(run_dir).is_relative_to(scenario_runner.P06_REPORT_ROOT)
    snapshot=Path(run_dir)/'snapshot-evidence.json'
    if snapshot.exists():
        value=json.loads(plain_file(run_dir,snapshot.name).read_bytes())
        current=current or _current_restore(value.get('restore',{}))
    if current:
        p06_pc026_binding.load()._report_core(report,Path(run_dir),Path(evidence_root))


def member_sources(run_dir: Path, evidence_root: Path) -> dict[str, Path]:
    from tests.p05_pc026_governance import consumption
    @consumption
    def consume():
        _admit_success(run_dir,evidence_root)
        return _member_sources(run_dir,evidence_root)
    return consume()


def member_inventory(run_dir: Path, evidence_root: Path, *, payload: bool=False) -> dict:
    from tests.p05_pc026_governance import consumption
    @consumption
    def consume():
        _admit_success(run_dir,evidence_root)
        return _member_inventory(run_dir,evidence_root,payload=payload)
    return consume()


def _current_restore(restore: dict) -> bool:
    from tests.p05_pc026_profile import CURRENT
    return (restore.get('canonical_schema_version') == 6 and restore.get('canonical_epoch') == 8
            and restore.get('snapshot_name') == CURRENT.snapshot)


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
