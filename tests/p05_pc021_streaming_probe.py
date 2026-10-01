"""Small owned-directory Windows K13 probe; synthetic reports, no live DFIR.

Modes split native execution into bounded batches. Fault rows explicitly
describe injection after/before real operations, never claim native failure.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tracemalloc
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tests import p05_pc021_package as pkg
from tests import p05_pc021_package_probe as fixture
from tests import p05_pc021_streaming as io


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as f:
        while chunk := f.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


class Trace(io._WindowsIO):
    def __init__(self, source, target, fault, observations):
        super().__init__()
        self.source, self.target, self.fault, self.obs = source, target, fault, observations
        self.paths = {}
        self.original = None
        self.original_live = False
        self.source_reads = self.source_probes = self.source_metas = 0
        self.created = self.part_closed = self.cleanup_started = False
        self.part = None
        self.delete_handle = None

    def _open(self, path, *args):
        h = super()._open(path, *args)
        self.paths[h] = path
        return h

    def open(self, path, directory):
        if path == self.source and not directory:
            self.source_probes += 1
            if self.fault == 'path_binding' and self.source_probes > 1:
                path = self.source.with_name('same-bytes-other-object.bin')
        h = super().open(path, directory)
        self.paths[h] = path
        if path == self.source and self.original is None:
            self.original, self.original_live = h, True
        return h

    def identity(self, h, directory):
        value = super().identity(h, directory)
        change = ((self.fault == 'source_identity' and h == self.original
                   and self.source_reads > 0 and self.original_live)
                  or (self.fault == 'part_identity' and self.paths.get(h) == self.part
                      and self.part_closed)
                  or (self.fault == 'final_identity' and self.paths.get(h) == self.target)
                  or (self.fault == 'cleanup_identity' and h == self.delete_handle)
                  or (self.fault == 'cleanup_parent' and self.cleanup_started
                      and self.paths.get(h) == self.target.parent))
        return (value[0], bytes([value[1][0] ^ 1]) + value[1][1:]) if change else value

    def metadata(self, h):
        value = super().metadata(h)
        if h == self.original and self.original_live:
            standard = io._Standard()
            assert self.info(h, 1, ctypes.byref(standard), ctypes.sizeof(standard))
            self.obs['source_allocation'] = {'logical': standard.size, 'allocated': standard.allocated}
            self.source_metas += 1
            self.obs.setdefault('source_metadata', []).append(list(value))
            if self.fault == 'metadata' and self.source_metas > 1:
                return value[:3] + (value[3] + 1,) + value[4:]
        return value

    def read(self, h):
        value = super().read(h)
        self.obs['max_read'] = max(self.obs.get('max_read', 0), len(value))
        if h == self.original and self.original_live:
            self.source_reads += 1
            if self.source_reads == 1:
                if self.fault == 'read': raise io.StreamingError('injected source read')
                if self.fault == 'short_read': return b''
                if self.fault == 'extra_read': return value + b'x'
                if self.fault == 'oversize_read': return b'x' * (pkg.CHUNK_LIMIT + 1)
                if self.fault == 'native_competition':
                    replacement = self.source.with_name('replacement.bin')
                    ctypes.set_last_error(0)
                    moved = bool(pkg.refresh.MoveFileExW(str(replacement), str(self.source), 9))
                    move_error = ctypes.get_last_error()
                    ctypes.set_last_error(0)
                    writer = self.create(str(self.source), 0x40000000, 7, None, 3, 0x02200000, None)
                    write_error = ctypes.get_last_error()
                    valid_writer = writer not in (None, ctypes.c_void_p(-1).value)
                    if valid_writer: super().close(writer)
                    self.obs['competition'] = {'move_return': moved, 'move_error': move_error,
                                               'write_handle_acquired': valid_writer,
                                               'write_error': write_error}
                    assert not moved and move_error in (5, 32)
                    assert not valid_writer and write_error == 32
        if value and self.fault == 'part_readback' and self.paths.get(h) == self.part and self.part_closed:
            return bytes([value[0] ^ 1]) + value[1:]
        if value and self.fault == 'final_readback' and self.paths.get(h) == self.target:
            return bytes([value[0] ^ 1]) + value[1:]
        return value

    def create_part(self, path):
        stream, h, identity = super().create_part(path)
        self.created, self.part = True, path
        self.paths[h] = path
        self.obs['created_identity'] = [identity[0], identity[1].hex()]
        self.obs['events'].append('create_part')
        api = self
        class Writer:
            def write(self, value):
                api.obs['events'].append('write')
                if api.fault == 'short_write': return len(value) - 1
                return stream.write(value)
            def flush(self):
                api.obs['events'].append('file_flush')
                if api.fault == 'flush': raise OSError('injected file flush')
                return stream.flush()
            def fileno(self): return stream.fileno()
            def close(self):
                api.obs['events'].append('part_close')
                stream.close()
                api.paths.pop(h, None)
                api.part_closed = True
                if api.fault == 'part_close': raise OSError('injected part close after actual close')
        return Writer(), h, identity

    def open_delete(self, path):
        self.cleanup_started = True
        h = super().open_delete(path)
        self.delete_handle = h
        return h

    def delete(self, h):
        self.obs['events'].append('owned_delete')
        if self.fault == 'cleanup_delete': raise io.StreamingError('injected owned cleanup disposition')
        super().delete(h)

    def close(self, h):
        source_close = h == self.original and self.original_live
        if source_close: self.original_live = False
        super().close(h)
        self.paths.pop(h, None)
        if source_close and self.fault == 'source_close':
            raise io.StreamingError('injected source close after actual close')
        if h == self.delete_handle and self.fault == 'cleanup_close':
            raise io.StreamingError('injected cleanup close after actual close')


def prepare(root, name, size=1024, *, sparse=False):
    case = root / ('c%02d' % len(list(root.iterdir())))
    case.mkdir()
    report, sources = fixture.make_case(case)
    report['calls'] = report['calls'][:2]
    chain = pkg.locate_download_chains(report)[0]
    source = pkg.trusted_source_path(case / 'trusted', chain)
    source.parent.mkdir(parents=True)
    with source.open('xb') as f:
        if sparse:
            f.write(b'initial')
        else:
            remaining = size
            while remaining:
                chunk = b'x' * min(65536, remaining)
                f.write(chunk)
                remaining -= len(chunk)
    if sparse:
        result = subprocess.run(['fsutil', 'sparse', 'setflag', str(source)],
                                capture_output=True, timeout=10)
        assert result.returncode == 0, repr(result.stdout + result.stderr)
        with source.open('r+b') as f:
            f.seek(size - 1)
            f.write(b'\0')
        assert source.stat().st_file_attributes & 0x200
    report['calls'][0]['structured']['data'][0]['file_size'] = size
    report['calls'][1]['structured'].update(size=size, sha256=file_hash(source))
    report['calls'][0]['structured']['data'][0]['uploaded_size'] = 7 if sparse else size
    chain = pkg.locate_download_chains(report)[0]
    phase = case / 'p'
    phase.mkdir()
    report_bytes = pkg._canonical_json(report)
    (phase / 'report.json').write_bytes(report_bytes)
    sentinel = case / 'sentinel.bin'
    sentinel.write_bytes(b'external sentinel')
    target = phase / 'downloads' / pkg.flow_key(chain.flow_id) / chain.file_id / 'content.bin'
    return case, source, phase, target, chain, report, report_bytes, sentinel


EXPECTED = {
    'metadata': 'source metadata drift', 'source_identity': 'retained identity drift',
    'path_binding': 'path binding drift', 'read': 'injected source read',
    'short_read': 'count/size/hash', 'extra_read': 'extra source read',
    'oversize_read': 'invalid chunk', 'short_write': 'short part write',
    'flush': 'injected file flush', 'fsync': 'injected file fsync',
    'part_close': 'part close failed', 'source_close': 'streaming close failed',
    'part_readback': 'byte-for-byte', 'part_identity': 'owned part identity changed',
    'final_readback': 'published member size/hash', 'final_identity': 'published identity',
    'publish': 'injected hard link', 'refresh_before': 'injected parent refresh 1',
    'refresh_published': 'injected parent refresh 2', 'refresh_cleaned': 'injected parent refresh 3',
    'cleanup_identity': 'cleanup ownership', 'cleanup_parent': 'identity drift',
    'cleanup_delete': 'injected owned cleanup', 'cleanup_close': 'streaming close failed',
}


def execute(root, name, fault='', size=1024, sparse=False):
    case, source, phase, target, chain, report, report_bytes, sentinel = prepare(root, name, size, sparse=sparse)
    observations = {'case': name, 'events': [], 'fault': fault, 'synthetic_report': True}
    api = Trace(source, target, fault, observations)
    if fault == 'path_binding': source.with_name('same-bytes-other-object.bin').write_bytes(source.read_bytes())
    if fault == 'native_competition': source.with_name('replacement.bin').write_bytes(source.read_bytes())
    other = phase / 'other-attempt.part'
    other.write_bytes(b'other attempt preserved')
    real_refresh = pkg.refresh.windows_refresh_directory
    real_link = pkg.refresh.CreateHardLinkW
    real_fsync = os.fsync
    real_fingerprint = io.fingerprint
    refresh_count = 0
    def refresh(path):
        nonlocal refresh_count
        if api.created and path == target.parent:
            refresh_count += 1
            observations['events'].append('parent_refresh')
            required = {'refresh_before': 1, 'refresh_published': 2, 'refresh_cleaned': 3}.get(fault)
            if refresh_count == required: raise io.StreamingError(f'injected parent refresh {required}')
        return real_refresh(path)
    def link(*args):
        observations['events'].append('native_hardlink')
        if fault == 'publish': raise io.StreamingError('injected hard link before API')
        return real_link(*args)
    def fsync(fd):
        observations['events'].append('file_fsync')
        if fault == 'fsync': raise OSError('injected file fsync')
        return real_fsync(fd)
    def fingerprint(path, *args, **kwargs):
        if path == target: observations['events'].append('final_readback')
        result = real_fingerprint(path, *args, **kwargs)
        if path == target and fault == 'cleanup_parent': api.cleanup_started = True
        return result
    tracemalloc.start()
    error = None
    try:
        with patch.object(io, '_native', return_value=api), patch.object(pkg.refresh, 'windows_refresh_directory', side_effect=refresh), patch.object(pkg.refresh, 'CreateHardLinkW', side_effect=link), patch.object(io.os, 'fsync', side_effect=fsync), patch.object(io, 'fingerprint', side_effect=fingerprint):
            pkg.preserve_chain(chain, phase_root=phase, trusted_root=case / 'trusted')
    except (pkg.PackagePreservationError, io.rb.ReadbackError, OSError, pkg.refresh.Pc022WindowsRefreshError) as exc:
        error = str(exc)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    observations.update(peak_bytes=peak, error=error, target_exists=target.exists(),
                        parts=[p.name for p in target.parent.glob('*.part')],
                        report_frozen=(phase / 'report.json').read_bytes() == report_bytes,
                        sentinel_frozen=sentinel.read_bytes() == b'external sentinel',
                        other_attempt_frozen=other.read_bytes() == b'other attempt preserved')
    assert observations['report_frozen'] and observations['sentinel_frozen'] and observations['other_attempt_frozen']
    assert not (phase / pkg.MANIFEST_NAME).exists()
    assert not api.paths, repr(api.paths)  # every native acquisition relinquished
    if fault in EXPECTED:
        assert error and EXPECTED[fault] in error, (fault, error)
        published = fault in {'final_readback', 'final_identity', 'refresh_published', 'cleanup_identity',
                              'cleanup_parent', 'cleanup_delete', 'cleanup_close', 'refresh_cleaned'}
        assert target.exists() == published, observations
        removed = fault in {'cleanup_close', 'refresh_cleaned'}
        assert bool(observations['parts']) != removed, observations
        if published: assert file_hash(target) == chain.sha256
        observations['kind'] = 'injected_fault'
    else:
        assert error is None, observations
        assert target.exists() and not observations['parts'], observations
        actual_id = pkg.refresh.handle_file_identity(target)
        assert [actual_id[0], actual_id[1].to_bytes(16, 'little').hex()] == observations['created_identity']
        assert observations['max_read'] <= pkg.CHUNK_LIMIT
        ordered = ['file_flush', 'file_fsync', 'part_close', 'parent_refresh',
                   'native_hardlink', 'parent_refresh', 'final_readback', 'owned_delete', 'parent_refresh']
        cursor = iter(observations['events'])
        assert all(any(item == expected for item in cursor) for expected in ordered)
        # The other attempt is preserved, and sealing refuses it. Remove ONLY
        # this fixture's own unrelated test marker before the positive manifest.
        with unittest_rejection(pkg.PackagePreservationError, 'temporary part'):
            pkg.build_phase_manifest(phase_root=phase, phase_prefix='phase', workflow_id=fixture.WORKFLOW_ID,
                                     report=report, report_ref_path='phase/report.json')
        other.unlink()
        manifest = pkg.build_phase_manifest(phase_root=phase, phase_prefix='phase', workflow_id=fixture.WORKFLOW_ID,
                                           report=report, report_ref_path='phase/report.json')
        payload = pkg.persist_phase_manifest(manifest, phase)
        pkg.verify_phase_package(phase_root=phase, manifest=json.loads(payload), report=report,
                                 report_ref_path='phase/report.json')
        observations['kind'] = 'native_success'
        observations['manifest_verified'] = True
    return observations


def unittest_rejection(error, text):
    import unittest
    return unittest.TestCase().assertRaisesRegex(error, text)


def native_safety(root, cross):
    from dataclasses import replace
    rows = []
    for name in ('leaf_junction', 'ancestor_junction', 'above_root_junction',
                 'destination_junction', 'existing_parts', 'native_collision'):
        case, source, phase, target, chain, report, report_bytes, sentinel = prepare(root, name)
        trusted = case / 'trusted'
        external = case / 'external'
        external.mkdir()
        (external / 'content.bin').write_bytes(source.read_bytes())
        def junction(link, destination):
            result = subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(destination)],
                                    capture_output=True, timeout=10)
            assert result.returncode == 0, repr(result.stdout + result.stderr)
        old_parts = []
        if name == 'leaf_junction':
            source.unlink()
            junction(source, external)
        elif name == 'ancestor_junction':
            source.unlink()
            source.parent.rmdir()
            junction(source.parent, external)
        elif name == 'above_root_junction':
            destination = case / 'actual-parent'
            destination.mkdir()
            trusted.rename(destination / 'trusted')
            alias = case / 'alias'
            junction(alias, destination)
            trusted = alias / 'trusted'
            source = trusted / pkg.flow_key(chain.flow_id) / chain.file_id / 'content.bin'
            chain = replace(chain, local_path=str(source))
            report['calls'][1]['structured']['local_path'] = str(source)
            report_bytes = pkg._canonical_json(report)
            (phase / 'report.json').write_bytes(report_bytes)
        elif name == 'destination_junction':
            phase.rename(case / 'actual-phase')
            junction(phase, case / 'actual-phase')
        elif name == 'existing_parts':
            target.parent.mkdir(parents=True)
            for filename in ('.pc021.part', '.pc021.other-attempt.part'):
                p = target.parent / filename
                p.write_bytes(filename.encode())
                old_parts.append(p)
        trace = []
        real_link = pkg.refresh.CreateHardLinkW
        def racing_link(*args):
            target.write_bytes((external / 'content.bin').read_bytes())
            ctypes.set_last_error(0)
            result = real_link(*args)
            trace.append({'return': bool(result), 'winerror': ctypes.get_last_error()})
            return result
        error = None
        try:
            with patch.object(pkg.refresh, 'CreateHardLinkW', side_effect=racing_link) if name == 'native_collision' else patch.object(io, '_native', side_effect=io._WindowsIO):
                pkg.preserve_chain(chain, phase_root=phase, trusted_root=trusted)
        except (pkg.PackagePreservationError, io.rb.ReadbackError, pkg.refresh.Pc022WindowsRefreshError) as exc:
            error = str(exc)
        required = {'leaf_junction': 'reparse', 'ancestor_junction': 'reparse',
                    'above_root_junction': 'reparse', 'destination_junction': 'reparse',
                    'existing_parts': 'unresolved attempt', 'native_collision': 'hard_link'}[name]
        assert error and required in error, (name, error)
        assert sentinel.read_bytes() == b'external sentinel'
        assert (phase / 'report.json').read_bytes() == report_bytes
        assert not (phase / pkg.MANIFEST_NAME).exists()
        assert file_hash(external / 'content.bin') == chain.sha256
        for p in old_parts: assert p.read_bytes() == p.name.encode()
        if name == 'native_collision':
            assert trace == [{'return': False, 'winerror': 183}], trace
            assert file_hash(target) == chain.sha256
            assert len(list(target.parent.glob('*.part'))) == 1
        else:
            assert not target.exists()
        rows.append({'case': name, 'kind': 'native_rejection', 'error': error,
                     'native_api': trace, 'sentinel_report_other_attempt_preserved': True})
    # Cross-volume publication is forbidden; source-to-part streaming is not.
    source = root / 'cross-source.bin'
    source.write_bytes(b'cross-volume-preserved')
    target = cross / 'cross-target.bin'
    assert not target.exists()
    with patch.object(pkg.refresh, 'CreateHardLinkW', side_effect=AssertionError('must not publish')) as api:
        with unittest_rejection(pkg.refresh.Pc022WindowsRefreshError, 'cross_volume'):
            pkg.refresh.windows_publish_hard_link(source, target)
        assert api.call_count == 0
    assert source.read_bytes() == b'cross-volume-preserved' and not target.exists()
    rows.append({'case': 'cross_volume', 'kind': 'native_rejection', 'publication_calls': 0})
    return rows


def main():
    assert os.name == 'nt', 'Windows-only probe'
    root, mode = Path(sys.argv[1]), sys.argv[2]
    assert root.is_dir() and not any(root.iterdir()), 'new empty owned root required'
    rows = []
    if mode == 'positive':
        rows.append(execute(root, 'ordinary', size=2*1024*1024))
        rows.append(execute(root, 'empty', size=0))
        rows.append(execute(root, 'sparse', size=16*1024*1024, sparse=True))
        rows.append(execute(root, 'large', size=16*1024*1024))
        rows.append(execute(root, 'native-sharing', fault='native_competition', size=150000))
        assert rows[3]['peak_bytes'] < 4*1024*1024
        assert rows[3]['peak_bytes'] - rows[0]['peak_bytes'] < 1024*1024
    elif mode == 'safety':
        rows = native_safety(root, Path(sys.argv[3]))
    else:
        assert mode in ('faults-1', 'faults-2')
        faults = list(EXPECTED)
        selected = faults[:12] if mode == 'faults-1' else faults[12:]
        for fault in selected:
            rows.append(execute(root, fault, fault=fault))
    output = {'mode': mode, 'rows': rows, 'failures': 0, 'native_durability_claim': False}
    (root.parent / (mode + '-summary.json')).write_text(json.dumps(output, indent=2), encoding='utf-8')
    print(json.dumps(output, separators=(',', ':')))


if __name__ == '__main__':
    main()
