"""Real POSIX package reads; drift/error cases explicitly inject at os.read.

No native-reader patch is used for ordinary content or graph verification.
The Windows preservation writer remains unavailable on POSIX.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tempfile
import tracemalloc
import unittest
from unittest.mock import patch

from tests import p05_pc021_package as pkg
from tests import p05_pc021_package_probe as fixture
from tests import p05_pc021_readonly as readonly
from tests import p05_pc021_streaming as streaming


@unittest.skipUnless(os.name == 'posix', 'POSIX production content-reader tests')
class PortablePackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('PC020_TEST_TEMP_ROOT'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.phase = self.root / 'phase'
        self.phase.mkdir()
        (self.root / 'sentinel.bin').write_bytes(b'external sentinel')

    def member(self, size=150000):
        report, _ = fixture.make_case(self.root)
        report['calls'] = report['calls'][:2]
        chain = pkg.locate_download_chains(report)[0]
        path = self.phase / 'downloads' / pkg.flow_key(chain.flow_id) / chain.file_id / 'content.bin'
        path.parent.mkdir(parents=True)
        digest = hashlib.sha256()
        with path.open('xb') as f:
            remaining = size
            while remaining:
                data = b'x' * min(65536, remaining)
                f.write(data)
                digest.update(data)
                remaining -= len(data)
        report['calls'][0]['structured']['data'][0]['file_size'] = size
        report['calls'][1]['structured'].update(
            size=size, sha256=digest.hexdigest(),
            local_path=r'Z:\absent-source-before-package-transport\content.bin')
        (self.phase / 'report.json').write_bytes(pkg._canonical_json(report))
        return path, report

    def manifest(self, report):
        return pkg.build_phase_manifest(phase_root=self.phase, phase_prefix='phase',
                                        workflow_id=fixture.WORKFLOW_ID, report=report,
                                        report_ref_path='phase/report.json')

    def verify(self, manifest, report):
        pkg.verify_phase_package(phase_root=self.phase, manifest=manifest,
                                 report=report, report_ref_path='phase/report.json')

    def snapshot(self):
        # Attribute-only for special objects, bounded hashing for ordinary files.
        rows = {}
        for p in self.root.rglob('*'):
            info = p.lstat()
            digest = hashlib.sha256()
            if stat.S_ISREG(info.st_mode):
                with p.open('rb') as f:
                    while chunk := f.read(65536): digest.update(chunk)
            rows[p.relative_to(self.root).as_posix()] = (
                info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns, digest.hexdigest())
        return rows

    def test_production_ordinary_empty_large_and_moved_source_without_outputs(self):
        peaks = []
        for size in (0, 150000, 16*1024*1024):
            with self.subTest(size=size):
                if size:
                    # The preceding sample is entirely this test's fixture.
                    import shutil
                    shutil.rmtree(self.phase)
                    self.phase.mkdir()
                path, report = self.member(size)
                before = self.snapshot()
                tracemalloc.start()
                manifest = self.manifest(report)
                self.verify(manifest, report)
                _, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                peaks.append(peak)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(set(manifest), pkg.MANIFEST_KEYS)
                self.assertTrue(all(set(row) == pkg.MEMBER_KEYS for row in manifest['members']))
                self.assertEqual(len(manifest['members']), 2)
                self.assertLess(peak, 2*1024*1024)
                self.assertFalse((self.phase / pkg.MANIFEST_NAME).exists())
        self.assertLess(peaks[-1] - peaks[1], 1024*1024)

    def test_real_leaf_and_ancestor_symlink_refused_without_writes(self):
        path, report = self.member()
        for leaf in (True, False):
            with self.subTest(leaf=leaf):
                link = path if leaf else path.parent
                moved = self.root / ('actual-file' if leaf else 'actual-directory')
                link.rename(moved)
                link.symlink_to(moved, target_is_directory=not leaf)
                before = self.snapshot()
                with self.assertRaises((pkg.PackagePreservationError, streaming.StreamingError)):
                    self.manifest(report)
                self.assertEqual(self.snapshot(), before)
                # Also test the reader itself, independently of tree lstat.
                with self.assertRaises(streaming.StreamingError):
                    streaming.fingerprint(path, pkg.CHUNK_LIMIT)
                link.unlink()
                moved.rename(link)

    def test_real_fifo_directory_socket_refused_without_read_or_outputs(self):
        import socket
        path, report = self.member()
        for kind in ('fifo', 'directory', 'socket'):
            with self.subTest(kind=kind):
                bad = self.phase / kind
                sock = None
                if kind == 'fifo': os.mkfifo(bad)
                elif kind == 'directory': bad.mkdir()
                else:
                    sock = socket.socket(socket.AF_UNIX)
                    sock.bind(str(bad))
                before = self.snapshot()
                with patch.object(readonly.os, 'read', side_effect=AssertionError('special object must not read')):
                    with self.assertRaises(streaming.StreamingError):
                        streaming.fingerprint(bad, pkg.CHUNK_LIMIT)
                self.assertEqual(self.snapshot(), before)
                if sock: sock.close()
                if kind == 'directory': bad.rmdir()
                else: bad.unlink()

    def test_corruption_and_manifest_mutation_reject_without_outputs(self):
        path, report = self.member()
        manifest = self.manifest(report)
        with path.open('r+b') as f: f.write(b'corrupt')
        before = self.snapshot()
        with self.assertRaisesRegex(pkg.PackagePreservationError, 'member bytes differ'):
            self.verify(manifest, report)
        with self.assertRaisesRegex(pkg.PackagePreservationError, 'frozen report'):
            self.manifest(report)
        self.assertEqual(self.snapshot(), before)

    def test_actual_metadata_and_samebytes_path_replacement_drift_refused(self):
        path, report = self.member()
        for fault in ('metadata', 'replacement', 'ancestor'):
            with self.subTest(fault=fault):
                actual_read = os.read
                first = [True]
                before = path.stat()
                replacement = self.root / 'replacement'
                if fault == 'replacement':
                    with path.open('rb') as src, replacement.open('xb') as dst:
                        while chunk := src.read(65536): dst.write(chunk)
                def read(fd, size):
                    chunk = actual_read(fd, size)
                    if first[0]:
                        first[0] = False
                        if fault == 'metadata':
                            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 2000000000))
                        elif fault == 'replacement': replacement.replace(path)
                        else:
                            moved = self.root / 'old-directory'
                            path.parent.rename(moved)
                            path.parent.mkdir()
                            with (moved / path.name).open('rb') as src, path.open('xb') as dst:
                                while copied := src.read(65536): dst.write(copied)
                    return chunk
                with patch.object(readonly.os, 'read', side_effect=read):
                    with self.assertRaisesRegex(streaming.StreamingError, 'drift'):
                        streaming.fingerprint(path, pkg.CHUNK_LIMIT)
                self.assertFalse((self.phase / pkg.MANIFEST_NAME).exists())
                self.assertEqual((self.root / 'sentinel.bin').read_bytes(), b'external sentinel')

    def test_read_short_extra_error_and_close_failures_fail_closed(self):
        path, report = self.member(3)
        for fault in ('short', 'extra', 'error', 'close'):
            with self.subTest(fault=fault):
                before = self.snapshot()
                actual_close = os.close
                def close(fd):
                    actual_close(fd)
                    raise OSError('injected close after actual close')
                if fault == 'close': seam = patch.object(readonly.os, 'close', side_effect=close)
                else:
                    value = {'short': b'', 'extra': b'xxxx'}.get(fault)
                    seam = patch.object(readonly.os, 'read', side_effect=OSError('injected read') if fault == 'error' else None, return_value=value)
                with seam:
                    with self.assertRaises(streaming.StreamingError):
                        streaming.fingerprint(path, pkg.CHUNK_LIMIT)
                self.assertEqual(self.snapshot(), before)

    def test_windows_preservation_still_refuses_posix_before_any_creation(self):
        path, report = self.member()
        before = self.snapshot()
        chain = pkg.locate_download_chains(report)[0]
        with self.assertRaises((pkg.PackagePreservationError, streaming.rb.ReadbackError)):
            pkg.preserve_chain(chain, phase_root=self.root / 'absent-phase',
                               trusted_root=self.root / 'absent-trusted')
        with self.assertRaisesRegex(streaming.rb.ReadbackError, 'Windows-only'):
            streaming._native()
        self.assertEqual(self.snapshot(), before)
        with self.assertRaisesRegex(streaming.StreamingError, 'explicit native'):
            streaming.fingerprint(path, pkg.CHUNK_LIMIT, expected_identity=(0, b'x'))


if __name__ == '__main__':
    unittest.main()
