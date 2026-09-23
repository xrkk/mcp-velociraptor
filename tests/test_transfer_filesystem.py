"""Actual Linux exclusive rename and fail-closed primitive checks."""

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from velo_transfer import (Budget, TransferContentError, capture_sources,
                           create_bundle, prepare_staging, unpack_bundle, verify_tree, publish_directory)
from velo_transfer import filesystem


def budget():
    return Budget(100, 100_000, 1_000_000, 2_000_000, 0, time.monotonic() + 30)


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.src = self.root / "src"
        self.src.mkdir()
        (self.src / "item").write_bytes(b"content")
        self.work = self.root / "work"
        self.work.mkdir()
        self.dest = self.root / "dest"
        self.dest.mkdir()
        self.b = budget()
        specs = [{"absolute_path": str(self.src / "item"), "relative_path": "sub/item"}]
        self.manifest = capture_sources(self.src, specs, self.b)
        info = create_bundle(self.src, specs, self.manifest, self.work / "bundle.zip", self.work, self.b)
        staging = prepare_staging(self.dest / "final", self.dest, self.b,
            stage_name=".velo-stage-" + os.urandom(8).hex(),
            register_stage=lambda path, identity, parent: True,
            verify_windows_acl=lambda path: True)
        self.stage = unpack_bundle(info["path"], self.work, info["size"], info["sha256"],
                                   self.dest / "final", self.dest, self.b, staging=staging,
                                   verify_windows_acl=lambda path: True)

    def publish(self):
        return publish_directory(self.stage["staging_directory"], self.dest / "final",
            self.dest, self.manifest, self.b,
            expected_staging_identity=self.stage["staging_identity"],
            expected_parent_identity=self.stage["parent_identity"])

    @unittest.skipUnless(os.name == "posix", "Linux renameat2 test")
    def test_real_exclusive_directory_publish(self):
        result = self.publish()
        self.assertEqual(result["identity"], self.stage["staging_identity"])
        self.assertEqual((self.dest / "final" / "sub" / "item").read_bytes(), b"content")
        self.assertFalse(Path(self.stage["staging_directory"]).exists())
        self.assertEqual(verify_tree(self.dest / "final", self.manifest, self.b,
                         result["identity"])["identity"], result["identity"])
        (self.dest / "final" / "sub" / "item").write_bytes(b"changed")
        with self.assertRaises(TransferContentError) as caught:
            verify_tree(self.dest / "final", self.manifest, self.b, result["identity"])
        self.assertEqual(caught.exception.code, "tree_content_mismatch")

    @unittest.skipUnless(os.name == "posix", "Linux renameat2 test")
    def test_existing_empty_directory_conflicts_and_preserves_stage(self):
        (self.dest / "final").mkdir()
        with self.assertRaises(TransferContentError) as caught:
            self.publish()
        self.assertEqual(caught.exception.code, "destination_exists")
        self.assertEqual(list((self.dest / "final").iterdir()), [])
        self.assertTrue(Path(self.stage["staging_directory"]).exists())

    def test_primitive_unavailable_and_cross_volume_fail_closed(self):
        with mock.patch.object(filesystem, "_rename_noreplace",
                               side_effect=TransferContentError("atomic_primitive_unavailable")):
            with self.assertRaises(TransferContentError) as caught:
                self.publish()
        self.assertEqual(caught.exception.code, "atomic_primitive_unavailable")
        self.assertFalse((self.dest / "final").exists())
        with mock.patch.object(filesystem, "_same_volume", return_value=False):
            with self.assertRaises(TransferContentError) as caught:
                self.publish()
        self.assertEqual(caught.exception.code, "cross_volume")

    def test_stage_and_parent_identity_changes_refuse_publish(self):
        wrong_stage = dict(self.stage["staging_identity"], inode=-1)
        with self.assertRaises(TransferContentError) as caught:
            publish_directory(self.stage["staging_directory"], self.dest / "final",
                self.dest, self.manifest, self.b,
                expected_staging_identity=wrong_stage,
                expected_parent_identity=self.stage["parent_identity"])
        self.assertEqual(caught.exception.code, "staging_changed")
        wrong_parent = dict(self.stage["parent_identity"], inode=-1)
        with self.assertRaises(TransferContentError) as caught:
            publish_directory(self.stage["staging_directory"], self.dest / "final",
                self.dest, self.manifest, self.b,
                expected_staging_identity=self.stage["staging_identity"],
                expected_parent_identity=wrong_parent)
        self.assertEqual(caught.exception.code, "destination_parent_changed")
        self.assertFalse((self.dest / "final").exists())

    @unittest.skipUnless(os.name == "posix", "Linux renameat2 test")
    def test_post_rename_failure_reports_published_identity_for_recovery(self):
        original = filesystem.verify_tree
        calls = []
        def fail_after_rename(*args, **kwargs):
            calls.append(args[0])
            if len(calls) == 2:
                raise TransferContentError("destination_changed")
            return original(*args, **kwargs)
        with mock.patch.object(filesystem, "verify_tree", side_effect=fail_after_rename):
            with self.assertRaises(TransferContentError) as caught:
                self.publish()
        self.assertEqual(caught.exception.code, "destination_changed")
        self.assertTrue(caught.exception.context["published"])
        self.assertEqual((self.dest / "final" / "sub" / "item").read_bytes(), b"content")

    @unittest.skipUnless(os.name == "nt", "Windows ACL gate requires Windows")
    def test_windows_acl_gate_requires_verifier(self):
        with self.assertRaises(TransferContentError) as caught:
            self.publish()
        self.assertEqual(caught.exception.code, "windows_acl_not_verified")
        self.assertFalse((self.dest / "final").exists())

    @unittest.skipUnless(os.name == "nt", "Windows MoveFileExW real test requires Windows")
    def test_windows_exclusive_publish(self):
        result = publish_directory(self.stage["staging_directory"], self.dest / "final",
            self.dest, self.manifest, self.b,
            expected_staging_identity=self.stage["staging_identity"],
            expected_parent_identity=self.stage["parent_identity"],
            verify_windows_acl=lambda path: True)
        self.assertEqual(result["identity"], self.stage["staging_identity"])


    @unittest.skipUnless(os.name == "nt", "Windows MoveFileExW real test requires Windows")
    def test_windows_existing_empty_and_nonempty_destination_preserved(self):
        for populated in (False, True):
            with self.subTest(populated=populated):
                final = self.dest / "final"
                final.mkdir()
                if populated:
                    (final / "keep").write_bytes(b"original")
                before = sorted((item.name, item.read_bytes() if item.is_file() else None)
                                for item in final.iterdir())
                with self.assertRaises(TransferContentError) as caught:
                    publish_directory(self.stage["staging_directory"], final,
                        self.dest, self.manifest, self.b,
                        expected_staging_identity=self.stage["staging_identity"],
                        expected_parent_identity=self.stage["parent_identity"],
                        verify_windows_acl=lambda path: True)
                self.assertEqual(caught.exception.code, "destination_exists")
                after = sorted((item.name, item.read_bytes() if item.is_file() else None)
                               for item in final.iterdir())
                self.assertEqual(after, before)
                self.assertTrue(Path(self.stage["staging_directory"]).exists())
                for item in final.iterdir():
                    item.unlink()
                final.rmdir()


if __name__ == "__main__":
    unittest.main()
