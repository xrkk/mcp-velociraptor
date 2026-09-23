"""Bounded content contract tests using only isolated benign temporary trees."""

import hashlib
import json
import os
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from velo_transfer import (Budget, TransferContentError, capture_sources,
                           create_bundle, prepare_staging, unpack_bundle, validate_sources, verify_tree)
from velo_transfer.manifest import BLOCK_SIZE, canonical_json


def budget(**changes):
    values = dict(max_files=100, max_metadata_bytes=100_000,
                  max_logical_bytes=10_000_000, max_package_bytes=12_000_000,
                  min_free_bytes=0, deadline_monotonic=time.monotonic() + 30)
    values.update(changes)
    return Budget(**values)


class ContentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.work = self.root / "work"
        self.work.mkdir()
        self.dest = self.root / "dest"
        self.dest.mkdir()
        self.budget = budget()

    def package(self, sources):
        manifest = capture_sources(self.source, sources, self.budget, ["benign-fixture"])
        package = self.work / "bundle.zip"
        info = create_bundle(self.source, sources, manifest, package, self.work, self.budget)
        return manifest, info

    def prepared(self, name="final", b=None):
        return prepare_staging(self.dest / name, self.dest, b or self.budget,
            stage_name=".velo-stage-" + os.urandom(8).hex(),
            register_stage=lambda path, identity, parent: True,
            verify_windows_acl=lambda path: True)

    def unpack(self, info, name="new"):
        return unpack_bundle(info["path"], self.work, info["size"], info["sha256"],
                             self.dest / name, self.dest, self.budget,
                             staging=self.prepared(name), verify_windows_acl=lambda path: True)

    def assert_code(self, code, action):
        with self.assertRaises(TransferContentError) as caught:
            action()
        self.assertEqual(caught.exception.code, code)

    def test_roundtrip_unicode_nested_empty_and_random(self):
        (self.source / "零.txt").write_bytes(b"")
        (self.source / "目录" / "子").mkdir(parents=True)
        (self.source / "目录" / "子" / "数据.bin").write_bytes(os.urandom(8193))
        (self.source / "目录" / "空").mkdir()
        specs = [{"absolute_path": str(self.source / "零.txt"), "relative_path": "单独/零.txt"},
                 {"absolute_path": str(self.source / "目录"), "relative_path": "目录"}]
        manifest, info = self.package(specs)
        self.assertEqual(validate_sources(self.source, specs, manifest, self.budget),
                         info["manifest_sha256"])
        self.assertEqual(info["size"], Path(info["path"]).stat().st_size)
        self.assertEqual(info["sha256"], hashlib.sha256(Path(info["path"]).read_bytes()).hexdigest())
        staged = self.unpack(info)
        self.assertEqual(staged["manifest_sha256"], info["manifest_sha256"])
        self.assertEqual((Path(staged["staging_directory"]) / "目录" / "子" / "数据.bin").read_bytes(),
                         (self.source / "目录" / "子" / "数据.bin").read_bytes())
        self.assertTrue((Path(staged["staging_directory"]) / "目录" / "空").is_dir())
        self.assertEqual((self.source / "零.txt").read_bytes(), b"")
        with zipfile.ZipFile(info["path"]) as archive:
            member = archive.getinfo("payload/目录/子/数据.bin")
            self.assertEqual(member.extract_version, 45)  # force_zip64 writes ZIP64 local header

    def test_source_mutation_replace_and_new_directory_member(self):
        folder = self.source / "dir"
        folder.mkdir()
        file = folder / "a.txt"
        file.write_bytes(b"same")
        specs = [{"absolute_path": str(folder), "relative_path": "dir"}]
        manifest = capture_sources(self.source, specs, self.budget)
        file.write_bytes(b"diff")
        self.assert_code("source_changed", lambda: validate_sources(self.source, specs, manifest, self.budget))
        file.write_bytes(b"same")
        manifest = capture_sources(self.source, specs, self.budget)
        replacement = folder / "new.txt"
        replacement.write_bytes(b"same")
        os.replace(replacement, file)
        self.assert_code("source_changed", lambda: validate_sources(self.source, specs, manifest, self.budget))
        manifest = capture_sources(self.source, specs, self.budget)
        (folder / "added.txt").write_bytes(b"x")
        self.assert_code("source_changed", lambda: validate_sources(self.source, specs, manifest, self.budget))

    def test_path_and_budget_public_capture(self):
        file = self.source / "a"
        file.write_bytes(b"abcdef")
        def scan(relative, b=None):
            return capture_sources(self.source,
                [{"absolute_path": str(file), "relative_path": relative}], b or self.budget)
        for path in ("../escape", "/abs", "C:/drive", "a:stream", "CON", "trail. ", "a\\b"):
            self.assert_code("invalid_relative_path", lambda p=path: scan(p))
        self.assert_code("logical_budget_exceeded", lambda: scan("a", budget(max_logical_bytes=5)))
        manifest = scan("a")
        self.assert_code("package_budget_exceeded", lambda: create_bundle(self.source,
            [{"absolute_path": str(file), "relative_path": "a"}], manifest,
            self.work / "too-small.zip", self.work, budget(max_package_bytes=100)))
        self.assertFalse((self.work / "too-small.zip").exists())
        self.assert_code("file_count_exceeded", lambda: scan("nested/a", budget(max_files=1)))
        self.assert_code("metadata_budget_exceeded", lambda: scan("a", budget(max_metadata_bytes=20)))
        self.assert_code("deadline_exceeded", lambda: scan("a", budget(deadline_monotonic=0)))
        self.assert_code("path_collision", lambda: capture_sources(self.source,
            [{"absolute_path": str(file), "relative_path": "A"},
             {"absolute_path": str(file), "relative_path": "a"}], self.budget))
        link = self.source / "link"
        link.symlink_to(file)
        self.assert_code("link_or_reparse", lambda: capture_sources(self.source,
            [{"absolute_path": str(link), "relative_path": "link"}], self.budget))

    def test_zip_negative_public_unpack(self):
        (self.source / "a").write_bytes(b"abc")
        specs = [{"absolute_path": str(self.source / "a"), "relative_path": "a"}]
        manifest, info = self.package(specs)
        original = Path(info["path"])
        def attempt(entries, manifest_override=None, b=None):
            crafted = self.work / ("crafted-" + os.urandom(4).hex() + ".zip")
            raw = canonical_json(manifest_override or manifest)
            with zipfile.ZipFile(crafted, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
                archive.writestr("manifest.json", raw)
                for name, data in entries:
                    archive.writestr(name, data)
            data = crafted.read_bytes()
            return lambda: unpack_bundle(crafted, self.work, len(data), hashlib.sha256(data).hexdigest(),
                                          self.dest / "final", self.dest, b or self.budget,
                                          staging=self.prepared(b=b), verify_windows_acl=lambda path: True)
        self.assert_code("unexpected_zip_member", attempt([("payload/a", b"abc"), ("extra", b"x")]))
        self.assert_code("missing_zip_member", attempt([]))
        self.assert_code("zip_size_mismatch", attempt([("payload/a", b"ab")]))
        self.assert_code("tree_content_mismatch", attempt([("payload/a", b"xyz")]))
        self.assert_code("zip_member_collision", attempt([("payload/a", b"abc"), ("payload/a", b"abc")]))
        self.assert_code("zip_member_collision", attempt([("payload/a", b"abc"), ("payload/A", b"abc")]))
        bad = json.loads(json.dumps(manifest))
        bad["entries"][0]["path"] = "../escape"
        self.assert_code("invalid_relative_path", attempt([("payload/../escape", b"abc")], bad))
        bad_absolute = json.loads(json.dumps(manifest))
        bad_absolute["entries"][0]["path"] = "/absolute"
        self.assert_code("invalid_relative_path", attempt([("payload//absolute", b"abc")], bad_absolute))
        self.assert_code("package_budget_exceeded", attempt([("payload/a", b"abc")], b=budget(max_package_bytes=1)))
        self.assert_code("logical_budget_exceeded", attempt([("payload/a", b"abc")], b=budget(max_logical_bytes=2)))
        self.assert_code("metadata_budget_exceeded", attempt([("payload/a", b"abc")], b=budget(max_metadata_bytes=20)))
        corrupted = self.work / "corrupt.zip"
        corrupted.write_bytes(original.read_bytes()[:-10])
        data = corrupted.read_bytes()
        self.assert_code("invalid_package", lambda: unpack_bundle(corrupted, self.work, len(data),
            hashlib.sha256(data).hexdigest(), self.dest / "final", self.dest, self.budget,
            staging=self.prepared(), verify_windows_acl=lambda path: True))
        self.assertFalse((self.dest / "final").exists())
        self.assertFalse((self.root / "escape").exists())

    def test_destination_link_is_rejected_by_public_unpack(self):
        (self.source / "a").write_bytes(b"abc")
        _, info = self.package([{"absolute_path": str(self.source / "a"), "relative_path": "a"}])
        (self.dest / "link").symlink_to(self.root, target_is_directory=True)
        self.assert_code("link_or_reparse", lambda: prepare_staging(
            self.dest / "link" / "final", self.dest, self.budget,
            stage_name=".velo-stage-link", register_stage=lambda *args: True))
        self.assertFalse((self.root / "final").exists())

    def test_zip_expansion_budget(self):
        contents = b"A" * 10000
        file = self.source / "dense"
        file.write_bytes(contents)
        normal = capture_sources(self.source,
            [{"absolute_path": str(file), "relative_path": "dense"}], self.budget)
        path = self.work / "dense.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", canonical_json(normal))
            archive.writestr("payload/dense", contents)
        data = path.read_bytes()
        self.assert_code("expansion_budget_exceeded", lambda: unpack_bundle(path, self.work,
            len(data), hashlib.sha256(data).hexdigest(), self.dest / "final", self.dest,
            budget(max_expansion_ratio=2),
            staging=self.prepared(b=budget(max_expansion_ratio=2)),
            verify_windows_acl=lambda path: True))
        self.assertFalse((self.dest / "final").exists())

    def test_tree_extra_and_content_change(self):
        (self.source / "a").write_bytes(b"abc")
        manifest, info = self.package([{"absolute_path": str(self.source / "a"), "relative_path": "a"}])
        stage = self.unpack(info)
        root = Path(stage["staging_directory"])
        (root / "extra").mkdir()
        self.assert_code("unexpected_tree_member", lambda: verify_tree(root, manifest, self.budget))
        (root / "extra").rmdir()
        (root / "a").write_bytes(b"xyz")
        self.assert_code("tree_content_mismatch", lambda: verify_tree(root, manifest, self.budget))

    def test_package_hash_disk_cancel_and_dangling_link(self):
        file = self.source / "a"
        file.write_bytes(b"abc")
        specs = [{"absolute_path": str(file), "relative_path": "a"}]
        manifest, info = self.package(specs)
        self.assert_code("package_hash_mismatch", lambda: unpack_bundle(info["path"], self.work,
            info["size"], "0" * 64, self.dest / "final", self.dest, self.budget,
            staging=self.prepared(), verify_windows_acl=lambda path: True))
        self.assert_code("disk_budget_exceeded", lambda: create_bundle(self.source, specs,
            manifest, self.work / "another.zip", self.work, budget(min_free_bytes=1 << 62)))
        def cancelled(): raise TransferContentError("cancelled")
        self.assert_code("cancelled", lambda: validate_sources(self.source, specs, manifest,
            budget(check_cancel=cancelled)))
        dangling = self.source / "dangling"
        dangling.symlink_to(self.source / "absent")
        self.assert_code("link_or_reparse", lambda: capture_sources(self.source,
            [{"absolute_path": str(dangling), "relative_path": "dangling"}], self.budget))
        self.assertFalse((self.dest / "final").exists())

    def test_zip_link_alias_and_extra_directory(self):
        file = self.source / "a"
        file.write_bytes(b"abc")
        manifest = capture_sources(self.source,
            [{"absolute_path": str(file), "relative_path": "a"}], self.budget)
        def crafted(members, changed=None):
            path = self.work / (os.urandom(4).hex() + ".zip")
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("manifest.json", canonical_json(changed or manifest))
                for item in members:
                    archive.writestr(*item)
            contents = path.read_bytes()
            return lambda: unpack_bundle(path, self.work, len(contents),
                hashlib.sha256(contents).hexdigest(), self.dest / "final", self.dest, self.budget,
                staging=self.prepared())
        link_info = zipfile.ZipInfo("payload/a")
        link_info.compress_type = zipfile.ZIP_DEFLATED
        link_info.external_attr = 0o120777 << 16
        self.assert_code("unsupported_zip_member", crafted([(link_info, b"target")]))
        self.assert_code("unexpected_zip_member", crafted([("payload/a", b"abc"),
                                                             ("payload/extra/", b"")]))
        changed = json.loads(json.dumps(manifest))
        changed["entries"][0]["path"] = "A"
        changed["entries"].append(dict(changed["entries"][0], path="a"))
        self.assert_code("path_collision", crafted([("payload/A", b"abc"),
                                                     ("payload/a", b"abc")], changed))
        self.assertFalse((self.dest / "final").exists())

    def test_reads_are_bounded(self):
        (self.source / "a").write_bytes(b"x" * (BLOCK_SIZE + 7))
        specs = [{"absolute_path": str(self.source / "a"), "relative_path": "a"}]
        original = os.fdopen
        seen = []
        class Reader:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): return self
            def __exit__(self, *args): return self.stream.__exit__(*args)
            def read(self, count=-1):
                seen.append(count)
                if count < 0 or count > BLOCK_SIZE: raise AssertionError("unbounded read")
                return self.stream.read(count)
        def guarded(fd, mode, **kwargs):
            stream = original(fd, mode, **kwargs)
            return Reader(stream) if mode == "rb" else stream
        manifest = capture_sources(self.source, specs, self.budget)
        with mock.patch("velo_transfer.manifest.os.fdopen", side_effect=guarded):
            capture_sources(self.source, specs, self.budget)
            info = create_bundle(self.source, specs, manifest,
                                 self.work / "streamed.zip", self.work, self.budget)
        original_zip_read = zipfile.ZipExtFile.read
        def guarded_zip_read(stream, count=-1):
            seen.append(count)
            if count < 0 or count > BLOCK_SIZE:
                raise AssertionError("unbounded ZIP read")
            return original_zip_read(stream, count)
        with mock.patch.object(zipfile.ZipExtFile, "read", guarded_zip_read):
            self.unpack(info, "streamed")
        self.assertGreaterEqual(len(seen), 4)
        self.assertTrue(all(0 <= value <= BLOCK_SIZE for value in seen))

    def test_scandir_stops_at_file_budget(self):
        folder = self.source / "many"
        folder.mkdir()
        for index in range(30):
            (folder / f"{index:02d}").write_bytes(b"x")
        original = os.scandir
        consumed = []
        class Counted:
            def __init__(self, iterator): self.iterator = iterator
            def __enter__(self): return self
            def __exit__(self, *args): self.iterator.close()
            def __iter__(self): return self
            def __next__(self):
                consumed.append(1)
                return next(self.iterator)
        def counted(path):
            return Counted(original(path))
        with mock.patch("velo_transfer.manifest.os.scandir", side_effect=counted):
            self.assert_code("file_count_exceeded", lambda: capture_sources(self.source,
                [{"absolute_path": str(folder), "relative_path": "many"}], budget(max_files=2)))
        self.assertLessEqual(len(consumed), 2)

    def test_zip64_eocd_budget_before_parser_and_valid_zip64(self):
        from velo_transfer import bundle as module
        (self.source / "a").write_bytes(b"abc")
        _, info = self.package([{"absolute_path": str(self.source / "a"), "relative_path": "a"}])
        raw = Path(info["path"]).read_bytes()
        eocd = raw.rfind(b"PK\x05\x06")
        self.assertGreaterEqual(eocd, 0)
        fields = list(__import__("struct").unpack_from("<HHHHIIH", raw, eocd + 4))
        record = __import__("struct").pack("<4sQHHIIQQQQ", b"PK\x06\x06", 44,
            45, 45, 0, 0, fields[2], fields[3], fields[4], fields[5])
        locator = __import__("struct").pack("<4sIQI", b"PK\x06\x07", 0, eocd, 1)
        valid = raw[:eocd] + record + locator + raw[eocd:]
        valid_path = self.work / "valid-zip64.zip"
        valid_path.write_bytes(valid)
        good = self.prepared("zip64")
        result = unpack_bundle(valid_path, self.work, len(valid), hashlib.sha256(valid).hexdigest(),
            self.dest / "zip64", self.dest, self.budget, staging=good, verify_windows_acl=lambda path: True)
        self.assertEqual((Path(result["staging_directory"]) / "a").read_bytes(), b"abc")
        many = self.work / "many.zip"
        with zipfile.ZipFile(many, "w") as archive:
            for index in range(100):
                archive.writestr(f"member-{index:03d}", b"")
        raw = many.read_bytes()
        eocd = raw.rfind(b"PK\x05\x06")
        fields = list(__import__("struct").unpack_from("<HHHHIIH", raw, eocd + 4))
        record = __import__("struct").pack("<4sQHHIIQQQQ", b"PK\x06\x06", 44,
            45, 45, 0, 0, fields[2], fields[3], fields[4], fields[5])
        locator = __import__("struct").pack("<4sIQI", b"PK\x06\x07", 0, eocd, 1)
        fake = __import__("struct").pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 0, 0, 0, 0, 0)
        crafted = raw[:eocd] + record + locator + fake
        bad_path = self.work / "contradictory.zip"
        bad_path.write_bytes(crafted)
        parsed = []
        original = module.zipfile.ZipFile
        class CountZip(original):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                parsed.append(len(self.infolist()))
        tight = budget(max_files=2, max_metadata_bytes=512)
        stage = self.prepared("bounded", tight)
        with mock.patch.object(module.zipfile, "ZipFile", CountZip):
            self.assert_code("invalid_package", lambda: unpack_bundle(bad_path, self.work,
                len(crafted), hashlib.sha256(crafted).hexdigest(), self.dest / "bounded",
                self.dest, tight, staging=stage, verify_windows_acl=lambda path: True))
        self.assertEqual(parsed, [])
        self.assertFalse((self.dest / "bounded").exists())

    def test_staging_registration_precedes_content_and_failure_retains_owner(self):
        (self.source / "a").write_bytes(b"abc")
        _, info = self.package([{"absolute_path": str(self.source / "a"), "relative_path": "a"}])
        name = ".velo-stage-fixed"
        seen = []
        def register(path, identity, parent):
            seen.append((path, identity, parent, list(Path(path).iterdir())))
            return True
        stage = prepare_staging(self.dest / "final", self.dest, self.budget,
            stage_name=name, register_stage=register)
        self.assertEqual(seen[0][3], [])
        self.assertEqual(seen[0][0], stage["staging_directory"])
        self.assert_code("stage_exists", lambda: prepare_staging(self.dest / "final",
            self.dest, self.budget, stage_name=name, register_stage=register))
        bad = self.work / "bad.zip"
        bad.write_bytes(b"broken")
        with self.assertRaises(TransferContentError) as caught:
            unpack_bundle(bad, self.work, 6, hashlib.sha256(b"broken").hexdigest(),
                self.dest / "final", self.dest, self.budget, staging=stage, verify_windows_acl=lambda path: True)
        self.assertEqual(caught.exception.context["stage_path"], stage["staging_directory"])
        self.assertEqual(caught.exception.context["stage_inode"], stage["staging_identity"]["inode"])
        self.assertTrue(caught.exception.context["registered"])
        self.assertTrue(Path(stage["staging_directory"]).exists())
        self.assertFalse((self.dest / "final").exists())
        failure_name = ".velo-stage-registration-failed"
        with self.assertRaises(TransferContentError) as caught:
            prepare_staging(self.dest / "final", self.dest, self.budget,
                stage_name=failure_name, register_stage=lambda *args: False)
        self.assertEqual(caught.exception.code, "stage_registration_failed")
        self.assertFalse(caught.exception.context["registered"])
        self.assertEqual(caught.exception.context["stage_path"], str(self.dest / failure_name))
        self.assertEqual(list((self.dest / failure_name).iterdir()), [])

    def test_space_drop_during_package_and_unpack(self):
        import shutil
        data = os.urandom(2 * BLOCK_SIZE + 123)
        file = self.source / "large"
        file.write_bytes(data)
        specs = [{"absolute_path": str(file), "relative_path": "large"}]
        manifest = capture_sources(self.source, specs, self.budget)
        real_usage = shutil.disk_usage
        calls = []
        def falling(path):
            usage = real_usage(path)
            calls.append(path)
            return type(usage)(usage.total, usage.used, usage.free if len(calls) <= 1 else 0)
        failing_path = self.work / "falling.zip"
        with mock.patch("shutil.disk_usage", side_effect=falling):
            self.assert_code("disk_budget_exceeded", lambda: create_bundle(self.source, specs,
                manifest, failing_path, self.work, self.budget))
        self.assertGreaterEqual(len(calls), 2)
        self.assertFalse(failing_path.exists())
        self.assertEqual(file.read_bytes(), data)
        _, info = self.package(specs)
        stage = self.prepared("space-drop")
        calls.clear()
        def falling_later(path):
            usage = real_usage(path)
            calls.append(path)
            return type(usage)(usage.total, usage.used, usage.free if len(calls) <= 2 else 0)
        with mock.patch("shutil.disk_usage", side_effect=falling_later):
            with self.assertRaises(TransferContentError) as caught:
                unpack_bundle(info["path"], self.work, info["size"], info["sha256"],
                    self.dest / "space-drop", self.dest, self.budget, staging=stage, verify_windows_acl=lambda path: True)
        self.assertEqual(caught.exception.code, "disk_budget_exceeded")
        self.assertGreaterEqual(len(calls), 3)
        self.assertEqual(caught.exception.context["stage_path"], stage["staging_directory"])
        self.assertTrue(Path(stage["staging_directory"]).exists())
        self.assertFalse((self.dest / "space-drop").exists())


if __name__ == "__main__":
    unittest.main()
