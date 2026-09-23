from __future__ import annotations

import hashlib
import copy
import json
import os
import subprocess
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from unittest.mock import patch

import velociraptor_api
import velociraptor_fixed_tools as fixed
from tests.test_p04_fixed_tools import ARTIFACT, FakeBackend, SPEC, flow_row
from velociraptor_fixed_tools import FixedToolService
from velociraptor_mcp_core import (
    RESULT_ROW_LIMIT,
    AlreadyExistsError,
    BackendError,
    NotFoundError,
    TargetContext,
    error_model,
)


POST_PUBLISH_MESSAGE = (
    "The file was published, but post-publication validation or cleanup failed. "
    "The completed file may remain; do not automatically retry or overwrite it."
)


def protobuf_varints(payload: bytes) -> dict[int, list[int]]:
    fields: dict[int, list[int]] = {}
    index = 0
    while index < len(payload):
        key = 0
        shift = 0
        while True:
            value = payload[index]
            index += 1
            key |= (value & 0x7F) << shift
            if value < 0x80:
                break
            shift += 7
        field, wire = key >> 3, key & 7
        if wire == 0:
            value = 0
            shift = 0
            while True:
                byte = payload[index]
                index += 1
                value |= (byte & 0x7F) << shift
                if byte < 0x80:
                    break
                shift += 7
            fields.setdefault(field, []).append(value)
        elif wire == 2:
            length = 0
            shift = 0
            while True:
                byte = payload[index]
                index += 1
                length |= (byte & 0x7F) << shift
                if byte < 0x80:
                    break
                shift += 7
            index += length
        elif wire == 1:
            index += 8
        elif wire == 5:
            index += 4
        else:
            raise AssertionError(f"unsupported protobuf wire type {wire}")
    return fields


def upload_row(
    name: str,
    *,
    size: int = 7,
    stored: int = 7,
    upload_id: int = 1,
    kind: str | None = None,
    path: str | None = None,
):
    upload = {
        "Path": path or rf"C:\fixture\{name}",
        "Size": size,
        "StoredSize": stored,
        "Components": [
            "clients", "C.one", "collections", "F.file", "uploads",
            "auto", "C:", "fixture", name,
        ],
        "Accessor": "auto",
        "UploadId": upload_id,
    }
    row = {"Upload": upload}
    if kind is not None:
        row["Type"] = kind
    return row


class SparseBackend(FakeBackend):
    def __init__(self):
        super().__init__()
        self.compact = b"ABCDXYZ"
        self.logical = b"\0\0\0ABCD\0\0XYZ\0\0\0\0"
        data = upload_row("sparse.bin", size=16, stored=7, upload_id=8)
        index = upload_row(
            "sparse.bin", size=16, stored=7, upload_id=8,
            kind="idx", path=r"C:\fixture\sparse.bin.idx",
        )
        self.uploads = [data, index]
        self.upload_snapshots = None
        self.upload_reads = 0

    def list_flow_uploads(self, client_id, flow_id):
        self.calls.append(("list_flow_uploads", client_id, flow_id))
        if self.upload_snapshots is None:
            return list(self.uploads)
        index = min(self.upload_reads, len(self.upload_snapshots) - 1)
        self.upload_reads += 1
        return self.upload_snapshots[index]

    def read_vfs_buffer(self, components, *, offset, length, padding):
        value = self.logical if padding else self.compact
        chunk = value[offset : offset + length]
        self.calls.append(
            ("read_vfs_buffer", tuple(components), offset, length, padding, len(chunk))
        )
        return chunk


class FileDeliveryContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp.cleanup()

    def service(self, backend):
        return FixedToolService(
            [SPEC], TargetContext(backend), backend, download_root=self.temp.name
        )

    def test_complete_metadata_is_validated_before_internal_indexes_are_hidden(self):
        backend = FakeBackend()
        backend.uploads = [
            upload_row(f"file-{number}.bin", upload_id=number)
            for number in range(1, 29)
        ]
        backend.uploads[4]["Upload"].update({"Size": 16, "StoredSize": 7})
        index = upload_row(
            "file-5.bin", size=16, stored=7, upload_id=5,
            kind="idx", path=r"C:\fixture\file-5.bin.idx",
        )
        backend.uploads.extend([index, copy.deepcopy(index)])
        result = self.service(backend).list_flow_files("F.file")
        self.assertEqual(len(result.data), 28)
        self.assertEqual(result.warnings, ["sparse_indexes_internal:1"])
        self.assertEqual(
            len([call for call in backend.calls if call[0] == "list_flow_uploads"]), 1
        )
        self.assertFalse(any(call[0] == "read_vfs_buffer" for call in backend.calls))
        self.assertEqual(list(Path(self.temp.name).iterdir()), [])

    def test_natural_idx_is_data_and_exact_duplicates_preserve_first_order(self):
        backend = FakeBackend()
        natural = upload_row("natural.idx", upload_id=30)
        other = upload_row("other.bin", upload_id=31)
        backend.uploads = [natural, dict(natural), other]
        result = self.service(backend).list_flow_files("F.file")
        self.assertEqual(
            [PureWindowsPath(item.original_path).name for item in result.data],
            ["natural.idx", "other.bin"],
        )
        self.assertEqual(result.warnings, [])

    def test_metadata_fail_closed_reasons(self):
        base = upload_row("sparse.bin", size=16, stored=7, upload_id=8)
        index = upload_row(
            "sparse.bin", size=16, stored=7, upload_id=8,
            kind="idx", path=r"C:\fixture\sparse.bin.idx",
        )
        cases = {}
        unknown = upload_row("a.bin")
        unknown["Type"] = "future"
        cases["unsupported_upload_type"] = ([unknown], "unsupported_upload_type")
        non_string = upload_row("a.bin")
        non_string["Type"] = 1
        cases["non_string_type"] = ([non_string], "unsupported_upload_type")
        nested = upload_row("a.bin")
        nested["Upload"]["Type"] = "idx"
        cases["nested_conflict"] = ([nested], "unsupported_upload_type")
        cases["orphan"] = ([index], "invalid_sparse_pair")
        bad_size = upload_row("a.bin")
        bad_size["Upload"]["Size"] = True
        cases["invalid_size"] = ([bad_size], "invalid_file_size")
        negative = upload_row("a.bin")
        negative["Upload"]["StoredSize"] = -1
        cases["negative_size"] = ([negative], "invalid_file_size")
        fractional = upload_row("a.bin")
        fractional["Upload"]["Size"] = 1.0
        cases["fractional_size"] = ([fractional], "invalid_file_size")
        reversed_size = upload_row("a.bin", size=1, stored=2)
        cases["reversed_size"] = ([reversed_size], "invalid_file_size")
        missing_size = upload_row("a.bin")
        del missing_size["Upload"]["Size"]
        cases["missing_size"] = ([missing_size], "invalid_file_size")
        wrong_path = {"Upload": dict(index["Upload"]), "Type": "idx"}
        wrong_path["Upload"]["Path"] = r"C:\fixture\wrong.idx"
        cases["bad_pair"] = ([base, wrong_path], "invalid_sparse_pair")
        exact_collision = copy.deepcopy(index)
        exact_collision["Upload"]["UploadId"] = 9
        cases["exact_selector_collision"] = (
            [base, index, exact_collision],
            "file_selector_conflict",
        )
        natural_collision = upload_row("SPARSE.BIN.IDX", upload_id=9)
        cases["casefold_selector_collision"] = (
            [base, index, natural_collision],
            "file_selector_conflict",
        )
        wrong_scope = upload_row("a.bin")
        wrong_scope["Upload"]["Components"] = list(wrong_scope["Upload"]["Components"])
        wrong_scope["Upload"]["Components"][3] = "F.other"
        cases["wrong_scope"] = ([wrong_scope], "invalid_sparse_pair")
        conflicting_data = copy.deepcopy(base)
        conflicting_data["Upload"]["Path"] = r"C:\fixture\different.bin"
        cases["same_identity_conflicting_data"] = (
            [base, conflicting_data],
            "file_identity_conflict",
        )
        conflicting_index = copy.deepcopy(index)
        conflicting_index["Upload"]["Path"] = r"C:\fixture\different.idx"
        cases["same_identity_conflicting_index"] = (
            [base, index, conflicting_index],
            "invalid_sparse_pair",
        )
        for name, (rows, expected_reason) in cases.items():
            with self.subTest(case=name):
                backend = FakeBackend()
                backend.uploads = rows
                with self.assertRaises(BackendError) as caught:
                    self.service(backend).list_flow_files("F.file")
                self.assertEqual(
                    error_model(caught.exception).details["reason"], expected_reason
                )
                self.assertEqual(
                    len([call for call in backend.calls if call[0] == "list_flow_uploads"]),
                    1,
                )
                self.assertFalse(any(call[0] == "read_vfs_buffer" for call in backend.calls))
                self.assertEqual(list(Path(self.temp.name).iterdir()), [])

    def test_illegal_metadata_after_public_limit_rejects_the_complete_table(self):
        backend = FakeBackend()
        backend.uploads = [
            upload_row(f"row-{index}.bin", upload_id=index)
            for index in range(RESULT_ROW_LIMIT + 1)
        ]
        invalid_index = RESULT_ROW_LIMIT
        backend.uploads[invalid_index]["Type"] = "future"
        with self.assertRaises(BackendError) as caught:
            self.service(backend).list_flow_files("F.file")
        self.assertEqual(error_model(caught.exception).details["reason"], "unsupported_upload_type")
        self.assertEqual(len(backend.uploads), 251)
        self.assertEqual(invalid_index, 250)
        print(json.dumps({"r2_03": {"input_count": 251, "invalid_index": 250}}))

    def test_sparse_download_preflights_compact_then_writes_logical_bytes(self):
        backend = SparseBackend()
        service = self.service(backend)
        listed = service.list_flow_files("F.file")
        result = service.download_flow_file("F.file", listed.data[0].file_id)
        self.assertEqual(result.size, 16)
        self.assertEqual(result.sha256, hashlib.sha256(backend.logical).hexdigest())
        self.assertEqual(Path(result.local_path).read_bytes(), backend.logical)
        reads = [call for call in backend.calls if call[0] == "read_vfs_buffer"]
        self.assertEqual(
            [(call[2], call[4], call[5]) for call in reads],
            [(0, False, 7), (7, False, 0), (0, True, 16), (16, True, 0)],
        )
        self.assertTrue(all(call[3] <= 1024 * 1024 for call in reads))
        self.assertEqual(list(Path(self.temp.name).rglob("*.part")), [])

    def test_sparse_preflight_never_creates_part_and_short_compact_rejects_early(self):
        class ObservedSparseBackend(SparseBackend):
            def __init__(self, root: Path, compact: bytes):
                super().__init__()
                self.root = root
                self.compact = compact
                self.observations = []

            def read_vfs_buffer(self, components, *, offset, length, padding):
                value = self.logical if padding else self.compact
                chunk = value[offset : offset + length]
                self.observations.append(
                    {
                        "padding": padding,
                        "offset": offset,
                        "request_length": length,
                        "returned_length": len(chunk),
                        "part_count": len(list(self.root.rglob("*.part"))),
                    }
                )
                return chunk

        root = Path(self.temp.name)
        good = ObservedSparseBackend(root, b"ABCDXYZ")
        delivered = self.service(good).download_flow_file(
            "F.file", self.service(good).list_flow_files("F.file").data[0].file_id
        )
        self.assertEqual(Path(delivered.local_path).read_bytes(), good.logical)
        compact_reads = [item for item in good.observations if item["padding"] is False]
        self.assertTrue(compact_reads)
        self.assertTrue(all(item["part_count"] == 0 for item in compact_reads))
        print(json.dumps({"r2_04": compact_reads}, sort_keys=True))

        short_root = root / "short"
        short_root.mkdir()
        short = ObservedSparseBackend(short_root, b"ABCDEF")
        service = FixedToolService(
            [SPEC], TargetContext(short), short, download_root=str(short_root)
        )
        file_id = service.list_flow_files("F.file").data[0].file_id
        with self.assertRaises(BackendError) as caught:
            service.download_flow_file("F.file", file_id)
        self.assertEqual(error_model(caught.exception).details["reason"], "size_mismatch")
        self.assertFalse(any(item["padding"] for item in short.observations))
        self.assertEqual(list(short_root.rglob("*.part")), [])
        self.assertEqual(list(short_root.rglob("content.bin")), [])

    def test_logical_and_ordinary_size_mismatch_clean_part_without_publishing(self):
        sparse = SparseBackend()
        sparse.logical = sparse.logical[:-1]
        sparse_service = self.service(sparse)
        sparse_id = sparse_service.list_flow_files("F.file").data[0].file_id
        with self.assertRaises(BackendError) as caught:
            sparse_service.download_flow_file("F.file", sparse_id)
        self.assertEqual(error_model(caught.exception).details["reason"], "size_mismatch")

        ordinary_root = Path(self.temp.name) / "ordinary"
        ordinary_root.mkdir()
        ordinary = FakeBackend()
        ordinary.uploads[0]["Upload"]["Size"] = 8
        ordinary.uploads[0]["Upload"]["StoredSize"] = 8
        service = FixedToolService(
            [SPEC], TargetContext(ordinary), ordinary, download_root=str(ordinary_root)
        )
        file_id = service.list_flow_files("F.file").data[0].file_id
        with self.assertRaises(BackendError) as caught:
            service.download_flow_file("F.file", file_id)
        self.assertEqual(error_model(caught.exception).details["reason"], "size_mismatch")
        for root in (Path(self.temp.name), ordinary_root):
            self.assertEqual(list(root.rglob("*.part")), [])
            self.assertEqual(list(root.rglob("content.bin")), [])

    def test_invalid_vfs_chunks_after_zero_or_one_valid_chunk_never_publish(self):
        class InvalidChunkBackend(FakeBackend):
            def __init__(self, invalid, after_valid):
                super().__init__()
                self.invalid = invalid
                self.after_valid = after_valid

            def read_vfs_buffer(self, components, *, offset, length, padding):
                if self.after_valid and offset == 0:
                    return b"p"
                return self.invalid

        for name, invalid, after_valid in (
            ("nonbytes", "not-bytes", False),
            ("oversize_after_valid", b"x" * (1024 * 1024 + 1), True),
        ):
            with self.subTest(case=name):
                root = Path(self.temp.name) / name
                root.mkdir()
                backend = InvalidChunkBackend(invalid, after_valid)
                service = FixedToolService(
                    [SPEC], TargetContext(backend), backend, download_root=str(root)
                )
                file_id = service.list_flow_files("F.file").data[0].file_id
                with self.assertRaises(BackendError) as caught:
                    service.download_flow_file("F.file", file_id)
                self.assertEqual(
                    error_model(caught.exception).details["reason"], "invalid_vfs_chunk"
                )
                self.assertEqual(list(root.rglob("*.part")), [])
                self.assertEqual(list(root.rglob("content.bin")), [])

    def test_empty_file_and_short_nonempty_chunks_reach_zero_byte_eof(self):
        backend = FakeBackend()
        backend.file_bytes = b""
        backend.uploads = [upload_row("empty.bin", size=0, stored=0)]
        service = self.service(backend)
        file_id = service.list_flow_files("F.file").data[0].file_id
        empty = service.download_flow_file("F.file", file_id)
        self.assertEqual((empty.size, Path(empty.local_path).read_bytes()), (0, b""))

        class ShortBackend(FakeBackend):
            def read_vfs_buffer(self, components, *, offset, length, padding):
                self.calls.append(("read_vfs_buffer", offset, length, padding))
                return self.file_bytes[offset : offset + 2]

        short = ShortBackend()
        second_root = Path(self.temp.name) / "second"
        second_root.mkdir()
        second = FixedToolService(
            [SPEC], TargetContext(short), short, download_root=str(second_root)
        )
        second_id = second.list_flow_files("F.file").data[0].file_id
        delivered = second.download_flow_file("F.file", second_id)
        self.assertEqual(Path(delivered.local_path).read_bytes(), b"payload")
        self.assertEqual(
            [call[1] for call in short.calls if call[0] == "read_vfs_buffer"],
            [0, 2, 4, 6, 7],
        )

    def test_link_and_fsync_failures_publish_nothing_and_clean_owned_part(self):
        for seam in ("link", "fsync"):
            with self.subTest(seam=seam):
                root = Path(self.temp.name) / seam
                root.mkdir()
                backend = FakeBackend()
                service = FixedToolService(
                    [SPEC], TargetContext(backend), backend, download_root=str(root)
                )
                file_id = service.list_flow_files("F.file").data[0].file_id
                target = "velociraptor_fixed_tools.os.link" if seam == "link" else "velociraptor_fixed_tools.os.fsync"
                with patch(target, side_effect=OSError("injected")):
                    with self.assertRaises(BackendError):
                        service.download_flow_file("F.file", file_id)
                self.assertEqual(list(root.rglob("content.bin")), [])
                self.assertEqual(list(root.rglob("*.part")), [])

    def test_cleanup_failure_is_split_before_and_after_publish(self):
        original_unlink = Path.unlink

        def run_case(root: Path, backend: FakeBackend):
            service = FixedToolService(
                [SPEC], TargetContext(backend), backend, download_root=str(root)
            )
            file_id = service.list_flow_files("F.file").data[0].file_id
            attempts = []

            def injected_unlink(path, *args, **kwargs):
                if path.suffix == ".part":
                    attempts.append(str(path))
                    raise OSError("injected owned temp cleanup failure")
                return original_unlink(path, *args, **kwargs)

            with self.assertLogs(fixed.__name__, level="WARNING") as logs:
                with patch.object(Path, "unlink", injected_unlink):
                    with self.assertRaises(BackendError) as caught:
                        service.download_flow_file("F.file", file_id)
            self.assertEqual(len(attempts), 1)
            self.assertIn("download_temp_cleanup_failed", "\n".join(logs.output))
            return error_model(caught.exception), attempts

        before_root = Path(self.temp.name) / "before"
        before_root.mkdir()
        backend = FakeBackend()
        backend.fail_vfs_at = len(backend.file_bytes)
        before_model, _ = run_case(before_root, backend)
        self.assertEqual(before_model.details["reason"], "OSError")
        self.assertEqual(list(before_root.rglob("content.bin")), [])
        self.assertEqual(len(list(before_root.rglob("*.part"))), 1)

        after_root = Path(self.temp.name) / "after"
        after_root.mkdir()
        after_model, _ = run_case(after_root, FakeBackend())
        self.assertEqual(after_model.details["reason"], "download_post_publish_failed")
        self.assertEqual(after_model.message, POST_PUBLISH_MESSAGE)
        self.assertFalse(after_model.retryable)
        self.assertEqual(len(list(after_root.rglob("content.bin"))), 1)
        self.assertEqual(len(list(after_root.rglob("*.part"))), 1)

    def test_cleanup_rejects_untrusted_parent_and_wrong_identity_without_unlink(self):
        root = Path(self.temp.name).resolve()
        parent = root / "owned"
        parent.mkdir()
        sentinel = root / "sentinel.bin"
        sentinel.write_bytes(b"sentinel")
        other = parent / ".other.part"
        other.write_bytes(b"other")
        temp = parent / ".request.part"
        temp.write_bytes(b"request")
        info = temp.lstat()
        identity = (info.st_dev, info.st_ino)
        original_contained = fixed._assert_contained
        original_unlink = Path.unlink
        unlink_calls = []

        def reject_parent(candidate_root, candidate, *, strict):
            if candidate == parent:
                raise BackendError(
                    details={"operation": "download_flow_file", "reason": "path_escape"}
                )
            return original_contained(candidate_root, candidate, strict=strict)

        def observed_unlink(path, *args, **kwargs):
            unlink_calls.append(str(path))
            return original_unlink(path, *args, **kwargs)

        with patch.object(fixed, "_assert_contained", reject_parent), patch.object(
            Path, "unlink", observed_unlink
        ):
            self.assertFalse(fixed._cleanup_owned_temp(root, parent, temp, identity))
        self.assertEqual(unlink_calls, [])
        self.assertTrue(temp.exists())

        with patch.object(Path, "unlink", observed_unlink):
            self.assertFalse(
                fixed._cleanup_owned_temp(root, parent, temp, (identity[0], identity[1] + 1))
            )
        self.assertEqual(unlink_calls, [])
        self.assertEqual(sentinel.read_bytes(), b"sentinel")
        self.assertEqual(other.read_bytes(), b"other")
        self.assertEqual(temp.read_bytes(), b"request")

    def test_metadata_drift_and_unknown_index_id_publish_nothing(self):
        backend = SparseBackend()
        service = self.service(backend)
        listed = service.list_flow_files("F.file")
        changed = copy.deepcopy(backend.uploads)
        changed[0]["Upload"]["Path"] = r"C:\fixture\changed.bin"
        changed[1]["Upload"]["Path"] = r"C:\fixture\changed.bin.idx"
        backend.upload_snapshots = [backend.uploads, changed]
        with self.assertRaises(BackendError) as caught:
            service.download_flow_file("F.file", listed.data[0].file_id)
        self.assertEqual(error_model(caught.exception).details["reason"], "metadata_changed")
        self.assertEqual(list(Path(self.temp.name).rglob("content.bin")), [])
        self.assertEqual(list(Path(self.temp.name).rglob("*.part")), [])
        with self.assertRaises(NotFoundError):
            service.download_flow_file("F.file", "f" * 64)

    def test_post_publish_validation_failure_keeps_completed_file(self):
        backend = FakeBackend()
        service = self.service(backend)
        file_id = service.list_flow_files("F.file").data[0].file_id
        original = Path.resolve
        calls = {"content": 0}

        def injected(path, *args, **kwargs):
            if path.name == "content.bin":
                calls["content"] += 1
                raise OSError("injected post-publish failure")
            return original(path, *args, **kwargs)

        with patch.object(Path, "resolve", injected):
            with self.assertRaises(BackendError) as caught:
                service.download_flow_file("F.file", file_id)
        model = error_model(caught.exception)
        self.assertEqual(model.details["reason"], "download_post_publish_failed")
        self.assertEqual(model.message, POST_PUBLISH_MESSAGE)
        self.assertEqual(model.code, "BACKEND_ERROR")
        self.assertFalse(model.retryable)
        self.assertNotIn(str(self.temp.name), model.message)
        self.assertNotIn("injected", model.message)
        completed = list(Path(self.temp.name).rglob("content.bin"))
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0].read_bytes(), backend.file_bytes)
        self.assertEqual(list(Path(self.temp.name).rglob("*.part")), [])

    def test_pre_publish_path_recheck_failure_cleans_part_and_publishes_nothing(self):
        backend = FakeBackend()
        service = self.service(backend)
        file_id = service.list_flow_files("F.file").data[0].file_id
        original = fixed._assert_safe_chain

        def injected(root, *paths):
            if any(path.suffix == ".part" for path in paths):
                raise BackendError(
                    details={"operation": "download_flow_file", "reason": "path_escape"}
                )
            return original(root, *paths)

        with patch.object(fixed, "_assert_safe_chain", injected):
            with self.assertRaises(BackendError) as caught:
                service.download_flow_file("F.file", file_id)
        self.assertEqual(error_model(caught.exception).details["reason"], "path_escape")
        self.assertEqual(list(Path(self.temp.name).rglob("content.bin")), [])
        self.assertEqual(list(Path(self.temp.name).rglob("*.part")), [])

    @unittest.skipUnless(os.name == "nt", "Windows NTFS hard-link competition")
    def test_two_requests_reach_real_ntfs_link_and_exactly_one_publishes(self):
        backend = FakeBackend()
        service = self.service(backend)
        file_id = service.list_flow_files("F.file").data[0].file_id
        real_link = os.link
        barrier = threading.Barrier(2, timeout=15)
        link_entries = []
        entry_lock = threading.Lock()

        def synchronized_link(source, destination, *args, **kwargs):
            with entry_lock:
                link_entries.append(str(source))
                part_count = len(list(Path(self.temp.name).rglob("*.part")))
            barrier.wait()
            self.assertEqual(part_count, 2)
            return real_link(source, destination, *args, **kwargs)

        def request():
            try:
                value = service.download_flow_file("F.file", file_id)
                return {"code": "SUCCESS", "sha256": value.sha256}
            except Exception as exc:
                model = error_model(exc)
                return {"code": model.code, "reason": model.details.get("reason")}

        with patch.object(fixed.os, "link", synchronized_link):
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(lambda _: request(), range(2)))
        self.assertEqual(len(link_entries), 2)
        self.assertEqual(sorted(item["code"] for item in results), ["ALREADY_EXISTS", "SUCCESS"])
        completed = list(Path(self.temp.name).rglob("content.bin"))
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0].read_bytes(), backend.file_bytes)
        self.assertEqual(list(Path(self.temp.name).rglob("*.part")), [])
        print(json.dumps({"r2_11": {"link_entries": 2, "results": results}}, sort_keys=True))

    @unittest.skipUnless(os.name == "nt", "Windows junction contract")
    def test_parent_and_created_child_junctions_are_rejected_without_touching_sentinel(self):
        backend = FakeBackend()
        service = self.service(backend)
        file_id = service.list_flow_files("F.file").data[0].file_id
        flow_key = hashlib.sha256(b"F.file").hexdigest()
        with tempfile.TemporaryDirectory() as outside:
            external = Path(outside)
            sentinel = external / "sentinel.txt"
            sentinel.write_bytes(b"external")
            child = Path(self.temp.name) / flow_key
            made = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(child), str(external)],
                capture_output=True,
                check=False,
            )
            self.assertEqual(made.returncode, 0, made.stderr.decode(errors="replace"))
            with self.assertRaises(BackendError):
                service.download_flow_file("F.file", file_id)
            self.assertEqual(sentinel.read_bytes(), b"external")
            self.assertEqual(list(external.rglob("content.bin")), [])
            os.rmdir(child)

        with tempfile.TemporaryDirectory() as outer, tempfile.TemporaryDirectory() as target:
            parent_link = Path(outer) / "linked-parent"
            made = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(parent_link), target],
                capture_output=True,
                check=False,
            )
            self.assertEqual(made.returncode, 0, made.stderr.decode(errors="replace"))
            nested_root = parent_link / "downloads"
            nested_root.mkdir()
            nested = FixedToolService(
                [SPEC], TargetContext(FakeBackend()), FakeBackend(),
                download_root=str(nested_root),
            )
            with self.assertRaises(BackendError):
                nested.download_flow_file("F.file", file_id)
            os.rmdir(parent_link)


class VfsPaddingRequestTests(unittest.TestCase):
    def test_old_descriptor_wire_field_eight_parses_as_explicit_boolean(self):
        for padding, expected in ((False, 0), (True, 1)):
            with self.subTest(padding=padding):
                requests = []

                class Stub:
                    def VFSGetBuffer(self, request):
                        requests.append(request)
                        return SimpleNamespace(data=b"ok")

                self.assertNotIn(
                    "padding", velociraptor_api.api_pb2.VFSFileBuffer.DESCRIPTOR.fields_by_name
                )
                with patch.object(velociraptor_api, "stub", Stub()):
                    value = velociraptor_api.read_vfs_buffer(
                        ["clients", "C.one", "file"], offset=1, length=2, padding=padding
                    )
                self.assertEqual(value, b"ok")
                self.assertEqual((requests[0].offset, requests[0].length), (1, 2))
                self.assertEqual(protobuf_varints(requests[0].SerializeToString())[8], [expected])

    def test_descriptor_with_padding_uses_normal_constructor_for_both_booleans(self):
        captured = []

        class Request:
            DESCRIPTOR = SimpleNamespace(
                fields_by_name={"components": object(), "offset": object(), "length": object(), "padding": object()}
            )

            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        class Stub:
            def VFSGetBuffer(self, request):
                captured.append(request)
                return SimpleNamespace(data=b"ok")

        with patch.object(velociraptor_api.api_pb2, "VFSFileBuffer", Request), patch.object(
            velociraptor_api, "stub", Stub()
        ):
            for padding in (False, True):
                self.assertEqual(
                    velociraptor_api.read_vfs_buffer(
                        ["clients", "C.one", "file"], offset=1, length=2, padding=padding
                    ),
                    b"ok",
                )
        self.assertEqual([request.padding for request in captured], [False, True])


if __name__ == "__main__":
    unittest.main()
