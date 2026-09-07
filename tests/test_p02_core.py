from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import grpc

from velociraptor_mcp_core import (
    DEFAULT_PAGE_SIZE,
    MAX_CURSOR_OFFSET,
    MAX_PAGE_SIZE,
    RESPONSE_BYTE_LIMIT,
    RESULT_ROW_LIMIT,
    BackendError,
    ClientIdNotFoundError,
    ClientNotFoundError,
    ClientNotUniqueError,
    ConfigNotFoundError,
    DataResult,
    HuntReferenceResult,
    InvalidArgumentError,
    NotCancellableError,
    NotFoundError,
    ResultBase,
    RowTooLargeError,
    TargetContext,
    VelociraptorBackend,
    canonical_json_bytes,
    decode_cursor,
    encode_cursor,
    error_model,
    error_result,
    limit_unpaged_result,
    paginate_result,
    success_result,
)


class FakeRpcError(grpc.RpcError):
    def __init__(self, status: grpc.StatusCode) -> None:
        self._status = status

    def code(self):
        return self._status


class SequenceBackend:
    def __init__(self, candidate_sets, existence=None, existence_error=None):
        self.candidate_sets = list(candidate_sets)
        self.existence = dict(existence or {})
        self.existence_error = existence_error
        self.list_calls = 0
        self.existence_calls = []

    def list_windows_clients(self):
        index = min(self.list_calls, len(self.candidate_sets) - 1)
        self.list_calls += 1
        return self.candidate_sets[index]

    def client_id_exists(self, client_id):
        self.existence_calls.append(client_id)
        if self.existence_error is not None:
            raise self.existence_error
        return self.existence.get(client_id, True)


class CoreContractTests(unittest.TestCase):
    def setUp(self):
        self.base = ResultBase(operation="query", status="FINISHED", warnings=[])

    def test_frozen_limits(self):
        self.assertEqual((RESULT_ROW_LIMIT, RESPONSE_BYTE_LIMIT), (250, 245554))
        self.assertEqual((DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE), (50, 250))

    def test_success_and_error_use_structured_content_only(self):
        result = success_result(
            paginate_result(self.base, [{"value": 1}], page_size=50)
        )
        self.assertFalse(result.is_error)
        self.assertEqual(result.content, [])
        self.assertEqual(result.structured_content["operation"], "query")
        self.assertNotIn("flow_id", result.structured_content)
        self.assertNotIn("hunt_id", result.structured_content)

        hunt = success_result(
            HuntReferenceResult(
                operation="start_hunt",
                status="RUNNING",
                warnings=[],
                hunt_id="H.real",
            )
        )
        self.assertNotIn("flow_id", hunt.structured_content)

        failed = error_result(
            ConfigNotFoundError(details={"source": "environment", "path": "secret"})
        )
        self.assertTrue(failed.is_error)
        self.assertEqual(failed.content, [])
        self.assertEqual(failed.structured_content["code"], "CONFIG_NOT_FOUND")
        self.assertEqual(failed.structured_content["details"], {"source": "environment"})
        self.assertNotIn("isError", failed.structured_content)

    def test_all_stable_error_codes_and_retryability(self):
        cases = [
            (ConfigNotFoundError(details={"source": "default"}), "CONFIG_NOT_FOUND", False),
            (FakeRpcError(grpc.StatusCode.UNAUTHENTICATED), "AUTHENTICATION_FAILED", False),
            (FakeRpcError(grpc.StatusCode.UNAVAILABLE), "CONNECTION_FAILED", True),
            (FakeRpcError(grpc.StatusCode.DEADLINE_EXCEEDED), "BACKEND_TIMEOUT", True),
            (ClientNotFoundError(details={"candidate_count": 0}), "CLIENT_NOT_FOUND", True),
            (ClientNotUniqueError(details={"candidate_count": 2}), "CLIENT_NOT_UNIQUE", False),
            (ClientIdNotFoundError(details={"retries": 1}), "CLIENT_ID_NOT_FOUND", True),
            (InvalidArgumentError(details={"field": "x", "reason": "type"}), "INVALID_ARGUMENT", False),
            (NotFoundError(details={"object_type": "flow", "object_id": "F.x"}), "NOT_FOUND", False),
            (NotCancellableError(details={"object_type": "flow", "state": "FINISHED"}), "NOT_CANCELLABLE", False),
            (RowTooLargeError(details={"actual_bytes": 1, "limit_bytes": 0, "row_index": 0}), "ROW_TOO_LARGE", False),
            (BackendError(details={"operation": "query", "reason": "invalid_json"}), "BACKEND_ERROR", False),
            (RuntimeError("must not leak"), "INTERNAL_ERROR", False),
        ]
        for exc, code, retryable in cases:
            with self.subTest(code=code):
                model = error_model(exc, operation="query")
                self.assertEqual(model.code, code)
                self.assertEqual(model.retryable, retryable)
                self.assertNotIn("must not leak", json.dumps(model.model_dump()))

    def test_cursor_canonical_form_and_bounds(self):
        for offset in (0, 1, MAX_CURSOR_OFFSET):
            self.assertEqual(decode_cursor(encode_cursor(offset)), offset)
        for cursor in ("v1:00", "v1:-1", "v2:0", "v1:", "1", "v1:2147483648"):
            with self.subTest(cursor=cursor):
                with self.assertRaises(InvalidArgumentError):
                    decode_cursor(cursor)

    def test_page_boundaries_and_multi_page_no_loss_or_duplicate(self):
        for count in (0, 1, 50, 250, 251, 1000):
            with self.subTest(count=count):
                sample = [{"i": value} for value in range(count)]
                page = paginate_result(self.base, sample)
                self.assertEqual(page.pagination.returned, min(count, DEFAULT_PAGE_SIZE))

        rows = [{"i": value} for value in range(251)]
        cursor = None
        combined = []
        while True:
            page = paginate_result(self.base, rows, cursor=cursor, page_size=50)
            combined.extend(page.data)
            if page.pagination.next_cursor is None:
                break
            cursor = page.pagination.next_cursor
        self.assertEqual(combined, rows)
        self.assertEqual(paginate_result(self.base, [], cursor="v1:0").data, [])
        self.assertEqual(paginate_result(self.base, rows, cursor="v1:251").data, [])
        with self.assertRaises(InvalidArgumentError):
            paginate_result(self.base, rows, cursor="v1:252")
        for size in (0, 251, True):
            with self.subTest(size=size):
                with self.assertRaises(InvalidArgumentError):
                    paginate_result(self.base, rows, page_size=size)

    def test_final_envelope_byte_limit_and_single_row_failure(self):
        warning = "告警\\\"" * 100
        base = ResultBase(operation="query", status="FINISHED", warnings=[warning])
        rows = [{"i": i, "text": "汉字\\\"" * 1500} for i in range(100)]
        page = paginate_result(base, rows, page_size=100)
        payload = page.model_dump(mode="json", exclude_none=True)
        self.assertLessEqual(len(canonical_json_bytes(payload)), RESPONSE_BYTE_LIMIT)
        self.assertTrue(page.pagination.truncated)
        self.assertGreater(page.pagination.returned, 0)

        with self.assertRaises(RowTooLargeError) as caught:
            paginate_result(base, [{"text": "x" * RESPONSE_BYTE_LIMIT}], page_size=1)
        self.assertGreater(caught.exception.public_details["actual_bytes"], RESPONSE_BYTE_LIMIT)

    def test_unpaged_limit_uses_row_and_byte_caps(self):
        rows = [{"i": i} for i in range(1000)]
        result = limit_unpaged_result(self.base, rows)
        self.assertEqual(len(result.data), RESULT_ROW_LIMIT)
        self.assertTrue(result.truncated)
        self.assertLessEqual(
            len(canonical_json_bytes(result.model_dump(mode="json", exclude_none=True))),
            RESPONSE_BYTE_LIMIT,
        )


class TargetContextTests(unittest.TestCase):
    def test_zero_one_many_and_process_local_cache(self):
        with self.assertRaises(ClientNotFoundError):
            TargetContext(SequenceBackend([[]])).get_client_id()
        with self.assertRaises(ClientNotUniqueError):
            TargetContext(
                SequenceBackend([[{"client_id": "C.1"}, {"client_id": "C.2"}]])
            ).get_client_id()

        backend = SequenceBackend([[{"client_id": "C.1"}]])
        first = TargetContext(backend)
        self.assertEqual(first.get_client_id(), "C.1")
        self.assertEqual(first.get_client_id(), "C.1")
        self.assertEqual(backend.list_calls, 1)
        second = TargetContext(backend)
        self.assertEqual(second.get_client_id(), "C.1")
        self.assertEqual(backend.list_calls, 2)

    def test_only_exact_zero_existence_probe_replaces_target_once(self):
        backend = SequenceBackend(
            [[{"client_id": "C.old"}], [{"client_id": "C.new"}]],
            existence={"C.old": False, "C.new": True},
        )
        context = TargetContext(backend)
        calls = []

        def operation(client_id):
            calls.append(client_id)
            if client_id == "C.old":
                raise RuntimeError("stale")
            return "ok"

        self.assertEqual(context.run_with_client(operation), "ok")
        self.assertEqual(calls, ["C.old", "C.new"])
        self.assertEqual(backend.list_calls, 2)

    def test_ordinary_failure_and_probe_failure_do_not_clear_cache(self):
        failures = (
            RuntimeError("collection failed"),
            FakeRpcError(grpc.StatusCode.UNAVAILABLE),
            FakeRpcError(grpc.StatusCode.DEADLINE_EXCEEDED),
        )
        for original in failures:
            with self.subTest(failure=type(original).__name__, status=str(getattr(original, "_status", ""))):
                backend = SequenceBackend(
                    [[{"client_id": "C.1"}]], existence={"C.1": True}
                )
                context = TargetContext(backend)
                with self.assertRaises(type(original)):
                    context.run_with_client(
                        lambda _: (_ for _ in ()).throw(original)
                    )
                self.assertEqual(context.get_client_id(), "C.1")
                self.assertEqual(backend.list_calls, 1)

        backend = SequenceBackend(
            [[{"client_id": "C.1"}]], existence_error=RuntimeError("probe")
        )
        context = TargetContext(backend)
        with self.assertRaisesRegex(RuntimeError, "offline"):
            context.run_with_client(
                lambda _: (_ for _ in ()).throw(RuntimeError("offline"))
            )
        self.assertEqual(context.get_client_id(), "C.1")
        self.assertEqual(backend.list_calls, 1)

    def test_second_missing_target_raises_stable_error_without_third_attempt(self):
        backend = SequenceBackend(
            [[{"client_id": "C.old"}], [{"client_id": "C.new"}]],
            existence={"C.old": False, "C.new": False},
        )
        calls = []

        def operation(client_id):
            calls.append(client_id)
            raise RuntimeError("gone")

        with self.assertRaises(ClientIdNotFoundError):
            TargetContext(backend).run_with_client(operation)
        self.assertEqual(calls, ["C.old", "C.new"])


class BackendAdapterTests(unittest.TestCase):
    def test_collection_returns_real_id_and_state(self):
        backend = VelociraptorBackend()
        with (
            patch(
                "velociraptor_api.start_collection",
                return_value=[{"flow_id": "F.real"}],
            ) as start,
            patch("velociraptor_api.get_flow_details", return_value={"state": "RUNNING"}),
        ):
            result = backend.start_collection(
                "C.real", "Windows.System.Pslist", {"ProcessRegex": "x"}
            )
        self.assertEqual(result.flow_id, "F.real")
        self.assertEqual(result.status, "RUNNING")
        self.assertIsNone(start.call_args.kwargs["timeout"])
        self.assertIsNone(start.call_args.kwargs["max_bytes"])

    def test_collection_rejects_missing_real_id_or_state(self):
        backend = VelociraptorBackend()
        with patch("velociraptor_api.start_collection", return_value=[]):
            with self.assertRaises(BackendError):
                backend.start_collection("C.real", "Windows.System.Pslist")
        with (
            patch("velociraptor_api.start_collection", return_value=[{"flow_id": "F.real"}]),
            patch("velociraptor_api.get_flow_details", return_value={}),
        ):
            with self.assertRaises(BackendError):
                backend.start_collection("C.real", "Windows.System.Pslist")

    def test_memory_acquisition_uses_fixed_internal_resource_override(self):
        backend = VelociraptorBackend()
        with (
            patch(
                "velociraptor_api.start_collection",
                return_value=[{"flow_id": "F.memory"}],
            ) as start,
            patch(
                "velociraptor_api.get_flow_details", return_value={"state": "WAITING"}
            ),
        ):
            backend.start_collection(
                "C.real",
                "Windows.Memory.Acquisition",
                {"Compression": "Snappy"},
            )
        self.assertEqual(start.call_args.kwargs["timeout"], 3600)
        self.assertEqual(start.call_args.kwargs["max_bytes"], 8 * 1024**3)


if __name__ == "__main__":
    unittest.main()
