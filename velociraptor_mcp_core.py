"""Shared MCP contracts for the Windows Velociraptor bridge.

This module owns process-local target resolution, structured MCP results, stable
public errors, and response limits.  Product tools should call these primitives
instead of duplicating target or output policy.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Literal, Protocol, TypeVar

import grpc
from mcp.types import CallToolResult
from pydantic import BaseModel, ConfigDict, Field


RESULT_ROW_LIMIT = 250
RESPONSE_BYTE_LIMIT = 245_554
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 250
MAX_CURSOR_OFFSET = 2_147_483_647
MAX_CURSOR_LENGTH = 13


class Pagination(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cursor: str
    next_cursor: str | None = None
    page_size: int = Field(ge=1, le=MAX_PAGE_SIZE)
    returned: int = Field(ge=0)
    truncated: bool


class ResultBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation: str
    status: str
    warnings: list[str] = Field(default_factory=list)


class DataResult(ResultBase):
    data: list[dict[str, Any]]
    pagination: Pagination


class UnpagedDataResult(ResultBase):
    data: list[dict[str, Any]]
    truncated: bool


class FlowReferenceResult(ResultBase):
    flow_id: str


class HuntReferenceResult(ResultBase):
    hunt_id: str
    flow_id: str | None = None


class FixedResultBase(ResultBase):
    status: Literal["success"]
    warnings: list[str]


class FixedDataResult(FixedResultBase):
    data: list[dict[str, Any]]
    pagination: Pagination


class FixedUnpagedDataResult(FixedResultBase):
    data: list[dict[str, Any]]
    truncated: bool


class FixedFlowReferenceResult(FixedResultBase):
    flow_id: str


class HuntStartedResult(FixedResultBase):
    hunt_id: str
    flow_id: str
    client_id: str
    state: str


class HuntStatusResult(FixedResultBase):
    hunt_id: str
    state: str
    flow_id: str | None = None
    flow_state: str | None = None
    client_id: str | None = None
    stats: dict[str, Any]


class HuntStoppedResult(FixedResultBase):
    hunt_id: str
    state: str
    flow_id: str | None = None
    flow_state_before: str | None = None
    flow_state_after: str | None = None


class FlowStatusResult(FixedResultBase):
    flow_id: str
    state: str
    status_message: str
    artifacts: list[str]
    artifacts_with_results: list[str]
    create_time: int = Field(ge=0)
    start_time: int = Field(ge=0)
    active_time: int = Field(ge=0)
    total_collected_rows: int = Field(ge=0)
    total_logs: int = Field(ge=0)
    total_uploaded_files: int = Field(ge=0)
    total_uploaded_bytes: int = Field(ge=0)


class CancelFlowResult(FixedResultBase):
    flow_id: str
    state_before: str
    state_after: str


class DownloadResult(FixedResultBase):
    flow_id: str
    file_id: str
    local_path: str
    size: int = Field(ge=0)
    sha256: str
    original_path: str


class FlowFileEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_id: str
    original_path: str
    file_size: int = Field(ge=0)
    uploaded_size: int = Field(ge=0)
    accessor: str


class FlowFileListResult(FixedResultBase):
    data: list[FlowFileEntry]
    truncated: bool


class ErrorResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    retryable: bool
    details: dict[str, Any]


class PublicError(Exception):
    code = "BACKEND_ERROR"
    default_message = "The Velociraptor backend could not complete the operation."
    retryable = False

    def __init__(
        self,
        message: str | None = None,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message or self.default_message)
        self.public_message = message or self.default_message
        self.public_details = dict(details or {})


class ConfigNotFoundError(PublicError):
    code = "CONFIG_NOT_FOUND"
    default_message = "Velociraptor API configuration is unavailable."


class AuthenticationFailedError(PublicError):
    code = "AUTHENTICATION_FAILED"
    default_message = "Velociraptor rejected the configured API identity."


class ConnectionFailedError(PublicError):
    code = "CONNECTION_FAILED"
    default_message = "The Velociraptor API connection is unavailable."
    retryable = True


class BackendTimeoutError(PublicError):
    code = "BACKEND_TIMEOUT"
    default_message = "The Velociraptor operation timed out."
    retryable = True


class ClientNotFoundError(PublicError):
    code = "CLIENT_NOT_FOUND"
    default_message = "No Windows client is registered in the root organization."
    retryable = True


class ClientNotUniqueError(PublicError):
    code = "CLIENT_NOT_UNIQUE"
    default_message = "More than one Windows client is registered; no target was selected."


class CachedClientIdNotFound(PublicError):
    """Private control signal emitted only by the exact existence probe."""

    code = "CLIENT_ID_NOT_FOUND"
    default_message = "The cached Windows client id no longer exists."
    retryable = True


class ClientIdNotFoundError(CachedClientIdNotFound):
    pass


class InvalidArgumentError(PublicError):
    code = "INVALID_ARGUMENT"
    default_message = "An argument is outside the supported contract."


class NotFoundError(PublicError):
    code = "NOT_FOUND"
    default_message = "The requested Velociraptor object was not found."


class NotCancellableError(PublicError):
    code = "NOT_CANCELLABLE"
    default_message = "The flow cannot be cancelled in its current state."


class DependencyMissingError(PublicError):
    code = "DEPENDENCY_MISSING"
    default_message = "A required Velociraptor artifact is not installed."


class AlreadyExistsError(PublicError):
    code = "ALREADY_EXISTS"
    default_message = "The requested output already exists and was not overwritten."


class RowTooLargeError(PublicError):
    code = "ROW_TOO_LARGE"
    default_message = "A single result row exceeds the MCP response byte limit."


class BackendError(PublicError):
    code = "BACKEND_ERROR"


class DownloadPostPublishError(BackendError):
    """Stable warning for failures after the output hard-link was published."""

    default_message = (
        "The file was published, but post-publication validation or cleanup failed. "
        "The completed file may remain; do not automatically retry or overwrite it."
    )


ERROR_DETAIL_FIELDS: dict[str, frozenset[str]] = {
    "CONFIG_NOT_FOUND": frozenset({"source"}),
    "AUTHENTICATION_FAILED": frozenset({"grpc_status"}),
    "CONNECTION_FAILED": frozenset({"grpc_status"}),
    "BACKEND_TIMEOUT": frozenset({"operation", "timeout_seconds"}),
    "CLIENT_NOT_FOUND": frozenset({"candidate_count"}),
    "CLIENT_NOT_UNIQUE": frozenset({"candidate_count"}),
    "CLIENT_ID_NOT_FOUND": frozenset({"retries"}),
    "INVALID_ARGUMENT": frozenset({"field", "reason", "minimum", "maximum"}),
    "NOT_FOUND": frozenset({"object_type", "object_id"}),
    "NOT_CANCELLABLE": frozenset({"object_type", "state"}),
    "DEPENDENCY_MISSING": frozenset({"artifact"}),
    "ALREADY_EXISTS": frozenset({"object_type", "object_id"}),
    "ROW_TOO_LARGE": frozenset({"actual_bytes", "limit_bytes", "row_index"}),
    "BACKEND_ERROR": frozenset({"operation", "grpc_status", "reason"}),
    "INTERNAL_ERROR": frozenset({"exception_type", "correlation_id"}),
}


def _filtered_details(code: str, details: Mapping[str, Any]) -> dict[str, Any]:
    allowed = ERROR_DETAIL_FIELDS[code]
    return {key: value for key, value in details.items() if key in allowed}


def _grpc_status_name(exc: grpc.RpcError) -> str:
    try:
        return exc.code().name
    except Exception:
        return "UNKNOWN"


def error_model(exc: Exception, *, operation: str = "") -> ErrorResult:
    if isinstance(exc, PublicError):
        code = exc.code
        return ErrorResult(
            code=code,
            message=exc.public_message,
            retryable=exc.retryable,
            details=_filtered_details(code, exc.public_details),
        )

    if isinstance(exc, (FileNotFoundError, PermissionError)):
        return ErrorResult(
            code="CONFIG_NOT_FOUND",
            message=ConfigNotFoundError.default_message,
            retryable=False,
            details={"source": "environment"},
        )

    if isinstance(exc, grpc.RpcError):
        status = _grpc_status_name(exc)
        if status in {"UNAUTHENTICATED", "PERMISSION_DENIED"}:
            return ErrorResult(
                code="AUTHENTICATION_FAILED",
                message=AuthenticationFailedError.default_message,
                retryable=False,
                details={"grpc_status": status},
            )
        if status == "DEADLINE_EXCEEDED":
            return ErrorResult(
                code="BACKEND_TIMEOUT",
                message=BackendTimeoutError.default_message,
                retryable=True,
                details={"operation": operation, "timeout_seconds": 0},
            )
        if status == "UNAVAILABLE":
            return ErrorResult(
                code="CONNECTION_FAILED",
                message=ConnectionFailedError.default_message,
                retryable=True,
                details={"grpc_status": status},
            )
        return ErrorResult(
            code="BACKEND_ERROR",
            message=BackendError.default_message,
            retryable=False,
            details={"operation": operation, "grpc_status": status},
        )

    return ErrorResult(
        code="INTERNAL_ERROR",
        message="An unexpected internal error occurred.",
        retryable=False,
        details={
            "exception_type": type(exc).__name__,
            "correlation_id": uuid.uuid4().hex,
        },
    )


def success_result(model: BaseModel) -> CallToolResult:
    return CallToolResult(
        content=[],
        structuredContent=model.model_dump(mode="json", exclude_none=True),
        isError=False,
    )


def error_result(exc: Exception, *, operation: str = "") -> CallToolResult:
    model = error_model(exc, operation=operation)
    return CallToolResult(
        content=[],
        structuredContent=model.model_dump(mode="json"),
        isError=True,
    )


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def encode_cursor(offset: int) -> str:
    if not isinstance(offset, int) or isinstance(offset, bool):
        raise InvalidArgumentError(details={"field": "cursor", "reason": "offset_type"})
    if offset < 0 or offset > MAX_CURSOR_OFFSET:
        raise InvalidArgumentError(
            details={
                "field": "cursor",
                "reason": "offset_range",
                "minimum": 0,
                "maximum": MAX_CURSOR_OFFSET,
            }
        )
    return f"v1:{offset}"


def decode_cursor(cursor: str | None) -> int:
    if cursor is None or cursor == "":
        return 0
    if not isinstance(cursor, str) or len(cursor) > MAX_CURSOR_LENGTH:
        raise InvalidArgumentError(details={"field": "cursor", "reason": "format"})
    if not cursor.startswith("v1:"):
        raise InvalidArgumentError(details={"field": "cursor", "reason": "format"})
    digits = cursor[3:]
    if not digits or not digits.isascii() or not digits.isdecimal():
        raise InvalidArgumentError(details={"field": "cursor", "reason": "format"})
    if len(digits) > 1 and digits.startswith("0"):
        raise InvalidArgumentError(details={"field": "cursor", "reason": "leading_zero"})
    offset = int(digits)
    if offset > MAX_CURSOR_OFFSET:
        raise InvalidArgumentError(
            details={
                "field": "cursor",
                "reason": "offset_range",
                "minimum": 0,
                "maximum": MAX_CURSOR_OFFSET,
            }
        )
    return offset


def _page_size(value: int | None) -> int:
    if value is None:
        return DEFAULT_PAGE_SIZE
    if not isinstance(value, int) or isinstance(value, bool):
        raise InvalidArgumentError(details={"field": "page_size", "reason": "type"})
    if value < 1 or value > MAX_PAGE_SIZE:
        raise InvalidArgumentError(
            details={
                "field": "page_size",
                "reason": "range",
                "minimum": 1,
                "maximum": MAX_PAGE_SIZE,
            }
        )
    return value


def normalize_page_size(value: int | None) -> int:
    return _page_size(value)


def _base_values(base_result: ResultBase | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(base_result, ResultBase):
        return base_result.model_dump(mode="json", exclude_none=True)
    return ResultBase.model_validate(dict(base_result)).model_dump(
        mode="json", exclude_none=True
    )


def _data_page(
    base: Mapping[str, Any],
    rows: Sequence[dict[str, Any]],
    *,
    offset: int,
    page_size: int,
    total: int,
) -> DataResult:
    returned = len(rows)
    end = offset + returned
    truncated = end < total
    pagination = Pagination(
        cursor=encode_cursor(offset),
        next_cursor=encode_cursor(end) if truncated else None,
        page_size=page_size,
        returned=returned,
        truncated=truncated,
    )
    return DataResult(**base, data=list(rows), pagination=pagination)


def paginate_result(
    base_result: ResultBase | Mapping[str, Any],
    rows: Sequence[dict[str, Any]],
    *,
    cursor: str | None = None,
    page_size: int | None = None,
) -> DataResult:
    size = _page_size(page_size)
    offset = decode_cursor(cursor)
    total = len(rows)
    if offset > total:
        raise InvalidArgumentError(
            details={"field": "cursor", "reason": "offset_after_end"}
        )

    base = _base_values(base_result)
    candidate = list(rows[offset : min(total, offset + size)])
    if not candidate:
        return _data_page(base, [], offset=offset, page_size=size, total=total)

    best: DataResult | None = None
    for count in range(1, len(candidate) + 1):
        current = _data_page(
            base,
            candidate[:count],
            offset=offset,
            page_size=size,
            total=total,
        )
        payload = current.model_dump(mode="json", exclude_none=True)
        if len(canonical_json_bytes(payload)) <= RESPONSE_BYTE_LIMIT:
            best = current

    if best is None:
        first = _data_page(
            base,
            candidate[:1],
            offset=offset,
            page_size=size,
            total=total,
        )
        actual = len(
            canonical_json_bytes(first.model_dump(mode="json", exclude_none=True))
        )
        raise RowTooLargeError(
            details={
                "actual_bytes": actual,
                "limit_bytes": RESPONSE_BYTE_LIMIT,
                "row_index": offset,
            }
        )
    return best


def paginate_window_result(
    base_result: ResultBase | Mapping[str, Any],
    rows: Sequence[dict[str, Any]],
    *,
    cursor: str | None = None,
    page_size: int | None = None,
) -> DataResult:
    """Build one bounded page from a backend ``page_size + 1`` window."""
    size = _page_size(page_size)
    offset = decode_cursor(cursor)
    window = list(rows)
    has_more = len(window) > size
    candidate = window[:size]
    base = _base_values(base_result)

    def build(count: int) -> DataResult:
        returned = candidate[:count]
        truncated = has_more or count < len(candidate)
        end = offset + len(returned)
        return DataResult(
            **base,
            data=returned,
            pagination=Pagination(
                cursor=encode_cursor(offset),
                next_cursor=encode_cursor(end) if truncated else None,
                page_size=size,
                returned=len(returned),
                truncated=truncated,
            ),
        )

    if not candidate:
        return build(0)

    best: DataResult | None = None
    for count in range(1, len(candidate) + 1):
        current = build(count)
        payload = current.model_dump(mode="json", exclude_none=True)
        if len(canonical_json_bytes(payload)) <= RESPONSE_BYTE_LIMIT:
            best = current

    if best is None:
        first = build(1)
        actual = len(
            canonical_json_bytes(first.model_dump(mode="json", exclude_none=True))
        )
        raise RowTooLargeError(
            details={
                "actual_bytes": actual,
                "limit_bytes": RESPONSE_BYTE_LIMIT,
                "row_index": offset,
            }
        )
    return best


def limit_unpaged_result(
    base_result: ResultBase | Mapping[str, Any],
    rows: Sequence[dict[str, Any]],
) -> UnpagedDataResult:
    base = _base_values(base_result)
    candidate = list(rows[:RESULT_ROW_LIMIT])
    truncated_by_rows = len(rows) > len(candidate)

    def build(count: int) -> UnpagedDataResult:
        return UnpagedDataResult(
            **base,
            data=candidate[:count],
            truncated=truncated_by_rows or count < len(candidate),
        )

    if not candidate:
        return build(0)

    best: UnpagedDataResult | None = None
    for count in range(1, len(candidate) + 1):
        current = build(count)
        if len(
            canonical_json_bytes(current.model_dump(mode="json", exclude_none=True))
        ) <= RESPONSE_BYTE_LIMIT:
            best = current

    if best is None:
        first = build(1)
        actual = len(
            canonical_json_bytes(first.model_dump(mode="json", exclude_none=True))
        )
        raise RowTooLargeError(
            details={
                "actual_bytes": actual,
                "limit_bytes": RESPONSE_BYTE_LIMIT,
                "row_index": 0,
            }
        )
    return best


T = TypeVar("T")


class TargetBackend(Protocol):
    def list_windows_clients(self) -> list[dict[str, Any]]: ...

    def client_id_exists(self, client_id: str) -> bool: ...


class TargetContext:
    """Resolve and cache exactly one Windows client for this Python process."""

    def __init__(self, backend: TargetBackend) -> None:
        self._backend = backend
        self._client_id: str | None = None

    def clear(self) -> None:
        self._client_id = None

    def get_client_id(self) -> str:
        if self._client_id is not None:
            return self._client_id
        candidates = self._backend.list_windows_clients()
        count = len(candidates)
        if count == 0:
            raise ClientNotFoundError(details={"candidate_count": 0})
        if count > 1:
            raise ClientNotUniqueError(details={"candidate_count": count})
        client_id = candidates[0].get("client_id")
        if not isinstance(client_id, str) or not client_id:
            raise BackendError(details={"operation": "list_windows_clients", "reason": "missing_client_id"})
        self._client_id = client_id
        return client_id

    def run_with_client(self, operation: Callable[[str], T]) -> T:
        client_id = self.get_client_id()
        try:
            return operation(client_id)
        except Exception as operation_error:
            try:
                exists = self._backend.client_id_exists(client_id)
            except Exception:
                raise operation_error
            if exists:
                raise operation_error

        self.clear()
        try:
            replacement = self.get_client_id()
        except ClientNotFoundError as exc:
            raise ClientIdNotFoundError(details={"retries": 1}) from exc

        try:
            return operation(replacement)
        except Exception as exc:
            try:
                exists = self._backend.client_id_exists(replacement)
            except Exception:
                raise exc
            if not exists:
                raise ClientIdNotFoundError(details={"retries": 1}) from exc
            raise exc


class VelociraptorBackend:
    """Thin production adapter over the existing gRPC/VQL helpers."""

    # A full physical-memory image can exceed Velociraptor's default 1 GiB
    # per-collection upload limit.  Keep this policy internal to the exact
    # reviewed artifact so callers cannot raise resource limits arbitrarily.
    MEMORY_ACQUISITION_TIMEOUT_SECONDS = 3600
    MEMORY_ACQUISITION_MAX_UPLOAD_BYTES = 8 * 1024**3

    def list_windows_clients(self) -> list[dict[str, Any]]:
        from velociraptor_api import list_windows_clients_strict

        return list_windows_clients_strict()

    def client_id_exists(self, client_id: str) -> bool:
        from velociraptor_api import client_id_exists

        return client_id_exists(client_id)

    def start_collection(
        self,
        client_id: str,
        artifact: str,
        parameters: Mapping[str, Any] | None = None,
        *,
        timeout: int | None = None,
    ) -> FlowReferenceResult:
        from velociraptor_api import get_flow_details, start_collection

        max_bytes = None
        if artifact == "Windows.Memory.Acquisition":
            timeout = max(timeout or 0, self.MEMORY_ACQUISITION_TIMEOUT_SECONDS)
            max_bytes = self.MEMORY_ACQUISITION_MAX_UPLOAD_BYTES

        rows = start_collection(
            client_id,
            artifact,
            parameters,
            timeout=timeout,
            max_bytes=max_bytes,
            org_id=None,
            root_org=True,
        )
        if not rows or not isinstance(rows[0].get("flow_id"), str):
            raise BackendError(
                details={"operation": "start_collection", "reason": "missing_flow_id"}
            )
        flow_id = rows[0]["flow_id"]
        details = get_flow_details(client_id, flow_id, org_id=None, root_org=True)
        state = details.get("state") if details else None
        if not isinstance(state, str) or not state:
            raise BackendError(
                details={"operation": "get_flow_details", "reason": "missing_state"}
            )
        return FlowReferenceResult(
            operation="start_collection",
            status=state,
            warnings=[],
            flow_id=flow_id,
        )

    def run_vql(self, query: str, *, max_rows: int) -> list[dict[str, Any]]:
        from velociraptor_api import run_vql_query_bounded

        return run_vql_query_bounded(query, max_rows=max_rows, root_org=True)

    def artifact_exists(self, artifact: str) -> bool:
        from velociraptor_api import artifact_exists

        return artifact_exists(artifact)

    def get_flow_details(self, client_id: str, flow_id: str) -> dict[str, Any] | None:
        from velociraptor_api import get_flow_details

        return get_flow_details(client_id, flow_id, root_org=True)

    def get_flow_results_window(
        self,
        client_id: str,
        flow_id: str,
        artifact: str,
        *,
        source: str | None,
        start_row: int,
        count: int,
    ) -> list[dict[str, Any]]:
        from velociraptor_api import get_flow_results_window

        return get_flow_results_window(
            client_id,
            flow_id,
            artifact,
            source=source,
            start_row=start_row,
            count=count,
            root_org=True,
        )

    def get_flow_result_count(
        self,
        client_id: str,
        flow_id: str,
        artifact: str,
        *,
        source: str | None,
    ) -> int:
        from velociraptor_api import get_flow_result_count

        return get_flow_result_count(
            client_id,
            flow_id,
            artifact,
            source=source,
            root_org=True,
        )

    def list_flow_uploads(
        self, client_id: str, flow_id: str
    ) -> list[dict[str, Any]]:
        from velociraptor_api import list_flow_uploads

        return list_flow_uploads(client_id, flow_id, root_org=True)

    def read_vfs_buffer(
        self,
        components: Sequence[str],
        *,
        offset: int,
        length: int,
        padding: bool,
    ) -> bytes:
        from velociraptor_api import read_vfs_buffer

        return read_vfs_buffer(
            components, offset=offset, length=length, padding=padding
        )

    def cancel_flow(self, client_id: str, flow_id: str) -> None:
        from velociraptor_api import cancel_flow_by_id

        cancel_flow_by_id(client_id, flow_id, root_org=True)

    def create_paused_hunt(
        self,
        artifact: str,
        parameters: Mapping[str, Any] | None,
        description: str,
    ) -> str:
        from velociraptor_api import create_paused_hunt

        return create_paused_hunt(artifact, parameters, description, root_org=True)

    def add_hunt_flow(self, client_id: str, hunt_id: str, flow_id: str) -> None:
        from velociraptor_api import add_hunt_flow

        add_hunt_flow(client_id, hunt_id, flow_id, root_org=True)

    def get_hunt_details(self, hunt_id: str) -> dict[str, Any] | None:
        from velociraptor_api import get_hunt_details

        return get_hunt_details(hunt_id, root_org=True)

    def list_hunt_flows(self, hunt_id: str) -> list[dict[str, Any]]:
        from velociraptor_api import list_hunt_flows

        return list_hunt_flows(hunt_id, root_org=True)

    def stop_hunt(self, hunt_id: str) -> None:
        from velociraptor_api import stop_hunt_by_id

        stop_hunt_by_id(hunt_id, root_org=True)
