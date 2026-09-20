"""Fixed MCP tools for one root-org Windows Velociraptor endpoint."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import os
import stat
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

import grpc
from jsonschema import Draft202012Validator
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult
from pydantic import StrictInt, StrictStr

from velociraptor_dynamic_artifacts import (
    ArtifactRegistryError,
    ArtifactSpec,
    _strict_tool_schema,
    _validate_runtime_parameters,
)
from velociraptor_mcp_core import (
    AlreadyExistsError,
    BackendError,
    CancelFlowResult,
    FixedDataResult,
    FixedFlowReferenceResult,
    FixedUnpagedDataResult,
    DependencyMissingError,
    DownloadPostPublishError,
    DownloadResult,
    FlowFileListResult,
    FlowStatusResult,
    HuntStartedResult,
    HuntStatusResult,
    HuntStoppedResult,
    InvalidArgumentError,
    NotCancellableError,
    NotFoundError,
    PublicError,
    RESULT_ROW_LIMIT,
    TargetContext,
    VelociraptorBackend,
    canonical_json_bytes,
    decode_cursor,
    error_result,
    limit_unpaged_result,
    normalize_page_size,
    paginate_window_result,
    success_result,
)


FIXED_TOOL_NAMES = (
    "run_vql",
    "start_hunt",
    "get_hunt_status",
    "stop_hunt",
    "get_flow_status",
    "get_flow_results",
    "list_flow_files",
    "download_flow_file",
    "cancel_flow",
    "collect_file",
    "collect_forensic_triage",
    "kill_process",
)
FINAL_TOOL_COUNT = 130
VFS_CHUNK_BYTES = 1024 * 1024
TERMINAL_FLOW_STATES = frozenset({"FINISHED", "ERROR"})
TRIAGE_ARTIFACT = "Windows.Triage.Targets"
TRIAGE_MAX_UPLOAD_BYTES = 4 * 1024**3
KILL_PROCESS_ARTIFACT = "Generic.Utils.KillProcess"
FILE_ARTIFACT = "Generic.Collectors.File"

# Runtime handlers validate value ranges themselves so malformed values receive
# the same structured INVALID_ARGUMENT envelope as other product errors.  The
# published JSON Schema constraints are applied after FastMCP builds its model.
NonEmptyString = StrictStr
Pid = StrictInt
PageSize = StrictInt

logger = logging.getLogger(__name__)


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidArgumentError(details={"field": field, "reason": "empty"})
    if any(ord(character) < 32 for character in value):
        raise InvalidArgumentError(details={"field": field, "reason": "control_character"})
    return value


def _require_query(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidArgumentError(details={"field": "query", "reason": "empty"})
    if any(ord(character) < 32 and character not in "\r\n\t" for character in value):
        raise InvalidArgumentError(
            details={"field": "query", "reason": "control_character"}
        )
    return value


def _backend_call(operation: str, callback):
    try:
        return callback()
    except (PublicError, grpc.RpcError):
        raise
    except Exception as exc:
        raise BackendError(
            details={"operation": operation, "reason": type(exc).__name__}
        ) from exc


def _int_field(row: Mapping[str, Any], name: str) -> int:
    value = row.get(name, 0)
    try:
        normalized = int(value or 0)
    except (TypeError, ValueError) as exc:
        raise BackendError(
            details={"operation": "read_backend_state", "reason": f"invalid_{name}"}
        ) from exc
    if normalized < 0:
        raise BackendError(
            details={"operation": "read_backend_state", "reason": f"invalid_{name}"}
        )
    return normalized


def _string_list(value: Any, *, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise BackendError(
            details={"operation": "read_backend_state", "reason": f"invalid_{field}"}
        )
    return list(value)


@dataclass(frozen=True)
class _FileRecord:
    file_id: str
    identity: dict[str, Any]
    components: tuple[str, ...]
    original_path: str
    file_size: int
    uploaded_size: int
    accessor: str
    index_selector: tuple[str, ...] | None = None

    def public_row(self) -> dict[str, Any]:
        return {
            "file_id": self.file_id,
            "original_path": self.original_path,
            "file_size": self.file_size,
            "uploaded_size": self.uploaded_size,
            "accessor": self.accessor,
        }


@dataclass(frozen=True)
class _UploadRecord:
    kind: str
    file: _FileRecord
    selector: tuple[str, ...]


@dataclass(frozen=True)
class _FileInventory:
    records: tuple[_FileRecord, ...]
    sparse_count: int


def _metadata_error(reason: str) -> BackendError:
    return BackendError(
        details={"operation": "list_flow_files", "reason": reason}
    )


def _upload_record(
    row: Mapping[str, Any], *, client_id: str, flow_id: str
) -> _UploadRecord:
    upload = row.get("Upload")
    upload_map = upload if isinstance(upload, Mapping) else {}
    raw_type = row.get("Type", "")
    if not isinstance(raw_type, str) or raw_type not in {"", "idx"}:
        raise _metadata_error("unsupported_upload_type")
    nested_type = upload_map.get("Type", "")
    if nested_type is None:
        nested_type = ""
    if not isinstance(nested_type, str):
        raise _metadata_error("unsupported_upload_type")
    if nested_type and nested_type != raw_type:
        raise _metadata_error("unsupported_upload_type")
    kind = "idx" if raw_type == "idx" else "data"
    components = (
        upload_map["Components"]
        if "Components" in upload_map
        else row.get("_Components")
    )
    if not isinstance(components, list) or not components or any(
        not isinstance(item, str) for item in components
    ):
        raise _metadata_error("invalid_sparse_pair")
    expected_prefix = ["clients", client_id, "collections", flow_id, "uploads"]
    if components[: len(expected_prefix)] != expected_prefix:
        raise _metadata_error("invalid_sparse_pair")
    accessor = upload_map.get("Accessor")
    if accessor is None:
        accessor = row.get("_accessor", "")
    if not isinstance(accessor, str):
        raise _metadata_error("invalid_sparse_pair")
    upload_id = upload_map.get("UploadId")
    identity = {
        "accessor": accessor,
        "components": components,
        "upload_id": upload_id,
    }
    file_id = hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
    original_path = (
        upload_map["Path"] if "Path" in upload_map else row.get("client_path", "")
    )
    if not isinstance(original_path, str):
        raise _metadata_error("invalid_sparse_pair")
    raw_file_size = (
        upload_map["Size"] if "Size" in upload_map else row.get("file_size")
    )
    raw_uploaded_size = (
        upload_map["StoredSize"]
        if "StoredSize" in upload_map
        else row.get("uploaded_size")
    )
    if (
        not isinstance(raw_file_size, int)
        or isinstance(raw_file_size, bool)
        or not isinstance(raw_uploaded_size, int)
        or isinstance(raw_uploaded_size, bool)
        or raw_file_size < 0
        or raw_uploaded_size < 0
        or raw_uploaded_size > raw_file_size
    ):
        raise _metadata_error("invalid_file_size")
    file = _FileRecord(
        file_id=file_id,
        identity=identity,
        components=tuple(components),
        original_path=original_path,
        file_size=raw_file_size,
        uploaded_size=raw_uploaded_size,
        accessor=accessor,
    )
    selector = tuple(components)
    if kind == "idx":
        selector = (*selector[:-1], selector[-1] + ".idx")
    return _UploadRecord(kind=kind, file=file, selector=selector)


def _deduplicated_uploads(
    rows: Sequence[Mapping[str, Any]], *, client_id: str, flow_id: str
) -> _FileInventory:
    records: list[_FileRecord] = []
    by_id: dict[str, _FileRecord] = {}
    indexes: dict[str, _UploadRecord] = {}
    selectors: dict[tuple[str, ...], tuple[str, str]] = {}
    for row in rows:
        upload = _upload_record(row, client_id=client_id, flow_id=flow_id)
        record = upload.file
        selector_key = tuple(part.casefold() for part in upload.selector)
        selector_value = (upload.kind, record.file_id)
        previous_selector = selectors.get(selector_key)
        if previous_selector is None:
            selectors[selector_key] = selector_value
        elif previous_selector != selector_value:
            raise _metadata_error("file_selector_conflict")
        if upload.kind == "idx":
            previous_index = indexes.get(record.file_id)
            if previous_index is None:
                indexes[record.file_id] = upload
            elif previous_index != upload:
                raise _metadata_error("invalid_sparse_pair")
            continue
        previous = by_id.get(record.file_id)
        if previous is None:
            by_id[record.file_id] = record
            records.append(record)
            continue
        if previous != record:
            raise _metadata_error("file_identity_conflict")

    sparse_count = 0
    paired: list[_FileRecord] = []
    for record in records:
        index = indexes.pop(record.file_id, None)
        if index is None:
            if record.file_size != record.uploaded_size:
                raise _metadata_error("invalid_sparse_pair")
            paired.append(record)
            continue
        index_record = index.file
        if (
            index_record.original_path != record.original_path + ".idx"
            or index_record.file_size != record.file_size
            or index_record.uploaded_size != record.uploaded_size
            or index_record.identity != record.identity
        ):
            raise _metadata_error("invalid_sparse_pair")
        sparse_count += 1
        paired.append(
            _FileRecord(
                **{
                    **record.__dict__,
                    "index_selector": index.selector,
                }
            )
        )
    if indexes:
        raise _metadata_error("invalid_sparse_pair")
    return _FileInventory(records=tuple(paired), sparse_count=sparse_count)


def _is_reparse(path: Path) -> bool:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _assert_plain_path(path: Path, *, operation: str) -> None:
    if _is_reparse(path):
        raise BackendError(details={"operation": operation, "reason": "reparse_point"})


def _assert_contained(root: Path, candidate: Path, *, strict: bool) -> Path:
    resolved = candidate.resolve(strict=strict)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise BackendError(
            details={"operation": "download_flow_file", "reason": "path_escape"}
        ) from exc
    return resolved


def _download_root(value: str | None) -> Path:
    if not isinstance(value, str) or not value:
        raise InvalidArgumentError(
            details={"field": "VELOCIRAPTOR_DOWNLOAD_ROOT", "reason": "missing"}
        )
    root = Path(value)
    if not root.is_absolute():
        raise InvalidArgumentError(
            details={"field": "VELOCIRAPTOR_DOWNLOAD_ROOT", "reason": "relative"}
        )
    if not root.exists() or not root.is_dir():
        raise InvalidArgumentError(
            details={"field": "VELOCIRAPTOR_DOWNLOAD_ROOT", "reason": "not_directory"}
        )
    for candidate in (root, *root.parents):
        if candidate.exists():
            _assert_plain_path(candidate, operation="download_flow_file")
    return root.resolve(strict=True)


def _ensure_child(root: Path, parent: Path, segment: str) -> Path:
    child = parent / segment
    try:
        child.mkdir()
    except FileExistsError:
        pass
    if not child.is_dir():
        raise BackendError(
            details={"operation": "download_flow_file", "reason": "path_not_directory"}
        )
    _assert_plain_path(child, operation="download_flow_file")
    _assert_contained(root, child, strict=True)
    return child


def _assert_safe_chain(root: Path, *paths: Path) -> None:
    _assert_plain_path(root, operation="download_flow_file")
    if root.resolve(strict=True) != root:
        raise BackendError(
            details={"operation": "download_flow_file", "reason": "path_escape"}
        )
    for path in paths:
        _assert_plain_path(path, operation="download_flow_file")
        _assert_contained(root, path, strict=True)


def _read_vfs_stream(
    backend: VelociraptorBackend,
    record: _FileRecord,
    *,
    padding: bool,
    stream=None,
) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = _backend_call(
            "download_flow_file",
            lambda: backend.read_vfs_buffer(
                record.components,
                offset=size,
                length=VFS_CHUNK_BYTES,
                padding=padding,
            ),
        )
        if not isinstance(chunk, bytes) or len(chunk) > VFS_CHUNK_BYTES:
            raise BackendError(
                details={
                    "operation": "download_flow_file",
                    "reason": "invalid_vfs_chunk",
                }
            )
        if not chunk:
            break
        if stream is not None:
            stream.write(chunk)
        digest.update(chunk)
        size += len(chunk)
    return size, digest.hexdigest()


def _cleanup_owned_temp(
    root: Path,
    parent: Path,
    temp: Path,
    identity: tuple[int, int],
) -> bool:
    try:
        _assert_plain_path(parent, operation="download_flow_file")
        _assert_contained(root, parent, strict=True)
        info = temp.lstat()
        if (info.st_dev, info.st_ino) != identity or _is_reparse(temp):
            return False
        _assert_contained(root, temp, strict=True)
        temp.unlink()
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return False
    except BackendError:
        return False


def _assert_owned_file(path: Path, identity: tuple[int, int]) -> None:
    info = path.lstat()
    if (info.st_dev, info.st_ino) != identity or _is_reparse(path):
        raise BackendError(
            details={"operation": "download_flow_file", "reason": "path_escape"}
        )


class FixedToolService:
    def __init__(
        self,
        specs: Sequence[ArtifactSpec],
        target: TargetContext,
        backend: VelociraptorBackend,
        *,
        download_root: str | None,
    ) -> None:
        self._specs = {spec.name: spec for spec in specs}
        self._target = target
        self._backend = backend
        self._download_root_value = download_root

    def _flow(self, client_id: str, flow_id: str) -> dict[str, Any]:
        _require_text(flow_id, "flow_id")
        row = _backend_call(
            "get_flow_status",
            lambda: self._backend.get_flow_details(client_id, flow_id),
        )
        if row is None:
            raise NotFoundError(details={"object_type": "flow", "object_id": flow_id})
        if not isinstance(row, dict):
            raise BackendError(
                details={"operation": "get_flow_status", "reason": "invalid_flow"}
            )
        return row

    def _flow_status_model(self, flow_id: str, row: Mapping[str, Any]) -> FlowStatusResult:
        state = row.get("state")
        if not isinstance(state, str) or not state:
            raise BackendError(
                details={"operation": "get_flow_status", "reason": "missing_state"}
            )
        request = row.get("request") if isinstance(row.get("request"), Mapping) else {}
        artifacts = row.get("artifacts") or request.get("artifacts") or []
        return FlowStatusResult(
            operation="get_flow_status",
            status="success",
            warnings=[],
            flow_id=flow_id,
            state=state,
            status_message=str(row.get("status") or ""),
            artifacts=_string_list(artifacts, field="artifacts"),
            artifacts_with_results=_string_list(
                row.get("artifacts_with_results"), field="artifacts_with_results"
            ),
            create_time=_int_field(row, "create_time"),
            start_time=_int_field(row, "start_time"),
            active_time=_int_field(row, "active_time"),
            total_collected_rows=_int_field(row, "total_collected_rows"),
            total_logs=_int_field(row, "total_logs"),
            total_uploaded_files=_int_field(row, "total_uploaded_files"),
            total_uploaded_bytes=_int_field(row, "total_uploaded_bytes"),
        )

    def run_vql(self, query: str) -> FixedUnpagedDataResult:
        normalized = _require_query(query)
        rows = _backend_call(
            "run_vql", lambda: self._backend.run_vql(normalized, max_rows=RESULT_ROW_LIMIT + 1)
        )
        generic = limit_unpaged_result(
            {"operation": "run_vql", "status": "success", "warnings": []}, rows
        )
        return FixedUnpagedDataResult.model_validate(generic.model_dump(mode="json"))

    def start_hunt(
        self,
        artifact: str,
        parameters: Mapping[str, Any] | None,
        description: str | None,
    ) -> HuntStartedResult:
        normalized_artifact = _require_text(artifact, "artifact")
        spec = self._specs.get(normalized_artifact)
        if spec is None:
            raise NotFoundError(
                details={"object_type": "artifact", "object_id": normalized_artifact}
            )
        if parameters is not None and not isinstance(parameters, Mapping):
            raise InvalidArgumentError(details={"field": "parameters", "reason": "type"})
        validated = _validate_runtime_parameters(spec, parameters or {})
        normalized_description = (
            f"MCP Hunt: {normalized_artifact}"
            if description is None or description == ""
            else _require_text(description, "description")
        )

        def operation(client_id: str) -> HuntStartedResult:
            hunt_id: str | None = None
            flow_id: str | None = None
            try:
                hunt_id = _backend_call(
                    "create_paused_hunt",
                    lambda: self._backend.create_paused_hunt(
                        normalized_artifact, validated or None, normalized_description
                    ),
                )
                flow = _backend_call(
                    "start_hunt_flow",
                    lambda: self._backend.start_collection(
                        client_id, normalized_artifact, validated or None
                    ),
                )
                flow_id = flow.flow_id
                _backend_call(
                    "add_hunt_flow",
                    lambda: self._backend.add_hunt_flow(client_id, hunt_id, flow_id),
                )
                details = _backend_call(
                    "get_hunt_status", lambda: self._backend.get_hunt_details(hunt_id)
                )
                if not isinstance(details, Mapping) or not isinstance(details.get("state"), str):
                    raise BackendError(
                        details={"operation": "get_hunt_status", "reason": "missing_state"}
                    )
                return HuntStartedResult(
                    operation="start_hunt",
                    status="success",
                    warnings=[],
                    hunt_id=hunt_id,
                    flow_id=flow_id,
                    client_id=client_id,
                    state=details["state"],
                )
            except Exception:
                if flow_id:
                    try:
                        self._backend.cancel_flow(client_id, flow_id)
                    except Exception:
                        pass
                if hunt_id:
                    try:
                        self._backend.stop_hunt(hunt_id)
                    except Exception:
                        pass
                raise

        return self._target.run_with_client(operation)

    def _hunt_flow(self, hunt_id: str) -> dict[str, Any] | None:
        flows = _backend_call(
            "list_hunt_flows", lambda: self._backend.list_hunt_flows(hunt_id)
        )
        if len(flows) > 1:
            raise BackendError(
                details={"operation": "list_hunt_flows", "reason": "multiple_hunt_flows"}
            )
        if not flows:
            return None
        row = flows[0]
        if not isinstance(row, dict):
            raise BackendError(
                details={"operation": "list_hunt_flows", "reason": "invalid_hunt_flow"}
            )
        return row

    def _hunt_details(self, hunt_id: str) -> dict[str, Any]:
        _require_text(hunt_id, "hunt_id")
        details = _backend_call(
            "get_hunt_status", lambda: self._backend.get_hunt_details(hunt_id)
        )
        if details is None:
            raise NotFoundError(details={"object_type": "hunt", "object_id": hunt_id})
        if not isinstance(details, dict) or not isinstance(details.get("state"), str):
            raise BackendError(
                details={"operation": "get_hunt_status", "reason": "invalid_hunt"}
            )
        return details

    def get_hunt_status(self, hunt_id: str) -> HuntStatusResult:
        details = self._hunt_details(hunt_id)
        flow = self._hunt_flow(hunt_id)
        stats = details.get("stats")
        return HuntStatusResult(
            operation="get_hunt_status",
            status="success",
            warnings=[],
            hunt_id=hunt_id,
            state=details["state"],
            flow_id=str(flow.get("FlowId")) if flow and flow.get("FlowId") else None,
            flow_state=str(flow.get("FlowState")) if flow and flow.get("FlowState") else None,
            client_id=str(flow.get("ClientId")) if flow and flow.get("ClientId") else None,
            stats=dict(stats) if isinstance(stats, Mapping) else {},
        )

    def stop_hunt(self, hunt_id: str) -> HuntStoppedResult:
        self._hunt_details(hunt_id)
        before = self._hunt_flow(hunt_id)
        _backend_call("stop_hunt", lambda: self._backend.stop_hunt(hunt_id))
        details = self._hunt_details(hunt_id)
        after = self._hunt_flow(hunt_id)
        return HuntStoppedResult(
            operation="stop_hunt",
            status="success",
            warnings=[],
            hunt_id=hunt_id,
            state=details["state"],
            flow_id=str((after or before).get("FlowId")) if (after or before) else None,
            flow_state_before=(
                str(before.get("FlowState")) if before and before.get("FlowState") else None
            ),
            flow_state_after=(
                str(after.get("FlowState")) if after and after.get("FlowState") else None
            ),
        )

    def get_flow_status(self, flow_id: str) -> FlowStatusResult:
        return self._target.run_with_client(
            lambda client_id: self._flow_status_model(
                flow_id, self._flow(client_id, flow_id)
            )
        )

    def get_flow_results(
        self,
        flow_id: str,
        source: str | None,
        cursor: str | None,
        page_size: int | None,
    ) -> FixedDataResult:
        size = normalize_page_size(page_size)
        offset = decode_cursor(cursor)

        def operation(client_id: str) -> FixedDataResult:
            details = self._flow(client_id, flow_id)
            request = details.get("request") if isinstance(details.get("request"), Mapping) else {}
            artifacts = details.get("artifacts") or request.get("artifacts") or []
            artifact_names = _string_list(artifacts, field="artifacts")
            if len(artifact_names) != 1:
                raise BackendError(
                    details={"operation": "get_flow_results", "reason": "artifact_count"}
                )
            artifact = artifact_names[0]
            known = _string_list(
                details.get("artifacts_with_results"), field="artifacts_with_results"
            )
            known = list(dict.fromkeys(known))
            selected_sources: list[str | None] = []

            def source_suffix(full_name: str) -> str | None:
                if full_name == artifact:
                    return None
                prefix = artifact + "/"
                if full_name.startswith(prefix) and len(full_name) > len(prefix):
                    return full_name[len(prefix) :]
                raise BackendError(
                    details={"operation": "get_flow_results", "reason": "source_scope_mismatch"}
                )

            if source is not None:
                normalized_source = _require_text(source, "source")
                if normalized_source in known:
                    selected_sources = [source_suffix(normalized_source)]
                else:
                    matches = [
                        item for item in known if item.rsplit("/", 1)[-1] == normalized_source
                    ]
                    if len(matches) != 1:
                        raise InvalidArgumentError(
                            details={"field": "source", "reason": "unknown"}
                        )
                    selected_sources = [source_suffix(matches[0])]
            else:
                selected_sources = [source_suffix(item) for item in known]

            totals = [
                _backend_call(
                    "get_flow_results",
                    lambda source_name=source_name: self._backend.get_flow_result_count(
                        client_id,
                        flow_id,
                        artifact,
                        source=source_name,
                    ),
                )
                for source_name in selected_sources
            ]
            total = sum(totals)
            if offset > total:
                raise InvalidArgumentError(
                    details={"field": "cursor", "reason": "offset_after_end"}
                )
            rows: list[dict[str, Any]] = []
            remaining_offset = offset
            remaining_count = size + 1
            for source_name, source_total in zip(selected_sources, totals):
                if remaining_offset >= source_total:
                    remaining_offset -= source_total
                    continue
                window = _backend_call(
                    "get_flow_results",
                    lambda source_name=source_name, start=remaining_offset, count=remaining_count: self._backend.get_flow_results_window(
                        client_id,
                        flow_id,
                        artifact,
                        source=source_name,
                        start_row=start,
                        count=count,
                    ),
                )
                rows.extend(window)
                remaining_count -= len(window)
                remaining_offset = 0
                if remaining_count <= 0:
                    break
            generic = paginate_window_result(
                {"operation": "get_flow_results", "status": "success", "warnings": []},
                rows,
                cursor=cursor,
                page_size=size,
            )
            return FixedDataResult.model_validate(generic.model_dump(mode="json"))

        return self._target.run_with_client(operation)

    def _file_records(self, client_id: str, flow_id: str) -> _FileInventory:
        self._flow(client_id, flow_id)
        rows = _backend_call(
            "list_flow_files",
            lambda: self._backend.list_flow_uploads(client_id, flow_id),
        )
        if not isinstance(rows, list) or any(not isinstance(row, Mapping) for row in rows):
            raise BackendError(
                details={"operation": "list_flow_files", "reason": "invalid_uploads"}
            )
        return _deduplicated_uploads(rows, client_id=client_id, flow_id=flow_id)

    def list_flow_files(self, flow_id: str) -> FlowFileListResult:
        def operation(client_id: str):
            inventory = self._file_records(client_id, flow_id)
            warnings = (
                [f"sparse_indexes_internal:{inventory.sparse_count}"]
                if inventory.sparse_count
                else []
            )
            return limit_unpaged_result(
                {
                    "operation": "list_flow_files",
                    "status": "success",
                    "warnings": warnings,
                },
                [record.public_row() for record in inventory.records],
            )

        generic = self._target.run_with_client(operation)
        return FlowFileListResult.model_validate(generic.model_dump(mode="json"))

    def download_flow_file(self, flow_id: str, file_id: str) -> DownloadResult:
        _require_text(flow_id, "flow_id")
        normalized_file_id = _require_text(file_id, "file_id")
        if len(normalized_file_id) != 64 or any(
            character not in "0123456789abcdef" for character in normalized_file_id
        ):
            raise InvalidArgumentError(details={"field": "file_id", "reason": "format"})
        root = _backend_call(
            "download_flow_file", lambda: _download_root(self._download_root_value)
        )

        def operation(client_id: str) -> DownloadResult:
            inventory = self._file_records(client_id, flow_id)
            selected = next(
                (
                    record
                    for record in inventory.records
                    if record.file_id == normalized_file_id
                ),
                None,
            )
            if selected is None:
                raise NotFoundError(
                    details={"object_type": "flow_file", "object_id": normalized_file_id}
                )
            flow_key = hashlib.sha256(flow_id.encode("utf-8")).hexdigest()
            flow_dir = _backend_call(
                "download_flow_file", lambda: _ensure_child(root, root, flow_key)
            )
            file_dir = _backend_call(
                "download_flow_file",
                lambda: _ensure_child(root, flow_dir, normalized_file_id),
            )
            final = file_dir / "content.bin"
            if final.exists() or final.is_symlink():
                if final.exists():
                    _assert_plain_path(final, operation="download_flow_file")
                raise AlreadyExistsError(
                    details={"object_type": "flow_file", "object_id": normalized_file_id}
                )
            temp = file_dir / f".{uuid.uuid4().hex}.part"
            linked = False
            temp_identity: tuple[int, int] | None = None
            cleanup_attempted = False
            try:
                _assert_safe_chain(root, flow_dir, file_dir)
                if selected.index_selector is not None:
                    compact_size, _ = _read_vfs_stream(
                        self._backend, selected, padding=False
                    )
                    if compact_size != selected.uploaded_size:
                        raise BackendError(
                            details={
                                "operation": "download_flow_file",
                                "reason": "size_mismatch",
                            }
                        )
                with temp.open("xb") as stream:
                    info = os.fstat(stream.fileno())
                    temp_identity = (info.st_dev, info.st_ino)
                    size, digest = _read_vfs_stream(
                        self._backend,
                        selected,
                        padding=selected.index_selector is not None,
                        stream=stream,
                    )
                    stream.flush()
                    os.fsync(stream.fileno())
                _assert_safe_chain(root, flow_dir, file_dir, temp)
                if size != selected.file_size:
                    raise BackendError(
                        details={"operation": "download_flow_file", "reason": "size_mismatch"}
                    )
                refreshed = self._file_records(client_id, flow_id)
                refreshed_selected = next(
                    (
                        record
                        for record in refreshed.records
                        if record.file_id == normalized_file_id
                    ),
                    None,
                )
                if refreshed_selected != selected:
                    raise BackendError(
                        details={
                            "operation": "download_flow_file",
                            "reason": "metadata_changed",
                        }
                    )
                if temp_identity is None:
                    raise BackendError(
                        details={
                            "operation": "download_flow_file",
                            "reason": "path_escape",
                        }
                    )
                _assert_safe_chain(root, flow_dir, file_dir, temp)
                _assert_owned_file(temp, temp_identity)
                try:
                    os.link(temp, final)
                    linked = True
                except FileExistsError as exc:
                    raise AlreadyExistsError(
                        details={
                            "object_type": "flow_file",
                            "object_id": normalized_file_id,
                        }
                    ) from exc
                _assert_safe_chain(root, flow_dir, file_dir, final)
                _assert_owned_file(final, temp_identity)
                completed = _assert_contained(root, final, strict=True)
                if completed.stat().st_size != size:
                    raise BackendError(
                        details={"operation": "download_flow_file", "reason": "size_mismatch"}
                    )
                cleanup_attempted = True
                if temp_identity is None or not _cleanup_owned_temp(
                    root, file_dir, temp, temp_identity
                ):
                    logger.warning("download_temp_cleanup_failed")
                    raise DownloadPostPublishError(
                        details={
                            "operation": "download_flow_file",
                            "reason": "download_post_publish_failed",
                        }
                    )
                return DownloadResult(
                    operation="download_flow_file",
                    status="success",
                    warnings=[],
                    flow_id=flow_id,
                    file_id=normalized_file_id,
                    local_path=str(completed),
                    size=size,
                    sha256=digest,
                    original_path=selected.original_path,
                )
            except Exception as exc:
                if linked:
                    if not cleanup_attempted and temp_identity is not None:
                        cleanup_attempted = True
                        if not _cleanup_owned_temp(
                            root, file_dir, temp, temp_identity
                        ):
                            logger.warning("download_temp_cleanup_failed")
                    raise DownloadPostPublishError(
                        details={
                            "operation": "download_flow_file",
                            "reason": "download_post_publish_failed",
                        }
                    ) from exc
                if not cleanup_attempted and temp_identity is not None:
                    cleanup_attempted = True
                    if not _cleanup_owned_temp(
                        root, file_dir, temp, temp_identity
                    ):
                        logger.warning("download_temp_cleanup_failed")
                if isinstance(exc, (PublicError, grpc.RpcError)):
                    raise
                raise BackendError(
                    details={
                        "operation": "download_flow_file",
                        "reason": type(exc).__name__,
                    }
                ) from exc

        return self._target.run_with_client(operation)

    def cancel_flow(self, flow_id: str) -> CancelFlowResult:
        def operation(client_id: str) -> CancelFlowResult:
            before = self._flow(client_id, flow_id)
            state_before = str(before.get("state") or "")
            if state_before in TERMINAL_FLOW_STATES:
                raise NotCancellableError(
                    details={"object_type": "flow", "state": state_before}
                )
            _backend_call(
                "cancel_flow", lambda: self._backend.cancel_flow(client_id, flow_id)
            )
            after = self._flow(client_id, flow_id)
            state_after = str(after.get("state") or "")
            if not state_after:
                raise BackendError(
                    details={"operation": "cancel_flow", "reason": "missing_state"}
                )
            return CancelFlowResult(
                operation="cancel_flow",
                status="success",
                warnings=[],
                flow_id=flow_id,
                state_before=state_before,
                state_after=state_after,
            )

        return self._target.run_with_client(operation)

    def collect_file(self, path: str) -> FixedFlowReferenceResult:
        normalized = _require_text(path, "path")
        if normalized.startswith(("\\\\", "//")) or normalized.startswith(
            ("\\\\?\\", "\\\\.\\")
        ):
            raise InvalidArgumentError(details={"field": "path", "reason": "unsupported_root"})
        if len(normalized) < 4 or normalized[1] != ":" or normalized[2] not in "\\/":
            raise InvalidArgumentError(details={"field": "path", "reason": "absolute_windows"})
        drive = normalized[:2]
        glob = normalized[3:]
        if not glob:
            raise InvalidArgumentError(details={"field": "path", "reason": "empty_glob"})
        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(["Glob"])
        writer.writerow([glob])
        parameters = {"Root": drive, "collectionSpec": buffer.getvalue()}
        flow = self._target.run_with_client(
            lambda client_id: _backend_call(
                "collect_file",
                lambda: self._backend.start_collection(
                    client_id, FILE_ARTIFACT, parameters, timeout=120
                ),
            )
        )
        return FixedFlowReferenceResult(
            operation="collect_file",
            status="success",
            warnings=[],
            flow_id=flow.flow_id,
        )

    def _dependency_collection(
        self,
        *,
        artifact: str,
        parameters: Mapping[str, Any],
        timeout: int | None,
        max_upload_bytes: int | None = None,
        operation: str,
    ) -> FixedFlowReferenceResult:
        exists = _backend_call(
            "artifact_exists", lambda: self._backend.artifact_exists(artifact)
        )
        if not exists:
            raise DependencyMissingError(details={"artifact": artifact})
        collection_options = {"timeout": timeout}
        if max_upload_bytes is not None:
            collection_options["max_upload_bytes"] = max_upload_bytes
        flow = self._target.run_with_client(
            lambda client_id: _backend_call(
                operation,
                lambda: self._backend.start_collection(
                    client_id, artifact, parameters, **collection_options
                ),
            )
        )
        return FixedFlowReferenceResult(
            operation=operation,
            status="success",
            warnings=[],
            flow_id=flow.flow_id,
        )

    def collect_forensic_triage(self) -> FixedFlowReferenceResult:
        return self._dependency_collection(
            artifact=TRIAGE_ARTIFACT,
            parameters={
                "Targets": json.dumps(["_BasicCollection"], separators=(",", ":"))
            },
            timeout=2400,
            max_upload_bytes=TRIAGE_MAX_UPLOAD_BYTES,
            operation="collect_forensic_triage",
        )

    def kill_process(self, pid: int) -> FixedFlowReferenceResult:
        if not isinstance(pid, int) or isinstance(pid, bool) or not 1 <= pid <= 2_147_483_647:
            raise InvalidArgumentError(
                details={"field": "pid", "reason": "range", "minimum": 1, "maximum": 2_147_483_647}
            )
        return self._dependency_collection(
            artifact=KILL_PROCESS_ARTIFACT,
            parameters={"Pid": pid},
            timeout=120,
            operation="kill_process",
        )


def _fixed_handlers(service: FixedToolService) -> list[tuple[str, Any, str]]:
    def run_vql(query: NonEmptyString) -> Annotated[CallToolResult, FixedUnpagedDataResult]:
        """Run a bounded VQL query in the root organization."""
        try:
            return success_result(service.run_vql(query))
        except Exception as exc:
            return error_result(exc, operation="run_vql")

    def start_hunt(
        artifact: NonEmptyString,
        parameters: dict[str, Any] | None = None,
        description: str | None = None,
    ) -> Annotated[CallToolResult, HuntStartedResult]:
        """Create a paused hunt and attach one real flow for the unique Windows client."""
        try:
            return success_result(service.start_hunt(artifact, parameters, description))
        except Exception as exc:
            return error_result(exc, operation="start_hunt")

    def get_hunt_status(
        hunt_id: NonEmptyString,
    ) -> Annotated[CallToolResult, HuntStatusResult]:
        """Read one hunt and its only associated flow."""
        try:
            return success_result(service.get_hunt_status(hunt_id))
        except Exception as exc:
            return error_result(exc, operation="get_hunt_status")

    def stop_hunt(
        hunt_id: NonEmptyString,
    ) -> Annotated[CallToolResult, HuntStoppedResult]:
        """Stop a hunt without cancelling its associated flow."""
        try:
            return success_result(service.stop_hunt(hunt_id))
        except Exception as exc:
            return error_result(exc, operation="stop_hunt")

    def get_flow_status(
        flow_id: NonEmptyString,
    ) -> Annotated[CallToolResult, FlowStatusResult]:
        """Read the backend state and counters for one flow."""
        try:
            return success_result(service.get_flow_status(flow_id))
        except Exception as exc:
            return error_result(exc, operation="get_flow_status")

    def get_flow_results(
        flow_id: NonEmptyString,
        source: str | None = None,
        cursor: str | None = None,
        page_size: PageSize | None = None,
    ) -> Annotated[CallToolResult, FixedDataResult]:
        """Read one bounded cursor page from a flow result source."""
        try:
            return success_result(
                service.get_flow_results(flow_id, source, cursor, page_size)
            )
        except Exception as exc:
            return error_result(exc, operation="get_flow_results")

    def list_flow_files(
        flow_id: NonEmptyString,
    ) -> Annotated[CallToolResult, FlowFileListResult]:
        """List stable file identifiers for uploads in one flow."""
        try:
            return success_result(service.list_flow_files(flow_id))
        except Exception as exc:
            return error_result(exc, operation="list_flow_files")

    def download_flow_file(
        flow_id: NonEmptyString,
        file_id: NonEmptyString,
    ) -> Annotated[CallToolResult, DownloadResult]:
        """Download one enumerated flow file without overwriting existing output."""
        try:
            return success_result(service.download_flow_file(flow_id, file_id))
        except Exception as exc:
            return error_result(exc, operation="download_flow_file")

    def cancel_flow(
        flow_id: NonEmptyString,
    ) -> Annotated[CallToolResult, CancelFlowResult]:
        """Cancel one non-terminal flow and return its before/after state."""
        try:
            return success_result(service.cancel_flow(flow_id))
        except Exception as exc:
            return error_result(exc, operation="cancel_flow")

    def collect_file(
        path: NonEmptyString,
    ) -> Annotated[CallToolResult, FixedFlowReferenceResult]:
        """Collect one absolute Windows path or glob without downloading it."""
        try:
            return success_result(service.collect_file(path))
        except Exception as exc:
            return error_result(exc, operation="collect_file")

    def collect_forensic_triage() -> Annotated[CallToolResult, FixedFlowReferenceResult]:
        """Start the locked basic Windows forensic triage collection."""
        try:
            return success_result(service.collect_forensic_triage())
        except Exception as exc:
            return error_result(exc, operation="collect_forensic_triage")

    def kill_process(pid: Pid) -> Annotated[CallToolResult, FixedFlowReferenceResult]:
        """End one process through the locked Velociraptor process artifact."""
        try:
            return success_result(service.kill_process(pid))
        except Exception as exc:
            return error_result(exc, operation="kill_process")

    return [
        ("run_vql", run_vql, run_vql.__doc__ or ""),
        ("start_hunt", start_hunt, start_hunt.__doc__ or ""),
        ("get_hunt_status", get_hunt_status, get_hunt_status.__doc__ or ""),
        ("stop_hunt", stop_hunt, stop_hunt.__doc__ or ""),
        ("get_flow_status", get_flow_status, get_flow_status.__doc__ or ""),
        ("get_flow_results", get_flow_results, get_flow_results.__doc__ or ""),
        ("list_flow_files", list_flow_files, list_flow_files.__doc__ or ""),
        ("download_flow_file", download_flow_file, download_flow_file.__doc__ or ""),
        ("cancel_flow", cancel_flow, cancel_flow.__doc__ or ""),
        ("collect_file", collect_file, collect_file.__doc__ or ""),
        (
            "collect_forensic_triage",
            collect_forensic_triage,
            collect_forensic_triage.__doc__ or "",
        ),
        ("kill_process", kill_process, kill_process.__doc__ or ""),
    ]


def register_fixed_tools(
    server: MCPServer,
    specs: Sequence[ArtifactSpec],
    target: TargetContext,
    backend: VelociraptorBackend,
    *,
    download_root: str | None,
) -> FixedToolService:
    existing = set(server._tool_manager._tools)
    conflicts = sorted(existing.intersection(FIXED_TOOL_NAMES))
    if conflicts:
        raise ArtifactRegistryError(
            "fixed tool name conflicts: " + ", ".join(conflicts)
        )
    if len(set(FIXED_TOOL_NAMES)) != len(FIXED_TOOL_NAMES):
        raise ArtifactRegistryError("fixed tool names are not unique")
    service = FixedToolService(
        specs, target, backend, download_root=download_root
    )
    for name, handler, description in _fixed_handlers(service):
        server.add_tool(handler, name=name, description=description)
        tool = server._tool_manager.get_tool(name)
        if tool is None:
            raise ArtifactRegistryError(f"tool {name} was not registered")
        _strict_tool_schema(tool)
        for field_name in (
            "query",
            "artifact",
            "hunt_id",
            "flow_id",
            "file_id",
            "path",
        ):
            field = tool.parameters.get("properties", {}).get(field_name)
            if field is not None:
                field["minLength"] = 1
        if name == "kill_process":
            field = tool.parameters["properties"]["pid"]
            field.update({"minimum": 1, "maximum": 2_147_483_647})
        if name == "get_flow_results":
            page_schema = tool.parameters["properties"]["page_size"]
            branches = page_schema.get("anyOf", [])
            integer_branch = next(
                (branch for branch in branches if branch.get("type") == "integer"),
                None,
            )
            if integer_branch is None:
                raise ArtifactRegistryError("get_flow_results page_size schema is invalid")
            integer_branch.update({"minimum": 1, "maximum": 250})
        Draft202012Validator.check_schema(tool.parameters)
    return service


def validate_combined_registry(
    server: MCPServer, specs: Sequence[ArtifactSpec]
) -> None:
    expected = {spec.name for spec in specs}.union(FIXED_TOOL_NAMES)
    tools = server._tool_manager._tools
    if len(tools) != FINAL_TOOL_COUNT or set(tools) != expected:
        raise ArtifactRegistryError(
            f"combined tool registry mismatch: expected {FINAL_TOOL_COUNT}, actual {len(tools)}"
        )
    for name in sorted(expected):
        tool = server._tool_manager.get_tool(name)
        if tool is None:
            raise ArtifactRegistryError(f"combined registry is missing {name}")
        Draft202012Validator.check_schema(tool.parameters)
        if tool.fn_metadata.output_schema is None:
            raise ArtifactRegistryError(f"tool {name} has no output schema")
        Draft202012Validator.check_schema(tool.fn_metadata.output_schema)
