"""Six bounded guest transfer tools on the existing authenticated MCPServer."""

from __future__ import annotations

import asyncio
import os
import re
import threading
from typing import Annotated, Any, Literal

from jsonschema import Draft202012Validator
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.utilities.func_metadata import FuncMetadata
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, ValidationError, model_serializer, model_validator

from velociraptor_dynamic_artifacts import ArtifactRegistryError, _strict_tool_schema

from .errors import TransferContentError
from .guest_service import GuestTransferService


TRANSFER_TOOL_NAMES = (
    "transfer_capabilities", "transfer_begin", "transfer_status",
    "transfer_chunk", "transfer_finish", "transfer_abort",
)
_SCHEMA = "velo.transfer.mcp.response.v1"
HexDigest = Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]


class StrictObject(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Source(StrictObject):
    absolute_path: StrictStr = Field(min_length=1)
    relative_path: StrictStr = Field(min_length=1)


class Destination(StrictObject):
    endpoint: Literal["host", "guest"]
    identity: dict[StrictStr, StrictStr] = Field(min_length=1, max_length=16)
    canonical_path: StrictStr = Field(min_length=1)


class VmIdentity(StrictObject):
    vm_uuid: StrictStr = Field(min_length=1)
    boot_identity: StrictStr = Field(min_length=1)
    vm_epoch: StrictStr = Field(min_length=1, max_length=256)


class Evidence(StrictObject):
    producer_complete: StrictBool
    producer_quiescent: StrictBool
    references: list[StrictStr] = Field(min_length=1)


class Budget(StrictObject):
    max_files: StrictInt = Field(gt=0)
    max_metadata_bytes: StrictInt = Field(gt=0)
    max_logical_bytes: StrictInt = Field(ge=0)
    max_package_bytes: StrictInt = Field(gt=0)
    min_free_bytes: StrictInt = Field(ge=0)
    max_chunk_bytes: StrictInt = Field(gt=0)
    max_duration_seconds: StrictInt = Field(gt=0)


class Package(StrictObject):
    size: StrictInt = Field(ge=0)
    sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")


class TransferRequest(StrictObject):
    protocol_version: Literal["velo.transfer.v1"]
    transfer_id: StrictStr = Field(min_length=1, max_length=128)
    request_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    direction: Literal["pull", "push"]
    sources: list[Source] = Field(min_length=1)
    expected_destination: Destination
    expected_vm_identity: VmIdentity
    evidence_context: Evidence
    budget: Budget
    package: Package | None = None

    @model_validator(mode="after")
    def validate_direction(self):
        if (self.direction == "push") != (self.package is not None) or (
                self.direction == "pull" and "package" in self.model_fields_set):
            raise ValueError("direction/package mismatch")
        if self.expected_destination.endpoint != ("host" if self.direction == "pull" else "guest"):
            raise ValueError("direction/destination mismatch")
        return self


class ProtocolBinding(StrictObject):
    protocol_version: Literal["velo.transfer.v1"]
    transfer_id: StrictStr
    request_digest: HexDigest
    direction: Literal["pull", "push"]
    vm_uuid: StrictStr
    boot_identity: StrictStr
    vm_epoch: StrictStr
    policy_id: StrictStr
    package_size: StrictInt = Field(ge=0)
    package_sha256: HexDigest
    manifest_sha256: HexDigest


class PrepareReceipt(StrictObject):
    type: Literal["prepare"]
    binding: ProtocolBinding
    prepare_id: StrictStr = Field(min_length=1)
    identity_digest: HexDigest
    prepared: Literal[True]


class SourceValidationReceipt(StrictObject):
    type: Literal["source_validation"]
    binding: ProtocolBinding
    prepare_receipt_sha256: HexDigest
    identity_digest: HexDigest


class DirectoryIdentity(StrictObject):
    device: StrictInt = Field(ge=0)
    inode: StrictInt = Field(ge=0)


class PublicationReceipt(StrictObject):
    type: Literal["publication"]
    binding: ProtocolBinding
    prepare_receipt_sha256: HexDigest
    destination: Destination
    manifest_sha256: HexDigest
    directory_identity: DirectoryIdentity
    publication_id: StrictStr = Field(min_length=1)


class TransferEnvelope(StrictObject):
    schema_: Literal["velo.transfer.mcp.response.v1"] = Field(alias="schema")
    status: Literal["success", "error"]
    result: dict[str, Any] | None = None
    error: dict[str, str] | None = None

    @model_serializer
    def serialize_envelope(self):
        result = {"schema": self.schema_, "status": self.status}
        if self.status == "success":
            result["result"] = self.result
        else:
            result["error"] = self.error
        return result


class TransferFuncMetadata(FuncMetadata):
    """Validate the advertised raw JSON contract before SDK/Pydantic coercion."""

    input_contract: dict[str, Any]

    def validate_arguments(self, arguments_to_validate):
        try:
            if not Draft202012Validator(self.input_contract).is_valid(arguments_to_validate):
                raise ValueError("invalid_transfer_arguments")
            # Deliberately omit SDK pre_parse_json: JSON strings are not objects,
            # and a numeric/boolean wire type must not change before validation.
            parsed = self.arg_model.model_validate(arguments_to_validate)
            return parsed.model_dump_one_level()
        except (ValidationError, ValueError, TypeError, RecursionError):
            # The SDK includes ValidationError text in its protocol error. Never
            # attach raw input, schema-validation messages or their exception cause.
            raise ValidationError.from_exception_data("TransferArguments", [{
                "type": "value_error", "loc": (), "input": {},
                "ctx": {"error": ValueError("invalid_transfer_arguments")},
            }]) from None


class TransferToolService:
    """One lazy production service; explicit factory injection is Python-test-only."""

    def __init__(self, factory=None):
        self._factory = factory or GuestTransferService
        self._service = None
        self._lock = threading.RLock()
        self._closed = False

    def _get(self):
        with self._lock:
            if self._closed:
                raise TransferContentError("transfer_service_closed")
            if self._service is None:
                self._service = self._factory()
            return self._service

    def invoke(self, name: str, **arguments) -> TransferEnvelope:
        with self._lock:
            if self._closed:
                return self._failure("transfer_service_closed")
            if name not in TRANSFER_TOOL_NAMES:
                return self._failure("invalid_operation")
            if os.environ.get("VELOCIRAPTOR_TRANSFER_POLICY") in (None, "") and self._factory is GuestTransferService:
                if name == "transfer_capabilities":
                    return self._success({"schema": "velo.transfer.guest.response.v1",
                                          "enabled": False, "reason": "not_configured"})
                return self._failure("transfer_disabled")
            try:
                service = self._get()
                result = getattr(service, name)(**arguments)
                return self._success(result)
            except TransferContentError as exc:
                return self._failure(exc.code)
            except Exception:
                return self._failure("internal_error")

    @staticmethod
    def _success(result):
        return TransferEnvelope(schema=_SCHEMA, status="success", result=result)

    @staticmethod
    def _failure(code):
        if not isinstance(code, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,79}", code) is None:
            code = "internal_error"
        return TransferEnvelope(schema=_SCHEMA, status="error", error={"code": code})

    def shutdown(self):
        with self._lock:
            if self._closed:
                return
            if self._service is not None:
                self._service.shutdown()
            self._closed = True


def register_transfer_tools(server: MCPServer, *, factory=None) -> TransferToolService:
    existing = set(server._tool_manager._tools)
    if existing.intersection(TRANSFER_TOOL_NAMES):
        raise ArtifactRegistryError("transfer tool name conflict")
    manager = TransferToolService(factory)

    async def call(name, **args):
        return await asyncio.to_thread(manager.invoke, name, **args)

    async def transfer_capabilities() -> TransferEnvelope:
        return await call("transfer_capabilities")

    async def transfer_begin(request: TransferRequest) -> TransferEnvelope:
        return await call("transfer_begin", request=request.model_dump(exclude_none=True))

    async def transfer_status(transfer_id: StrictStr, request_digest: StrictStr) -> TransferEnvelope:
        return await call("transfer_status", transfer_id=transfer_id, request_digest=request_digest)

    async def transfer_chunk(transfer_id: StrictStr, request_digest: StrictStr,
                             offset: StrictInt, count: StrictInt,
                             data_base64: StrictStr | None = None,
                             chunk_sha256: StrictStr | None = None) -> TransferEnvelope:
        return await call("transfer_chunk", transfer_id=transfer_id, request_digest=request_digest,
                          offset=offset, count=count, data_base64=data_base64,
                          chunk_sha256=chunk_sha256)

    async def transfer_finish(transfer_id: StrictStr, request_digest: StrictStr,
                              action: Literal["prepare", "commit", "release"],
                              prepare_receipt: PrepareReceipt | None = None,
                              source_validation_receipt: SourceValidationReceipt | None = None,
                              publication_receipt: PublicationReceipt | None = None) -> TransferEnvelope:
        return await call("transfer_finish", transfer_id=transfer_id, request_digest=request_digest,
                          action=action,
                          prepare_receipt=prepare_receipt.model_dump() if prepare_receipt else None,
                          source_validation_receipt=(source_validation_receipt.model_dump()
                                                     if source_validation_receipt else None),
                          publication_receipt=publication_receipt.model_dump() if publication_receipt else None)

    async def transfer_abort(transfer_id: StrictStr, request_digest: StrictStr) -> TransferEnvelope:
        return await call("transfer_abort", transfer_id=transfer_id, request_digest=request_digest)

    handlers = (transfer_capabilities, transfer_begin, transfer_status,
                transfer_chunk, transfer_finish, transfer_abort)
    for name, handler in zip(TRANSFER_TOOL_NAMES, handlers, strict=True):
        server.add_tool(handler, name=name, description=f"Local guest {name.replace('_', ' ')}")
        tool = server._tool_manager.get_tool(name)
        if tool is None:
            raise ArtifactRegistryError("transfer registration missing")
        _strict_tool_schema(tool)
        parameters = tool.parameters
        props = parameters.get("properties", {})
        if "transfer_id" in props:
            props["transfer_id"]["minLength"] = 1
        if "request_digest" in props:
            props["request_digest"]["pattern"] = r"^[0-9a-f]{64}$"
        if name == "transfer_begin":
            request_schema = parameters["$defs"]["TransferRequest"]
            request_schema["properties"]["package"] = {"$ref": "#/$defs/Package"}
            request_schema.pop("default", None)
            request_schema["allOf"] = [{
                "if": {"properties": {"direction": {"const": "push"}}, "required": ["direction"]},
                "then": {"required": ["package"], "properties": {
                    "expected_destination": {"properties": {"endpoint": {"const": "guest"}}}}},
                "else": {"not": {"required": ["package"]}, "properties": {
                    "expected_destination": {"properties": {"endpoint": {"const": "host"}}}}},
            }]
        if name == "transfer_chunk":
            props["offset"]["minimum"] = 0
            props["count"]["minimum"] = 1
            props["data_base64"] = {"type": "string"}
            props["chunk_sha256"] = {"type": "string", "pattern": r"^[0-9a-f]{64}$"}
            parameters["oneOf"] = [{"required": ["data_base64", "chunk_sha256"]},
                                   {"not": {"anyOf": [{"required": ["data_base64"]},
                                                        {"required": ["chunk_sha256"]}]}}]
        if name == "transfer_finish":
            for receipt in ("prepare_receipt", "source_validation_receipt", "publication_receipt"):
                model = {"prepare_receipt": "PrepareReceipt",
                         "source_validation_receipt": "SourceValidationReceipt",
                         "publication_receipt": "PublicationReceipt"}[receipt]
                props[receipt] = {"$ref": f"#/$defs/{model}"}
            parameters["allOf"] = [
                {"if": {"properties": {"action": {"const": "prepare"}}, "required": ["action"]},
                 "then": {"not": {"anyOf": [{"required": [key]} for key in (
                     "prepare_receipt", "source_validation_receipt", "publication_receipt")]}}},
                {"if": {"properties": {"action": {"const": "commit"}}, "required": ["action"]},
                 "then": {"required": ["prepare_receipt", "source_validation_receipt"],
                          "not": {"required": ["publication_receipt"]}}},
                {"if": {"properties": {"action": {"const": "release"}}, "required": ["action"]},
                 "then": {"required": ["prepare_receipt", "publication_receipt"],
                          "not": {"required": ["source_validation_receipt"]}}},
            ]
        tool.fn_metadata.output_schema = {
            "type": "object",
            "oneOf": [
                {"type": "object", "additionalProperties": False,
                 "properties": {"schema": {"const": _SCHEMA}, "status": {"const": "success"},
                                "result": {"type": "object"}},
                 "required": ["schema", "status", "result"]},
                {"type": "object", "additionalProperties": False,
                 "properties": {"schema": {"const": _SCHEMA}, "status": {"const": "error"},
                                "error": {"type": "object", "additionalProperties": False,
                                          "properties": {"code": {"type": "string",
                                                                  "pattern": "^[a-z][a-z0-9_]{0,79}$"}},
                                          "required": ["code"]}},
                 "required": ["schema", "status", "error"]},
            ]}
        Draft202012Validator.check_schema(parameters)
        Draft202012Validator.check_schema(tool.fn_metadata.output_schema)
        previous = tool.fn_metadata
        tool.fn_metadata = TransferFuncMetadata(
            arg_model=previous.arg_model, output_schema=previous.output_schema,
            output_model=previous.output_model, wrap_output=previous.wrap_output,
            input_contract=parameters,
        )
    return manager
