"""Bounded host transport adapters; global transfer state belongs to the caller."""

from __future__ import annotations

import asyncio
import base64
import errno
import hashlib
import json
import re
import secrets
import ssl
import time
from contextlib import asynccontextmanager
from importlib.resources import files
from typing import Any

import httpx2
from jsonschema import Draft202012Validator
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from .connection import ConnectionProfile
from . import windows_commands as wc
from .errors import TransferContentError

NAMES = ("transfer_capabilities", "transfer_begin", "transfer_status", "transfer_chunk",
         "transfer_chunks", "transfer_finish", "transfer_abort")
READ_ONLY = frozenset(("transfer_capabilities", "transfer_status"))
SCHEMAS = json.loads(files("velo_transfer").joinpath("transfer_tools_schema.json").read_text())


class AdapterError(Exception):
    def __init__(self, code: str, *, may_have_committed: bool = False, retryable: bool = False,
                 guest_result: dict | None = None, cleanup_path: str | None = None):
        self.code = code
        self.may_have_committed = may_have_committed
        self.retryable = retryable
        self.guest_result = guest_result
        self.cleanup_path = cleanup_path
        self.operation: str | None = None
        self.transfer_id: str | None = None
        self.request_digest: str | None = None
        super().__init__(code)


def _remaining(deadline: float, per_request: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AdapterError("deadline_exceeded")
    if not 0 < per_request <= 300:
        raise AdapterError("invalid_timeout")
    return min(remaining, per_request)


def _command(builder, *args):
    try:
        return builder(*args)
    except ValueError:
        raise AdapterError("command_too_long") from None


def _json_pairs(items):
    result = {}
    for k, v in items:
        if k in result:
            raise AdapterError("malformed_response")
        result[k] = v
    return result


def _guest_result(envelope: Any) -> dict:
    if not isinstance(envelope, dict) or envelope.get("schema") != "velo.transfer.mcp.response.v1":
        raise AdapterError("malformed_response")
    if set(envelope) == {"schema", "status", "error"} and envelope["status"] == "error":
        error = envelope["error"]
        if not isinstance(error, dict) or set(error) != {"code"} or not isinstance(error["code"], str):
            raise AdapterError("malformed_response")
        raise AdapterError(error["code"])
    if set(envelope) != {"schema", "status", "result"} or envelope["status"] != "success":
        raise AdapterError("malformed_response")
    result = envelope["result"]
    if not isinstance(result, dict) or result.get("schema") != "velo.transfer.guest.response.v1":
        raise AdapterError("malformed_response")
    return result


def _validate_capabilities(caps: dict, expected_vm_identity: dict) -> None:
    if caps.get("enabled") is False:
        raise AdapterError("capabilities_disabled")
    if caps.get("enabled") is not True or caps.get("protocol_version") != "velo.transfer.v1":
        raise AdapterError("protocol_error")
    if any(caps.get(k) != expected_vm_identity[k] for k in ("vm_uuid", "boot_identity")):
        raise AdapterError("identity_mismatch")
    if any(not isinstance(caps.get(k), str) or not caps[k] for k in ("build", "policy_id")):
        raise AdapterError("protocol_error")
    limits = caps.get("limits")
    maximum = limits.get("max_chunk_bytes") if isinstance(limits, dict) else None
    default = caps.get("default_chunk_bytes")
    if (not isinstance(maximum, int) or isinstance(maximum, bool) or maximum <= 0 or
            not isinstance(default, int) or isinstance(default, bool) or not 0 < default <= maximum):
        raise AdapterError("protocol_error")


def _classify(exc: Exception, operation: str | None = None) -> AdapterError:
    unknown = operation is not None and operation not in READ_ONLY
    if isinstance(exc, BaseExceptionGroup):
        classified = [_classify(child, operation) for child in exc.exceptions if isinstance(child, Exception)]
        if classified and all(item.code == "connection_unavailable" for item in classified):
            return classified[0]
        for item in classified:
            if item.code not in ("connection_unavailable", "protocol_error"):
                return item
        return AdapterError("protocol_error", may_have_committed=unknown)
    if isinstance(exc, HTTPBodyLimitError):
        return AdapterError(str(exc), may_have_committed=unknown)
    if isinstance(exc, AdapterError):
        return exc
    if isinstance(exc, httpx2.ConnectError):
        seen = set()
        stack = [exc.__cause__, exc.__context__]
        unreachable = False
        while stack:
            current = stack.pop()
            if current is None or id(current) in seen:
                continue
            seen.add(id(current))
            if isinstance(current, (ssl.SSLError, ssl.CertificateError)):
                return AdapterError("tls_auth_failed", may_have_committed=unknown)
            if isinstance(current, OSError) and current.errno in (
                    errno.ECONNREFUSED, errno.ENETUNREACH, errno.EHOSTUNREACH):
                unreachable = True
            if isinstance(current, BaseExceptionGroup):
                stack.extend(current.exceptions)
            stack.extend((current.__cause__, current.__context__))
        if unreachable:
            return AdapterError("outcome_unknown" if unknown else "connection_unavailable",
                                may_have_committed=unknown, retryable=not unknown)
        return AdapterError("connection_failed", may_have_committed=unknown)
    if isinstance(exc, (httpx2.TimeoutException, asyncio.TimeoutError, httpx2.NetworkError)):
        return AdapterError("outcome_unknown" if unknown else "transport_timeout",
                            may_have_committed=unknown, retryable=not unknown)
    if isinstance(exc, httpx2.HTTPStatusError):
        status = exc.response.status_code
        if status in (401, 403):
            return AdapterError("authentication_denied")
        if status in (400, 421):
            return AdapterError("host_rejected")
    return AdapterError("protocol_error", may_have_committed=unknown)


def _group_leaves(group: BaseExceptionGroup) -> list[BaseException]:
    leaves = []
    for child in group.exceptions:
        if isinstance(child, BaseExceptionGroup):
            leaves.extend(_group_leaves(child))
        else:
            leaves.append(child)
    return leaves


from . import wire
from .http_budget import CountedTransport, HTTPBodyLimitError, CALL_HTTP_FAILURE

_VBT_MAGIC = wire.MAGIC


def _header_bytes(header):
    return json.dumps(header, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _parse_vbt(body):
    try:
        return wire.parse(body)
    except wire.WireError:
        raise AdapterError("malformed_response") from None


def _http_safety_code(status, content_type, body):
    """Classify exact non-200 safety JSON before considering instance headers."""
    try:
        error = wire.strict_json(body)
        code = error["error"]["code"]
        allowed = ("session_required", "invalid_frame") if status == 400 else (wire.HTTP_ERRORS.get(status),)
        if (content_type != "application/json" or type(code) is not str or
                error != {"error": {"code": code}} or code not in allowed):
            raise wire.WireError("invalid_frame")
        return code
    except (wire.WireError, KeyError, TypeError):
        return "protocol_error"


class _DirectChunkChannel:
    """Binary encoding on the same HTTP client and official SDK live session.

    This channel never initializes another session, probes a write, retries a
    write, or falls back to JSON after any uncertain outcome.
    """
    def __init__(self, http, url, session_id, instance, deadline, timeout):
        self.http = http; self.url = url.rsplit("/", 1)[0] + "/chunkbin"
        self.session_id = session_id; self.instance = instance
        self.deadline = deadline; self.timeout = timeout

    async def call(self, name, arguments):
        if name != "transfer_chunks":
            raise AdapterError("invalid_operation")
        push = "chunks" in arguments
        direction = "push" if push else "pull"
        headers = {"Mcp-Session-Id":self.session_id, "X-MCP-Server-Instance":self.instance,
            "Content-Type":"application/octet-stream", "x-velo-direction":direction,
            "x-velo-transfer-id":arguments["transfer_id"],
            "x-velo-request-digest":arguments["request_digest"], "x-velo-offset":str(arguments["offset"])}
        try:
            if push:
                meta = [{k:c[k] for k in ("count", "chunk_sha256")} for c in arguments["chunks"]]
                payload = b"".join(base64.b64decode(c["data_base64"], validate=True) for c in arguments["chunks"])
                body = wire.encode({"chunks":meta},payload,"push_request")
            else:
                headers.update({"x-velo-count-per-chunk":str(arguments["count_per_chunk"]),
                                "x-velo-chunk-count":str(arguments["chunk_count"])})
                body = wire.encode({},b"","pull_request")
        except (wire.WireError, ValueError):
            raise AdapterError("invalid_arguments") from None
        async def outgoing():
            for i in range(0,len(body),65536):
                _remaining(self.deadline,self.timeout)
                yield body[i:i+65536]
        try:
            timeout = _remaining(self.deadline,self.timeout)
            async with asyncio.timeout(timeout):
                async with self.http.stream("POST",self.url,headers=headers,content=outgoing()) as response:
                    if response.status_code == 200 and response.headers.get("x-mcp-server-instance") != self.instance:
                        raise AdapterError("instance_changed",may_have_committed=push)
                    data = bytearray()
                    async for part in response.aiter_bytes():
                        if len(data)+len(part)>wire.BODY_LIMIT:
                            raise AdapterError("response_too_large",may_have_committed=push)
                        data.extend(part)
                    if response.status_code != 200:
                        raise AdapterError(_http_safety_code(response.status_code,
                            response.headers.get("content-type"), bytes(data)), may_have_committed=push)
                    if response.headers.get("content-type") != "application/octet-stream":
                        raise AdapterError("malformed_response",may_have_committed=push)
                    header,payload = wire.parse(bytes(data))
                    component = "error_response" if header.get("status")=="error" else direction+"_response"
                    wire.validate(header,payload,component)
                    if component=="error_response":
                        raise AdapterError(header["error"]["code"])
                    result = header["result"]
                    if push:
                        if result["accepted"]!=len(arguments["chunks"]) or result["verified_offset"]!=arguments["offset"]+sum(c["count"] for c in arguments["chunks"]):
                            raise AdapterError("malformed_response",may_have_committed=True)
                    else:
                        meta = result["chunks"]
                        if len(meta)>arguments["chunk_count"] or (meta and meta[0]["offset"]!=arguments["offset"]):
                            raise AdapterError("malformed_response")
                        chunks=[];cursor=0
                        for index,item in enumerate(meta):
                            count=item["count"]
                            if count>arguments["count_per_chunk"] or (index<len(meta)-1 and count!=arguments["count_per_chunk"]):
                                raise AdapterError("malformed_response")
                            chunks.append(dict(item,data_base64=base64.b64encode(payload[cursor:cursor+count]).decode("ascii")))
                            cursor+=count
                        result=dict(result,chunks=chunks)
                    return dict(result,schema="velo.transfer.guest.response.v1")
        except wire.WireError:
            raise AdapterError("malformed_response",may_have_committed=push) from None
        except HTTPBodyLimitError as exc:
            raise AdapterError(str(exc),may_have_committed=push) from None
        except AdapterError:
            raise
        except Exception as exc:
            raise _classify(exc,name if push else "transfer_status") from None


class TransportAdapter:
    def __init__(self, session: ClientSession, channel: str, endpoint: str, deadline: float,
                 request_timeout: float, instances: list[str]):
        self._session = session
        self.channel = channel
        self.endpoint = endpoint
        self.deadline_monotonic = deadline
        self.request_timeout_seconds = request_timeout
        self.raw_chunk_bytes = 1 << 20
        self.batch_chunks = 1
        self._instances = instances
        self._direct = None
        self._binary_factory = None
        self._wire_selected = None
        self.observations: dict[str, Any] = {"endpoint": endpoint, "instance": instances[-1] if instances else None,
                                              "instance_changed": len(set(instances)) > 1}
        self.fallback_reason: str | None = None
        self._last_result: dict | None = None

    def _observe(self):
        if self._instances:
            current = self._instances[-1]
            if self.observations["instance"] is not None and current != self.observations["instance"]:
                self.observations["instance_changed"] = True
            self.observations["instance"] = current

    async def _invoke(self, name: str, arguments: dict):
        attempted = False
        if name == "transfer_chunks" and self._direct is not None:
            attempted = True
            try:
                return await self._direct.call(name, arguments)
            except AdapterError as exc:
                if name not in READ_ONLY and exc.code != "batch_not_allowed":
                    exc.may_have_committed = True
                    exc.retryable = False
                raise
            except Exception as exc:
                raise _classify(exc, name) from None
        failure = {}
        failure_token = CALL_HTTP_FAILURE.set(failure)
        try:
            timeout = _remaining(self.deadline_monotonic, self.request_timeout_seconds)
            attempted = True
            result = await asyncio.wait_for(
                self._session.call_tool(name, arguments, read_timeout_seconds=timeout),
                timeout=timeout)
            self._observe()
            if self.observations["instance_changed"]:
                raise AdapterError("instance_changed", may_have_committed=name not in READ_ONLY)
            if result.is_error or not isinstance(result.structured_content, dict):
                raise AdapterError("tool_error" if result.is_error else "malformed_response")
            envelope = result.structured_content
            if not Draft202012Validator(SCHEMAS[name]["outputSchema"]).is_valid(envelope):
                raise AdapterError("malformed_response")
            if result.content:
                # MCPServer publishes the same structured JSON as the single text block.
                if len(result.content) != 1 or result.content[0].type != "text":
                    raise AdapterError("malformed_response")
                try:
                    content = json.loads(result.content[0].text, object_pairs_hook=_json_pairs)
                except (ValueError, TypeError):
                    raise AdapterError("malformed_response") from None
                if content != envelope:
                    raise AdapterError("malformed_response")
            return _guest_result(envelope)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            error = AdapterError(failure["code"]) if failure.get("code") else _classify(exc, name)
            if attempted and name not in READ_ONLY and error.code != "batch_not_allowed":
                error.may_have_committed = True
                # Unknown writes require coordinator proof reconciliation.
                error.retryable = False
            raise error from None
        finally:
            CALL_HTTP_FAILURE.reset(failure_token)

    async def call(self, operation: str, arguments: dict) -> dict:
        if operation not in NAMES or not isinstance(arguments, dict):
            raise AdapterError("invalid_operation")
        validator = Draft202012Validator(SCHEMAS[operation]["inputSchema"])
        errors = sorted(validator.iter_errors(arguments), key=lambda e: list(e.path))
        if errors:
            raise AdapterError("invalid_arguments")
        if operation == "transfer_chunk" and arguments["count"] > self.raw_chunk_bytes:
            raise AdapterError("chunk_too_large")
        if operation in ("transfer_chunk", "transfer_chunks"):
            chunks = arguments.get("chunks", [arguments] if "data_base64" in arguments else [])
            total = 0
            for item in chunks:
                count = item["count"]
                if count > self.raw_chunk_bytes or len(item["data_base64"]) > 4 * ((count + 2) // 3):
                    raise AdapterError("chunk_too_large")
                total += count
                if total > wire.BATCH_LIMIT:
                    raise AdapterError("chunk_too_large")
                try:
                    raw = base64.b64decode(item["data_base64"], validate=True)
                except ValueError:
                    raise AdapterError("invalid_chunk") from None
                if len(raw) != count or hashlib.sha256(raw).hexdigest() != item["chunk_sha256"]:
                    raise AdapterError("chunk_hash_mismatch")
        # Count the JSON request before the SDK constructs its encoded body.
        # iterencode bounds counting without joining an unbounded document.
        size = 0
        for part in json.JSONEncoder(ensure_ascii=False).iterencode({"jsonrpc":"2.0","id":0,
                "method":"tools/call","params":{"name":operation,"arguments":arguments}}):
            size += len(part.encode("utf-8"))
            if size > wire.BODY_LIMIT - 4096:
                raise AdapterError("request_too_large")
        attempts = 3 if operation in READ_ONLY else 1
        for i in range(attempts):
            try:
                result = await self._invoke(operation, arguments)
                if operation == "transfer_capabilities":
                    self.observations.update({k: result.get(k) for k in (
                        "vm_uuid", "boot_identity", "policy_id", "build", "limits", "protocol_version")})
                    limit = result.get("limits", {}).get("max_chunk_bytes") if isinstance(result.get("limits"), dict) else None
                    if isinstance(limit, int) and not isinstance(limit, bool) and limit > 0:
                        self.raw_chunk_bytes = min(1 << 20, limit)
                    selected = result.get("binary_wire") == {"version":"VBT1","session_required":True}
                    if self._wire_selected is not None and self._wire_selected != selected:
                        raise AdapterError("protocol_error")
                    self._wire_selected = selected
                    if selected:
                        if self._binary_factory is None:
                            raise AdapterError("protocol_error")
                        self._direct = self._binary_factory()
                    batch = result.get("max_batch_chunks")
                    # Leave room for JSON metadata and the SDK text mirror.
                    # CountedTransport independently enforces actual body bytes.
                    if type(batch) is int and 1 <= batch <= 64:
                        response_budget = 100 * 1024 * 1024
                        encoded_chunk = 4 * (self.raw_chunk_bytes + 2) // 3
                        self.batch_chunks = max(1, min(batch, response_budget // (2 * (encoded_chunk + 2048))))
                    else:
                        self.batch_chunks = 1
                self._last_result = result
                return result
            except AdapterError as exc:
                exc.operation = operation
                details = arguments.get("request", arguments)
                exc.transfer_id = details.get("transfer_id")
                exc.request_digest = details.get("request_digest")
                if not exc.retryable or i == attempts - 1:
                    raise
        raise AdapterError("transport_timeout")

    async def probe(self, expected_vm_identity: dict) -> None:
        if not isinstance(expected_vm_identity, dict) or not all(
                isinstance(expected_vm_identity.get(key), str) and expected_vm_identity[key]
                for key in ("vm_uuid", "boot_identity")):
            raise AdapterError("invalid_expected_identity")
        try:
            listed = await asyncio.wait_for(self._session.list_tools(), timeout=_remaining(
                self.deadline_monotonic, self.request_timeout_seconds))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise _classify(exc, "transfer_capabilities") from None
        found = {tool.name: tool for tool in listed.tools}
        if any(name not in found for name in NAMES):
            raise AdapterError("incompatible_server")
        for name in NAMES:
            tool = found[name]
            if tool.input_schema != SCHEMAS[name]["inputSchema"] or tool.output_schema != SCHEMAS[name]["outputSchema"]:
                raise AdapterError("schema_mismatch")
        caps = await self.call("transfer_capabilities", {})
        _validate_capabilities(caps, expected_vm_identity)


class WindowsAdapter(TransportAdapter):
    def __init__(self, session, endpoint, deployment, deadline, request_timeout, instances):
        super().__init__(session, "windows", endpoint, deadline, request_timeout, instances)
        self._deployment = deployment
        self.raw_chunk_bytes = 4096

    async def _powershell(self, script: str, *, operation: str | None = None,
                          helper: bool = False) -> str | tuple[str, int]:
        try:
            wc.bounded(script)
            timeout = _remaining(self.deadline_monotonic, self.request_timeout_seconds)
        except ValueError:
            raise AdapterError("command_too_long") from None
        try:
            result = await asyncio.wait_for(self._session.call_tool(
                "PowerShell", {"command": script, "timeout": max(1, min(30, int(
                    timeout)))}, read_timeout_seconds=timeout), timeout=timeout)
            self._observe()
            return wc.parse_outer_status(result) if helper else wc.parse_outer(result)
        except asyncio.CancelledError:
            raise
        except ValueError:
            raise AdapterError("powershell_response", may_have_committed=operation not in READ_ONLY) from None
        except Exception as exc:
            raise _classify(exc, operation) from None

    async def probe(self, expected_vm_identity: dict) -> None:
        if not isinstance(expected_vm_identity, dict) or not all(
                isinstance(expected_vm_identity.get(key), str) and expected_vm_identity[key]
                for key in ("vm_uuid", "boot_identity")):
            raise AdapterError("invalid_expected_identity")
        try:
            listed = await asyncio.wait_for(self._session.list_tools(), timeout=_remaining(
                self.deadline_monotonic, self.request_timeout_seconds))
            found = {tool.name: tool for tool in listed.tools}
            schema = found["PowerShell"].input_schema
            props = schema.get("properties", {})
            if (set(props) != {"command", "timeout"} or props["command"].get("type") != "string" or
                    props["timeout"].get("type") != "integer" or "command" not in schema.get("required", [])):
                raise AdapterError("schema_mismatch")
        except KeyError:
            raise AdapterError("tools_missing") from None
        caps = await self.call("transfer_capabilities", {})
        _validate_capabilities(caps, expected_vm_identity)

    async def call(self, operation: str, arguments: dict) -> dict:
        if operation not in NAMES or not isinstance(arguments, dict):
            raise AdapterError("invalid_operation")
        validator = Draft202012Validator(SCHEMAS[operation]["inputSchema"])
        errors = sorted(validator.iter_errors(arguments), key=lambda e: list(e.path))
        if errors:
            raise AdapterError("invalid_arguments")
        if operation == "transfer_chunk" and arguments["count"] > self.raw_chunk_bytes:
            raise AdapterError("chunk_too_large")
        raw = json.dumps({"operation": operation, "arguments": arguments}, ensure_ascii=False,
                         sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(raw) > 4 * 1024 * 1024:
            raise AdapterError("request_too_large")
        path = wc.requests_path(self._deployment.guest_work_root, secrets.token_hex(16))
        owned = False
        owner_identity = None
        create_attempted = False
        invoked = False
        result = None
        pending_error = None
        try:
            create = _command(wc.create_script, path)
            create_attempted = True
            created = await self._powershell(create, operation=operation)
            matched = re.fullmatch(r"ACK:created:([0-9a-f]{24})", created)
            if matched is None:
                raise AdapterError("control_ack_invalid", may_have_committed=True)
            owner_identity = matched.group(1)
            owned = True
            offset = 0
            while offset < len(raw):
                count = min(4096, len(raw) - offset)
                while count:
                    try:
                        script = wc.write_script(path, offset, raw[offset:offset + count], owner_identity)
                        break
                    except ValueError:
                        count //= 2
                if not count:
                    raise AdapterError("command_too_long")
                expected = f"ACK:{offset}:{count}:{hashlib.sha256(raw[offset:offset + count]).hexdigest()}"
                for attempt in range(2):
                    try:
                        ack = await self._powershell(script, operation=operation)
                        if ack != expected:
                            raise AdapterError("control_ack_invalid", may_have_committed=True)
                        break
                    except AdapterError as exc:
                        if attempt or exc.code not in ("outcome_unknown", "transport_timeout"):
                            raise
                offset += count
            if await self._powershell(_command(wc.verify_script, path, len(raw), hashlib.sha256(raw).hexdigest(),
                                               owner_identity),
                                      operation=operation) != "ACK:verified":
                raise AdapterError("control_ack_invalid", may_have_committed=True)
            invoked = True
            stdout, exit_code = await self._powershell(_command(wc.invoke_script, path, self._deployment.python_path,
                                                                self._deployment.project_root,
                                                                self._deployment.policy_path, owner_identity,
                                                                self._deployment.extra_trusted_sids),
                                                       operation=operation, helper=True)
            try:
                result = wc.parse_helper(stdout, exit_code)
            except wc.GuestHelperError as exc:
                raise AdapterError(exc.code, may_have_committed=operation not in READ_ONLY) from None
            except (ValueError, TypeError):
                raise AdapterError("helper_response", may_have_committed=operation not in READ_ONLY) from None
            if result.get("schema") != "velo.transfer.guest.response.v1":
                raise AdapterError("helper_response", may_have_committed=operation not in READ_ONLY)
            if operation == "transfer_capabilities":
                self.observations.update({k: result.get(k) for k in (
                    "vm_uuid", "boot_identity", "policy_id", "build", "limits", "protocol_version")})
                if result.get("enabled") is True:
                    limits = result.get("limits")
                    maximum = limits.get("max_chunk_bytes") if isinstance(limits, dict) else None
                    default = result.get("default_chunk_bytes")
                    if (not isinstance(maximum, int) or isinstance(maximum, bool) or maximum <= 0 or
                            not isinstance(default, int) or isinstance(default, bool) or not 0 < default <= maximum):
                        raise AdapterError("protocol_error")
                    self.raw_chunk_bytes = min(4096, maximum, default)
        except BaseException as exc:
            pending_error = exc
        finally:
            if owned:
                try:
                    if await self._powershell(_command(wc.cleanup_script, path, owner_identity),
                                              operation=operation) != "ACK:deleted":
                        raise AdapterError("cleanup_failed", may_have_committed=invoked)
                except BaseException as cleanup:
                    self.observations["cleanup_failed"] = True
                    self.observations["pending_control_path"] = path
                    if pending_error is None:
                        pending_error = AdapterError("cleanup_failed", may_have_committed=invoked,
                                                     guest_result=result, cleanup_path=path)
                    elif isinstance(pending_error, AdapterError):
                        pending_error.cleanup_path = path
            elif create_attempted and pending_error is not None:
                self.observations["control_cleanup_unknown"] = True
                self.observations["pending_control_path"] = path
        if pending_error is not None:
            if isinstance(pending_error, AdapterError):
                pending_error.operation = operation
                details = arguments.get("request", arguments)
                pending_error.transfer_id = details.get("transfer_id")
                pending_error.request_digest = details.get("request_digest")
            raise pending_error
        self._last_result = result
        return result


@asynccontextmanager
async def open_adapter(profile: ConnectionProfile, channel: str, *, deadline_monotonic: float,
                       request_timeout_seconds: float):
    if channel not in ("velo", "windows"):
        raise AdapterError("invalid_channel")
    endpoint = profile.velo if channel == "velo" else profile.windows
    if endpoint is None:
        raise AdapterError("channel_unconfigured")
    instances: list[str] = []
    denied_status: list[int] = []
    session_ids: list[str] = []

    async def response_hook(response):
        sid = response.headers.get("mcp-session-id")
        if sid is not None:
            session_ids.append(sid)
        failure = CALL_HTTP_FAILURE.get()
        if failure is not None and response.status_code >= 400:
            try:
                body = await response.aread()
                failure["code"] = _http_safety_code(response.status_code,
                    response.headers.get("content-type"), body)
            except HTTPBodyLimitError as exc:
                failure["code"] = str(exc)
        if response.status_code in (400, 401, 403, 421):
            denied_status.append(response.status_code)
        value = response.headers.get("x-mcp-server-instance")
        if value is not None:
            instances.append(value)

    try:
        opened = False
        body_completed = False
        adapter = None
        timeout = _remaining(deadline_monotonic, request_timeout_seconds)
        headers = {"Authorization": "Bearer " + endpoint.token.read()} if endpoint.token is not None else {}
        async with httpx2.AsyncClient(headers={**headers,"Accept-Encoding":"identity"},
                                      transport=CountedTransport(),
                                      timeout=timeout, follow_redirects=False, trust_env=False,
                                      event_hooks={"response": [response_hook]}) as http:
            async with streamable_http_client(endpoint.url, http_client=http) as (read, write):
                async with ClientSession(read, write) as session:
                    await asyncio.wait_for(session.initialize(), timeout=_remaining(
                        deadline_monotonic, request_timeout_seconds))
                    if channel == "windows":
                        adapter = WindowsAdapter(session, endpoint.url, profile.deployment,
                                                 deadline_monotonic, request_timeout_seconds, instances)
                        opened = True
                        yield adapter
                    else:
                        adapter = TransportAdapter(session, channel, endpoint.url, deadline_monotonic,
                                                   request_timeout_seconds, instances)
                        def binary_factory():
                            if not session_ids or len(set(session_ids)) != 1 or not instances or len(set(instances)) != 1:
                                raise AdapterError("protocol_error")
                            return _DirectChunkChannel(http, endpoint.url, session_ids[0], instances[0],
                                                       deadline_monotonic, request_timeout_seconds)
                        adapter._binary_factory = binary_factory
                        opened = True
                        yield adapter
                    body_completed = True
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        if opened and isinstance(exc, BaseExceptionGroup):
            leaves = _group_leaves(exc)
            local = [leaf for leaf in leaves if isinstance(leaf, TransferContentError)]
            if len(leaves) == 1 and local:
                raise local[0] from None
            if local:
                # Other leaves make the outcome uncertain; never select a
                # local leaf or trigger pre-begin fallback.
                raise AdapterError("protocol_error", may_have_committed=True) from None
        if opened and not isinstance(exc, (AdapterError, BaseExceptionGroup)):
            raise
        leaves = _group_leaves(exc) if isinstance(exc, BaseExceptionGroup) else [exc]
        if any(isinstance(leaf, AdapterError) for leaf in leaves):
            raise _classify(exc) from None
        if any(status in (401, 403) for status in denied_status):
            raise AdapterError("authentication_denied") from None
        if any(status in (400, 421) for status in denied_status):
            raise AdapterError("host_rejected") from None
        error = _classify(exc)
        if body_completed and adapter is not None and adapter._last_result is not None:
            error.guest_result = adapter._last_result
        raise error from None


@asynccontextmanager
async def select_adapter(profile: ConnectionProfile, *, expected_vm_identity: dict,
                         deadline_monotonic: float, request_timeout_seconds: float,
                         begun_channel: str | None = None):
    if begun_channel is not None:
        async with open_adapter(profile, begun_channel, deadline_monotonic=deadline_monotonic,
                                request_timeout_seconds=request_timeout_seconds) as adapter:
            await adapter.probe(expected_vm_identity)
            yield adapter
        return
    reason = None
    selected = False
    try:
        async with open_adapter(profile, "velo", deadline_monotonic=deadline_monotonic,
                                request_timeout_seconds=request_timeout_seconds) as adapter:
            await adapter.probe(expected_vm_identity)
            selected = True
            yield adapter
            return
    except AdapterError as exc:
        if selected or exc.code not in ("connection_unavailable", "tools_missing", "capabilities_disabled"):
            raise
        reason = exc.code
    async with open_adapter(profile, "windows", deadline_monotonic=deadline_monotonic,
                            request_timeout_seconds=request_timeout_seconds) as adapter:
        await adapter.probe(expected_vm_identity)
        adapter.fallback_reason = reason
        yield adapter
