"""Bounded host transport adapters; global transfer state belongs to the caller."""

from __future__ import annotations

import asyncio
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

NAMES = ("transfer_capabilities", "transfer_begin", "transfer_status", "transfer_chunk",
         "transfer_finish", "transfer_abort")
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


class TransportAdapter:
    def __init__(self, session: ClientSession, channel: str, endpoint: str, deadline: float,
                 request_timeout: float, instances: list[str]):
        self._session = session
        self.channel = channel
        self.endpoint = endpoint
        self.deadline_monotonic = deadline
        self.request_timeout_seconds = request_timeout
        self.raw_chunk_bytes = 1 << 20
        self._instances = instances
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
            error = _classify(exc, name)
            if attempted and name not in READ_ONLY:
                error.may_have_committed = True
                error.retryable = False
            raise error from None

    async def call(self, operation: str, arguments: dict) -> dict:
        if operation not in NAMES or not isinstance(arguments, dict):
            raise AdapterError("invalid_operation")
        if not Draft202012Validator(SCHEMAS[operation]["inputSchema"]).is_valid(arguments):
            raise AdapterError("invalid_arguments")
        if operation == "transfer_chunk" and arguments["count"] > self.raw_chunk_bytes:
            raise AdapterError("chunk_too_large")
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
            raise AdapterError("tools_missing")
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
        if not Draft202012Validator(SCHEMAS[operation]["inputSchema"]).is_valid(arguments):
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
                                                                self._deployment.policy_path, owner_identity),
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

    async def response_hook(response):
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
        async with httpx2.AsyncClient(headers=headers,
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
                        opened = True
                        yield adapter
                    body_completed = True
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        if opened and not isinstance(exc, (AdapterError, BaseExceptionGroup)):
            raise
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
