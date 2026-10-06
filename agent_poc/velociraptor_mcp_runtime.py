"""
Shared MCP + model runtime used by the Velociraptor agent.
"""
import copy
import hashlib
import json
import logging
import os
import sys
from collections.abc import Collection
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import PaginatedRequestParams
from velociraptor_env import load_environment

import ollama

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

load_environment()

logger = logging.getLogger(__name__)
RUNTIME_VERBOSE = os.environ.get("VELOCIRAPTOR_AGENT_VERBOSE", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

# The stdio client can emit noisy shutdown warnings when the child process has
# already exited before process-group cleanup runs. Keep the default runtime
# quiet unless the caller explicitly enables verbose diagnostics.
logging.getLogger("mcp.client.stdio").setLevel(logging.ERROR)
logging.getLogger("mcp.os.posix.utilities").setLevel(logging.ERROR)

# Host-side transfer tools are excluded from model-facing definitions: their
# payloads are exactly what must stay out of model context, and actual
# transfers belong to the existing velo_transfer CLI.
HOST_TRANSFER_TOOLS = frozenset((
    "transfer_capabilities", "transfer_begin", "transfer_status",
    "transfer_chunk", "transfer_chunks", "transfer_finish", "transfer_abort",
))
TRANSFER_RESPONSE_SCHEMA = "velo.transfer.mcp.response.v1"
LIST_TOOLS_MAX_PAGES = 16
VIEW_SCHEMA = "velo.model.view.v1"
VIEW_SAMPLE_ROW_LIMIT = 4096
VIEW_ERROR_CODE_LIMIT = 128
PAGINATION_KEYS = ("cursor", "next_cursor", "page_size", "returned", "truncated")


def _model_provider() -> str:
    return (
        os.environ.get("VELOCIRAPTOR_MODEL_PROVIDER")
        or "ollama"
    ).strip().lower()


def _default_model(provider: str) -> str:
    if provider in {"azure", "azure_openai"}:
        return os.environ.get("AZURE_OPENAI_MODEL", "gpt-5.4-mini")
    return os.environ.get("OLLAMA_MODEL", "gemma4:e2b")


def _azure_openai_base_url() -> str:
    endpoint = (
        os.environ.get("AZURE_OPENAI_BASE_URL")
        or os.environ.get("AZURE_OPENAI_ENDPOINT")
        or os.environ.get("OPENAI_BASE_URL")
        or ""
    ).strip().rstrip("/")
    if not endpoint:
        raise RuntimeError(
            "Azure OpenAI mode requires AZURE_OPENAI_ENDPOINT or "
            "AZURE_OPENAI_BASE_URL."
        )
    if endpoint.endswith("/openai/v1"):
        return f"{endpoint}/"
    return f"{endpoint}/openai/v1/"


def _bounded_json(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False)


class VelociraptorMCPClient:
    def __init__(
        self,
        model: Optional[str] = None,
        default_allowed_tools: Optional[Collection[str]] = None,
        verbose: Optional[bool] = None,
        label: Optional[str] = None,
        model_result_max_bytes: int = 16384,
        model_result_sample_rows: int = 10,
        model_result_fields: Optional[Collection[str]] = None,
        max_tool_rounds: int = 8,
    ):
        self.model_provider = _model_provider()
        self.model = model or _default_model(self.model_provider)
        if self.model_provider not in {"ollama", "azure", "azure_openai"}:
            raise ValueError(
                "Unsupported model provider. Use VELOCIRAPTOR_MODEL_PROVIDER=ollama "
                "or VELOCIRAPTOR_MODEL_PROVIDER=azure."
            )
        self.azure_openai_client = None
        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        self.tools = []
        self.conversation_history = []
        self.verbose = RUNTIME_VERBOSE if verbose is None else verbose
        self.label = label or "MCP client"
        self.default_allowed_tools = self._validated_tool_names(
            default_allowed_tools, "default_allowed_tools")
        # Only the most recent CallToolResult is kept here, in memory; callers
        # must persist the full original themselves if they need an archive.
        self.last_tool_result: Optional[dict] = None
        if (not isinstance(model_result_max_bytes, int)
                or isinstance(model_result_max_bytes, bool)
                or not 1024 <= model_result_max_bytes <= 65536):
            raise ValueError("model_result_max_bytes must be an integer in 1024..65536")
        if (not isinstance(model_result_sample_rows, int)
                or isinstance(model_result_sample_rows, bool)
                or not 0 <= model_result_sample_rows <= 10):
            raise ValueError("model_result_sample_rows must be an integer in 0..10")
        if (not isinstance(max_tool_rounds, int) or isinstance(max_tool_rounds, bool)
                or not 1 <= max_tool_rounds <= 32):
            raise ValueError("max_tool_rounds must be an integer in 1..32")
        self.model_result_max_bytes = model_result_max_bytes
        self.model_result_sample_rows = model_result_sample_rows
        fields = model_result_fields
        if fields is not None:
            if isinstance(fields, str) or isinstance(fields, Collection) is False:
                raise ValueError("model_result_fields must be a collection of field names")
            names = list(dict.fromkeys(fields))  # order-preserving dedupe
            if (len(names) > 32 or any(
                    not isinstance(name, str) or not name or len(name) > 128
                    for name in names)):
                raise ValueError(
                    "model_result_fields allows at most 32 non-empty names of "
                    "at most 128 characters each")
            fields = tuple(names)
        self.model_result_fields = fields
        self.max_tool_rounds = max_tool_rounds

    @staticmethod
    def _validated_tool_names(source, label: str) -> Optional[frozenset]:
        """Accept None or a real collection of unique string tool names."""
        if source is None:
            return None
        if isinstance(source, str):
            raise ValueError(
                f"invalid_{label}: a bare string is not a tool-name collection")
        try:
            names = set(source)
        except TypeError:
            raise ValueError(f"invalid_{label}") from None
        for name in names:
            if not isinstance(name, str):
                raise ValueError(f"invalid_{label}: tool names must be strings")
        return frozenset(names)

    async def connect(self):
        """Connect to the MCP server bridge."""
        bridge_path = Path(__file__).resolve().parent.parent / "mcp_velociraptor_bridge.py"
        server_params = StdioServerParameters(
            command=sys.executable,
            args=[str(bridge_path)],
            env=None,
        )

        stdio_transport = await self.exit_stack.enter_async_context(
            stdio_client(server_params)
        )
        self.stdio, self.write = stdio_transport
        self.session = await self.exit_stack.enter_async_context(
            ClientSession(self.stdio, self.write)
        )

        await self.session.initialize()
        await self._load_tools()
        if self.verbose:
            print(
                f"{self.label} connected to Velociraptor MCP Bridge with {len(self.tools)} tools",
                file=sys.stderr,
            )

    async def _load_tools(self) -> None:
        """Load the full tool metadata over real SDK pagination.

        list_tools(*, params=PaginatedRequestParams) with continuation cursors
        read from ListToolsResult.next_cursor; bounded to 16 pages, rejecting
        repeated cursors and duplicate tool names.
        """
        tools: dict[str, object] = {}
        cursor = None
        seen_cursors = set()
        for _ in range(LIST_TOOLS_MAX_PAGES):
            if cursor is None:
                response = await self.session.list_tools()
            else:
                response = await self.session.list_tools(
                    params=PaginatedRequestParams(cursor=cursor))
            for tool in response.tools:
                if tool.name in tools:
                    raise RuntimeError(f"duplicate tool from server: {tool.name}")
                tools[tool.name] = tool
            cursor = response.next_cursor
            if cursor is None:
                break
            if cursor in seen_cursors:
                raise RuntimeError("duplicate list_tools cursor")
            seen_cursors.add(cursor)
        else:
            raise RuntimeError("tool listing exceeded the bounded page count")
        self.tools = list(tools.values())

    async def disconnect(self):
        """Disconnect from the MCP server."""
        await self.exit_stack.aclose()

    def reset_conversation(self):
        """Clear prior chat state so each analysis can start with fresh context."""
        self.conversation_history = []

    def _get_azure_openai_client(self):
        if OpenAI is None:
            raise RuntimeError(
                "The openai package is required when "
                "VELOCIRAPTOR_MODEL_PROVIDER=azure. Install requirements.txt."
            )
        if self.azure_openai_client is None:
            api_key = os.environ.get("AZURE_OPENAI_API_KEY", "").strip()
            if not api_key:
                raise RuntimeError(
                    "Azure OpenAI mode requires AZURE_OPENAI_API_KEY."
                )
            self.azure_openai_client = OpenAI(
                base_url=_azure_openai_base_url(),
                api_key=api_key,
            )
        return self.azure_openai_client

    def _resolve_allowed_tools(
        self,
        allowed_tools: Optional[Collection[str]] = None,
    ) -> Optional[frozenset]:
        if allowed_tools is not None:
            return self._validated_tool_names(allowed_tools, "allowed_tools")
        return self.default_allowed_tools

    def get_tool_definitions(
        self,
        allowed_tools: Optional[Collection[str]] = None,
    ) -> list[dict]:
        """Convert MCP tools to model function-calling format.

        Definitions carry the real, complete ``Tool.input_schema`` (deep-copied)
        so $defs/$ref/oneOf/additionalProperties and every constraint survive.
        An explicit name list restricts both exposure and, in chat, execution;
        with no explicit list the semantic is all available business tools with
        the seven host transfer tools excluded.
        """
        allowed = self._resolve_allowed_tools(allowed_tools)
        if allowed is not None:
            known = {tool.name for tool in self.tools}
            unknown = sorted(allowed - known)
            if unknown:
                raise ValueError(f"unknown_tool: {', '.join(unknown)}")
            host_transfer = sorted(allowed & HOST_TRANSFER_TOOLS)
            if host_transfer:
                raise ValueError(
                    "host_transfer_required: transfer tools are host-side; use "
                    f"the velo_transfer CLI instead of {', '.join(host_transfer)}")
        tool_defs = []
        for tool in self.tools:
            if allowed is not None and tool.name not in allowed:
                continue
            if allowed is None and tool.name in HOST_TRANSFER_TOOLS:
                continue
            schema = copy.deepcopy(tool.input_schema)
            if not isinstance(schema, dict):
                schema = {"type": "object", "properties": {}, "required": []}
            tool_defs.append({
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description or "",
                    "parameters": schema,
                },
            })
        return tool_defs

    def _host_payload(self, tool_name: str, result) -> dict:
        """Adapt a real CallToolResult to the host-side ok/data interface."""
        structured = result.structured_content
        if isinstance(structured, dict):
            if structured.get("schema") == TRANSFER_RESPONSE_SCHEMA:
                if structured.get("status") == "success":
                    return {"ok": True, "data": structured.get("result"),
                            "structured_content": structured}
                return {"ok": False, "error": structured.get("error"),
                        "structured_content": structured}
            if result.is_error:
                return {"ok": False, "error": structured,
                        "structured_content": structured}
            if (structured.get("status") == "success"
                    and structured.get("operation") == tool_name):
                payload = {"ok": True, "structured_content": structured}
                payload["data"] = (structured["data"] if "data" in structured
                                   else structured)
                return payload
            return {"ok": False, "error": {"code": "protocol_error"},
                    "structured_content": structured}
        if result.is_error:
            return {"ok": False, "error": {"code": "protocol_error"}}
        if not structured and result.content:
            # Legacy compatibility: only a clear old envelope (a dict with a
            # boolean ok field) is accepted from text content.
            raw_text = "\n".join(
                item.text if hasattr(item, "text") else str(item)
                for item in result.content
            )
            try:
                parsed = json.loads(raw_text)
            except (json.JSONDecodeError, ValueError):
                return {"ok": False, "error": {"code": "protocol_error"}}
            if isinstance(parsed, dict) and isinstance(parsed.get("ok"), bool):
                return parsed
            return {"ok": False, "error": {"code": "protocol_error"}}
        return {"ok": False, "error": {"code": "protocol_error"}}

    async def call_tool_payload(self, tool_name: str, arguments: dict) -> dict:
        """Execute a tool via MCP and return the structured host payload.

        The full raw CallToolResult of the most recent call is available in
        ``last_tool_result`` (in-memory only, one entry, cleared before each
        new call); persist it yourself if you need an archive.
        """
        self.last_tool_result = None
        try:
            result = await self.session.call_tool(tool_name, arguments)
        except Exception:
            return {"ok": False, "error": {"code": "call_failed"}}
        self.last_tool_result = result.model_dump(mode="json", by_alias=True)
        return self._host_payload(tool_name, result)

    def _model_view_object(self, payload: dict) -> dict:
        structured = payload.get("structured_content")
        ok = payload.get("ok") is True
        view = {"schema": VIEW_SCHEMA, "tool_ok": ok, "view_complete": True}
        if isinstance(structured, dict):
            view["operation"] = structured.get("operation")
            view["status"] = structured.get("status")
            pagination = structured.get("pagination")
            if isinstance(pagination, dict):
                view["pagination"] = {key: pagination.get(key)
                                      for key in PAGINATION_KEYS}
                view["server_truncated"] = pagination.get("truncated")
            else:
                view["pagination"] = None
                view["server_truncated"] = None
            warnings = structured.get("warnings")
            if isinstance(warnings, list):
                view["warnings_count"] = len(warnings)
            if not ok:
                error_value = payload.get("error")
                if isinstance(error_value, dict):
                    view["error"] = error_value
            canonical = json.dumps(structured, ensure_ascii=False, sort_keys=True,
                                   separators=(",", ":"), allow_nan=False)
            encoded = canonical.encode("utf-8")
            view["raw_bytes"] = len(encoded)
            view["raw_sha256"] = hashlib.sha256(encoded).hexdigest()
            data = payload.get("data")
            if isinstance(data, list):
                view["rows_received"] = len(data)
                samples = []
                for row in data:
                    if len(samples) >= self.model_result_sample_rows:
                        break
                    if not isinstance(row, dict):
                        continue
                    projected = (
                        {name: row[name] for name in self.model_result_fields
                         if name in row}
                        if self.model_result_fields is not None else row)
                    try:
                        line = _bounded_json(projected)
                    except (TypeError, ValueError):
                        continue
                    if len(line.encode("utf-8")) > VIEW_SAMPLE_ROW_LIMIT:
                        continue
                    samples.append(projected)
                view["sample_rows"] = samples
                view["sample_omitted_count"] = len(data) - len(samples)
                if (self.model_result_fields is not None
                        or len(samples) < len(data)):
                    view["view_complete"] = False
            view["payload"] = structured
        return view

    def _model_view(self, payload: dict) -> str:
        """Render the bounded velo.model.view.v1 message for the model."""
        view = self._model_view_object(payload)

        def encoded(value) -> bytes:
            return _bounded_json(value).encode("utf-8")

        limit = self.model_result_max_bytes
        if len(encoded(view)) > limit:
            view.pop("payload", None)
            view["payload_omitted"] = True
            view["view_complete"] = False
        while len(encoded(view)) > limit:
            if not view.get("sample_rows"):
                break
            view["sample_rows"].pop()
            view["sample_omitted_count"] = (view.get("rows_received", 0)
                                            - len(view["sample_rows"]))
        if len(encoded(view)) <= limit:
            return _bounded_json(view)
        fallback = {
            "schema": VIEW_SCHEMA,
            "tool_ok": view.get("tool_ok") is True,
            "view_error": "model_view_overflow",
            "view_complete": False,
            "fields_omitted": True,
            "rows_received": view.get("rows_received"),
            "sample_rows": [],
            "sample_omitted_count": view.get("rows_received", 0),
        }
        error = view.get("error")
        if isinstance(error, dict):
            code = error.get("code")
            if (isinstance(code, str) and code
                    and len(code.encode("utf-8")) <= VIEW_ERROR_CODE_LIMIT):
                fallback["error"] = {"code": code}
            else:
                fallback["error"] = {"code": "tool_error"}
                fallback["error_code_omitted"] = True
        if len(encoded(fallback)) <= limit:
            return _bounded_json(fallback)
        return _bounded_json({
            "schema": VIEW_SCHEMA, "tool_ok": fallback["tool_ok"],
            "view_error": "model_view_overflow", "view_complete": False,
            "fields_omitted": True,
        })

    async def call_tool(self, tool_name: str, arguments: dict) -> str:
        """Execute a tool and return the bounded model view as JSON text."""
        payload = await self.call_tool_payload(tool_name, arguments)
        return self._model_view(payload)

    def _denied_tool_view(self, code: str) -> str:
        return _bounded_json({
            "schema": VIEW_SCHEMA, "tool_ok": False, "view_error": code,
            "view_complete": False, "error": {"code": code},
            "error_complete": True, "rows_received": 0, "sample_rows": [],
            "sample_omitted_count": 0,
        })

    async def _chat_ollama(
        self,
        tools: list[dict],
        exposed_names: frozenset,
    ) -> str:
        rounds_executed = 0
        response = ollama.chat(
            model=self.model,
            messages=self.conversation_history,
            tools=tools,
        )

        while response.get("message", {}).get("tool_calls"):
            if rounds_executed >= self.max_tool_rounds:
                stop = "model_tool_round_budget"
                self.conversation_history.append({
                    "role": "assistant", "content": stop,
                })
                return stop
            self.conversation_history.append(response["message"])

            for tool_call in response["message"]["tool_calls"]:
                tool_name = tool_call["function"]["name"]
                tool_args = tool_call["function"]["arguments"]

                if self.verbose:
                    print(f"{self.label} tool: {tool_name}", file=sys.stderr)
                    if tool_args:
                        print(json.dumps(tool_args, indent=2), file=sys.stderr)

                if tool_name not in exposed_names:
                    self.conversation_history.append({
                        "role": "tool",
                        "content": self._denied_tool_view("tool_not_allowed"),
                    })
                    continue
                tool_result = await self.call_tool(tool_name, tool_args)
                self.conversation_history.append({
                    "role": "tool",
                    "content": tool_result,
                })
            rounds_executed += 1

            response = ollama.chat(
                model=self.model,
                messages=self.conversation_history,
                tools=tools,
            )

        assistant_message = response["message"]["content"]
        self.conversation_history.append({
            "role": "assistant",
            "content": assistant_message,
        })
        return assistant_message

    async def _chat_azure_openai(
        self,
        tools: list[dict],
        exposed_names: frozenset,
    ) -> str:
        client = self._get_azure_openai_client()
        response = client.chat.completions.create(
            model=self.model,
            messages=self.conversation_history,
            tools=tools or None,
        )
        message = response.choices[0].message
        rounds_executed = 0

        while message.tool_calls:
            if rounds_executed >= self.max_tool_rounds:
                stop = "model_tool_round_budget"
                self.conversation_history.append({
                    "role": "assistant", "content": stop,
                })
                return stop
            self.conversation_history.append(message.model_dump(exclude_none=True))

            for tool_call in message.tool_calls:
                tool_name = tool_call.function.name
                raw_args = tool_call.function.arguments or "{}"
                try:
                    tool_args = json.loads(raw_args)
                except json.JSONDecodeError:
                    tool_args = {}

                if self.verbose:
                    print(f"{self.label} tool: {tool_name}", file=sys.stderr)
                    if tool_args:
                        print(json.dumps(tool_args, indent=2), file=sys.stderr)

                if tool_name not in exposed_names:
                    self.conversation_history.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": self._denied_tool_view("tool_not_allowed"),
                    })
                    continue
                tool_result = await self.call_tool(tool_name, tool_args)
                self.conversation_history.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": tool_result,
                })
            rounds_executed += 1

            response = client.chat.completions.create(
                model=self.model,
                messages=self.conversation_history,
                tools=tools or None,
            )
            message = response.choices[0].message

        assistant_message = message.content or ""
        self.conversation_history.append({
            "role": "assistant",
            "content": assistant_message,
        })
        return assistant_message

    async def chat(
        self,
        user_message: str,
        allowed_tools: Optional[Collection[str]] = None,
        system_prompt: Optional[str] = None,
    ) -> str:
        """Send a message and get a response with tool calling.

        The tool definitions generated for this call also fix the set of names
        the model may actually execute: anything else is answered with a
        bounded tool_not_allowed view instead of an MCP call.
        """
        if system_prompt and (
            not self.conversation_history
            or self.conversation_history[0].get("role") != "system"
        ):
            self.conversation_history.append({
                "role": "system",
                "content": system_prompt,
            })

        self.conversation_history.append({
            "role": "user",
            "content": user_message,
        })

        tools = self.get_tool_definitions(allowed_tools)
        exposed_names = frozenset(
            definition["function"]["name"] for definition in tools)
        if self.model_provider in {"azure", "azure_openai"}:
            return await self._chat_azure_openai(tools, exposed_names)
        return await self._chat_ollama(tools, exposed_names)
