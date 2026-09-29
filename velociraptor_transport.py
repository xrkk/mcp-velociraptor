"""Fail-closed transport seam and formal HTTP entry gate for the MCP bridge.

Internal testing keeps the stdio transport.  The formal deployment runs one
stateful Streamable HTTP server on the exact guest host-only address.  This
module only validates configuration and guards the HTTP entry; it never
touches tool business logic, and the bearer token value never reaches logs,
errors, or exception text.
"""

from __future__ import annotations

import hmac
import os
import secrets
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping

TEST_TRANSPORT = "stdio"
FORMAL_TRANSPORT = "http"
FORMAL_PORT = 28790
FORMAL_PATH = "/mcp"
WILDCARD_BIND_ADDRESSES = frozenset({"0.0.0.0", "::"})

TRANSPORT_ENV = "VELOCIRAPTOR_MCP_TRANSPORT"
HOST_ENV = "VELOCIRAPTOR_MCP_HOST"
PORT_ENV = "VELOCIRAPTOR_MCP_PORT"
PATH_ENV = "VELOCIRAPTOR_MCP_PATH"
TOKEN_ENV = "VELOCIRAPTOR_MCP_BEARER_TOKEN"
ALLOWED_ORIGINS_ENV = "VELOCIRAPTOR_MCP_ALLOWED_ORIGINS"

INSTANCE_HEADER = b"x-mcp-server-instance"


class TransportConfigError(Exception):
    """Configuration rejected before any socket is opened."""


@dataclass(frozen=True)
class TransportConfig:
    mode: str
    host: str | None = None
    port: int = FORMAL_PORT
    path: str = FORMAL_PATH
    bearer_token: str | None = None
    allowed_origins: tuple[str, ...] = ()


def resolve_transport_config(
    env: Mapping[str, str] | None = None,
    *,
    bind_address_validator: Callable[[str], None] | None = None,
) -> TransportConfig:
    """Resolve the transport seam from the environment, fail-closed.

    ``bind_address_validator`` is the injectable hook the P05 installer uses
    to prove the configured host really belongs to the target host-only NIC;
    it is not a runtime concern of this process.
    """
    source = os.environ if env is None else env
    mode = source.get(TRANSPORT_ENV, TEST_TRANSPORT).strip().lower() or TEST_TRANSPORT
    if mode == TEST_TRANSPORT:
        return TransportConfig(mode=TEST_TRANSPORT)
    if mode != FORMAL_TRANSPORT:
        raise TransportConfigError(
            f"{TRANSPORT_ENV} must be '{TEST_TRANSPORT}' or '{FORMAL_TRANSPORT}'"
        )

    host = source.get(HOST_ENV, "").strip()
    if not host:
        raise TransportConfigError(f"{HOST_ENV} is required for the formal entry")
    if host.lower() in WILDCARD_BIND_ADDRESSES:
        raise TransportConfigError(
            f"{HOST_ENV} must be an exact host address, not a wildcard bind"
        )
    if bind_address_validator is not None:
        try:
            bind_address_validator(host)
        except TransportConfigError:
            raise
        except Exception as exc:
            raise TransportConfigError(
                f"{HOST_ENV} failed the deployment bind-address check"
            ) from exc

    port_text = source.get(PORT_ENV, str(FORMAL_PORT)).strip()
    try:
        port = int(port_text, 10)
    except ValueError:
        raise TransportConfigError(f"{PORT_ENV} must be an integer") from None
    if port != FORMAL_PORT:
        raise TransportConfigError(f"{PORT_ENV} must be exactly {FORMAL_PORT}")

    path = source.get(PATH_ENV, FORMAL_PATH).strip()
    if path != FORMAL_PATH:
        raise TransportConfigError(f"{PATH_ENV} must be exactly {FORMAL_PATH}")

    token = source.get(TOKEN_ENV, "").strip()
    if not token:
        raise TransportConfigError(f"{TOKEN_ENV} is required and must not be empty")

    origins = tuple(
        value.strip()
        for value in source.get(ALLOWED_ORIGINS_ENV, "").split(";")
        if value.strip()
    )
    return TransportConfig(
        mode=FORMAL_TRANSPORT,
        host=host,
        port=port,
        path=path,
        bearer_token=token,
        allowed_origins=origins,
    )


def new_server_instance_id() -> str:
    """Unpredictable, non-secret identity for evidence correlation only.

    The value is scoped to this process lifetime, carries no hostname, path,
    or secret material, and never replaces bearer authentication.
    """
    return secrets.token_hex(16)


async def _send_plain_response(
    send: Callable[[dict[str, Any]], Awaitable[None]],
    status: int,
    body: bytes,
) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class BearerAuthGate:
    """Constant-time bearer check that runs before the MCP handler."""

    def __init__(self, app: Any, token: str) -> None:
        self.app = app
        self._expected = token.encode("utf-8")

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        header = b""
        for name, value in scope.get("headers", []):
            if name == b"authorization":
                header = value
                break
        scheme, _, provided = header.partition(b" ")
        provided = provided.strip()
        if scheme.lower() != b"bearer" or not provided:
            await _send_plain_response(send, 401, b"Unauthorized")
            return
        if not hmac.compare_digest(provided, self._expected):
            await _send_plain_response(send, 401, b"Unauthorized")
            return
        await self.app(scope, receive, send)


class ServerInstanceHeader:
    """Stamp the process-scoped instance header on every proxied response."""

    def __init__(self, app: Any, instance_id: str) -> None:
        self.app = app
        self._value = instance_id.encode("ascii")

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower() != INSTANCE_HEADER
                ]
                headers.append((INSTANCE_HEADER, self._value))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)


def build_formal_http_app(server: Any, config: TransportConfig) -> Any:
    """Wrap the single registered MCPServer instance for the formal entry.

    The SDK app keeps stateful sessions (``stateless_http=False``) and DNS
    rebinding protection enabled with the exact allowed Host generated from
    the validated configuration.  The outermost middleware authenticates,
    the inner one stamps the instance header; both run before any MCP
    handler sees the request.
    """
    from mcp.server.transport_security import TransportSecuritySettings

    app = server.streamable_http_app(
        streamable_http_path=config.path,
        stateless_http=False,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[f"{config.host}:{config.port}"],
            allowed_origins=list(config.allowed_origins),
        ),
        host=config.host,
    )
    service = getattr(server, "_guest_transfer_tools", None)
    if service is not None:
        from starlette.routing import Route
        app.router.routes.append(Route("/chunkbin", _chunkbin_endpoint(service), methods=["POST"]))
    app.add_middleware(ServerInstanceHeader, instance_id=new_server_instance_id())
    app.add_middleware(BearerAuthGate, token=config.bearer_token or "")
    return app


_VBT_MAGIC = b"VBT1"


def _vbt_frame(header: dict, payload: bytes) -> bytes:
    import json as _json
    raw = _json.dumps(header, separators=(",", ":")).encode("utf-8")
    return _VBT_MAGIC + len(raw).to_bytes(4, "little") + raw + payload


def _vbt_parse(body: bytes) -> tuple[dict, bytes]:
    if len(body) < 8 or body[:4] != _VBT_MAGIC:
        raise ValueError("bad_magic")
    header_len = int.from_bytes(body[4:8], "little")
    if header_len > 1 << 20 or 8 + header_len > len(body):
        raise ValueError("bad_header")
    import json as _json
    header = _json.loads(body[8:8 + header_len])
    if not isinstance(header, dict):
        raise ValueError("bad_header")
    return header, body[8 + header_len:]


def _chunkbin_endpoint(service):
    """Binary chunk batches over the authenticated formal app.

    Envelope rules, budgets, hashes and ledger writes are exactly the
    transfer_chunks tool's; only the wire form differs: a small JSON header
    plus raw payload bytes, so multi-hundred-MiB batches stop paying
    base64+JSON text encoding twice.
    """
    import asyncio
    import base64

    async def endpoint(request):
        from starlette.responses import Response

        tid = request.headers.get("x-velo-transfer-id", "")
        digest = request.headers.get("x-velo-request-digest", "")
        offset = request.headers.get("x-velo-offset", "")
        if not tid or not digest or not offset.isdigit():
            return Response(_vbt_frame({"status": "error", "error": {"code": "invalid_arguments"}}, b""),
                            media_type="application/octet-stream", status_code=200)
        try:
            body = await request.body()
        except Exception:
            return Response(_vbt_frame({"status": "error", "error": {"code": "connection_failed"}}, b""),
                            media_type="application/octet-stream")
        push_header = None
        arguments = None
        direction = request.headers.get("x-velo-direction", "pull")
        try:
            if direction == "push":
                header, payload = _vbt_parse(body)
                push_header = header
                items_meta = header.get("chunks")
                if not isinstance(items_meta, list) or not items_meta:
                    raise ValueError("chunks")
                chunks = []
                cursor = 0
                for item in items_meta:
                    count = item["count"]
                    if not isinstance(count, int) or count <= 0 or cursor + count > len(payload):
                        raise ValueError("count")
                    chunks.append({"count": count,
                                   "data_base64": base64.b64encode(payload[cursor:cursor + count]).decode("ascii"),
                                   "chunk_sha256": item["chunk_sha256"]})
                    cursor += count
                if cursor != len(payload):
                    raise ValueError("length")
                arguments = {"transfer_id": tid, "request_digest": digest, "offset": int(offset),
                             "chunks": chunks}
            else:
                per = request.headers.get("x-velo-count-per-chunk", "")
                total = request.headers.get("x-velo-chunk-count", "")
                if not per.isdigit() or not total.isdigit():
                    raise ValueError("range")
                arguments = {"transfer_id": tid, "request_digest": digest, "offset": int(offset),
                             "count_per_chunk": int(per), "chunk_count": int(total)}
        except (ValueError, KeyError, TypeError) as exc:
            return Response(_vbt_frame({"status": "error", "error": {
                "code": "invalid_arguments", "detail": f"{type(exc).__name__}: {exc}"[:160]}}, b""),
                            media_type="application/octet-stream")
        try:
            envelope = await asyncio.to_thread(service.invoke, "transfer_chunks", **arguments)
        except Exception:
            envelope = service._failure("internal_error")
        result = envelope.result if envelope.status == "success" else None
        if result is None:
            return Response(_vbt_frame({"status": "error", "error": {"code": envelope.error["code"]}}, b""),
                            media_type="application/octet-stream")
        if direction == "push":
            return Response(_vbt_frame({"status": "success",
                                        "result": {"verified_offset": result["verified_offset"],
                                                   "accepted": result.get("accepted", 0)}}, b""),
                            media_type="application/octet-stream")
        items = result.get("chunks", [])
        meta = [{"offset": c["offset"], "count": c["count"], "chunk_sha256": c["chunk_sha256"]} for c in items]
        payload = b"".join(base64.b64decode(c["data_base64"]) for c in items)
        return Response(_vbt_frame({"status": "success",
                                    "result": {"verified_offset": result["verified_offset"], "chunks": meta}},
                                   payload),
                        media_type="application/octet-stream")

    return endpoint


def run_formal_http(
    server: Any,
    config: TransportConfig,
    *,
    on_ready: Callable[[], None] | None = None,
    stop_requested: Callable[[], bool] | None = None,
) -> None:
    """Serve the formal entry with one process and one worker."""
    import uvicorn

    class LifecycleServer(uvicorn.Server):
        async def startup(self, sockets=None):
            await super().startup(sockets=sockets)
            if self.started and on_ready is not None:
                on_ready()

        async def on_tick(self, counter):
            if stop_requested is not None and stop_requested():
                self.should_exit = True
            return await super().on_tick(counter)

    app = build_formal_http_app(server, config)
    http_server = LifecycleServer(
        uvicorn.Config(
            app,
            host=config.host,
            port=config.port,
            log_level="warning",
        )
    )
    http_server.run()
    if not http_server.started:
        raise RuntimeError('Formal HTTP startup did not reach readiness')
