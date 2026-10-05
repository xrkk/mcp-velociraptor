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


async def _send_security_response(scope, receive, send, status, code):
    from velo_transfer.http_wire import security_error
    await security_error(status, code)(scope, receive, send)


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
        credentials = [value for name, value in scope.get("headers", []) if name.lower() == b"authorization"]
        header = credentials[0] if len(credentials) == 1 else b""
        scheme, _, provided = header.partition(b" ")
        provided = provided.strip()
        if scheme.lower() != b"bearer" or not provided:
            await _send_security_response(scope, receive, send, 401, "unauthorized")
            return
        if not hmac.compare_digest(provided, self._expected):
            await _send_security_response(scope, receive, send, 401, "unauthorized")
            return
        scope = {**scope, "velo.bearer_owner": __import__("hashlib").sha256(provided).digest()}
        await self.app(scope, receive, send)


class HostOriginGate:
    """DNS-rebinding gate that covers every formal path, not only the SDK's.

    The SDK enforces ``TransportSecuritySettings`` inside its streamable-HTTP
    route handler; any route appended to the same router (the binary chunk
    channel) would otherwise skip Host/Origin validation entirely. This
    middleware applies the SDK's own rules - same status codes, same wildcard
    handling, absent Origin still allowed - to every HTTP request before any
    handler runs or any body is read.
    """

    def __init__(
        self,
        app: Any,
        allowed_hosts: tuple[str, ...],
        allowed_origins: tuple[str, ...],
    ) -> None:
        self.app = app
        self._hosts = allowed_hosts
        self._origins = allowed_origins

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        host = b""
        origin = b""
        for name, value in scope.get("headers", []):
            if name.lower() == b"host" and not host:
                host = value
            elif name.lower() == b"origin" and not origin:
                origin = value
        hosts = [v for k,v in scope.get("headers", []) if k.lower() == b"host"]
        origins = [v for k,v in scope.get("headers", []) if k.lower() == b"origin"]
        if len(hosts) != 1 or not self._match(host.decode("latin-1"), self._hosts):
            await _send_security_response(scope, receive, send, 421, "bad_host")
            return
        if len(origins) > 1 or (origins and not self._match(origin.decode("latin-1"), self._origins)):
            await _send_security_response(scope, receive, send, 403, "origin_denied")
            return
        await self.app(scope, receive, send)

    @staticmethod
    def _match(value: str, allowed: tuple[str, ...]) -> bool:
        if value in allowed:
            return True
        for pattern in allowed:
            if pattern.endswith(":*") and value.startswith(pattern[:-2] + ":"):
                return True
        return False


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
    """One approved ledger/controller and actual pinned SDK manager."""
    from contextlib import asynccontextmanager
    import anyio
    from mcp.server.transport_security import TransportSecuritySettings
    from starlette.applications import Starlette
    from starlette.routing import Route
    from velociraptor_observation_controller import SessionController, _HTTPIngress, _BinaryIngress, _approved_controller
    from velociraptor_observation_sdk_adapter import _TrackedManager
    from velo_transfer.http_wire import SDKSessionBindings
    controller=getattr(server,'_observation_controller',None)
    if not _approved_controller(controller):
        controller=SessionController.open_approved(new_server_instance_id())
    try:
        manager=_TrackedManager(server._lowlevel_server, security_settings=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,allowed_hosts=[f'{config.host}:{config.port}'],
            allowed_origins=list(config.allowed_origins)))
        controller._attach_manager(manager)
        bindings=SDKSessionBindings(manager,controller._ledger._instance)
        controller._bindings=bindings
        @asynccontextmanager
        async def lifespan(app):
            async with manager.run():
                try:yield
                finally:
                    with anyio.CancelScope(shield=True):await controller._drain()
        routes=[Route(config.path,_HTTPIngress(controller),methods=['GET','POST','DELETE'])]
        service=getattr(server,'_guest_transfer_tools',None)
        if service is not None:routes.append(Route('/chunkbin',_BinaryIngress(controller,service),methods=['POST']))
        app=Starlette(routes=routes,lifespan=lifespan)
        app.state.transfer_bindings=bindings
        app.state.observation_controller=controller
        app.add_middleware(HostOriginGate,allowed_hosts=(f'{config.host}:{config.port}',),allowed_origins=tuple(config.allowed_origins))
        app.add_middleware(ServerInstanceHeader,instance_id=controller._ledger._instance)
        app.add_middleware(BearerAuthGate,token=config.bearer_token or '')
        return app
    except BaseException as primary:
        controller._abort_startup(primary)
        raise


def _build_protocol_http_app(server: Any, config: TransportConfig) -> Any:
    """Internal protocol-test composition; grants no formal archive authority.

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
        max_request_body_size=100 << 20,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[f"{config.host}:{config.port}"],
            allowed_origins=list(config.allowed_origins),
        ),
        host=config.host,
    )
    from velo_transfer.http_wire import SDKSessionBindings, TransferHTTPGate
    instance = new_server_instance_id()
    bindings = SDKSessionBindings(getattr(server, "session_manager", None), instance)
    app.state.transfer_bindings = bindings
    service = getattr(server, "_guest_transfer_tools", None)
    if service is not None:
        from starlette.routing import Route
        app.router.routes.append(Route("/chunkbin", _chunkbin_endpoint(service), methods=["POST"]))
    app.add_middleware(TransferHTTPGate, bindings=bindings, mcp_path=config.path)
    # Registered first so it wraps closest to the router: the bearer gate stays
    # the outermost rejection point on /mcp, while every appended route (the
    # binary chunk channel) passes the same Host/Origin rules as the SDK's own
    # route before its handler runs.
    app.add_middleware(
        HostOriginGate,
        allowed_hosts=(f"{config.host}:{config.port}",),
        allowed_origins=tuple(config.allowed_origins),
    )
    app.add_middleware(ServerInstanceHeader, instance_id=instance)
    app.add_middleware(BearerAuthGate, token=config.bearer_token or "")
    return app


# Compatibility names for Python tests; production uses context-selected codec.
from velo_transfer.wire import MAGIC as _VBT_MAGIC, parse as _vbt_parse
from velo_transfer.http_wire import chunk_endpoint as _chunkbin_endpoint


def _vbt_frame(header: dict, payload: bytes) -> bytes:
    import json
    raw = json.dumps(header, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return _VBT_MAGIC + len(raw).to_bytes(4, "little") + raw + payload


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
