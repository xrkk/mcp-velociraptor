"""Opt-in in-memory tools/call observation for the default MCP HTTP SDK chain.

Not installed by the bridge. No business hooks, persistence or authentication.
Middleware completion is a worker-exit boundary only for the normal awaited SDK
sync dispatch (AnyIO's default non-abandoning worker); detached/custom workers
are unsupported. Request snapshots are diagnostic until sealed.
"""
from __future__ import annotations

import contextvars
import hashlib
import json
import math
import re
import threading
from typing import Any

import anyio


class ObservationError(ValueError):
    """Observation admission, validation, capacity or lifecycle refusal."""


_current: contextvars.ContextVar[ObservationScope | None] = contextvars.ContextVar(
    "velociraptor_observation_scope", default=None
)
_KIND = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")


def _json_copy(value: Any, active: set[int] | None = None) -> Any:
    """Copy strict JSON values without custom conversion or shared containers."""
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ObservationError("non-finite JSON number")
        return value
    if type(value) not in (dict, list):
        raise ObservationError("non-JSON value")
    active = set() if active is None else active
    identity = id(value)
    if identity in active:
        raise ObservationError("cyclic JSON value")
    active.add(identity)
    try:
        if type(value) is dict:
            if any(type(k) is not str for k in value):
                raise ObservationError("JSON object keys must be strings")
            return {k: _json_copy(v, active) for k, v in value.items()}
        return [_json_copy(v, active) for v in value]
    finally:
        active.remove(identity)


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise ObservationError("invalid canonical JSON") from exc


def current_scope() -> ObservationScope:
    scope = _current.get()
    if scope is None:
        raise ObservationError("missing observation parent")
    return scope


def emit(kind: str, facts: dict[str, Any]) -> None:
    """Append an explicitly supplied fact to the current request, or refuse."""
    current_scope().emit(kind, facts)


class ObservationScope:
    """Shared request object; all mutation and reads serialize on one lock."""

    def __init__(self, key: dict[str, Any], tool: str, arguments_sha256: str,
                 max_events: int, max_bytes: int) -> None:
        self._lock = threading.Lock()
        self._key = _json_copy(key)
        self._tool = tool
        self._arguments_sha256 = arguments_sha256
        self._events: list[dict[str, Any]] = []
        self._outcome: str | None = None
        self._sealed = False
        self._failed = False
        self._max_events = max_events
        self._max_bytes = max_bytes

    def emit(self, kind: str, facts: dict[str, Any]) -> None:
        with self._lock:
            if self._sealed:
                raise ObservationError("observation is sealed")
            try:
                if type(kind) is not str or not _KIND.fullmatch(kind):
                    raise ObservationError("invalid event kind")
                if type(facts) is not dict:
                    raise ObservationError("facts must be a JSON object")
                event = {"sequence": len(self._events) + 1, "kind": kind,
                         "facts": _json_copy(facts)}
                if len(self._events) >= self._max_events:
                    raise ObservationError("event count budget exceeded")
                if len(_canonical(event)) > self._max_bytes:
                    raise ObservationError("event byte budget exceeded")
                if self._failed:
                    raise ObservationError("observation already failed")
                self._events.append(event)
            except (ObservationError, RecursionError):
                self._failed = True
                raise

    def snapshot(self, *, allow_unsealed: bool = False) -> dict[str, Any]:
        with self._lock:
            if not self._sealed and not allow_unsealed:
                raise ObservationError("observation is not sealed")
            return _json_copy({"key": self._key, "tool": self._tool,
                               "arguments_sha256": self._arguments_sha256,
                               "events": self._events, "outcome": self._outcome,
                               "sealed": self._sealed})

    def _finish(self, outcome: str) -> bool:
        with self._lock:
            self._outcome = "raised" if outcome == "returned" and self._failed else outcome
            self._sealed = True
            return self._failed


class RequestObserver:
    """Explicit bounded observer, installed only by an opting-in SDK caller.

    Use ``server.middleware.append(observer.middleware)`` in controlled tests.
    Only the default awaited SDK worker chain is supported, never detached work.
    The instance must be the caller-owned service instance used for that server.
    """

    def __init__(self, instance_id: str, *, max_requests: int,
                 max_events_per_request: int, max_event_bytes: int) -> None:
        if type(instance_id) is not str or not instance_id:
            raise ObservationError("missing instance identity")
        for limit in (max_requests, max_events_per_request, max_event_bytes):
            if type(limit) is not int or limit <= 0:
                raise ObservationError("budgets must be positive integers")
        self._instance_id = instance_id
        self._max_requests = max_requests
        self._max_events = max_events_per_request
        self._max_bytes = max_event_bytes
        self._lock = threading.Lock()
        self._scopes: dict[tuple[Any, ...], ObservationScope] = {}

    async def middleware(self, ctx: Any, call_next: Any) -> Any:
        if ctx.method != "tools/call":
            return await call_next(ctx)
        request = ctx.request
        session_id = None if request is None else request.headers.get("mcp-session-id")
        request_id = ctx.request_id
        if type(session_id) is not str or not session_id:
            raise ObservationError("missing HTTP session identity")
        if type(request_id) is int:
            request_id_type = "integer"
        elif type(request_id) is str:
            request_id_type = "string"
        else:
            raise ObservationError("invalid typed request identity")
        params = ctx.params
        if params is None:
            raise ObservationError("missing tool parameters")
        tool = params.get("name")
        if type(tool) is not str or not tool:
            raise ObservationError("missing tool name")
        arguments = params.get("arguments", {})
        if type(arguments) is not dict:
            raise ObservationError("arguments must be a JSON object")
        arguments_sha256 = hashlib.sha256(_canonical(_json_copy(arguments))).hexdigest()
        key = dict(instance_id=self._instance_id, session_id=session_id,
                   request_id_type=request_id_type, request_id=request_id)
        index = (self._instance_id, session_id, request_id_type, request_id)
        # Canonical validation also refuses invalid Unicode before reserving a key.
        _canonical(key); _canonical(tool)
        with self._lock:
            if index in self._scopes:
                raise ObservationError("duplicate observation parent")
            if len(self._scopes) >= self._max_requests:
                raise ObservationError("request count budget exceeded")
            scope = ObservationScope(key, tool, arguments_sha256,
                                     self._max_events, self._max_bytes)
            self._scopes[index] = scope
        token = _current.set(scope)
        outcome = "returned"
        primary: BaseException | None = None
        failed = False
        try:
            result = await call_next(ctx)
        except BaseException as exc:
            primary = exc
            outcome = "cancelled" if isinstance(exc, anyio.get_cancelled_exc_class()) else "raised"
            raise
        finally:
            try:
                failed = scope._finish(outcome)
            except BaseException:
                if primary is None:
                    raise
                primary.add_note("Observation finalization failed; scope remains diagnostic.")
            finally:
                _current.reset(token)
        if failed:
            raise ObservationError("request observation failed")
        return result

    def snapshots(self, *, allow_unsealed: bool = False) -> list[dict[str, Any]]:
        with self._lock:
            scopes = list(self._scopes.values())
        return [scope.snapshot(allow_unsealed=allow_unsealed) for scope in scopes]
