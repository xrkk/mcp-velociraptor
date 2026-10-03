"""Opt-in in-memory tools/call observation for the default MCP HTTP SDK chain.

Not installed by the bridge. Target facts are opt-in; no persistence or authentication.
Middleware completion is a worker-exit boundary only for the normal awaited SDK
sync dispatch (AnyIO's default non-abandoning worker); detached/custom workers
are unsupported. Request snapshots are diagnostic until sealed.
"""
from __future__ import annotations

import contextvars
from contextlib import contextmanager
import uuid
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


def observation_active() -> bool:
    """Internal business activation check, without treating failures as absent."""
    return _current.get() is not None


def observation_failed() -> bool:
    scope = _current.get()
    if scope is None:
        return False
    with scope._lock:
        return scope._failed


_TARGET_FIELDS = {
    "target.resolve": {"operation_id", "mode", "client_id"},
    "target.operation.begin": {"operation_id", "attempt", "client_id"},
    "target.operation.end": {"operation_id", "attempt", "client_id", "outcome"},
    "target.exists": {"operation_id", "attempt", "client_id", "exists"},
    "target.clear": {"operation_id", "previous_client_id"},
}


def emit_target_fact(kind: str, facts: dict[str, Any]) -> None:
    """Internal exact target whitelist; absent scope is the only no-op case."""
    scope = _current.get()
    if scope is None:
        return
    try:
        if type(facts) is not dict or kind not in _TARGET_FIELDS or set(facts) != _TARGET_FIELDS[kind]:
            raise ObservationError("invalid target fact fields")
        operation_id = facts["operation_id"]
        if operation_id is not None:
            import uuid
            if type(operation_id) is not str or str(uuid.UUID(operation_id)) != operation_id:
                raise ObservationError("invalid operation identity")
        if kind in ("target.operation.begin", "target.operation.end", "target.exists"):
            if operation_id is None or type(facts["attempt"]) is not int or facts["attempt"] not in (1, 2):
                raise ObservationError("invalid operation attempt")
        field = "previous_client_id" if kind == "target.clear" else "client_id"
        client = facts[field]
        if not (kind == "target.clear" and client is None) and (type(client) is not str or not client):
            raise ObservationError("invalid target client identity")
        if kind == "target.resolve" and facts["mode"] not in ("selected", "cache_hit"):
            raise ObservationError("invalid resolution mode")
        if kind == "target.operation.end" and facts["outcome"] not in ("returned", "raised", "cancelled"):
            raise ObservationError("invalid operation outcome")
        if kind == "target.exists" and type(facts["exists"]) is not bool:
            raise ObservationError("invalid existence fact")
        scope.emit(kind, facts)
    except BaseException:
        # Keep failures sticky even if an injected emitter fails before append.
        with scope._lock:
            if not scope._sealed:
                scope._failed = True
        raise


# Internal call-local associations. Neither is an API parameter or a last-flow cache.
_operation_current = contextvars.ContextVar("velociraptor_operation", default=None)
_creation_current = contextvars.ContextVar("velociraptor_creation", default=None)
_FLOW_FIELDS = {
    "flow.create.begin": {"operation_id", "attempt", "creation_id", "client_id",
                          "artifact", "parameters_sha256", "timeout", "max_bytes", "org_id", "root_org"},
    "flow.create.return": {"operation_id", "attempt", "creation_id", "client_id", "rows"},
    "flow.metadata.return": {"operation_id", "attempt", "creation_id", "client_id", "flow_id", "state"},
}


def _fail(scope):
    with scope._lock:
        if not scope._sealed:
            scope._failed = True


@contextmanager
def operation_context(facts):
    """Only TargetContext's actual operation interval establishes association."""
    scope = _current.get()
    token = _operation_current.set((scope, dict(facts)) if scope is not None else None)
    try:
        yield
    finally:
        _operation_current.reset(token)


@contextmanager
def creation_context():
    """Backend-owned slot for exactly its API call, restored on nested exit."""
    holder = {"owner": (_current.get(), _operation_current.get())} if observation_active() else None
    token = _creation_current.set(holder)
    try:
        yield holder
    finally:
        _creation_current.reset(token)


def _operation(scope, client):
    association = _operation_current.get()
    if association is None or association[0] is not scope or association[1]["client_id"] != client:
        raise ObservationError("missing or mismatched creation operation")
    return association[1]


def _flow_emit(scope, kind, facts):
    if set(facts) != _FLOW_FIELDS[kind]:
        raise ObservationError("invalid flow fact fields")
    scope.emit(kind, facts)


def flow_creation_begin(client, artifact, normalized_parameters, timeout, max_bytes, org_id, root_org):
    scope = _current.get()
    if scope is None:
        return None
    try:
        operation = _operation(scope, client)
        if (org_id is not None and type(org_id) is not str) or type(root_org) is not bool:
            raise ObservationError("invalid creation organization")
        holder = _creation_current.get()
        # A nested direct API call must not replace the backend's outer association.
        if holder is None or "base" in holder or holder["owner"] != (scope, _operation_current.get()):
            holder = {}
        base = {**operation, "creation_id": str(uuid.uuid4())}
        holder.update(scope=scope, base=base, returned=False)
        _flow_emit(scope, "flow.create.begin", {
            **base, "artifact": artifact,
            "parameters_sha256": hashlib.sha256(normalized_parameters.encode("utf-8")).hexdigest(),
            "timeout": timeout, "max_bytes": max_bytes, "org_id": org_id, "root_org": root_org,
        })
        return holder
    except BaseException:
        _fail(scope)
        raise


def _creation(scope, holder, client):
    operation = _operation(scope, client)
    if not holder or holder["scope"] is not scope or any(holder["base"][k] != v for k, v in operation.items()):
        raise ObservationError("mismatched creation association")
    return holder["base"]


def flow_creation_return(holder, rows):
    if holder is None:
        return
    scope = _current.get()
    try:
        base = _creation(scope, holder, holder["base"]["client_id"])
        if type(rows) is not list:
            raise ObservationError("invalid creation rows")
        projected = []
        for index, row in enumerate(rows):
            if type(row) is not dict:
                raise ObservationError("invalid creation row")
            flow, artifacts = row.get("flow_id"), row.get("artifacts")
            if flow is not None and type(flow) is not str:
                raise ObservationError("invalid returned flow identity")
            if artifacts is not None and (type(artifacts) is not list or any(type(a) is not str for a in artifacts)):
                raise ObservationError("invalid returned artifacts")
            timeout, max_bytes = row.get("timeout"), row.get("max_upload_bytes")
            if any(v is not None and type(v) is not int for v in (timeout, max_bytes)):
                raise ObservationError("invalid returned resource")
            specs_sha = hashlib.sha256(_canonical(_json_copy(row["specs"]))).hexdigest() if "specs" in row else None
            projected.append(dict(row_index=index, flow_id=flow, artifacts=artifacts,
                                  timeout=timeout, max_upload_bytes=max_bytes, specs_sha256=specs_sha))
        _flow_emit(scope, "flow.create.return", {**base, "rows": projected})
        holder["returned"] = True
        holder["first_flow"] = projected[0]["flow_id"] if projected else None
    except BaseException:
        if scope is not None:
            _fail(scope)
        raise


def flow_metadata_return(holder, client, flow, state):
    if holder is None:
        return
    scope = _current.get()
    try:
        base = _creation(scope, holder, client)
        if not holder["returned"] or holder["first_flow"] != flow or type(flow) is not str or type(state) is not str or not state:
            raise ObservationError("invalid metadata association")
        _flow_emit(scope, "flow.metadata.return", {**base, "flow_id": flow, "state": state})
    except BaseException:
        if scope is not None:
            _fail(scope)
        raise


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
