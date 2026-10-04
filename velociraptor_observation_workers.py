"""Private retained-thread ownership primitive for the lifecycle controller.

This is not a session controller or a completion proof. No public factory,
environment or protocol input activates ownership. The future approved SDK
adapter must bind and finish the actual accepted handler's private owner.
"""
from __future__ import annotations

import asyncio
import contextvars
from dataclasses import dataclass
import threading
import time

import anyio

_CURRENT_OWNER = contextvars.ContextVar('pc026_thread_owner', default=None)


class WorkerOwnershipError(Exception):
    pass


@dataclass(eq=False, frozen=True, slots=True)
class _Owner:
    group: object
    sequence: int


@dataclass(slots=True)
class _ThreadWork:
    sequence: int
    owner: _Owner
    thread: threading.Thread | None = None
    result: object = None
    error: BaseException | None = None
    wrapper_exited: bool = False
    joined: bool = False
    cancelled: bool = False


class _WorkerGroup:
    """Bounded permanent ownership; never evicts uncertain/finished records."""
    def __init__(self, max_work):
        if type(max_work) is not int or max_work <= 0:
            raise WorkerOwnershipError('worker_budget_invalid')
        self._limit = max_work
        self._lock = threading.RLock()
        self._sequence = 0
        self._owners = {}
        self._ended = set()
        self._threads = {}
        self._closing = False
        self._unknown = False

    def _next(self):
        if self._sequence >= self._limit:
            self._closing = True
            raise WorkerOwnershipError('worker_budget_exhausted')
        self._sequence += 1
        return self._sequence

    def _admit(self):
        with self._lock:
            if self._closing or self._unknown:
                raise WorkerOwnershipError('worker_ingress_closed')
            owner = _Owner(self, self._next())
            self._owners[owner.sequence] = owner
            return owner

    def _valid(self, owner):
        return (isinstance(owner, _Owner) and owner.group is self
                and self._owners.get(owner.sequence) is owner and owner.sequence not in self._ended)

    def _register(self, owner):
        with self._lock:
            # CLOSING freezes ingress, not descendants of an admitted handler.
            if self._unknown or not self._valid(owner):
                raise WorkerOwnershipError('worker_owner_invalid')
            work = _ThreadWork(self._next(), owner)
            self._threads[work.sequence] = work
            return work

    def _finish_owner(self, owner, *, primary=None):
        with self._lock:
            if not self._valid(owner) or any(w.owner is owner and not w.joined for w in self._threads.values()):
                self._unknown = True
                if primary is not None:
                    primary.add_note('retained_owner_finish_unconfirmed')
                    raise primary
                raise WorkerOwnershipError('worker_owner_finish_unconfirmed')
            self._ended.add(owner.sequence)

    def _freeze(self):
        with self._lock:
            self._closing = True

    def _mark_unknown(self):
        with self._lock:
            self._unknown = True
            self._closing = True

    def _quiescent(self):
        with self._lock:
            return (not self._unknown and set(self._owners) == self._ended
                    and all(w.joined and w.wrapper_exited and w.thread is not None
                            and not w.thread.is_alive() for w in self._threads.values()))

    async def _wait_barrier(self, timeout_ns):
        if type(timeout_ns) is not int or timeout_ns <= 0:
            raise WorkerOwnershipError('worker_timeout_invalid')
        self._freeze()
        deadline = time.monotonic_ns() + timeout_ns
        while not self._quiescent():
            with self._lock:
                unknown = self._unknown
            if unknown or time.monotonic_ns() >= deadline:
                self._mark_unknown()
                raise WorkerOwnershipError('worker_barrier_unknown')
            await anyio.sleep(.001)
        # This is only the retained-thread barrier. It cannot authorize cut
        # publication or HTTP 200; SDK, processes, native I/O and export remain.
        with self._lock:
            return self._sequence


async def _owned_to_thread(function, /, *args, **kwargs):
    owner = _CURRENT_OWNER.get()
    if owner is None:
        return await asyncio.to_thread(function, *args, **kwargs)
    group = owner.group
    work = group._register(owner)
    loop = asyncio.get_running_loop()
    done = loop.create_future()
    context = contextvars.copy_context()

    def notify():
        if not done.done():
            done.set_result(None)

    def execute():
        try:
            work.result = context.run(function, *args, **kwargs)
        except BaseException as exc:
            work.error = exc
        finally:
            work.wrapper_exited = True
            try:
                loop.call_soon_threadsafe(notify)
            except RuntimeError:
                group._mark_unknown()

    work.thread = threading.Thread(target=execute, daemon=False, name='pc026-retained-worker')
    try:
        work.thread.start()
    except BaseException:
        group._mark_unknown()
        raise
    cancellation = None
    # AnyIO level cancellation and repeated asyncio Task.cancel are different.
    # Both must leave the waiter retained until the real wrapper AND thread exit.
    with anyio.CancelScope(shield=True):
        while not done.done():
            try:
                await asyncio.shield(done)
            except asyncio.CancelledError as exc:
                cancellation = cancellation or exc
                work.cancelled = True
        try:
            work.thread.join()
            if work.thread.is_alive() or not work.wrapper_exited:
                raise WorkerOwnershipError('worker_join_unconfirmed')
            work.joined = True
        except BaseException:
            group._mark_unknown()
            primary = cancellation if cancellation is not None else work.error
            if primary is not None:
                primary.add_note('retained_worker_join_failed')
                raise primary
            raise
    if cancellation is not None:
        if work.error is not None:
            cancellation.add_note('retained_worker_raised')
        raise cancellation
    if work.error is not None:
        raise work.error
    return work.result
