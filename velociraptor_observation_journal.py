"""PC026 10 per-request journal; explicit publisher, no root authority.

The factory owns unreturned resources. A returned journal is request-owned;
close always retires it, and closes its publisher only with owns_publisher=True.
Publish exceptions or invalid acknowledgments permanently poison the journal.
Only confirmed head/count/bytes and parent metadata are retained, not records.
"""
from __future__ import annotations

import copy
import hashlib
import threading

from velociraptor_observation_archive import ArchiveCodec, ACCEPT, EVENT, SEAL


class JournalError(ValueError):
    """Known validation refusal or unknown publication; no implicit recovery."""


def _note(primary, text):
    try:
        primary.add_note(text)
    except BaseException:
        pass


class RequestJournal:
    def __init__(self, publisher, codec: ArchiveCodec, accept_payload: dict,
                 *, owns_publisher: bool = False):
        self._lock = threading.RLock()
        self._publisher, self._codec = publisher, codec
        self._owns = owns_publisher is True
        self._owner = None
        self._head = None
        self._count = self._bytes = self._events = 0
        self._failed = self._poisoned = self._sealed = self._closed = False
        self._close_failed = False
        try:
            if (type(owns_publisher) is not bool or not isinstance(codec, ArchiveCodec)
                    or not callable(getattr(publisher, 'publish', None))
                    or (owns_publisher and not callable(getattr(publisher, 'close', None)))):
                raise JournalError('invalid journal dependencies/ownership')
            record = dict(schema_version=1, kind=ACCEPT, sequence=0,
                          previous=None, payload=copy.deepcopy(accept_payload))
            raw = codec.encode(record)
            self._parent = record['payload']
            self._reserve(raw)
            self._publish(raw, 0)
        except BaseException as primary:
            self._failed = True
            try:
                self.close()
            except BaseException:
                _note(primary, 'Journal acquisition close failed.')
            raise

    def parent(self):
        with self._lock:
            return copy.deepcopy(self._parent)

    def claim(self, owner, key, tool, arguments_sha256):
        """One permanent scope claim, including identity-refused acquisitions."""
        with self._lock:
            if self._owner is not None:
                raise JournalError('journal already claimed')
            self._owner = owner
            if (self._closed or self._sealed or self._poisoned or self._failed
                    or self._parent['key'] != key or self._parent['tool'] != tool
                    or self._parent['arguments_sha256'] != arguments_sha256):
                self._failed = True
                raise JournalError('journal parent mismatch/unavailable')

    def close_claim(self, owner):
        with self._lock:
            if self._owner is owner:
                self.close()

    def _reserve(self, raw):
        # Reserve one record and the entire per-record byte ceiling for seal.
        if (self._count + 2 > self._codec.max_records
                or self._bytes + len(raw) + self._codec.max_record_bytes
                > self._codec.max_total_bytes):
            raise JournalError('seal reservation exceeded')

    def _publish(self, raw, sequence):
        expected = dict(path=f'{sequence:08d}.json', size=len(raw),
                        sha256=hashlib.sha256(raw).hexdigest())
        try:
            result = self._publisher.publish(raw)
            # Identity is diagnostic metadata, never an approval or a source gate.
            if (type(result) is not dict or set(result) != {'ref', 'identity'}
                    or type(result['identity']) is not dict
                    or type(result['ref']) is not dict
                    or set(result['ref']) != set(expected)
                    or type(result['ref']['path']) is not str
                    or type(result['ref']['sha256']) is not str
                    or type(result['ref']['size']) is not int
                    or result['ref'] != expected):
                raise JournalError('publisher acknowledgment differs')
        except BaseException:
            self._failed = self._poisoned = True
            raise
        self._head = {'size': expected['size'], 'sha256': expected['sha256']}
        self._count += 1
        self._bytes += len(raw)

    def fail(self):
        with self._lock:
            self._failed = True

    def _available(self):
        if self._poisoned or self._closed or self._sealed:
            raise JournalError('journal unavailable')

    def append(self, event):
        """Validate and publish one event, retaining only its confirmed head."""
        with self._lock:
            self._available()
            try:
                if self._failed:
                    raise JournalError('journal already failed')
                sequence = self._events + 1
                if sequence + 1 > 99999999 or event.get('sequence') != sequence:
                    raise JournalError('event sequence differs/filename limit')
                raw = self._codec.encode(dict(schema_version=1, kind=EVENT,
                    sequence=sequence, previous=dict(self._head), payload=event))
                self._reserve(raw)
                self._publish(raw, sequence)
                self._events += 1
            except BaseException:
                self._failed = True
                raise

    def seal(self, outcome, *, failed=False):
        """Terminate a known chain; every failed seal permanently poisons it."""
        with self._lock:
            self._available()
            try:
                if type(failed) is not bool:
                    raise JournalError('invalid failed flag')
                if self._failed and not failed:
                    raise JournalError('failed journal cannot complete')
                raw = self._codec.encode(dict(schema_version=1, kind=SEAL,
                    sequence=self._events + 1, previous=dict(self._head),
                    payload=dict(outcome=outcome,
                        archive_status='FAILED' if failed else 'COMPLETE',
                        event_count=self._events)))
                if (self._count + 1 > self._codec.max_records
                        or self._bytes + len(raw) > self._codec.max_total_bytes):
                    raise JournalError('seal budget exceeded')
                self._publish(raw, self._events + 1)
                self._sealed = True
            except BaseException:
                # A seal failure is terminal even when it happened before IO.
                self._failed = self._poisoned = True
                raise

    def diagnostics(self):
        with self._lock:
            return dict(head_ref=copy.deepcopy(self._head), record_count=self._count,
                event_count=self._events, total_bytes=self._bytes, failed=self._failed,
                poisoned=self._poisoned, sealed=self._sealed, closed=self._closed,
                close_failed=self._close_failed)

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True  # One close attempt, no replay of uncertain close.
            if self._owns:
                try:
                    self._publisher.close()
                except BaseException:
                    self._failed = self._close_failed = True
                    raise
