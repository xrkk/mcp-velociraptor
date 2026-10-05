"""PC026 approved, bounded attempt ledger. Not installed by the bridge.

BEGIN precedes directory/accept, ACK precedes business, END follows actual caller
worker exit and sealed/closed originals. UNKNOWN is permanent and never replayed.
Catalog/state/security locks have separate roles; no state lock calls a journal.
"""
from __future__ import annotations

from dataclasses import dataclass
import copy
import hashlib
import re
import threading

from velociraptor_observation_archive import _key, _canonical
from velociraptor_observation_catalog import KIND, WindowsCatalogPublisher, _directory
from velociraptor_observation_config import load_approved, CONFIG
from velociraptor_observation_journal import RequestJournal
from velociraptor_observation_namespace import WindowsDirectoryAllocator
from velociraptor_observation_windows import WindowsRecordPublisher
from tests.p05_pc026_windows_reader import WindowsSession, _note


class LedgerError(RuntimeError):
    pass


def _require(ok, code):
    if not ok:
        raise LedgerError(code)


class AttemptLease:
    __slots__ = ('_decision', '_reason')

    def __new__(cls):
        raise TypeError('attempt leases are issued only by the ledger')

    def __setattr__(self, name, value):
        raise AttributeError('immutable attempt lease')

    @property
    def decision(self): return self._decision

    @property
    def reason(self): return self._reason


@dataclass
class _Attempt:
    sequence: int
    key: dict
    tool: str
    sha: str
    decision: str
    state: str = 'BEGUN'
    directory: object = None
    publisher: object = None
    journal: object = None
    active: bool = True


def _ack(result, raw, sequence):
    expected = dict(path=f'{sequence:08d}.json', size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    _require(type(result) is dict and set(result) == {'ref', 'identity'}
        and type(result['identity']) is dict and type(result['ref']) is dict
        and set(result['ref']) == set(expected) and type(result['ref']['size']) is int
        and type(result['ref']['path']) is str and type(result['ref']['sha256']) is str
        and result['ref'] == expected, 'publication_ack_differs')
    return expected


class _RequestPublisher:
    def __init__(self, ledger, attempt, publisher):
        self.ledger, self.attempt, self.publisher = ledger, attempt, publisher
        self.closed = self.close_failed = False
        self.count = self.total = 0
        self.head = self.accept_ref = None

    def publish(self, raw):
        try:
            self.ledger._recheck(self.attempt.directory)
            result = self.publisher.publish(raw)
            ref = _ack(result, raw, self.count)
            self.ledger._recheck(self.attempt.directory)
            self.count += 1; self.total += len(raw); self.head = ref
            if self.count == 1: self.accept_ref = dict(ref)
            return result
        except BaseException:
            self.ledger._poison()
            raise

    def close(self):
        if self.closed: return
        self.closed = True
        try:
            self.publisher.close()
            self.ledger._recheck(self.attempt.directory)
        except BaseException:
            self.close_failed = True
            self.ledger._poison()
            raise


@dataclass(frozen=True)
class _PrefixOriginal:
    path: str
    raw: bytes
    identity: bytes
    sd: bytes


@dataclass(frozen=True)
class _SessionPrefix:
    instance: str
    session: str
    catalog_count: int
    catalog_head: bytes
    attempts: tuple
    originals: tuple


class ArchiveAttemptLedger:
    def __init__(self):
        raise TypeError('use open_approved(instance_id)')

    @classmethod
    def open_approved(cls, instance_id):
        _require(type(instance_id) is str and re.fullmatch('[0-9a-f]{32}', instance_id), 'instance_invalid')
        config = load_approved()
        self = object.__new__(cls)
        self._initialize(instance_id, config)
        return self

    def _initialize(self, instance, config):
        self._state_lock, self._catalog_lock, self._security_lock = threading.RLock(), threading.Lock(), threading.RLock()
        self._instance, self._config = instance, config
        self._limits = copy.deepcopy(config.document['budgets'])
        self._attempts, self._seen = {}, set()
        self._attempt_count = self._seen_bytes = self._active = self._request_reserve = 0
        self._accepted = self._rejected = self._catalog_count = self._catalog_bytes = 0
        self._head = None
        self._unknown = self._closed = self._closing = False
        self._allocator = self._catalog = self._reader = self._exporter = None
        self._issued_prefixes = {}
        try:
            config.group.recheck()
            self._allocator = WindowsDirectoryAllocator(config.document['guest_namespace_root'],
                max_directories=self._limits['max_directories'])
            root = self._allocator.root
            _require(root.identity == config.document['root_identity'], 'actual_root_identity_differs')
            sd = self._allocator._session._bind(root.path, True, 'state')[1][1]
            _require(sd == config.root_sd, 'actual_root_full_sd_differs')
            # Pure-check first/last record ceilings before the first mkdir.
            payload = dict(config_ref=config.group.allowed[CONFIG],
                freeze_ref=config.document['implementation_freeze_ref'], root_identity=root.identity)
            self._raw('INSTANCE_BEGIN', payload)
            self._raw('INSTANCE_END', dict(attempt_count=0, accepted_count=0, rejected_count=0, state='CLOSED_KNOWN'),
                      sequence=1, previous=dict(size=1, sha256='0'*64))
            self._recheck(root)
            self._instance_dir = self._allocator.allocate(root, 'i'+instance)
            self._recheck(self._instance_dir)
            self._catalog_dir = self._allocator.allocate(self._instance_dir, 'c')
            self._recheck(self._catalog_dir)
            cc = config.catalog_codec
            self._catalog = WindowsCatalogPublisher(self._catalog_dir.path, max_records=cc.max_records,
                max_record_bytes=cc.max_record_bytes, max_total_bytes=cc.max_total_bytes, max_json_depth=cc.max_json_depth)
            self._reader = WindowsSession()
            _require(self._reader.sid == root.identity['principal_sid'], 'readback_principal_differs')
            self._publish('INSTANCE_BEGIN', payload)
        except BaseException as primary:
            self._unknown = self._closed = True
            self._cleanup(primary)
            raise

    def _poison(self):
        with self._state_lock: self._unknown = True

    def _available(self):
        _require(not (self._closed or self._closing or self._unknown), 'ledger_unavailable')

    def _recheck(self, lease):
        with self._security_lock:
            self._config.group.recheck()
            self._allocator.recheck(lease)

    def _raw(self, kind, payload, *, sequence=None, previous=None):
        seq = self._catalog_count if sequence is None else sequence
        prev = self._head if sequence is None else previous
        return self._config.catalog_codec.encode(dict(schema_version=1, kind=KIND, sequence=seq,
            previous=copy.deepcopy(prev), record_type=kind, instance_id=self._instance, payload=payload))

    def _publish(self, kind, payload):
        # Caller owns catalog transaction lock; initialization has no other caller.
        raw = self._raw(kind, payload)
        _require(self._catalog_count < self._limits['max_catalog_records']
                 and self._catalog_bytes + len(raw) <= self._config.catalog_codec.max_total_bytes, 'catalog_budget')
        try:
            self._recheck(self._catalog_dir)
            result = self._catalog.publish(raw)
            _ack(result, raw, self._catalog_count)
            self._recheck(self._catalog_dir)
        except BaseException:
            self._poison()
            raise
        self._head = dict(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        self._catalog_count += 1; self._catalog_bytes += len(raw)

    def begin(self, key, tool, arguments_sha256):
        _key(key)
        _require(key['instance_id'] == self._instance and type(tool) is str and bool(tool)
            and type(arguments_sha256) is str and re.fullmatch('[0-9a-f]{64}', arguments_sha256), 'attempt_parent_invalid')
        key = copy.deepcopy(key); raw_key = _canonical(key)[:-1]
        _require(len(raw_key) <= self._limits['max_key_bytes'], 'key_budget')
        with self._catalog_lock:
            with self._state_lock:
                self._available()
                _require(self._attempt_count < self._limits['max_attempts'], 'attempt_budget_exhausted')
                reason = 'NONE'
                if raw_key in self._seen: reason = 'DUPLICATE'
                elif self._active >= self._limits['max_active']: reason = 'ACTIVE_LIMIT'
                elif self._seen_bytes + len(raw_key) > self._limits['max_seen_key_bytes']: reason = 'SEEN_LIMIT'
                elif (self._request_reserve + self._config.codec.max_total_bytes
                      + (3*self._limits['max_attempts']+2)*self._limits['max_catalog_record_bytes']
                      + self._limits['max_active']*self._config.codec.max_record_bytes
                      + self._limits['max_catalog_record_bytes'] > self._limits['max_total_archive_bytes']): reason = 'BYTE_LIMIT'
                decision = 'NEW' if reason == 'NONE' else 'REJECTED'
                seq = self._attempt_count + 1
            payload = dict(attempt_sequence=seq, key=key, tool=tool, arguments_sha256=arguments_sha256,
                           decision=decision, reason=reason)
            # Formatting refusal, including an oversized tool, has no reservation/write.
            self._raw('ATTEMPT_BEGIN', payload)
            lease = object.__new__(AttemptLease)
            object.__setattr__(lease, '_decision', decision); object.__setattr__(lease, '_reason', reason)
            attempt = _Attempt(seq, key, tool, arguments_sha256, decision, active=decision == 'NEW')
            with self._state_lock:
                self._attempt_count += 1; self._attempts[lease] = attempt
                if raw_key not in self._seen:
                    self._seen.add(raw_key); self._seen_bytes += len(raw_key)
                if attempt.active:
                    self._active += 1; self._request_reserve += self._config.codec.max_total_bytes
            try:
                self._publish('ATTEMPT_BEGIN', payload)
                if decision == 'REJECTED':
                    self._publish('ATTEMPT_END', dict(attempt_sequence=seq, disposition='REJECTED', outcome=None,
                        head_ref=None, record_count=0, event_count=0, total_bytes=0))
                    attempt.state = 'ENDED'; self._rejected += 1
                return lease
            except BaseException:
                self._poison()
                self._retire(attempt)
                raise

    def _owned(self, lease, state):
        _require(type(lease) is AttemptLease and lease in self._attempts, 'attempt_not_owned')
        attempt = self._attempts[lease]
        _require(attempt.decision == 'NEW' and attempt.state == state, 'attempt_reentry_or_phase')
        return attempt

    def _retire(self, attempt):
        with self._state_lock:
            if attempt.active:
                attempt.active = False; self._active -= 1

    def accept(self, lease):
        with self._state_lock:
            self._available(); attempt = self._owned(lease, 'BEGUN'); attempt.state = 'ACCEPTING'
        publisher = None
        try:
            self._recheck(self._instance_dir)
            attempt.directory = self._allocator.allocate(self._instance_dir, _directory(attempt.sequence, attempt.key))
            self._recheck(attempt.directory)
            codec = self._config.codec
            native = WindowsRecordPublisher(attempt.directory.path, max_records=codec.max_records,
                max_record_bytes=codec.max_record_bytes, max_total_bytes=codec.max_total_bytes, max_json_depth=codec.max_json_depth)
            publisher = attempt.publisher = _RequestPublisher(self, attempt, native)
            journal = attempt.journal = RequestJournal(publisher, codec, dict(key=attempt.key, tool=attempt.tool,
                arguments_sha256=attempt.sha, acceptance_sequence=attempt.sequence), owns_publisher=True)
            with self._catalog_lock:
                with self._state_lock: self._available()
                ref = dict(publisher.accept_ref); ref['path'] = attempt.directory.path.name + '/' + ref['path']
                self._publish('ACCEPT_ACK', dict(attempt_sequence=attempt.sequence, accept_ref=ref))
                self._accepted += 1
            with self._state_lock: attempt.state = 'ACCEPTED'
            return journal
        except BaseException as primary:
            self._poison(); attempt.state = 'UNKNOWN'; self._retire(attempt)
            if publisher is not None:
                try: attempt.journal.close() if attempt.journal is not None else publisher.close()
                except BaseException: _note(primary, 'accept_close_failed')
            raise

    def finish(self, lease, outcome):
        _require(outcome in ('returned', 'raised', 'cancelled') and type(outcome) is str, 'outcome_invalid')
        with self._state_lock:
            _require(not self._closed and not self._closing, 'ledger_closed')
            attempt = self._owned(lease, 'ACCEPTED'); attempt.state = 'FINISHING'
        journal, publisher = attempt.journal, attempt.publisher
        try:
            diagnostics = journal.diagnostics()  # Never with state/catalog lock held.
        except BaseException:
            self._poison()
            with self._state_lock: attempt.state = 'ACCEPTED'
            raise
        if not diagnostics['closed']:
            with self._state_lock: attempt.state = 'ACCEPTED'
            raise LedgerError('journal_not_closed')
        try:
            _require(diagnostics['sealed'] and not diagnostics['poisoned'] and not diagnostics['close_failed']
                     and publisher.closed and not publisher.close_failed and journal._owner is not None, 'journal_not_known')
            with self._security_lock:
                self._recheck(attempt.directory)
                names = self._reader._directory_names(attempt.directory.path, self._config.codec.max_records + 1)
                expected = frozenset(f'{i:08d}.json' for i in range(publisher.count))
                _require(names == expected, 'request_directory_members_differ')
                actual_bytes = 0
                def originals():
                    nonlocal actual_bytes
                    for index in range(publisher.count):
                        raw = self._reader._record_bytes(attempt.directory.path/f'{index:08d}.json', self._config.codec.max_record_bytes)
                        actual_bytes += len(raw)
                        yield raw
                summary = self._config.codec.verify(originals())
                _require(self._reader._directory_names(attempt.directory.path, self._config.codec.max_records+1) == names, 'request_directory_drift')
                self._recheck(attempt.directory)
            _require(summary['key'] == attempt.key and summary['tool'] == attempt.tool
                and summary['arguments_sha256'] == attempt.sha and summary['acceptance_sequence'] == attempt.sequence
                and summary['outcome'] == outcome and summary['status'] in ('COMPLETE', 'FAILED')
                and summary['head_ref'] == dict(size=publisher.head['size'], sha256=publisher.head['sha256'])
                and diagnostics['head_ref'] == summary['head_ref']
                and actual_bytes == publisher.total
                and diagnostics['record_count'] == publisher.count and diagnostics['total_bytes'] == publisher.total
                and diagnostics['event_count'] == summary['event_count'], 'request_originals_differ')
            with self._catalog_lock:
                with self._state_lock: self._available()
                ref = dict(publisher.head); ref['path'] = attempt.directory.path.name + '/' + ref['path']
                self._publish('ATTEMPT_END', dict(attempt_sequence=attempt.sequence, disposition=summary['status'],
                    outcome=outcome, head_ref=ref, record_count=publisher.count, event_count=summary['event_count'], total_bytes=publisher.total))
            attempt.state = 'ENDED'
        except BaseException:
            attempt.state = 'UNKNOWN'; self._poison()
            raise
        finally:
            self._retire(attempt)  # Caller asserted actual worker exit, not HTTP cancel.

    def _session_prefix(self, session, *, max_files, max_bytes):
        """Private bounded native snapshot; format EOF is never storage EOF.

        Temporary source handles are closed before returning immutable bytes.
        This snapshot grants no export authority or final-close certificate.
        """
        _require(type(session) is str and bool(session), 'session_invalid')
        _require(all(type(x) is int and x>0 for x in (max_files,max_bytes)), 'prefix_budget_invalid')
        reader=None;primary=None
        try:
            # Actual catalog publication owns this same lock through readback.
            # It cannot leave a pending transaction outside this snapshot.
            with self._catalog_lock, self._security_lock:
                with self._state_lock:self._available()
                self._recheck(self._catalog_dir)
                count=self._catalog_count;head=copy.deepcopy(self._head)
                _require(count>0 and head is not None,'prefix_head_missing')
                reader=WindowsSession()
                _require(reader.sid==self._allocator.root.identity['principal_sid'],'prefix_principal_differs')
                expected=frozenset(f'{i:08d}.json' for i in range(count))
                names=reader._directory_names(self._catalog_dir.path,self._config.catalog_codec.max_records+1)
                _require(names==expected,'prefix_catalog_members_differ')
                originals=[];total=0;catalog=[];begins={};ends={};acks={}
                def read(path,coordinate,limit):
                    nonlocal total
                    _require(len(originals)<max_files,'prefix_file_budget')
                    raw,_,identity=reader._read_original(path,limit)
                    _require(len(raw)<=limit,'prefix_record_budget')
                    sd=reader._bind(path,False,'state')[1][1]
                    _require(hashlib.sha256(sd).hexdigest()==identity['acl_sha256'],'prefix_sd_differs')
                    # Includes actual source bytes, SD and retained metadata;
                    # caller reserves against its remaining retained budget.
                    total+=len(raw)+len(sd)+len(_canonical(identity))+len(coordinate.encode('utf-8'))+512
                    _require(total<=max_bytes,'prefix_byte_budget')
                    originals.append(_PrefixOriginal(coordinate,raw,_canonical(identity),bytes(sd)))
                    return raw
                for index in range(count):
                    raw=read(self._catalog_dir.path/f'{index:08d}.json',f'c/{index:08d}.json',
                        self._config.catalog_codec.max_record_bytes)
                    row=self._config.catalog_codec.parse(raw);catalog.append(raw)
                    kind,p=row['record_type'],row['payload']
                    if kind=='ATTEMPT_BEGIN':begins[p['attempt_sequence']]=p
                    elif kind=='ATTEMPT_END':ends[p['attempt_sequence']]=p
                    elif kind=='ACCEPT_ACK':acks[p['attempt_sequence']]=p
                summary=self._config.catalog_codec.verify(iter(catalog))
                _require(summary['instance_id']==self._instance and summary['record_count']==count
                    and summary['head_ref']==head,'prefix_catalog_head_differs')
                _require(reader._directory_names(self._catalog_dir.path,self._config.catalog_codec.max_records+1)==names,
                    'prefix_catalog_directory_drift')
                selected=tuple(number for number,p in begins.items() if p['key']['session_id']==session)
                by_sequence={a.sequence:a for a in self._attempts.values() if a.key['session_id']==session}
                _require(set(selected)==set(by_sequence),'prefix_session_attempts_differ')
                for number in selected:
                    begin=begins[number];end=ends.get(number);attempt=by_sequence[number]
                    _require(end is not None and attempt.state=='ENDED','prefix_session_unended')
                    _require(begin['key']==attempt.key and begin['tool']==attempt.tool
                        and begin['arguments_sha256']==attempt.sha and begin['decision']==attempt.decision,
                        'prefix_session_parent_differs')
                    if attempt.decision=='REJECTED':
                        _require(end['disposition']=='REJECTED' and number not in acks,'prefix_rejection_differs')
                        continue
                    self._recheck(attempt.directory)
                    maximum=self._config.codec.max_records+1
                    expected=frozenset(f'{i:08d}.json' for i in range(end['record_count']))
                    names=reader._directory_names(attempt.directory.path,maximum)
                    _require(names==expected,'prefix_request_members_differ')
                    records=[]
                    for index in range(end['record_count']):
                        coordinate=attempt.directory.path.name+f'/{index:08d}.json'
                        records.append(read(attempt.directory.path/f'{index:08d}.json',coordinate,
                            self._config.codec.max_record_bytes))
                    actual=self._config.codec.verify(iter(records))
                    expected_head={k:end['head_ref'][k] for k in ('size','sha256')}
                    _require(actual['status']==end['disposition'] and actual['key']==begin['key']
                        and actual['tool']==begin['tool'] and actual['arguments_sha256']==begin['arguments_sha256']
                        and actual['acceptance_sequence']==number and actual['outcome']==end['outcome']
                        and actual['head_ref']==expected_head and actual['event_count']==end['event_count']
                        and sum(map(len,records))==end['total_bytes'],'prefix_request_originals_differ')
                    accept=dict(path=attempt.directory.path.name+'/00000000.json',size=len(records[0]),
                        sha256=hashlib.sha256(records[0]).hexdigest())
                    _require(acks.get(number,{}).get('accept_ref')==accept,'prefix_accept_ack_differs')
                    _require(reader._directory_names(attempt.directory.path,maximum)==names,
                        'prefix_request_directory_drift')
                    self._recheck(attempt.directory)
                self._recheck(self._catalog_dir)
                with self._state_lock:self._available()
                # Head cannot be cut ahead of completed publication/readback.
                _require(count==self._catalog_count and head==self._head,'prefix_head_drift')
                prefix = _SessionPrefix(self._instance,session,count,_canonical(head),selected,tuple(originals))
        except BaseException as error:
            primary=error;self._poison();raise
        finally:
            if reader is not None:
                try:reader.close()
                except BaseException:
                    self._poison()
                    if primary is None:raise
                    _note(primary,'prefix_reader_close_failed')
        with self._state_lock:
            self._available()
            self._issued_prefixes[session] = prefix
        return prefix

    def _cleanup(self, primary=None):
        first = primary
        # Returned journals belong to their caller; no active journal is stolen.
        for resource in (self._exporter, self._reader, self._catalog, self._allocator, self._config.group):
            if resource is not None:
                try: resource.close()
                except BaseException as exc:
                    if first is None: first = exc
                    else: _note(first, 'archive_resource_close_failed')
        if primary is None and first is not None:
            raise LedgerError('archive_resource_close_failed') from first

    def close(self):
        with self._catalog_lock:
            with self._state_lock:
                if self._closed:
                    _require(not self._unknown, 'ledger_closed_unknown')
                    return
                _require(self._active == 0, 'active_attempts_remain')
                self._closing = True
            primary = None
            try:
                _require(not self._unknown and all(a.state == 'ENDED' for a in self._attempts.values()), 'ledger_unknown')
                self._publish('INSTANCE_END', dict(attempt_count=self._attempt_count, accepted_count=self._accepted,
                    rejected_count=self._rejected, state='CLOSED_KNOWN'))
            except BaseException as exc:
                primary = exc; self._poison()
            finally:
                with self._state_lock: self._closed = True
                try: self._cleanup(primary)
                except BaseException as exc:
                    self._poison(); primary = exc
            if primary is not None: raise primary

    def __enter__(self):
        with self._state_lock: self._available()
        return self

    def __exit__(self, kind, primary, tb):
        try: self.close()
        except BaseException:
            if primary is None: raise
            _note(primary, 'archive_close_failed')
