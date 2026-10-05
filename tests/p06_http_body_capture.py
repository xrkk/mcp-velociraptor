"""PC026 transport-body originals; capture alone is never a business success gate."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

import anyio
import httpx2

KIND = 'pc026-http-body-capture-v1'
SEQUENCE_EXTENSION = 'pc026_capture_sequence'
ENDS = {'not_started', 'eof', 'closed', 'error'}
EXCHANGE_KEYS = {'sequence', 'method', 'request_ref', 'request_end', 'response_status',
                 'response_content_type', 'response_content_encoding', 'response_ref', 'response_end', 'error'}


class CaptureError(ValueError):
    pass


def require(value, message):
    if not value:
        raise CaptureError(message)


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode('utf-8')


def _uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _directory(path):
    path = Path(os.path.abspath(path))
    for parent in [*reversed(path.parents), path]:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                and not getattr(info, 'st_file_attributes', 0) & 0x400,
                'capture directory is not an ordinary no-follow directory')
    return path


def _identity(info):
    return info.st_dev, info.st_ino


class _Directory:
    """Hold the capture directory; relative no-follow opens where supported."""
    def __init__(self, path):
        self.path = _directory(path)
        self.identity = _identity(self.path.stat())
        self.fd = None
        if os.open in os.supports_dir_fd:
            self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                require(_identity(os.fstat(self.fd)) == self.identity, 'capture directory changed')
            except BaseException:
                self.close()
                raise

    def check(self):
        require(_identity(_directory(self.path).stat()) == self.identity, 'capture directory changed')

    def open(self, name, flags):
        self.check()
        flags |= getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
        existing = None
        if not flags & os.O_CREAT:
            existing = (self.path / name).lstat()
            require(stat.S_ISREG(existing.st_mode)
                    and not getattr(existing, 'st_file_attributes', 0) & 0x400,
                    'capture file is not an ordinary no-follow file')
        fd = os.open(name if self.fd is not None else self.path / name, flags, 0o600,
                     **({'dir_fd': self.fd} if self.fd is not None else {}))
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and not getattr(info, 'st_file_attributes', 0) & 0x400,
                    'capture file is not an ordinary exclusive file')
            self.check()
            named = (self.path / name).lstat()
            require(_identity(named) == _identity(info)
                    and not getattr(named, 'st_file_attributes', 0) & 0x400
                    and (existing is None or _identity(existing) == _identity(info)),
                    'capture file identity changed')
            return fd
        except BaseException:
            os.close(fd)
            raise

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class _Body:
    def __init__(self, directory, name):
        self.directory, self.name = directory, name
        self.fd = None
        self.hash = hashlib.sha256()
        self.size = 0
        self.ref = None

    def start(self):
        self.fd = self.directory.open(self.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)

    def write(self, chunk):
        view = memoryview(chunk)
        while view:
            count = os.write(self.fd, view)
            if count <= 0:
                raise OSError('capture write made no progress')
            self.hash.update(view[:count]); self.size += count
            view = view[count:]

    def finish(self):
        if self.fd is None:
            return
        fd, self.fd = self.fd, None
        try:
            os.fsync(fd)
        finally:
            try:
                require(os.fstat(fd).st_size == self.size, 'capture body size changed')
                self.ref = {'path': self.name, 'size': self.size, 'sha256': self.hash.hexdigest()}
            finally:
                os.close(fd)


def _diagnostic(exc, message):
    # Only local type names and fixed messages, never str(remote_exception).
    return {'type': type(exc).__name__, 'message': message}


class _Tee(httpx2.AsyncByteStream):
    def __init__(self, owner, original, row, direction):
        self.owner, self.original, self.row, self.direction = owner, original, row, direction
        self.body = _Body(owner.directory, f"exchange-{row['sequence']:08d}-{direction}.bin")
        self.started = self.closed = False
        self.scope = self.read_done = self.iterator = None
        self.close_lock = anyio.Lock()

    def end(self, value):
        self.row[self.direction + '_end'] = value

    def finish(self):
        try:
            self.body.finish()
        except BaseException as exc:
            self.end('error'); self.owner.fail(self.row, exc, 'capture body finalization failed')
            raise
        finally:
            self.row[self.direction + '_ref'] = self.body.ref

    async def __aiter__(self):
        require(not self.closed and not self.owner.closing, 'capture stream is closed')
        require(not self.started, 'capture stream cannot be replayed')
        self.started = True
        phase = 'capture'
        original_error = None
        try:
            self.body.start()
            phase = 'stream'
            self.iterator = self.original.__aiter__()
            while not self.closed and not self.owner.closing:
                self.read_done = anyio.Event()
                phase = 'stream'
                try:
                    with anyio.CancelScope() as scope:
                        self.scope = scope
                        chunk = await anext(self.iterator)
                    if scope.cancel_called:
                        self.end('closed'); break
                except StopAsyncIteration:
                    self.end('eof'); break
                finally:
                    self.scope = None
                    self.read_done.set()
                # No prefetch: persist exactly this chunk before yielding it.
                phase = 'capture'
                self.body.write(chunk)
                phase = 'stream'
                yield chunk
            else:
                self.end('closed')
        except GeneratorExit:
            if self.row[self.direction + '_end'] == 'not_started':
                self.end('closed')
            raise
        except BaseException as exc:
            original_error = exc
            cancelled = isinstance(exc, anyio.get_cancelled_exc_class())
            self.end('closed' if cancelled else 'error')
            if phase == 'capture' and not cancelled:
                self.owner.fail(self.row, exc, 'capture body write failed')
            else:
                self.owner.observe_error(self.row, exc, 'body stream cancelled' if cancelled else 'body stream failed')
            raise
        finally:
            try:
                self.finish()
            except BaseException as finalization_error:
                if original_error is not None:
                    original_error.add_note('capture body finalization also failed')
                    raise original_error from finalization_error
                raise

    async def aclose(self):
        # Shield resource release when SDK exits an AnyIO cancellation scope.
        with anyio.CancelScope(shield=True):
            async with self.close_lock:
                if self.closed:
                    return
                self.closed = True
                if self.scope is not None:
                    self.scope.cancel()
                    await self.read_done.wait()
                if self.started and self.row[self.direction + '_end'] == 'not_started':
                    self.end('closed')
                error = None
                try:
                    if self.iterator is not None and hasattr(self.iterator, 'aclose'):
                        await self.iterator.aclose()
                except BaseException as exc:
                    error = exc; self.end('error'); self.owner.fail(self.row, exc, 'body iterator close failed')
                try:
                    if self.direction == 'response' or self.owner.closing:
                        await self.owner.close_original(self.original)
                except BaseException as exc:
                    error = error or exc; self.end('error'); self.owner.fail(self.row, exc, 'body stream close failed')
                try:
                    self.finish()
                except BaseException as exc:
                    error = error or exc
                if error is not None:
                    raise error


class CaptureTransport(httpx2.AsyncBaseTransport):
    """Own inner transport and streams; caller supplies an admitted new run.

    The current runner constructs this only after fixed admission.
    """
    def __init__(self, inner, run_dir, run_id):
        require(_uuid(run_id), 'capture run_id must be a canonical UUID')
        root = _directory(run_dir)
        self.run_id = run_id
        anchor = _Directory(root)
        try:
            if anchor.fd is not None:
                os.mkdir('raw-mcp', mode=0o700, dir_fd=anchor.fd)
            else:
                (root / 'raw-mcp').mkdir(mode=0o700)
            anchor.check()  # exclusive, including existing empty directory
            self.directory = _Directory(root / 'raw-mcp')
        finally:
            anchor.close()
        self.inner = inner
        self.rows, self.streams, self.requests = [], [], []
        self.failure = None
        self.closed_originals = set()
        self.closing = self.closed = False
        self.close_lock = anyio.Lock()

    async def __aenter__(self):
        require(not self.closing and not self.closed, 'capture transport is closed')
        try:
            await self.inner.__aenter__()
        except BaseException as exc:
            self.fail(None, exc, 'inner transport enter failed')
            try:
                await self.aclose()
            except BaseException as close_error:
                raise exc from close_error
            raise
        return self

    async def close_original(self, stream):
        # Strong references in self.streams prevent id reuse. Shared replayable
        # request streams remain usable for the client's own redirects/retries.
        key = id(stream)
        if key not in self.closed_originals:
            self.closed_originals.add(key)
            await stream.aclose()

    def observe_error(self, row, exc, message):
        if row['error'] is None:
            row['error'] = _diagnostic(exc, message)

    def fail(self, row, exc, message):
        diagnostic = _diagnostic(exc, message)
        if row is not None and row['error'] is None:
            row['error'] = diagnostic
        if self.failure is None:
            self.failure = diagnostic

    def _allow_failed_requests(self):
        return False

    async def handle_async_request(self, request):
        require(not self.closing and not self.closed, 'capture transport is closed')
        require(self.failure is None or self._allow_failed_requests(), 'capture transport has failed')
        sequence = len(self.rows) + 1
        require(sequence <= 99_999_999, 'capture sequence exhausted')
        row = dict(sequence=sequence, method=request.method, request_ref=None, request_end='not_started',
                   response_status=None, response_content_type=None, response_content_encoding=None,
                   response_ref=None, response_end='not_started', error=None)
        self.rows.append(row)
        request_stream = _Tee(self, request.stream, row, 'request')
        self.streams.append(request_stream); request.stream = request_stream
        done = anyio.Event()
        response = None
        original_error = None
        try:
            with anyio.CancelScope() as scope:
                pending = (scope, done); self.requests.append(pending)
                response = await self.inner.handle_async_request(request)
                if SEQUENCE_EXTENSION in response.extensions:
                    error=CaptureError('capture sequence extension collision')
                    self.fail(row,error,'capture sequence extension collision')
                    await self.close_original(response.stream)
                    raise error
                response.extensions[SEQUENCE_EXTENSION] = sequence
                row.update(response_status=response.status_code,
                           response_content_type=response.headers.get('content-type', ''),
                           response_content_encoding=response.headers.get('content-encoding', ''))
                stream = _Tee(self, response.stream, row, 'response')
                self.streams.append(stream); response.stream = stream
            if scope.cancel_called:
                raise CaptureError('capture closed during exchange')
            return response
        except BaseException as exc:
            original_error = exc
            self.observe_error(row, exc, 'HTTP exchange did not complete')
            raise
        finally:
            self.requests.remove(pending)
            # Completion signal after request resources, before close publishes.
            try:
                await request_stream.aclose()
            except BaseException as close_error:
                if original_error is not None:
                    original_error.add_note('capture request close also failed')
                    raise original_error from close_error
                raise
            finally:
                request.stream = request_stream.original
                done.set()

    async def aclose(self):
        with anyio.CancelScope(shield=True):
            async with self.close_lock:
                if self.closed:
                    return
                self.closing = True
                error = None
                for scope, _ in list(self.requests):
                    scope.cancel()
                for _, done in list(self.requests):
                    await done.wait()
                for stream in self.streams:
                    try:
                        await stream.aclose()
                    except BaseException as exc:
                        error = error or exc
                for stream in self.streams:
                    try:
                        await self.close_original(stream.original)
                    except BaseException as exc:
                        self.fail(stream.row, exc, 'original body stream close failed')
                        error = error or exc
                try:
                    await self.inner.aclose()
                except BaseException as exc:
                    self.fail(None, exc, 'inner transport close failed'); error = error or exc
                try:
                    value = dict(schema_version=1, kind=KIND, run_id=self.run_id, exchanges=self.rows,
                                 status='FAILED' if self.failure else 'RECORDED', failure=self.failure)
                    fd = self.directory.open('capture.pending.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                    try:
                        raw = canonical(value); view = memoryview(raw)
                        while view:
                            count = os.write(fd, view)
                            if count <= 0: raise OSError('capture index write made no progress')
                            view = view[count:]
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    # Publish only fsynced bytes, with exclusive no-overwrite link.
                    # A failed staging original remains for failure preservation.
                    self.directory.check()
                    if self.directory.fd is not None:
                        os.link('capture.pending.json', 'capture.json',
                                src_dir_fd=self.directory.fd, dst_dir_fd=self.directory.fd,
                                follow_symlinks=False)
                        os.unlink('capture.pending.json', dir_fd=self.directory.fd)
                    else:
                        os.link(self.directory.path / 'capture.pending.json',
                                self.directory.path / 'capture.json', follow_symlinks=False)
                        (self.directory.path / 'capture.pending.json').unlink()
                    self.directory.check()
                except BaseException as exc:
                    error = error or exc
                finally:
                    self.closed = True
                    self.directory.close()
                if error is not None:
                    raise error


def _json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'capture duplicate JSON key')
            value[key] = item
        return value
    def constant(_):
        raise CaptureError('capture nonfinite JSON number')
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    require(raw == canonical(value), 'capture JSON is not canonical')
    return value


def verify(run_dir, run_id=None, *, _reader=None):
    """Read-only structural/original validation, without a business verdict."""
    directory = _Directory(_directory(run_dir) / 'raw-mcp')
    files = {'capture.json'}
    def read(name):
        if _reader is not None: return _reader.read(name, raw=True)
        fd = directory.open(name, os.O_RDONLY)
        try:
            before = os.fstat(fd); chunks = []
            while chunk := os.read(fd, 65536): chunks.append(chunk)
            after = os.fstat(fd)
            require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'capture original drift')
            return b''.join(chunks)
        finally:
            os.close(fd)
    def diagnostic(value):
        require(value is None or isinstance(value, dict) and set(value) == {'type', 'message'}
                and all(isinstance(value[k], str) and value[k] for k in value), 'capture diagnostic differs')
    try:
        value = _json(read('capture.json'))
        require(isinstance(value, dict) and set(value) == {'schema_version', 'kind', 'run_id', 'exchanges', 'status', 'failure'},
                'capture exact index keys differ')
        require(type(value['schema_version']) is int and value['schema_version'] == 1 and value['kind'] == KIND
                and _uuid(value['run_id']) and (run_id is None or value['run_id'] == run_id), 'capture model/run differs')
        require(isinstance(value['status'], str) and value['status'] in {'RECORDED', 'FAILED'}, 'capture status differs')
        diagnostic(value['failure'])
        require((value['status'] == 'RECORDED') == (value['failure'] is None), 'capture failure/status differs')
        require(isinstance(value['exchanges'], list), 'capture exchanges differ')
        for sequence, row in enumerate(value['exchanges'], 1):
            require(isinstance(row, dict) and set(row) == EXCHANGE_KEYS, 'capture exact exchange keys differ')
            require(type(row['sequence']) is int and row['sequence'] == sequence and sequence <= 99_999_999,
                    'capture sequence differs')
            require(isinstance(row['method'], str) and row['method'] and row['method'].isascii()
                    and all(c.isalnum() or c in "!#$%&'*+-.^_`|~" for c in row['method']), 'capture method differs')
            diagnostic(row['error'])
            status = row['response_status']
            require(status is None or type(status) is int and 100 <= status <= 599, 'capture response status differs')
            require(all((row[k] is None if status is None else isinstance(row[k], str))
                        for k in ('response_content_type', 'response_content_encoding')), 'capture response headers differ')
            if status is None:
                require(row['response_ref'] is None and row['response_end'] == 'not_started', 'capture absent response differs')
            for direction in ('request', 'response'):
                end, ref = row[direction + '_end'], row[direction + '_ref']
                require(isinstance(end, str) and end in ENDS, 'capture end differs')
                require(end != 'not_started' or ref is None, 'capture unstarted body has Ref')
                require(end != 'eof' or ref is not None, 'capture EOF body lacks Ref')
                if ref is None: continue
                name = f'exchange-{sequence:08d}-{direction}.bin'
                require(isinstance(ref, dict) and set(ref) == {'path', 'size', 'sha256'} and ref['path'] == name
                        and name not in files and type(ref['size']) is int and ref['size'] >= 0
                        and isinstance(ref['sha256'], str), 'capture Ref/path differs')
                files.add(name)
                # Bounded-memory body verification; no parsing or rewriting.
                if _reader is not None:
                    for _ in _reader.chunks(name, ref, raw=True): pass
                else:
                    fd = directory.open(name, os.O_RDONLY)
                    try:
                        before = os.fstat(fd); digest = hashlib.sha256(); size = 0
                        while chunk := os.read(fd, 65536): digest.update(chunk); size += len(chunk)
                        after = os.fstat(fd)
                        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                                (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'capture body drift')
                        require(size == ref['size'] and digest.hexdigest() == ref['sha256'], 'capture Ref size/hash differs')
                    finally:
                        os.close(fd)
        directory.check()
        require({p.name for p in directory.path.iterdir()} == files, 'capture files missing or unindexed')
        return value
    finally:
        directory.close()
