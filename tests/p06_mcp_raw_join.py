"""Independent read-only PC026 raw association; no production admission or cost."""
from __future__ import annotations

import codecs
import hashlib
import json
import math
import os
import zlib

from mcp.types import CallToolRequestParams, CallToolResult, InitializeRequestParams, InitializeResult, PaginatedRequestParams, ListToolsResult
from pydantic import BaseModel
from tests import p06_http_body_capture as capture, p06_call_clock as clocks
from tests.p06_aggregate_reports import REPORT_KEYS

KIND = 'pc026-mcp-raw-join-v1'
# Explicit refusal, above both the existing tool result and 100 MiB HTTP limit.
MAX_MESSAGE_BYTES = 128 * 1024 * 1024
CHUNK = 65536
SCENARIOS = {'p06-compromise-scope', 'p06-ransomware-root-cause',
             'p06-credential-lateral-movement', 'p06-data-exfiltration', 'p06-remediation-validation'}


class JoinError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise JoinError(message)


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'),
                          allow_nan=False).encode('utf-8')
    except (UnicodeError,ValueError) as exc:
        raise JoinError('JSON value is not finite UTF8') from exc


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def number(text):
        value = float(text)
        require(math.isfinite(value), 'nonfinite JSON number')
        return value
    def constant(_):
        raise JoinError('nonfinite JSON number')
    try:
        if isinstance(raw, bytes): raw = raw.decode('utf-8',errors='strict')
        value = json.loads(raw, object_pairs_hook=pairs, parse_float=number, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise JoinError('invalid UTF8/JSON original') from exc
    require(isinstance(value, dict), 'JSON-RPC batch/non-object unsupported')
    return value


def preserve(raw, parsed):
    """Check each supplied key against the actual SDK model, recursively.

    Known defaults and known None omission are permitted. Ignored extensions,
    colliding aliases and scalar coercion cannot disappear behind model_dump.
    """
    if isinstance(parsed, BaseModel):
        require(isinstance(raw, dict), 'SDK input model type differs')
        aliases = {}
        for name, field in type(parsed).model_fields.items():
            aliases[name] = name
            if isinstance(field.alias, str): aliases[field.alias] = name
        dumped = parsed.model_dump(mode='json',by_alias=True,exclude_none=True)
        seen = set()
        for key, value in raw.items():
            if key in aliases:
                name = aliases[key]
                require(name not in seen, 'SDK field aliases collide')
                seen.add(name)
                field = type(parsed).model_fields[name]
                output_key = field.serialization_alias or field.alias or name
                require(value is None or output_key in dumped, 'SDK dropped declared field')
                preserve(value, getattr(parsed, name))
            else:
                extras = parsed.model_extra or {}
                require(key in extras and key in dumped, 'SDK dropped extension field')
                preserve(value, extras[key])
    elif isinstance(parsed, list):
        require(isinstance(raw, list) and len(raw) == len(parsed), 'SDK list type differs')
        for left, right in zip(raw, parsed): preserve(left, right)
    elif isinstance(parsed, dict):
        require(isinstance(raw, dict) and set(raw) == set(parsed), 'SDK dictionary fields differ')
        for key in raw: preserve(raw[key], parsed[key])
    else:
        require(canonical(raw) == canonical(parsed), 'SDK scalar coercion differs')


def sdk(model, raw):
    try:
        parsed = model.model_validate(raw, strict=True)
    except ValueError as exc:
        raise JoinError('SDK result/params model invalid') from exc
    preserve(raw, parsed)
    return parsed.model_dump(mode='json', by_alias=True, exclude_none=True)


class _Reader:
    def __init__(self, root):
        self.run = capture._Directory(root)
        try:
            self.raw = capture._Directory(self.run.path / 'raw-mcp')
        except BaseException:
            self.run.close(); raise
        self.observed = {}

    def chunks(self, name, ref=None, *, raw=False):
        directory = self.raw if raw else self.run
        fd = directory.open(name, os.O_RDONLY)
        try:
            before = os.fstat(fd)
            identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            key = ('raw' if raw else 'run', name)
            if key in self.observed:
                require(identity == self.observed[key][0], 'original identity drift')
            hash_ = hashlib.sha256(); size = 0
            while part := os.read(fd, CHUNK):
                hash_.update(part); size += len(part); yield part
            after = os.fstat(fd)
            require(identity == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                    'original changed during read')
            reference = {'path':name, 'size':size, 'sha256':hash_.hexdigest()}
            if ref is not None: require(reference == ref, 'body Ref drift')
            previous = self.observed.setdefault(key, (identity, reference))
            require(previous == (identity, reference), 'original bytes drift')
        finally:
            os.close(fd)

    def read(self, name, *, raw=False):
        return b''.join(self.chunks(name, raw=raw))

    def recheck(self):
        for (directory, name), (_, ref) in list(self.observed.items()):
            for _ in self.chunks(name, ref, raw=directory == 'raw'): pass
        self.run.check(); self.raw.check()

    def close(self):
        self.raw.close(); self.run.close()


def decoded(chunks, encoding):
    encoding = encoding.strip().lower()
    require(encoding in {'', 'identity', 'gzip'}, 'unsupported Content-Encoding')
    if encoding != 'gzip':
        yield from chunks; return
    decoder = zlib.decompressobj(31)
    try:
        for chunk in chunks:
            require(not decoder.eof or not chunk, 'gzip extra member/trailing bytes')
            while chunk:
                part = decoder.decompress(chunk, CHUNK)
                chunk = decoder.unconsumed_tail
                if part: yield part
                require(not decoder.unused_data, 'gzip extra member/trailing bytes')
        require(decoder.eof, 'gzip incomplete stream/trailer unsupported')
        tail = decoder.flush()
        if tail: yield tail
    except zlib.error as exc:
        raise JoinError('gzip integrity failure') from exc


def lines(chunks):
    utf8 = codecs.getincrementaldecoder('utf-8-sig')('strict')
    line = []; size = 0; skip_lf = False
    def feed(text):
        nonlocal line, size, skip_lf
        for char in text:
            if skip_lf:
                skip_lf = False
                if char == '\n': continue
            if char in '\r\n':
                yield ''.join(line); line = []; size = 0; skip_lf = char == '\r'
            else:
                line.append(char); size += len(char.encode('utf-8'))
                require(size <= MAX_MESSAGE_BYTES, 'SSE line exceeds supported message limit')
    try:
        for chunk in chunks: yield from feed(utf8.decode(chunk))
        yield from feed(utf8.decode(b'', final=True))
    except UnicodeError as exc:
        raise JoinError('SSE incomplete/invalid UTF8') from exc
    require(not line, 'SSE half-frame unterminated line')


def sse(chunks):
    data = []; size = 0; event = ''; pending = False
    for line in lines(chunks):
        if line == '':
            if data:
                require(event in {'', 'message'}, 'unsupported SSE event with data')
                yield strict_json('\n'.join(data))
            data = []; size = 0; event = ''; pending = False
        elif line.startswith(':'):
            pass
        else:
            pending = True
            key, _, value = line.partition(':')
            if value.startswith(' '): value = value[1:]
            if key == 'data':
                size += len(value.encode('utf-8')) + 1
                require(size <= MAX_MESSAGE_BYTES, 'SSE frame exceeds supported message limit')
                data.append(value)
            elif key == 'event': event = value
            # id/retry/unknown fields preserve original bytes; they are not data.
    require(not data and not pending, 'SSE half-frame undispatched tail')


def messages(reader, row, direction):
    ref, end = row[direction + '_ref'], row[direction + '_end']
    if direction == 'request':
        require(end == 'eof' and ref is not None, 'request body is incomplete')
        kind, encoding = 'application/json', ''
    else:
        require(end in {'eof', 'closed', 'not_started'}, 'response body error termination')
        if row['response_status'] is not None:
            require(type(row['response_status']) is int and 200 <= row['response_status'] < 300,
                    'non-success HTTP response')
        if ref is None:
            require(end == 'not_started', 'response original missing'); return
        kind = row['response_content_type'].split(';',1)[0].strip().lower()
        encoding = row['response_content_encoding']
    chunks = decoded(reader.chunks(ref['path'],ref,raw=True), encoding)
    if direction == 'response' and kind == 'text/event-stream':
        for frame, value in enumerate(sse(chunks),1):
            yield value, dict(exchange_sequence=row['sequence'], direction=direction,
                              frame_index=frame, body_ref=ref)
        return
    # Single JSON message buffering is bounded; never buffer an SSE stream.
    parts = []; size = 0
    for chunk in chunks:
        size += len(chunk)
        require(size <= MAX_MESSAGE_BYTES, 'JSON message exceeds supported message limit')
        parts.append(chunk)
    body = b''.join(parts)
    if not body:
        if direction == 'request':
            require(row['method'] in {'GET','DELETE'}, 'empty POST/other request unsupported')
        return
    require(kind == 'application/json', 'unsupported nonempty Content-Type')
    require(direction != 'response' or end == 'eof', 'JSON response is incomplete')
    value = strict_json(body)
    if direction == 'response' and row['method'] == 'DELETE':
        # The governed controller returns an empty JSON HTTP control body;
        # it is not a JSON-RPC response and has no invented request id.
        require(row['response_status'] == 200 and end == 'eof' and value == {},
                'DELETE control response differs')
        return
    yield value, dict(exchange_sequence=row['sequence'], direction=direction, frame_index=1, body_ref=ref)


def envelope(value, direction):
    require(value.get('jsonrpc') == '2.0', 'JSON-RPC version differs')
    if 'method' in value:
        require(isinstance(value['method'], str) and value['method'], 'JSON-RPC method invalid')
        require(not {'result','error'} & set(value), 'ambiguous JSON-RPC method/result')
        require(set(value) <= {'jsonrpc','id','method','params'}, 'unsupported JSON-RPC extension')
        require('params' not in value or isinstance(value['params'], dict), 'JSON-RPC params invalid')
        if 'id' not in value:
            require(value['method'].startswith('notifications/'), 'uninterpretable notification')
            return 'notification', None
        require(direction == 'request', 'server-initiated request unsupported')
        kind = 'request'
    else:
        require(direction == 'response', 'response in request body unsupported')
        require(('result' in value) != ('error' in value), 'JSON-RPC response result/error differs')
        require(set(value) <= {'jsonrpc','id','result','error'}, 'unsupported JSON-RPC extension')
        kind = 'response'
    require(type(value.get('id')) in (int,str), 'JSON-RPC id is not strict integer/string')
    return kind, (type(value['id']),value['id'])


def report_shape(report):
    require(set(report) == REPORT_KEYS and type(report.get('schema_version')) is int
            and report['schema_version'] == 2 and isinstance(report['scenario'],str)
            and report['scenario'] in SCENARIOS | {'resource-qualification','individual-acceptance'},
            'current P06 report root/schema/scenario differs')
    require(report['status'] == 'success' and report['failure'] is None
            and report['transport'] == 'streamable-http', 'report is not current successful HTTP evidence')
    session = report['mcp_session']
    require(isinstance(session,dict) and set(session) == {'id','initialized_at','closed_at'}
            and all(isinstance(v,str) and v for v in session.values()), 'report session lifecycle incomplete')
    identity = report['server_identity']
    require(isinstance(identity,dict) and set(identity) == {'computer_name','service_name','pid',
                'process_start_time_utc','instance_id','executable_sha256'}, 'report server identity shape differs')
    for row in report['calls']:
        require(row['monotonic']['invoked'] is True and type(row.get('attempt')) is int and row['attempt'] >= 1
                and isinstance(row.get('tool'),str) and isinstance(row.get('arguments'),dict)
                and isinstance(row.get('mcp_result'),dict), 'report call is incomplete')
        require(type(row.get('is_error')) is bool and row['is_error'] == row['mcp_result'].get('isError',False),
                'report CallToolResult error flag differs')
    # Source/service/session approval belongs to later production integration.


def join(run_dir, *, _reader=None):
    index = capture.verify(run_dir, _reader=_reader)
    require(index['status'] == 'RECORDED', 'capture FAILED cannot join')
    require(all(row['request_end'] != 'error' and row['response_end'] != 'error'
                for row in index['exchanges']), 'capture has error termination')
    reader = _reader or _Reader(run_dir)
    try:
        report_raw = reader.read('report.json'); report = strict_json(report_raw)
        clock_raw = reader.read('call-clock.json')
        clocks.validate(clock_raw,report_raw,report)
        report_shape(report)
        require(index['run_id'] == report['run_id'], 'capture cross-run binding')
        capture_raw = reader.read('capture.json',raw=True)
        require(capture._json(capture_raw) == index, 'capture index drift')
        requests = {}; responses = {}; tool_requests = []
        for row in index['exchanges']:
            for message, location in messages(reader,row,'request'):
                kind, key = envelope(message,'request')
                if kind == 'notification': continue
                require(key not in requests, 'duplicate request id/lifecycle')
                entry = dict(id=message['id'],method=message['method'],location=location)
                if message['method'] == 'tools/call':
                    params = message.get('params')
                    require(isinstance(params,dict) and isinstance(params.get('arguments'),dict),
                            'tools/call arguments missing/invalid')
                    sdk(CallToolRequestParams,params)
                    entry.update(tool=params['name'],arguments_sha256=digest(params['arguments']))
                    tool_requests.append(entry)
                elif message['method'] == 'initialize':
                    sdk(InitializeRequestParams,message.get('params'))
                elif message['method'] == 'tools/list':
                    sdk(PaginatedRequestParams,message.get('params',{}))
                requests[key] = entry
        initialized = [r for r in requests.values() if r['method'] == 'initialize']
        require(len(initialized) == 1, 'exactly one initialize lifecycle required')
        init_sequence = initialized[0]['location']['exchange_sequence']
        require(all(r['location']['exchange_sequence'] > init_sequence for r in requests.values()
                    if r is not initialized[0]), 'request precedes initialize lifecycle')
        require(any(r['method'] == 'tools/list' for r in requests.values()), 'tools/list request missing')
        require(len(tool_requests) == len(report['calls']), 'tools/call count differs; hidden/missing call')
        expected = {}
        for entry, row in zip(tool_requests,report['calls']):
            require(entry['tool'] == row['tool'] and entry['arguments_sha256'] == digest(row['arguments']),
                    'tools/call order/tool/arguments differ')
            expected[(type(entry['id']),entry['id'])] = row
        for row in index['exchanges']:
            for message, location in messages(reader,row,'response'):
                kind, key = envelope(message,'response')
                if kind == 'notification': continue
                require(key in requests, 'orphan response id')
                require(key not in responses, 'duplicate response id/replay')
                require('result' in message and isinstance(message['result'],dict), 'JSON-RPC error/non-result response')
                method = requests[key]['method']; result = message['result']
                result_hash = None
                if method == 'tools/call':
                    normalized = sdk(CallToolResult,result)
                    require(canonical(normalized) == canonical(expected[key]['mcp_result']),
                            'full SDK CallToolResult differs')
                    result_hash = digest(normalized)
                elif method == 'initialize': sdk(InitializeResult,result)
                elif method == 'tools/list': sdk(ListToolsResult,result)
                responses[key] = dict(location=location,result_sha256=result_hash)
        require(set(responses) == set(requests), 'request response missing')
        output_calls = []
        for entry, row in zip(tool_requests,report['calls']):
            response = responses[(type(entry['id']),entry['id'])]
            output_calls.append(dict(sequence=row['sequence'],request_id=entry['id'],
                request_location=entry['location'],response_location=response['location'],tool=row['tool'],
                arguments_sha256=entry['arguments_sha256'],result_sha256=response['result_sha256']))
        reader.recheck()
        require(capture.verify(run_dir, _reader=_reader) == index, 'capture final drift')
        def ref(name, raw): return {'path':name,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        return dict(schema_version=1,kind=KIND,run_id=report['run_id'],report_ref=ref('report.json',report_raw),
                    capture_ref=ref('raw-mcp/capture.json',capture_raw),clock_ref=ref('call-clock.json',clock_raw),
                    calls=output_calls)
    finally:
        if _reader is None: reader.close()
