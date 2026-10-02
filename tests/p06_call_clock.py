"""PC026 per-run observations, never a wire counter or a historical repair API."""
from __future__ import annotations

import hashlib
import math
import os
import re
import time
import uuid

from tests import p05_pc020_evidence as evidence
from tests.p06_package import canonical_bytes

KIND = 'pc026-p06-call-clock-v1'
RUNNER_KEYS = {'pid', 'process_start_time_utc', 'executable_sha256'}


class ClockError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ClockError(message)


def _uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def validate_clock(clock):
    require(isinstance(clock, dict) and set(clock) == {
        'clock_id', 'api', 'implementation', 'resolution_seconds', 'monotonic', 'adjustable'},
        'call-clock exact clock keys differ')
    require(_uuid(clock['clock_id']) and clock['api'] == 'time.monotonic_ns', 'call-clock API/UUID differs')
    require(isinstance(clock['implementation'], str) and bool(clock['implementation'].strip()),
            'call-clock implementation missing')
    resolution = clock['resolution_seconds']
    require(type(resolution) in (float, int) and math.isfinite(resolution) and resolution > 0,
            'call-clock resolution is not finite positive')
    require(clock['monotonic'] is True and clock['adjustable'] is False, 'call-clock properties differ')


def validate_calls(report, clock):
    validate_clock(clock)
    require(isinstance(report.get('calls'), list), 'call-clock calls missing')
    previous = None
    for sequence, row in enumerate(report['calls'], 1):
        require(isinstance(row, dict) and type(row.get('sequence')) is int
                and row['sequence'] == sequence, 'call-clock call sequence differs')
        value = row.get('monotonic')
        require(isinstance(value, dict) and set(value) == {'clock_id', 'invoked', 'started_ns', 'ended_ns'},
                'call-clock exact monotonic keys differ')
        require(value['clock_id'] == clock['clock_id'] and type(value['invoked']) is bool,
                'call-clock call domain/invoked differs')
        start, end = value['started_ns'], value['ended_ns']
        if not value['invoked']:
            require(start is None and end is None, 'call-clock non-invoked interval must be null')
            require(report.get('status') == 'failed', 'successful report has a non-invoked call')
            continue
        require(type(start) is int and type(end) is int and 0 <= start <= end,
                'call-clock interval is not ordered nonnegative integers')
        require(previous is None or start >= previous, 'call-clock intervals overlap or regress')
        previous = end
        require(type(row.get('duration_ms')) is int and row['duration_ms'] == (end - start) // 1_000_000,
                'call-clock duration differs from interval floor')


def validate(raw, report_raw, report):
    """Validate exact original bytes and identity, not UTC-derived observations."""
    value = evidence._json_bytes(raw, 'call-clock original')
    require(isinstance(value, dict) and set(value) == {
        'schema_version', 'kind', 'run_id', 'runner', 'report_ref', 'clock', 'status'},
        'call-clock exact record keys differ')
    require(type(value['schema_version']) is int and value['schema_version'] == 1
            and value['kind'] == KIND and value['status'] == 'RECORDED', 'call-clock record model differs')
    require(_uuid(value['run_id']) and value['run_id'] == report.get('run_id'), 'call-clock cross-run binding')
    require(isinstance(value['runner'], dict) and set(value['runner']) == RUNNER_KEYS
            and isinstance(report.get('runner'), dict) and set(report['runner']) == RUNNER_KEYS
            and all(type(value['runner'][key]) is type(report['runner'][key])
                    and value['runner'][key] == report['runner'][key] for key in RUNNER_KEYS),
            'call-clock runner binding differs')
    require(type(value['runner']['pid']) is int and value['runner']['pid'] > 0
            and isinstance(value['runner']['process_start_time_utc'], str)
            and isinstance(value['runner']['executable_sha256'], str)
            and re.fullmatch('[0-9a-f]{64}', value['runner']['executable_sha256']),
            'call-clock runner identity malformed')
    ref = value['report_ref']
    require(isinstance(ref, dict) and set(ref) == {'path', 'size', 'sha256'}
            and ref['path'] == 'report.json' and type(ref['size']) is int
            and ref['size'] == len(report_raw) and ref['sha256'] == hashlib.sha256(report_raw).hexdigest(),
            'call-clock report Ref differs')
    require(evidence._json_bytes(report_raw, 'timed report', canonical=False) == report,
            'call-clock report original differs')
    validate_calls(report, value['clock'])
    return value


class RunClock:
    """One real clock domain owned by a new admitted runner invocation."""
    def __init__(self):
        info = time.get_clock_info('monotonic')
        self.clock = {'clock_id': str(uuid.uuid4()), 'api': 'time.monotonic_ns',
                      'implementation': info.implementation, 'resolution_seconds': info.resolution,
                      'monotonic': info.monotonic, 'adjustable': info.adjustable}
        validate_clock(self.clock)
        self.failed = False
        self.previous_end = None

    def not_invoked(self):
        return {'clock_id': self.clock['clock_id'], 'invoked': False, 'started_ns': None, 'ended_ns': None}

    def _sample(self):
        value = time.monotonic_ns()
        require(type(value) is int and value >= 0, 'call-clock sample is not a nonnegative integer')
        return value

    async def observe(self, session, tool, arguments, row):
        """Return SDK result/error without losing either when end sampling fails.

        The runner must serialize the returned result before raising timing_error.
        No assertion, serialization, UTC read or sleep intervenes at the boundaries.
        """
        from tests.p05_pc026_governance import before_effect
        row['monotonic'] = self.not_invoked()
        row['duration_ms'] = 0
        raw = error = timing_error = None
        try:
            require(not self.failed, 'call-clock failed; new SDK invocation prohibited')
            method = session.call_tool
            before_effect()
            try:
                start = self._sample()
                require(self.previous_end is None or start >= self.previous_end,
                        'call-clock start regressed')
            except BaseException:
                self.failed = True
                raise
            value = row['monotonic']
            value.update(invoked=True, started_ns=start)
            try:
                raw = await method(tool, arguments)
            except BaseException as exc:
                # Sample before recording/formatting the exception.
                try:
                    value['ended_ns'] = self._sample()
                except BaseException as clock_exc:
                    timing_error = clock_exc
                error = exc
            else:
                try:
                    value['ended_ns'] = self._sample()
                except BaseException as clock_exc:
                    timing_error = clock_exc
            end = value['ended_ns']
            if timing_error is None:
                try:
                    require(type(end) is int and end >= start, 'call-clock end regressed')
                    row['duration_ms'] = (end - start) // 1_000_000
                    self.previous_end = end
                except BaseException as exc:
                    timing_error = exc
            if timing_error is not None:
                self.failed = True
        except BaseException as exc:
            error = exc
        return raw, error, timing_error

    def save(self, run_dir, report, report_raw):
        # Caller has finalized lifecycle/rechecks and written these report bytes.
        # Failed incomplete intervals remain originals; only consumers validate.
        value = {'schema_version': 1, 'kind': KIND, 'run_id': report['run_id'],
                 'runner': report['runner'], 'report_ref': {'path': 'report.json', 'size': len(report_raw),
                 'sha256': hashlib.sha256(report_raw).hexdigest()}, 'clock': self.clock, 'status': 'RECORDED'}
        with (run_dir / 'call-clock.json').open('xb') as stream:
            stream.write(canonical_bytes(value))
            stream.flush()
            os.fsync(stream.fileno())
