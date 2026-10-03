"""Pure PC026 observation record codec (08); no storage or source authority.

Depth counts nested JSON objects/arrays, including the outer record at depth 1.
Validation consumes one iterable once and keeps only one record and its summary.
A COMPLETE archive can describe a raised/cancelled business outcome. Neither
that status nor a hash grants admission, durability, or instance-wide coverage.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from collections.abc import Iterable


class ArchiveError(ValueError):
    """Malformed record/chain or explicit resource-budget refusal."""


ACCEPT = "pc026-observation-accept-v1"
EVENT = "pc026-observation-event-v1"
SEAL = "pc026-observation-seal-v1"
_OUTCOMES = ("returned", "raised", "cancelled")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_TARGET = {
    "target.resolve": {"operation_id", "mode", "client_id"},
    "target.operation.begin": {"operation_id", "attempt", "client_id"},
    "target.operation.end": {"operation_id", "attempt", "client_id", "outcome"},
    "target.exists": {"operation_id", "attempt", "client_id", "exists"},
    "target.clear": {"operation_id", "previous_client_id"},
}
_BASE = {"operation_id", "attempt", "client_id"}
_CREATE = {
    "flow.create.begin": {"artifact", "parameters_sha256", "timeout", "max_bytes", "org_id", "root_org"},
    "flow.create.return": {"rows"},
    "flow.metadata.return": {"flow_id", "state"},
}
_READ = {
    "flow.read.metadata": {"state", "artifacts", "sources"},
    "flow.results.plan": {"artifact", "requested_source", "selected_sources", "offset", "page_size"},
    "flow.results.count": {"artifact", "source_index", "source", "total"},
    "flow.results.window": {"artifact", "source_index", "source", "start_row", "requested_count", "returned", "rows_sha256"},
    "flow.results.page": {"returned", "data_sha256", "pagination"},
    "flow.files.raw": {"row_count", "rows_sha256"},
    "flow.files.inventory": {"record_count", "identities_sha256", "sparse_count", "size_mismatch_count"},
    "flow.files.result": {"returned", "data_sha256", "truncated"},
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ArchiveError(message)


def _exact(value, fields):
    _require(type(value) is dict and set(value) == fields, "invalid exact fields")


def _integer(value, minimum=0):
    _require(type(value) is int and value >= minimum, "invalid integer")


def _string(value, *, nonempty=False):
    _require(type(value) is str and (not nonempty or bool(value)), "invalid string")


def _hash(value):
    _require(type(value) is str and _HASH.fullmatch(value) is not None, "invalid SHA256")


def _nullable(value, check):
    if value is not None:
        check(value)


def _uuid(value):
    _string(value)
    try:
        valid = str(uuid.UUID(value)) == value
    except ValueError:
        valid = False
    _require(valid, "invalid operation UUID")


def _strings(value, *, nullable_items=False):
    _require(type(value) is list, "invalid string array")
    for item in value:
        if nullable_items and item is None:
            continue
        _string(item)


def _key(value):
    _exact(value, {"instance_id", "session_id", "request_id_type", "request_id"})
    _string(value["instance_id"], nonempty=True)
    _string(value["session_id"], nonempty=True)
    tag, identity = value["request_id_type"], value["request_id"]
    _require((tag == "integer" and type(identity) is int) or
             (tag == "string" and type(identity) is str), "invalid typed request key")


def _operation(facts):
    _uuid(facts["operation_id"])
    _integer(facts["attempt"], 1)
    _require(facts["attempt"] in (1, 2), "invalid operation attempt")
    _string(facts["client_id"], nonempty=True)


def _event(event):
    _exact(event, {"sequence", "kind", "facts"})
    _integer(event["sequence"], 1)
    kind, f = event["kind"], event["facts"]
    _string(kind)
    if kind in _TARGET:
        _exact(f, _TARGET[kind])
        if kind in ("target.operation.begin", "target.operation.end", "target.exists"):
            _operation(f)
        else:
            _nullable(f["operation_id"], _uuid)
        if kind == "target.clear":
            _nullable(f["previous_client_id"], lambda v: _string(v, nonempty=True))
        else:
            _string(f["client_id"], nonempty=True)
        if kind == "target.resolve":
            _require(f["mode"] in ("selected", "cache_hit"), "invalid resolution mode")
        if kind == "target.operation.end":
            _require(f["outcome"] in _OUTCOMES, "invalid outcome")
        if kind == "target.exists":
            _require(type(f["exists"]) is bool, "invalid exists")
    elif kind in _CREATE:
        _exact(f, _BASE | {"creation_id"} | _CREATE[kind])
        _operation(f)
        _uuid(f["creation_id"])
        if kind == "flow.create.begin":
            _string(f["artifact"], nonempty=True)
            _hash(f["parameters_sha256"])
            for field in ("timeout", "max_bytes"):
                _nullable(f[field], lambda v: _integer(v, 1))
            _nullable(f["org_id"], _string)
            _require(type(f["root_org"]) is bool, "invalid root_org")
        elif kind == "flow.create.return":
            _require(type(f["rows"]) is list, "invalid creation rows")
            for index, row in enumerate(f["rows"]):
                _exact(row, {"row_index", "flow_id", "artifacts", "timeout", "max_upload_bytes", "specs_sha256"})
                _integer(row["row_index"])
                _require(row["row_index"] == index, "invalid row index")
                _nullable(row["flow_id"], _string)
                _nullable(row["artifacts"], _strings)
                for field in ("timeout", "max_upload_bytes"):
                    _nullable(row[field], lambda v: _require(type(v) is int, "invalid returned resource"))
                _nullable(row["specs_sha256"], _hash)
        else:
            _string(f["flow_id"], nonempty=True)
            _string(f["state"], nonempty=True)
    elif kind in _READ:
        _exact(f, _BASE | {"flow_id"} | _READ[kind])
        _operation(f)
        _string(f["flow_id"], nonempty=True)
        for field in _READ[kind]:
            value = f[field]
            if field.endswith("sha256"):
                _hash(value)
            elif field in {"offset", "page_size", "source_index", "total", "start_row", "requested_count", "returned",
                           "row_count", "record_count", "sparse_count", "size_mismatch_count"}:
                _integer(value)
            elif field in {"artifacts", "sources", "selected_sources"}:
                _strings(value, nullable_items=field == "selected_sources")
            elif field in {"source", "requested_source"}:
                _nullable(value, _string)
            elif field == "state":
                _nullable(value, lambda v: _string(v, nonempty=True))
            elif field == "artifact":
                _string(value)
            elif field == "truncated":
                _require(type(value) is bool, "invalid truncated")
            elif field == "pagination":
                _exact(value, {"cursor", "next_cursor", "page_size", "returned", "truncated"})
                _string(value["cursor"])
                _nullable(value["next_cursor"], _string)
                _integer(value["page_size"], 1)
                _integer(value["returned"])
                _require(value["returned"] == f["returned"] and type(value["truncated"]) is bool,
                         "invalid pagination")
    else:
        raise ArchiveError("unknown business event kind")


def _record(record):
    _exact(record, {"schema_version", "kind", "sequence", "previous", "payload"})
    _require(type(record["schema_version"]) is int and record["schema_version"] == 1, "invalid schema version")
    _integer(record["sequence"])
    previous = record["previous"]
    if previous is not None:
        _exact(previous, {"size", "sha256"})
        _integer(previous["size"], 1)
        _hash(previous["sha256"])
    kind, p = record["kind"], record["payload"]
    _string(kind)
    if kind == ACCEPT:
        _require(record["sequence"] == 0 and previous is None, "invalid acceptance position")
        _exact(p, {"key", "tool", "arguments_sha256", "acceptance_sequence"})
        _key(p["key"])
        _string(p["tool"], nonempty=True)
        _hash(p["arguments_sha256"])
        _integer(p["acceptance_sequence"], 1)
    elif kind == EVENT:
        _require(previous is not None and record["sequence"] > 0, "invalid event position")
        _event(p)
        _require(p["sequence"] == record["sequence"], "event sequence differs")
    elif kind == SEAL:
        _require(previous is not None, "seal needs previous")
        _exact(p, {"outcome", "archive_status", "event_count"})
        _require(p["outcome"] in _OUTCOMES and p["archive_status"] in ("COMPLETE", "FAILED"), "invalid seal status")
        _integer(p["event_count"])
        _require(record["sequence"] == p["event_count"] + 1, "invalid seal sequence")
    else:
        raise ArchiveError("unknown record kind")


def _encoding_shape(value, maximum):
    # An iterative DFS rejects custom conversions/cycles before json.dumps.
    # Iterator frames do not duplicate every member of a large input array.
    stack = [iter((value,))]
    active = set()
    owners = [None]
    while stack:
        try:
            item = next(stack[-1])
        except StopIteration:
            stack.pop()
            owner = owners.pop()
            if owner is not None:
                active.remove(owner)
            continue
        if item is None or type(item) in (str, bool, int):
            continue
        if type(item) is float:
            _require(math.isfinite(item), "non-finite JSON number")
            continue
        _require(type(item) in (dict, list), "non-JSON encoding input")
        _require(len(stack) <= maximum, "JSON depth budget exceeded")
        identity = id(item)
        _require(identity not in active, "cyclic JSON input")
        active.add(identity)
        if type(item) is dict:
            _require(all(type(k) is str for k in item), "non-string JSON key")
            children = iter(item.values())
        else:
            children = iter(item)
        stack.append(children)
        owners.append(identity)


def _canonical(value):
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ArchiveError("invalid canonical JSON") from exc


def _pairs(items):
    result = {}
    for key, value in items:
        _require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _constant(value):
    raise ArchiveError("non-finite JSON number")


def _depth(raw: bytes, maximum: int):
    # Scan before the recursive standard-library decoder; braces inside strings
    # (including escaped quotes/backslashes) are not container nesting.
    depth = 0
    string = escaped = False
    for byte in raw:
        if string:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                string = False
        elif byte == 34:
            string = True
        elif byte in (123, 91):
            depth += 1
            _require(depth <= maximum, "JSON depth budget exceeded")
        elif byte in (125, 93):
            depth -= 1
    # Syntax balance and string termination are checked by json.loads.


class ArchiveCodec:
    """Explicit four-budget pure codec; budgets apply separately to each verify.

    encode validates one record, including its local position/previous shape.
    verify additionally checks the preceding original bytes and whole-chain order.
    Neither entry retains or repairs supplied records. Parser/encoder platform
    recursion limits also refuse explicitly even if a larger depth was requested.
    """

    def __init__(self, *, max_records: int, max_record_bytes: int,
                 max_total_bytes: int, max_json_depth: int):
        for value in (max_records, max_record_bytes, max_total_bytes, max_json_depth):
            _integer(value, 1)
        self.max_records = max_records
        self.max_record_bytes = max_record_bytes
        self.max_total_bytes = max_total_bytes
        self.max_json_depth = max_json_depth

    def parse(self, raw: bytes) -> dict:
        """Validate one original; a valid standalone event is not a valid chain."""
        _require(type(raw) is bytes, "record must be bytes")
        _require(len(raw) <= self.max_record_bytes and len(raw) <= self.max_total_bytes,
                 "record byte budget exceeded")
        _depth(raw, self.max_json_depth)
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise ArchiveError("invalid JSON original") from exc
        _require(_canonical(value) == raw, "noncanonical JSON original")
        _record(value)
        return value

    def encode(self, record: dict) -> bytes:
        """Generate only canonical records accepted by this same parser."""
        # Reject custom objects, tuples and non-string keys before serialization.
        _encoding_shape(record, self.max_json_depth)
        _record(record)
        raw = _canonical(record)
        parsed = self.parse(raw)
        _require(parsed == record, "non-JSON encoding input")
        return raw

    def verify(self, records: Iterable[bytes]) -> dict:
        """Consume a chain once; EOF classifies prefixes, never proves storage EOF."""
        count = total = events = 0
        summary = None
        head = None
        status, outcome = "INCOMPLETE", None
        for raw in records:
            count += 1
            _require(count <= self.max_records, "record count budget exceeded")
            _require(type(raw) is bytes, "record must be bytes")
            total += len(raw)
            _require(total <= self.max_total_bytes, "total byte budget exceeded")
            _require(status == "INCOMPLETE", "record after terminal seal")
            record = self.parse(raw)
            _require(record["sequence"] == count - 1, "noncontiguous record sequence")
            _require(record["previous"] == head, "previous original Ref differs")
            p = record["payload"]
            if count == 1:
                _require(record["kind"] == ACCEPT, "first record must accept")
                summary = {"key": dict(p["key"]), "tool": p["tool"],
                           "arguments_sha256": p["arguments_sha256"],
                           "acceptance_sequence": p["acceptance_sequence"]}
            elif record["kind"] == EVENT:
                events += 1
            elif record["kind"] == SEAL:
                _require(p["event_count"] == events, "seal event count differs")
                status, outcome = p["archive_status"], p["outcome"]
            else:
                raise ArchiveError("acceptance inside chain")
            head = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        _require(summary is not None, "empty chain")
        return {**summary, "event_count": events, "status": status,
                "outcome": outcome, "head_ref": head}


def request_key_sha256(key: dict) -> str:
    """04 canonical key digest (no LF); protocol identity, not authorization."""
    _key(key)
    return hashlib.sha256(_canonical(key)[:-1]).hexdigest()
