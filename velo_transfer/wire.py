"""Strict PC026 VBT1 components; no transport or filesystem side effects."""
from __future__ import annotations

import hashlib
import json
import re
from importlib.resources import files

MAGIC = b"VBT1"
HEADER_LIMIT = 1 << 20
CHUNK_LIMIT = 1 << 20
BATCH_LIMIT = 64 << 20
BODY_LIMIT = 100 << 20
_CONTRACT = json.loads(files("velo_transfer").joinpath("transfer_tools_schema.json").read_text())
CODES = frozenset(_CONTRACT["transfer_status"]["outputSchema"]["oneOf"][1]["properties"]["error"]["properties"]["code"]["enum"])
HTTP_ERRORS = {401: "unauthorized", 421: "bad_host", 403: "origin_denied",
               404: "session_not_found", 413: "body_too_large", 415: "unsupported_media_type",
               500: "internal_error"}


class WireError(ValueError):
    pass


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise WireError("invalid_frame")
        value[key] = item
    return value


def strict_json(raw):
    try:
        return json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw,
                          object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(WireError("invalid_frame")))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise WireError("invalid_frame") from None


def _object(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise WireError("invalid_frame")


def _integer(value, minimum=0, maximum=None):
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise WireError("invalid_frame")


def _digest(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise WireError("invalid_frame")


def validate(header, payload, component):
    if component == "pull_request":
        _object(header, ())
        if payload:
            raise WireError("invalid_frame")
        return
    if component == "error_response":
        _object(header, ("status", "error")); _object(header["error"], ("code",))
        if header["status"] != "error" or type(header["error"]["code"]) is not str or header["error"]["code"] not in CODES or payload:
            raise WireError("invalid_frame")
        return
    if component == "push_response":
        _object(header, ("status", "result")); _object(header["result"], ("verified_offset", "accepted"))
        if header["status"] != "success" or payload:
            raise WireError("invalid_frame")
        _integer(header["result"]["verified_offset"])
        _integer(header["result"]["accepted"], 1, 64)
        return
    if component == "push_request":
        _object(header, ("chunks",)); items = header["chunks"]; minimum = 1
    elif component == "pull_response":
        _object(header, ("status", "result")); _object(header["result"], ("verified_offset", "chunks"))
        if header["status"] != "success":
            raise WireError("invalid_frame")
        _integer(header["result"]["verified_offset"])
        items = header["result"]["chunks"]; minimum = 0
    else:
        raise WireError("invalid_frame")
    if type(items) is not list or not minimum <= len(items) <= 64 or len(payload) > BATCH_LIMIT:
        raise WireError("invalid_frame")
    cursor = 0
    previous_end = None
    for item in items:
        _object(item, ("count", "chunk_sha256") if component == "push_request" else ("offset", "count", "chunk_sha256"))
        _integer(item["count"], 1, CHUNK_LIMIT); _digest(item["chunk_sha256"])
        if component == "pull_response":
            _integer(item["offset"])
            if previous_end is not None and item["offset"] != previous_end:
                raise WireError("invalid_frame")
            previous_end = item["offset"] + item["count"]
        end = cursor + item["count"]
        if end > len(payload) or hashlib.sha256(payload[cursor:end]).hexdigest() != item["chunk_sha256"]:
            raise WireError("invalid_frame")
        cursor = end
    if cursor != len(payload) or (previous_end is not None and header["result"]["verified_offset"] != previous_end):
        raise WireError("invalid_frame")


def parse(body):
    if len(body) > BODY_LIMIT or len(body) < 8 or body[:4] != MAGIC:
        raise WireError("invalid_frame")
    size = int.from_bytes(body[4:8], "little")
    if size > HEADER_LIMIT or 8 + size > len(body):
        raise WireError("invalid_frame")
    header = strict_json(body[8:8 + size])
    if type(header) is not dict:
        raise WireError("invalid_frame")
    return header, body[8 + size:]


def decode(body, component):
    header, payload = parse(body)
    validate(header, payload, component)
    return header, payload


def encode(header, payload, component):
    validate(header, payload, component)
    raw = json.dumps(header, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(raw) > HEADER_LIMIT or 8 + len(raw) + len(payload) > BODY_LIMIT:
        raise WireError("invalid_frame")
    return MAGIC + len(raw).to_bytes(4, "little") + raw + payload


def one_header(headers, name, *, required=True):
    values = [v for k, v in headers if k.lower() == name.encode("ascii")]
    if not values and not required:
        return None
    if len(values) != 1:
        raise WireError("invalid_frame")
    try:
        value = values[0].decode("ascii")
    except UnicodeError:
        raise WireError("invalid_frame") from None
    if not value or value.strip() != value or "," in value:
        raise WireError("invalid_frame")
    return value


def request_headers(headers):
    direction = one_header(headers, "x-velo-direction")
    if direction not in ("push", "pull"):
        raise WireError("invalid_frame")
    value = {"transfer_id": one_header(headers, "x-velo-transfer-id"),
             "request_digest": one_header(headers, "x-velo-request-digest")}
    if not 1 <= len(value["transfer_id"]) <= 128:
        raise WireError("invalid_frame")
    _digest(value["request_digest"])
    for name, key, minimum, maximum in (("x-velo-offset", "offset", 0, None),
        ("x-velo-count-per-chunk", "count_per_chunk", 1, CHUNK_LIMIT),
        ("x-velo-chunk-count", "chunk_count", 1, 64)):
        raw = one_header(headers, name, required=key == "offset" or direction == "pull")
        if direction == "push" and key != "offset":
            if raw is not None:
                raise WireError("invalid_frame")
            continue
        if len(raw) > 128 or re.fullmatch(r"0|[1-9][0-9]*", raw) is None:
            raise WireError("invalid_frame")
        value[key] = int(raw); _integer(value[key], minimum, maximum)
    return direction, value
