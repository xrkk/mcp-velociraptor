"""Strict request-spec parsing and exclusive output-directory creation.

The spec is the only input surface of the flow host. Every field is validated
before any connection or business side effect; nothing here reads the profile
contents beyond the path string itself.
"""
from __future__ import annotations

import json
import math
import os
import stat
from dataclasses import dataclass
from pathlib import Path

SPEC_SCHEMA = "velo.flow.request.v1"
SPEC_MAX_BYTES = 65536
MAX_PATH_CHARS = 4096

REQUIRED_FIELDS = ("schema", "flow_id", "connection_profile", "output_dir", "budget")
OPTIONAL_FIELDS = ("source", "page_size", "sample_fields", "sample_rows")
BUDGET_FIELDS = {
    "deadline_seconds": (120.0, 0.1, 3600.0, "number"),
    "request_timeout_seconds": (30.0, 0.01, 120.0, "number"),
    "max_status_calls": (64, 1, 512, "integer"),
    "max_pages": (100, 1, 1000, "integer"),
    "max_result_bytes": (67108864, 1, 268435456, "integer"),
    "max_log_bytes": (67108864, 1048576, 268435456, "integer"),
}


class SpecError(ValueError):
    """Stable-code spec failure; message never carries spec or token contents."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise SpecError("duplicate_key")
        result[key] = value
    return result


def _reject_constant(value):
    raise SpecError("invalid_number")


def _text_id(value, field: str) -> str:
    if (not isinstance(value, str) or not value or len(value) > 256 or
            any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)):
        raise SpecError(f"invalid_{field}")
    return value


def _absolute_path(value, field: str) -> Path:
    if not isinstance(value, str) or not value or len(value) > MAX_PATH_CHARS:
        raise SpecError(f"invalid_{field}")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise SpecError(f"invalid_{field}")
    return path


def _integer(value, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise SpecError("invalid_budget")
    return value


def _number(value, minimum: float, maximum: float) -> float:
    if (not isinstance(value, (int, float)) or isinstance(value, bool) or
            not math.isfinite(value) or not minimum <= value <= maximum):
        raise SpecError("invalid_budget")
    return float(value)


@dataclass(frozen=True)
class SpecData:
    flow_id: str
    connection_profile: Path
    output_dir: Path
    source: str | None
    page_size: int
    sample_fields: tuple[str, ...]
    sample_rows: int
    deadline_seconds: float
    request_timeout_seconds: float
    max_status_calls: int
    max_pages: int
    max_result_bytes: int
    max_log_bytes: int


def parse_spec(raw: bytes) -> SpecData:
    if not isinstance(raw, bytes) or not raw or len(raw) > SPEC_MAX_BYTES:
        raise SpecError("spec_too_large")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=_reject_constant)
    except SpecError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise SpecError("invalid_json") from None
    if not isinstance(data, dict):
        raise SpecError("invalid_spec")
    unknown = set(data) - set(REQUIRED_FIELDS) - set(OPTIONAL_FIELDS)
    missing = [field for field in REQUIRED_FIELDS if field not in data]
    if unknown or missing:
        raise SpecError("invalid_spec")
    if data["schema"] != SPEC_SCHEMA:
        raise SpecError("invalid_schema")

    budget = data["budget"]
    if not isinstance(budget, dict) or not set(budget) <= set(BUDGET_FIELDS):
        raise SpecError("invalid_budget")
    parsed_budget = {}
    for field, (default, minimum, maximum, kind) in BUDGET_FIELDS.items():
        value = budget.get(field, default)
        parsed_budget[field] = (_number(value, minimum, maximum) if kind == "number"
                                else _integer(value, minimum, maximum))

    source = data.get("source", None)
    if source is not None:
        source = _text_id(source, "source")

    page_size = data.get("page_size", 250)
    if not isinstance(page_size, int) or isinstance(page_size, bool) or not 1 <= page_size <= 250:
        raise SpecError("invalid_page_size")

    sample_fields = data.get("sample_fields", [])
    if (not isinstance(sample_fields, list) or len(sample_fields) > 32 or
            any(not isinstance(item, str) or not item or len(item) > 128 for item in sample_fields)):
        raise SpecError("invalid_sample_fields")

    sample_rows = data.get("sample_rows", 10)
    if not isinstance(sample_rows, int) or isinstance(sample_rows, bool) or not 0 <= sample_rows <= 10:
        raise SpecError("invalid_sample_rows")

    return SpecData(
        flow_id=_text_id(data["flow_id"], "flow_id"),
        connection_profile=_absolute_path(data["connection_profile"], "connection_profile"),
        output_dir=_absolute_path(data["output_dir"], "output_dir"),
        source=source,
        page_size=page_size,
        sample_fields=tuple(sample_fields),
        sample_rows=sample_rows,
        deadline_seconds=parsed_budget["deadline_seconds"],
        request_timeout_seconds=parsed_budget["request_timeout_seconds"],
        max_status_calls=parsed_budget["max_status_calls"],
        max_pages=parsed_budget["max_pages"],
        max_result_bytes=parsed_budget["max_result_bytes"],
        max_log_bytes=parsed_budget["max_log_bytes"],
    )


def load_spec(path: str | Path) -> SpecData:
    try:
        raw = Path(path).read_bytes()
    except OSError:
        raise SpecError("spec_unreadable") from None
    return parse_spec(raw)


def create_output_dir(path: Path) -> Path:
    """Create one new 0700 directory; reject existing paths and symlinked ancestry."""
    if (not path.is_absolute() or ".." in path.parts or
            any(part in ("", ".") for part in path.parts)):
        raise SpecError("invalid_output_dir")
    if os.path.lexists(path):
        raise SpecError("output_dir_exists")
    parent = path.parent
    if not parent.is_dir():
        raise SpecError("output_parent_missing")
    for ancestor in (path, *path.parents):
        try:
            info = ancestor.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise SpecError("output_dir_symlink")
        if ancestor != path and not stat.S_ISDIR(info.st_mode):
            raise SpecError("output_dir_symlink")
    try:
        os.mkdir(path, 0o700)
    except OSError:
        raise SpecError("output_dir_create_failed") from None
    return path


def open_exclusive(path: Path):
    """Open one new file for writing; never overwrite (mode 'xb')."""
    try:
        return open(path, "xb")
    except OSError:
        raise SpecError("output_file_conflict") from None
