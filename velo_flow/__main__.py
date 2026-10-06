"""CLI entry point: ``.venv/bin/python -m velo_flow --spec /absolute/request.json``.

stdout carries exactly one compact JSON summary (<=4096 bytes); diagnostics go
to stderr. Exit codes: 0 complete, 2 partial/failed, 3 input error before any
business call. ``execute`` exposes the same chain with a ``session_factory``
injection point used only by offline evidence to simulate explicit external
transport faults; production always uses the real Streamable HTTP transport.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

from velo_transfer.connection import ConnectionError as ProfileError
from velo_transfer.connection import load_connection_profile

from . import transport
from .coordinator import RESULT_SCHEMA, FlowHostCoordinator, OutputSink, RunResult, RunStop
from .spec import SpecError, create_output_dir, load_spec

EXIT_COMPLETE = 0
EXIT_INCOMPLETE = 2
EXIT_INPUT = 3


def _emit(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":"),
                                 allow_nan=False) + "\n")
    sys.stdout.flush()


def _debug(message: str, enabled: bool) -> None:
    if enabled:
        print(f"[velo_flow {time.strftime('%H:%M:%S')}] {message}", file=sys.stderr)


async def execute(spec_path: Path, *, session_factory=None, debug: bool = False) -> int:
    try:
        spec = load_spec(spec_path)
    except SpecError as exc:
        _emit({"schema": RESULT_SCHEMA, "outcome": "failed", "reason": exc.code,
               "error": {"code": exc.code}, "exit_code": EXIT_INPUT})
        return EXIT_INPUT
    try:
        endpoint = load_connection_profile(spec.connection_profile).velo
        token = endpoint.token.read() if endpoint.token is not None else None
    except ProfileError:
        _emit({"schema": RESULT_SCHEMA, "outcome": "failed", "reason": "invalid_profile",
               "error": {"code": "invalid_profile"}, "exit_code": EXIT_INPUT})
        return EXIT_INPUT
    try:
        create_output_dir(spec.output_dir)
    except SpecError as exc:
        _emit({"schema": RESULT_SCHEMA, "outcome": "failed", "reason": exc.code,
               "error": {"code": exc.code}, "exit_code": EXIT_INPUT})
        return EXIT_INPUT
    try:
        sink = OutputSink(spec.output_dir)
    except SpecError as exc:
        _emit({"schema": RESULT_SCHEMA, "outcome": "failed", "reason": exc.code,
               "error": {"code": exc.code}, "exit_code": EXIT_INPUT})
        return EXIT_INPUT

    core = FlowHostCoordinator(spec, sink)
    factory = session_factory or (lambda: transport.open_session(
        endpoint.url, token, spec.request_timeout_seconds))
    deadline = time.monotonic() + spec.deadline_seconds
    run_result: RunResult | None = None
    close_error = None
    _debug("connecting", debug)
    try:
        context = factory()
        session = await asyncio.wait_for(context.__aenter__(), timeout=spec.deadline_seconds)
    except asyncio.TimeoutError:
        run_result = RunResult("partial", "deadline_exceeded", False, "deadline_exceeded")
    except RunStop as stop:
        run_result = RunResult(stop.outcome, stop.reason, False, stop.reason)
    except Exception:
        run_result = RunResult("failed", "connect_failed", False, "connect_failed")
    else:
        try:
            _debug("session ready, running coordinator", debug)
            run_result = await core.run(session, deadline_monotonic=deadline)
        finally:
            try:
                await context.__aexit__(None, None, None)
                _debug("session closed cleanly", debug)
            except Exception as exc:
                close_error = exc
                _debug("shutdown fault recorded", debug)

    if close_error is not None:
        if run_result is not None and run_result.complete:
            run_result = RunResult("partial", "close_failed", False, "close_failed")
        elif run_result is not None:
            run_result.secondary_code = "close_failed"

    file_facts = {
        "contract_path": str(sink.contract_path),
        "calls_path": str(sink.calls_path), "calls_bytes": sink.calls_bytes,
        "calls_sha256": None,
        "rows_path": str(sink.rows_path), "rows_bytes": sink.rows_bytes,
        "rows_sha256": None,
    }
    if run_result is None:
        run_result = RunResult("failed", "connect_failed", False, "connect_failed")
    try:
        file_facts = sink.finalize()
    except RunStop as stop:
        run_result = RunResult("failed", stop.reason, False, stop.reason)

    result_path = str(sink.result_path)
    try:
        summary = core.build_summary(run_result, file_facts)
        with open(sink.result_path, "xb") as fh:
            fh.write(json.dumps(summary, ensure_ascii=False, separators=(",", ":"),
                                allow_nan=False).encode("utf-8"))
    except (OSError, RunStop):
        run_result = RunResult("failed", "io_error", False, "io_error")
        result_path = None
        try:
            summary = core.build_summary(run_result, file_facts)
        except RunStop:
            summary = {"schema": RESULT_SCHEMA, "outcome": "failed", "reason": "io_error",
                       "flow_id": spec.flow_id, "complete": False}

    exit_code = EXIT_COMPLETE if run_result.complete else EXIT_INCOMPLETE
    try:
        _emit(core.stdout_summary(summary, exit_code, result_path))
    except (RunStop, TypeError, ValueError):
        _emit({"schema": RESULT_SCHEMA, "outcome": "failed", "reason": "stdout_overflow",
               "flow_id": spec.flow_id, "complete": False, "result_path": result_path,
               "exit_code": EXIT_INCOMPLETE})
        return EXIT_INCOMPLETE
    return exit_code


class _ArgumentParser(argparse.ArgumentParser):
    """Argparse that reports usage errors through the exit-3 input channel."""

    def error(self, message):
        self.print_usage(sys.stderr)
        _emit({"schema": RESULT_SCHEMA, "outcome": "failed", "reason": "invalid_arguments",
               "error": {"code": "invalid_arguments"}, "exit_code": EXIT_INPUT})
        raise SystemExit(EXIT_INPUT)


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(
        prog="velo_flow",
        description="Wait for one existing Velociraptor flow, page its results once, "
                    "and write a bounded summary into a new output directory.")
    parser.add_argument("--spec", required=True,
                        help="absolute path to the velo.flow.request.v1 JSON spec")
    parser.add_argument("--debug", action="store_true",
                        help="progress diagnostics on stderr")
    args = parser.parse_args(argv)
    return asyncio.run(execute(Path(args.spec), debug=args.debug))


if __name__ == "__main__":
    sys.exit(main())
