"""Foreground transfer CLI. Stdout contains a single bounded JSON summary."""
import argparse
import asyncio
import json
import sys

from .adapters import AdapterError
from .errors import TransferContentError
from .host_coordinator import transfer
from .request import load_request


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run or resume a bounded host transfer")
    parser.add_argument("--spec", required=True, help="absolute path to the authorized request JSON")
    parser.add_argument("--abort", action="store_true", help="cancel the original task without deleting evidence")
    args = parser.parse_args(argv)
    try:
        request = load_request(args.spec)
        if args.abort and not request.resume:
            raise TransferContentError("abort_requires_resume")
        summary = asyncio.run(transfer(request, abort=args.abort))
    except (TransferContentError, AdapterError, OSError) as exc:
        # No result path is claimed when parsing or durable publication failed.
        code = exc.code if isinstance(exc, (TransferContentError, AdapterError)) else "host_io_failed"
        print(json.dumps({"schema": "velo.transfer.command-error.v1", "error": code}, separators=(",", ":")))
        return 4 if "conflict" in code or "revision" in code else 3
    print(json.dumps(summary, ensure_ascii=False, separators=(",", ":")))
    return summary["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
