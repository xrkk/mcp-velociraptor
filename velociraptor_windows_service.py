"""Formal Windows SCM entry for the Velociraptor MCP HTTP service.

Keep the established SCM adapter in place for existing deployments and source
evidence. It calls mcp_velociraptor_bridge.main in this same process.
"""

from pathlib import Path
import sys


def main() -> int:
    # SCM starts in System32. Resolve the existing adapter from this deployment,
    # without relying on cwd or an unrelated installed ``tests`` package.
    root = Path(__file__).resolve().parent
    sys.path.insert(0, str(root / "tests"))
    from p05_service_host import main as run_service

    return run_service()


if __name__ == "__main__":
    raise SystemExit(main())
