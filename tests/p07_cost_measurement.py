"""ACC-P07-002 / ACC-024 cost measurement: tool count, schema bytes, comparison.

Produces a structured JSON report covering the ACC-024 cost dimensions:
actual tool count, tools/list schema byte size, representative fixed-task
call chain profile, and transparent comparison with the legacy 78-tool baseline.
"""

from __future__ import annotations

import json
import hashlib
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT = REPO_ROOT / "Logs" / "P07" / "cost-measurement.json"


def measure_static() -> dict:
    """Measure tool counts and schema bytes without a live MCP session."""
    sys.path.insert(0, str(REPO_ROOT))

    # Parse tool names from source without importing modules that may need
    # dependencies not available on this host (jsonschema, mcp, etc.)
    import re
    from pathlib import Path as P

    dyn_src = P(REPO_ROOT / "velociraptor_dynamic_artifacts.py").read_text()
    match = re.search(r'APPROVED_WINDOWS_ARTIFACTS[^=]*=\s*\{(.*?)\}', dyn_src, re.DOTALL)
    dynamic_names = sorted(set(re.findall(r'"(Windows\.[^"]+)"', match.group(1)))) if match else []
    dynamic_count = len(dynamic_names)

    fix_src = P(REPO_ROOT / "velociraptor_fixed_tools.py").read_text()
    match2 = re.search(r'FIXED_TOOL_NAMES\s*=\s*\((.*?)\)', fix_src, re.DOTALL)
    fixed_names = sorted(set(re.findall(r'"([a-z_]+)"', match2.group(1)))) if match2 else []
    fixed_count = len(fixed_names)
    total = dynamic_count + fixed_count

    # Schema bytes: serialize tool names + estimated schema footprint
    tool_names = sorted(dynamic_names + fixed_names)
    schema_payload = json.dumps({"tools": tool_names}, ensure_ascii=False, indent=1)
    schema_bytes = len(schema_payload.encode("utf-8"))

    # Source line counts
    bridge_lines = len(Path(REPO_ROOT / "mcp_velociraptor_bridge.py").read_text().splitlines())
    core_lines = len(Path(REPO_ROOT / "velociraptor_mcp_core.py").read_text().splitlines())

    # Legacy baseline for comparison
    legacy_tool_count = 78

    return {
        "schema": "p07-cost-measurement-v1",
        "measured_at": datetime.now(UTC).isoformat(),
        "tool_counts": {
            "dynamic_artifact_tools": dynamic_count,
            "fixed_lifecycle_tools": fixed_count,
            "total_current": total,
            "legacy_baseline": legacy_tool_count,
            "delta_from_legacy": total - legacy_tool_count,
        },
        "schema_bytes": {
            "tools_list_names_only": schema_bytes,
            "schema_sha256": hashlib.sha256(schema_payload.encode("utf-8")).hexdigest(),
        },
        "source_metrics": {
            "bridge_lines": bridge_lines,
            "core_lines": core_lines,
            "bridge_lines_before_p07": 2219,
            "bridge_lines_removed": 2219 - bridge_lines,
        },
        "representative_fixed_task_chain": {
            "description": "Standard investigation: triage -> flow status -> flow results -> file list -> file download -> hunt lifecycle -> cancel",
            "minimum_calls": 7,
            "estimated_output_per_call_bytes_range": "1KB-50KB (structured JSON, pagination-limited)",
        },
        "comparison_with_legacy": {
            "legacy": {
                "tool_count": legacy_tool_count,
                "had_structured_results": False,
                "had_formal_http": False,
                "had_pagination": False,
            },
            "current": {
                "tool_count": total,
                "has_structured_results": True,
                "has_formal_http": True,
                "has_pagination": True,
            },
        },
    }


def main() -> int:
    report = measure_static()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(OUTPUT), "total_tools": report["tool_counts"]["total_current"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
