"""Synthetic production-stack fixture for the PC017 triage request budget."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp.server.transport_security import TransportSecuritySettings
from tests.p04_fixture_server import dynamic_candidate
import velociraptor_api
from velociraptor_fixed_tools import register_fixed_tools, validate_combined_registry
from velociraptor_mcp_core import TargetContext, VelociraptorBackend


class RecordingStub:
    def __init__(self, trace: Path, *, dependency: bool) -> None:
        self.trace = trace
        self.dependency = dependency
        self.requests = []

    def save(self) -> None:
        self.trace.write_text(
            json.dumps(
                {
                    "requests": self.requests,
                    "submit_count": sum(
                        "LET collection <= collect_client" in item["query"]
                        for item in self.requests
                    ),
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    def Query(self, request):
        query = request.Query[0].VQL
        self.requests.append(
            {"org_id": getattr(request, "org_id", ""), "query": query}
        )
        self.save()
        if "FROM artifact_definitions()" in query:
            rows = [{"name": "Windows.Triage.Targets"}] if self.dependency else []
        elif "FROM clients()" in query:
            rows = [
                {
                    "client_id": "C.fixture",
                    "system": "windows",
                    "hostname": "TRIAGE-FIXTURE",
                    "fqdn": "TRIAGE-FIXTURE",
                }
            ]
        elif "LET collection <= collect_client" in query:
            rows = [{"flow_id": "F.triage-budget"}]
        elif "FROM flows(" in query:
            rows = [{"state": "WAITING"}]
        else:
            raise AssertionError(f"unexpected external query: {query}")
        return [SimpleNamespace(Response=json.dumps(rows), error="", log="")]


def main() -> int:
    trace = Path(os.environ["PC017_TRIAGE_TRACE"])
    stub = RecordingStub(
        trace, dependency=os.environ.get("PC017_TRIAGE_DEPENDENCY") == "present"
    )
    velociraptor_api.stub = stub
    velociraptor_api._stub_created_at = time.monotonic()
    server, specs = dynamic_candidate()
    backend = VelociraptorBackend()
    register_fixed_tools(
        server,
        specs,
        TargetContext(backend),
        backend,
        download_root=os.environ["PC017_TRIAGE_DOWNLOAD_ROOT"],
    )
    validate_combined_registry(server, specs)
    if os.environ.get("PC017_TRIAGE_TRANSPORT") != "http":
        server.run("stdio")
        return 0

    import uvicorn

    port = int(os.environ["PC017_TRIAGE_PORT"])
    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=False,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[f"127.0.0.1:{port}"],
            allowed_origins=[],
        ),
        host="127.0.0.1",
    )
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
