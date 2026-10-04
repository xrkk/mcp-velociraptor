"""HostOriginGate regression: the /chunkbin route must not bypass DNS-rebinding
protection (R14 independent verification CHK-R14-001).

The negative cases assert both the status code and that the wrapped handler
never executed; the positive cases assert the request reaches the handler.
"""

from __future__ import annotations

import asyncio
import unittest

from velociraptor_transport import FORMAL_TRANSPORT, HostOriginGate, TransportConfig, _build_protocol_http_app

GOOD_HOST = "127.0.0.1:28790"


class _Probe:
    """Raw ASGI probe recording whether the wrapped app ever ran."""

    def __init__(self) -> None:
        self.executed = False

    async def __call__(self, scope, receive, send):
        self.executed = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def _run(gate: HostOriginGate, probe: _Probe, headers: list[tuple[bytes, bytes]]):
    scope = {"type": "http", "path": "/chunkbin", "headers": headers}
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(gate(scope, receive, send))
    return sent


class HostOriginGateUnitTests(unittest.TestCase):
    def _gate(self, probe, hosts=(GOOD_HOST,), origins=("https://allowed.example",)):
        return HostOriginGate(probe, hosts, origins)

    def test_good_host_without_origin_passes(self):
        probe = _Probe()
        sent = _run(self._gate(probe), probe, [(b"host", GOOD_HOST.encode())])
        self.assertTrue(probe.executed)
        self.assertEqual(sent[0]["status"], 200)

    def test_good_host_with_allowed_origin_passes(self):
        probe = _Probe()
        _run(self._gate(probe), probe,
             [(b"host", GOOD_HOST.encode()), (b"origin", b"https://allowed.example")])
        self.assertTrue(probe.executed)

    def test_missing_host_rejected_before_handler(self):
        probe = _Probe()
        sent = _run(self._gate(probe), probe, [])
        self.assertFalse(probe.executed)
        self.assertEqual(sent[0]["status"], 421)

    def test_wrong_host_rejected_before_handler(self):
        probe = _Probe()
        sent = _run(self._gate(probe), probe, [(b"host", b"rebind.example")])
        self.assertFalse(probe.executed)
        self.assertEqual(sent[0]["status"], 421)

    def test_disallowed_origin_rejected_before_handler(self):
        probe = _Probe()
        sent = _run(self._gate(probe), probe,
                    [(b"host", GOOD_HOST.encode()), (b"origin", b"https://not-allowed.example")])
        self.assertFalse(probe.executed)
        self.assertEqual(sent[0]["status"], 403)

    def test_wildcard_host_pattern_matches_any_port(self):
        probe = _Probe()
        gate = self._gate(probe, hosts=("192.168.204.232:*",))
        _run(gate, probe, [(b"host", b"192.168.204.232:9999")])
        self.assertTrue(probe.executed)

    def test_wildcard_host_pattern_still_rejects_other_hosts(self):
        probe = _Probe()
        gate = self._gate(probe, hosts=("192.168.204.232:*",))
        sent = _run(gate, probe, [(b"host", b"rebind.example:9999")])
        self.assertFalse(probe.executed)
        self.assertEqual(sent[0]["status"], 421)

    def test_non_http_scope_passes_through(self):
        probe = _Probe()
        gate = self._gate(probe)

        async def call():
            async def receive():
                return {"type": "lifespan.startup"}

            async def send(message):
                pass

            await gate({"type": "lifespan"}, receive, send)

        asyncio.run(call())
        self.assertTrue(probe.executed)


class _StubSdkServer:
    """Minimal server stand-in exposing the chunkbin wiring surface."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._guest_transfer_tools = object()

    def streamable_http_app(self, **kwargs):
        from starlette.applications import Starlette
        from starlette.responses import PlainTextResponse
        from starlette.routing import Route

        async def mcp(request):
            return PlainTextResponse("mcp-ok")

        return Starlette(routes=[Route(self._path, mcp, methods=["POST", "GET"])])


class FormalAppWiringTests(unittest.TestCase):
    """/chunkbin behind the same Host/Origin rules as /mcp, bearer unchanged."""

    def _client(self):
        from starlette.testclient import TestClient

        config = TransportConfig(
            mode=FORMAL_TRANSPORT,
            host="127.0.0.1",
            port=28790,
            bearer_token="secret-token",
            allowed_origins=("https://allowed.example",),
        )
        app = _build_protocol_http_app(_StubSdkServer(config.path), config)
        return TestClient(app)

    def _headers(self, *, host=GOOD_HOST, origin=None, bearer="secret-token"):
        headers = {}
        if host is not None:
            headers["Host"] = host
        if origin is not None:
            headers["Origin"] = origin
        if bearer is not None:
            headers["Authorization"] = f"Bearer {bearer}"
        return headers

    def test_chunkbin_wrong_host_is_421_and_never_reaches_handler(self):
        with self._client() as client:
            response = client.post(
                "/chunkbin", content=b"",
                headers=self._headers(host="rebind.example"),
            )
            self.assertEqual(response.status_code, 421)
            self.assertNotIn(b"VBT1", response.content)

    def test_chunkbin_disallowed_origin_is_403_and_never_reaches_handler(self):
        with self._client() as client:
            response = client.post(
                "/chunkbin", content=b"",
                headers=self._headers(origin="https://not-allowed.example"),
            )
            self.assertEqual(response.status_code, 403)
            self.assertNotIn(b"VBT1", response.content)

    def test_chunkbin_missing_host_is_421(self):
        with self._client() as client:
            response = client.post(
                "/chunkbin", content=b"", headers=self._headers(host="")
            )
            self.assertEqual(response.status_code, 421)

    def test_chunkbin_valid_host_reaches_endpoint(self):
        with self._client() as client:
            response = client.post(
                "/chunkbin", content=b"", headers=self._headers()
            )
            # Host passes, but the strict live-session gate still precedes the endpoint.
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json(), {"error": {"code": "session_required"}})

    def test_chunkbin_bearer_gate_still_first(self):
        with self._client() as client:
            response = client.post(
                "/chunkbin", content=b"",
                headers=self._headers(host="rebind.example", bearer="wrong"),
            )
            self.assertEqual(response.status_code, 401)

    def test_mcp_route_keeps_sdk_gate_and_gate_middleware(self):
        with self._client() as client:
            good = client.post("/mcp", content=b"{}", headers=self._headers())
            self.assertEqual(good.status_code, 200)
            bad_host = client.post(
                "/mcp", content=b"", headers=self._headers(host="rebind.example")
            )
            self.assertEqual(bad_host.status_code, 421)
            bad_origin = client.post(
                "/mcp", content=b"",
                headers=self._headers(origin="https://not-allowed.example"),
            )
            self.assertEqual(bad_origin.status_code, 403)


if __name__ == "__main__":
    unittest.main()
