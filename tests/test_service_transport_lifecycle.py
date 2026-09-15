"""Exercise the internal service lifecycle seam without opening sockets."""
import asyncio
import types
import unittest
from unittest.mock import Mock, patch

from velociraptor_transport import TransportConfig, run_formal_http


class ServiceTransportLifecycleTests(unittest.TestCase):
    def execute(self, *, ready=True, stop=None):
        events = []

        class Server:
            def __init__(self, config):
                self.started = False
                self.should_exit = False

            async def startup(self, sockets=None):
                events.append('startup')
                self.started = ready

            async def on_tick(self, counter):
                events.append(('tick', counter, self.should_exit))
                return self.should_exit

            def run(self):
                async def serve():
                    await self.startup()
                    if self.started:
                        for counter in range(2):
                            if await self.on_tick(counter):
                                events.append('graceful_shutdown')
                                break
                asyncio.run(serve())

        module = types.SimpleNamespace(Server=Server, Config=Mock())
        with patch.dict('sys.modules', uvicorn=module), patch('velociraptor_transport.build_formal_http_app') as app:
            run_formal_http(object(), TransportConfig('http', host='192.0.2.2'),
                            on_ready=lambda: events.append('ready'), stop_requested=stop)
            app.assert_called_once()
        return events

    def test_ready_follows_real_server_startup(self):
        self.assertEqual(self.execute()[:2], ['startup', 'ready'])

    def test_stop_enters_existing_graceful_shutdown_path(self):
        values = iter([False, True])
        self.assertEqual(self.execute(stop=lambda: next(values)),
                         ['startup', 'ready', ('tick', 0, False), ('tick', 1, True), 'graceful_shutdown'])

    def test_failed_startup_is_not_successful_service_exit(self):
        with self.assertRaisesRegex(RuntimeError, 'did not reach readiness'):
            self.execute(ready=False)


if __name__ == '__main__':
    unittest.main()
