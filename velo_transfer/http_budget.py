"""Count actual HTTP request/response stream bytes before forwarding them."""
from __future__ import annotations
import httpx2
from contextvars import ContextVar
from .wire import BODY_LIMIT


CALL_HTTP_FAILURE = ContextVar("velo_transfer_http_failure", default=None)


class HTTPBodyLimitError(httpx2.TransportError):
    pass


class CountedStream(httpx2.AsyncByteStream):
    def __init__(self, stream, limit, code):
        self.stream = stream; self.limit = limit; self.code = code

    async def __aiter__(self):
        count = 0
        iterator = self.stream.__aiter__()
        try:
            async for part in iterator:
                count += len(part)
                if count > self.limit:
                    fact = CALL_HTTP_FAILURE.get()
                    if fact is not None:
                        fact["code"] = self.code
                    raise HTTPBodyLimitError(self.code)
                yield part
        finally:
            close = getattr(iterator, "aclose", None)
            if close is not None:
                await close()
            await self.stream.aclose()

    async def aclose(self):
        await self.stream.aclose()


class CountedTransport(httpx2.AsyncBaseTransport):
    def __init__(self, inner=None, limit=BODY_LIMIT):
        self.inner = inner or httpx2.AsyncHTTPTransport()
        self.limit = min(limit, BODY_LIMIT)

    async def handle_async_request(self, request):
        request.stream = CountedStream(request.stream, self.limit, 'request_too_large')
        response = await self.inner.handle_async_request(request)
        response.stream = CountedStream(response.stream, self.limit, 'response_too_large')
        return response

    async def aclose(self):
        await self.inner.aclose()
