"""Bounded MCP 2.1.1 adapter. Derived portions: MIT Anthropic, PBC 2024.
See docs/observation-sdk-LICENSE.txt and observation-sdk-source-map.json.
Private resource adapter only: no admission/controller/cut authority is granted.
"""
from __future__ import annotations
from contextlib import asynccontextmanager
import anyio
from mcp.server.streamable_http import StreamableHTTPServerTransport as _BaseTransport
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager as _BaseManager
from mcp.server.runner import ServerRunner
from mcp.server.connection import Connection
from mcp.shared.jsonrpc_dispatcher import JSONRPCDispatcher
from mcp.server.streamable_http_manager import (AuthenticatedUser, ErrorData, INVALID_REQUEST, JSONRPCError, MCP_SESSION_ID_HEADER, Receive, Request, Response, Scope, Send, TaskStatus, anyio, authorization_context, logger, uuid4)
from mcp.server.streamable_http import (AsyncGenerator, CONTENT_TYPE_SSE, DEFAULT_NEGOTIATED_VERSION, EventMessage, EventSourceResponse, GET_STREAM_KEY, HTTPStatus, INTERNAL_ERROR, INVALID_PARAMS, JSONRPCError, JSONRPCRequest, JSONRPCResponse, LAST_EVENT_ID_HEADER, MCP_PROTOCOL_VERSION_HEADER, MCP_SESSION_ID_HEADER, PARSE_ERROR, REQUEST_STREAM_BUFFER_SIZE, ReadStream, Receive, Request, RequestId, SSEEvent, Scope, Send, ServerMessageMetadata, SessionMessage, ValidationError, WriteStream, anyio, asynccontextmanager, check_accept_headers, jsonrpc_message_adapter, logger, partial, pydantic_core)

class _Resources:
    def __init__(self):
        self.streams = []
        self.error = None
        self.closing = False
        self.runner_exited = False
        self.dispatcher_joined = False
        self.connection_closed = False
    def fault(self, error):
        if self.error is None:
            self.error = error
        controller=getattr(self,'controller',None)
        if controller is not None:controller._unknown(getattr(self,'session',None))
    def watch(self, stream):
        wrapped = _OwnedStream(self, stream)
        self.streams.append(wrapped)
        return wrapped
    def memory(self, size=0):
        streams = tuple(self.watch(s) for s in anyio.create_memory_object_stream(size))
        from velociraptor_observation_controller import _CURRENT_HTTP
        current = _CURRENT_HTTP.get()
        if current is not None:
            current[2].streams.extend(streams)
        return streams
    def context(self, size=0):
        from mcp.shared._context_streams import create_context_streams
        return tuple(self.watch(s) for s in create_context_streams(size))
    async def close(self, streams):
        primary = None
        with anyio.CancelScope(shield=True):
            for stream in streams:
                try:
                    await stream.aclose()
                except BaseException as error:
                    self.fault(error)
                    primary = primary or error
        if primary is not None:
            raise primary
    async def close_all(self):
        await self.close(tuple(self.streams))
        if self.error is not None:
            raise self.error
    def known_closed(self):
        return (self.error is None and self.runner_exited and self.dispatcher_joined
                and self.connection_closed and all(s.closed for s in self.streams))

class _OwnedStream:
    def __init__(self, resources, stream):
        self._resources = resources
        self._stream = stream
        self._attempted = False
        self.closed = False
        self._error = None
        self._done = anyio.Event()
    def __getattr__(self, name):
        return getattr(self._stream, name)
    def clone(self):
        return self._resources.watch(self._stream.clone())
    def __aiter__(self):
        return self
    async def __anext__(self):
        return await self._stream.__anext__()
    async def __aenter__(self):
        await self._stream.__aenter__()
        return self
    async def __aexit__(self, typ, primary, traceback):
        try:
            await self.aclose()
        except BaseException:
            if primary is not None:
                primary.add_note('sdk_owned_stream_close_failed')
                raise primary
            raise
    def close(self):
        # The pinned outgoing dispatcher closes its real memory streams
        # synchronously. Retain that close witness, just like async aclose.
        if self._attempted:
            if not self._done.is_set():
                error=RuntimeError('sdk_stream_close_in_progress')
                self._resources.fault(error);raise error
            if self._error is not None:raise self._error
            return
        self._attempted=True
        try:
            self._stream.close()
            self.closed=True
        except BaseException as error:
            self._error=error;self._resources.fault(error);raise
        finally:self._done.set()

    async def aclose(self):
        with anyio.CancelScope(shield=True):
            if self._attempted:
                await self._done.wait()
                if self._error is not None:
                    raise self._error
                return
            self._attempted = True
            try:
                await self._stream.aclose()
                self.closed = True
            except BaseException as error:
                self._error = error
                self._resources.fault(error)
                raise
            finally:
                self._done.set()


class _TrackedDispatcher(JSONRPCDispatcher):
    """Original small hooks over pinned upstream algorithms; no source copy."""
    async def _write(self, message, metadata=None):
        controller=getattr(self._resources,'controller',None)
        if controller is not None and isinstance(message,JSONRPCRequest):
            controller._issued_request(self,message)
        return await super()._write(message,metadata)

    async def _dispatch(self, item, on_request, on_notify, sender_ctx):
        controller=getattr(self._resources,'controller',None)
        if (controller is not None and not isinstance(item,Exception)
                and isinstance(item.message,(JSONRPCResponse,JSONRPCError))):
            async def consume():
                await super(_TrackedDispatcher,self)._dispatch(item,on_request,on_notify,sender_ctx)
            return await controller._consume_response(self,item,consume)
        return await super()._dispatch(item,on_request,on_notify,sender_ctx)

async def _serve_loop(server, read_stream, write_stream, *, lifespan_state,
                      session_id=None, init_options=None, raise_exceptions=False, resources):
    # Derived from the fixed serve_loop/serve_connection recipes (53 source lines).
    dispatcher = _TrackedDispatcher(read_stream, write_stream,
        raise_handler_exceptions=raise_exceptions, inline_methods=frozenset({'initialize'}))
    dispatcher._resources=resources
    resources.dispatcher=dispatcher
    connection = Connection.for_loop(dispatcher, session_id=session_id)
    runner = ServerRunner(server, connection, lifespan_state, init_options=init_options)
    primary = None
    try:
        controller = getattr(resources, 'controller', None)
        if controller is None:
            await dispatcher.run(runner.on_request, runner.on_notify)
        else:
            async def request(dctx, method, params):
                return await controller._dispatch(dctx, method, params, runner.on_request)
            async def notify(dctx, method, params):
                return await controller._dispatch(dctx, method, params, runner.on_notify)
            await dispatcher.run(request, notify)
    except BaseException as error:
        primary = error
        resources.fault(error)
        raise
    finally:
        resources.dispatcher_joined = True
        with anyio.CancelScope(shield=True):
            try:
                await connection.exit_stack.aclose()
                resources.connection_closed = True
            except BaseException as error:
                resources.fault(error)
                if primary is not None:
                    primary.add_note('sdk_connection_close_failed')
                    raise primary
                raise

class _TrackedTransport(_BaseTransport):
    def __init__(self, *args, resources, **kwargs):
        super().__init__(*args, **kwargs)
        self._owned = resources

    async def _clean_up_memory_streams(self, request_id: RequestId) -> None:
        pair = self._request_streams.pop(request_id, None)
        if pair is not None:
            await self._owned.close(pair)

    async def _handle_post_request(self, scope: Scope, request: Request, receive: Receive, send: Send) -> None:
        """Handle POST requests containing JSON-RPC messages."""
        writer = self._read_stream_writer
        if writer is None:
            raise ValueError('No read stream writer available. Ensure connect() is called first.')
        try:
            if not await self._validate_accept_header(request, scope, send):
                return
            if not self._check_content_type(request):
                response = self._create_error_response('Unsupported Media Type: Content-Type must be application/json', HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
                await response(scope, receive, send)
                return
            body = await request.body()
            try:
                raw_message = pydantic_core.from_json(body)
            except ValueError as e:
                response = self._create_error_response(f'Parse error: {str(e)}', HTTPStatus.BAD_REQUEST, PARSE_ERROR)
                await response(scope, receive, send)
                return
            try:
                message = jsonrpc_message_adapter.validate_python(raw_message, by_name=False)
            except ValidationError as e:
                response = self._create_error_response(f'Validation error: {str(e)}', HTTPStatus.BAD_REQUEST, INVALID_PARAMS)
                await response(scope, receive, send)
                return
            is_initialization_request = isinstance(message, JSONRPCRequest) and message.method == 'initialize'
            if is_initialization_request:
                if self.mcp_session_id:
                    request_session_id = self._get_session_id(request)
                    if request_session_id and request_session_id != self.mcp_session_id:
                        response = self._create_error_response('Not Found: Invalid or expired session ID', HTTPStatus.NOT_FOUND)
                        await response(scope, receive, send)
                        return
            elif not await self._validate_request_headers(request, send):
                return
            if not isinstance(message, JSONRPCRequest):
                response = self._create_json_response(None, HTTPStatus.ACCEPTED)
                await response(scope, receive, send)
                session_message = SessionMessage(message, metadata=self._message_metadata(request))
                await writer.send(session_message)
                return
            protocol_version = str(message.params.get('protocolVersion', DEFAULT_NEGOTIATED_VERSION)) if is_initialization_request and message.params else request.headers.get(MCP_PROTOCOL_VERSION_HEADER, DEFAULT_NEGOTIATED_VERSION)
            request_id = str(message.id)
            if self.is_json_response_enabled:
                self._request_streams[request_id] = self._owned.memory(REQUEST_STREAM_BUFFER_SIZE)
                request_stream_reader = self._request_streams[request_id][1]
                metadata = self._message_metadata(request, on_request_unanswered=partial(self._terminate_unanswered_request, message.id))
                session_message = SessionMessage(message, metadata=metadata)
                await writer.send(session_message)
                try:
                    event_message = await request_stream_reader.receive()
                except (anyio.EndOfStream, anyio.ClosedResourceError):
                    logger.debug(f'Session terminated with request {request_id} in flight; no response to send')
                    response = self._create_error_response('Session terminated before the request completed', HTTPStatus.INTERNAL_SERVER_ERROR, INTERNAL_ERROR)
                else:
                    response = self._create_json_response(event_message.message)
                finally:
                    await self._clean_up_memory_streams(request_id)
                await response(scope, receive, send)
            else:
                priming_event = await self._mint_priming_event(request_id, protocol_version)
                sse_stream_writer, sse_stream_reader = self._owned.memory(0)
                self._sse_stream_writers[request_id] = sse_stream_writer
                self._request_streams[request_id] = self._owned.memory(REQUEST_STREAM_BUFFER_SIZE)
                request_stream_reader = self._request_streams[request_id][1]
                headers = {'Cache-Control': 'no-cache, no-transform', 'Connection': 'keep-alive', 'Content-Type': CONTENT_TYPE_SSE, **({MCP_SESSION_ID_HEADER: self.mcp_session_id} if self.mcp_session_id else {})}
                response = EventSourceResponse(content=sse_stream_reader, data_sender_callable=partial(self._run_sse_writer, request_id, sse_stream_writer, request_stream_reader, priming_event), headers=headers)
                try:
                    async with anyio.create_task_group() as tg:
                        tg.start_soon(response, scope, receive, send)
                        session_message = self._create_session_message(message, request, request_id, protocol_version)
                        await writer.send(session_message)
                except Exception as _adapter_error:
                    self._owned.fault(_adapter_error)
                    logger.exception('SSE response error')
                    await sse_stream_writer.aclose()
                    await self._clean_up_memory_streams(request_id)
                finally:
                    await sse_stream_reader.aclose()
        except Exception as err:
            self._owned.fault(err)
            logger.exception('Error handling POST request')
            response = self._create_error_response('Error handling POST request', HTTPStatus.INTERNAL_SERVER_ERROR, INTERNAL_ERROR)
            await response(scope, receive, send)
            await writer.send(Exception(err))
            return

    async def _handle_get_request(self, request: Request, send: Send) -> None:
        """Handle GET request to establish SSE.

            This allows the server to communicate to the client without the client
            first sending data via HTTP POST. The server can send JSON-RPC requests
            and notifications on this stream.
            """
        writer = self._read_stream_writer
        if writer is None:
            raise ValueError('No read stream writer available. Ensure connect() is called first.')
        _, has_sse = check_accept_headers(request)
        if not has_sse:
            response = self._create_error_response('Not Acceptable: Client must accept text/event-stream', HTTPStatus.NOT_ACCEPTABLE)
            await response(request.scope, request.receive, send)
            return
        if not await self._validate_request_headers(request, send):
            return
        if (last_event_id := request.headers.get(LAST_EVENT_ID_HEADER)):
            await self._replay_events(last_event_id, request, send)
            return
        headers = {'Cache-Control': 'no-cache, no-transform', 'Connection': 'keep-alive', 'Content-Type': CONTENT_TYPE_SSE}
        if self.mcp_session_id:
            headers[MCP_SESSION_ID_HEADER] = self.mcp_session_id
        if GET_STREAM_KEY in self._request_streams:
            response = self._create_error_response('Conflict: Only one SSE stream is allowed per session', HTTPStatus.CONFLICT)
            await response(request.scope, request.receive, send)
            return
        sse_stream_writer, sse_stream_reader = self._owned.memory(0)

        async def standalone_sse_writer():
            try:
                self._request_streams[GET_STREAM_KEY] = self._owned.memory(REQUEST_STREAM_BUFFER_SIZE)
                standalone_stream_reader = self._request_streams[GET_STREAM_KEY][1]
                async with sse_stream_writer, standalone_stream_reader:
                    async for event_message in standalone_stream_reader:
                        event_data = self._create_event_data(event_message)
                        await sse_stream_writer.send(event_data)
            except anyio.ClosedResourceError:
                pass
            except Exception as _adapter_error:
                self._owned.fault(_adapter_error)
                logger.exception('Error in standalone SSE writer')
            finally:
                logger.debug('Closing standalone SSE writer')
                await self._clean_up_memory_streams(GET_STREAM_KEY)
        response = EventSourceResponse(content=sse_stream_reader, data_sender_callable=standalone_sse_writer, headers=headers)
        try:
            await response(request.scope, request.receive, send)
        except Exception as _adapter_error:
            self._owned.fault(_adapter_error)
            logger.exception('Error in standalone SSE response')
            await self._clean_up_memory_streams(GET_STREAM_KEY)
        finally:
            await sse_stream_writer.aclose()
            await sse_stream_reader.aclose()

    async def terminate(self) -> None:
        """Terminate the current session, closing all streams.

            Once terminated, all requests with this session ID will receive 404 Not Found.
            """
        self._owned.closing = True
        self._terminated = True
        logger.info(f'Terminating session: {self.mcp_session_id}')
        request_stream_keys = list(self._request_streams.keys())
        for key in request_stream_keys:
            await self._clean_up_memory_streams(key)
        self._request_streams.clear()
        try:
            if self._read_stream_writer is not None:
                await self._read_stream_writer.aclose()
            if self._read_stream is not None:
                await self._read_stream.aclose()
            if self._write_stream_reader is not None:
                await self._write_stream_reader.aclose()
            if self._write_stream is not None:
                await self._write_stream.aclose()
        except Exception as e:
            self._owned.fault(e)
            logger.debug(f'Error closing streams: {e}')
        await self._owned.close_all()

    @asynccontextmanager
    async def connect(self) -> AsyncGenerator[tuple[ReadStream[SessionMessage | Exception], WriteStream[SessionMessage]], None]:
        primary = None
        try:
            'Context manager that provides read and write streams for a connection.\n\n            Yields:\n                Tuple of (read_stream, write_stream) for bidirectional communication\n            '
            read_stream_writer, read_stream = self._owned.context(0)
            write_stream, write_stream_reader = self._owned.context(0)
            self._read_stream_writer = read_stream_writer
            self._read_stream = read_stream
            self._write_stream_reader = write_stream_reader
            self._write_stream = write_stream
            async with anyio.create_task_group() as tg:

                async def message_router():
                    try:
                        async for session_message in write_stream_reader:
                            message = session_message.message
                            target_request_id = None
                            if isinstance(message, JSONRPCResponse | JSONRPCError) and message.id is not None:
                                target_request_id = str(message.id)
                            elif session_message.metadata is not None and isinstance(session_message.metadata, ServerMessageMetadata) and (session_message.metadata.related_request_id is not None):
                                related_request_id = session_message.metadata.related_request_id
                                if self.is_json_response_enabled:
                                    logger.debug(f'Dropped message related to request {related_request_id} in JSON mode')
                                    continue
                                target_request_id = str(related_request_id)
                            request_stream_id = target_request_id if target_request_id is not None else GET_STREAM_KEY
                            event_id = None
                            if self._event_store:
                                event_id = await self._event_store.store_event(request_stream_id, message)
                                logger.debug(f'Stored {event_id} from {request_stream_id}')
                            if request_stream_id in self._request_streams:
                                try:
                                    await self._request_streams[request_stream_id][0].send(EventMessage(message, event_id))
                                except (anyio.BrokenResourceError, anyio.ClosedResourceError):
                                    self._request_streams.pop(request_stream_id, None)
                            else:
                                logger.debug(f'Request stream {request_stream_id} not found\n                                for message. Still processing message as the client\n                                might reconnect and replay.')
                    except anyio.ClosedResourceError:
                        if self._terminated:
                            logger.debug('Read stream closed by client')
                        else:
                            self._owned.fault(RuntimeError('sdk_router_unexpected_closure'))
                            logger.exception('Unexpected closure of read stream in message router')
                    except Exception as _adapter_error:
                        self._owned.fault(_adapter_error)
                        logger.exception('Error in message router')
                tg.start_soon(message_router)
                try:
                    yield (read_stream, write_stream)
                finally:
                    for stream_id in list(self._request_streams.keys()):
                        await self._clean_up_memory_streams(stream_id)
                    self._request_streams.clear()
                    try:
                        await read_stream_writer.aclose()
                        await read_stream.aclose()
                        await write_stream_reader.aclose()
                        await write_stream.aclose()
                    except Exception as e:
                        self._owned.fault(e)
                        logger.debug(f'Error closing streams: {e}')
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                await self._owned.close_all()
            except BaseException:
                if primary is not None:
                    primary.add_note('sdk_transport_close_failed')
                    raise primary
                raise

class _TrackedManager(_BaseManager):
    def __init__(self, *args, **kwargs):
        from pathlib import Path
        from velociraptor_observation_sdk import _verify_installed, PIN_PATH
        _verify_installed((Path(__file__).parent / PIN_PATH).read_bytes(), Path.read_bytes)
        super().__init__(*args, **kwargs)
        self._owned_transports = {}
        self._controller = None

    async def _handle_stateful_request(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Process request in stateful mode - maintaining session state between requests."""
        request = Request(scope, receive)
        request_mcp_session_id = request.headers.get(MCP_SESSION_ID_HEADER)
        user = scope.get('user')
        requestor = authorization_context(user) if isinstance(user, AuthenticatedUser) else None
        if request_mcp_session_id is not None and request_mcp_session_id in self._server_instances:
            transport = self._server_instances[request_mcp_session_id]
            if requestor != self._session_owners.get(request_mcp_session_id):
                logger.warning('Rejecting request for session %s: credential does not match the one that created the session', request_mcp_session_id[:64])
                body = JSONRPCError(jsonrpc='2.0', id=None, error=ErrorData(code=INVALID_REQUEST, message='Session not found'))
                response = Response(body.model_dump_json(by_alias=True, exclude_unset=True), status_code=404, media_type='application/json')
                await response(scope, receive, send)
                return
            logger.debug('Session already exists, handling request directly')
            if transport.idle_scope is not None and self.session_idle_timeout is not None:
                transport.idle_scope.deadline = anyio.current_time() + self.session_idle_timeout
            await transport.handle_request(scope, receive, send)
            return
        if request_mcp_session_id is None:
            logger.debug('Creating new transport')
            async with self._session_creation_lock:
                new_session_id = uuid4().hex
                http_transport = _TrackedTransport(mcp_session_id=new_session_id, is_json_response_enabled=self.json_response, event_store=self.event_store, security_settings=self.security_settings, retry_interval=self.retry_interval, resources=_Resources())
                if self._controller is not None:
                    http_transport._owned.controller = self._controller
                    http_transport._owned.session = new_session_id
                    self._controller._creating(new_session_id, scope, http_transport)
                self._owned_transports[new_session_id] = http_transport
                assert http_transport.mcp_session_id is not None
                if requestor is not None:
                    self._session_owners[http_transport.mcp_session_id] = requestor
                self._server_instances[http_transport.mcp_session_id] = http_transport
                logger.info(f'Created new transport with session ID: {new_session_id}')

                async def run_server(*, task_status: TaskStatus[None]=anyio.TASK_STATUS_IGNORED) -> None:
                    try:
                        async with http_transport.connect() as streams:
                            read_stream, write_stream = streams
                            task_status.started()
                            try:
                                idle_scope = anyio.CancelScope()
                                if self.session_idle_timeout is not None:
                                    idle_scope.deadline = anyio.current_time() + self.session_idle_timeout
                                    http_transport.idle_scope = idle_scope
                                with idle_scope:
                                    await _serve_loop(self.app, read_stream, write_stream, lifespan_state=self._lifespan_state, session_id=http_transport.mcp_session_id, resources=http_transport._owned)
                                if idle_scope.cancelled_caught:
                                    assert http_transport.mcp_session_id is not None
                                    logger.info(f'Session {http_transport.mcp_session_id} idle timeout')
                                    self._server_instances.pop(http_transport.mcp_session_id, None)
                                    self._session_owners.pop(http_transport.mcp_session_id, None)
                                    await http_transport.terminate()
                            except Exception:
                                logger.exception(f'Session {http_transport.mcp_session_id} crashed')
                            finally:
                                if http_transport.mcp_session_id and http_transport.mcp_session_id in self._server_instances and (not http_transport.is_terminated):
                                    logger.info(f'Cleaning up crashed session {http_transport.mcp_session_id} from active instances.')
                                    del self._server_instances[http_transport.mcp_session_id]
                                    self._session_owners.pop(http_transport.mcp_session_id, None)
                    except BaseException as _runner_error:
                        http_transport._owned.fault(_runner_error)
                        raise
                    finally:
                        http_transport._owned.runner_exited = True
                assert self._task_group is not None
                await self._task_group.start(run_server)
                await http_transport.handle_request(scope, receive, send)
        else:
            logger.info(f'Rejected request with unknown or expired session ID: {request_mcp_session_id[:64]}')
            body = JSONRPCError(jsonrpc='2.0', id=None, error=ErrorData(code=INVALID_REQUEST, message='Session not found'))
            response = Response(body.model_dump_json(by_alias=True, exclude_unset=True), status_code=404, media_type='application/json')
            await response(scope, receive, send)
