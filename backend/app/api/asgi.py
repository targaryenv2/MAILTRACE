"""FastAPI mount, used when FastAPI happens to be installed.

There is no second implementation of anything here. Every request is converted
into the same :class:`app.api.routes.Request` and handed to the same
:func:`~app.api.routes.dispatch`, so FastAPI buys three things and changes no
behaviour: an ASGI app that ``uvicorn --reload`` can hot-reload during
development, HTTP/2 and proper concurrency if someone puts this behind a real
server, and a Swagger page.

The catch-all route is registered deliberately rather than declaring each
endpoint twice. Declaring them twice would give FastAPI a typed schema and give
the project two route tables that drift the first time one is edited; that trade
is not worth a nicer ``/docs`` page. ``GET /api/routes`` is the route index for
both servers.

Import this module only through :func:`create_app`, which raises a clear error
when FastAPI is absent instead of failing at import time.
"""

from __future__ import annotations

from typing import Any

from .routes import Request, dispatch


def create_app() -> Any:
    """Build the ASGI application. Raises ``RuntimeError`` if FastAPI is missing."""
    try:
        from fastapi import FastAPI  # type: ignore[import-not-found]
        # type: ignore[import-not-found]
        from fastapi.responses import Response as FastResponse
        # type: ignore[import-not-found]
        from fastapi.responses import StreamingResponse
        # type: ignore[import-not-found]
        from fastapi.middleware.cors import CORSMiddleware
        # type: ignore[import-not-found]
        from starlette.requests import ClientDisconnect
    except ImportError as exc:  # pragma: no cover - exercised only without fastapi
        raise RuntimeError(
            "FastAPI is not installed. The standard-library server serves the same "
            "API: python mailtrace.py serve") from exc

    import asyncio
    import queue as _queue

    from ..config import get_settings
    from .events import get_bus, sse_frame
    from .server import DIST_DIR, SSE_HEARTBEAT_SECONDS, _security_headers

    st = get_settings()
    app = FastAPI(
        title="MailTrace",
        version="1.0.0",
        description="Email threat detection, geolocation and forensic "
        "intelligence. Route index: GET /api/routes")
    app.add_middleware(
        CORSMiddleware, allow_origins=st.cors_origin_list(), allow_methods=[
            "GET", "POST", "PATCH", "OPTIONS"], allow_headers=[
            "Content-Type", "X-Analyst", "X-Filename"])

    @app.get("/api/events")
    async def events(since: int = 0) -> Any:  # noqa: ANN401
        """Stream investigation steps as Server-Sent Events."""
        bus = get_bus()

        async def gen() -> Any:  # noqa: ANN401
            q = bus.subscribe()
            try:
                for event in bus.since(since)["events"]:
                    yield sse_frame(event)
                yield b": connected\n\n"
                while True:
                    try:
                        # The bus is a threading queue, so the wait has to happen off
                        # the event loop or a single subscriber would block every
                        # other request on this worker.
                        event = await asyncio.get_running_loop().run_in_executor(
                            None, lambda: q.get(timeout=SSE_HEARTBEAT_SECONDS))
                        yield sse_frame(event)
                    except _queue.Empty:
                        yield b": keep-alive\n\n"
            except (asyncio.CancelledError, ClientDisconnect):
                pass
            finally:
                bus.unsubscribe(q)

        return StreamingResponse(
            gen(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "X-Accel-Buffering": "no"})

    @app.api_route("/api/{path:path}",
                   methods=["GET", "POST", "PATCH", "OPTIONS", "HEAD"])
    async def api(path: str, request: Any) -> Any:  # noqa: ANN401
        """Dispatch to the shared routing table."""
        body = await request.body()
        req = Request(
            method=request.method,
            path=(
                "/api/" +
                path).rstrip("/") or "/api",
            query=dict(
                request.query_params),
            body=body,
            headers={
                k.lower(): v for k,
                v in request.headers.items()})
        resp = dispatch(req)
        headers = dict(_security_headers())
        headers.update(resp.headers)
        return FastResponse(content=resp.body, status_code=resp.status,
                            media_type=resp.content_type, headers=headers)

    if DIST_DIR.is_dir():
        # type: ignore[import-not-found]
        from fastapi.staticfiles import StaticFiles
        # html=True gives the SPA fallback; mounting last means /api never
        # reaches the static handler.
        app.mount(
            "/",
            StaticFiles(
                directory=str(DIST_DIR),
                html=True),
            name="console")

    return app
