"""The dependency-free HTTP server.

This is the path that always works: :mod:`http.server` from the standard library,
threaded, serving the routing table in :mod:`app.api.routes` plus the built
frontend if one exists. No pip install, no uvicorn, no wheels to download on a
machine behind a proxy. ``python mailtrace.py serve`` uses it, and so does the
test suite's end-to-end run.

Three things here are more than boilerplate.

*Server-Sent Events, not WebSockets.* The live investigation feed is one-way -
the server narrates, the browser listens - and SSE is a plain HTTP response, so
it works through :mod:`http.server` without a protocol upgrade, reconnects on its
own, and degrades to ``GET /api/events/since`` polling when a proxy buffers it.
A WebSocket would need a framework or a hand-rolled frame codec to carry no extra
information.

*SPA fallback with an explicit boundary.* Unknown paths under ``/`` return
``index.html`` so client-side routing works on a hard refresh, but unknown paths
under ``/api/`` return JSON 404s. Serving HTML to a fetch() call is how a
frontend ends up reporting "unexpected token <" instead of "not found".

*Static serving is confined.* Every resolved path is checked against the dist
root before it is opened, so ``GET /../../.env`` cannot walk out of it. That check
is not theoretical: this server binds a socket on a machine that also holds the
API keys.
"""

from __future__ import annotations

import json
import logging
import mimetypes
import queue
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from ..config import REPO_ROOT, get_settings
from .events import get_bus, sse_frame
from .routes import Request, Response, dispatch

log = logging.getLogger(__name__)

DIST_DIR = REPO_ROOT / "frontend" / "dist"
SSE_PATH = "/api/events"
# How long a streaming connection waits for the next event before emitting a
# comment frame. Without it an idle stream looks dead to an intermediate proxy
# and gets closed; 15s is well inside the usual 60s idle timeout.
SSE_HEARTBEAT_SECONDS = 15.0

_PLACEHOLDER = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MailTrace API</title>
<style>
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#080a12;
color:#e8ecf8;font:15px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:44rem;padding:2.5rem}
h1{font-size:1.6rem;margin:0 0 .25rem;letter-spacing:-.02em}
p{color:#9aa4bf;margin:.4rem 0 1.2rem}
code{background:#141a2b;border:1px solid #222b45;border-radius:6px;padding:.15em .45em;
font:13px ui-monospace,SFMono-Regular,Menlo,monospace;color:#c8d2ee}
a{color:#7aa2ff}
ul{padding-left:1.1rem;color:#9aa4bf}
</style></head><body><main>
<h1>MailTrace Backend API is running</h1>
<p>The backend API server is active on port 8000.</p>
<ul>
<li>Frontend UI is running independently at <a href="http://localhost:5173" target="_blank">http://localhost:5173</a>.</li>
<li>API Health: <a href="/api/health">/api/health</a></li>
<li>API Routes: <a href="/api/routes">/api/routes</a></li>
<li>API Stats: <a href="/api/stats">/api/stats</a></li>
<li>Cases: <a href="/api/cases">/api/cases</a></li>
</ul>
</main></body></html>
"""


def _security_headers() -> Dict[str, str]:
    """Headers applied to every response.

    The CSP is strict because this console renders attacker-supplied strings -
    subjects, sender names, URLs pulled out of hostile mail. ``'unsafe-inline'``
    is permitted for styles only: the built frontend injects a style element, and
    style injection cannot execute. Scripts stay same-origin with no inline
    allowance, so an injected ``<script>`` in a rendered subject is inert.
    """
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https://*.tile.openstreetmap.org; connect-src 'self'; "
            "font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
        ),
    }


def _cors_headers(origin: str) -> Dict[str, str]:
    allowed = get_settings().cors_origin_list()
    if not origin:
        return {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-Analyst, X-Filename",
        }
    if "*" in allowed:
        value = origin
    elif origin in allowed:
        value = origin
    else:
        value = "*"
    return {
        "Access-Control-Allow-Origin": value,
        "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-Analyst, X-Filename",
        "Access-Control-Max-Age": "600",
        "Vary": "Origin",
    }


def _static_target(path: str) -> Optional[Tuple[Path, str]]:
    """Do not serve frontend static dist on the backend API server."""
    return None


class Handler(BaseHTTPRequestHandler):
    server_version = "MailTrace/1.0"
    protocol_version = "HTTP/1.1"

    # -- plumbing ----------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        log.info("%s %s", self.address_string(), fmt % args)

    def _headers(self) -> Dict[str, str]:
        return {k.lower(): v for k, v in self.headers.items()}

    def _send(self, resp: Response) -> None:
        body = resp.body
        self.send_response(resp.status)
        self.send_header("Content-Type", resp.content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in list(_security_headers().items()
                               ) + list(resp.headers.items()):
            self.send_header(key, value)
        for key, value in _cors_headers(
            self._headers().get(
                "origin", "")).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # client navigated away mid-response; nothing to recover

    def _request(self) -> Request:
        parts = urlparse(self.path)
        length = int(self._headers().get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        query = {
            k: v[0] for k,
            v in parse_qs(
                parts.query,
                keep_blank_values=True).items()}
        # HEAD is routed as GET. The routing table has no HEAD entries and should
        # not need any: RFC 9110 defines HEAD as GET without the body, and the
        # body is suppressed in _send. Dispatching HEAD literally returned 405 for
        # every endpoint, which broke health checks that probe with HEAD.
        method = "GET" if self.command == "HEAD" else self.command
        return Request(method=method, path=parts.path.rstrip("/") or "/",
                       query=query, body=body, headers=self._headers())

    # -- verbs -------------------------------------------------------------
    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send(Response(status=204, body=b"", content_type="text/plain"))

    def do_GET(self) -> None:  # noqa: N802
        parts = urlparse(self.path)
        path = parts.path.rstrip("/") or "/"
        if path == SSE_PATH:
            self._stream(parse_qs(parts.query))
            return
        if path.startswith("/api/"):
            self._send(dispatch(self._request()))
            return
        self._send(Response(status=200, body=_PLACEHOLDER.encode("utf-8"),
                            content_type="text/html; charset=utf-8"))


    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        self._send(dispatch(self._request()))

    def do_PATCH(self) -> None:  # noqa: N802
        self._send(dispatch(self._request()))

    # -- streaming ---------------------------------------------------------
    def _stream(self, query: Dict[str, Any]) -> None:
        """Stream events until the client disconnects.

        The subscription is taken *before* the backlog is replayed, so an event
        published between the replay and the first read is queued rather than
        lost. That ordering is the whole correctness argument for this endpoint.
        """
        bus = get_bus()
        q = bus.subscribe()
        last_id = self._headers().get(
            "last-event-id") or (query.get("since") or ["0"])[0]
        try:
            since = int(last_id)
        except (TypeError, ValueError):
            since = 0
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "keep-alive")
        # nginx: do not buffer the stream
        self.send_header("X-Accel-Buffering", "no")
        for key, value in _security_headers().items():
            self.send_header(key, value)
        for key, value in _cors_headers(
            self._headers().get(
                "origin", "")).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            for event in bus.since(since)["events"]:
                self.wfile.write(sse_frame(event))
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while True:
                try:
                    event = q.get(timeout=SSE_HEARTBEAT_SECONDS)
                    self.wfile.write(sse_frame(event))
                except queue.Empty:
                    self.wfile.write(b": keep-alive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # the browser closed the tab; the only correct action is to stop
        finally:
            bus.unsubscribe(q)
            self.close_connection = True


class ApiServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def build_server(host: Optional[str] = None,
                 port: Optional[int] = None) -> ApiServer:
    st = get_settings()
    st.ensure_dirs()
    return ApiServer(
        (host or st.host, int(
            port if port is not None else st.port)), Handler)


def serve(host: Optional[str] = None, port: Optional[int] = None,
          announce: bool = True) -> None:
    """Run the API in the foreground until interrupted."""
    server = build_server(host, port)
    bound_host, bound_port = server.server_address[0], server.server_address[1]
    if announce:
        st = get_settings()
        caps = st.capability_report()
        print("MailTrace API  http://%s:%s" % (bound_host, bound_port))
        print("  console      %s" % ("bundled build at /" if DIST_DIR.is_dir()
                                     else "not built (npm run build in frontend/)"))
        print("  demo mode    %s   network %s" %
              (caps["demo_mode"], caps["network"]))
        print(
            "  live streams %s" %
            (bound_host +
             ":%s" %
             bound_port +
             SSE_PATH))
        print("Ctrl+C to stop.")
    try:
        server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        print("\nstopping...")
    finally:
        server.shutdown()
        server.server_close()


class BackgroundServer:
    """Run the API on a spare port in a thread. Used by the end-to-end tests.

    A context manager rather than a fixture so the same helper works from a test,
    a script or an interactive session, and so the socket is always closed even
    when an assertion fails midway.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._server = build_server(host, port)
        self.host, self.port = self._server.server_address[0], self._server.server_address[1]
        self.base = "http://%s:%d" % (self.host, self.port)
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={
                "poll_interval": 0.05}, daemon=True)

    def __enter__(self) -> "BackgroundServer":
        self._thread.start()
        deadline = threading.Event()
        for _ in range(
                100):  # up to ~2s; the listener is normally up immediately
            try:
                with socket.create_connection((self.host, self.port), timeout=0.2):
                    return self
            except OSError:
                deadline.wait(0.02)
        raise RuntimeError("API server did not start on %s" % self.base)

    def __exit__(self, *exc: Any) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=3)


def main(argv: Optional[list] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run the MailTrace API")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument(
        "--routes",
        action="store_true",
        help="print the route table and exit")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s")
    if args.routes:
        print(
            json.dumps(
                json.loads(
                    dispatch(
                        Request(
                            method="GET",
                            path="/api/routes")).body.decode()),
                indent=2))
        return 0
    serve(args.host, args.port)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
