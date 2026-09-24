"""HTTP layer. One routing table, two servers.

:mod:`app.api.routes` holds the endpoints as plain functions.
:mod:`app.api.server` serves them with the standard library, which always works.
:mod:`app.api.asgi` mounts the same table under FastAPI when it is installed.

Prefer :func:`available_server` over importing either directly: it reports which
of the two this machine can actually run, which is what the CLI and the README
need to say out loud.
"""

from __future__ import annotations

from typing import Tuple

from .events import get_bus  # noqa: F401
from .routes import Request, Response, dispatch  # noqa: F401


def available_server() -> Tuple[str, str]:
    """Return ``(engine, reason)`` for the server this machine will use."""
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
    except ImportError:
        return (
            "stdlib",
            "fastapi/uvicorn not installed; using http.server, which "
            "serves the identical API")
    return ("fastapi", "fastapi and uvicorn are installed")


def serve(host: str = "", port: int = 0, prefer: str = "auto") -> None:
    """Start the API. ``prefer`` is ``auto``, ``stdlib`` or ``fastapi``."""
    engine = available_server()[0] if prefer == "auto" else prefer
    if engine == "fastapi":
        import uvicorn  # type: ignore[import-not-found]

        from ..config import get_settings
        from .asgi import create_app
        st = get_settings()
        uvicorn.run(create_app(), host=host or st.host,
                    port=int(port or st.port), log_level="info")
        return
    from .server import serve as stdlib_serve
    stdlib_serve(host or None, port or None)
