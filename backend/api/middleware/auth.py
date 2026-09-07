import contextvars
import uuid
from collections.abc import Awaitable, Callable

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from backend.config import settings

request_id_contextvar = contextvars.ContextVar("request_id", default="-")


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable]
    ):
        req_id = str(uuid.uuid4())
        request_id_contextvar.set(req_id)
        
        response = await call_next(request)
        response.headers["X-Request-ID"] = req_id
        return response


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Phase 2F — safe-by-default authentication.

    * ``/health`` is always open (liveness).
    * With **no** API key configured, local (loopback) callers are allowed as a
      dev convenience, but non-local callers are **refused** — the open bypass
      never applies off-localhost.
    * With a key configured it is enforced on every protected surface, now
      **including** the Maltego transform route (previously bypassed). The
      WebSocket is authenticated in its own handler (middleware does not run for
      WS connections).
    """

    _PROTECTED_PREFIXES = ("/api/", "/maltego/")

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable]
    ):
        from ..security import is_local, key_ok

        path = request.url.path
        if path.startswith("/health"):
            return await call_next(request)

        if not settings.mailaccess_api_key:
            # Dev convenience for localhost only; remote access requires a key.
            if is_local(request):
                return await call_next(request)
            return JSONResponse(
                status_code=503,
                content={
                    "error": "authentication required",
                    "detail": "set MAILACCESS_API_KEY to expose MailAccess to non-local clients",
                },
            )

        if any(path.startswith(prefix) for prefix in self._PROTECTED_PREFIXES):
            if not key_ok(request):
                return JSONResponse(status_code=401, content={"error": "unauthorized"})

        return await call_next(request)
