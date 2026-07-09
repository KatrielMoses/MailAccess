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
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable]
    ):
        path = request.url.path
        
        # Bypass authentication for /health, websocket, and Maltego transform routes
        if path.startswith("/health") or path.startswith("/ws/") or path.startswith("/maltego/"):
            return await call_next(request)

        # If API key is not configured, bypass authentication entirely
        if not settings.mailaccess_api_key:
            return await call_next(request)

        # For /api/ routes, enforce the API key header
        if path.startswith("/api/"):
            api_key = request.headers.get("X-API-Key")
            if not api_key or api_key != settings.mailaccess_api_key:
                return JSONResponse(
                    status_code=401,
                    content={"error": "unauthorized"}
                )

        return await call_next(request)
