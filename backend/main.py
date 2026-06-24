from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from rich.console import Console

from .api.router import api_router, ws_router
from .api.middleware.auth import APIKeyMiddleware, RequestIDMiddleware, request_id_contextvar
from .api.routes.health import router as health_router
from .api.routes.maltego import router as maltego_router
from .config import APP_VERSION, settings
from .db.database import init_db
from .integrations.maltego_transform import generate_mtz_bundle

_MTZ_PATH = Path(__file__).parent.parent / "maltego" / "MailAccess.mtz"
_startup_console = Console()

logger = logging.getLogger("mailaccess.http")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(levelname)s [%(request_id)s] %(name)s: %(message)s",
    )
    old_factory = logging.getLogRecordFactory()

    def record_factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        record.request_id = request_id_contextvar.get()
        return record

    logging.setLogRecordFactory(record_factory)

    _startup_console.print(
        f"[dim]Config loaded — CORS: {len(settings.cors_origins)} origins, "
        f"{len(settings.module_timeout_overrides)} timeout overrides[/dim]"
    )

    await init_db()
    generate_mtz_bundle(_MTZ_PATH)
    async def _warm_breach_corpus() -> None:
        try:
            from .core.breach_corpus import BreachCorpus

            await asyncio.to_thread(BreachCorpus().load)
        except Exception as exc:
            logging.getLogger("mailaccess.startup").debug(
                "breach corpus warmup skipped: %s", exc
            )

    asyncio.create_task(_warm_breach_corpus())
    _slog = logging.getLogger("mailaccess.startup")
    if settings.module_timeout_overrides:
        _slog.info(
            "MODULE_TIMEOUT_OVERRIDES applied: %s",
            {k: f"{v}s" for k, v in settings.module_timeout_overrides.items()},
        )
    yield


app = FastAPI(
    title="MailAccess",
    description="OSINT email intelligence API",
    version=APP_VERSION,
    lifespan=lifespan,
    debug=settings.debug,
)

app.add_middleware(APIKeyMiddleware)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    ms = (time.perf_counter() - start) * 1000
    logger.info("%s %s → %d (%.1f ms)", request.method, request.url.path, response.status_code, ms)
    return response


@app.exception_handler(Exception)
async def global_error_handler(request: Request, exc: Exception):
    if isinstance(exc, HTTPException):
        return await http_exception_handler(request, exc)
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": type(exc).__name__, "detail": str(exc)},
    )


# REST endpoints under /api; WebSocket at /ws/investigate/{id} (no prefix)
# Maltego TRX transform server at /maltego (no API key required)
app.include_router(health_router)
app.include_router(api_router, prefix="/api")
app.include_router(ws_router)
app.include_router(maltego_router, prefix="/maltego", tags=["maltego"])
