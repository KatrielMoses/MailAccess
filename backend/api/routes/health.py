from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import APP_VERSION
from backend.db.database import get_db
from backend.modules import loaded_module_names

router = APIRouter()


@router.get("/health")
async def health_check(session: AsyncSession = Depends(get_db)):
    db_status = "error"
    try:
        # Simple query to check if the DB is reachable
        await session.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception:
        pass

    # T4 — readiness must not block on the ~3s module-discovery sweep (that would race
    # the CLI's /health poll timeout and spuriously exit 3 on a cold start). Report the
    # modules discovered so far WITHOUT forcing discovery; the first investigation warms
    # the registry within its own budget.
    modules_loaded = loaded_module_names()

    return {
        "status": "ok",
        "version": APP_VERSION,
        "modules_loaded": modules_loaded,
        "db": db_status
    }
