from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import get_db
from backend.modules import get_all_modules

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

    modules_loaded = [mod.name for mod in get_all_modules()]

    return {
        "status": "ok",
        "version": "0.6.0",
        "modules_loaded": modules_loaded,
        "db": db_status
    }
