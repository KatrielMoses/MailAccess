from fastapi import APIRouter

from .routes.graph import router as graph_router
from .routes.investigations import router as investigations_router
from .routes.leads import router as leads_router
from .routes.modules import router as modules_router
from .websocket import router as ws_router

api_router = APIRouter()
api_router.include_router(investigations_router, tags=["investigations"])
api_router.include_router(graph_router, tags=["graph"])
api_router.include_router(modules_router, prefix="/modules", tags=["modules"])
api_router.include_router(leads_router, tags=["leads"])

__all__ = ["api_router", "ws_router"]
