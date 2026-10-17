from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from ...core.capabilities import provider_capabilities, provider_module_enabled
from ...modules import get_all_modules

router = APIRouter()


class ModuleInfo(BaseModel):
    name: str
    description: str
    requires_key: bool


@router.get("/", response_model=list[ModuleInfo])
async def list_modules() -> list[ModuleInfo]:
    return [
        ModuleInfo(
            name=m.name,
            description=m.description,
            requires_key=m.requires_key,
        )
        for m in get_all_modules()
        if provider_module_enabled(m.name)  # a provider that is off appears nowhere
    ]


capabilities_router = APIRouter()


@capabilities_router.get("/capabilities")
async def capabilities() -> dict:
    """Which paid providers this engine can use. Booleans only: no key material."""
    return {"providers": provider_capabilities()}
