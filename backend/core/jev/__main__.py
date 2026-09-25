"""Smoke-test the seam against the configured endpoint (the demo task only).

    JEV_ENABLED=true JEV_API_KEY=... JEV_BASE_URL=... JEV_MODEL=... \
        python -m backend.core.jev "Ada Lovelace" "acme-support"
"""

from __future__ import annotations

import asyncio
import json
import sys

from . import metrics
from .tasks.demo import is_plausible_personal_name


async def _main(texts: list[str]) -> None:
    for text in texts:
        answer, source = await is_plausible_personal_name(text)
        print(f"{text!r}: is_personal_name={answer} (source={source})")
    print(json.dumps(metrics.snapshot(), indent=2))


if __name__ == "__main__":
    asyncio.run(_main(sys.argv[1:] or ["Ada Lovelace", "acme-support"]))
