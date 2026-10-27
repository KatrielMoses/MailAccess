"""Local-only mode: skip unsolicited vendor calls.

Investigations and harvests still talk to the OSINT sources the operator
chose. What this gate stops is product-network chatter that is not part of
the lookup itself: the free-tier coverage teaser (sends the harvested
domain), the founder-seat counter, the CLI sponsor feed, and the PyPI
update check.

A configured Pro key still reaches ``/v1/enrich`` — that call is opt-in.
``mailaccess pro`` still prints the pitch; live seat counts are omitted.
"""

from __future__ import annotations

import os
from typing import Final

ENV_VAR: Final = "MAILACCESS_LOCAL_ONLY"
_TRUE: Final = frozenset({"1", "true", "yes", "on"})


def env_flag() -> bool:
    return os.environ.get(ENV_VAR, "").strip().lower() in _TRUE


def is_enabled() -> bool:
    if env_flag():
        return True
    try:
        from backend.config import settings

        return bool(getattr(settings, "mailaccess_local_only", False))
    except Exception:
        return False


def pro_key_set() -> bool:
    try:
        from backend.config import settings

        return bool((getattr(settings, "mailaccess_pro_key", "") or "").strip())
    except Exception:
        return False


def pro_notice(target: str) -> str | None:
    """The line to print before keyed Pro enrichment sends ``target`` in local-only mode.

    Local-only stops the calls MailAccess makes on its own; a Pro key is an explicit
    opt-in, so its enrichment still runs, but the user is told first. ``None`` when
    local-only is off or no Pro key is set.
    """
    if not (is_enabled() and pro_key_set()):
        return None
    return (
        f"Local-only mode is on, but your Pro key is set: this run sends {target} to "
        "MailAccess Pro (mailaccess.pro) to add business contacts. To keep everything "
        "local, run `mailaccess keys unset MAILACCESS_PRO_KEY`."
    )


def activate() -> None:
    """Turn local-only on for this process (``--local-only`` / CLI enable)."""
    os.environ[ENV_VAR] = "1"
    try:
        from backend.config import settings

        settings.mailaccess_local_only = True
    except Exception:
        pass
