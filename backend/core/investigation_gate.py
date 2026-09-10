"""RC5 (Output-Trust) — per-run investigate entry gates.

Two preconditions decided ONCE at investigate entry and enforced at the single
module-execution point (``_phase_runner.run_one_module``):

* **Domain resolvability** — if the email's domain does not resolve, the mailbox
  cannot exist. Running the username/account ENUMERATORS on the localpart then
  fabricates a fake identity from hundreds of soft hits (the ``user@nonexistent``
  → 318-accounts pathology). Skip them and let the run return an honest empty
  result instead.
* **Role / system address** — ``noreply@`` / ``info@`` / ``admin@`` are not
  people, so personal-identity enumeration and personal-threat findings are
  meaningless for them.

Task-local (a ``contextvar``) so concurrent investigations never cross-contaminate.
"""
from __future__ import annotations

import contextvars
from dataclasses import dataclass

# The modules that enumerate a PERSONAL identity from the email localpart. These
# are the ones gated off for a non-resolving domain or a role/system address.
PERSONAL_ENUMERATION_MODULES: frozenset[str] = frozenset(
    {
        "username_platforms",
        "username_pivot",
        "account_discovery",
        "messaging_hints",
    }
)


@dataclass(frozen=True)
class TargetGate:
    domain_resolves: bool = True
    is_role_system: bool = False


_GATE: contextvars.ContextVar[TargetGate] = contextvars.ContextVar(
    "investigation_target_gate", default=TargetGate()
)


def set_target_gate(*, domain_resolves: bool, is_role_system: bool) -> contextvars.Token:
    return _GATE.set(
        TargetGate(domain_resolves=domain_resolves, is_role_system=is_role_system)
    )


def reset_target_gate(token: contextvars.Token) -> None:
    try:
        _GATE.reset(token)
    except (ValueError, LookupError):
        pass


def current_gate() -> TargetGate:
    return _GATE.get()


def enumeration_blocked(module_name: str) -> tuple[bool, str | None]:
    """Return (blocked, reason) for *module_name* under the current gate."""
    if module_name not in PERSONAL_ENUMERATION_MODULES:
        return (False, None)
    gate = _GATE.get()
    if not gate.domain_resolves:
        return (True, "domain_does_not_resolve")
    if gate.is_role_system:
        return (True, "role_or_system_address")
    return (False, None)
