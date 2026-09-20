"""Admin CLI for the MailAccess Pro entitlement store (0.17.0 Phase 1).

Manual key population until Phase 5 wires Stripe webhooks. Keys are stored
hashed; the raw key is shown ONCE at generation time and never persisted.

    python -m scripts.pro_keys_admin generate --notes "acme corp, monthly"
    python -m scripts.pro_keys_admin add <raw-key> --notes "..."
    python -m scripts.pro_keys_admin list
    python -m scripts.pro_keys_admin deactivate <raw-key>

The generated key is a URL-safe random token; give it to the customer and set it
on their side as MAILACCESS_PRO_KEY. The store only ever keeps its SHA-256 hash.
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
import sys

from backend.core.pro_keys import (
    add_pro_key,
    deactivate_pro_key,
    list_pro_keys,
)


async def _generate(notes: str | None) -> int:
    raw = "map_" + secrets.token_urlsafe(32)
    created = await add_pro_key(raw, notes=notes)
    if not created:  # astronomically unlikely hash collision
        print("collision generating key; re-run", file=sys.stderr)
        return 1
    print("Pro key created. Give this to the customer — it is shown only once:\n")
    print(f"  {raw}\n")
    print("Store it on their side as MAILACCESS_PRO_KEY.")
    return 0


async def _add(raw: str, notes: str | None) -> int:
    created = await add_pro_key(raw, notes=notes)
    print("added" if created else "already present (unchanged)")
    return 0


async def _list() -> int:
    rows = await list_pro_keys()
    if not rows:
        print("(no Pro keys)")
        return 0
    for r in rows:
        state = "active" if r["active"] else "inactive"
        print(f"{r['key_hash_prefix']}…  {state:8}  {r['created_at']}  {r['notes'] or ''}")
    return 0


async def _deactivate(raw: str) -> int:
    changed = await deactivate_pro_key(raw)
    print("deactivated" if changed else "no matching active key")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="generate a new random Pro key")
    g.add_argument("--notes", default=None)

    a = sub.add_parser("add", help="add a specific raw key (stored hashed)")
    a.add_argument("key")
    a.add_argument("--notes", default=None)

    sub.add_parser("list", help="list entitlements (hash prefix + status)")

    d = sub.add_parser("deactivate", help="revoke a key")
    d.add_argument("key")

    args = parser.parse_args(argv)
    if args.cmd == "generate":
        return asyncio.run(_generate(args.notes))
    if args.cmd == "add":
        return asyncio.run(_add(args.key, args.notes))
    if args.cmd == "list":
        return asyncio.run(_list())
    if args.cmd == "deactivate":
        return asyncio.run(_deactivate(args.key))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
