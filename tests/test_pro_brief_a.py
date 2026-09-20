"""0.17.0 Brief A — persistence isolation, resolver protection, export parity.

Acceptance tests (not repros) for P1 #1/#2/#8:

* A1 — hosted "MailAccess Pro" corpus leads are per-query, live-only and NEVER
  persisted: they ride in ``result.corpus_leads`` (a serving-only channel outside
  ``unique_emails``); ``sanitize_for_persistence`` clears the channel and scrubs any
  stray ``mailaccess_pro`` evidence, and ``write_back`` persists a native-only
  snapshot + contacts projection.
* A2 — a native row is never influenced by corpus evidence, and the person-field
  source weight for ``mailaccess_pro`` is a floor below every native source.
* A3 — the corpus-provenance export column appears only when a corpus lead is
  present (byte-identical to v0.16.0 otherwise; positive control here).

Network-free; SQLite writes use a temporary database.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import pytest

import backend.config as config_mod
from backend.core import corpus_store as C
from backend.core import domain_harvest_report as R
from backend.core.domain_harvest_orchestrator import (
    MODULE_MAILACCESS_PRO,
    DomainHarvestResult,
    HarvestedEmail,
    _inject_pro_leads,
    is_corpus_lead,
)
from backend.core.email_confidence import SOURCE_WEIGHTS
from backend.core.product_mode import ProductMode

PUBLIC = ProductMode.PUBLIC_BUSINESS_CONTACT
_KEY = "map_test_key"


def _native(email: str, **over: Any) -> HarvestedEmail:
    kw: dict[str, Any] = {
        "email": email,
        "on_domain": True,
        "is_role": False,
        "role_match_type": None,
        "confidence_score": 0.9,
        "confidence_label": "CONFIRMED",
        "found_by_modules": ["company_page"],
        "evidence": [{"module": "company_page", "metadata": {"full_name": "Real Native"}}],
    }
    kw.update(over)
    return HarvestedEmail(**kw)


def _result(
    rows: list[HarvestedEmail],
    corpus: list[HarvestedEmail] | None = None,
    mode: str = PUBLIC.value,
) -> DomainHarvestResult:
    now = datetime.now(timezone.utc).isoformat()
    non_role = sum(1 for e in rows if not e.is_role)
    return DomainHarvestResult(
        domain="acme.com",
        started_at=now,
        completed_at=now,
        duration_seconds=1.0,
        module_results={},
        unique_emails=rows,
        total_unique_emails=len(rows),
        high_confidence_count=sum(1 for e in rows if e.confidence_label == "CONFIRMED"),
        likely_confidence_count=0,
        medium_confidence_count=0,
        low_confidence_count=sum(1 for e in rows if e.confidence_label == "LOW"),
        role_account_count=sum(1 for e in rows if e.is_role),
        personal_email_count=non_role,
        corpus_leads=corpus or [],
        metadata={"mode": mode},
    )


def _mixed() -> tuple[list[HarvestedEmail], list[HarvestedEmail]]:
    """A native aggregate plus a serving-only channel of injected corpus leads."""
    rows = [_native("native@acme.com")]
    channel: list[HarvestedEmail] = []
    _inject_pro_leads(
        rows,
        [{"email": "corpus@acme.com", "name": "Corp Biz", "title": "CEO"}],
        mode=PUBLIC,
        key=_KEY,
        domain="acme.com",
        corpus_leads_out=channel,
    )
    return rows, channel


@pytest.fixture(autouse=True)
def _key_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod.settings, "mailaccess_pro_key", _KEY)


# ---------------------------------------------------------------------------
# A1 — corpus rides the serving-only channel, never the native aggregate.
# ---------------------------------------------------------------------------
def test_corpus_never_in_native_aggregate() -> None:
    rows, channel = _mixed()
    assert [e.email for e in rows] == ["native@acme.com"]
    assert [e.email for e in channel] == ["corpus@acme.com"]
    assert is_corpus_lead(channel[0])


def test_sanitize_clears_corpus_channel() -> None:
    rows, channel = _mixed()
    clean = C.sanitize_for_persistence(_result(rows, channel))
    assert [e.email for e in clean.unique_emails] == ["native@acme.com"]
    assert list(getattr(clean, "corpus_leads", []) or []) == []
    assert clean.total_unique_emails == 1


def test_sanitize_recomputes_counts() -> None:
    rows, channel = _mixed()
    clean = C.sanitize_for_persistence(_result(rows, channel))
    assert clean.high_confidence_count == 1
    assert clean.low_confidence_count == 0
    assert clean.personal_email_count == 1


def test_sanitize_does_not_mutate_input() -> None:
    rows, channel = _mixed()
    src = _result(rows, channel)
    C.sanitize_for_persistence(src)
    # The live result still carries the corpus channel for the export path.
    assert [e.email for e in src.corpus_leads] == ["corpus@acme.com"]


def test_sanitize_strips_pro_evidence_from_native_row() -> None:
    # Belt-and-suspenders: even a row that (via a legacy/external path) carries a
    # mailaccess_pro evidence entry alongside a native module is scrubbed, without
    # being dropped.
    row = _native("native@acme.com")
    row.found_by_modules = ["company_page", MODULE_MAILACCESS_PRO]
    row.evidence.append({"module": MODULE_MAILACCESS_PRO, "metadata": {"full_name": "Corp"}})
    clean = C.sanitize_for_persistence(_result([row]))
    kept = clean.unique_emails[0]
    assert kept.email == "native@acme.com"
    assert MODULE_MAILACCESS_PRO not in kept.found_by_modules
    assert all(ev["module"] != MODULE_MAILACCESS_PRO for ev in kept.evidence)
    # Original untouched.
    assert MODULE_MAILACCESS_PRO in row.found_by_modules


def test_sanitize_noop_when_no_corpus() -> None:
    src = _result([_native("native@acme.com")])
    assert C.sanitize_for_persistence(src) is src  # returned unchanged


def test_write_back_persists_native_only(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    import backend.db.database as db
    from backend.db.models import Base, Contact

    async def run() -> None:
        eng = create_async_engine("sqlite+aiosqlite:///" + (tmp_path / "brief_a.db").as_posix())
        async with eng.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        monkeypatch.setattr(
            db, "AsyncSessionLocal", async_sessionmaker(eng, expire_on_commit=False)
        )
        monkeypatch.setattr(C, "_SCHEMA_READY", True)
        monkeypatch.setattr(config_mod.settings, "harvest_cache_enabled", True)

        rows, channel = _mixed()
        data = _result(rows, channel)
        data.metadata[C.SCOPE_SIGNATURE_KEY] = C.scope_signature(mode=PUBLIC.value)
        await C.write_back("acme.com", data)

        cached = await C.read_fresh_crawl("acme.com", C.scope_signature(mode=PUBLIC.value))
        assert cached is not None
        assert [e.email for e in cached.unique_emails] == ["native@acme.com"]

        async with db.AsyncSessionLocal() as session:
            emails = {c.email for c in (await session.execute(select(Contact))).scalars().all()}
        assert emails == {"native@acme.com"}

        served = await C.read_leads("acme.com", mode="security-investigation")
        assert {row["email"] for row in served["leads"]} == {"native@acme.com"}
        await eng.dispose()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# A2 — resolver protection / source-weight floor
# ---------------------------------------------------------------------------
def test_pro_source_weight_is_a_floor() -> None:
    from backend.core.claim_resolver import _DEFAULT_SOURCE_WEIGHT

    pro = SOURCE_WEIGHTS[MODULE_MAILACCESS_PRO]
    assert pro == 0.05
    # Below the neutral default (which a native person source like company_page
    # falls back to) and below every explicitly-weighted person-field source, so a
    # native claim always outranks corpus in the person-field resolver.
    assert pro < _DEFAULT_SOURCE_WEIGHT
    for src in ("apollo", "pdl", "github_profile_email", "github_org_member"):
        assert pro < SOURCE_WEIGHTS[src]


# ---------------------------------------------------------------------------
# A3 — corpus is live-display-only: exports are native-only even when the
# returned result also carries a populated corpus channel.
# ---------------------------------------------------------------------------
def test_export_excludes_corpus_when_corpus_channel_is_present() -> None:
    rows, channel = _mixed()
    res = _result(rows, channel)
    js = R.format_harvest_json_export(res)
    assert all(row["email"] != "corpus@acme.com" for row in js["emails"])
    csv_out = R.format_harvest_csv_export(res)
    header = csv_out.splitlines()[0]
    assert "corpus" not in header.split(",")
    # Corpus and personal columns/keys are absent from every persisted format.
    assert "is_personal" not in header
    ndjson = R.format_harvest_ndjson_export(res)
    assert "corpus@acme.com" not in ndjson
    assert '"is_personal"' not in ndjson


def test_export_column_absent_when_no_corpus() -> None:
    res = _result([_native("native@acme.com")])
    csv_out = R.format_harvest_csv_export(res)
    header = csv_out.splitlines()[0]
    assert "corpus" not in header.split(",")
    ndjson = R.format_harvest_ndjson_export(res)
    assert '"is_personal"' not in ndjson
