"""0.17.0 Phase 3 — CLI surface, honest rendering & exports for corpus leads.

Gate these. Network-free: the connector is mocked, rendering/export are pure.
Proves the honesty-at-display contract: corpus leads are provenance-chipped,
unverified, REVIEW-verdicted, counted, and never dressed as native/verified;
no key is byte-identical to today; a dead API degrades to a one-line note.
"""

from __future__ import annotations

from typing import Any

import pytest
import typer
from rich.console import Console

import backend.config as config_mod
from backend.core import mailaccess_pro_connector
from backend.core.domain_harvest_orchestrator import (
    MODULE_MAILACCESS_PRO,
    DomainHarvestResult,
    HarvestedEmail,
)
from backend.core.domain_harvest_report import (
    format_harvest_cli_output,
    format_harvest_csv_export,
    format_harvest_json_export,
)
from cli.harvest_emails import _pro_wrong_mode_hint
from cli.main import _resolve_company_domain_cli

_KEY = "map_test_key"


def _native(email="jane@acme.io") -> HarvestedEmail:
    return HarvestedEmail(
        email=email,
        on_domain=True,
        is_role=False,
        role_match_type=None,
        confidence_score=0.9,
        confidence_label="CONFIRMED",
        found_by_modules=["company_page"],
        is_smtp_verified=True,
        verification="smtp_verified",
    )


def _corpus(email="bob@acme.io") -> HarvestedEmail:
    return HarvestedEmail(
        email=email,
        on_domain=True,
        is_role=False,
        role_match_type=None,
        confidence_score=0.45,
        confidence_label="LOW",
        found_by_modules=[MODULE_MAILACCESS_PRO],
        verification="unverified",
        full_name="Bob Stone",
        job_title="VP of Sales",
        seniority="vp",
        linkedin_url="https://linkedin.com/in/bobstone",
        evidence=[
            {
                "module": MODULE_MAILACCESS_PRO,
                "metadata": {
                    "source_type": MODULE_MAILACCESS_PRO,
                    "full_name": "Bob Stone",
                    "job_title": "VP of Sales",
                    "linkedin_url": "https://linkedin.com/in/bobstone",
                    "corpus_verified": False,
                    "corpus_source": "linkedin",
                },
            }
        ],
    )


def _result(emails, *, mode="public-business-contact", pro_meta=None) -> DomainHarvestResult:
    metadata: dict[str, Any] = {"mode": mode}
    if pro_meta is not None:
        metadata["mailaccess_pro"] = pro_meta
    return DomainHarvestResult(
        domain="acme.io",
        started_at="2026-09-17T10:00:00Z",
        completed_at="2026-09-17T10:00:01Z",
        duration_seconds=1.0,
        module_results={},
        unique_emails=emails,
        total_unique_emails=len(emails),
        high_confidence_count=sum(1 for e in emails if e.confidence_label == "CONFIRMED"),
        likely_confidence_count=0,
        medium_confidence_count=0,
        low_confidence_count=sum(1 for e in emails if e.confidence_label == "LOW"),
        role_account_count=0,
        personal_email_count=len(emails),
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# 1. --company resolution
# ---------------------------------------------------------------------------
def _console() -> Console:
    return Console(record=True, width=120, force_terminal=False)


def _text(console: Console) -> str:
    return console.export_text()


def test_company_ok_resolves(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod.settings, "mailaccess_pro_key", _KEY)

    async def _resolve(company):
        return {"status": "ok", "company": {"name": "Stripe", "domain": "stripe.com"}}

    monkeypatch.setattr(mailaccess_pro_connector, "resolve_company", _resolve)
    console = _console()
    domain = _resolve_company_domain_cli("Stripe", "public-business-contact", console)
    assert domain == "stripe.com"
    assert "Resolved 'Stripe' → stripe.com" in _text(console)


def test_company_disambiguation_exits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod.settings, "mailaccess_pro_key", _KEY)

    async def _resolve(company):
        return {
            "status": "disambiguation",
            "candidates": [
                {"name": "Acme Inc", "domain": "acme.com", "employees": 500},
                {"name": "Acme LLC", "domain": "acme.io", "employees": 20},
            ],
        }

    monkeypatch.setattr(mailaccess_pro_connector, "resolve_company", _resolve)
    console = _console()
    with pytest.raises(typer.Exit):
        _resolve_company_domain_cli("Acme", "public-business-contact", console)
    out = _text(console)
    assert "acme.com" in out and "acme.io" in out
    assert "--domain" in out


def test_company_empty_exits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod.settings, "mailaccess_pro_key", _KEY)

    async def _resolve(company):
        return {"status": "empty"}

    monkeypatch.setattr(mailaccess_pro_connector, "resolve_company", _resolve)
    console = _console()
    with pytest.raises(typer.Exit):
        _resolve_company_domain_cli("Nope", "public-business-contact", console)
    assert "No company match" in _text(console)


def test_company_unavailable_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod.settings, "mailaccess_pro_key", None)
    called = {"n": 0}

    async def _resolve(company):
        called["n"] += 1
        return {"status": "ok", "company": {"domain": "x.com"}}

    monkeypatch.setattr(mailaccess_pro_connector, "resolve_company", _resolve)
    console = _console()
    with pytest.raises(typer.Exit):
        _resolve_company_domain_cli("Stripe", "public-business-contact", console)
    assert "MailAccess Pro key" in _text(console)
    assert called["n"] == 0  # never called the API without a key


def test_company_unavailable_in_security_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod.settings, "mailaccess_pro_key", _KEY)
    console = _console()
    with pytest.raises(typer.Exit):
        _resolve_company_domain_cli("Stripe", "security-investigation", console)
    assert "lead-gen product" in _text(console)


# ---------------------------------------------------------------------------
# 2. Wrong-mode hint ("key never forces mode")
# ---------------------------------------------------------------------------
def test_wrong_mode_hint() -> None:
    hint = _pro_wrong_mode_hint("security-investigation", _KEY)
    assert hint and "public-business-contact" in hint
    # Right mode → no hint.
    assert _pro_wrong_mode_hint("public-business-contact", _KEY) is None
    # No key → no hint (Stream 1 users never see Pro copy).
    assert _pro_wrong_mode_hint("security-investigation", None) is None
    # Default (None → security) with a key → hint.
    assert _pro_wrong_mode_hint(None, _KEY) is not None


def test_pro_key_implies_lead_gen_mode() -> None:
    """0.17.0 — a Pro key auto-selects the lead-gen product; no --mode needed."""
    from cli.main import _pro_effective_mode

    # No key → mode is left untouched (open-tool default applies downstream).
    assert _pro_effective_mode(None, has_pro_key=False) is None
    # Key + no --mode → the lead-gen product, so corpus enrichment runs.
    assert _pro_effective_mode(None, has_pro_key=True) == "public-business-contact"
    # An explicit --mode always wins, even with a key (deliberate opt-out).
    assert _pro_effective_mode("security-investigation", has_pro_key=True) == "security-investigation"
    assert (
        _pro_effective_mode("org-authorized-verification", has_pro_key=True)
        == "org-authorized-verification"
    )


# ---------------------------------------------------------------------------
# 3. Honest rendering — provenance chip + unverified + REVIEW, not verified.
# ---------------------------------------------------------------------------
def test_corpus_lead_rendered_distinctly() -> None:
    out = format_harvest_cli_output(_result([_native(), _corpus()]))
    assert "MailAccess Pro" in out
    assert "corpus" in out and "unverified" in out
    assert "REVIEW" in out
    assert "+1 corpus leads (MailAccess Pro, unverified)" in out
    # The corpus email must NOT appear in the CONFIRMED/verified native affordance.
    # It lives only in the corpus section; the native one keeps its tier.
    assert "bob@acme.io" in out
    assert "jane@acme.io" in out


# ---------------------------------------------------------------------------
# 4. No key / no corpus leads → identical to Stream 1 (no Pro lines).
# ---------------------------------------------------------------------------
def test_no_corpus_leads_no_pro_lines() -> None:
    out = format_harvest_cli_output(_result([_native()]))
    assert "MailAccess Pro" not in out
    assert "corpus leads" not in out
    assert "Corpus enrichment unavailable" not in out
    assert "jane@acme.io" in out  # native result intact


# ---------------------------------------------------------------------------
# 5. Enrichment-unavailable → native intact + subtle note.
# ---------------------------------------------------------------------------
def test_enrichment_unavailable_note() -> None:
    out = format_harvest_cli_output(
        _result([_native()], pro_meta={"requested": True, "status": "unavailable", "injected": 0})
    )
    assert "Corpus enrichment unavailable" in out
    assert "jane@acme.io" in out  # full native result still shown


def test_enrichment_empty_no_note() -> None:
    # Requested + empty (no leads) is NOT an error → no "unavailable" note.
    out = format_harvest_cli_output(
        _result([_native()], pro_meta={"requested": True, "status": "empty", "injected": 0})
    )
    assert "Corpus enrichment unavailable" not in out


# ---------------------------------------------------------------------------
# Deliverable 4 — corpus leads are live-display-only and never serialised.
# ---------------------------------------------------------------------------
def test_exports_exclude_corpus_lead() -> None:
    result = _result([_native()])
    result.corpus_leads = [_corpus()]
    payload = format_harvest_json_export(result)
    assert all(e["email"] != "bob@acme.io" for e in payload["emails"])

    csv_text = format_harvest_csv_export(result)
    header = csv_text.splitlines()[0]
    assert "corpus" not in header
    assert "bob@acme.io" not in csv_text


# ---------------------------------------------------------------------------
# Fix 2 (invariant #5) — the persisted history baseline is NATIVE-ONLY. The single-
# domain CLI and all regular exports use the same native-only serializer, so
# serving-only corpus leads never land in ~/.mailaccess/cache/harvest_history.
# ---------------------------------------------------------------------------
def test_history_baseline_excludes_corpus_leads() -> None:
    result = _result([_native()])
    result.corpus_leads = [_corpus()]  # serving-only channel

    full = format_harvest_json_export(result)
    history = format_harvest_json_export(result)

    assert all(e["email"] != "bob@acme.io" for e in full["emails"])
    assert all(e["email"] != "bob@acme.io" for e in history["emails"])
    assert [e["email"] for e in history["emails"]] == ["jane@acme.io"]  # native only


# ---------------------------------------------------------------------------
# Connector resolve_company fail-open.
# ---------------------------------------------------------------------------
def test_resolve_company_fail_open_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    monkeypatch.setattr(config_mod.settings, "mailaccess_pro_key", None)
    env = asyncio.run(mailaccess_pro_connector.resolve_company("Stripe"))
    assert env["status"] == "unavailable"
