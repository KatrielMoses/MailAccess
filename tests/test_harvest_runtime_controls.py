import asyncio
from types import SimpleNamespace

import pytest

from backend.core import domain_harvest_orchestrator as orchestrator
from backend.core import harvest_runner
from backend.core.domain_harvest_orchestrator import (
    _run_with_soft_timeout,
    _safe_phase12_run,
)
from backend.core.harvest_runner import WorkerContext, run_adaptive_harvest
from backend.core.mail_provider import MailProvider
from backend.core.work_scheduler import WorkScheduler
from backend.modules.base import ModuleResult, ModuleStatus


@pytest.fixture(autouse=True)
def _disable_m365_preflight_for_runtime_tests(monkeypatch):
    """Keep unrelated harvest-control tests offline and deterministic."""
    async def no_preflight(_domain, _emails):
        return None

    monkeypatch.setattr(harvest_runner, "run_m365_passive_intel", no_preflight)


def test_skip_modules_are_recorded_without_execution():
    async def run():
        result = await run_adaptive_harvest(
            "acme.org",
            timeout_seconds=1,
            skip_modules=("public_forge", "package_ecosystems"),
        )
        return result

    result = asyncio.run(run())
    assert result.module_results["public_forge"].metadata["skip_reason"] == "runtime_policy"
    assert result.module_results["package_ecosystems"].metadata["skip_reason"] == "runtime_policy"


def test_soft_timeout_cancels_source_task_and_returns_partial():
    cancelled = asyncio.Event()

    async def slow_source():
        try:
            await asyncio.sleep(10)
        finally:
            cancelled.set()

    async def run():
        return await _run_with_soft_timeout(
            "slow_source",
            slow_source(),
            None,
            soft_timeout=0.01,
        )

    result = asyncio.run(run())
    assert result.status == ModuleStatus.PARTIAL
    assert cancelled.is_set()


def test_safe_module_runner_accepts_and_forwards_progress_callback():
    actions = []

    class ProgressModule:
        async def run(self, domain, *, progress_callback=None):
            progress_callback("querying source")
            return ModuleResult(status=ModuleStatus.SUCCESS)

    async def run():
        return await _safe_phase12_run(
            "progress_module",
            ProgressModule(),
            "example.com",
            progress_callback=actions.append,
        )

    _, result = asyncio.run(run())
    assert result.status == ModuleStatus.SUCCESS
    assert actions == ["querying source"]


@pytest.mark.asyncio
async def test_discovery_timeout_returns_exportable_partial_result(monkeypatch):
    async def timed_out_tracks(ctx):
        ctx.module_results["commoncrawl_email"] = ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[
                {
                    "metadata": {
                        "email": "found@example.com",
                        "confidence_score": 0.9,
                        "source_type": "commoncrawl_email",
                    }
                }
            ],
        )
        await asyncio.sleep(2)

    monkeypatch.setattr("backend.core.harvest_runner._run_tracks", timed_out_tracks)
    result = await run_adaptive_harvest("example.com", timeout_seconds=0.01)

    assert result.metadata["harvest_status"] == "partial_timeout"
    assert result.metadata["timed_out"] is True
    assert result.metadata["timeout_at_seconds"] == 0.01
    assert any(email.email == "found@example.com" for email in result.unique_emails)


@pytest.mark.asyncio
async def test_smtp_verification_runs_after_timeout(monkeypatch):
    smtp_calls = []

    async def timed_out_tracks(ctx):
        ctx.module_results["commoncrawl_email"] = ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[
                {
                    "metadata": {
                        "email": "found@example.com",
                        "confidence_score": 0.9,
                    }
                }
            ],
        )
        await asyncio.sleep(2)

    async def fake_smtp(domain, module_results):
        smtp_calls.append((domain, module_results))
        return {"candidates_routed": 1, "status": "verified", "provider": "google"}

    monkeypatch.setattr("backend.core.harvest_runner._run_tracks", timed_out_tracks)
    monkeypatch.setattr(
        "backend.core.domain_harvest_orchestrator._attach_smtp_email_verification",
        fake_smtp,
    )

    result = await run_adaptive_harvest("example.com", timeout_seconds=0.01)

    assert smtp_calls
    assert smtp_calls[0][0] == "example.com"
    assert result.metadata["smtp_email_verification"] == {
        "candidates_routed": 1,
        "status": "verified",
        "provider": "google",
    }


@pytest.mark.asyncio
async def test_degraded_harvest_uses_cached_provider_detection(monkeypatch):
    from types import SimpleNamespace

    from backend.core.mail_provider import MailProvider

    detection_calls = []
    attach_calls = []

    async def degraded_tracks(ctx):
        ctx.module_results["commoncrawl_email"] = ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[
                {
                    "metadata": {
                        "email": "person@google.example",
                        "on_domain": True,
                        "confidence_score": 0.7,
                        "confidence_label": "LIKELY",
                    }
                }
            ],
        )

    async def fake_resolve_mx(domain):
        return [SimpleNamespace(host="aspmx.l.google.com", priority=1)]

    def fake_detect(records, *, target_domain):
        detection_calls.append(target_domain)
        return SimpleNamespace(
            provider=MailProvider.GOOGLE,
            primary_mx="aspmx.l.google.com",
            matched_mx_hosts=("aspmx.l.google.com",),
        )

    async def fake_attach(domain, module_results, *, provider_detection=None, mx_records=None):
        attach_calls.append({
            "provider_detection": provider_detection,
            "mx_records": mx_records,
        })
        finding = module_results["commoncrawl_email"].findings[0]
        metadata = finding["metadata"]
        metadata["provider_verification_provider"] = "google"
        metadata["provider_verification_status"] = "verified"
        return {"provider": "google", "checked": 1, "verified": 1}

    monkeypatch.setattr("backend.core.harvest_runner._run_tracks", degraded_tracks)
    monkeypatch.setattr("backend.core.harvest_runner.resolve_mx", fake_resolve_mx)
    monkeypatch.setattr("backend.core.harvest_runner.detect_provider_from_mx", fake_detect)
    monkeypatch.setattr(
        "backend.core.domain_harvest_orchestrator._attach_smtp_email_verification",
        fake_attach,
    )
    monkeypatch.setattr("backend.config.settings.enable_low_email_validation", False)

    result = await run_adaptive_harvest(
        "google.example",
        timeout_seconds=1,
        enable_smtp=True,
        skip_modules=("ripe_stat_asn", "shodan_internetdb"),
    )

    assert detection_calls == ["google.example"]
    assert attach_calls and attach_calls[0]["provider_detection"].provider is MailProvider.GOOGLE
    verified = [email for email in result.unique_emails if email.is_provider_verified]
    assert len(verified) == 1
    assert verified[0].provider_verification_provider == "google"


# ---------------------------------------------------------------------------
# Acceptance: degraded-harvest simulation (Google-MX domain on the timeout
# path) — export must contain populated, honest provider_verification_* on
# every record, no SMTP probing may occur for Google, and verification must
# run strictly before Shodan/RIPE enrichment on BOTH paths.
# ---------------------------------------------------------------------------


def _google_tail_patches(monkeypatch, calls):
    """Shared patching for the degraded-harvest simulations.

    ``calls`` records ("verify", ...) and ("enrich", module_name) so tests
    can assert ordering. Returns nothing; everything goes through monkeypatch.
    """
    from types import SimpleNamespace

    from backend.core.mail_provider import MailProvider

    async def fake_resolve_mx(domain):
        return [SimpleNamespace(host="aspmx.l.google.com", priority=1)]

    def fake_detect(records, *, target_domain):
        return SimpleNamespace(
            provider=MailProvider.GOOGLE,
            primary_mx="aspmx.l.google.com",
            matched_mx_hosts=("aspmx.l.google.com",),
        )

    class FakeGoogleVerifier:
        def __init__(self, **kwargs):
            # Hard requirement: the Google route must never enable SMTP.
            assert kwargs.get("smtp_fallback_enabled") is False
            self.kwargs = kwargs

        async def verify_batch(self, emails, domain, session=None, max_checks=25):
            from backend.core.google_workspace_verifier import VerificationResult

            results = []
            for index, email in enumerate(emails):
                if index == 0:
                    results.append(
                        VerificationResult(
                            email=email,
                            status="possibly_exists",
                            exists=None,
                            gravatar_hit=True,
                            gravatar_checked=True,
                            http_status=200,
                        )
                    )
                else:
                    results.append(
                        VerificationResult(
                            email=email,
                            status="inconclusive",
                            gravatar_checked=True,
                        )
                    )
            return results

    class NoSMTPVerifier:
        def __init__(self, *args, **kwargs):
            raise AssertionError(
                "SMTPVerifier must not be constructed for a Google-MX domain"
            )

    async def fake_run_module(module_name, ctx, soft_timeout=None, **kwargs):
        calls.append(("enrich", module_name))
        return [], []

    async def fake_native_validation(domain, module_results):
        # Stub the DNS-backed native validation pass: the simulation must not
        # do live network work, and real MX answers for the fake domain would
        # filter the seeded candidates out of the verification tail.
        return {"checked": 0, "skipped": "simulation"}

    monkeypatch.setattr("backend.core.harvest_runner.resolve_mx", fake_resolve_mx)
    monkeypatch.setattr("backend.core.harvest_runner.detect_provider_from_mx", fake_detect)
    monkeypatch.setattr(
        "backend.core.domain_harvest_orchestrator.GoogleWorkspaceVerifier",
        FakeGoogleVerifier,
    )
    monkeypatch.setattr(
        "backend.core.domain_harvest_orchestrator.SMTPVerifier", NoSMTPVerifier
    )
    monkeypatch.setattr("backend.core.harvest_runner._run_module", fake_run_module)
    monkeypatch.setattr("backend.config.settings.enable_low_email_validation", False)
    monkeypatch.setattr("backend.config.settings.xposed_or_not_enabled", False)

    # Record verification relative to enrichment.
    import backend.core.domain_harvest_orchestrator as orchestrator

    real_attach = orchestrator._attach_smtp_email_verification

    async def recording_attach(
        domain, module_results, *, provider_detection=None, mx_records=None
    ):
        calls.append(("verify", domain))
        return await real_attach(
            domain,
            module_results,
            provider_detection=provider_detection,
            mx_records=mx_records,
        )

    monkeypatch.setattr(
        "backend.core.domain_harvest_orchestrator._attach_smtp_email_verification",
        recording_attach,
    )
    monkeypatch.setattr(
        "backend.core.domain_harvest_orchestrator._attach_native_email_validation",
        fake_native_validation,
    )


def _seed_google_findings(ctx, domain, count=3):
    ctx.module_results["commoncrawl_email"] = ModuleResult(
        status=ModuleStatus.SUCCESS,
        findings=[
            {
                "metadata": {
                    "email": f"person{i}@{domain}",
                    "on_domain": True,
                    "confidence_score": 0.7,
                    "confidence_label": "LIKELY",
                }
            }
            for i in range(count)
        ],
    )


@pytest.mark.asyncio
async def test_google_timeout_path_export_has_honest_provider_statuses(monkeypatch):
    """Degraded-harvest simulation: Google-MX domain forced onto the timeout
    path. The single export, written after the tail, must carry populated
    provider_verification_* on every record with honest non-verified statuses,
    and verification must be logged before Shodan/RIPE enrichment."""
    from backend.core.domain_harvest_report import format_harvest_json_export

    calls: list = []
    _google_tail_patches(monkeypatch, calls)

    async def timed_out_tracks(ctx):
        _seed_google_findings(ctx, "google.example")
        await asyncio.sleep(2)

    monkeypatch.setattr("backend.core.harvest_runner._run_tracks", timed_out_tracks)

    result = await run_adaptive_harvest(
        "google.example", timeout_seconds=0.01, enable_smtp=True
    )

    assert result.metadata["harvest_status"] == "partial_timeout"

    # Ordering: verification strictly before Shodan/RIPE enrichment.
    verify_idx = next(i for i, c in enumerate(calls) if c[0] == "verify")
    enrich_idx = [i for i, c in enumerate(calls) if c[0] == "enrich"]
    assert enrich_idx, "enrichment tail must still run on the timeout path"
    assert all(verify_idx < i for i in enrich_idx)
    assert {c[1] for c in calls if c[0] == "enrich"} == {
        "ripe_stat_asn",
        "shodan_internetdb",
    }

    # Summary: Google method, routed-vs-contacted telemetry split, no
    # field implying SMTP contact occurred.
    smtp_summary = result.metadata["smtp_email_verification"]
    assert smtp_summary["method"] == "google"
    assert smtp_summary["provider"] == "google"
    assert smtp_summary["candidates_routed"] == 3
    assert smtp_summary["gravatar_checked"] == 3
    assert "checked" not in smtp_summary
    assert "probes_attempted" not in smtp_summary

    # The export itself: populated provider_verification_* on every record.
    payload = format_harvest_json_export(result)
    assert payload["emails"], "export must contain the seeded records"
    statuses = set()
    for entry in payload["emails"]:
        assert entry["provider_verification_provider"] == "google"
        assert entry["provider_verification_status"]
        statuses.add(entry["provider_verification_status"])
    assert statuses <= {"possibly_exists", "unverifiable_provider"}
    assert "unverifiable_provider" in statuses  # honest non-verified stamp


@pytest.mark.asyncio
async def test_google_completion_path_verification_precedes_enrichment(monkeypatch):
    """Same ordering guarantee on the normal completion path."""
    from backend.core.domain_harvest_report import format_harvest_json_export

    calls: list = []
    _google_tail_patches(monkeypatch, calls)

    async def fast_tracks(ctx):
        _seed_google_findings(ctx, "google.example")

    monkeypatch.setattr("backend.core.harvest_runner._run_tracks", fast_tracks)

    result = await run_adaptive_harvest(
        "google.example", timeout_seconds=5, enable_smtp=True
    )

    assert result.metadata.get("harvest_status") != "partial_timeout"
    verify_idx = next(i for i, c in enumerate(calls) if c[0] == "verify")
    enrich_idx = [i for i, c in enumerate(calls) if c[0] == "enrich"]
    assert enrich_idx
    assert all(verify_idx < i for i in enrich_idx)

    payload = format_harvest_json_export(result)
    for entry in payload["emails"]:
        assert entry["provider_verification_provider"] == "google"
        assert entry["provider_verification_status"] in {
            "possibly_exists",
            "unverifiable_provider",
        }


@pytest.mark.asyncio
async def test_provider_dispatch_candidates_routed_counts_unique_candidates(monkeypatch):
    """``candidates_routed`` counts the candidate objects handed to the
    verifier, fixed at dispatch time — a duplicate-email artifact in the
    verifier's result list must not inflate it. The ambiguous ``checked``
    field is gone: routed and contacted are always separate fields."""
    from types import SimpleNamespace

    import backend.core.domain_harvest_orchestrator as orchestrator
    from backend.core.domain_harvest_orchestrator import _dispatch_provider_verifier
    from backend.core.mail_provider import MailProvider

    findings = {
        "a@example.com": [{"metadata": {"email": "a@example.com"}}],
        "b@example.com": [{"metadata": {"email": "b@example.com"}}],
    }
    detection = SimpleNamespace(provider=MailProvider.M365)

    class DuplicatingVerifier:
        def __init__(self, **kwargs):
            pass

        async def verify_batch(self, emails):
            # Re-probe artifact: the same address appears twice in results.
            return [
                SimpleNamespace(
                    email="a@example.com", status="verified", exists=True,
                    if_exists_result=None, is_unmanaged=None,
                    throttle_status=None, http_status=200, error=None,
                ),
                SimpleNamespace(
                    email="a@example.com", status="verified", exists=True,
                    if_exists_result=None, is_unmanaged=None,
                    throttle_status=None, http_status=200, error=None,
                ),
                SimpleNamespace(
                    email="b@example.com", status="inconclusive", exists=None,
                    if_exists_result=None, is_unmanaged=None,
                    throttle_status=None, http_status=200, error=None,
                ),
            ]

    monkeypatch.setattr(orchestrator, "M365Verifier", DuplicatingVerifier)
    summary = await _dispatch_provider_verifier("example.com", findings, detection)
    assert summary["candidates_routed"] == 2
    assert "checked" not in summary


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["clean", "timeout", "exception", "soft_kill"])
async def test_termination_handler_fires_once_for_every_exit_mode(
    monkeypatch, tmp_path, mode
):
    """The harvest-end handler receives the live snapshot on every exit path."""
    import json

    from backend.config import settings
    from backend.core.harvest_results import write_harvest_export

    monkeypatch.setattr(settings, "harvest_results_dir", tmp_path)

    async def no_seed_scheduler(ctx):
        return None

    async def tracks(ctx):
        ctx.module_results["commoncrawl_email"] = ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[
                {
                    "metadata": {
                        "email": "before-exit@acme.org",
                        "confidence_score": 0.9,
                        "confidence_label": "LIKELY",
                        "on_domain": True,
                        "source_type": "commoncrawl_email",
                    }
                }
            ],
        )
        if mode == "timeout":
            await asyncio.sleep(1)
        elif mode == "exception":
            raise RuntimeError("injected stage failure")
        elif mode == "soft_kill":
            raise asyncio.CancelledError()

    monkeypatch.setattr("backend.core.harvest_runner._seed_scheduler", no_seed_scheduler)
    monkeypatch.setattr("backend.core.harvest_runner._run_tracks", tracks)

    snapshots = []
    written = []

    def on_harvest_end(snapshot):
        snapshots.append(snapshot)
        written.append(
            write_harvest_export(snapshot, timestamp=f"20260718_{mode}")
        )

    try:
        result = await run_adaptive_harvest(
            "acme.org",
            timeout_seconds=0.01 if mode == "timeout" else 1,
            enable_smtp=False,
            skip_modules=("ripe_stat_asn", "shodan_internetdb"),
            on_harvest_end=on_harvest_end,
        )
    except asyncio.CancelledError:
        result = None

    assert len(snapshots) == 1
    assert any(email.email == "before-exit@acme.org" for email in snapshots[0].unique_emails)
    from backend.core.domain_harvest_report import format_harvest_json_export
    assert format_harvest_json_export(snapshots[0])["emails"]
    assert len(written) == 1
    assert written[0].main_json is not None
    assert written[0].main_json.exists()
    assert json.loads(written[0].main_json.read_text(encoding="utf-8"))["emails"]
    snapshot = snapshots[0]
    assert any(email.email == "before-exit@acme.org" for email in snapshot.unique_emails)
    if mode == "timeout":
        assert snapshot.metadata["harvest_status"] == "partial_timeout"
    if mode == "soft_kill":
        assert snapshot.metadata["terminated_early"] is True


@pytest.mark.asyncio
async def test_m365_preflight_runs_before_scheduler(monkeypatch):
    order = []

    async def fake_preflight(domain, _emails):
        order.append(("m365", domain))
        return SimpleNamespace(tenant_type="managed", tenant_id="tenant-guid")

    real_scheduler = WorkScheduler

    class TrackingScheduler(real_scheduler):
        def __init__(self, *args, **kwargs):
            order.append(("scheduler", None))
            super().__init__(*args, **kwargs)

    async def no_seed(_ctx: WorkerContext):
        return None

    async def no_tracks(_ctx: WorkerContext):
        return None

    monkeypatch.setattr(harvest_runner.settings, "enable_m365_passive_intel", True)
    monkeypatch.setattr(harvest_runner, "run_m365_passive_intel", fake_preflight)
    monkeypatch.setattr(harvest_runner, "WorkScheduler", TrackingScheduler)
    monkeypatch.setattr(harvest_runner, "_seed_scheduler", no_seed)
    monkeypatch.setattr(harvest_runner, "_run_tracks", no_tracks)
    monkeypatch.setattr(harvest_runner, "StealthSession", lambda **_kw: SimpleNamespace())

    await run_adaptive_harvest(
        "acme.com",
        timeout_seconds=1,
        timing_profile="t5",
        enable_smtp=False,
        module_overrides={"test": object()},
    )

    assert [entry[0] for entry in order] == ["m365", "scheduler"]


@pytest.mark.asyncio
async def test_m365_preflight_timeout_does_not_block_harvest(monkeypatch):
    captured = {}

    async def slow_preflight(_domain, _emails):
        await asyncio.sleep(25)

    async def no_seed(_ctx: WorkerContext):
        return None

    async def capture_tracks(ctx: WorkerContext):
        captured["context"] = ctx.m365_context

    monkeypatch.setattr(harvest_runner.settings, "enable_m365_passive_intel", True)
    monkeypatch.setattr(harvest_runner, "run_m365_passive_intel", slow_preflight)
    monkeypatch.setattr(harvest_runner, "_seed_scheduler", no_seed)
    monkeypatch.setattr(harvest_runner, "_run_tracks", capture_tracks)
    monkeypatch.setattr(harvest_runner, "StealthSession", lambda **_kw: SimpleNamespace())

    started = asyncio.get_running_loop().time()
    await run_adaptive_harvest(
        "acme.com",
        timeout_seconds=1,
        timing_profile="t5",
        enable_smtp=False,
        module_overrides={"test": object()},
    )

    assert asyncio.get_running_loop().time() - started < 21
    assert captured["context"] is None


@pytest.mark.asyncio
async def test_m365_context_available_to_provider_verifier(monkeypatch):
    async def fake_resolve_mx(_domain):
        return ["mx.example.com"]

    async def fake_verify(self, emails):
        return [
            SimpleNamespace(
                email=email,
                status="inconclusive",
                if_exists_result=None,
                is_unmanaged=None,
                throttle_status=None,
                http_status=None,
                error=None,
            )
            for email in emails
        ]

    async def should_not_rerun(*_args, **_kwargs):
        raise AssertionError("M365 passive intel was re-run")

    monkeypatch.setattr(orchestrator, "resolve_mx", fake_resolve_mx)
    monkeypatch.setattr(orchestrator.M365Verifier, "verify_batch", fake_verify)
    monkeypatch.setattr(orchestrator.settings, "enable_m365_passive_intel", True)
    monkeypatch.setattr(
        "backend.modules.m365_passive_intel.run_m365_passive_intel",
        should_not_rerun,
    )

    module_results = {
        "pattern_and_verify": ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[
                {
                    "metadata": {
                        "email": "bob@acme.com",
                        "on_domain": True,
                    }
                }
            ],
        )
    }
    context = SimpleNamespace(
        tenant_type="managed",
        tenant_id="tenant-guid",
        is_cloud=True,
        adfs_url=None,
    )

    summary = await orchestrator._attach_smtp_email_verification(
        "acme.com",
        module_results,
        provider_detection=SimpleNamespace(provider=MailProvider.M365),
        m365_context=context,
    )

    tenant = summary["infrastructure"]["m365_tenant"]
    assert tenant["tenant_type"] == "managed"
    assert tenant["tenant_id"] == "tenant-guid"
    assert tenant["is_cloud"] is True

    m365_summary = await orchestrator._attach_m365_email_verification(
        "acme.com",
        module_results,
        provider_detection=SimpleNamespace(
            provider=MailProvider.M365,
            primary_mx="mx.example.com",
            matched_mx_hosts=("mx.example.com",),
        ),
        m365_context=context,
    )
    assert m365_summary["realm"]["namespace_type"] == "managed"


def test_m365_context_is_promoted_to_export_infrastructure():
    from backend.core.domain_harvest_report import _build_infrastructure

    result = SimpleNamespace(
        module_results={},
        metadata={
            "verification_tail": {
                "smtp_email_verification": {
                    "infrastructure": {
                        "m365_tenant": {
                            "tenant_type": "managed",
                            "tenant_id": "tenant-guid",
                            "is_cloud": True,
                        }
                    }
                }
            }
        },
    )

    infrastructure = _build_infrastructure(result)
    assert infrastructure["m365_tenant"]["tenant_type"] == "managed"


def test_accumulated_enrichment_partial_status_is_preserved():
    context = SimpleNamespace(module_results={})
    partial = ModuleResult(
        status=ModuleStatus.PARTIAL,
        findings=[{"metadata": {"email": "alice@acme.com"}}],
    )
    success = ModuleResult(
        status=ModuleStatus.SUCCESS,
        findings=[{"metadata": {"email": "bob@acme.com"}}],
    )

    harvest_runner._record_module_result(
        context,
        harvest_runner.MODULE_EMAIL_IDENTITY_ENRICHMENT,
        partial,
    )
    harvest_runner._record_module_result(
        context,
        harvest_runner.MODULE_EMAIL_IDENTITY_ENRICHMENT,
        success,
    )

    assert (
        context.module_results[harvest_runner.MODULE_EMAIL_IDENTITY_ENRICHMENT].status
        is ModuleStatus.PARTIAL
    )
