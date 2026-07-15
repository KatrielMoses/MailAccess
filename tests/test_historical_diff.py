from backend.core.historical_diff import annotate_historical_diff
from backend.modules.base import ModuleResult, ModuleStatus


def test_historical_diff_classifies_persistent_and_historical_only():
    results = {
        "commoncrawl_email": ModuleResult(status=ModuleStatus.SUCCESS, findings=[
            {"metadata": {"email": "alice@acme.org", "oldest_timestamp": "20250101000000", "newest_timestamp": "20260101000000"}},
            {"metadata": {"email": "old@acme.org", "oldest_timestamp": "20180101000000", "newest_timestamp": "20190101000000"}},
        ]),
        "wayback_domain_harvest": ModuleResult(status=ModuleStatus.SUCCESS, findings=[]),
    }
    metrics = annotate_historical_diff(results)
    assert metrics["persistent"] == 1
    assert metrics["historical_only"] == 1
    assert results["commoncrawl_email"].findings[0]["metadata"]["historical_status"] == "persistent"
    assert results["commoncrawl_email"].findings[1]["metadata"]["historical_status"] == "historical_only"
