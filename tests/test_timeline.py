from __future__ import annotations

from datetime import datetime, timezone

from backend.core.timeline import TimelineBuilder


AS_OF = datetime(2026, 5, 27, tzinfo=timezone.utc)


def _build(rows: list[dict]):
    return TimelineBuilder(as_of=AS_OF).build_timeline(rows)


def test_timeline_sorts_and_derives_first_seen() -> None:
    timeline = _build(
        [
            {
                "module_name": "hudson_rock",
                "data": {
                    "platform": "hudson_rock",
                    "metadata": {"last_seen": "2025-01-15", "stealer_families": ["Redline"]},
                },
            },
            {
                "module_name": "github_commits",
                "data": {
                    "platform": "github_commit",
                    "metadata": {
                        "commit_date": "2011-03-10T12:30:00Z",
                        "repo": "KatrielMoses/repo",
                    },
                },
            },
            {
                "module_name": "wayback",
                "data": {
                    "platform": "wayback_machine",
                    "metadata": {
                        "archive_date": "2012-02-01",
                        "original_domain": "example.com",
                    },
                },
            },
        ]
    )

    assert [event.event_type for event in timeline.events] == [
        "commit",
        "archive_snapshot",
        "stealer_log",
    ]
    assert timeline.first_seen_date == "2011-03-10"
    assert timeline.first_seen_source == "github_commits"
    assert timeline.identity_age_years == 15
    assert timeline.established_identity is True
    assert timeline.most_recent_date == "2025-01-15"
    assert timeline.most_recent_is_active_risk is True
    assert timeline.active_risk_count == 1


def test_timeline_dedupes_same_breach_and_merges_sources() -> None:
    timeline = _build(
        [
            {
                "module_name": "xposedornot",
                "data": {
                    "platform": "XposedOrNot",
                    "source": "xposedornot",
                    "breach_name": "LinkedIn",
                    "breach_date": "2012-06",
                    "data_classes": ["Email addresses", "Passwords"],
                    "metadata": {"breach_name": "LinkedIn"},
                },
            },
            {
                "module_name": "leakcheck",
                "data": {
                    "platform": "LinkedIn",
                    "source": "leakcheck",
                    "breach_name": "LinkedIn",
                    "metadata": {"breach_name": "LinkedIn"},
                },
            },
        ]
    )

    assert len(timeline.events) == 1
    event = timeline.events[0]
    assert event.event_type == "breach"
    assert event.date == "2012-06"
    assert "xposedornot" in event.source_module
    assert "leakcheck" in event.source_module
    assert event.is_active_risk is False


def test_timeline_keeps_separate_commit_events() -> None:
    timeline = _build(
        [
            {
                "module_name": "github_commits",
                "data": {
                    "platform": "github_commit",
                    "metadata": {
                        "commit_date": "2026-05-17T12:00:00Z",
                        "repo": "KatrielMoses/MailAccess",
                        "commit_sha": "17d27c6",
                        "commit_message": "UI redone",
                    },
                },
            },
            {
                "module_name": "github_commits",
                "data": {
                    "platform": "github_commit",
                    "metadata": {
                        "commit_date": "2026-05-17T12:00:00Z",
                        "repo": "KatrielMoses/MailAccess",
                        "commit_sha": "2704469",
                        "commit_message": "UI redone again",
                    },
                },
            },
        ]
    )

    assert len(timeline.events) == 2
    assert [event.event_type for event in timeline.events] == ["commit", "commit"]
    assert [event.detail for event in timeline.events] == [
        "17d27c6; UI redone",
        "2704469; UI redone again",
    ]


def test_timeline_uses_xposedornot_breach_date_and_leakcheck_date() -> None:
    timeline = _build(
        [
            {
                "module_name": "xposedornot",
                "data": {
                    "platform": "XposedOrNot",
                    "source": "xposedornot",
                    "breach_name": "LinkedIn",
                    "metadata": {
                        "breach_name": "LinkedIn",
                        "breached_date": "2012-06-01",
                    },
                },
            },
            {
                "module_name": "leakcheck",
                "data": {
                    "platform": "LinkedIn",
                    "source": "leakcheck",
                    "breach_name": "LinkedIn",
                    "metadata": {
                        "breach_name": "LinkedIn",
                        "source_module": "leakcheck",
                        "breach_date": "2012-06-01",
                    },
                },
            },
        ]
    )

    assert len(timeline.events) == 1
    event = timeline.events[0]
    assert event.event_type == "breach"
    assert event.date == "2012-06-01"
    assert "xposedornot" in event.source_module
    assert "leakcheck" in event.source_module


def test_recent_password_breach_is_active_risk() -> None:
    timeline = _build(
        [
            {
                "module_name": "breachdirectory",
                "data": {
                    "platform": "RockYou2024",
                    "metadata": {
                        "breach_source": "RockYou2024",
                        "has_password_hash": True,
                    },
                    "confidence": "high",
                    "severity": "critical",
                },
            }
        ]
    )

    assert len(timeline.events) == 1
    assert timeline.events[0].date == "2024-01"
    assert timeline.events[0].is_active_risk is True
    assert timeline.active_risk_count == 1


def test_empty_timeline_is_graceful() -> None:
    timeline = _build(
        [
            {
                "module_name": "gravatar",
                "data": {"platform": "Gravatar", "metadata": {"display_name": "No Date"}},
            }
        ]
    )

    assert timeline.events == []
    assert timeline.first_seen_date is None
    assert timeline.identity_age_years is None
    assert timeline.timeline_span_years is None
