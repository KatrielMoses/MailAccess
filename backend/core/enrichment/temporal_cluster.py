"""Cluster platform accounts by creation date to detect coordinated signups."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

_DATE_KEYS = (
    "created_at",
    "join_date",
    "registered",
    "registered_at",
    "account_created",
    "creation_date",
)

_MILLIS_THRESHOLD = 10**11


def extract_creation_date(finding: dict[str, Any]) -> datetime | None:
    """Extract and parse an account creation date from a finding dict.

    Keys checked in priority order: created_at, join_date, registered,
    registered_at, account_created, creation_date.  Checks both the
    top-level dict and a nested ``metadata`` dict.

    Accepts ISO 8601 strings, Unix timestamps (int/float), and datetime
    objects.  Unix values > 10**11 are treated as milliseconds.

    Returns a timezone-aware UTC datetime, or None if not found or
    unparseable.
    """
    payloads: list[dict[str, Any]] = [finding]
    meta = finding.get("metadata")
    if isinstance(meta, dict):
        payloads.append(meta)

    for payload in payloads:
        for key in _DATE_KEYS:
            val = payload.get(key)
            if val is None:
                continue
            result = _parse_value(val)
            if result is not None:
                return result
    return None


def _parse_value(val: object) -> datetime | None:
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc)

    if isinstance(val, int | float):
        ts = float(val)
        if ts > _MILLIS_THRESHOLD:
            ts /= 1000.0
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None

    if isinstance(val, str):
        _ISO_FORMATS = (
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%d",
        )
        for fmt in _ISO_FORMATS:
            try:
                dt = datetime.strptime(val, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                continue

    return None


class TemporalClusterer:
    """Detect coordinated signup windows across platforms.

    After sorting by creation date, uses a union-find sweep on consecutive
    pairs: if two adjacent dates are within ``window_days`` of each other
    they join the same cluster.  This gives transitive closure — A and C can
    cluster via B even if A–C span > window_days.
    """

    def __init__(self, window_days: int = 60, min_cluster_size: int = 5) -> None:
        self.window_days = window_days
        self.min_cluster_size = min_cluster_size

    def cluster(
        self,
        pairs: list[tuple[str, datetime | None]],
    ) -> list[dict[str, Any]]:
        """Return coordinated-signup clusters from (platform, creation_date) pairs.

        None dates are excluded before clustering.  Clusters smaller than
        ``min_cluster_size`` and singletons are not returned.

        Each returned dict has:
          platforms, earliest, latest, span_days, cluster_size, score.
        Score = cluster_size × time_window_inverse, capped at 1.0.
        """
        dated = [(p, dt) for p, dt in pairs if dt is not None]
        if not dated:
            return []

        dated.sort(key=lambda x: x[1])
        n = len(dated)

        parent = list(range(n))

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        def union(a: int, b: int) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        for i in range(n - 1):
            gap = (dated[i + 1][1] - dated[i][1]).days
            if gap <= self.window_days:
                union(i, i + 1)

        groups: dict[int, list[int]] = {}
        for i in range(n):
            groups.setdefault(find(i), []).append(i)

        results: list[dict[str, Any]] = []
        for indexes in groups.values():
            size = len(indexes)
            if size < max(2, self.min_cluster_size):
                continue
            platforms = [dated[i][0] for i in indexes]
            dates = [dated[i][1] for i in indexes]
            earliest = min(dates)
            latest = max(dates)
            span_days = (latest - earliest).days
            time_window_inverse = max(0.0, 1.0 - (span_days / 180.0))
            score = min(1.0, size * time_window_inverse)
            results.append({
                "platforms": platforms,
                "earliest": earliest,
                "latest": latest,
                "span_days": span_days,
                "cluster_size": size,
                "score": round(score, 3),
            })

        return results
