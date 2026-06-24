"""Group platform domains by shared infrastructure (registrar + /24 subnet).

Used by the domain_cluster post-primary module and the identity-graph builder
to surface clusters of platforms that share the same registrar AND sit on the
same /24 IP subnet.  Clusters of three or more platforms are emitted as
findings; the graph builder also adds a ``shared_infrastructure`` edge between
each pair of platforms in the cluster (weight 0.4, weaker than shared
username/avatar matches).

This is the *infrastructure* half of Phase 6B.  Creation-date clustering is
already covered by ``temporal_cluster.py`` and is intentionally not reimplemented
here — see Phase 2E for the original signup-window work.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any  # noqa: F401  (re-exported for downstream callers)

# Private-IPv4 ranges are filtered out before subnet computation so loopback
# addresses and RFC1918 space never produce a cluster key.  A more selective
# filter would also exclude CGNAT (100.64.0.0/10) and the documentation
# block (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), but for the
# investigation volume MailAccess handles the four /8s below are enough
# signal-to-noise improvement.
_PRIVATE_V4 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
)


@dataclass
class InfraCluster:
    """A group of platforms sharing the same registrar AND /24 subnet.

    The ``cluster_id`` is a stable 12-char SHA-256 digest of the
    (registrar, /24 subnet) tuple so callers can deduplicate across runs.
    """

    cluster_id: str
    platforms: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    shared_registrar: str | None = None
    shared_ip_subnet: str | None = None
    confidence: float = 0.0
    signal: str = ""

    @property
    def platform_count(self) -> int:
        return len(self.platforms)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "platforms": list(self.platforms),
            "domains": list(self.domains),
            "shared_registrar": self.shared_registrar,
            "shared_ip_subnet": self.shared_ip_subnet,
            "confidence": round(self.confidence, 3),
            "signal": self.signal,
            "platform_count": len(self.platforms),
        }


def ip_to_subnet(ip: str, prefix: int = 24) -> str | None:
    """Return the ``/prefix`` subnet string for an IPv4 address, or None.

    Returns None for IPv6 addresses (out of scope — clustering on IPv6 /48s
    produces too many false positives in the consumer mailbox landscape),
    loopback/private addresses, and malformed inputs.
    """
    if not ip or not isinstance(ip, str):
        return None
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    if not isinstance(addr, ipaddress.IPv4Address):
        return None
    if any(addr in net for net in _PRIVATE_V4):
        return None
    network = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
    return str(network)


def normalize_registrar(registrar: str | None) -> str | None:
    """Lowercase + strip + collapse whitespace on a registrar string.

    Returns None when the registrar is empty or missing so the clusterer
    can group on ``is None`` for privacy-protected records rather than
    treat them as a single shared registrar.
    """
    if not registrar or not isinstance(registrar, str):
        return None
    cleaned = re.sub(r"\s+", " ", registrar.strip().lower())
    return cleaned or None


def _make_cluster_id(registrar: str | None, subnet: str | None) -> str:
    digest = hashlib.sha256(
        f"{(registrar or '').encode()}::{subnet or ''}".encode()
    ).hexdigest()[:12]
    return f"infra_{digest}"


class InfrastructureClusterer:
    """Group platform domains by shared registrar + /24 subnet.

    The clusterer is intentionally pure-logic: callers feed in the list of
    (platform, domain, registrar, ip) tuples and receive the list of
    ``InfraCluster`` objects.  The module wrapper does the actual
    WHOIS/DNS work; the test suite passes pre-computed fixtures.
    """

    def __init__(
        self,
        min_cluster_size: int = 3,
        subnet_prefix: int = 24,
        require_both: bool = True,
    ) -> None:
        self.min_cluster_size = min_cluster_size
        self.subnet_prefix = subnet_prefix
        # require_both=True (default) means a cluster only forms when the
        # registrar AND the subnet agree.  Setting it to False would let
        # one factor alone create a cluster — useful for analyst review but
        # too noisy for the default signal.
        self.require_both = require_both

    def cluster(
        self,
        observations: list[tuple[str, str, str | None, str | None]],
    ) -> list[InfraCluster]:
        """Return infrastructure clusters from observation tuples.

        Each observation is ``(platform, domain, registrar, ip)``.
        Observations missing the registrar or IP, or with private/loopback
        IPs, are skipped before clustering.

        A cluster is emitted when ``len(platforms) >= min_cluster_size`` and
        every member shares the same registrar AND /24 subnet (or just one
        factor when ``require_both`` is False).
        """
        # Deduplicate by domain: one domain can map to multiple platforms
        # (e.g. a brand site and its mobile sub-app), but should only vote
        # once when checking the cluster size.
        per_domain: dict[str, dict[str, Any]] = {}
        for platform, domain, registrar, ip in observations:
            if not platform or not domain:
                continue
            reg = normalize_registrar(registrar)
            subnet = ip_to_subnet(ip or "", self.subnet_prefix) if ip else None
            entry = per_domain.setdefault(
                domain.lower(),
                {"platforms": set(), "registrar": reg, "subnet": subnet},
            )
            entry["platforms"].add(platform)
            # Prefer non-None values when multiple observations land on the
            # same domain (e.g. WHOIS succeeds, then DNS gives the IP).
            if reg is not None:
                entry["registrar"] = reg
            if subnet is not None:
                entry["subnet"] = subnet

        # Group domains by (registrar, subnet) — only those with both
        # attributes survive (unless require_both is False).
        buckets: dict[tuple[str | None, str | None], set[str]] = {}
        for domain, entry in per_domain.items():
            reg = entry["registrar"]
            subnet = entry["subnet"]
            if self.require_both and (reg is None or subnet is None):
                continue
            key = (reg, subnet)
            buckets.setdefault(key, set()).add(domain)

        results: list[InfraCluster] = []
        for (reg, subnet), domain_set in buckets.items():
            # Cluster size is the number of distinct *platforms*, not
            # domains — a domain that resolves to two platforms still
            # counts as a single observation in the infrastructure sense.
            all_platforms: set[str] = set()
            for domain in domain_set:
                all_platforms.update(per_domain[domain]["platforms"])
            if len(all_platforms) < self.min_cluster_size:
                continue

            platforms_sorted = sorted(all_platforms)
            domains_sorted = sorted(domain_set)
            cluster_id = _make_cluster_id(reg, subnet)
            # Confidence scales with cluster size: 3 platforms → 0.5,
            # 4 → 0.6, 5 → 0.7, capped at 0.9 (never crosses the
            # "high" threshold — infrastructure is corroborating, not
            # confirmatory).
            confidence = min(0.5 + 0.1 * (len(all_platforms) - 3), 0.9)
            signal = (
                f"{len(all_platforms)} platforms share registrar "
                f"'{reg}' and /{self.subnet_prefix} subnet {subnet}"
            )
            results.append(
                InfraCluster(
                    cluster_id=cluster_id,
                    platforms=platforms_sorted,
                    domains=domains_sorted,
                    shared_registrar=reg,
                    shared_ip_subnet=subnet,
                    confidence=confidence,
                    signal=signal,
                )
            )

        # Largest clusters first so the CLI surfaces the strongest signal
        # under the headline area.
        results.sort(
            key=lambda c: (len(c.platforms), c.confidence), reverse=True
        )
        return results
