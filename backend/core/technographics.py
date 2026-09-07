"""Phase 5D — technographic fingerprinting from already-fetched bytes.

Tags a company with its tech stack — mail provider, CMS, analytics/marketing,
e-commerce, JS framework — so a segment can be filtered by it ("companies on
Google Workspace / HubSpot / Shopify", the headline Apollo/BuiltWith filter),
derivable at $0 from data MailAccess already downloaded:

* **mail provider** from the MX records the harvest already resolved (no new DNS);
* **CMS / analytics / ecommerce / framework** from the homepage HTML already in
  the shared fetch cache (no new HTTP).

The detector is a pure function over bytes/strings — regex/substring only, no DOM
parser — mirroring ``context_router``'s posture. It introduces NO network I/O;
the caller supplies the already-fetched HTML and the already-resolved provider.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Fingerprint ruleset. Each entry: (tag, compiled pattern). Ordered, additive —
# a page can carry several analytics/marketing tags at once.
# ---------------------------------------------------------------------------
def _c(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


_CMS_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("wordpress", _c(r'/wp-content/|/wp-includes/|name=["\']generator["\'][^>]*wordpress')),
    ("shopify", _c(r"cdn\.shopify\.com|shopify\.theme|x-shopify|myshopify\.com")),
    ("wix", _c(r"static\.wixstatic\.com|wix\.com|X-Wix-")),
    ("squarespace", _c(r"squarespace\.com|static1\.squarespace")),
    ("webflow", _c(r"\.webflow\.io|webflow\.js|data-wf-page|data-wf-site")),
    ("drupal", _c(r"/sites/default/files/|Drupal\.settings|name=[\"']generator[\"'][^>]*drupal")),
    ("joomla", _c(r"/media/jui/|com_content|name=[\"']generator[\"'][^>]*joomla")),
    ("ghost", _c(r"content=[\"']Ghost|/ghost/api/|ghost\.io")),
    ("hubspot_cms", _c(r"hs-scripts\.com|hubspotusercontent|/hs/hsstatic/")),
    ("contentful", _c(r"cdn\.contentful\.com|images\.ctfassets\.net")),
    ("magento", _c(r"/static/version\d|Magento_|mage/cookies")),
)

_ANALYTICS_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("google_analytics", _c(
        r"""google-analytics\.com/analytics\.js|gtag\(['"]config['"]"""
        r"""|ga\(['"]create['"]|googletagmanager\.com/gtag"""
    )),
    ("google_tag_manager", _c(r"googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]+")),
    ("segment", _c(r"cdn\.segment\.com|analytics\.track\(|analytics\.load\(")),
    ("hotjar", _c(r"static\.hotjar\.com|hjSiteSettings|hj\(['\"]")),
    ("hubspot", _c(r"js\.hs-analytics\.net|js\.hsforms\.net|hs-scripts\.com")),
    ("facebook_pixel", _c(r"""connect\.facebook\.net/en_US/fbevents\.js|fbq\(['"]init['"]""")),
    ("linkedin_insight", _c(r"snap\.licdn\.com|_linkedin_partner_id")),
    ("plausible", _c(r"plausible\.io/js|data-domain=")),
    ("matomo", _c(r"matomo\.js|piwik\.js|_paq\.push")),
    ("mixpanel", _c(r"cdn\.mxpanel\.com|mixpanel\.init|api\.mixpanel\.com")),
    ("intercom", _c(r"widget\.intercom\.io|intercomSettings")),
)

_ECOMMERCE_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("shopify", _c(r"cdn\.shopify\.com|myshopify\.com")),
    ("woocommerce", _c(
        r"/wp-content/plugins/woocommerce|/wc-ajax/|woocommerce-page"
        r"|class=[\"'][^\"']*woocommerce"
    )),
    ("magento", _c(r"Magento_|/static/version\d")),
    ("bigcommerce", _c(r"bigcommerce\.com|/stencil/")),
    ("stripe", _c(r"js\.stripe\.com")),
)

_FRAMEWORK_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("nextjs", _c(r"__NEXT_DATA__|/_next/static/")),
    ("nuxt", _c(r"__NUXT__|/_nuxt/")),
    ("react", _c(r"data-reactroot|react-dom")),
    ("angular", _c(r"ng-version=|angular\.js")),
    ("vue", _c(r"data-v-[0-9a-f]{8}|vue\.js")),
    ("remix", _c(r"__remixContext|/build/_shared/")),
)


@dataclass
class Technographics:
    """Filterable tech-stack tags for a domain (Phase 5D)."""

    mail_provider: str | None = None
    cms: list[str] = field(default_factory=list)
    analytics: list[str] = field(default_factory=list)
    ecommerce: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    source: str = "cached_bytes"  # provenance: derived from already-fetched data

    def as_dict(self) -> dict[str, Any]:
        return {
            "mail_provider": self.mail_provider,
            "cms": self.cms,
            "analytics": self.analytics,
            "ecommerce": self.ecommerce,
            "frameworks": self.frameworks,
            "source": self.source,
        }

    def is_empty(self) -> bool:
        return not (
            self.mail_provider or self.cms or self.analytics
            or self.ecommerce or self.frameworks
        )

    def flat_tags(self) -> set[str]:
        """All tags as ``dimension:value`` tokens for filtering."""
        tags: set[str] = set()
        if self.mail_provider:
            tags.add(f"mail_provider:{self.mail_provider}")
        for v in self.cms:
            tags.add(f"cms:{v}")
        for v in self.analytics:
            tags.add(f"analytics:{v}")
        for v in self.ecommerce:
            tags.add(f"ecommerce:{v}")
        for v in self.frameworks:
            tags.add(f"framework:{v}")
        return tags


def _scan(html: str, rules: tuple[tuple[str, re.Pattern[str]], ...]) -> list[str]:
    hits: list[str] = []
    for tag, pattern in rules:
        if pattern.search(html) and tag not in hits:
            hits.append(tag)
    return hits


def detect_from_html(html: str | bytes | None) -> dict[str, list[str]]:
    """Return CMS / analytics / ecommerce / framework tags from homepage bytes.

    Pure regex over the raw markup — no DOM parser, no network. Never raises.
    """
    if not html:
        return {"cms": [], "analytics": [], "ecommerce": [], "frameworks": []}
    if isinstance(html, bytes):
        text = html.decode("utf-8", errors="ignore")
    else:
        text = html
    # bound the scan to a sane size (homepages can be large; the fingerprints all
    # appear in <head>/early body).
    text = text[:600_000]
    return {
        "cms": _scan(text, _CMS_RULES),
        "analytics": _scan(text, _ANALYTICS_RULES),
        "ecommerce": _scan(text, _ECOMMERCE_RULES),
        "frameworks": _scan(text, _FRAMEWORK_RULES),
    }


def detect(
    *, html: str | bytes | None = None, mail_provider: str | None = None
) -> Technographics:
    """Build a :class:`Technographics` from already-fetched HTML + resolved MX.

    ``mail_provider`` is the provider label the harvest already derived from MX
    (e.g. ``"google"``, ``"microsoft"``); pass ``None`` to omit it. No I/O.
    """
    tags = detect_from_html(html)
    mp = (mail_provider or "").strip().lower() or None
    if mp in {"unknown", "none", "self-hosted-or-unknown"}:
        mp = mp if mp == "self-hosted-or-unknown" else None
    return Technographics(
        mail_provider=mp,
        cms=tags["cms"],
        analytics=tags["analytics"],
        ecommerce=tags["ecommerce"],
        frameworks=tags["frameworks"],
    )


def matches_filters(tech: Technographics | dict[str, Any] | None, filters: list[str]) -> bool:
    """True if *tech* satisfies ALL ``dimension=value`` filters (AND semantics).

    Filters are ``key=value`` strings where key ∈ {mail_provider, cms, analytics,
    ecommerce, framework}. An empty filter list matches everything. A domain with
    no technographics fails any non-empty filter.
    """
    if not filters:
        return True
    if tech is None:
        return False
    flat = tech.flat_tags() if isinstance(tech, Technographics) else _flat_from_dict(tech)
    for f in filters:
        if "=" not in f:
            continue
        key, _, value = f.partition("=")
        token = f"{key.strip().lower()}:{value.strip().lower()}"
        # allow 'framework' alias already; match case-insensitively
        if token not in {t.lower() for t in flat}:
            return False
    return True


def _flat_from_dict(d: dict[str, Any]) -> set[str]:
    tags: set[str] = set()
    mp = d.get("mail_provider")
    if mp:
        tags.add(f"mail_provider:{mp}")
    for dim in ("cms", "analytics", "ecommerce"):
        for v in d.get(dim, []) or []:
            tags.add(f"{dim}:{v}")
    for v in d.get("frameworks", []) or []:
        tags.add(f"framework:{v}")
    return tags


__all__ = [
    "Technographics",
    "detect",
    "detect_from_html",
    "matches_filters",
]
