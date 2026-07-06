"""Pre-filter for raw extracted name strings.

Different from :mod:`backend.core.name_consensus` (which scores
candidates *for a specific email* with source weighting) — this
module scores raw extracted strings for "is this even a person name"
*before* they enter the consensus pipeline.  Cheap, deterministic,
no NLP.  Returns ``True`` only for strings that pass a basic structural
check (capitalisation, token count, no digits, not in the navigation/
footer stoplist).

The pattern validation is borrowed from ``name_consensus.PERSON_RE``
(which itself is Unicode-aware across Latin / Cyrillic / Arabic /
CJK / Devanagari scripts).  We intentionally *don't* import
``name_consensus`` here to keep this cheap module loadable from hot
paths without dragging in rapidfuzz / unidecode.
"""

from __future__ import annotations

import re
import unicodedata

# ----------------------------------------------------------------------
# Validation patterns
# ----------------------------------------------------------------------
# Latin token: capital first, AT LEAST ONE lowercase (incl.
# diacritics in Latin-1 Supplement and Latin Extended Additional)
# trailing.  Rejects single-letter "Y" tokens and all-caps strings
# like "JOHN SMITH" while accepting "José", "François", "Łukasz",
# "O'Brien" (apostrophe in body), "Mary-Jane" (hyphen).
_LOWER_LATIN = r"[a-z\u00E0-\u024F\u1E00-\u1EFF]"
_LATIN_TOKEN = (
    rf"[A-Z\u00C0-\u024F\u1E00-\u1EFF]"
    rf"[a-zA-Z\u00C0-\u024F\u1E00-\u1EFF''\-]*{_LOWER_LATIN}[a-zA-Z\u00C0-\u024F\u1E00-\u1EFF''\-]*"
)
# Non-Latin alphabetic runs: Cyrillic, Arabic, CJK, Devanagari.
_NONLATIN_TOKEN = r"[Ѐ-ӿ؀-ۿ一-鿿ऀ-ॿ]+"

# Two separate top-level patterns because Latin tokens require
# whitespace between them (real names), while non-Latin runs (e.g.
# Japanese / Chinese / Korean) frequently arrive space-less.
_LATIN_PERSON_RE = re.compile(
    rf"^{_LATIN_TOKEN}(?:\s+{_LATIN_TOKEN}){{1,3}}$",
    re.UNICODE,
)
# Non-Latin allows whitespace-less runs so "王小明" / "山田太郎"
# survive.  We additionally require at least one non-Latin letter
# in :func:`is_plausible_person_name` before accepting the hit, so
# this pattern alone is necessary-but-not-sufficient.
_NONLATIN_PERSON_RE = re.compile(
    rf"^{_NONLATIN_TOKEN}(?:\s?{_NONLATIN_TOKEN}){{1,3}}$",
    re.UNICODE,
)

# Backward-compatible alias — older callers import ``_PERSON_RE``.
_PERSON_RE = _LATIN_PERSON_RE

# Common nav / footer / placeholder text.  Lower-cased comparison.
_NAV_FOOTER_STOPLIST: frozenset[str] = frozenset(
    {
        "privacy policy",
        "terms of service",
        "terms of use",
        "cookie policy",
        "contact us",
        "about us",
        "learn more",
        "read more",
        "sign up",
        "sign in",
        "log in",
        "log out",
        "all rights reserved",
        "site map",
        "follow us",
        "get started",
        "view profile",
        "view all",
        "see more",
        "load more",
        "next page",
        "previous page",
        "join us",
        "our team",
        "our company",
        "open menu",
        "close menu",
        "menu",
        "search",
        "subscribe",
        "newsletter",
        "skip to content",
        "skip to main",
    }
)

# A short list of words that, when they appear as a *token* in a candidate
# string, almost certainly indicate a job-title or nav label rather than
# a person.  Used by :func:`is_plausible_person_name` to reject strings like
# "Chief Executive Officer Jane" or "Home About Team Privacy".
_ROLE_WORDS: frozenset[str] = frozenset(
    {
        # Common job titles that show up in company about pages.
        "chief",
        "officer",
        "executive",
        "director",
        "senior",
        "junior",
        "lead",
        "head",
        "manager",
        "engineer",
        "developer",
        "designer",
        "analyst",
        "consultant",
        "marketing",
        "sales",
        "operations",
        "product",
        "project",
        "program",
        "account",
        "people",
        "human",
        "resources",
        "administrative",
        "technology",
        "technical",
        "founder",
        "co-founder",
        "cofounder",
        "ceo",
        "cto",
        "cfo",
        "coo",
        "cmo",
        "vp",
        "svp",
        "evp",
    }
)

# Phase 4 expanded stopword set — covers five categories of tokens that
# show up as "name" fragments in training / vendor / enterprise page
# copy but are NEVER person-name components:
#
#   1. Cloud & vendor product names   (azure, aws, gcp, kubernetes …)
#   2. Certification & training terms (cert, certification, training …)
#   3. Microsoft stack specifics      (dynamics, powerbi, teams …)
#   4. Marketing & navigation phrases (learn, platform, solutions …)
#   5. Geographic / page-furniture  (north, login, dashboard …)
#
# Rejection rule (Phase 4): REJECT only when ALL tokens are stopwords,
# OR when >=50 % tokens are stopwords in a 3+ token name.  Two-token
# names where only ONE token is suspicious pass but get a confidence
# penalty via :func:`name_suspicion_penalty`.
#
# The hard stopword check lives in :func:`is_plausible_person_name`.
# :func:`name_suspicion_penalty` scores the greyer cases for downstream
# confidence adjustment.
_NAVIGATION_TOKENS: frozenset[str] = frozenset(
    {
        # ── Category 1: Cloud & vendor product / platform names ──────────
        "azure",
        "aws",
        "gcp",
        "google",
        "microsoft",
        "oracle",
        "salesforce",
        "cisco",
        "vmware",
        "redhat",
        "ibm",
        "kubernetes",
        "k8s",
        "docker",
        "docker",
        "terraform",
        "ansible",
        "jenkins",
        "gitlab",
        "github",
        "jira",
        "confluence",
        "splunk",
        "datadog",
        "pagerduty",
        "cloudflare",
        "fastly",
        "snowflake",
        "databricks",
        "elastic",
        "elasticsearch",
        "mongodb",
        "postgres",
        "postgresql",
        "redis",
        "kafka",
        "airflow",
        "grafana",
        "prometheus",
        "vault",
        "consul",
        "nomad",
        "argocd",
        "helm",
        "istio",
        "envoy",
        "linkerd",
        "linux",
        "python",
        "devops",
        "ceh",
        # ── Category 2: Certification & training terms ────────────────────
        "cert",
        "certified",
        "certification",
        "certifications",
        "microcredential",
        "credential",
        "credentials",
        "specialization",
        "specializations",
        "associate",
        "professional",
        "practitioner",
        "expert",
        "master",
        "foundation",
        "fundamentals",
        "essentials",
        "bootcamp",
        "academy",
        "institute",
        "school",
        "training",
        "course",
        "courses",
        "curriculum",
        "learning",
        "learner",
        "enrollment",
        "cohort",
        "lab",
        "labs",
        "sandbox",
        "workshop",
        "webinar",
        "masterclass",
        "instructor",
        "self-paced",
        # Named cert acronyms
        "comptia",
        "cissp",
        "cism",
        "cisa",
        "crisc",
        "cgeit",
        "pmp",
        "capm",
        "prince2",
        "itil",
        "togaf",
        "cobit",
        "ccna",
        "ccnp",
        "ccie",
        "mcsa",
        "mcse",
        "mcsd",
        "rhce",
        "rhcsa",
        "lpic",
        "lfcs",
        "lfce",
        # ── Category 3: Microsoft stack specifics ──────────────────────────
        "dynamics",
        "powerbi",
        "powerapps",
        "powerautomate",
        "dataverse",
        "fabric",
        "copilot",
        "entra",
        "defender",
        "sentinel",
        "purview",
        "intune",
        "endpoint",
        "sharepoint",
        "teams",
        "onedrive",
        "exchange",
        "activedirectory",
        "azuread",
        # ── Category 4: Marketing & navigation phrases ────────────────────
        "learn",
        "growing",
        "grow",
        "transform",
        "transforming",
        "discover",
        "discovering",
        "journey",
        "experience",
        "experiences",
        "engineered",
        "trusted",
        "proven",
        "simple",
        "secure",
        "flexible",
        "scalable",
        "reliable",
        "innovative",
        "innovation",
        "solutions",
        "services",
        "platform",
        "platforms",
        "product",
        "products",
        "offering",
        "offerings",
        "capability",
        "capabilities",
        "resource",
        "resources",
        "guide",
        "guides",
        "overview",
        "introduction",
        "advanced",
        "beginner",
        "intermediate",
        # ── Category 5: Geographic & page-furniture terms ─────────────────
        "north",
        "south",
        "east",
        "west",
        "northeast",
        "northwest",
        "southeast",
        "southwest",
        "americas",
        "emea",
        "apac",
        "global",
        "regional",
        "international",
        "worldwide",
        "domestic",
        "local",
        "national",
        "login",
        "signin",
        "signup",
        "register",
        "registration",
        "subscribe",
        "unsubscribe",
        "newsletter",
        "portal",
        "dashboard",
        "console",
        "panel",
        "admin",
        "settings",
        "profile",
        "account",
        "billing",
        "pricing",
        "plans",
        "features",
        "benefits",
        "testimonials",
        "customers",
        "partners",
        "careers",
        "jobs",
        "hiring",
        "recruitment",
        "newsroom",
        "press",
        "events",
        "forum",
        "podcast",
        "webcast",
        "livestream",
        "download",
        "downloads",
        "documentation",
        "docs",
        "helpdesk",
        "faq",
        "contact",
        "about",
        "management",
        # ── Retained legacy terms (infrastructure / business / UI) ────────
        "network",
        "cloud",
        "technology",
        "infrastructure",
        "architecture",
        "control",
        "monitoring",
        "insights",
        "center",
        "community",
        "newsroom",
        "media",
        "analytics",
        "enterprise",
        "security",
        "app",
        "prep",
        "skills",
        "path",
        "paths",
        "action",
        "built",
        "branch",
        "banking",
        "financial",
        "application",
        "availability",
        "career",
        "news",
        "event",
        "events",
    }
)

# Same idea — when the *entire input string* matches one of these words,
# it cannot be a person name.
_NON_NAME_WORDS: frozenset[str] = frozenset(
    {
        "home",
        "about",
        "team",
        "our",
        "people",
        "leadership",
        "staff",
        "board",
        "careers",
        "jobs",
        "press",
        "contact",
        "company",
        "blog",
        "news",
        "legal",
        "privacy",
        "policy",
        "support",
        "help",
        "login",
        "signup",
        "join",
        "menu",
        "search",
        "language",
        "english",
        "french",
        "spanish",
        "german",
        "italian",
        "portuguese",
        "chinese",
        "japanese",
        "korean",
        "russian",
        "arabic",
        "hindi",
        # Footer / legalese phrases that often appear title-cased.
        "rights",
        "reserved",
        "all",
        "and",
        "or",
        "the",
        "reserved",
        "copyright",
        "policy",
        "cookies",
        "terms",
        "conditions",
        "subscribe",
        "unsubscribe",
        "follow",
        "share",
    }
)


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------
def is_plausible_person_name(text: str) -> bool:
    """Cheap pre-filter for raw extracted name strings.

    Returns ``True`` only for strings that look like a real person's
    display name: 2–4 capitalised tokens, no digits, total length
    4–50, not in the stoplist, not equal to a known non-name word.
    """
    if not isinstance(text, str):
        return False

    cleaned = text.strip()
    if not cleaned:
        return False
    # Length floor of 2 — single-character tokens are too noise-prone
    # but valid CJK family-name-only names (e.g. "李") and Latin
    # "Ed Lee" survive.  Latin-only names additionally need 4 chars
    # to pass the Latin path's structural check below; non-Latin
    # paths accept the shorter ground floor.
    if len(cleaned) < 2 or len(cleaned) > 50:
        return False

    # Reject digits explicitly — JS/CSS noise slips through with
    # numeric suffix, and "1.2.3 Name" patterns from build artifacts
    # are common in HTML dumps.
    if any(ch.isdigit() for ch in cleaned):
        return False

    lower = cleaned.lower()
    if lower in _NAV_FOOTER_STOPLIST:
        return False

    # Single non-name word like "Home" / "Team" / "Leadership".
    if lower in _NON_NAME_WORDS:
        return False

    # Two complementary paths — Latin (requires whitespace) and
    # non-Latin (CJK allows whitespace-less runs).  The non-Latin
    # path is the only way "王小明" without spaces can pass; mixed
    # strings ("John 王小明") correctly fall through both.
    if _LATIN_PERSON_RE.match(cleaned):
        tokens = [t for t in cleaned.split() if t]
        if tokens:
            token_count = len(tokens)
            # Apply the same Phase 4 ALL-stopwords rule to role words.
            # "Chief Executive Officer" → all 3 tokens role words → reject.
            # "Chief John Smith" → 1 role word / 3 tokens → 33 % → allowed
            #   (penalty applied downstream by name_suspicion_penalty).
            role_suspicious = [
                t.lower().strip(".,;:'-")
                for t in tokens
                if t.lower().strip(".,;:'-") in _ROLE_WORDS
            ]
            role_suspicious_count = len(role_suspicious)
            if role_suspicious_count == token_count:
                return False
            if token_count >= 3 and role_suspicious_count / token_count >= 0.5:
                return False
            if tokens[0].lower().strip(".,;:'-") in _NON_NAME_WORDS:
                return False
            # Reject candidates whose AVERAGE token length is below 4
            # characters.  Real first / last names in Latin script
            # average 5-6 chars; nav fragments like "Can Fix Here"
            # (3 / 3 / 4 = 3.33 avg) and "Cert Prep Want" (4 / 4 / 4
            # = 4.0 avg) typically have shorter tokens.  We use a
            # STRICT less-than check so 4.0 averages ("Cert Prep
            # Want") are still accepted by this rule alone — the
            # token-level navigation-token check below then catches
            # them.
            total_chars = sum(len(t) for t in tokens)
            avg_len = total_chars / len(tokens)
            if avg_len < 4:
                return False
            # Reject candidates that contain an ALL-CAPS token of
            # length > 3 (likely acronym / abbreviation such as
            # "AWS", "GCP", "CISSP", "CEH", "Python" — wait, Python
            # is title-cased so it doesn't trip this, but acronyms
            # do).  A single fully-uppercase token in a multi-word
            # candidate is a strong signal of a product / cert name
            # mixed into the text, not a person name component.
            for token in tokens:
                cleaned_token = token.strip(".,;:'-")
                if (
                    len(cleaned_token) > 3
                    and cleaned_token.isalpha()
                    and cleaned_token.isupper()
                ):
                    return False
            # Phase 4 navigation-token rejection rule:
            #   REJECT if ALL tokens are in _NAVIGATION_TOKENS
            #   OR if >= 50 % tokens are in _NAVIGATION_TOKENS in a 3+ token name
            #   ALLOW (pass through, penalized later by name_suspicion_penalty)
            #     if only ONE token is suspicious in a 2-token name
            #     (e.g. "Azure Smith" — Azure is a real first name for some people)
            suspicious_tokens = [
                t.lower().strip(".,;:'-")
                for t in tokens
                if t.lower().strip(".,;:'-") in _NAVIGATION_TOKENS
            ]
            token_count = len(tokens)
            suspicious_count = len(suspicious_tokens)
            if suspicious_count == token_count:
                return False
            if token_count >= 3 and suspicious_count / token_count >= 0.5:
                return False
        return True
    if _NONLATIN_PERSON_RE.match(cleaned):
        # Reject mixed scripts by checking there's at least one
        # alphabetic non-Latin character, and the alphabetic content
        # is *only* non-Latin (so we don't conflate "Joseph 王" with
        # a pure CJK name).
        has_latin = False
        has_non_latin_alpha = False
        for ch in cleaned:
            if ch.isspace():
                continue
            if ch.isalpha():
                if (
                    "A" <= ch <= "Z"
                    or "a" <= ch <= "z"
                    or "À" <= ch <= "ɏ"
                    or "Ḁ" <= ch <= "ỿ"
                ):
                    has_latin = True
                else:
                    has_non_latin_alpha = True
        return has_non_latin_alpha and not has_latin

    return False


def name_suspicion_penalty(name: str) -> float:
    """Return a confidence penalty multiplier (0.0–1.0) for a candidate name.

    Phase 4 introduces a suspicion-score layer between the binary
    ``is_plausible_person_name`` pass and the confidence scoring in
    :mod:`backend.modules.employee_name_discovery`.  The idea is:

      - Fully clean names  → 1.0  (no penalty)
      - One suspicious token in a 2-token name  → 0.6  (e.g. "Azure Smith")
      - Minority suspicious in a 3+ token name  → 0.8  (e.g. "John Cloud Wilson")
      - All tokens suspicious  → 0.0  (reject; ``is_plausible_person_name``
        already returned False for these, but callers that skip that check
        get the zero here)
      - Majority suspicious in a 3+ token name  → 0.0  (reject)

    The combined stopword set for this function includes both
    ``_NAVIGATION_TOKENS`` and ``_ROLE_WORDS``.
    """
    if not isinstance(name, str):
        return 1.0

    tokens = [t.lower().strip(".,;:'-") for t in name.split()]
    if not tokens:
        return 1.0

    suspicious_count = sum(
        1
        for t in tokens
        if t in _NAVIGATION_TOKENS or t in _ROLE_WORDS
    )
    total = len(tokens)

    if suspicious_count == 0:
        return 1.0
    if suspicious_count == total:
        return 0.0
    if total >= 3 and suspicious_count / total >= 0.5:
        return 0.0
    if suspicious_count == 1 and total == 2:
        return 0.6
    return 0.8


def _accent_count(s: str) -> int:
    """Number of Unicode combining marks (accents, diacritics) in *s*."""
    return sum(1 for c in unicodedata.normalize("NFD", s) if unicodedata.combining(c))


def dedupe_names(names: list[str]) -> list[str]:
    """Phase 4 improved dedup with four capabilities:

    1. Case-insensitive dedup (original behaviour).
    2. Apostrophe / hyphen / period normalisation for canonical-key
       building: "O'Brien" / "Obrien" share a key;
       "Mary-Jane Watson" / "Mary Jane Watson" share a key;
       "John D. Smith" / "John Smith" share a key.
       (Periods are stripped so initials don't create spurious
       distinct entries.)
    3. Longer / more-complete form preferred when resolving duplicates:
       "John D. Smith" beats "John Smith"; "María García" beats
       "Maria Garcia".
    4. Names with ``name_suspicion_penalty() == 0.0`` are silently
       dropped — they have already been rejected and should not appear
       in the dedup pool.

    We deliberately don't do fuzzy / token-set matching here — that
    complexity belongs to :mod:`backend.core.name_consensus`.  This is a
    cheap pre-aggregation filter only.
    """
    # Normalisation targets the characters that create variant spellings
    # of the same person.  Periods are included so "John D. Smith"
    # and "John Smith" share the same dedup key.
    _NORM_PUNCT = str.maketrans("", "", ".'-")

    def _norm_key(s: str) -> str:
        """Canonical dedup key: lowercase, whitespace collapsed, variant
        punctuation stripped, accents normalised."""
        # Replace hyphens with spaces before normalising so "Mary-Jane"
        # and "Mary Jane" produce the same key.
        no_hyphen = s.replace("-", " ")
        stripped = no_hyphen.strip().translate(_NORM_PUNCT)
        # NFD decomposes e.g. "á" into "a" + combining acute; filtering out
        # combining marks makes "María" and "Maria" share a key.
        no_accents = unicodedata.normalize("NFD", stripped)
        ascii_only = "".join(c for c in no_accents if not unicodedata.combining(c))
        return re.sub(r"\s+", " ", ascii_only).lower()

    canonical: dict[str, str] = {}
    order: list[str] = []
    for raw in names:
        if not isinstance(raw, str):
            continue
        cleaned = re.sub(r"\s+", " ", raw.strip())
        if not cleaned:
            continue
        # Drop names already condemned by the suspicion penalty.
        if name_suspicion_penalty(cleaned) == 0.0:
            continue
        key = _norm_key(cleaned)
        if key not in canonical:
            canonical[key] = cleaned
            order.append(key)
        else:
            existing = canonical[key]
            # Prefer the longer / better-formed form.  Use total char count as
            # primary key; if tied (e.g. "Maria Garcia" vs "María García" — both
            # 12 code points) prefer the one with more Unicode diacritical marks,
            # which is the richer spelling.
            existing_score = (len(existing), _accent_count(existing))
            cleaned_score = (len(cleaned), _accent_count(cleaned))
            if cleaned_score > existing_score:
                canonical[key] = cleaned

    return [canonical[key] for key in order]


def matches_domain(text: str, domain: str) -> bool:
    """Return True when *text* is identical to *domain* or its registrable part.

    Used by callers to drop names like "Acme" / "acme com" that are
    just the company/domain appearing in the title field of a
    LinkedIn result.
    """
    if not isinstance(text, str) or not isinstance(domain, str):
        return False
    cleaned = text.strip().lower()
    domain_clean = domain.strip().lower()
    if not cleaned or not domain_clean:
        return False
    if cleaned == domain_clean:
        return True
    # Strip TLD and re-check.
    parts = domain_clean.rsplit(".", 1)
    registrable = parts[0] if len(parts) == 2 else domain_clean
    return cleaned == registrable
