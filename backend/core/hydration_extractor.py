"""Hydration extractor — pull employee metadata from SSR framework state.

The harvest loop fetches HTML for team / about / leadership pages; many
of those pages render server-side, and the data behind the rendered DOM
is sitting right there in the page source as a JSON payload injected
by the framework's hydration layer.  A headless browser would re-render
it, but we can skip that step entirely and parse the payload directly.

Five framework targets are supported:

* **Next.js Pages Router** — ``<script id="__NEXT_DATA__">…</script>``
* **Next.js App Router**  — ``self.__next_f.push(…)`` RSC chunks
* **Nuxt**                — ``window.__NUXT__ = {…}`` (Nuxt 2) and
                              ``<script type="application/json">…</script>``
                              blocks (Nuxt 3)
* **Remix**               — ``window.__remixContext = {…}``
* **SvelteKit**           — ``<script type="application/json">…</script>``

Extraction is pure: the module takes raw bytes (decoded as UTF-8 with
replacement for the rare non-UTF-8 page) and an
:class:`~backend.core.signal_pool.AsyncSignalPool` reference, locates
each framework's payload blocks via stdlib regex, parses them with
:mod:`json`, walks the resulting object graph recursively (depth-capped
at 12 plus an ``id(node)`` visited set to prevent cyclic explosions),
identifies person-shaped sub-trees by a ≥2-of-4 key heuristic, and
publishes one or more :class:`~backend.core.signal_pool.Signal` records
per hit into the pool.

No DOM parser, no BeautifulSoup — the spec requires the stdlib
(``re``, ``json``, ``html.unescape``) only.  Microdata / hCard / JSON-LD
on the same page are handled by
:mod:`backend.core.structured_data_extractor`; this module is the
parallel path for framework hydration payloads.

Integration
-----------

A typical call site looks like::

    pool = AsyncSignalPool()
    extractor = HydrationDataExtractor(pool)
    count = await extractor.extract_from_html(
        html_bytes, page_url="https://example.com/team"
    )

Each person hit becomes 1-3 signals — always a ``name`` signal (when a
name could be located) and optionally an ``email`` signal and a
``schema`` signal carrying the raw dictionary for downstream consumers.
All signals from a single hit share the same ``name`` and
``slug_or_email`` metadata so
:class:`~backend.core.signal_pool.AsyncSignalPool`'s canonical-key
cluster logic folds them onto the same
:class:`~backend.core.signal_pool.CandidatePerson`.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from html import unescape
from typing import Any

from .name_quality import is_plausible_person_name
from .signal_normalize import normalize_slug_or_email
from .signal_pool import AsyncSignalPool, Signal

_LOG = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# Public constants — also exposed for callers that want to tag their own
# payloads or filter by framework.
# ----------------------------------------------------------------------

FRAMEWORK_NEXT_PAGES = "next_pages"
FRAMEWORK_NEXT_APP = "next_app"
FRAMEWORK_NUXT = "nuxt"
FRAMEWORK_REMIX = "remix"
FRAMEWORK_SVELTEKIT = "sveltekit"

#: Hard cap on recursive walk depth.  Real hydration payloads rarely
#: exceed 6-8 levels; the cap is a safety net so a maliciously deep
#: payload (or a payload with a self-reference) cannot wedge the worker.
MAX_DEPTH = 12

#: Per-frame avatar/bio-first URL extracted from ``sameAs`` / ``avatar`` /
#: ``image`` / ``photo`` keys.  Ordered by specificity — first hit wins.
_BIO_KEYS = ("bio", "avatar", "image", "photo", "sameAs", "description")
#: Name-shaped keys.  Both camelCase and PascalCase aliases are common
#: in JSON-LD (``givenName`` / ``familyName``).
_NAME_KEYS = (
    "name",
    "displayName",
    "fullName",
    "firstName",
    "lastName",
    "givenName",
    "familyName",
    "given_name",
    "family_name",
    "nickname",
)
#: Role-shaped keys whose values are unambiguously the person's role.
#: ``title`` is treated separately because it overlaps with article /
#: post / position titles in unrelated contexts.
_ROLE_KEYS_STRICT = ("jobTitle", "role", "department", "position", "worksFor")
#: ``title`` counts as role only when it is a non-empty string.  When it
#: is a dict (a schema.org CreativeWork, say) it does not count.
_TITLE_KEY = "title"

#: Subtitle-shaped key used by INE.com instructor cards.  On INE the
#: ``title`` of a card is the instructor's display name and the
#: ``subtitle`` is their job title / role — the opposite of the standard
#: convention.  Detected via :func:`is_plausible_person_name` on the
#: title value to keep the heuristic from firing on other "title +
#: subtitle" patterns (e.g. blog post teasers) that share the same
#: key layout.
_SUBTITLE_KEY = "subtitle"

#: Email-shaped keys.  Domain-specific aliases (``work_email`` /
#: ``contact_email``) come from real-world hydration dumps where the
#: framework lets the developer override the field name.
_EMAIL_KEYS = ("email", "work_email", "contact_email", "workEmail")

#: Cap on input HTML size before we give up on regex extraction.  Real
#: team pages are well under 1 MB; anything past this is almost
#: certainly not a team page (or it's a misconfigured HTML dump) and
#: the regex pass is the wrong place to defend against memory pressure.
_MAX_HTML_BYTES = 8 * 1024 * 1024


# ----------------------------------------------------------------------
# Regex patterns
# ----------------------------------------------------------------------

#: Legacy Next.js Pages Router hydration payload.  Whole script body
#: is the JSON document.
_NEXT_DATA_SCRIPT_RE = re.compile(
    r'<script\b[^>]*\bid\s*=\s*["\']__NEXT_DATA__["\']'
    r"[^>]*>(?P<body>.*?)</script>",
    flags=re.IGNORECASE | re.DOTALL,
)

#: Next.js App Router streaming push calls.  Each chunk is the
#: argument list passed to ``self.__next_f.push(…)``; the second
#: element is typically an escaped JSON-ish blob.
_NEXT_F_PUSH_RE = re.compile(
    r"self\.__next_f\.push\(\s*(?P<args>.*?)\s*\)\s*;?",
    flags=re.DOTALL,
)

#: Nuxt 2 hydration marker — the assignment to ``window.__NUXT__``.
#: We capture the ``{`` position and run a brace matcher forward to
#: handle arbitrarily-nested objects and arrays (regex cannot).
_NUXT_ASSIGN_RE = re.compile(
    r"window\.__NUXT__\s*=\s*(?P<open>\{)",
    flags=re.IGNORECASE,
)

#: Remix hydration marker — ``window.__remixContext = {…}``.
_REMIX_ASSIGN_RE = re.compile(
    r"window\.__remixContext\s*=\s*(?P<open>\{)",
    flags=re.IGNORECASE,
)

#: Generic ``<script type="application/json">…</script>`` block.  Used
#: by Nuxt 3, SvelteKit, and any framework that emits raw JSON inline.
#: We feed the body straight through :func:`json.loads` — these blocks
#: are always well-formed JSON.
_APP_JSON_SCRIPT_RE = re.compile(
    r"<script\b[^>]*\btype\s*=\s*[\"']application/json[\"'][^>]*>"
    r"(?P<body>.*?)</script>",
    flags=re.IGNORECASE | re.DOTALL,
)


# ----------------------------------------------------------------------
# Person-hit DTO + extractor class
# ----------------------------------------------------------------------
@dataclass(slots=True)
class PersonHit:
    """One raw person-shaped sub-tree located inside a hydration payload.

    This is the in-flight representation before signals are built.  Once
    the wrapping :class:`HydrationDataExtractor` publishes Signals into
    the pool, each Signal carries the same ``name`` + ``slug_or_email``
    metadata so the pool's :func:`canonical_key` collapses the bundle
    onto a single :class:`~backend.core.signal_pool.CandidatePerson`.

    Fields
    ------

    framework:
        One of :data:`FRAMEWORK_NEXT_PAGES`, :data:`FRAMEWORK_NEXT_APP`,
        :data:`FRAMEWORK_NUXT`, :data:`FRAMEWORK_REMIX`,
        :data:`FRAMEWORK_SVELTEKIT`.  Carried into the ``schema``
        signal's metadata so downstream filters can scope by framework.
    name:
        Best-effort display name.  None when no name-shaped key resolved.
    role:
        Best-effort role string.  None when no role-shaped key resolved.
    email:
        Best-effort email address (already trimmed of ``mailto:`` /
        query-string junk; lower-cased before publishing).  None when
        no email-shaped key resolved.
    bio_url:
        First non-empty URL-shaped value found in the bio-shaped keys
        (``sameAs`` / ``avatar`` / ``image`` / ``photo``).
    avatar:
        Convenience alias for ``bio_url`` when the source key was
        ``avatar`` / ``image`` / ``photo``.  Kept separate from
        ``bio_url`` so callers can distinguish profile-picture-style
        URLs from generic ``sameAs`` social links.
    raw:
        The original sub-tree as a Python dict, preserved so the
        ``schema`` signal can carry the full payload for downstream
        consumers that want richer fields than the heuristic picked up.
    page_url:
        The URL the HTML came from — recorded so the Signal metadata
        stays useful even when the caller threads multiple pages through
        one pool.
    """

    framework: str
    name: str | None = None
    role: str | None = None
    email: str | None = None
    bio_url: str | None = None
    avatar: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    page_url: str = ""

    # The dedup key is shared across all signals of this hit.  Stable
    # within an extraction call so the pool clusters every signal of
    # the same person on the same :class:`CandidatePerson`.
    dedup_key: tuple[str | None, str | None] = field(default_factory=lambda: (None, None))


class HydrationDataExtractor:
    """Find person-shaped sub-trees in framework hydration payloads and
    publish Signal records to the pool.

    Parameters
    ----------

    pool:
        The :class:`~backend.core.signal_pool.AsyncSignalPool` to
        publish into.  Required.
    source_name:
        The module name recorded on every Signal published
        (``Signal.source``).  Defaults to ``"hydration_extractor"`` —
        match the convention used by the other platform-extraction
        modules (see ``structured_data_extractor`` callers).
    """

    def __init__(
        self,
        pool: AsyncSignalPool,
        *,
        source_name: str = "hydration_extractor",
    ) -> None:
        if pool is None:
            raise ValueError("HydrationDataExtractor requires a non-None AsyncSignalPool")
        self._pool = pool
        self._source = source_name

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def extract_from_html(
        self,
        html: bytes | str | None,
        *,
        page_url: str = "",
    ) -> int:
        """Parse *html* and publish every person-shaped hit to the pool.

        Returns the number of person hits published.  A return value of
        zero is normal — hydration payloads are present only on SSR
        pages, and many SSR pages still don't carry person data.
        """
        hits = self.find_hits_from_html(html, page_url=page_url)

        if not hits:
            return 0
        await self._publish_hits(hits)
        return len(hits)

    @classmethod
    def find_hits_from_html(
        cls,
        html: bytes | str | None,
        *,
        page_url: str = "",
    ) -> list[PersonHit]:
        """Return hydration person hits without requiring a signal pool.

        The harvest company-page path needs the same person records as the
        signal-pool integration, but it already has its own ``PersonRecord``
        aggregation.  Keeping this pure adapter avoids creating a temporary
        pool for every fetched page.
        """
        if html is None:
            return []
        extractor = cls.__new__(cls)
        text = extractor._decode(html)
        if not text:
            return []
        payloads = list(extractor._collect_payloads(text))
        if not payloads:
            return []

        hits: list[PersonHit] = []
        seen_keys: set[tuple[str | None, str | None]] = set()
        for framework, payload in payloads:
            for hit in extractor._walk(payload, framework):
                if hit.dedup_key in seen_keys or hit.dedup_key == (None, None):
                    continue
                seen_keys.add(hit.dedup_key)
                if page_url:
                    hit.page_url = page_url
                hits.append(hit)
        return hits

    # ------------------------------------------------------------------
    # Payload extraction (one entry per framework)
    # ------------------------------------------------------------------

    def _collect_payloads(self, text: str) -> Iterable[tuple[str, Any]]:
        """Yield ``(framework, payload_object)`` tuples.

        Each framework contributes zero or one *successful* payloads.
        Failures (regex match but malformed JSON / unbalanced braces)
        are logged and skipped — never raised — so a single broken
        payload on the page cannot stop the others.
        """

        # 1. Next.js Pages Router — single large JSON document.
        for match in _NEXT_DATA_SCRIPT_RE.finditer(text):
            body = (match.group("body") or "").strip()
            parsed = _safe_loads(body)
            if parsed is not None:
                yield FRAMEWORK_NEXT_PAGES, parsed

        # 2. Next.js App Router — every push call is its own payload.
        # Most pushes parse as a JSON array (e.g. ``[1,"…"]``); some
        # are escaped strings (``"1:H4s…"``); many are HTML/JSX that
        # fails to parse and is skipped silently.
        for match in _NEXT_F_PUSH_RE.finditer(text):
            args = (match.group("args") or "").strip()
            parsed = _safe_loads(args)
            if parsed is None:
                continue
            # The shape inside a push is heterogeneous — sometimes an
            # array, sometimes a string, sometimes the data is two
            # levels deep.  Walk whatever we got and let the recursion
            # find the person nodes wherever they live.
            yield FRAMEWORK_NEXT_APP, parsed

        # 3. Nuxt 2 — ``window.__NUXT__ = {…}``.
        for match in _NUXT_ASSIGN_RE.finditer(text):
            start = match.start("open")
            literal = _balanced_json_slice(text, start)
            if literal is None:
                continue
            parsed = _safe_loads(literal)
            if parsed is not None:
                yield FRAMEWORK_NUXT, parsed

        # 4. Remix — ``window.__remixContext = {…}``.
        for match in _REMIX_ASSIGN_RE.finditer(text):
            start = match.start("open")
            literal = _balanced_json_slice(text, start)
            if literal is None:
                continue
            parsed = _safe_loads(literal)
            if parsed is not None:
                yield FRAMEWORK_REMIX, parsed

        # 5. SvelteKit / Nuxt 3 — ``<script type="application/json">``.
        for match in _APP_JSON_SCRIPT_RE.finditer(text):
            body = (match.group("body") or "").strip()
            if not body:
                continue
            parsed = _safe_loads(body)
            if parsed is None:
                continue
            # We can't always tell which framework emitted a generic
            # ``application/json`` block; prefer SvelteKit since that's
            # the more common emitter when no other marker is present.
            yield FRAMEWORK_SVELTEKIT, parsed

    # ------------------------------------------------------------------
    # Recursive walker
    # ------------------------------------------------------------------

    def _walk(
        self,
        node: Any,
        framework: str,
        depth: int = 0,
        visited: set[int] | None = None,
    ) -> Iterable[PersonHit]:
        """Yield :class:`PersonHit` records from *node*.

        Recursive — capped at :data:`MAX_DEPTH` and protected from
        cycles via ``id(node)`` membership in *visited*.
        """
        if depth > MAX_DEPTH:
            return
        if visited is None:
            visited = set()
        if isinstance(node, dict):
            node_id = id(node)
            if node_id in visited:
                return
            visited.add(node_id)
            hit = self._classify(node, framework)
            if hit is not None:
                yield hit
            for value in node.values():
                yield from self._walk(value, framework, depth + 1, visited)
        elif isinstance(node, list):
            for item in node:
                yield from self._walk(item, framework, depth, visited)

    # ------------------------------------------------------------------
    # Heuristic classifier
    # ------------------------------------------------------------------

    def _classify(self, node: dict[str, Any], framework: str) -> PersonHit | None:
        """Return a :class:`PersonHit` when *node* matches the
        ≥2-of-4 person heuristic, otherwise ``None``.

        The four signal groups are name-shaped, role-shaped,
        email-shaped, and bio-shaped.  Each is "present" when its key
        set contains at least one key whose value is a non-empty
        string (or, for ``sameAs`` etc., a non-empty string-or-list).
        """
        name_value = _first_string(node, _NAME_KEYS)
        role_value = _first_string(node, _ROLE_KEYS_STRICT)

        # INE.com instructor card shape: ``title`` is the person's name
        # and ``subtitle`` is their role.  We activate this path only
        # when the title value passes :func:`is_plausible_person_name`
        # so a generic "title + subtitle" pair (e.g. blog post teasers)
        # does not get misclassified as a person.
        # NOTE: ``_string_at`` expects an iterable of key names — passing
        # the bare ``_TITLE_KEY`` string would iterate over the
        # characters of the word "title" and never match the actual
        # key.  This bug silently disabled the ``title`` role-fallback
        # path; fixing it here also makes the INE-style detection work.
        title_str = _string_at(node, (_TITLE_KEY,))
        subtitle_str = _string_at(node, (_SUBTITLE_KEY,))
        ine_name: str | None = None
        ine_role: str | None = None
        if title_str and subtitle_str and is_plausible_person_name(title_str):
            ine_name = title_str
            ine_role = subtitle_str

        if name_value is None:
            name_value = ine_name
        if role_value is None:
            # Prefer the INE-style subtitle over the ambiguous ``title``
            # fallback so an INE card gets a real role string instead of
            # re-using the instructor's name.
            role_value = ine_role or title_str
        email_value = _string_at(node, _EMAIL_KEYS)
        bio_value = _bio_value(node)

        # Count distinct groups hit (max 4).  The threshold is 2 — a
        # node with just a name and nothing else is too noisy to be a
        # person hit on its own; one with name + role or name + email
        # is reliable.
        groups = sum(
            1
            for value in (name_value, role_value, email_value, bio_value)
            if value is not None
        )
        if groups < 2:
            return None

        # ``bio_url`` carries the most useful "social-link-style" URL
        # we found across any bio-shaped key (``sameAs``, ``avatar``,
        # ``image``, ``photo``).  We prefer URL-shaped values over
        # prose bios so the Signal metadata has something a downstream
        # consumer can actually dereference.  Falls back to the prose
        # ``bio`` / ``description`` text when no URL was found.
        bio_url = _bio_url(node)
        # ``avatar`` is separate — strictly an ``avatar`` / ``image`` /
        # ``photo`` URL, useful for downstream per-cluster avatar
        # clustering.  Independent of ``bio_url`` so a person with
        # only an ``avatar`` URL still surfaces a non-empty avatar.
        avatar = _avatar_url(node)

        # Build the dedup key — the pool re-uses
        # :func:`canonical_key` / :func:`normalize_slug_or_email`
        # under the hood, so feeding the same strings through here
        # produces the same key the pool will compute.
        norm_email = normalize_slug_or_email(email_value or "")
        if norm_email:
            slug = norm_email
        else:
            slug = normalize_slug_or_email(name_value or "")
        # None for the empty slot so the pool's "(None, None) -> skip"
        # rule doesn't mistake our nobody for a real candidate.
        if name_value:
            from .signal_normalize import normalize_name

            canon_name = normalize_name(name_value) or None
        else:
            canon_name = None
        slug_or_email: str | None = slug if slug else None
        dedup_key: tuple[str | None, str | None] = (canon_name, slug_or_email)

        return PersonHit(
            framework=framework,
            name=name_value,
            role=role_value,
            email=(email_value.lower() if email_value else None),
            bio_url=bio_url,
            avatar=avatar,
            raw=dict(node),
            page_url="",
            dedup_key=dedup_key,
        )

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------

    async def _publish_hits(self, hits: list[PersonHit]) -> None:
        """Publish every :class:`Signal` derived from *hits* via
        :meth:`AsyncSignalPool.publish_many`.

        Each hit contributes 1-3 signals:

        * **name** signal — always when :attr:`PersonHit.name` is set.
        * **email** signal — when :attr:`PersonHit.email` is set.
        * **schema** signal — always (carries the raw dictionary so
          downstream consumers can re-extract fields the heuristic
          missed).

        All signals from a single hit share the same ``name`` +
        ``slug_or_email`` metadata so the pool's cluster logic folds
        them onto the same :class:`CandidatePerson`.
        """
        signals: list[Signal] = []
        for hit in hits:
            signals.extend(self._signals_for_hit(hit))
        if not signals:
            return
        await self._pool.publish_many(signals)

    def _signals_for_hit(self, hit: PersonHit) -> Iterable[Signal]:
        name = hit.name or ""
        meta = {
            "name": name or None,
            "slug_or_email": hit.dedup_key[1] or None,
            "framework": hit.framework,
            "page_url": hit.page_url or None,
            "person": hit.raw,
        }
        if hit.name:
            yield Signal(
                source=self._source,
                kind="name",
                value=hit.name,
                metadata=meta,
            )
        if hit.email:
            # Same metadata so the name + email signals cluster together.
            yield Signal(
                source=self._source,
                kind="email",
                value=hit.email,
                metadata=meta,
            )
        # Always emit the schema signal — it carries the raw payload so
        # downstream consumers can re-extract fields the heuristic missed.
        if hit.name or hit.email:
            yield Signal(
                source=self._source,
                kind="schema",
                value=hit.name or hit.email or hit.framework,
                metadata=meta,
            )

    # ------------------------------------------------------------------
    # Decoding
    # ------------------------------------------------------------------

    @staticmethod
    def _decode(html: bytes | str) -> str:
        """Decode *html* to text.

        ``str`` inputs pass through with HTML entities unescaped (so
        the regexes see ``__NEXT_DATA__`` rather than
        ``__NEXT_DATA__``).  ``bytes`` inputs are decoded as UTF-8 with
        replacement so a page with one bad byte doesn't blow up the
        worker.  Anything past :data:`_MAX_HTML_BYTES` is truncated
        with a warning — the regex still finds the script-block opener
        because all five targets land at the top of the page, but
        truly enormous pages are an unrealistic target for OSINT.
        """
        if isinstance(html, str):
            decoded = unescape(html)
        elif isinstance(html, bytes | bytearray):
            raw = bytes(html)
            if len(raw) > _MAX_HTML_BYTES:
                _LOG.warning(
                    "hydration_extractor: truncating %d-byte HTML payload to %d bytes",
                    len(raw),
                    _MAX_HTML_BYTES,
                )
                raw = raw[:_MAX_HTML_BYTES]
            decoded = raw.decode("utf-8", errors="replace")
            decoded = unescape(decoded)
        else:
            return ""
        return decoded


# ----------------------------------------------------------------------
# Module-level helpers — pure functions, no instance state.
# ----------------------------------------------------------------------
def _safe_loads(body: str) -> Any | None:
    """Try ``json.loads(body)`` and return ``None`` on failure."""
    if not body:
        return None
    try:
        return json.loads(body)
    except (ValueError, TypeError):
        return None


def _balanced_json_slice(text: str, open_pos: int) -> str | None:
    """Return the substring of *text* corresponding to the balanced
    JSON literal starting at *open_pos* (which must point at ``{`` or
    ``[``), or ``None`` if the slice is unbalanced.

    Strings (delimited by ``"``) are skipped over so braces inside them
    don't confuse the counter.  Backslash escapes inside the string are
    honored so an embedded ``\\"`` doesn't terminate it early.

    Used for the ``window.__NUXT__ = {…}`` and ``window.__remixContext
    = {…}`` assignments, where the literal can contain arbitrarily
    nested objects and arrays — too much for a regex.
    """
    if open_pos < 0 or open_pos >= len(text):
        return None
    opener = text[open_pos]
    if opener not in "{[":
        return None
    stack: list[str] = []
    in_string = False
    escape = False
    for i in range(open_pos, len(text)):
        c = text[i]
        if in_string:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_string = False
            continue
        if c == '"':
            in_string = True
        elif c in "{[":
            stack.append(c)
        elif c in "}]":
            if not stack:
                return None
            opening = stack.pop()
            expected = "}" if opening == "{" else "]"
            if c != expected:
                return None
            if not stack:
                return text[open_pos : i + 1]
    return None


def _string_at(node: dict[str, Any], keys: Iterable[str]) -> str | None:
    """First non-empty string value among *keys*, or ``None``."""
    for key in keys:
        val = node.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def _first_string(node: dict[str, Any], keys: Iterable[str]) -> str | None:
    """Convenience alias for :func:`_string_at`."""
    return _string_at(node, keys)


def _bio_value(node: dict[str, Any]) -> str | None:
    """First non-empty string-or-list value across any bio-shaped key.

    Preserved for backward compatibility with the public module
    surface and for callers that want a generic bio blob.  Prefer
    :func:`_bio_url` for signal-publishing — it returns a URL when
    one is available.
    """
    for key in _BIO_KEYS:
        val = node.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item.strip():
                    return item.strip()
    return None


#: http/https prefix check used to discriminate URL values from bio
#: prose.  ``urlparse`` would be overkill here — we only need to skip
#: the prose and keep the URL.
_URL_PREFIX = ("http://", "https://")


def _first_url(val: Any) -> str | None:
    """First http(s) URL value in *val* (string or list)."""
    if isinstance(val, str):
        text = val.strip()
        if text and text.startswith(_URL_PREFIX):
            return text
        return None
    if isinstance(val, list):
        for item in val:
            if isinstance(item, str):
                text = item.strip()
                if text and text.startswith(_URL_PREFIX):
                    return text
    return None


def _bio_url(node: dict[str, Any]) -> str | None:
    """First URL-shaped value across the URL-preferring bio keys.

    Order: ``avatar`` / ``image`` / ``photo`` (typically image URLs),
    then ``sameAs`` and ``references`` (social/profile URL lists).
    These are the fields downstream consumers actually want.  Falls
    back to prose ``bio`` / ``description`` text when no URL was found
    so the :attr:`PersonHit.bio_url` field always carries *something*
    useful.
    """
    for key in ("avatar", "image", "photo", "sameAs", "references"):
        candidate = _first_url(node.get(key))
        if candidate:
            return candidate
    for key in ("bio", "description"):
        val = node.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def _avatar_url(node: dict[str, Any]) -> str | None:
    """First URL across ``avatar`` / ``image`` / ``photo`` only.

    Used to populate :attr:`PersonHit.avatar` — separate from
    :attr:`PersonHit.bio_url` because the per-cluster avatar
    clustering downstream of this module keys on avatar URLs alone,
    not on ``sameAs`` social handles.
    """
    for key in ("avatar", "image", "photo"):
        candidate = _first_url(node.get(key))
        if candidate:
            return candidate
    return None


__all__ = [
    "HydrationDataExtractor",
    "PersonHit",
    "FRAMEWORK_NEXT_PAGES",
    "FRAMEWORK_NEXT_APP",
    "FRAMEWORK_NUXT",
    "FRAMEWORK_REMIX",
    "FRAMEWORK_SVELTEKIT",
    "MAX_DEPTH",
]
