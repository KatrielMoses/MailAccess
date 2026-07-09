"""Extract person records from raw HTML using structured-data signals.

MailAccess 0.11.1 Phase 2 — Site Intelligence Rebuild.

Replaces the body-text regex approach used in
:mod:`backend.core.company_page_names` with a priority-ordered
ladder of structured-data extractors:

1. **JSON-LD Person**          (``@type=Person``)                — 0.90
2. **Microdata Person**        (``itemtype=schema.org/Person``)   — 0.85
3. **RDFa Person**             (``typeof=schema:Person``)        — 0.85
4. **hCard / vCard microformat**(``class="vcard"``)               — 0.80
5. **DOM team card pattern**   (image + heading + title repeat)  — 0.65
6. **Heading + adjacent title**(h2/h3/h4 followed by title text) — 0.55
7. **mailto: extraction**      (anchor href="mailto:...")        — 0.70 / 0.40
8. **Body-text name extraction** (existing pipeline, only with
   ``aggressive=True``)                                          — 0.30

The function is pure — no HTTP, no global state, no I/O.  It can
be reused on archive / Wayback content as well as live pages,
which is exactly how the orchestrator's Phase-2 call site uses it.

Why HTMLParser instead of nested regex:
    Microdata + RDFa + hCard all rely on the *containing* element
    having a marker (itemtype / typeof / class~="vcard") and the
    inner element having its own marker (itemprop / property /
    class~="fn").  Walking that requires real parse-tree access;
    regex on nested tags is a well-known footgun.  ``html.parser``
    is stdlib (matches the project's no-new-deps convention — see
    the comment at the top of ``backend.core.duckduckgo_dorker``
    for why ``bs4`` is intentionally avoided).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from html import unescape
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse

from .name_quality import is_plausible_person_name

_LOG = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# PersonRecord — one (name, email?, title?, source) datum
# ----------------------------------------------------------------------
@dataclass
class PersonRecord:
    """A person discovered on a page.

    Fields
    ------
    name:
        Display name.  Always normalised to title-case where the
        source was uppercase-only.
    email:
        ``"alice@example.com"`` when discovered (``mailto:``, JSON-LD
        ``email``, hCard ``class="email"``).  ``None`` otherwise.
    title:
        Job title / role when one was found adjacent to the name.
        ``None`` otherwise.
    source_type:
        One of ``"json_ld"``, ``"microdata"``, ``"rdfa"``, ``"hcard"``,
        ``"dom_team_card"``, ``"heading_plus_title"``, ``"mailto"``,
        ``"body_text_aggressive"``.
    confidence:
        0.0–1.0.  See the module docstring for the per-source ladder.
    page_url:
        The URL the record was extracted from — preserved so
        callers can group records by source.
    """

    name: str
    email: str | None
    title: str | None
    source_type: str
    confidence: float
    page_url: str


# Confidence ladder per spec.
_CONF_JSON_LD = 0.90
_CONF_MICRODATA = 0.85
_CONF_RDFA = 0.85
_CONF_HCARD = 0.80
_CONF_DOM_TEAM_CARD = 0.65
_CONF_HEADING_PLUS_TITLE = 0.55
_CONF_MAILTO_TEAM = 0.70
_CONF_MAILTO_GENERAL = 0.40
_CONF_BODY_TEXT_AGGRESSIVE = 0.30

# Title patterns used by methods 5 (DOM team card) and 6
# (heading + adjacent title).  These are intentionally loose —
# the caller still runs :func:`is_plausible_person_name` on
# the candidate name before producing the record, so the
# title-pattern match just gates "is this likely a team card?".
_TITLE_TOKEN_RE = re.compile(
    r"\b(?:CEO|CTO|CFO|COO|CMO|CIO|CISO|CISO|VP|SVP|EVP|"
    r"CHRO|CHRO|HR|"
    r"Director|Manager|Head|Lead|Principal|"
    r"Founder|Co-?Founder|Co-?founder|"
    r"President|Chairman|Administrator|Engineer|"
    r"Officer|Executive|Partner|Architect|Analyst|Consultant|"
    r"Chief\s+\w+|Head\s+of\s+\w+)\b",
    flags=re.IGNORECASE,
)


# ----------------------------------------------------------------------
# JSON-LD helpers
# ----------------------------------------------------------------------
# Strict-by-spec regex: only match script tags that explicitly
# carry the ld+json type attribute.
_JSON_LD_RE = re.compile(
    r'<script\b[^>]*\btype\s*=\s*["\']application/ld\+json["\']'
    r"[^>]*>(?P<body>.*?)</script>",
    flags=re.IGNORECASE | re.DOTALL,
)


def _is_substring_match(haystack: str, needle: str) -> bool:
    """Case-insensitive substring check on two non-empty strings."""
    if not haystack or not needle:
        return False
    return needle.lower() in haystack.lower()


def _walk_json_ld(node: Any) -> list[dict[str, Any]]:
    """Yield raw Person-shaped dicts from a parsed JSON-LD tree.

    Handles flat Person, ``@graph`` arrays, Person nested in
    Organization.employee / .member / .founder, and ItemList
    containing Person.  Returned dicts expose at minimum
    ``{name, jobTitle, email, worksFor}`` so the caller can apply
    its own filtering.
    """
    out: list[dict[str, Any]] = []
    if isinstance(node, dict):
        typ = node.get("@type")
        types: list[str] = list(typ) if isinstance(typ, list) else [str(typ or "")]
        # Some authors use lowercase "type" or the full URL form.
        if "type" in node and isinstance(node["type"], str):
            types.append(node["type"])
        if any(
            t.lower() in ("person", "https://schema.org/person") for t in types
        ):
            name = node.get("name")
            if isinstance(name, str) and name.strip():
                works_for = node.get("worksFor") or node.get("worksfor")
                out.append(
                    {
                        "name": name.strip(),
                        "jobTitle": str(node.get("jobTitle") or "") or None,
                        "email": str(node.get("email") or "") or None,
                        "worksFor": works_for,
                    }
                )
        # Recurse into every value — covers @graph, properties,
        # nested arrays, etc.
        for key, value in node.items():
            if key in ("@context",):
                continue
            if isinstance(value, dict | list):
                out.extend(_walk_json_ld(value))
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, dict | list):
                out.extend(_walk_json_ld(item))
    return out


def _organization_employees(organisation_node: dict[str, Any]) -> list[dict[str, Any]]:
    """Re-shape an Organization node's ``employee`` / ``member`` / ``founder`` into Person dicts."""
    out: list[dict[str, Any]] = []
    org_name = str(organisation_node.get("name") or "") or None
    org_url = str(organisation_node.get("url") or "") or None
    for key in ("employee", "member", "founder", "members"):
        value = organisation_node.get(key)
        items = value if isinstance(value, list) else [value]
        for item in items:
            if not isinstance(item, dict):
                continue
            typ = item.get("@type") or item.get("type") or ""
            if isinstance(typ, list):
                type_matches = any(
                    str(t).lower() == "person" for t in typ
                )
            else:
                type_matches = str(typ).lower() == "person"
            if not type_matches:
                continue
            name = item.get("name")
            if isinstance(name, str) and name.strip():
                out.append(
                    {
                        "name": name.strip(),
                        "jobTitle": str(item.get("jobTitle") or "")
                        or str(item.get("jobTitle") or "")
                        or None,
                        "email": str(item.get("email") or "") or None,
                        "worksFor": {"name": org_name, "url": org_url},
                    }
                )
    return out


def _works_for_target_domain(record: dict[str, Any], domain: str) -> bool:
    """True when ``record['worksFor']`` matches *domain* or the page is on *domain*.

    The spec says: ``worksFor.name`` or ``worksFor.url`` must contain
    *domain* OR the page is on *domain*.  We check both substring and
    registrable-domain match.
    """
    if not domain:
        return True  # no domain supplied → assume OK
    wf = record.get("worksFor")
    if isinstance(wf, dict):
        wf_name = str(wf.get("name") or "")
        wf_url = str(wf.get("url") or "")
        if _is_substring_match(wf_name, domain):
            return True
        if _is_substring_match(wf_url, domain):
            return True
        # Registrable-domain match: foo.example.com → example.com.
        wf_host = urlparse(wf_url).netloc.lower() if wf_url else ""
        wf_reg = wf_host.rsplit(".", 2)[-2] if wf_host.count(".") >= 1 else wf_host
        domain_reg = domain.lower().rsplit(".", 2)[-2] if domain.count(".") >= 1 else domain.lower()
        if wf_reg and wf_reg == domain_reg:
            return True
    if isinstance(wf, str):
        if _is_substring_match(wf, domain):
            return True
    return False


# ----------------------------------------------------------------------
# DOM walking — single HTMLParser subclass with slots per source
# ----------------------------------------------------------------------
class _BlockScanner(HTMLParser):
    """Capture the (open-tag HTML + inner markup + close tag) for each
    microdata/RDFa/hCard block we see."""

    VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img",
                 "input", "link", "meta", "param", "source", "track",
                 "wbr"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        # List of {kind, tag, attrs, inner_segments, open_depth}.
        self._stack: list[dict[str, Any]] = []
        self.blocks: list[dict[str, Any]] = []
        self._counter = 0

    @staticmethod
    def _attrs_dict(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        return {k.lower(): (v or "") for k, v in attrs}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        attr_dict = self._attrs_dict(attrs)
        itemtype = (attr_dict.get("itemtype") or "").lower()
        typeof = (attr_dict.get("typeof") or "").lower()
        cls_attr = (attr_dict.get("class") or "").lower()
        kind: str | None = None
        if itemtype and "person" in itemtype:
            kind = "microdata"
        elif typeof and "person" in typeof:
            kind = "rdfa"
        elif "vcard" in cls_attr.split():
            kind = "hcard"
        if tag_lower in self.VOID_TAGS:
            return
        self._stack.append(
            {
                "tag": tag_lower,
                "attrs": attr_dict,
                "kind": kind,
                "open_id": self._counter,
            }
        )
        self._counter += 1
        if kind:
            self.blocks.append(
                {
                    "kind": kind,
                    "tag": tag_lower,
                    "attrs": attr_dict,
                    "open_id": self._counter - 1,
                }
            )

    def handle_startendtag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        # Self-closing tag — no inner content possible, but if
        # it carries an outer marker (itemtype) record it anyway.
        attr_dict = self._attrs_dict(attrs)
        kind = None
        if "person" in (attr_dict.get("itemtype") or "").lower():
            kind = "microdata"
        elif "person" in (attr_dict.get("typeof") or "").lower():
            kind = "rdfa"
        if kind:
            self.blocks.append(
                {
                    "kind": kind,
                    "tag": tag.lower(),
                    "attrs": attr_dict,
                    "open_id": self._counter,
                }
            )
            self._counter += 1

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i]["tag"] == tag_lower:
                self._stack.pop(i)
                return


# ----------------------------------------------------------------------
# Headings + DOM team-card sweep
# ----------------------------------------------------------------------
class _HeadingAndTitleParser(HTMLParser):
    """Capture headings (h2/h3/h4) and their adjacent text.

    For DOM team-card detection we also capture every <img> so we
    can count the "image + heading + title" repetitions.
    """

    VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img",
                 "input", "link", "meta", "param", "source", "track",
                 "wbr"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._stack: list[str] = []
        self._text_buffer: list[str] = []
        # head/tail proximity data: every time we close an h2/h3/h4
        # we record the heading and the next ~120 chars of text.
        self.headings: list[dict[str, Any]] = []
        self._last_heading: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        if tag_lower in self.VOID_TAGS:
            return
        self._stack.append(tag_lower)

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if self._stack and self._stack[-1] == tag_lower:
            self._stack.pop()

    def handle_data(self, data: str) -> None:
        if not data:
            return
        # Strip trailing whitespace inside the data — we don't want
        # heading text to swallow trailing punctuation.
        clean = data.strip()
        if not clean:
            return
        top = self._stack[-1] if self._stack else ""
        if top in ("h2", "h3", "h4"):
            if self._last_heading is not None:
                self.headings.append(self._last_heading)
            self._last_heading = {
                "tag": top,
                "name": clean,
                "next_text": "",
            }
        else:
            # Tail proximity: when we're NOT inside an h2/h3/h4 but
            # there is a pending heading, capture the next text
            # segment as a candidate title.
            if (
                self._last_heading is not None
                and not self._last_heading.get("next_text")
                and self._last_heading["tag"]
                not in (top or "")
                and top not in ("script", "style")
            ):
                self._last_heading["next_text"] = clean[:120]
                self.headings.append(self._last_heading)
                self._last_heading = None

    def finalize(self) -> None:
        if self._last_heading is not None:
            self.headings.append(self._last_heading)
            self._last_heading = None


# ----------------------------------------------------------------------
# Body-text "Name, Title" pattern (only used when aggressive=True)
# ----------------------------------------------------------------------
_TITLE_AFTER_NAME_RE = re.compile(
    r"\b([A-Z][a-z][A-Za-z'\-]{1,30}"
    r"(?:\s+[A-Z][a-z][A-Za-z'\-]{1,30}){1,3}?)\s*"
    r"[,\-]\s*"
    r"([A-Z][A-Za-z &\-/\.]{2,40})"
)

_WESTERN_LINE_NAME_RE = re.compile(
    r"\b[A-Z][a-z][A-Za-z'\-]{1,30}(?:\s+[A-Z][a-z][A-Za-z'\-]{1,30}){1,3}?\b"
)

# Same tag stripper pattern the existing company_page_names uses.
_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_RE = re.compile(
    r"<(?:script|style|noscript|svg|iframe)[^>]*>.*?</(?:script|style|noscript|svg|iframe)>",
    flags=re.IGNORECASE | re.DOTALL,
)


def _html_to_text(html: str) -> str:
    if not html:
        return ""
    no_scripts = _SCRIPT_RE.sub(" ", html)
    text = unescape(no_scripts)
    text = _TAG_RE.sub(" ", text)
    text = re.sub(r"&[#a-zA-Z0-9]+;", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _extract_body_text_names(
    html: str,
    domain: str,
    page_url: str,
) -> list[PersonRecord]:
    """Aggressive-only body-text extraction (mirror of legacy logic)."""
    text = _html_to_text(html)
    if not text:
        return []
    out: list[PersonRecord] = []
    seen: set[str] = set()
    # First pass: "Name, Title" pairs.
    for match in _TITLE_AFTER_NAME_RE.finditer(text):
        name = match.group(1).strip()
        title = match.group(2).strip()
        if not is_plausible_person_name(name):
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(
            PersonRecord(
                name=name,
                email=None,
                title=title,
                source_type="body_text_aggressive",
                confidence=_CONF_BODY_TEXT_AGGRESSIVE,
                page_url=page_url,
            )
        )
    # Second pass: standalone capitalised names (loose, lower priority
    # by virtue of the same confidence score).
    token_re = re.compile(r"[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ'\-]*")
    tokens = token_re.findall(text)
    for i in range(len(tokens)):
        for window in (2, 3, 4):
            seq = tokens[i : i + window]
            if len(seq) != window:
                continue
            candidate = " ".join(seq)
            if not _WESTERN_LINE_NAME_RE.fullmatch(candidate):
                continue
            if not is_plausible_person_name(candidate):
                continue
            key = candidate.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(
                PersonRecord(
                    name=candidate,
                    email=None,
                    title=None,
                    source_type="body_text_aggressive",
                    confidence=_CONF_BODY_TEXT_AGGRESSIVE,
                    page_url=page_url,
                )
            )
    return out


# ----------------------------------------------------------------------
# Public entry point
# ----------------------------------------------------------------------
def extract_people(
    html: str,
    page_url: str,
    domain: str,
    *,
    is_team_page: bool = False,
    aggressive: bool = False,
) -> list[PersonRecord]:
    """Run all extraction methods against *html* and return PersonRecords.

    Parameters
    ----------
    html:
        Raw page HTML.
    page_url:
        The URL the HTML came from — recorded on every record.
    domain:
        Target corporate domain (e.g. ``"example.com"``).  Used by
        the JSON-LD filter to confirm ``worksFor`` matches.
    is_team_page:
        ``True`` when the URL was matched by
        :func:`backend.core.site_discovery.discover_team_pages`.  Only
        affects the mailto confidence split (0.70 here, 0.40 on
        general pages).
    aggressive:
        Opt-in flag that enables the body-text extraction method
        (confidence 0.30).  Off by default per spec.

    Order of methods
    ----------------
    1. JSON-LD Person (0.90)
    2. Microdata Person (0.85)
    3. RDFa Person (0.85)
    4. hCard / vCard (0.80)
    5. DOM team cards (0.65) — only emit on 2+ repetitions
    6. Heading + adjacent title (0.55) — only on *is_team_page*
    7. mailto: (0.70 / 0.40)
    8. Body-text (0.30) — only when *aggressive*

    Records are deduplicated by ``(name.lower(), email.lower() if email)``
    and the highest-confidence match wins.
    """
    if not html:
        return []

    out: list[PersonRecord] = []

    # ----- 1. JSON-LD -----
    out.extend(_extract_json_ld_records(html, page_url, domain))

    # ----- 2-4. Microdata / RDFa / hCard -----
    out.extend(_extract_structured_blocks_records(html, page_url, domain))

    # ----- 5. DOM team cards -----
    out.extend(_extract_dom_team_card_records(html, page_url, is_team_page))

    # ----- 6. Heading + adjacent title (team pages only) -----
    if is_team_page:
        out.extend(_extract_heading_title_records(html, page_url, domain))

    # ----- 7. mailto: -----
    out.extend(_extract_mailto_records(html, page_url, is_team_page))

    # ----- 8. Body-text (aggressive only) -----
    if aggressive:
        out.extend(_extract_body_text_names(html, domain, page_url))

    # ----- Dedup -----
    deduped = _dedupe_records(out)
    return sorted(deduped, key=lambda r: (-r.confidence, r.name))


# ----------------------------------------------------------------------
# Per-method helpers
# ----------------------------------------------------------------------
def _extract_json_ld_records(
    html: str, page_url: str, domain: str
) -> list[PersonRecord]:
    out: list[PersonRecord] = []
    for match in _JSON_LD_RE.finditer(html or ""):
        raw = match.group("body") or ""
        try:
            data = json.loads(raw)
        except Exception:  # noqa: BLE001 — malformed JSON-LD is not fatal
            continue
        # Method 1.a — flat Person / @graph / nested inside arrays
        for person in _walk_json_ld(data):
            wf = person.get("worksFor")
            if not _works_for_target_domain(
                {"worksFor": wf}, domain
            ) and not _page_on_domain(page_url, domain):
                continue
            if not _ok_name(person.get("name")):
                continue
            out.append(
                PersonRecord(
                    name=str(person.get("name")).strip(),
                    email=_clean_email(person.get("email")),
                    title=_clean_title(person.get("jobTitle")),
                    source_type="json_ld",
                    confidence=_CONF_JSON_LD,
                    page_url=page_url,
                )
            )
        # Method 1.b — Organization.employee / member / founder.
        # Walk every dict in the tree looking for Organization nodes
        # with employee/member/founder keys.
        for org in _walk_org_nodes(data):
            for person in _organization_employees(org):
                if not _ok_name(person.get("name")):
                    continue
                # Filter by worksFor when the organisation has a name.
                if domain and not _works_for_target_domain(
                    person, domain
                ) and not _page_on_domain(page_url, domain):
                    continue
                out.append(
                    PersonRecord(
                        name=str(person.get("name")).strip(),
                        email=_clean_email(person.get("email")),
                        title=_clean_title(person.get("jobTitle")),
                        source_type="json_ld",
                        confidence=_CONF_JSON_LD,
                        page_url=page_url,
                    )
                )
    return out


def _walk_org_nodes(node: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if isinstance(node, dict):
        typ = node.get("@type") or node.get("type") or ""
        types = typ if isinstance(typ, list) else [typ]
        if any(
            str(t).lower() in ("organization", "https://schema.org/organization")
            for t in types
        ):
            out.append(node)
        for v in node.values():
            if isinstance(v, dict | list):
                out.extend(_walk_org_nodes(v))
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, dict | list):
                out.extend(_walk_org_nodes(item))
    return out


def _extract_structured_blocks_records(
    html: str, page_url: str, domain: str
) -> list[PersonRecord]:
    """Microdata / RDFa / hCard in a single sweep.

    Each block is registered when its outer marker opens; the inner
    markers (itemprop / property / class~="fn" …) are then matched
    via a single linear scan that tracks depth relative to the outer
    block.  This avoids needing a full tree materialisation.
    """
    if not html:
        return []
    out: list[PersonRecord] = []
    scanner = _BlockScanner()
    scanner.feed(html)
    # For each block, run a focused inner-parser over the full HTML
    # using depth tracking.  The browser-level HTMLParser doesn't
    # expose depth, so we roll a tiny scanner that does.
    blocks = list(scanner.blocks)
    for block in blocks:
        # Method 2 / 3 / 4 — name
        for marker_key in _markers_for_kind(block["kind"], "name"):
            name = _scan_for_marker(
                html, block["kind"], marker_key, block_open_attrs=block["attrs"]
            )
            if name and _ok_name(name):
                # Dedup by name during this block pass — later markers
                # for the same person shouldn't double-record.
                break
        else:
            continue
        # Email
        email: str | None = None
        for marker_key in _markers_for_kind(block["kind"], "email"):
            email_val = _scan_for_marker(
                html, block["kind"], marker_key, block_open_attrs=block["attrs"]
            )
            if email_val:
                # For hCard <a class="email" href="mailto:..."> the
                # inner parser grabs the href value, not the visible
                # text.  Normalise.
                email = _normalise_email(email_val)
                break
        # Title
        title: str | None = None
        for marker_key in _markers_for_kind(block["kind"], "title"):
            title_val = _scan_for_marker(
                html, block["kind"], marker_key, block_open_attrs=block["attrs"]
            )
            if title_val:
                title = _normalise_title(title_val)
                break
        out.append(
            PersonRecord(
                name=name.strip(),
                email=email,
                title=title,
                source_type=block["kind"],
                confidence=_conf_for_kind(block["kind"]),
                page_url=page_url,
            )
        )
    return out


_MARKER_SETS = {
    "microdata": {
        "name": ["name"],
        "email": ["email"],
        "title": ["jobtitle", "title", "role"],
    },
    "rdfa": {
        "name": ["schema:name", "foaf:name"],
        "email": ["schema:email", "foaf:mbox"],
        "title": ["schema:jobtitle", "schema:title", "schema:role"],
    },
    "hcard": {
        "name": ["fn"],
        "email": ["email"],
        "title": ["title", "role"],
    },
}


def _markers_for_kind(kind: str, field: str) -> list[str]:
    return _MARKER_SETS.get(kind, {}).get(field, [])


def _conf_for_kind(kind: str) -> float:
    return {
        "microdata": _CONF_MICRODATA,
        "rdfa": _CONF_RDFA,
        "hcard": _CONF_HCARD,
    }.get(kind, 0.0)


# ----------------------------------------------------------------------
# Linear scanner for inner markers — used by blocks 2/3/4
# ----------------------------------------------------------------------
class _BlockScopedScanner(HTMLParser):
    """Single scan of *html* that emits marker values only when
    inside an element whose itemtype/typeof/class matches
    *outer_attrs*.

    The spec for microdata requires exactly
    ``itemtype`` containing ``schema.org/Person``; for RDFa
    ``typeof`` containing ``Person``; for hCard class containing
    ``vcard``.  Matching against the *outer's attrs* is enough —
    we don't allow nested Person elements.
    """

    VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img",
                 "input", "link", "meta", "param", "source", "track",
                 "wbr"}

    def __init__(self, kind: str, outer_attrs: dict[str, str], marker: str) -> None:
        super().__init__(convert_charrefs=True)
        self._kind = kind
        self._outer_attrs = outer_attrs
        self._marker = marker.lower()
        # Track *outer* depth separately from *inner-marker* depth.
        # We must stay "inside outer" until the actual outer element
        # closes — closing a nested marker must NOT exit the outer.
        self._outer_depth = 0
        self._inner_depth = 0
        self._capturing = False
        self._text_parts: list[str] = []
        self.captured: list[str] = []

    @staticmethod
    def _attrs_dict(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        return {k.lower(): (v or "") for k, v in attrs}

    def _is_outer(self, attrs: dict[str, str]) -> bool:
        if self._kind == "microdata":
            return "person" in (attrs.get("itemtype") or "").lower()
        if self._kind == "rdfa":
            return "person" in (attrs.get("typeof") or "").lower()
        if self._kind == "hcard":
            return "vcard" in (attrs.get("class") or "").lower().split()
        return False

    def _is_marker(self, attrs: dict[str, str]) -> bool:
        if self._kind == "microdata":
            return (attrs.get("itemprop") or "").lower() == self._marker
        if self._kind == "rdfa":
            return (attrs.get("property") or "").lower() == self._marker
        if self._kind == "hcard":
            return self._marker in (attrs.get("class") or "").lower().split()
        return False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = self._attrs_dict(attrs)
        if tag.lower() in self.VOID_TAGS:
            return
        # Enter the outer block the first time we see it.
        if self._outer_depth == 0 and self._is_outer(attr_dict):
            self._outer_depth = 1
            return
        if self._outer_depth == 0:
            return
        # We're inside an outer block.  Is this tag a marker?
        if self._is_marker(attr_dict):
            self._capturing = True
            self._inner_depth = 0
            self._text_parts = []
            # Email markers very often live on an <a href="mailto:..">.
            # The schema.org spec lets ``email`` be plain text OR a
            # hyperlink; when it is a hyperlink we want the href
            # value, not the inner text (which can be display text
            # like "email" or a truncated local part).
            #
            # ``self._marker`` is the fully-qualified name the caller
            # passed in (e.g. "schema:email", "email", "schema:mbox")
            # — we strip the XML-namespace prefix to compare.
            _local_marker = self._marker.split(":", 1)[-1].lower()
            if _local_marker == "email" or _local_marker == "mbox":
                href = (attr_dict.get("href") or "").strip()
                if href.lower().startswith("mailto:"):
                    self.captured.append(href[len("mailto:") :].strip())
                    self._capturing = False
                    return
            return
        # Nested tag inside an outer block (not a marker).  Push depth.
        self._outer_depth += 1

    def handle_startendtag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        # Self-closing tag — no nested content.
        attr_dict = self._attrs_dict(attrs)
        if self._outer_depth == 0 and self._is_outer(attr_dict):
            # Self-closing outer — no inner content possible, but
            # the marker attribute is on this tag itself so we can
            # read it directly.  Practically rare for Person blocks.
            self._outer_depth = 1
            if self._is_marker(attr_dict):
                if (
                    self._kind == "hcard"
                    and self._marker == "email"
                    and (attr_dict.get("href") or "").strip()
                ):
                    href = attr_dict["href"]
                    if href.lower().startswith("mailto:"):
                        self.captured.append(href[len("mailto:") :].strip())
                    else:
                        self.captured.append(href.strip())
                elif tag.lower() in ("img", "span") and attr_dict.get("alt"):
                    self.captured.append(attr_dict["alt"])
                # We didn't record text — finish the outer.
            self._outer_depth = 0
            return
        if self._outer_depth == 0:
            return
        # Inside outer, self-closing tag with marker attrs.
        if self._is_marker(attr_dict):
            if (
                self._kind == "hcard"
                and self._marker == "email"
                and (attr_dict.get("href") or "").strip()
            ):
                self.captured.append(attr_dict["href"].lstrip("mailto:").strip())
            elif attr_dict.get("alt"):
                self.captured.append(attr_dict["alt"])

    def handle_endtag(self, tag: str) -> None:
        if self._outer_depth == 0:
            return
        # The outer element itself just closed (we're at the matching
        # close for the outer tag) — flush any pending capture and exit.
        if self._capturing and self._inner_depth == 0:
            text = "".join(self._text_parts).strip()
            if text:
                self.captured.append(unescape(text))
            self._capturing = False
        # Pop one outer-depth level.  The outer tag's close empties out.
        self._outer_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._capturing or not data:
            return
        self._text_parts.append(data)

    # Override the default to translate ``handle_endtag`` for nested
    # tags — the stdlib's :class:`html.parser.HTMLParser` doesn't pass
    # us a depth counter, so we track it ourselves via _outer_depth.
    # Inner tags are visited through plain ``handle_starttag`` +
    # ``handle_endtag`` calls; the outer counter is bumped on every
    # nested open and popped on every close.
    def handle_starttag_for_outer(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # Wrapper — not used at module-level.  Reserved for callers
        # that want to drive the parser manually.
        self.handle_starttag(tag, attrs)


def _scan_for_marker(
    html: str,
    kind: str,
    marker: str,
    *,
    block_open_attrs: dict[str, str],
) -> str | None:
    """Run a fresh :class:`_BlockScopedScanner` over *html* and return
    the first marker value found, or ``None``."""
    scanner = _BlockScopedScanner(kind, block_open_attrs, marker)
    scanner.feed(html)
    scanner.close()
    if scanner.captured:
        return scanner.captured[0]
    return None


# ----------------------------------------------------------------------
# DOM team-card sweep
# ----------------------------------------------------------------------
_IMG_TAG_RE = re.compile(
    r"<\s*img\b[^>]*>",
    flags=re.IGNORECASE,
)


# Anchor mailto with display-text capture.  When a DOM team-card
# has a sibling ``<a href="mailto:...">``, we capture both the href
# and the inner display text so the email can be merged with the
# surrounding card.
_MAILTO_INNER_RE = re.compile(
    r'<a\b[^>]*\bhref\s*=\s*["\']mailto:([^"\']+)["\'][^>]*>'
    r"(?P<inner>[^<]*)</a\s*>",
    flags=re.IGNORECASE | re.DOTALL,
)


def _find_mailto_for_heading(
    html: str, heading_text: str
) -> str | None:
    """Find the first mailto link inside the heading's card block.

    Looks for the heading wrapped in an ``<h2>``/``<h3>``/``<h4>``
    tag (NOT in an alt= attribute) and returns the first
    ``mailto:..`` href that follows the heading tag's close
    and precedes the next ``<h*>`` open.  Returns ``None``
    when no mailto link is in the same card region.
    """
    if not html or not heading_text:
        return None
    # Search for the heading wrapped in an actual h2/h3/h4 element
    # (avoid matching ``<img alt="Subramanian Krishnan" />`` which
    # shares the same display text but is not a heading).
    pattern = re.compile(
        r"<h[1-6]\b[^>]*>\s*" + re.escape(heading_text) + r"\s*</h[1-6]\s*>",
        flags=re.IGNORECASE,
    )
    head_match = pattern.search(html)
    if head_match is None:
        # Fallback: any literal occurrence (useful for unusual HTML).
        pos = html.find(heading_text)
        if pos < 0:
            return None
        after_heading = pos + len(heading_text)
    else:
        after_heading = head_match.end()
    tail = html[after_heading:]
    # Cap at the next <h*> open to keep the search within the card.
    next_head = re.search(r"<h[1-6]\b", tail, flags=re.IGNORECASE)
    if next_head:
        tail = tail[: next_head.start()]
    for match in _MAILTO_INNER_RE.finditer(tail):
        addr = (match.group(1) or "").strip()
        if "?" in addr:
            addr = addr.split("?", 1)[0]
        if "<" in addr and ">" in addr:
            addr = addr[addr.find("<") + 1 : addr.find(">")].strip()
        if "@" in addr:
            return addr
    return None


def _extract_dom_team_card_records(
    html: str, page_url: str, is_team_page: bool
) -> list[PersonRecord]:
    """5 — DOM team-card pattern: image + heading + title, 2+ times.

    We deliberately only emit on confirmed team pages — a single
    repeating "image + name + title" block is too noisy on
    product / pricing pages to be worth surfacing as a team
    record.  Off when *is_team_page* is False.

    Each card also picks up a sibling ``<a href="mailto:...">``
    when one is present so the structured record carries its
    email directly.  Without that pass we would emit a separate
    mailto-derived record (with a guessed local-part name) and
    the email would not link back to the structured identity.
    """
    if not is_team_page or not html:
        return []
    parser = _HeadingAndTitleParser()
    parser.feed(html)
    parser.close()
    parser.finalize()
    headings = [h for h in parser.headings if h.get("name") and h.get("next_text")]
    if len(headings) < 2:
        # Need at least 2 cards for the pattern to be a "team grid".
        return []
    images = _IMG_TAG_RE.findall(html)
    if len(images) < 2:
        return []
    out: list[PersonRecord] = []
    seen: set[str] = set()
    for h in headings:
        # The heading's *name* attribute holds the display name and
        # *next_text* holds the title pattern.
        name = h.get("name") or ""
        title = h.get("next_text") or ""
        if not is_plausible_person_name(name):
            continue
        if not _TITLE_TOKEN_RE.search(title):
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        # Look for an adjacent mailto link inside the same card.
        email = _find_mailto_for_heading(html, name)
        out.append(
            PersonRecord(
                name=name.strip(),
                email=email,
                title=title.strip(),
                source_type="dom_team_card",
                confidence=_CONF_DOM_TEAM_CARD,
                page_url=page_url,
            )
        )
    return out


def _extract_heading_title_records(
    html: str, page_url: str, domain: str
) -> list[PersonRecord]:
    """6 — heading + adjacent title, only on team pages."""
    if not html:
        return []
    parser = _HeadingAndTitleParser()
    parser.feed(html)
    parser.close()
    parser.finalize()
    out: list[PersonRecord] = []
    seen: set[str] = set()
    for h in parser.headings:
        name = h.get("name") or ""
        title = h.get("next_text") or ""
        if not name:
            continue
        if not is_plausible_person_name(name):
            continue
        if not _TITLE_TOKEN_RE.search(title):
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(
            PersonRecord(
                name=name.strip(),
                email=None,
                title=title.strip(),
                source_type="heading_plus_title",
                confidence=_CONF_HEADING_PLUS_TITLE,
                page_url=page_url,
            )
        )
    return out


# ----------------------------------------------------------------------
# mailto: extraction
# ----------------------------------------------------------------------
_MAILTO_RE = re.compile(
    r'<a\b[^>]*\bhref\s*=\s*["\']mailto:([^"\']+)["\']',
    flags=re.IGNORECASE,
)


def _extract_mailto_records(
    html: str, page_url: str, is_team_page: bool
) -> list[PersonRecord]:
    """7 — every ``mailto:`` link becomes a record.

    Team pages get ``_CONF_MAILTO_TEAM`` (0.70); general pages get
    ``_CONF_MAILTO_GENERAL`` (0.40) because ``info@`` /
    ``contact@`` etc. are common and noisy on most pages.
    """
    if not html:
        return []
    confidence = _CONF_MAILTO_TEAM if is_team_page else _CONF_MAILTO_GENERAL
    out: list[PersonRecord] = []
    seen: set[str] = set()
    for match in _MAILTO_RE.finditer(html):
        raw = match.group(1).strip()
        if not raw:
            continue
        # Strip query / display-name parts:
        #   mailto:foo@example.com?subject=…
        #   mailto:John Doe <foo@example.com>
        email_part = raw
        if "?" in email_part:
            email_part = email_part.split("?", 1)[0]
        if "<" in email_part and ">" in email_part:
            email_part = email_part[ email_part.find("<") + 1 : email_part.find(">") ]
        email_part = email_part.strip()
        if "@" not in email_part:
            continue
        key = email_part.lower()
        if key in seen:
            continue
        seen.add(key)
        local = email_part.split("@", 1)[0]
        # Best-effort name from the local part: john.doe → John Doe.
        name = _local_part_to_name(local)
        out.append(
            PersonRecord(
                name=name,
                email=email_part,
                title=None,
                source_type="mailto",
                confidence=confidence,
                page_url=page_url,
            )
        )
    return out


def _local_part_to_name(local: str) -> str:
    """Turn ``john.doe`` / ``jane_smith`` / ``jsmith`` into a guessed display name.

    Falls back to the local part itself when no separators are found.
    The result is not validated by :func:`is_plausible_person_name`
    here — the caller decides whether the record is usable.
    """
    cleaned = re.sub(r"[^A-Za-z0-9._\-]+", " ", local).strip()
    if not cleaned:
        return local
    if "." in cleaned:
        parts = [p for p in cleaned.split(".") if p]
        if 1 <= len(parts) <= 3:
            return " ".join(p.capitalize() for p in parts)
    if "_" in cleaned:
        parts = [p for p in cleaned.split("_") if p]
        if 1 <= len(parts) <= 3:
            return " ".join(p.capitalize() for p in parts)
    if len(cleaned) <= 5:
        # Likely an initial-style login (e.g. ``jsmith``).  Use the
        # first letter + remainder as a 2-token name: ``jsmith``
        # → ``J Smith``.  This is a guess; analysts can override.
        return f"{cleaned[0].upper()} {cleaned[1:].capitalize()}"
    return cleaned.capitalize()


# ----------------------------------------------------------------------
# Helpers shared across methods
# ----------------------------------------------------------------------
def _page_on_domain(page_url: str, domain: str) -> bool:
    if not domain or not page_url:
        return False
    host = (urlparse(page_url).netloc or "").lower()
    return host == domain.lower() or host.endswith("." + domain.lower())


def _clean_email(value: Any) -> str | None:
    if not value:
        return None
    s = str(value).strip()
    if not s or "@" not in s:
        return None
    if "<" in s and ">" in s:
        s = s[s.find("<") + 1 : s.find(">")].strip()
    if "?" in s:
        s = s.split("?", 1)[0].strip()
    return s or None


def _clean_title(value: Any) -> str | None:
    if not value:
        return None
    s = str(value).strip()
    if not s:
        return None
    # Truncate to a sensible title length.
    if len(s) > 80:
        s = s[:80].rstrip(" ,;-")
    return s


def _normalise_email(value: str) -> str:
    v = value.strip()
    if v.lower().startswith("mailto:"):
        v = v[len("mailto:") :]
    if "?" in v:
        v = v.split("?", 1)[0]
    return v.strip()


def _normalise_title(value: str) -> str:
    v = re.sub(r"\s+", " ", value.strip())
    if len(v) > 80:
        v = v[:80].rstrip(" ,;-")
    return v


def _ok_name(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    name = value.strip()
    if not name:
        return False
    return bool(is_plausible_person_name(name))


def _dedupe_records(
    records: list[PersonRecord],
) -> list[PersonRecord]:
    """Deduplicate by lower(name) OR lower(email) and merge.

    Two records collide when either their names or their emails
    match (case-insensitive).  The winner is decided by
    confidence, with the loser's title back-filling the winner
    when the winner has no title.  Output contains one record
    per identity.

    The merge-on-email path matters in two real cases:
      * ``<div itemscope itemtype="Person">...<a itemprop="email"
        href="mailto:foo@x">...</div>`` — microdata yields the
        structured record with ``foo@x``; the standalone mailto
        extractor then yields a *second* record for the same
        href.  We want one record, the higher-confidence one.
      * A user's name appears in JSON-LD (``Alice Smith``) and
        separately in microdata on the same page with a
        different spelling — we keep the higher-confidence one
        with both attributes.

    Implementation: flat fold over the input.  Each incoming
    record collides with whichever existing record shares its
    name-key OR email-key; ties go to the earliest occurrence.
    """
    merged: list[PersonRecord] = []

    def _key_fields(r: PersonRecord) -> tuple[str, str]:
        return (
            (r.name or "").strip().lower(),
            (r.email or "").strip().lower(),
        )

    for new in records:
        if not (new.name or "").strip():
            continue
        new_name_key, new_email_key = _key_fields(new)
        # Find a colliding existing record.
        target_idx = -1
        for idx, existing in enumerate(merged):
            ex_name_key, ex_email_key = _key_fields(existing)
            if new_name_key and new_name_key == ex_name_key:
                target_idx = idx
                break
            if new_email_key and new_email_key == ex_email_key:
                target_idx = idx
                break
        if target_idx == -1:
            merged.append(new)
            continue
        target = merged[target_idx]
        # Decide winner.
        if new.confidence > target.confidence:
            winner, loser = new, target
            merged[target_idx] = winner
        else:
            winner, loser = target, new
        # Back-fill missing fields on the winner from the loser.
        if not winner.email and loser.email:
            winner.email = loser.email
        if not winner.title and loser.title:
            winner.title = loser.title
        # If the loser had a "better" name (the structured record
        # often does), the name stays on the winner already.

    return merged


__all__ = [
    "PersonRecord",
    "extract_people",
    "TEAM_TITLE_TOKEN_RE",  # exposed for tests that import it
]
# Reset the alias typo so the public name is consistent.
TEAM_TITLE_TOKEN_RE = _TITLE_TOKEN_RE
