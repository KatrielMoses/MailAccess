"""Schema.org content-authorship extractor.

This module focuses on JSON-LD and Microdata pages that describe
content authorship.  It looks for target entity types such as
``Article`` and ``VideoObject`` and then resolves author-like
properties to Person nodes so the discovered identity can be pushed
into :class:`backend.core.signal_pool.AsyncSignalPool`.

The extractor is intentionally narrow: it ignores body text, hCard,
RDFa, and general team-page heuristics.  That keeps it aligned with the
content-authorship use case rather than the broader people-discovery
pipeline.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from html import unescape
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse

from .signal_normalize import normalize_slug_or_email
from .signal_pool import AsyncSignalPool, Signal

_LOG = logging.getLogger(__name__)

_TARGET_ENTITY_TYPES = frozenset(
    {
        "article",
        "blogposting",
        "newsarticle",
        "course",
        "courseinstance",
        "podcastepisode",
        "videoobject",
    }
)
_TARGET_PROPERTIES = frozenset({"author", "creator", "instructor", "performer", "actor"})
_PERSON_TYPES = frozenset({"person", "https://schema.org/person", "schema:person"})
_ORG_TYPES = frozenset({"organization", "https://schema.org/organization", "schema:organization"})
_JSON_LD_RE = re.compile(
    r'<script\b[^>]*\btype\s*=\s*["\']application/ld\+json["\'][^>]*>'
    r"(?P<body>.*?)</script\s*>",
    flags=re.IGNORECASE | re.DOTALL,
)


@dataclass(slots=True)
class _AuthorshipEntity:
    name: str
    email: str | None = None
    job_title: str | None = None
    works_for_name: str | None = None
    works_for_url: str | None = None
    same_as: tuple[str, ...] = ()
    source_type: str = "json_ld"
    target_entity_type: str | None = None
    target_property: str | None = None


@dataclass(slots=True)
class _HtmlNode:
    tag: str
    attrs: dict[str, str] = field(default_factory=dict)
    children: list["_HtmlNode"] = field(default_factory=list)
    text_parts: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return "".join(self.text_parts)


class _HtmlTreeBuilder(HTMLParser):
    """Build a lightweight node tree for Microdata traversal."""

    VOID_TAGS = {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = _HtmlNode("document")
        self._stack: list[_HtmlNode] = [self.root]

    @staticmethod
    def _attrs_dict(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        return {key.lower(): (value or "") for key, value in attrs}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        node = _HtmlNode(tag.lower(), self._attrs_dict(attrs))
        self._stack[-1].children.append(node)
        if tag.lower() not in self.VOID_TAGS:
            self._stack.append(node)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        node = _HtmlNode(tag.lower(), self._attrs_dict(attrs))
        self._stack[-1].children.append(node)

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        for index in range(len(self._stack) - 1, 0, -1):
            if self._stack[index].tag == tag_lower:
                del self._stack[index:]
                return

    def handle_data(self, data: str) -> None:
        if data:
            self._stack[-1].text_parts.append(data)


def _decode_html(html: bytes | str) -> str:
    if isinstance(html, str):
        return unescape(html)
    return unescape(bytes(html).decode("utf-8", errors="replace"))


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = re.sub(r"\s+", " ", str(value).strip())
    return text or None


def _clean_email(value: Any) -> str | None:
    text = _clean_text(value)
    if not text or "@" not in text:
        return None
    if text.lower().startswith("mailto:"):
        text = text[7:]
    if "<" in text and ">" in text:
        text = text[text.find("<") + 1 : text.find(">")].strip()
    if "?" in text:
        text = text.split("?", 1)[0].strip()
    return text or None


def _normalise_type(value: Any) -> list[str]:
    if isinstance(value, list):
        items = value
    elif value is None:
        items = []
    else:
        items = [value]
    types: list[str] = []
    for item in items:
        if not isinstance(item, str):
            continue
        text = item.strip().lower()
        if not text:
            continue
        types.append(text)
        if text.startswith("https://schema.org/"):
            types.append(text.rsplit("/", 1)[-1])
        elif text.startswith("schema:"):
            types.append(text.split(":", 1)[-1])
    return types


def _is_target_entity(node: dict[str, Any]) -> str | None:
    types = _normalise_type(node.get("@type") or node.get("type"))
    for type_name in types:
        if type_name in _TARGET_ENTITY_TYPES:
            return type_name
    return None


def _is_person_node(node: dict[str, Any]) -> bool:
    types = _normalise_type(node.get("@type") or node.get("type"))
    return any(type_name in _PERSON_TYPES for type_name in types)


def _is_org_node(node: dict[str, Any]) -> bool:
    types = _normalise_type(node.get("@type") or node.get("type"))
    return any(type_name in _ORG_TYPES for type_name in types)


def _walk_dicts(node: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if isinstance(node, dict):
        out.append(node)
        for value in node.values():
            if isinstance(value, dict | list):
                out.extend(_walk_dicts(value))
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, dict | list):
                out.extend(_walk_dicts(item))
    return out


def _json_ld_scripts(html: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for match in _JSON_LD_RE.finditer(html or ""):
        body = (match.group("body") or "").strip()
        if not body:
            continue
        try:
            payload = json.loads(body)
        except Exception:  # noqa: BLE001 - malformed JSON-LD is skipped
            continue
        records.extend(_json_ld_entities(payload))
    return records


def _json_ld_entities(node: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if isinstance(node, dict):
        entity_type = _is_target_entity(node)
        if entity_type:
            out.append({"node": node, "entity_type": entity_type})
        for value in node.values():
            if isinstance(value, dict | list):
                out.extend(_json_ld_entities(value))
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, dict | list):
                out.extend(_json_ld_entities(item))
    return out


def _json_ld_id_key(node: dict[str, Any]) -> str | None:
    for key in ("@id", "id"):
        value = node.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _json_ld_index(nodes: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for node in nodes:
        key = _json_ld_id_key(node)
        if key:
            index[key] = node
    return index


def _json_ld_person_from_value(
    value: Any,
    index: dict[str, dict[str, Any]],
    *,
    seen_ids: set[str],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if isinstance(value, list):
        for item in value:
            out.extend(_json_ld_person_from_value(item, index, seen_ids=seen_ids))
        return out
    if isinstance(value, str):
        ref = value.strip()
        if not ref:
            return out
        node = index.get(ref)
        if node is not None and _is_person_node(node):
            out.append(node)
        return out
    if not isinstance(value, dict):
        return out

    if _is_person_node(value):
        key = _json_ld_id_key(value)
        if key:
            if key in seen_ids:
                return out
            seen_ids.add(key)
        out.append(value)
        return out

    ref_key = _json_ld_id_key(value)
    if ref_key and ref_key in index:
        resolved = index[ref_key]
        if _is_person_node(resolved):
            if ref_key not in seen_ids:
                seen_ids.add(ref_key)
                out.append(resolved)
        return out

    nested = value.get("@graph")
    if nested is not None:
        out.extend(_json_ld_person_from_value(nested, index, seen_ids=seen_ids))
    return out


def _json_ld_works_for(node: dict[str, Any], index: dict[str, dict[str, Any]]) -> tuple[str | None, str | None]:
    works_for = node.get("worksFor") or node.get("worksfor")
    if isinstance(works_for, list):
        works_for = works_for[0] if works_for else None
    if isinstance(works_for, str):
        referenced = index.get(works_for.strip())
        if referenced is not None:
            works_for = referenced
    if not isinstance(works_for, dict):
        return None, None
    return _clean_text(works_for.get("name")), _clean_text(works_for.get("url"))


def _json_ld_same_as(node: dict[str, Any]) -> tuple[str, ...]:
    same_as = node.get("sameAs") or node.get("sameas")
    values: list[str] = []
    if isinstance(same_as, list):
        items = same_as
    elif same_as is None:
        items = []
    else:
        items = [same_as]
    for item in items:
        text = _clean_text(item)
        if text:
            values.append(text)
    return tuple(values)


def _json_ld_authors(html: str) -> list[_AuthorshipEntity]:
    entities: list[_AuthorshipEntity] = []
    nodes: list[dict[str, Any]] = []
    for match in _JSON_LD_RE.finditer(html or ""):
        body = (match.group("body") or "").strip()
        if not body:
            continue
        try:
            payload = json.loads(body)
        except Exception:  # noqa: BLE001 - malformed JSON-LD is skipped
            continue
        nodes.extend(_walk_dicts(payload))
    index = _json_ld_index(nodes)

    for node in nodes:
        entity_type = _is_target_entity(node)
        if not entity_type:
            continue
        for prop in _TARGET_PROPERTIES:
            if prop not in node:
                continue
            seen_ids: set[str] = set()
            for person in _json_ld_person_from_value(node.get(prop), index, seen_ids=seen_ids):
                name = _clean_text(person.get("name"))
                if not name:
                    continue
                works_for_name, works_for_url = _json_ld_works_for(person, index)
                entities.append(
                    _AuthorshipEntity(
                        name=name,
                        email=_clean_email(person.get("email")),
                        job_title=_clean_text(person.get("jobTitle") or person.get("title")),
                        works_for_name=works_for_name,
                        works_for_url=works_for_url,
                        same_as=_json_ld_same_as(person),
                        source_type="json_ld",
                        target_entity_type=entity_type,
                        target_property=prop,
                    )
                )
    return entities


def _microdata_itemtypes(node: _HtmlNode) -> list[str]:
    itemtype = node.attrs.get("itemtype") or ""
    if not itemtype:
        return []
    return _normalise_type(itemtype)


def _microdata_is_person(node: _HtmlNode) -> bool:
    return any(type_name in _PERSON_TYPES for type_name in _microdata_itemtypes(node))


def _microdata_is_target_entity(node: _HtmlNode) -> str | None:
    for type_name in _microdata_itemtypes(node):
        if type_name in _TARGET_ENTITY_TYPES:
            return type_name
    return None


def _microdata_itemprop(node: _HtmlNode) -> list[str]:
    prop = node.attrs.get("itemprop") or ""
    if not prop:
        return []
    return [item for item in re.split(r"\s+", prop.strip().lower()) if item]


def _microdata_property_value(node: _HtmlNode) -> str | None:
    for attr in ("content", "href", "src", "value"):
        value = _clean_text(node.attrs.get(attr))
        if not value:
            continue
        if attr == "href" and value.lower().startswith("mailto:"):
            return _clean_email(value)
        return value
    text = _clean_text(node.text)
    return text


def _microdata_collect_descendants(node: _HtmlNode) -> list[_HtmlNode]:
    out: list[_HtmlNode] = []
    for child in node.children:
        out.append(child)
        out.extend(_microdata_collect_descendants(child))
    return out


def _microdata_person_from_node(node: _HtmlNode) -> _AuthorshipEntity | None:
    if not _microdata_is_person(node):
        return None

    fields: dict[str, list[Any]] = {
        "name": [],
        "email": [],
        "jobTitle": [],
        "worksFor_name": [],
        "worksFor_url": [],
        "sameAs": [],
    }

    def walk(scope: _HtmlNode) -> None:
        for child in scope.children:
            props = _microdata_itemprop(child)
            if props:
                for prop in props:
                    if prop == "sameas":
                        value = _microdata_property_value(child)
                        if value:
                            fields["sameAs"].append(value)
                    elif prop in ("name", "givenname", "familyname"):
                        value = _microdata_property_value(child)
                        if value:
                            fields["name"].append(value)
                    elif prop == "email":
                        value = _microdata_property_value(child)
                        if value:
                            fields["email"].append(_clean_email(value))
                    elif prop in ("jobtitle", "title"):
                        value = _microdata_property_value(child)
                        if value:
                            fields["jobTitle"].append(value)
                    elif prop == "worksfor":
                        if child.attrs.get("itemscope") is not None:
                            org_name, org_url = _microdata_org_from_node(child)
                            if org_name:
                                fields["worksFor_name"].append(org_name)
                            if org_url:
                                fields["worksFor_url"].append(org_url)
                        else:
                            value = _microdata_property_value(child)
                            if value:
                                fields["worksFor_name"].append(value)
                    elif prop in _TARGET_PROPERTIES:
                        # Nested author-like property inside the person scope
                        # is ignored here; we are already inside the person.
                        pass
            # Nested itemscopes are values on their parent property and
            # can themselves contain useful fields such as worksFor.
            if child.attrs.get("itemscope") is not None:
                walk(child)
            else:
                walk(child)

    walk(node)

    name = next((str(item).strip() for item in fields["name"] if _clean_text(item)), None)
    if not name:
        return None

    same_as = tuple(
        item
        for item in (
            _clean_text(value)
            for value in fields["sameAs"]
        )
        if item
    )
    works_for_name = next((str(item).strip() for item in fields["worksFor_name"] if _clean_text(item)), None)
    works_for_url = next((str(item).strip() for item in fields["worksFor_url"] if _clean_text(item)), None)
    job_title = next((str(item).strip() for item in fields["jobTitle"] if _clean_text(item)), None)
    email = next((str(item).strip() for item in fields["email"] if _clean_email(item)), None)

    return _AuthorshipEntity(
        name=name,
        email=_clean_email(email),
        job_title=_clean_text(job_title),
        works_for_name=_clean_text(works_for_name),
        works_for_url=_clean_text(works_for_url),
        same_as=same_as,
        source_type="microdata",
    )


def _microdata_org_from_node(node: _HtmlNode) -> tuple[str | None, str | None]:
    if "itemscope" not in node.attrs:
        return None, None
    name: str | None = None
    url: str | None = None

    def walk(scope: _HtmlNode) -> None:
        nonlocal name, url
        for child in scope.children:
            props = _microdata_itemprop(child)
            if "name" in props and name is None:
                name = _clean_text(_microdata_property_value(child))
            if "url" in props and url is None:
                url = _clean_text(_microdata_property_value(child))
            if child.children:
                walk(child)

    walk(node)
    return name, url


def _microdata_authors(html: str) -> list[_AuthorshipEntity]:
    builder = _HtmlTreeBuilder()
    builder.feed(html or "")
    builder.close()
    out: list[_AuthorshipEntity] = []

    for node in _microdata_collect_descendants(builder.root):
        entity_type = _microdata_is_target_entity(node)
        if not entity_type:
            continue
        for child in _microdata_collect_descendants(node):
            props = _microdata_itemprop(child)
            if not props or "itemscope" not in child.attrs:
                continue
            if not any(prop in _TARGET_PROPERTIES for prop in props):
                continue
            person = _microdata_person_from_node(child)
            if person is None:
                continue
            out.append(
                _AuthorshipEntity(
                    name=person.name,
                    email=person.email,
                    job_title=person.job_title,
                    works_for_name=person.works_for_name,
                    works_for_url=person.works_for_url,
                    same_as=person.same_as,
                    source_type="microdata",
                    target_entity_type=entity_type,
                    target_property=next(prop for prop in props if prop in _TARGET_PROPERTIES),
                )
            )
    return out


def _works_for_matches_domain(
    works_for_name: str | None,
    works_for_url: str | None,
    target_domain: str | None,
) -> bool:
    if not target_domain:
        return False
    domain = target_domain.strip().lower()
    if not domain:
        return False
    candidates = [works_for_name or "", works_for_url or ""]
    for candidate in candidates:
        if not candidate:
            continue
        text = candidate.strip().lower()
        if not text:
            continue
        if domain in text:
            return True
        if text.startswith("http://") or text.startswith("https://"):
            host = urlparse(text).netloc.lower()
            if host == domain or host.endswith("." + domain):
                return True
            if host and host.rsplit(".", 2)[-2:] == domain.rsplit(".", 2)[-2:]:
                return True
    return False


def _dedupe_entities(entities: list[_AuthorshipEntity]) -> list[_AuthorshipEntity]:
    seen: set[tuple[str, str | None, str | None, str | None, tuple[str, ...]]] = set()
    deduped: list[_AuthorshipEntity] = []
    for entity in entities:
        key = (
            entity.name.lower(),
            entity.email.lower() if entity.email else None,
            entity.job_title.lower() if entity.job_title else None,
            (entity.works_for_name or "").lower() or None,
            entity.same_as,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entity)
    return deduped


class SchemaContentExtractor:
    """Extract authorship-oriented Person signals from schema graphs."""

    def __init__(self, pool: AsyncSignalPool, source: str = "schema_content") -> None:
        if pool is None:
            raise ValueError("SchemaContentExtractor requires a non-None AsyncSignalPool")
        self._pool = pool
        self._source = source

    async def extract_from_html(
        self,
        html: bytes | str,
        *,
        page_url: str | None = None,
        target_domain: str | None = None,
    ) -> int:
        """Parse *html* and publish discovered people into the pool."""
        decoded = _decode_html(html)
        if not decoded:
            return 0

        entities = _dedupe_entities(_json_ld_authors(decoded) + _microdata_authors(decoded))
        if not entities:
            return 0

        signals: list[Signal] = []
        for entity in entities:
            flags = set()
            if _works_for_matches_domain(entity.works_for_name, entity.works_for_url, target_domain):
                flags.add("worksfor_match")
            slug_or_email = normalize_slug_or_email(entity.email)
            meta = {
                "name": entity.name,
                "slug_or_email": slug_or_email,
                "page_url": page_url,
                "target_domain": target_domain,
                "source_type": entity.source_type,
                "target_entity_type": entity.target_entity_type,
                "target_property": entity.target_property,
                "person": {
                    "name": entity.name,
                    "email": entity.email,
                    "jobTitle": entity.job_title,
                    "worksFor": {
                        "name": entity.works_for_name,
                        "url": entity.works_for_url,
                    }
                    if entity.works_for_name or entity.works_for_url
                    else None,
                    "sameAs": list(entity.same_as),
                },
            }
            if entity.name:
                signals.append(
                    Signal(
                        source=self._source,
                        kind="name",
                        value=entity.name,
                        metadata=meta,
                        flags=frozenset(flags),
                    )
                )
            if entity.email:
                signals.append(
                    Signal(
                        source=self._source,
                        kind="email",
                        value=entity.email,
                        metadata=meta,
                        flags=frozenset(flags),
                    )
                )
            signals.append(
                Signal(
                    source=self._source,
                    kind="schema",
                    value=entity.name or entity.email or entity.target_property or "schema",
                    metadata=meta,
                    flags=frozenset(flags),
                )
            )

        if not signals:
            return 0
        try:
            await self._pool.publish_many(signals)
        except Exception:  # pragma: no cover - defensive
            _LOG.exception("SchemaContentExtractor failed to publish signals")
            raise
        return len(entities)
