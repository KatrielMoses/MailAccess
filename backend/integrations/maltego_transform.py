"""TRX protocol helpers for Maltego local transform server.

Covers XML request parsing, XML response building, and one-time MTZ bundle
generation for import into Maltego Desktop.
"""
from __future__ import annotations

import io
import logging
import os
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("mailaccess.maltego")

# ---------------------------------------------------------------------------
# MTZ bundle templates
# ---------------------------------------------------------------------------

_TRANSFORM_SET_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<MaltegoTransformSet name="MailAccess"
    description="MailAccess OSINT email investigation transforms">
    <Transforms>
        <Transform name="mailaccess.EmailInvestigate"/>
    </Transforms>
</MaltegoTransformSet>
"""

_EMAIL_INVESTIGATE_TRANSFORM = """\
<?xml version="1.0" encoding="UTF-8"?>
<MaltegoTransform name="mailaccess.EmailInvestigate"
    displayName="[MailAccess] Email Investigate"
    abstract="false" template="false" visibility="public"
    description="Run full OSINT investigation on an email address via MailAccess"
    author="MailAccess" requireDisplayInfo="false">
    <TransformAdapter>com.paterva.maltego.transform.protocol.v2api.RemoteTransformAdapterV2</TransformAdapter>
    <Properties>
        <Fields>
            <Field name="transform.remote.url" type="string"
                nullable="false" hidden="false" readonly="false"
                description="">http://localhost:8000/maltego/email_investigate</Field>
        </Fields>
    </Properties>
    <InputConstraints>
        <Entity type="maltego.EmailAddress" min="1" max="1"/>
    </InputConstraints>
    <OutputEntities/>
    <defaultSets>
        <Set>MailAccess</Set>
    </defaultSets>
    <StealthLevel>0</StealthLevel>
</MaltegoTransform>
"""


def generate_mtz_bundle(path: str | os.PathLike) -> None:
    """Write the Maltego config bundle to *path* if it does not already exist."""
    p = Path(path)
    if p.exists():
        return
    p.parent.mkdir(parents=True, exist_ok=True)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("TransformSet.xml", _TRANSFORM_SET_XML)
        zf.writestr("Transforms/EmailInvestigate.transform", _EMAIL_INVESTIGATE_TRANSFORM)

    p.write_bytes(buf.getvalue())
    logger.info(
        "Maltego transform bundle at %s — import into Maltego via Manage → Import Config", p
    )


# ---------------------------------------------------------------------------
# TRX XML parsing
# ---------------------------------------------------------------------------


def parse_request(xml_body: bytes | str) -> str:
    """Extract the email address from a TRX request body.

    Raises ValueError if the body is malformed or contains no EmailAddress entity.
    """
    text = xml_body if isinstance(xml_body, str) else xml_body.decode("utf-8")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"Malformed TRX XML: {exc}") from exc

    for entity in root.iter("Entity"):
        if entity.get("Type") == "maltego.EmailAddress":
            value = entity.findtext("Value")
            if value and value.strip():
                return value.strip()

    raise ValueError("No maltego.EmailAddress entity found in TRX request")


# ---------------------------------------------------------------------------
# TRX XML response building
# ---------------------------------------------------------------------------


def build_response(data: dict[str, Any], partial: bool = False) -> bytes:
    """Build a TRX XML response from an enriched investigation result dict.

    If *partial* is True a PartialError UIMessage is included to signal that
    the investigation timed out and results may be incomplete.
    """
    entities = _collect_entities(data)

    root = ET.Element("MaltegoMessage")
    resp = ET.SubElement(root, "MaltegoTransformResponseMessage")
    entities_el = ET.SubElement(resp, "Entities")

    for ent in entities:
        entity_el = ET.SubElement(entities_el, "Entity")
        entity_el.set("Type", ent["type"])

        value_el = ET.SubElement(entity_el, "Value")
        value_el.text = str(ent["value"])

        weight_el = ET.SubElement(entity_el, "Weight")
        weight_el.text = str(ent["weight"])

        if ent["fields"]:
            additional = ET.SubElement(entity_el, "AdditionalFields")
            for name, (display, field_value) in ent["fields"].items():
                field_el = ET.SubElement(additional, "Field")
                field_el.set("Name", name)
                field_el.set("DisplayName", display)
                field_el.text = str(field_value)

    ui_messages = ET.SubElement(resp, "UIMessages")
    if partial:
        msg = ET.SubElement(ui_messages, "UIMessage")
        msg.set("MessageType", "PartialError")
        msg.text = "Investigation timed out — showing partial results"
    else:
        msg = ET.SubElement(ui_messages, "UIMessage")
        msg.set("MessageType", "Inform")
        msg.text = "Investigation complete"

    return _serialise(root)


def build_error_response(message: str) -> bytes:
    """Build a TRX FatalError XML response."""
    root = ET.Element("MaltegoMessage")
    resp = ET.SubElement(root, "MaltegoTransformResponseMessage")
    ET.SubElement(resp, "Entities")
    ui_messages = ET.SubElement(resp, "UIMessages")
    msg = ET.SubElement(ui_messages, "UIMessage")
    msg.set("MessageType", "FatalError")
    msg.text = message
    return _serialise(root)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _serialise(root: ET.Element) -> bytes:
    """Serialise an ElementTree root to UTF-8 bytes with XML declaration."""
    declaration = b'<?xml version="1.0" encoding="UTF-8"?>\n'
    return declaration + ET.tostring(root, encoding="unicode").encode("utf-8")


def _collect_entities(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert investigation findings to Maltego entities.

    Returns at most 100 entities sorted by descending weight (confidence).
    Mirrors the entity-type mapping in MaltegoExporter so both outputs are
    consistent.
    """
    email = data.get("email", "")
    findings = data.get("findings", [])

    seen: set[tuple[str, str]] = set()
    result: list[dict[str, Any]] = []

    def add(
        type_: str,
        value: str,
        weight: int,
        source: str,
        extra: dict[str, tuple[str, Any]] | None = None,
    ) -> None:
        if not value:
            return
        key = (type_, value)
        if key in seen:
            return
        seen.add(key)
        fields: dict[str, tuple[str, Any]] = {"source": ("Source", source)}
        if extra:
            fields.update(extra)
        result.append({"type": type_, "value": value, "weight": weight, "fields": fields})

    add("maltego.EmailAddress", email, 100, "mailaccess")

    for f in findings:
        f_data = f.get("data", {}) or {}
        module_name = f.get("module_name", "")
        metadata = f_data.get("metadata", {}) or {}

        if module_name in ("haveibeenpwned", "hibp", "xposedornot") or "breach_name" in f_data:
            breach_name = f_data.get("breach_name", "Unknown")
            breach_date = f_data.get("breach_date", "")
            label = (
                f"{breach_name} breach ({breach_date})" if breach_date else f"{breach_name} breach"
            )
            severity = f_data.get("severity", "medium")
            weight = 90 if severity == "critical" else 70 if severity == "high" else 50
            data_classes = f_data.get("data_classes") or []
            extra = (
                {"dataclasses": ("Data Classes", ", ".join(data_classes))} if data_classes else None
            )
            add("maltego.Phrase", label, weight, module_name, extra)
            continue

        if module_name == "gravatar" or "photo_url" in f_data:
            photo_url = f_data.get("photo_url", "")
            if photo_url:
                add("maltego.URL", photo_url, 40, module_name)
            continue

        if module_name in ("dns_lookup", "whois_lookup") or "domain" in f_data:
            domain = f_data.get("domain", "")
            if domain:
                add("maltego.Domain", domain, 70, module_name)
            org = f_data.get("registrant_org") or metadata.get("registrant_org", "")
            if org:
                add("maltego.Organization", org, 60, module_name)
            name = f_data.get("registrant_name") or metadata.get("registrant_name", "")
            if name:
                add("maltego.Person", name, 60, module_name)
            continue

        # UserAccount / social finding
        status = f_data.get("status", "")
        weight = 80 if status == "confirmed" else 50
        display_name = metadata.get("display_name") or f_data.get("display_name", "")
        username = metadata.get("username") or f_data.get("username", "")
        profile_url = f_data.get("profile_url") or metadata.get("profile_url", "")

        if display_name:
            add("maltego.Person", display_name, weight, module_name)
        if username:
            add("maltego.Alias", username, weight, module_name)
        if profile_url:
            add("maltego.URL", profile_url, weight, module_name)

    result.sort(key=lambda e: e["weight"], reverse=True)
    return result[:100]
