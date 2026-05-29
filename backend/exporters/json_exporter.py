from __future__ import annotations

import json
from datetime import date, datetime
from enum import Enum
from typing import Any

from .base import BaseExporter


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        return super().default(obj)


def _build_profile_intelligence(fbm: dict[str, Any]) -> dict[str, Any]:
    profile: dict[str, Any] = {}

    gh_findings = [
        f for f in fbm.get("github_commits", [])
        if isinstance(f, dict) and f.get("platform") == "github_user"
    ]
    if gh_findings:
        profile["github"] = gh_findings[0].get("metadata") or {}

    grav_findings = [
        f for f in fbm.get("gravatar", [])
        if isinstance(f, dict) and f.get("platform") == "gravatar_profile"
    ]
    if grav_findings:
        profile["gravatar"] = grav_findings[0].get("metadata") or {}

    kb_findings = [
        f for f in fbm.get("keybase", [])
        if isinstance(f, dict) and f.get("platform") == "keybase_profile"
    ]
    if kb_findings:
        profile["keybase"] = kb_findings[0].get("metadata") or {}

    pypi = [
        f for f in fbm.get("pypi_discovery", [])
        if isinstance(f, dict) and f.get("signal_type") == "package_authorship"
    ]
    if pypi:
        profile["pypi_packages"] = pypi

    npm = [
        f for f in fbm.get("npm_discovery", [])
        if isinstance(f, dict) and f.get("signal_type") == "package_authorship"
    ]
    if npm:
        profile["npm_packages"] = npm

    tw_findings = [
        f for f in fbm.get("twitter_profile", [])
        if isinstance(f, dict) and f.get("platform") == "twitter_profile"
    ]
    if tw_findings:
        profile["twitter"] = tw_findings[0].get("metadata") or {}

    li_findings = [
        f for f in fbm.get("linkedin_serp", [])
        if isinstance(f, dict) and f.get("platform") == "linkedin_snippet"
    ]
    if li_findings:
        profile["linkedin"] = li_findings[0].get("metadata") or {}

    etsy_findings = [
        f for f in fbm.get("marketplace_profile", [])
        if isinstance(f, dict) and f.get("platform") == "etsy_shop"
    ]
    if etsy_findings:
        profile["etsy"] = etsy_findings[0].get("metadata") or {}

    ebay_findings = [
        f for f in fbm.get("marketplace_profile", [])
        if isinstance(f, dict) and f.get("platform") == "ebay_profile"
    ]
    if ebay_findings:
        profile["ebay"] = ebay_findings[0].get("metadata") or {}

    return profile


def _build_pii_findings(fbm: dict[str, Any]) -> list[dict[str, Any]]:
    pii_items: list[dict[str, Any]] = []

    for module_name, findings in fbm.items():
        for f in findings:
            if not isinstance(f, dict):
                continue
            sig = str(f.get("signal_type") or "")
            meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}

            if sig == "phone_in_bio":
                phone = str(meta.get("phone") or "").strip()
                if phone:
                    pii_items.append({
                        "type": "phone",
                        "value": phone,
                        "confidence": str(f.get("confidence") or "medium").upper(),
                        "source_module": module_name,
                        "source_field": str(meta.get("source_field") or ""),
                    })
            elif sig == "email_in_bio":
                email = str(meta.get("email") or "").strip()
                if email:
                    pii_items.append({
                        "type": "email",
                        "value": email,
                        "confidence": str(f.get("confidence") or "medium").upper(),
                        "source_module": module_name,
                        "source_field": str(meta.get("source_field") or ""),
                    })

    for f in fbm.get("opencorporates", []):
        if not isinstance(f, dict):
            continue
        meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
        addr = str(meta.get("registered_address") or "").strip()
        company = str(meta.get("company_name") or "").strip()
        if addr:
            pii_items.append({
                "type": "address",
                "value": addr,
                "confidence": "MEDIUM",
                "source_module": "opencorporates",
                "company": company,
            })

    return pii_items


class JsonExporter(BaseExporter):
    format_name = "json"
    content_type = "application/json"

    def export(self, investigation_id: str, data: dict[str, Any]) -> bytes:
        payload = {"investigation_id": investigation_id, **data}
        payload.pop("credential_risk", None)
        
        alt_emails = []
        for f in data.get("findings", []):
            if f.get("module_name") == "alternate_email":
                meta = f.get("data", {}).get("metadata", {})
                if meta:
                    alt_emails.append(meta)
        payload["alternate_emails"] = alt_emails

        fbm = data.get("findings_by_module", {})
        payload["profile_intelligence"] = _build_profile_intelligence(fbm)
        payload["pii_findings"] = _build_pii_findings(fbm)
        
        return json.dumps(payload, cls=CustomJSONEncoder, indent=2).encode("utf-8")
