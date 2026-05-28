from __future__ import annotations

import csv
import io
from typing import Any

from .base import BaseExporter


class MaltegoExporter(BaseExporter):
    format_name = "maltego"
    content_type = "text/csv"

    def export(self, _investigation_id: str, data: dict[str, Any]) -> bytes:
        email = data.get("email", "")
        findings = data.get("findings", [])
        credential_score = data.get("credential_risk_score", "")
        credential_band = data.get("credential_risk_band", "")
        score_drivers = " | ".join(str(item) for item in data.get("score_drivers", []))
        recommended_actions = " | ".join(
            str(item) for item in data.get("recommended_actions", [])
        )
        credibility = data.get("email_credibility") if isinstance(data.get("email_credibility"), dict) else {}
        canonical_email = str(credibility.get("canonical_email") or data.get("canonical_email") or email)
        provider_family = str(credibility.get("provider_family") or "")
        reputation_verdict = str(credibility.get("reputation_verdict") or "clean")
        reputation_flags = ", ".join(str(item) for item in credibility.get("reputation_flags", []))
        is_disposable = bool(credibility.get("is_disposable"))
        is_malicious = bool(credibility.get("is_malicious"))

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "Entity Type",
                "Value",
                "Weight",
                "DataClasses",
                "CredentialRiskScore",
                "CredentialRiskBand",
                "ScoreDrivers",
                "RecommendedActions",
                "Link#maltego.Link",
            ]
        )

        writer.writerow(
            [
                "maltego.EmailAddress",
                email,
                100,
                "",
                credential_score,
                credential_band,
                score_drivers,
                recommended_actions,
                email,
            ]
        )

        writer.writerow(
            [
                "maltego.Phrase",
                f"Email credibility: {reputation_verdict}",
                90 if is_malicious else 60 if is_disposable else 40,
                reputation_flags,
                credential_score,
                credential_band,
                score_drivers,
                recommended_actions,
                canonical_email,
            ]
        )

        if provider_family:
            writer.writerow(
                [
                    "maltego.Phrase",
                    f"Provider family: {provider_family}",
                    30,
                    "",
                    credential_score,
                    credential_band,
                    score_drivers,
                    recommended_actions,
                    canonical_email,
                ]
            )

        seen_persons: set[str] = set()

        for finding in findings:
            f_data = finding.get("data", {}) or {}
            module_name = finding.get("module_name", "")
            metadata = f_data.get("metadata", {}) or {}
            for row in _finding_to_rows(email, module_name, f_data, metadata, seen_persons):
                writer.writerow(
                    [
                        row[0],
                        row[1],
                        row[2],
                        row[3],
                        credential_score,
                        credential_band,
                        score_drivers,
                        recommended_actions,
                        row[4],
                    ]
                )

        return buf.getvalue().encode("utf-8")


def _finding_to_rows(
    email: str,
    module_name: str,
    f_data: dict[str, Any],
    metadata: dict[str, Any],
    seen_persons: set[str],
) -> list[list[Any]]:
    if module_name in ("haveibeenpwned", "hibp", "xposedornot") or "breach_name" in f_data:
        breach_name = f_data.get("breach_name", "Unknown")
        breach_date = f_data.get("breach_date", "")
        value = f"{breach_name} breach ({breach_date})" if breach_date else f"{breach_name} breach"
        data_classes = f_data.get("data_classes") or []
        dc_str = ", ".join(data_classes)
        severity = f_data.get("severity", "medium")
        weight = 90 if severity == "critical" else 70 if severity == "high" else 50
        return [["maltego.Phrase", value, weight, dc_str, email]]

    if module_name == "gravatar" or "photo_url" in f_data:
        photo_url = f_data.get("photo_url", "")
        if not photo_url:
            return []
        return [["maltego.URL", photo_url, 40, "", email]]

    if module_name in ("dns_lookup", "whois_lookup") or "domain" in f_data:
        rows: list[list[Any]] = []
        domain = f_data.get("domain", "")
        if domain:
            rows.append(["maltego.Domain", domain, 70, "", email])
        registrant_org = f_data.get("registrant_org") or metadata.get("registrant_org", "")
        if registrant_org:
            rows.append(["maltego.Organization", registrant_org, 60, "", email])
        registrant_name = f_data.get("registrant_name") or metadata.get("registrant_name", "")
        if registrant_name and registrant_name not in seen_persons:
            seen_persons.add(registrant_name)
            rows.append(["maltego.Person", registrant_name, 60, "", email])
        return rows

    status = f_data.get("status", "")
    weight = 80 if status == "confirmed" else 50
    display_name = metadata.get("display_name") or f_data.get("display_name", "")
    username = metadata.get("username") or f_data.get("username", "")
    profile_url = f_data.get("profile_url") or metadata.get("profile_url", "")

    rows: list[list[Any]] = []
    if display_name:
        rows.append(["maltego.Person", display_name, weight, "", email])
    if username:
        rows.append(["maltego.Alias", username, weight, "", email])
    if profile_url:
        rows.append(["maltego.URL", profile_url, weight, "", email])
    return rows
