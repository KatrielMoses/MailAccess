from __future__ import annotations

import csv
import io
import json
from typing import Any

from .base import BaseExporter


class CsvExporter(BaseExporter):
    format_name = "csv"
    content_type = "text/csv"

    def export(self, investigation_id: str, data: dict[str, Any]) -> bytes:
        buf = io.StringIO()
        writer = csv.writer(buf)

        exposure_score = data.get("exposure_score")
        credential_score = data.get("credential_risk_score")
        credential_band = data.get("credential_risk_band", "")
        score_drivers = " | ".join(str(item) for item in data.get("score_drivers", []))
        recommended_actions = " | ".join(
            str(item) for item in data.get("recommended_actions", [])
        )
        email = data.get("email", "")
        credibility = data.get("email_credibility") if isinstance(data.get("email_credibility"), dict) else {}
        canonical_email = credibility.get("canonical_email", data.get("canonical_email", ""))
        provider_family = credibility.get("provider_family", "")
        is_disposable = credibility.get("is_disposable", "")
        disposable_provider = credibility.get("disposable_provider", "")
        reputation_verdict = credibility.get("reputation_verdict", "")
        reputation_flags = " | ".join(str(item) for item in credibility.get("reputation_flags", []))
        is_malicious = credibility.get("is_malicious", "")
        first_seen_emailrep = credibility.get("first_seen", "")
        timeline = data.get("timeline") if isinstance(data.get("timeline"), dict) else {}
        first_seen_date = timeline.get("first_seen_date", "")
        identity_age_years = timeline.get("identity_age_years", "")
        active_risk_count = timeline.get("active_risk_count", "")
        most_recent_date = timeline.get("most_recent_date", "")
        most_recent_event = timeline.get("most_recent_event", "")
        most_recent_exposure = (
            f"{most_recent_date} - {most_recent_event}"
            if most_recent_date and most_recent_event
            else most_recent_event or most_recent_date
        )

        alt_emails = [
            f.get("data", {}).get("metadata", {}).get("discovered_email")
            for f in data.get("findings", [])
            if f.get("module_name") == "alternate_email" and f.get("data", {}).get("metadata", {}).get("discovered_email")
        ]
        alternate_email_count = len(alt_emails)
        alternate_emails_str = ",".join(alt_emails)

        writer.writerow(
            [
                "investigation_id",
                "email",
                "canonical_email",
                "provider_family",
                "is_disposable",
                "disposable_provider",
                "reputation_verdict",
                "reputation_flags",
                "is_malicious",
                "first_seen_emailrep",
                "exposure_score",
                "credential_risk_score",
                "credential_risk_band",
                "first_seen_date",
                "identity_age_years",
                "active_risk_count",
                "most_recent_exposure",
                "score_drivers",
                "recommended_actions",
                "alternate_email_count",
                "alternate_emails",
                "timestamp",
                "module_name",
                "platform",
                "profile_url",
                "confidence",
                "severity",
                "metadata_json",
                "status",
            ]
        )

        findings = data.get("findings", [])
        if not findings:
            writer.writerow(
                [
                    investigation_id,
                    email,
                    canonical_email,
                    provider_family,
                    is_disposable,
                    disposable_provider,
                    reputation_verdict,
                    reputation_flags,
                    is_malicious,
                    first_seen_emailrep,
                    exposure_score if exposure_score is not None else "",
                    credential_score if credential_score is not None else "",
                    credential_band,
                    first_seen_date,
                    identity_age_years,
                    active_risk_count,
                    most_recent_exposure,
                    score_drivers,
                    recommended_actions,
                    alternate_email_count,
                    alternate_emails_str,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "{}",
                    "",
                ]
            )
            return buf.getvalue().encode("utf-8")

        for finding in findings:
            f_data = finding.get("data", {})
            metadata = f_data.get("metadata", {})
            metadata_json = json.dumps(metadata) if metadata else "{}"
            writer.writerow(
                [
                    investigation_id,
                    email,
                    canonical_email,
                    provider_family,
                    is_disposable,
                    disposable_provider,
                    reputation_verdict,
                    reputation_flags,
                    is_malicious,
                    first_seen_emailrep,
                    exposure_score if exposure_score is not None else "",
                    credential_score if credential_score is not None else "",
                    credential_band,
                    first_seen_date,
                    identity_age_years,
                    active_risk_count,
                    most_recent_exposure,
                    score_drivers,
                    recommended_actions,
                    alternate_email_count,
                    alternate_emails_str,
                    finding.get("created_at", ""),
                    finding.get("module_name", ""),
                    f_data.get("platform", ""),
                    f_data.get("profile_url", ""),
                    f_data.get("confidence", ""),
                    f_data.get("severity", ""),
                    metadata_json,
                    f_data.get("status", ""),
                ]
            )

        return buf.getvalue().encode("utf-8")
