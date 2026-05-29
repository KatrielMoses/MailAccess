from __future__ import annotations

from typing import Any

from .base import BaseExporter


def _summary_profile_intelligence(fbm: dict[str, Any]) -> dict[str, Any]:
    profile: dict[str, Any] = {}
    gh = [f for f in fbm.get("github_commits", []) if isinstance(f, dict) and f.get("platform") == "github_user"]
    if gh:
        profile["github"] = gh[0].get("metadata", {})
    tw = [f for f in fbm.get("twitter_profile", []) if isinstance(f, dict) and f.get("platform") == "twitter_profile"]
    if tw:
        profile["twitter"] = tw[0].get("metadata", {})
    li = [f for f in fbm.get("linkedin_serp", []) if isinstance(f, dict) and f.get("platform") == "linkedin_snippet"]
    if li:
        profile["linkedin"] = li[0].get("metadata", {})
    kb = [f for f in fbm.get("keybase", []) if isinstance(f, dict) and f.get("platform") == "keybase_profile"]
    if kb:
        profile["keybase"] = kb[0].get("metadata", {})
    return profile


def _summary_pii(fbm: dict[str, Any]) -> list[dict[str, Any]]:
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
                    pii_items.append({"type": "phone", "value": phone, "module": module_name})
            elif sig == "email_in_bio":
                email = str(meta.get("email") or "").strip()
                if email:
                    pii_items.append({"type": "email", "value": email, "module": module_name})
    return pii_items


class MarkdownExporter(BaseExporter):
    format_name = "markdown"
    content_type = "text/markdown"

    def export(self, investigation_id: str, data: dict[str, Any]) -> bytes:
        lines: list[str] = []

        email = data.get("email", "unknown")
        timestamp = data.get("created_at", "unknown")

        def _cell(value: Any) -> str:
            return str(value if value is not None else "").replace("\n", " ").replace("|", "\\|")

        lines.append("# MailAccess Investigation Report")
        lines.append(f"> {email} - {timestamp}")
        lines.append("")

        credibility = data.get("email_credibility")
        if isinstance(credibility, dict) and credibility:
            lines.append("## Email Credibility")
            lines.append("| Field | Value |")
            lines.append("| --- | --- |")
            for key in (
                "canonical_email",
                "provider_family",
                "is_alias",
                "aliases_detected",
                "is_disposable",
                "disposable_provider",
                "reputation_verdict",
                "reputation_flags",
                "is_malicious",
                "first_seen",
                "domain_age_days",
                "domain_age_note",
            ):
                value = credibility.get(key)
                if value is None or value == "":
                    continue
                lines.append(f"| {key} | {value} |")
            lines.append("")

        score = data.get("exposure_score")
        risk = data.get("risk_level", "unknown")
        credential_score = data.get("credential_risk_score")
        credential_band = data.get("credential_risk_band", "UNKNOWN")
        findings = data.get("findings", [])
        total_findings = len(findings)
        breach_count = sum(
            1
            for finding in findings
            if finding.get("module_name", "").lower()
            in ("hibp", "haveibeenpwned", "xposedornot")
        )

        runs = data.get("module_runs", [])
        modules_run = len(runs)
        modules_failed = sum(1 for run in runs if run.get("status") == "failed")

        lines.append("## Executive Summary")
        lines.append("| Field | Value |")
        lines.append("| --- | --- |")
        lines.append(f"| Exposure Score | {score if score is not None else 'N/A'} |")
        lines.append(f"| Risk Level | {risk} |")
        credential_value = credential_score if credential_score is not None else "N/A"
        lines.append(
            f"| Credential Risk | {credential_value} ({credential_band}) |"
        )
        lines.append(f"| Total Findings | {total_findings} |")
        lines.append(f"| Breach Count | {breach_count} |")
        lines.append(f"| Modules Run | {modules_run} |")
        lines.append(f"| Modules Failed | {modules_failed} |")
        lines.append("")

        lines.append("## Credential Risk Drivers")
        drivers = data.get("score_drivers", []) or ["No credential risk drivers recorded."]
        for driver in drivers:
            if driver == "No credential risk drivers recorded.":
                lines.append(driver)
            else:
                lines.append(f"- {driver}")
        lines.append("")

        lines.append("## Recommended Actions")
        actions = data.get("recommended_actions", []) or ["No follow-up actions recorded."]
        for action in actions:
            if action == "No follow-up actions recorded.":
                lines.append(action)
            else:
                lines.append(f"- {action}")
        lines.append("")

        timeline = data.get("timeline") if isinstance(data.get("timeline"), dict) else {}
        events = timeline.get("events") if isinstance(timeline.get("events"), list) else []
        lines.append("## Exposure Timeline")
        if events:
            lines.append(
                f"- First seen: {timeline.get('first_seen_date') or 'unknown'} "
                f"({timeline.get('first_seen_source') or 'unknown'})"
            )
            lines.append(
                f"- Most recent: {timeline.get('most_recent_date') or 'unknown'} "
                f"({timeline.get('most_recent_event') or 'unknown'})"
            )
            lines.append(
                f"- Active risk count: {timeline.get('active_risk_count', 0)}"
            )
            lines.append("")
            lines.append("| Date | Type | Event | Source | Detail |")
            lines.append("| --- | --- | --- | --- | --- |")
            for event in events:
                if not isinstance(event, dict):
                    continue
                marker = " (active risk)" if event.get("is_active_risk") else ""
                lines.append(
                    "| "
                    f"{_cell(event.get('date', ''))} | "
                    f"{_cell(event.get('event_type', ''))} | "
                    f"{_cell(str(event.get('title', '')) + marker)} | "
                    f"{_cell(event.get('source_module', ''))} | "
                    f"{_cell(event.get('detail'))} |"
                )
        else:
            lines.append("No dated exposure events recovered.")
        lines.append("")

        alt_emails = [
            f.get("data", f)
            for f in data.get("findings", [])
            if f.get("module_name") == "alternate_email"
        ]
        if alt_emails:
            lines.append("## Alternate Emails")
            for f in alt_emails:
                meta = f.get("metadata", {})
                disc_email = meta.get("discovered_email", "unknown")
                conf = str(f.get("confidence", "unknown")).upper()
                source = meta.get("source", "unknown")
                source_detail = meta.get("source_detail", "")
                reason = meta.get("reason", "")
                lines.append(f"- **{disc_email}** (Confidence: {conf})")
                source_str = source
                if source_detail:
                    source_str += f" ({source_detail})"
                lines.append(f"  - Source: {source_str}")
                if reason:
                    lines.append(f"  - Reason: {reason}")
            lines.append("")

        fbm = data.get("findings_by_module", {})
        profile = _summary_profile_intelligence(fbm)
        if profile:
            lines.append("## Profile Intelligence")
            for section_name, section_data in profile.items():
                if not section_data:
                    continue
                lines.append(f"### {section_name.title()}")
                if isinstance(section_data, dict):
                    for key, value in section_data.items():
                        if value is None or value == "":
                            continue
                        if isinstance(value, list):
                            continue
                        lines.append(f"- **{key}**: {value}")
                lines.append("")
            lines.append("")

        pii_items = _summary_pii(fbm)
        if pii_items:
            lines.append("## PII Extracted")
            for item in pii_items:
                lines.append(f"- **{item.get('type', 'unknown')}**: {item.get('value', '')} ({item.get('module', 'unknown')})")
            lines.append("")

        lines.append("## Findings by Module")
        findings_by_module = data.get("findings_by_module", {})
        runs_by_module = {run.get("module_name"): run for run in runs}

        if not findings_by_module:
            lines.append("No findings.\n")

        for module_name, module_findings in findings_by_module.items():
            run_info = runs_by_module.get(module_name, {})
            status = run_info.get("status", "unknown")
            lines.append(f"### {module_name} - {status}")

            for f_data in module_findings:
                platform = f_data.get("platform", "Unknown Platform")
                lines.append(f"#### {platform}")

                metadata = f_data.get("metadata") or {}
                if metadata:
                    has_rows = False
                    for key, value in metadata.items():
                        if value is not None and value != "":
                            if not has_rows:
                                lines.append("| Key | Value |")
                                lines.append("| --- | --- |")
                                has_rows = True
                            lines.append(f"| {key} | {value} |")
                    if has_rows:
                        lines.append("")

                profile_url = f_data.get("profile_url")
                if profile_url:
                    lines.append(f"[Profile URL]({profile_url})")
                    lines.append("")

        lines.append("## Metadata Table")
        lines.append("| Data Type | Value | Source Module |")
        lines.append("| --- | --- | --- |")

        metadata_rows: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()

        for finding in findings:
            module_name = finding.get("module_name", "unknown")
            f_data = finding.get("data", {})
            meta = f_data.get("metadata", {})

            for key, value in meta.items():
                if not value:
                    continue
                key_lower = key.lower()
                data_type = None

                if "name" in key_lower and "username" not in key_lower:
                    data_type = "names"
                elif "username" in key_lower:
                    data_type = "usernames"
                elif any(token in key_lower for token in ("photo", "avatar", "image", "thumbnail")):
                    data_type = "photos"
                elif "phone" in key_lower:
                    data_type = "phones"
                elif "location" in key_lower:
                    data_type = "locations"

                if data_type:
                    values = value if isinstance(value, list) else [value]
                    for item in values:
                        value_str = str(item).strip()
                        if not value_str:
                            continue
                        sig = (data_type, value_str, module_name)
                        if sig not in seen:
                            seen.add(sig)
                            metadata_rows.append(sig)

        if metadata_rows:
            metadata_rows.sort(key=lambda item: (item[0], item[1]))
            for data_type, value, module_name in metadata_rows:
                lines.append(f"| {data_type} | {value} | {module_name} |")
        else:
            lines.append("| No recovered data points | - | - |")
        lines.append("")

        lines.append("## Module Run Log")
        lines.append("| Module | Status | Findings Count | Errors |")
        lines.append("| --- | --- | --- | --- |")

        for run in runs:
            module_name = run.get("module_name", "unknown")
            status = run.get("status", "unknown")
            error = run.get("error") or ""
            count = len(findings_by_module.get(module_name, []))
            lines.append(f"| {module_name} | {status} | {count} | {error} |")

        return "\n".join(lines).encode("utf-8")
