from __future__ import annotations

import asyncio
import html as _html
from datetime import datetime, timezone
from typing import Any

from .base import BaseExporter

_RISK_CLASS = {
    "low": "risk-low",
    "medium": "risk-medium",
    "high": "risk-high",
    "critical": "risk-critical",
}

_STATUS_CLASS = {
    "success": "status-success",
    "failed": "status-failed",
    "skipped": "status-skipped",
}

_CONF_CLASS = {
    "high": "conf-high",
    "medium": "conf-medium",
    "low": "conf-low",
}


def _e(value: Any) -> str:
    if isinstance(value, list):
        return _html.escape(", ".join(str(v) for v in value))
    return _html.escape(str(value) if value is not None else "")


class PdfExporter(BaseExporter):
    format_name = "pdf"
    content_type = "application/pdf"

    def export(self, investigation_id: str, data: dict[str, Any]) -> bytes:
        raise NotImplementedError("Use generate() for PDF export")

    async def generate(self, investigation_id: str, data: dict[str, Any]) -> bytes:
        html_content = self._build_html(investigation_id, data)
        return await asyncio.to_thread(self._render_pdf, html_content)

    def _render_pdf(self, html_content: str) -> bytes:
        from weasyprint import HTML  # type: ignore[import-untyped]

        return HTML(string=html_content).write_pdf()  # type: ignore[no-any-return]

    def _build_html(self, investigation_id: str, data: dict[str, Any]) -> str:
        email = data.get("email", "unknown")
        score = data.get("exposure_score")
        risk = data.get("risk_level", "unknown")
        credential_score = data.get("credential_risk_score")
        credential_band = data.get("credential_risk_band", "UNKNOWN")
        risk_class = _RISK_CLASS.get(risk, "risk-unknown")
        summary = data.get("summary", "")

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
        findings_by_module = data.get("findings_by_module", {})
        score_drivers = data.get("score_drivers", [])
        recommended_actions = data.get("recommended_actions", [])
        credibility_html = self._credibility_html(data.get("email_credibility"))
        identity_html = self._identity_html(data)
        defenders_brief_html = self._defenders_brief_html(data.get("defenders_brief"))

        score_display = str(score) if score is not None else "-"
        credential_display = str(credential_score) if credential_score is not None else "-"
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        findings_html = self._findings_html(findings_by_module, runs)
        metadata_html = self._metadata_table_html(findings)
        log_html = self._module_log_html(runs, findings_by_module)
        timeline_html = self._timeline_html(data.get("timeline"))
        
        alt_emails = [
            f.get("data", f)
            for f in findings
            if f.get("module_name") == "alternate_email"
        ]
        alt_emails_html = self._alt_emails_html(alt_emails)
        
        driver_html = self._string_list_html(
            score_drivers, empty="No credential risk drivers recorded."
        )
        action_html = self._string_list_html(
            recommended_actions, empty="No credential follow-up actions recorded."
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>{self._css()}</style>
</head>
<body>

<header class="page-header">
  <div class="logo">Mail<span class="logo-access">Access</span></div>
  <div class="header-meta">
    <div class="header-email">{_e(email)}</div>
    <div>Generated {_e(generated_at)}</div>
    <div style="font-size:7pt">ID&nbsp;{_e(investigation_id)}</div>
  </div>
</header>

<section class="summary-card">
  <div class="score-row">
    <div class="score-number">{_e(score_display)}</div>
    <div>
      <div class="risk-badge {risk_class}">{_e(risk)}</div>
      <div style="font-size:7pt;color:#718096;margin-top:4px">exposure score / 100</div>
    </div>
  </div>
  <div class="credential-row">
    <div class="credential-pill">
      Credential Risk: <strong>{_e(credential_display)}/100</strong> {_e(credential_band)}
    </div>
    {identity_html}
  </div>
  <div class="stat-pills">
    <div class="pill"><strong>{_e(total_findings)}</strong>&nbsp;findings</div>
    <div class="pill"><strong>{_e(breach_count)}</strong>&nbsp;breaches</div>
    <div class="pill"><strong>{_e(modules_run)}</strong>&nbsp;modules run</div>
    <div class="pill"><strong>{_e(modules_failed)}</strong>&nbsp;failed</div>
  </div>
  <p class="summary-text">{_e(summary)}</p>
</section>

{defenders_brief_html}

<h2>Email Credibility</h2>
{credibility_html}

<h2>Credential Risk Drivers</h2>
{driver_html}

<h2>Recommended Actions</h2>
{action_html}

<h2>Exposure Timeline</h2>
{timeline_html}

{alt_emails_html}

<h2>Findings by Module</h2>
{findings_html}

<h2>Recovered Data Points</h2>
{metadata_html}

<h2>Module Run Log</h2>
{log_html}

</body>
</html>"""

    def _string_list_html(self, values: list[Any], *, empty: str) -> str:
        if not values:
            return f'<p class="empty">{_e(empty)}</p>'
        items = "".join(f"<li>{_e(value)}</li>" for value in values)
        return f"<ul>{items}</ul>"

    def _defenders_brief_html(self, brief: Any) -> str:
        if not isinstance(brief, dict) or not brief:
            return ""
        findings = brief.get("top_findings") if isinstance(brief.get("top_findings"), list) else []
        finding_html = ""
        for finding in findings[:3]:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity") or "").lower()
            finding_html += f"""
<div class="brief-finding">
  <div><strong>{_e(finding.get('title', ''))}</strong> <span class="brief-severity">{_e(severity.upper())}</span></div>
  <div>{_e(finding.get('detail', ''))}</div>
  <div class="brief-action">{_e(finding.get('remediation', ''))}</div>
</div>"""
        return f"""
<section class="brief-section">
  <h2>Defender's Brief</h2>
  <div class="brief-risk">Risk: <strong>{_e(brief.get('risk_level', 'UNKNOWN'))}</strong></div>
  <p>{_e(brief.get('risk_summary', ''))}</p>
  {finding_html}
  <p class="brief-next"><strong>Next action:</strong> {_e(brief.get('next_action', ''))}</p>
</section>"""

    def _alt_emails_html(self, alt_emails: list[dict[str, Any]]) -> str:
        if not alt_emails:
            return ""
        
        cards = ""
        for f in alt_emails:
            meta = f.get("metadata", {})
            disc_email = meta.get("discovered_email", "unknown")
            conf = str(f.get("confidence", "unknown")).upper()
            conf_class = _CONF_CLASS.get(conf.lower(), "conf-unknown")
            source = meta.get("source", "unknown")
            source_detail = meta.get("source_detail", "")
            reason = meta.get("reason", "")
            
            source_str = source
            if source_detail:
                source_str += f" ({source_detail})"
            
            reason_html = f'<div style="font-size: 8pt; color: #a0aec0; margin-top: 4px;">"{_e(reason)}"</div>' if reason else ""
            
            cards += f"""
<div class="finding-card">
  <div class="finding-header">
    <span class="platform-name">{_e(disc_email)}</span>
    <span class="confidence-badge {conf_class}">{_e(conf)}</span>
  </div>
  <div style="font-size: 8.5pt; color: #cbd5e1;">Source: {_e(source_str)}</div>
  {reason_html}
</div>"""
        
        return f"<h2>Alternate Emails</h2>\n<div class=\"module-section\">\n{cards}\n</div>"

    def _identity_html(self, data: dict[str, Any]) -> str:
        confirmed_name = data.get("confirmed_name")
        confidence = str(data.get("name_confidence") or "unknown")
        if not confirmed_name or confidence == "unknown":
            return ""
        sources = data.get("name_sources")
        source_text = ", ".join(str(source) for source in sources) if isinstance(sources, list) else ""
        return (
            '<div class="credential-pill">'
            f"Identity: <strong>{_e(confirmed_name)}</strong> {_e(confidence.upper())}"
            f"{' - ' + _e(source_text) if source_text else ''}"
            "</div>"
        )

    def _credibility_html(self, credibility: Any) -> str:
        if not isinstance(credibility, dict) or not credibility:
            return '<p class="empty">No email credibility data recorded.</p>'
        rows = "".join(
            f"<tr><td>{_e(key)}</td><td>{_e(value)}</td></tr>"
            for key, value in credibility.items()
            if value is not None and value != ""
        )
        return f'<table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>{rows}</tbody></table>'

    def _timeline_html(self, timeline: Any) -> str:
        if not isinstance(timeline, dict):
            return '<p class="empty">No dated exposure events recovered.</p>'
        events = timeline.get("events")
        if not isinstance(events, list) or not events:
            return '<p class="empty">No dated exposure events recovered.</p>'

        summary = (
            '<div class="timeline-summary">'
            f"<span><strong>First seen</strong> {_e(timeline.get('first_seen_date') or '-')}</span>"
            f"<span><strong>Most recent</strong> "
            f"{_e(timeline.get('most_recent_date') or '-')}</span>"
            f"<span><strong>Active risk</strong> {_e(timeline.get('active_risk_count', 0))}</span>"
            "</div>"
        )
        rows = ""
        for event in events:
            if not isinstance(event, dict):
                continue
            active = bool(event.get("is_active_risk"))
            active_text = "active risk" if active else ""
            active_class = "timeline-active" if active else ""
            rows += (
                f"<tr class=\"{active_class}\">"
                f"<td>{_e(event.get('date', ''))}</td>"
                f"<td>{_e(event.get('event_type', ''))}</td>"
                f"<td>{_e(event.get('title', ''))}</td>"
                f"<td>{_e(event.get('source_module', ''))}</td>"
                f"<td>{_e(active_text)}</td>"
                f"</tr>"
            )
        return (
            f"{summary}"
            "<table>"
            "<thead><tr><th>Date</th><th>Type</th><th>Event</th>"
            "<th>Source</th><th>Risk</th></tr></thead>"
            f"<tbody>{rows}</tbody>"
            "</table>"
        )

    def _findings_html(self, findings_by_module: dict[str, list], runs: list[dict]) -> str:
        if not findings_by_module:
            return '<p class="empty">No findings recorded.</p>'

        runs_by_module = {run.get("module_name"): run for run in runs}
        parts: list[str] = []

        for module_name, module_findings in findings_by_module.items():
            run_info = runs_by_module.get(module_name, {})
            status = run_info.get("status", "unknown")
            status_class = _STATUS_CLASS.get(status, "status-unknown")
            cards = "".join(self._finding_card(finding) for finding in module_findings)
            parts.append(
                f"""
<div class="module-section">
  <div class="module-header">
    <span class="module-name">{_e(module_name)}</span>
    <span class="status-badge {status_class}">{_e(status)}</span>
  </div>
  {cards}
</div>"""
            )

        return "\n".join(parts)

    def _finding_card(self, f_data: dict[str, Any]) -> str:
        platform = f_data.get("platform", "Unknown Platform")
        profile_url = f_data.get("profile_url") or ""
        confidence = str(f_data.get("confidence", "")).lower()
        conf_class = _CONF_CLASS.get(confidence, "conf-unknown")
        metadata = f_data.get("metadata") or {}

        url_html = (
            f'<div class="profile-url">{_e(profile_url)}</div>' if profile_url else ""
        )
        conf_html = (
            f'<span class="confidence-badge {conf_class}">{_e(confidence)}</span>'
            if confidence
            else ""
        )

        meta_rows = "".join(
            f'<tr><td class="meta-key">{_e(key)}</td>'
            f'<td class="meta-val">{_e(value)}</td></tr>'
            for key, value in metadata.items()
            if value is not None and value != ""
        )
        meta_html = (
            f'<table class="meta-table"><tbody>{meta_rows}</tbody></table>'
            if meta_rows
            else ""
        )

        return f"""
<div class="finding-card">
  <div class="finding-header">
    <span class="platform-name">{_e(platform)}</span>
    {conf_html}
  </div>
  {url_html}
  {meta_html}
</div>"""

    def _metadata_table_html(self, findings: list[dict[str, Any]]) -> str:
        rows: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()

        type_map = {
            "name": lambda key: "name" in key and "username" not in key,
            "username": lambda key: "username" in key,
            "photo": lambda key: any(
                token in key for token in ("photo", "avatar", "image", "thumbnail")
            ),
            "phone": lambda key: "phone" in key,
            "location": lambda key: "location" in key,
        }

        for finding in findings:
            module_name = finding.get("module_name", "unknown")
            f_data = finding.get("data", {})
            meta = f_data.get("metadata", {}) if isinstance(f_data, dict) else {}

            for key, value in meta.items():
                if not value:
                    continue
                key_lower = key.lower()
                data_type = next(
                    (candidate for candidate, test in type_map.items() if test(key_lower)),
                    None,
                )
                if data_type is None:
                    continue
                for item in (value if isinstance(value, list) else [value]):
                    value_str = str(item).strip()
                    if not value_str:
                        continue
                    sig = (data_type, value_str, module_name)
                    if sig not in seen:
                        seen.add(sig)
                        rows.append(sig)

        if not rows:
            return '<p class="empty">No structured data points recovered.</p>'

        rows.sort(key=lambda item: (item[0], item[1]))
        row_html = "".join(
            f"<tr><td>{_e(data_type)}</td><td>{_e(value)}</td><td>{_e(source)}</td></tr>"
            for data_type, value, source in rows
        )
        return (
            "<table>"
            "<thead><tr><th>Type</th><th>Value</th><th>Source</th></tr></thead>"
            f"<tbody>{row_html}</tbody>"
            "</table>"
        )

    def _module_log_html(
        self, runs: list[dict[str, Any]], findings_by_module: dict[str, list]
    ) -> str:
        if not runs:
            return '<p class="empty">No modules ran.</p>'

        row_html = ""
        for run in runs:
            module_name = run.get("module_name", "unknown")
            status = run.get("status", "unknown")
            status_class = _STATUS_CLASS.get(status, "status-unknown")
            error = run.get("error") or "-"
            count = len(findings_by_module.get(module_name, []))
            duration = run.get("duration_ms")
            duration_text = f"{duration}&nbsp;ms" if duration is not None else "-"
            row_html += (
                f"<tr>"
                f"<td>{_e(module_name)}</td>"
                f'<td><span class="status-badge {status_class}">{_e(status)}</span></td>'
                f'<td style="text-align:center">{_e(count)}</td>'
                f'<td style="text-align:right">{duration_text}</td>'
                f"<td>{_e(error)}</td>"
                f"</tr>"
            )

        return (
            "<table>"
            "<thead><tr>"
            "<th>Module</th><th>Status</th>"
            '<th style="text-align:center">Findings</th>'
            '<th style="text-align:right">Duration</th>'
            "<th>Error</th>"
            "</tr></thead>"
            f"<tbody>{row_html}</tbody>"
            "</table>"
        )

    def _css(self) -> str:
        return """
* { box-sizing: border-box; margin: 0; padding: 0; }

@page {
  size: A4;
  margin: 14mm 12mm 20mm 12mm;
  @bottom-right {
    content: "Page " counter(page) " of " counter(pages);
    font-family: system-ui, -apple-system, 'Segoe UI', Arial, sans-serif;
    font-size: 8pt;
    color: #4a5568;
  }
  @bottom-left {
    content: "MailAccess - Confidential";
    font-family: system-ui, -apple-system, 'Segoe UI', Arial, sans-serif;
    font-size: 8pt;
    color: #4a5568;
  }
}

body {
  background: #0f1117;
  color: #e2e8f0;
  font-family: system-ui, -apple-system, 'Segoe UI', Arial, sans-serif;
  font-size: 9.5pt;
  line-height: 1.55;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  border-bottom: 2px solid #22d3ee;
  padding-bottom: 8px;
  margin-bottom: 18px;
}

.logo {
  font-size: 20pt;
  font-weight: 900;
  color: #22d3ee;
  letter-spacing: -0.5px;
  line-height: 1;
}
.logo-access { color: #e2e8f0; }

.header-meta {
  text-align: right;
  font-size: 8pt;
  color: #718096;
  line-height: 1.7;
}
.header-email { color: #e2e8f0; font-weight: 600; font-size: 9pt; }

.summary-card {
  background: #1a1d27;
  border: 1px solid #2d3748;
  border-radius: 5px;
  padding: 14px 16px;
  margin-bottom: 22px;
}

.score-row {
  display: flex;
  align-items: flex-start;
  gap: 14px;
  margin-bottom: 10px;
}

.score-number {
  font-size: 44pt;
  font-weight: 900;
  color: #22d3ee;
  line-height: 1;
  letter-spacing: -2px;
}

.risk-badge {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 3px;
  font-size: 10pt;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.risk-low      { background: #14532d; color: #22c55e; }
.risk-medium   { background: #713f12; color: #eab308; }
.risk-high     { background: #7c2d12; color: #f97316; }
.risk-critical { background: #7f1d1d; color: #ef4444; }
.risk-unknown  { background: #1f2937; color: #6b7280; }

.credential-row {
  margin-bottom: 10px;
}

.credential-pill {
  display: inline-block;
  background: #111827;
  border: 1px solid #374151;
  border-radius: 999px;
  padding: 4px 10px;
  font-size: 8pt;
  color: #cbd5e1;
}
.credential-pill strong { color: #f8fafc; }

.stat-pills { display: flex; gap: 6px; flex-wrap: wrap; }

.pill {
  background: #2d3748;
  border-radius: 20px;
  padding: 2px 9px;
  font-size: 8pt;
  color: #a0aec0;
}
.pill strong { color: #e2e8f0; }

.summary-text {
  font-size: 8.5pt;
  color: #718096;
  margin-top: 8px;
}

.brief-section {
  background: #111827;
  border: 1px solid #374151;
  border-left: 4px solid #22d3ee;
  border-radius: 5px;
  padding: 12px 14px;
  margin-bottom: 18px;
}
.brief-section h2 {
  margin-top: 0;
}
.brief-risk {
  font-size: 10pt;
  margin-bottom: 5px;
}
.brief-finding {
  border-top: 1px solid #2d3748;
  padding-top: 7px;
  margin-top: 7px;
}
.brief-severity {
  color: #fbbf24;
  font-size: 7pt;
  margin-left: 4px;
}
.brief-action,
.brief-next {
  color: #cbd5e1;
  margin-top: 4px;
}

.timeline-summary {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 8px;
  color: #a0aec0;
  font-size: 8pt;
}
.timeline-summary span {
  background: #111827;
  border: 1px solid #374151;
  border-radius: 3px;
  padding: 3px 7px;
}
.timeline-active td {
  color: #fbbf24;
}

h2 {
  font-size: 12pt;
  color: #22d3ee;
  border-bottom: 1px solid #2d3748;
  padding-bottom: 3px;
  margin-top: 22px;
  margin-bottom: 10px;
  letter-spacing: 0.3px;
}

.module-section { margin-bottom: 18px; }

.module-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}

.module-name {
  font-size: 10.5pt;
  font-weight: 700;
  color: #e2e8f0;
}

.status-badge {
  display: inline-block;
  padding: 1px 7px;
  border-radius: 3px;
  font-size: 7pt;
  font-weight: 700;
  text-transform: uppercase;
}

.status-success { background: #14532d; color: #22c55e; }
.status-failed  { background: #7f1d1d; color: #ef4444; }
.status-skipped { background: #1f2937; color: #6b7280; }
.status-unknown { background: #1f2937; color: #6b7280; }

.finding-card {
  background: #1a1d27;
  border: 1px solid #2d3748;
  border-left: 3px solid #22d3ee;
  border-radius: 4px;
  padding: 8px 10px;
  margin-bottom: 6px;
  page-break-inside: avoid;
}

.finding-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 4px;
}

.platform-name {
  font-size: 9.5pt;
  font-weight: 700;
  color: #e2e8f0;
}

.confidence-badge {
  display: inline-block;
  padding: 1px 6px;
  border-radius: 3px;
  font-size: 7pt;
  font-weight: 700;
  text-transform: uppercase;
}

.conf-high    { background: #14532d; color: #22c55e; }
.conf-medium  { background: #713f12; color: #eab308; }
.conf-low     { background: #7f1d1d; color: #ef4444; }
.conf-unknown { background: #1f2937; color: #6b7280; }

.profile-url {
  font-size: 7.5pt;
  color: #22d3ee;
  margin-bottom: 5px;
  word-break: break-all;
}

.meta-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 8pt;
  margin-top: 4px;
}
.meta-table td {
  padding: 2px 4px;
  vertical-align: top;
  border: none;
  background: transparent !important;
}
.meta-key { color: #718096; white-space: nowrap; width: 35%; }
.meta-val { color: #e2e8f0; }

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 8pt;
  margin-bottom: 14px;
}

th {
  background: #1e2130;
  color: #a0aec0;
  text-align: left;
  padding: 5px 8px;
  font-weight: 600;
  border-bottom: 1px solid #2d3748;
  white-space: nowrap;
}

td {
  padding: 4px 8px;
  border-bottom: 1px solid #1e2130;
  vertical-align: top;
}

tr:nth-child(odd) td { background: #0f1117; }
tr:nth-child(even) td { background: #141720; }

ul {
  margin: 0 0 14px 18px;
}

li {
  margin-bottom: 4px;
}

.empty {
  color: #4a5568;
  font-style: italic;
  font-size: 8.5pt;
  padding: 6px 0;
}
"""
