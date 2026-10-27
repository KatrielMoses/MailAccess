from __future__ import annotations

import re
from typing import Any

from .pdf_exporter import _CONF_CLASS, _PLACEHOLDER, PdfExporter, _e

_H2_RE = re.compile(r"<h2>([^<]+)</h2>")

_SCREEN_CSS = """
@media screen {
  html { background: #0f1117; }
  body {
    max-width: 960px;
    margin: 24px auto;
    padding: 0 20px 48px;
    font-size: 15px;
    line-height: 1.6;
  }
  .score-number { font-size: 56px; }
  a { color: #22d3ee; }
  a:hover { color: #67e8f9; }
  nav.toc {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 14px;
    margin: 0 0 18px;
    padding: 10px 12px;
    background: #1a1d27;
    border: 1px solid #2d3748;
    border-radius: 5px;
    font-size: 13px;
  }
  nav.toc a { text-decoration: none; }
  h2 { scroll-margin-top: 16px; }
  .profile-url a { word-break: break-all; }
}
@media print {
  nav.toc { display: none; }
}
"""


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "section"


class HtmlExporter(PdfExporter):
    """Self-contained HTML investigation report for a browser.

    Reuses the PDF report's structured sections so the two formats stay aligned,
    then adds a viewport, title, in-page nav, clickable finding URLs, and
    screen-sized type. No weasyprint (or other extra) is required.
    """

    format_name = "html"
    content_type = "text/html; charset=utf-8"

    def export(self, investigation_id: str, data: dict[str, Any]) -> bytes:
        html = self._build_html(investigation_id, data)
        return self._for_browser(html, str(data.get("email") or "unknown")).encode("utf-8")

    async def generate(self, investigation_id: str, data: dict[str, Any]) -> bytes:
        return self.export(investigation_id, data)

    def _finding_card(self, f_data: dict[str, Any]) -> str:
        platform = f_data.get("platform", "Unknown Platform")
        profile_url = f_data.get("profile_url") or f_data.get("url") or ""
        confidence = str(f_data.get("confidence", "")).lower()
        metadata = f_data.get("metadata") or {}
        avatar_src = f_data.get("_pdf_avatar") or self._avatar_url(f_data) or _PLACEHOLDER

        if isinstance(profile_url, str) and profile_url.startswith(("http://", "https://")):
            url_html = (
                f'<div class="profile-url"><a href="{_e(profile_url)}" rel="noreferrer">'
                f"{_e(profile_url)}</a></div>"
            )
        elif profile_url:
            url_html = f'<div class="profile-url">{_e(profile_url)}</div>'
        else:
            url_html = ""

        conf_html = ""
        if confidence:
            conf_class = _CONF_CLASS.get(confidence, "conf-unknown")
            conf_html = f'<span class="confidence-badge {conf_class}">{_e(confidence)}</span>'

        meta_rows = "".join(
            f'<tr><td class="meta-key">{_e(key)}</td><td class="meta-val">{_e(value)}</td></tr>'
            for key, value in metadata.items()
            if value is not None and value != ""
        )
        meta_html = (
            f'<table class="meta-table"><tbody>{meta_rows}</tbody></table>' if meta_rows else ""
        )

        return f"""
<div class="finding-card">
  <div class="finding-header">
    <img class="finding-avatar" src="{_e(avatar_src)}" alt="" />
    <span class="platform-name">{_e(platform)}</span>
    {conf_html}
  </div>
  {url_html}
  {meta_html}
</div>"""

    def _for_browser(self, html: str, email: str) -> str:
        used: dict[str, int] = {}

        def _with_id(match: re.Match[str]) -> str:
            title = match.group(1)
            base = _slug(title)
            n = used.get(base, 0)
            used[base] = n + 1
            section_id = base if n == 0 else f"{base}-{n + 1}"
            return f'<h2 id="{section_id}">{title}</h2>'

        html = _H2_RE.sub(_with_id, html)
        sections = [
            (match.group("id"), match.group("title"))
            for match in re.finditer(r'<h2 id="(?P<id>[^"]+)">(?P<title>[^<]+)</h2>', html)
        ]
        nav = ""
        if sections:
            links = "".join(
                f'<a href="#{section_id}">{_e(title)}</a>' for section_id, title in sections
            )
            nav = f'<nav class="toc" aria-label="Report sections">{links}</nav>'
        extra_head = (
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f"<title>MailAccess report — {_e(email)}</title>\n"
            f"<style>{_SCREEN_CSS}</style>\n"
        )
        html = html.replace('<meta charset="utf-8">', '<meta charset="utf-8">\n' + extra_head, 1)
        if nav:
            html = html.replace("</header>", "</header>\n" + nav, 1)
        return html
