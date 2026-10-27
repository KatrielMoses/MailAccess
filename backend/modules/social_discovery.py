"""Social profile discovery via Oxylabs Web Search (Pro, BYOK).

Finds a subject's public Instagram / Facebook / LinkedIn profiles from search results —
no bot-evasion, just a query. One search per platform; each result is parsed (name,
handle, URL, IG follower stats, LinkedIn title/company) and MATCH-GATED against the
subject's trusted handles + confirmed name, so a same-named stranger is not attached.

Runs in the profile phase (after the sweep). Skipped without an Oxylabs token.
"""
from __future__ import annotations

import re
from typing import Any

from ..core import oxylabs_client
from ..core.evidence import subject_is_freemail
from ..core.identity_match import known_names, names_match, spine_handles
from .base import BaseModule, ModuleResult, ModuleStatus

_PLATFORMS = (
    ("instagram", "Instagram", "instagram.com"),
    ("facebook", "Facebook", "facebook.com"),
    ("linkedin", "LinkedIn", "linkedin.com"),
)
_IG_STATS = re.compile(r"([\d.,]+[KMB]?)\s+Followers.*?([\d.,]+[KMB]?)\s+Following.*?([\d.,]+[KMB]?)\s+Posts", re.I | re.S)
_TITLE_HANDLE = re.compile(r"\(@([A-Za-z0-9_.]+)\)")
# facebook.com/<handle> but not the directory / numeric-id / app paths.
_FB_SKIP = ("public/", "profile.php", "people/", "pages/", "groups/", "sharer")


def _localpart(email: str) -> str:
    return email.split("@", 1)[0].lower() if "@" in email else email.lower()


def _handle_variants(localpart: str, spine: list[str]) -> set[str]:
    """Plausible handle forms for this person: the local part with separators normalised
    (and trailing digits dropped), plus every spine (Class-1) handle."""
    base = re.sub(r"[^a-z0-9._-]", "", localpart)
    seps = {base, base.replace(".", ""), base.replace(".", "_"), base.replace(".", "-"),
            base.replace("_", ""), base.replace("-", "")}
    nodigits = re.sub(r"\d+$", "", base)
    if nodigits and nodigits != base:
        seps |= {nodigits, nodigits.replace(".", ""), nodigits.replace(".", "_"), nodigits.replace(".", "-")}
    seps |= {h.lower() for h in spine if h}
    return {s for s in seps if len(s) >= 3}


def _handle_from_url(url: str, host: str) -> str:
    path = re.sub(r"^https?://(www\.|[a-z]{2}\.)?", "", url.lower()).split("?", 1)[0]
    path = path[len(host):].strip("/") if path.startswith(host) else path.split("/", 1)[-1].strip("/")
    if host == "facebook.com" and any(path.startswith(p) for p in _FB_SKIP):
        return ""
    if host == "linkedin.com" and path.startswith("in/"):
        path = path[3:]  # linkedin.com/in/<slug> -> <slug>
    return path.split("/", 1)[0]


def _name_from_title(title: str) -> str:
    t = re.split(r"\s*[(•|·\-–]\s*", title, 1)[0].strip()
    return t if t and len(t.split()) >= 2 else ""


def _parse_ig_stats(outline: str) -> dict[str, str]:
    m = _IG_STATS.search(outline or "")
    return {"followers": m.group(1), "following": m.group(2), "posts": m.group(3)} if m else {}


def _parse_linkedin(title: str, outline: str) -> dict[str, str]:
    out: dict[str, str] = {}
    # "Jane Doe - HR Operations at Example Corp" -> headline after the first " - ".
    parts = re.split(r"\s+[-–]\s+", title, 1)
    if len(parts) == 2 and "linkedin" not in parts[1].lower():
        out["headline"] = parts[1].strip()
    for key, pat in (("employer", r"Experience:\s*([^·|]+)"), ("school", r"Education:\s*([^·|]+)"),
                     ("location", r"Location:\s*([^·|]+)")):
        m = re.search(pat, outline or "", re.I)
        if m:
            out[key] = m.group(1).strip()
    return out


class SocialDiscoveryModule(BaseModule):
    name = "social_discovery"
    description = "Instagram/Facebook/LinkedIn profiles via Oxylabs Web Search (Pro; needs OXYLABS_SEARCH_TOKEN)."
    requires_key = True

    async def run(self, email: str, collected: dict[str, Any] | None = None) -> ModuleResult:
        if collected is None:
            return ModuleResult(status=ModuleStatus.SKIPPED, errors=["Runs in the profile phase only"])
        if not oxylabs_client.oxylabs_active():
            return ModuleResult(status=ModuleStatus.SKIPPED, errors=["Oxylabs is not configured"])
        names = known_names(collected)
        if not names:
            return ModuleResult(status=ModuleStatus.SKIPPED, errors=["No confirmed name to match against"])
        subject_name = names[0]
        freemail = subject_is_freemail(email)
        variants = _handle_variants(_localpart(email), spine_handles(collected))
        primary = sorted(variants, key=len, reverse=True)[0] if variants else ""

        findings: list[dict[str, Any]] = []
        calls = 0
        for slug, label, host in _PLATFORMS:
            query = f"{subject_name} {label}" + (f" {primary}" if primary else "")
            results = await oxylabs_client.web_search(query, max_results=6)
            calls += 1
            best = self._pick(results, host, subject_name, variants, freemail)
            if best:
                findings.append(self._finding(best, label, host, subject_name))
        status = ModuleStatus.SUCCESS if findings else ModuleStatus.SUCCESS_EMPTY
        return ModuleResult(status=status, findings=findings, metadata={"calls": calls, "provider": "oxylabs"})

    def _pick(self, results, host, subject_name, variants, freemail):
        """Highest-precision match for this host: handle ∈ trusted variants (strong), else a
        name match when the subject is freemail (their local part is their handle)."""
        best = None
        for r in results:
            url = str(r.get("url") or "")
            if host not in url.lower():
                continue
            handle = _handle_from_url(url, host)
            if not handle:
                continue
            title = str(r.get("title") or "")
            name = _name_from_title(title) or (_TITLE_HANDLE.sub("", title).strip())
            handle_hit = handle.lower() in variants or handle.replace(".", "").lower() in variants
            name_hit = bool(name) and names_match(name, subject_name)
            if handle_hit:
                return {"r": r, "url": url, "handle": handle, "name": name, "conf": "high"}
            if name_hit and freemail and best is None:
                best = {"r": r, "url": url, "handle": handle, "name": name, "conf": "medium"}
        return best

    def _finding(self, b, label, host, subject_name):
        r, url = b["r"], b["url"]
        outline = r.get("outline")
        outline = (outline[0] if isinstance(outline, list) and outline else outline) or ""
        meta: dict[str, Any] = {
            "name": b["name"] or subject_name,
            "handle": b["handle"],
            "provider": "oxylabs",
            "verification": "corroborated" if b["conf"] == "high" else "unverified",
            "match": "handle" if b["conf"] == "high" else "name+freemail",
        }
        if host == "instagram.com":
            meta.update(_parse_ig_stats(str(outline)))
        elif host == "linkedin.com":
            meta.update(_parse_linkedin(str(r.get("title") or ""), str(outline)))
        return {
            "platform": label,
            "profile_url": url,
            "username": b["handle"],
            "confidence": b["conf"],
            "source": "social_discovery",
            "metadata": meta,
        }
