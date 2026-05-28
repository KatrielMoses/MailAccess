from __future__ import annotations

import asyncio
import hashlib
import re
from typing import Any

from ..config import settings
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus


class AlternateEmailModule(BaseModule):
    name = "alternate_email"
    description = "Discover alternate email addresses belonging to the same person."
    requires_key = False

    async def run(self, email: str, collected: dict[str, ModuleResult]) -> ModuleResult:
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        anchor_email = email.strip().lower()

        async with build_client(timeout=15.0) as client:
            tasks = [
                self._source_github(client, anchor_email, collected),
                self._source_gravatar(anchor_email, collected),
                self._source_breach(anchor_email, collected),
                self._source_permutation(client, anchor_email, collected),
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, Exception):
                errors.append(f"Alternate email source error: {res}")
            elif isinstance(res, tuple):
                source_findings, source_errors = res
                findings.extend(source_findings)
                errors.extend(source_errors)

        # Deduplicate findings
        unique_emails: dict[str, dict[str, Any]] = {}
        for f in findings:
            meta = f.get("metadata", {})
            disc_email = meta.get("discovered_email")
            if not disc_email or disc_email == anchor_email:
                continue

            # Basic validation of email format
            if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", disc_email):
                continue

            # Filter role accounts
            local_part = disc_email.split("@")[0].lower()
            if local_part in ("noreply", "admin", "info", "support", "contact"):
                continue

            if disc_email not in unique_emails:
                unique_emails[disc_email] = f
                # ensure 'sources' list exists if we want to merge them, but prompt asks to keep one entry, merge sources list
                # actually, prompt says: "keep one entry, merge sources list"
                unique_emails[disc_email]["metadata"]["sources"] = [meta.get("source")]
            else:
                existing_sources = unique_emails[disc_email]["metadata"].get("sources", [])
                new_source = meta.get("source")
                if new_source and new_source not in existing_sources:
                    existing_sources.append(new_source)
                unique_emails[disc_email]["metadata"]["sources"] = existing_sources

        final_findings = list(unique_emails.values())
        
        status = ModuleStatus.SUCCESS
        if errors and not final_findings:
            status = ModuleStatus.PARTIAL
        elif errors and final_findings:
            status = ModuleStatus.PARTIAL

        return ModuleResult(
            status=status,
            findings=final_findings,
            metadata={"alternate_emails_found": len(final_findings)},
            errors=errors,
        )

    async def _source_github(
        self, client: Any, anchor_email: str, collected: dict[str, ModuleResult]
    ) -> tuple[list[dict[str, Any]], list[str]]:
        findings = []
        errors = []

        gh_result = collected.get("github_commits")
        if not gh_result or gh_result.status not in (ModuleStatus.SUCCESS, ModuleStatus.PARTIAL):
            return [], []

        usernames = []
        for finding in gh_result.findings:
            if finding.get("platform") == "github_user":
                login = finding.get("metadata", {}).get("login")
                if login and login not in usernames:
                    usernames.append(login)

            # Check commit trailers
            if finding.get("platform") == "github_commit":
                message = str(finding.get("metadata", {}).get("commit_message") or "")
                for trailer in ("Co-authored-by:", "Signed-off-by:"):
                    for line in message.splitlines():
                        if line.startswith(trailer):
                            match = re.search(r"<([^>]+)>", line)
                            if match:
                                ext_email = match.group(1).lower().strip()
                                if ext_email and ext_email != anchor_email and "noreply" not in ext_email:
                                    findings.append(self._make_finding(
                                        ext_email,
                                        "high",
                                        "github_commits",
                                        "Commit Message Trailer",
                                        "git_commit_trailer",
                                        "Found in commit message trailer",
                                        anchor_email
                                    ))

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        token = settings.github_token
        if token:
            headers["Authorization"] = f"Bearer {token}"

        for username in usernames:
            try:
                resp = await client.get(f"https://api.github.com/users/{username}/events/public", headers=headers)
                if resp.status_code == 200:
                    events = resp.json()
                    for event in events:
                        if event.get("type") == "PushEvent":
                            payload = event.get("payload", {})
                            commits = payload.get("commits", [])
                            for commit in commits:
                                author = commit.get("author", {})
                                email = author.get("email", "").lower().strip()
                                if email and email != anchor_email and "noreply@users.github.com" not in email:
                                    findings.append(self._make_finding(
                                        email,
                                        "high",
                                        "github_commits",
                                        f"github.com/{username}",
                                        "git_commit_author",
                                        "Same git author with different email",
                                        anchor_email
                                    ))
            except Exception as e:
                errors.append(f"GitHub event fetch failed for {username}: {e}")

        return findings, errors

    async def _source_gravatar(
        self, anchor_email: str, collected: dict[str, ModuleResult]
    ) -> tuple[list[dict[str, Any]], list[str]]:
        findings = []
        errors = []

        grav_result = collected.get("gravatar")
        if not grav_result or grav_result.status not in (ModuleStatus.SUCCESS, ModuleStatus.PARTIAL):
            return [], []

        for finding in grav_result.findings:
            if finding.get("platform") == "Gravatar":
                meta = finding.get("metadata", {})
                
                # Check bio/aboutMe
                about_me = meta.get("about_me") or ""
                emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", about_me)
                for email in emails:
                    email_clean = email.lower().strip()
                    if email_clean != anchor_email:
                        findings.append(self._make_finding(
                            email_clean,
                            "medium",
                            "gravatar_profile",
                            "Gravatar Bio",
                            "gravatar_bio_regex",
                            "Found email in Gravatar aboutMe text",
                            anchor_email
                        ))

                # Check accounts
                accounts = meta.get("accounts", [])
                for acc in accounts:
                    # In some rare cases, email is exposed in accounts
                    pass

        return findings, errors

    async def _source_breach(
        self, anchor_email: str, collected: dict[str, ModuleResult]
    ) -> tuple[list[dict[str, Any]], list[str]]:
        findings = []
        errors = []

        breach_modules = ("hibp", "breachdirectory", "breach_deep", "xposedornot", "leakcheck")
        
        target_fields = (
            "backup_email", "recovery_email", "secondary_email",
            "alternate_email", "contact_email", "related_emails", "linked_accounts"
        )

        for mod_name in breach_modules:
            mod_res = collected.get(mod_name)
            if not mod_res or mod_res.status not in (ModuleStatus.SUCCESS, ModuleStatus.PARTIAL):
                continue
            
            for finding in mod_res.findings:
                meta = finding.get("metadata", {})
                for field in target_fields:
                    val = meta.get(field)
                    if isinstance(val, str):
                        # Simple extraction
                        emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", val)
                        for email in emails:
                            email_clean = email.lower().strip()
                            if email_clean != anchor_email:
                                findings.append(self._make_finding(
                                    email_clean,
                                    "high",
                                    "breach_record",
                                    f"Breach record field ({field})",
                                    "breach_backup_field",
                                    "Backup or recovery email found in breach",
                                    anchor_email
                                ))
                    elif isinstance(val, list):
                        for item in val:
                            if isinstance(item, str):
                                emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", item)
                                for email in emails:
                                    email_clean = email.lower().strip()
                                    if email_clean != anchor_email:
                                        findings.append(self._make_finding(
                                            email_clean,
                                            "high",
                                            "breach_record",
                                            f"Breach record field ({field})",
                                            "breach_backup_field",
                                            "Backup or recovery email found in breach",
                                            anchor_email
                                        ))

        return findings, errors

    async def _source_permutation(
        self, client: Any, anchor_email: str, collected: dict[str, ModuleResult]
    ) -> tuple[list[dict[str, Any]], list[str]]:
        findings = []
        errors = []

        # Find real name from github_commits or gravatar
        real_names = []
        gh_meta = collected.get("github_commits", ModuleResult(status=ModuleStatus.SKIPPED)).metadata or {}
        gh_name = gh_meta.get("real_name_from_git")
        if gh_name:
            real_names.append(gh_name)

        grav_meta = {}
        grav_res = collected.get("gravatar")
        if grav_res and grav_res.findings:
            for f in grav_res.findings:
                if f.get("platform") == "Gravatar":
                    disp_name = f.get("metadata", {}).get("display_name")
                    if disp_name:
                        real_names.append(disp_name)

        if not real_names:
            return [], []

        # Assuming high confidence if name found in multiple sources or explicitly
        # We will use the most common name
        from collections import Counter
        most_common_name = Counter(real_names).most_common(1)[0][0]
        
        parts = most_common_name.lower().split()
        if len(parts) < 2:
            return [], []
            
        first = parts[0]
        last = parts[-1]
        fi = first[0]

        local_parts = [
            f"{first}",
            f"{first}{last}",
            f"{first}.{last}",
            f"{first}_{last}",
            f"{fi}{last}",
            f"{fi}.{last}",
            f"{fi}_{last}",
            f"{last}{first}",
            f"{first}{fi}",
            f"{last}{fi}",
        ]

        providers = ["gmail.com", "outlook.com", "protonmail.com", "yahoo.com", "icloud.com", "hotmail.com"]
        
        permutations = []
        for lp in local_parts:
            for prov in providers:
                perm = f"{lp}@{prov}"
                if perm != anchor_email:
                    permutations.append(perm)
                    
        # Limit to 20
        permutations = permutations[:20]

        async def check_gravatar(candidate: str):
            md5_hash = hashlib.md5(candidate.encode("utf-8")).hexdigest()
            url = f"https://www.gravatar.com/{md5_hash}.json"
            try:
                resp = await client.head(url)
                if resp.status_code == 200:
                    return candidate
            except Exception:
                pass
            return None

        results = await asyncio.gather(*[check_gravatar(cand) for cand in permutations])
        for res in results:
            if res:
                findings.append(self._make_finding(
                    res,
                    "medium",
                    "permutation_gravatar",
                    "Gravatar permutation check",
                    "permutation_gravatar_hit",
                    "Gravatar profile found for this address",
                    anchor_email
                ))

        return findings, errors

    def _make_finding(
        self,
        discovered_email: str,
        confidence: str,
        source: str,
        source_detail: str,
        discovery_method: str,
        reason: str,
        anchor_email: str
    ) -> dict[str, Any]:
        return {
            "platform": "alternate_email",
            "profile_url": None,
            "confidence": confidence,
            "metadata": {
                "discovered_email": discovered_email,
                "source": source,
                "source_detail": source_detail,
                "discovery_method": discovery_method,
                "reason": reason,
                "anchor_email": anchor_email,
            },
        }
