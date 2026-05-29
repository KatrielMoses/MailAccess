from __future__ import annotations

from typing import Any

import httpx

from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_KEYBASE_API = "https://keybase.io/_/api/1.0/user/lookup.json"
_FIELDS = "basics,profile,proofs_summary"


class KeybaseModule(BaseModule):
    name = "keybase"
    description = "Look up Keybase profile and verified cross-platform identity proofs."
    requires_key = False

    async def run(self, email: str, original_email: str | None = None) -> ModuleResult:
        local_parts: list[str] = []
        if original_email and original_email.lower() != email.lower():
            orig_local = original_email.split("@")[0] if "@" in original_email else original_email
            local_parts.append(orig_local)
        canonical_local = email.split("@")[0] if "@" in email else email
        if canonical_local not in local_parts:
            local_parts.append(canonical_local)

        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        seen_usernames: set[str] = set()

        async with build_client(timeout=10.0, follow_redirects=True) as client:
            # Keybase public API: look up by username (email local part).
            # Email-based lookup requires Keybase authentication; skip it.
            for local_part in local_parts:
                found, errs = await self._lookup(client, username=local_part)
                errors.extend(errs)
                for f in found:
                    kb_user = str((f.get("metadata") or {}).get("username") or "")
                    if kb_user not in seen_usernames:
                        seen_usernames.add(kb_user)
                        findings.append(f)

        if errors and not findings:
            status = ModuleStatus.PARTIAL
        elif errors:
            status = ModuleStatus.PARTIAL
        else:
            status = ModuleStatus.SUCCESS

        return ModuleResult(status=status, findings=findings, errors=errors)

    async def _lookup(
        self,
        client: httpx.AsyncClient,
        *,
        email: str | None = None,
        username: str | None = None,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        params: dict[str, str] = {"fields": _FIELDS}
        if email:
            params["email"] = email
        elif username:
            params["username"] = username
        else:
            return [], []

        try:
            resp = await client.get(_KEYBASE_API, params=params)
        except httpx.TimeoutException:
            return [], ["Keybase lookup timed out"]
        except Exception as exc:
            return [], [f"Keybase lookup error: {exc}"]

        if resp.status_code == 404:
            return [], []
        if resp.status_code != 200:
            return [], [f"Keybase HTTP {resp.status_code}"]

        try:
            data = resp.json()
        except Exception:
            return [], ["Keybase returned unparseable JSON"]

        status_obj = data.get("status") if isinstance(data.get("status"), dict) else {}
        if status_obj.get("code") != 0:
            # 205 = not found, others are real errors
            if status_obj.get("code") == 205:
                return [], []
            return [], [f"Keybase API error: {status_obj.get('desc', 'unknown')}"]

        them_list = data.get("them") if isinstance(data.get("them"), list) else []
        findings: list[dict[str, Any]] = []

        for them in them_list:
            if not isinstance(them, dict):
                continue

            basics = them.get("basics") if isinstance(them.get("basics"), dict) else {}
            profile = them.get("profile") if isinstance(them.get("profile"), dict) else {}
            proofs = them.get("proofs_summary") if isinstance(them.get("proofs_summary"), dict) else {}
            all_proofs = proofs.get("all") if isinstance(proofs.get("all"), list) else []

            kb_username = str(basics.get("username") or "")
            full_name = str(profile.get("full_name") or "").strip() or None
            bio = str(profile.get("bio") or "").strip() or None
            location = str(profile.get("location") or "").strip() or None
            twitter = str(profile.get("twitter") or "").strip() or None
            github_handle = str(profile.get("github") or "").strip() or None
            websites = profile.get("websites") if isinstance(profile.get("websites"), list) else []

            profile_meta: dict[str, Any] = {"username": kb_username}
            if full_name:
                profile_meta["name"] = full_name
            if bio:
                profile_meta["bio"] = bio
            if location:
                profile_meta["location"] = location
            if twitter:
                profile_meta["twitter"] = twitter
            if github_handle:
                profile_meta["github"] = github_handle
            if websites:
                profile_meta["websites"] = [str(w) for w in websites if w]

            # Collect verified proof platforms for summary
            verified_platforms: list[str] = []
            for proof in all_proofs:
                if not isinstance(proof, dict):
                    continue
                proof_type = str(proof.get("proof_type") or "")
                if proof_type:
                    verified_platforms.append(proof_type)

            profile_meta["verified_proofs"] = verified_platforms

            findings.append(
                {
                    "platform": "keybase_profile",
                    "url": f"https://keybase.io/{kb_username}",
                    "confidence": "high",
                    "source": "keybase",
                    "signal_type": "profile",
                    "metadata": profile_meta,
                }
            )

            # Individual proof findings
            for proof in all_proofs:
                if not isinstance(proof, dict):
                    continue
                proof_type = str(proof.get("proof_type") or "")
                nametag = str(proof.get("nametag") or "")
                proof_url = str(proof.get("proof_url") or proof.get("service_url") or "")
                if not proof_type:
                    continue
                findings.append(
                    {
                        "platform": f"keybase_proof_{proof_type}",
                        "url": proof_url,
                        "confidence": "high",
                        "source": "keybase",
                        "signal_type": "verified_proof",
                        "metadata": {
                            "proof_type": proof_type,
                            "handle": nametag,
                            "proof_url": proof_url,
                            "keybase_username": kb_username,
                        },
                    }
                )

        return findings, []
