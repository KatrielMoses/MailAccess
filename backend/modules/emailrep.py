import httpx

from ..config import settings
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_REPUTATION_CONFIDENCE = {"high": "high", "medium": "medium", "low": "low", "none": "none"}


class EmailRepModule(BaseModule):
    name = "emailrep"
    email_linked = True
    description = "Query EmailRep.io for reputation score, risk flags, and linked profile data."
    requires_key = False  # Free tier works without a key; key raises rate limits

    async def run(self, email: str) -> ModuleResult:
        headers = {"User-Agent": "MailAccess OSINT Tool"}
        if settings.emailrep_api_key:
            headers["Key"] = settings.emailrep_api_key

        try:
            async with build_client(timeout=8.0) as client:
                res = await client.get(
                    f"https://emailrep.io/{email}",
                    headers=headers,
                )
        except httpx.TimeoutException:
            return ModuleResult(status=ModuleStatus.FAILED, errors=["EmailRep.io request timed out"])
        except Exception as e:
            return ModuleResult(status=ModuleStatus.FAILED, errors=[str(e)])

        if res.status_code in (400, 404):
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=[f"EmailRep.io returned {res.status_code}: unrated or unknown email"],
            )

        if res.status_code == 429:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                findings=[],
                metadata={},
                errors=["EmailRep rate-limited. Set EMAILREP_API_KEY for higher limits."],
            )

        if res.status_code != 200:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"EmailRep.io returned unexpected status {res.status_code}"],
            )

        try:
            data = res.json()
        except Exception:
            return ModuleResult(status=ModuleStatus.FAILED, errors=["Failed to parse EmailRep.io response"])

        reputation = data.get("reputation", "none")
        suspicious = bool(data.get("suspicious", False))
        references = data.get("references", 0)

        details = data.get("details", {})
        blacklisted = bool(details.get("blacklisted", False))
        malicious_activity = bool(details.get("malicious_activity", False))
        credentials_leaked = bool(details.get("credentials_leaked", False))
        data_breach = bool(details.get("data_breach", False))
        last_seen = details.get("last_seen")
        days_since_seen = details.get("days_since_seen")
        first_seen = details.get("first_seen")
        spam = bool(details.get("spam", False))
        free_provider = bool(details.get("free_provider", False))
        disposable = bool(details.get("disposable", False))
        profiles = details.get("profiles") or []

        finding = {
            "platform": "emailrep",
            "confidence": _REPUTATION_CONFIDENCE.get(reputation, "none"),
            "severity": "high" if suspicious else "info",
            "metadata": {
                "reputation": reputation,
                "suspicious": suspicious,
                "references": references,
                "blacklisted": blacklisted,
                "malicious_activity": malicious_activity,
                "credentials_leaked": credentials_leaked,
                "data_breach": data_breach,
                "last_seen": last_seen,
                "days_since_seen": days_since_seen,
                "first_seen": first_seen,
                "spam": spam,
                "free_provider": free_provider,
                "disposable": disposable,
                "profiles": profiles,
            },
        }

        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[finding],
            metadata={
                "reputation_score": reputation,
                "is_suspicious": suspicious,
                "is_disposable": disposable,
                "is_blacklisted": blacklisted,
                "known_platforms": profiles,
            },
        )
