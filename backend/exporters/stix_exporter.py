from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import stix2

from .base import BaseExporter


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_date(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    for fmt in (
        "%Y-%m-%d",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
    ):
        try:
            dt = datetime.strptime(value[:26], fmt[: len(value[:26])])
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _account_type(platform: str) -> str:
    lower = platform.lower().strip()
    if lower.startswith("gravatar linked:"):
        lower = lower.replace("gravatar linked:", "").strip()
    return lower.replace(" ", "_")


class StixExporter(BaseExporter):
    format_name = "stix"
    content_type = "application/json"

    def export(self, _investigation_id: str, data: dict[str, Any]) -> bytes:
        email: str = data.get("email", "unknown@unknown.com")
        published: datetime = _parse_date(data.get("created_at")) or _utcnow()
        findings: list[dict] = data.get("findings", [])
        module_runs: list[dict] = data.get("module_runs", [])
        credential_score = data.get("credential_risk_score")
        credential_band = data.get("credential_risk_band", "UNKNOWN")
        score_drivers = data.get("score_drivers", [])
        recommended_actions = data.get("recommended_actions", [])
        credibility = data.get("email_credibility") if isinstance(data.get("email_credibility"), dict) else {}

        stix_objects: list[Any] = []
        all_ids: list[str] = []

        def register(obj: Any) -> Any:
            stix_objects.append(obj)
            all_ids.append(obj.id)
            return obj

        email_sco = register(stix2.EmailAddress(value=email))

        if credibility:
            credibility_lines = [
                f"Canonical email: {credibility.get('canonical_email') or data.get('canonical_email') or email}",
                f"Provider family: {credibility.get('provider_family') or 'other'}",
                f"Verdict: {credibility.get('reputation_verdict') or 'clean'}",
                f"Disposable: {credibility.get('is_disposable')}",
                f"Malicious: {credibility.get('is_malicious')}",
            ]
            flags = credibility.get("reputation_flags") or []
            if flags:
                credibility_lines.append(f"Flags: {'; '.join(str(item) for item in flags)}")
            first_seen = credibility.get("first_seen")
            if first_seen:
                credibility_lines.append(f"First seen: {first_seen}")
            register(
                stix2.Note(
                    content="\n".join(credibility_lines),
                    abstract="Email Credibility Assessment",
                    object_refs=[email_sco.id],
                )
            )

        names_seen: set[str] = set()
        accounts_seen: set[tuple[str, str]] = set()
        domains_seen: set[str] = set()

        identities: list[Any] = []
        user_accounts: list[Any] = []
        breach_notes: list[Any] = []

        def add_identity(name: str) -> Any | None:
            cleaned = (name or "").strip()
            if not cleaned or cleaned in names_seen:
                return None
            names_seen.add(cleaned)
            obj = register(stix2.Identity(name=cleaned, identity_class="individual"))
            identities.append(obj)
            return obj

        def add_user_account(
            platform: str,
            username: str,
            display_name: str | None = None,
        ) -> Any | None:
            cleaned_user = (username or "").strip()
            cleaned_platform = (platform or "").strip()
            if not cleaned_user or not cleaned_platform:
                return None
            key = (_account_type(cleaned_platform), cleaned_user.lower())
            if key in accounts_seen:
                return None
            accounts_seen.add(key)
            kwargs: dict[str, Any] = {
                "user_id": cleaned_user,
                "account_type": _account_type(cleaned_platform),
            }
            if display_name:
                kwargs["display_name"] = display_name
            obj = register(stix2.UserAccount(**kwargs))
            user_accounts.append(obj)
            return obj

        def add_domain(domain: str) -> Any | None:
            cleaned = (domain or "").strip().lower()
            if not cleaned or cleaned in domains_seen:
                return None
            domains_seen.add(cleaned)
            return register(stix2.DomainName(value=cleaned))

        for run in module_runs:
            if run.get("module_name") == "domain_intel":
                meta = run.get("run_metadata") or {}
                if not meta.get("is_free_provider"):
                    add_domain(meta.get("domain", ""))

        for finding in findings:
            module_name: str = finding.get("module_name", "")
            f_data: dict = finding.get("data") or {}
            platform: str = f_data.get("platform", "")
            meta: dict = f_data.get("metadata") or {}

            if module_name in ("hibp", "haveibeenpwned", "xposedornot"):
                breach_name = (
                    meta.get("breach_name")
                    or meta.get("name")
                    or f_data.get("breach_name")
                    or "Unknown Breach"
                ).strip()
                data_classes: list[str] = (
                    meta.get("data_classes")
                    or meta.get("exposed_data")
                    or f_data.get("data_classes")
                    or []
                )
                content = (
                    f"{breach_name} - {', '.join(data_classes)}"
                    if data_classes
                    else breach_name
                )
                note_kwargs: dict[str, Any] = {
                    "content": content,
                    "abstract": "Data Breach Exposure",
                    "object_refs": [email_sco.id],
                }
                breach_dt = _parse_date(meta.get("breach_date"))
                if breach_dt:
                    note_kwargs["created"] = breach_dt
                breach_notes.append(register(stix2.Note(**note_kwargs)))

            elif module_name in ("social", "social_links", "gravatar"):
                display_name: str | None = meta.get("display_name")
                username: str | None = meta.get("username")

                if display_name:
                    add_identity(display_name)
                if username:
                    add_user_account(platform, username, display_name)

                if module_name == "gravatar":
                    for account in meta.get("accounts") or []:
                        shortname = account.get("shortname", "")
                        account_display = (
                            account.get("display")
                            or account.get("username")
                            or account.get("shortname", "")
                        )
                        if shortname and account_display:
                            add_user_account(shortname, account_display)

                if "gravatar linked:" in platform.lower():
                    account_display = (
                        meta.get("display")
                        or meta.get("username")
                        or meta.get("shortname")
                    )
                    if account_display:
                        add_user_account(platform, account_display)

            elif module_name == "domain_intel":
                registrant_name: str | None = meta.get("registrant_name")
                if registrant_name:
                    add_identity(registrant_name)

        for account in user_accounts:
            register(
                stix2.Relationship(
                    relationship_type="related-to",
                    source_ref=email_sco.id,
                    target_ref=account.id,
                )
            )
        for identity in identities:
            register(
                stix2.Relationship(
                    relationship_type="attributed-to",
                    source_ref=email_sco.id,
                    target_ref=identity.id,
                )
            )
        for note in breach_notes:
            register(
                stix2.Relationship(
                    relationship_type="related-to",
                    source_ref=email_sco.id,
                    target_ref=note.id,
                )
            )

        credential_note = register(
            stix2.Note(
                content=(
                    f"Credential risk: {credential_score if credential_score is not None else 'N/A'}/100 "
                    f"({credential_band})\n"
                    f"Drivers: {'; '.join(str(item) for item in score_drivers) or 'none'}\n"
                    f"Recommended actions: {'; '.join(str(item) for item in recommended_actions) or 'none'}"
                ),
                abstract="Credential Risk Assessment",
                object_refs=[email_sco.id],
            )
        )
        register(
            stix2.Relationship(
                relationship_type="related-to",
                source_ref=email_sco.id,
                target_ref=credential_note.id,
            )
        )

        report = stix2.Report(
            name=f"MailAccess: {email} ({credential_band} credential risk)",
            published=published,
            object_refs=list(all_ids),
        )
        stix_objects.append(report)

        bundle = stix2.Bundle(objects=stix_objects)
        return bundle.serialize(pretty=False).encode("utf-8")
