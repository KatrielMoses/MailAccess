"""Quality and yield accounting for domain harvest runs."""

from __future__ import annotations

from typing import Any

from .domain_harvest_orchestrator import DomainHarvestResult
from .email_extraction import validate_email


def _status(module: Any) -> str:
    return module.status.value if hasattr(module.status, "value") else str(module.status)


def source_health(result: DomainHarvestResult) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for name, module in result.module_results.items():
        reasons = [str(error) for error in (module.errors or [])]
        metadata = module.metadata if isinstance(module.metadata, dict) else {}
        for key in ("skip_reason", "error", "failure_reason"):
            if metadata.get(key):
                reasons.append(str(metadata[key]))
        outcomes = metadata.get("sub_source_outcomes")
        if isinstance(outcomes, dict):
            for sub_name, outcome in outcomes.items():
                if isinstance(outcome, dict) and outcome.get("error"):
                    reasons.append(f"{sub_name}:{outcome['error']}")
        text = " ".join(reasons).lower()
        declared_category = metadata.get("health_category")
        if isinstance(declared_category, str) and declared_category:
            category = declared_category
        elif any(token in text for token in ("captcha", "blocked", "rate", "429", "403")):
            category = "blocked_or_rate_limited"
        elif "timeout" in text or "timed out" in text:
            category = "timeout"
        elif any(token in text for token in ("key", "credential", "auth")):
            category = "configuration"
        elif _status(module).lower() == "failed":
            category = "failed"
        elif _status(module).lower() == "partial":
            category = "partial"
        elif _status(module).lower() == "skipped":
            category = "skipped"
        elif not module.findings:
            category = "success_empty"
        else:
            category = "ok"
        output[name] = {"status": _status(module), "category": category, "findings": len(module.findings or []), "reasons": reasons[:20]}
    return output


def pgp_quality(result: DomainHarvestResult) -> dict[str, Any]:
    module = result.module_results.get("pgp_domain_email")
    findings = list(module.findings or []) if module is not None else []
    valid = matches = evidence = malformed = 0
    for finding in findings:
        metadata = finding.get("metadata") if isinstance(finding, dict) else {}
        metadata = metadata if isinstance(metadata, dict) else {}
        email = str(metadata.get("email") or "").strip().lower()
        if not validate_email(email):
            malformed += 1
            continue
        valid += 1
        matches += email.rsplit("@", 1)[-1] == result.domain.lower()
        evidence += bool(metadata.get("evidence"))
    return {
        "findings": len(findings),
        "valid_email_pct": round(valid / len(findings) * 100, 2) if findings else 100.0,
        "strict_domain_match_pct": round(matches / valid * 100, 2) if valid else 100.0,
        "with_uid_evidence_pct": round(evidence / valid * 100, 2) if valid else 100.0,
        "malformed_findings": malformed,
        "quality_pass": malformed == 0 and matches == valid and evidence == valid,
    }


def build_metrics(result: DomainHarvestResult, emails: list[dict[str, Any]]) -> dict[str, Any]:
    personal = [email for email in emails if not email["is_role"]]
    raw = sum(len(module.findings or []) for module in result.module_results.values())
    seen: set[str] = set()
    source_yield: dict[str, dict[str, Any]] = {}
    for name, module in result.module_results.items():
        contributed = [email for email in emails if name in email["found_by_modules"]]
        new = []
        for email in contributed:
            if email["email"].lower() not in seen:
                seen.add(email["email"].lower())
                new.append(email)
        source_yield[name] = {"status": _status(module), "raw_findings": len(module.findings or []), "unique_emails_contributed": len(contributed), "new_unique_emails": len(new), "new_personal_emails": sum(not email["is_role"] for email in new), "errors": len(module.errors or [])}
    with_urls = sum(bool(email["aggregated_source_urls"]) for email in emails)
    return {
        "raw_findings": raw,
        "unique_emails": len(emails),
        "unique_on_domain_emails": sum(email["on_domain"] for email in emails),
        "unique_personal_emails": len(personal),
        "role_accounts": len(emails) - len(personal),
        "multi_source_emails": sum(email["source_count"] >= 2 for email in emails),
        "smtp_verified_emails": sum(email["is_smtp_verified"] for email in emails),
        "emails_with_evidence_urls": with_urls,
        "evidence_url_coverage_pct": round(with_urls / len(emails) * 100, 2) if emails else 0.0,
        "module_errors": sum(len(module.errors or []) for module in result.module_results.values()),
        "dedup_ratio": round(raw / len(emails), 2) if emails else 0.0,
        "source_yield": source_yield,
        "source_health": source_health(result),
        "pgp_quality": pgp_quality(result),
    }
