from ..config import settings
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus


class HIBPModule(BaseModule):
    name = "hibp"
    email_linked = True
    description = "Check if the email appears in known data breaches via the HIBP v3 API."
    requires_key = True

    async def run(self, email: str) -> ModuleResult:
        if not settings.hibp_api_key:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["HIBP_API_KEY not set"],
            )

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            "hibp-api-key": settings.hibp_api_key,
            "user-agent": "MailAccess OSINT Tool"
        }
        params = {
            "truncateResponse": "false"
        }

        findings = []
        errors = []

        async with build_client(timeout=10.0, follow_redirects=True) as client:
            try:
                res = await client.get(url, headers=headers, params=params)
                
                if res.status_code == 404:
                    return ModuleResult(
                        status=ModuleStatus.SUCCESS,
                        findings=[],
                        metadata={
                            "total_breaches": 0,
                            "breach_dates": None,
                            "most_critical_breach": None,
                            "all_data_classes": []
                        }
                    )
                elif res.status_code == 429:
                    return ModuleResult(
                        status=ModuleStatus.PARTIAL,
                        findings=[],
                        errors=["Rate limit exceeded. Please wait before retrying."]
                    )
                elif res.status_code == 200:
                    data = res.json()
                    
                    total_breaches = len(data)
                    all_data_classes = set()
                    breach_domains: list[str] = []
                    dates = []

                    most_critical_name = None
                    highest_severity_val = -1

                    for breach in data:
                        name = breach.get("Name")
                        domain = breach.get("Domain", "")
                        breach_date = breach.get("BreachDate")
                        description = breach.get("Description")
                        data_classes = breach.get("DataClasses", [])
                        is_sensitive = breach.get("IsSensitive")
                        is_verified = breach.get("IsVerified")
                        pwn_count = breach.get("PwnCount")

                        if breach_date:
                            dates.append(breach_date)

                        severity = "medium"
                        sev_val = 0

                        classes_lower = [c.lower() for c in data_classes]
                        if any("password" in c or "financial" in c for c in classes_lower):
                            severity = "critical"
                            sev_val = 2
                        elif any("phone" in c or "address" in c for c in classes_lower):
                            severity = "high"
                            sev_val = 1

                        if sev_val > highest_severity_val or (sev_val == highest_severity_val and most_critical_name is None):
                            highest_severity_val = sev_val
                            most_critical_name = name

                        for c in data_classes:
                            all_data_classes.add(c)

                        # Breach-event record (the actual breach entry)
                        findings.append({
                            "platform": "HaveIBeenPwned",
                            "url": f"https://haveibeenpwned.com/PwnedWebsites#{name}" if name else "https://haveibeenpwned.com",
                            "metadata": {
                                "name": name,
                                "domain": domain,
                                "breach_date": breach_date,
                                "description": description,
                                "data_classes": data_classes,
                                "is_sensitive": is_sensitive,
                                "is_verified": is_verified,
                                "pwn_count": pwn_count,
                                "severity": severity,
                            },
                            "confidence": "high",
                        })

                        # Per-domain confirmed-account finding
                        if domain:
                            breach_domains.append(domain)
                            findings.append({
                                "platform": domain,
                                "url": f"https://{domain}",
                                "metadata": {
                                    "note": "Domain appeared in breach data — account confirmed",
                                    "breach_name": name,
                                    "breach_date": breach_date,
                                    "severity": severity,
                                },
                                "confidence": "high",
                                "source": "breach_confirmed",
                            })

                    if dates:
                        dates.sort()
                        date_range = f"{dates[0]} to {dates[-1]}" if len(dates) > 1 else dates[0]
                    else:
                        date_range = None

                    return ModuleResult(
                        status=ModuleStatus.SUCCESS,
                        findings=findings,
                        metadata={
                            "total_breaches": total_breaches,
                            "breach_dates": date_range,
                            "most_critical_breach": most_critical_name,
                            "all_data_classes": list(all_data_classes),
                            "breach_domains": breach_domains,
                        },
                    )
                else:
                    return ModuleResult(
                        status=ModuleStatus.FAILED,
                        errors=[f"HIBP API error: {res.status_code}"]
                    )

            except Exception as e:
                return ModuleResult(
                    status=ModuleStatus.FAILED,
                    errors=[f"HIBP network error: {str(e)}"]
                )
