import asyncio

import dns.resolver

from .base import BaseModule, ModuleResult, ModuleStatus


class DnsLookupModule(BaseModule):
    name = "dns_lookup"
    description = "Resolve MX, SPF, DMARC, and DKIM DNS records for the email's domain."
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        domain = email.split("@")[-1].lower()
        
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        resolver.timeout = 5.0

        def get_mx():
            try:
                answers = resolver.resolve(domain, "MX")
                records = []
                provider = "unknown"
                for rdata in answers:
                    exchange = str(rdata.exchange).lower().rstrip('.')
                    records.append({"priority": rdata.preference, "exchange": exchange})
                    if "google" in exchange: provider = "Google Workspace"
                    elif "outlook" in exchange or "microsoft" in exchange: provider = "Microsoft 365"
                    elif "protonmail" in exchange: provider = "ProtonMail"
                    elif "yahoo" in exchange: provider = "Yahoo Mail"
                    elif provider == "unknown": provider = exchange
                return {"mx_records": records, "mx_provider": provider}
            except Exception:
                return {}

        def get_spf():
            try:
                answers = resolver.resolve(domain, "TXT")
                for rdata in answers:
                    txt = "".join([b.decode('utf-8', errors='ignore') for b in rdata.strings])
                    if txt.startswith("v=spf1"):
                        return {"spf_record": txt, "has_spf": True}
            except Exception:
                pass
            return {"has_spf": False}

        def get_dmarc():
            try:
                answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
                for rdata in answers:
                    txt = "".join([b.decode('utf-8', errors='ignore') for b in rdata.strings])
                    if txt.startswith("v=DMARC1"):
                        policy = "none"
                        for part in txt.split(";"):
                            part = part.strip()
                            if part.startswith("p="):
                                policy = part[2:]
                        return {"dmarc_record": txt, "has_dmarc": True, "dmarc_policy": policy}
            except Exception:
                pass
            return {"has_dmarc": False}

        def get_dkim(selector):
            try:
                answers = resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                for rdata in answers:
                    txt = "".join([b.decode('utf-8', errors='ignore') for b in rdata.strings])
                    if txt.startswith("v=DKIM1"):
                        return {"has_dkim": True, "dkim_selector": selector}
            except Exception:
                pass
            return None

        def get_a():
            try:
                answers = resolver.resolve(domain, "A")
                if answers:
                    return {"ip_address": str(answers[0])}
            except Exception:
                pass
            return {}

        def get_ns():
            try:
                answers = resolver.resolve(domain, "NS")
                ns_list = [str(rdata.target).rstrip('.') for rdata in answers]
                return {"nameservers": ns_list}
            except Exception:
                pass
            return {}

        # Run concurrently
        mx_task = asyncio.to_thread(get_mx)
        spf_task = asyncio.to_thread(get_spf)
        dmarc_task = asyncio.to_thread(get_dmarc)
        a_task = asyncio.to_thread(get_a)
        ns_task = asyncio.to_thread(get_ns)

        mx_res, spf_res, dmarc_res, a_res, ns_res = await asyncio.gather(
            mx_task, spf_task, dmarc_task, a_task, ns_task, return_exceptions=True
        )

        mx_res = mx_res if isinstance(mx_res, dict) else {}
        spf_res = spf_res if isinstance(spf_res, dict) else {"has_spf": False}
        dmarc_res = dmarc_res if isinstance(dmarc_res, dict) else {"has_dmarc": False}
        a_res = a_res if isinstance(a_res, dict) else {}
        ns_res = ns_res if isinstance(ns_res, dict) else {}

        # DKIM (concurrently)
        selectors = ["google", "default", "mail", "dkim", "selector1", "selector2"]
        dkim_tasks = [asyncio.to_thread(get_dkim, sel) for sel in selectors]
        dkim_results = await asyncio.gather(*dkim_tasks, return_exceptions=True)
        dkim_res = {"has_dkim": False}
        for res in dkim_results:
            if isinstance(res, dict) and res.get("has_dkim"):
                dkim_res = res
                break

        findings = []
        if mx_res:
            findings.append({"platform": "dns_mx", "metadata": mx_res, "confidence": "high"})
        if spf_res.get("has_spf"):
            findings.append({"platform": "dns_spf", "metadata": spf_res, "confidence": "high"})
        if dmarc_res.get("has_dmarc"):
            findings.append({"platform": "dns_dmarc", "metadata": dmarc_res, "confidence": "high"})
        if dkim_res.get("has_dkim"):
            findings.append({"platform": "dns_dkim", "metadata": dkim_res, "confidence": "high"})
        if a_res:
            findings.append({"platform": "dns_a", "metadata": a_res, "confidence": "high"})
        if ns_res:
            findings.append({"platform": "dns_ns", "metadata": ns_res, "confidence": "high"})

        security_score = 0
        if spf_res.get("has_spf"): security_score += 1
        if dmarc_res.get("has_dmarc"): security_score += 1
        if dkim_res.get("has_dkim"): security_score += 1

        metadata = {
            "domain": domain,
            "mx_provider": mx_res.get("mx_provider"),
            "has_spf": spf_res.get("has_spf", False),
            "has_dmarc": dmarc_res.get("has_dmarc", False),
            "has_dkim": dkim_res.get("has_dkim", False),
            "dkim_selector": dkim_res.get("dkim_selector"),
            "ip_address": a_res.get("ip_address"),
            "nameservers": ns_res.get("nameservers"),
            "security_score": security_score
        }
        
        metadata = {k: v for k, v in metadata.items() if v is not None}

        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            metadata=metadata,
            findings=findings
        )
