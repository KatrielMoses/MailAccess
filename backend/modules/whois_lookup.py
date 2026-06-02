from __future__ import annotations

import asyncio
import re
import socket
import whois
from typing import Any
from datetime import datetime
from ..core.http_client import build_client
from ..core.phone_extractor import normalize_phone
from .base import BaseModule, ModuleResult, ModuleStatus
from .domain_intel import _FREE_PROVIDERS

_WHOIS_PHONE_RE = re.compile(r"(?:Phone|Tel|Telephone):\s*(\+?[\d\s\-\(\)\.]{7,20})", re.I)

class WhoisLookupModule(BaseModule):
    name = "whois_lookup"
    description = "Retrieve WHOIS registration data for the email's domain."
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        domain = email.split("@")[-1].lower()

        if domain in _FREE_PROVIDERS:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                metadata={"domain": domain},
                errors=["free provider"]
            )

        def do_whois():
            return whois.whois(domain)

        is_partial = False
        primary_error: str | None = None
        try:
            w = await asyncio.wait_for(asyncio.to_thread(do_whois), timeout=10.0)
            if w is None:
                raise ValueError("whois returned None")
        except (TimeoutError, asyncio.TimeoutError, OSError, ConnectionError, socket.gaierror) as e:
            # Network-level failure on the primary path — try IANA fallback
            primary_error = str(e)
            w = None
        except Exception as e:
            # Parse failure — try IANA fallback
            primary_error = str(e)
            w = None

        raw_whois_text = ""

        if w is None:
            # ---- IANA raw socket fallback ----
            def do_raw_whois() -> str:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10.0)
                try:
                    sock.connect(("whois.iana.org", 43))
                    sock.send(f"{domain}\r\n".encode())
                    raw = b""
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        raw += chunk
                finally:
                    sock.close()
                return raw.decode(errors="replace")

            try:
                raw_text = await asyncio.wait_for(
                    asyncio.to_thread(do_raw_whois), timeout=12.0
                )
                raw_whois_text = raw_text

                class DummyWhois:
                    def __init__(self) -> None:
                        self.creation_date = None
                        self.expiration_date = None
                        self.updated_date = None
                        self.registrar = None
                        self.name = None
                        self.org = None
                        self.emails = None
                        self.country = None
                        self.name_servers: list[str] = []
                        self.status = None

                w = DummyWhois()
                for line in raw_text.splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith("%"):
                        continue
                    lower = stripped.lower()
                    if ":" not in stripped:
                        continue
                    key, _, val = stripped.partition(":")
                    val = val.strip()
                    key_l = key.strip().lower()
                    if not val:
                        continue
                    if key_l in ("registrar",):
                        w.registrar = w.registrar or val
                    elif key_l in ("organisation", "organization", "org"):
                        w.org = w.org or val
                    elif key_l in ("created", "creation date", "registered"):
                        w.creation_date = w.creation_date or val
                    elif key_l in ("changed", "updated", "updated date", "last-modified"):
                        w.updated_date = w.updated_date or val
                    elif key_l in ("expires", "expiry date", "expiration date", "expire"):
                        w.expiration_date = w.expiration_date or val
                    elif key_l in ("nserver", "name server", "nameserver"):
                        if isinstance(w.name_servers, list):
                            w.name_servers.append(val.split()[0].lower())
                    elif key_l == "status":
                        w.status = w.status or val
                    elif key_l == "country":
                        w.country = w.country or val
                is_partial = True

            except (OSError, ConnectionError, socket.gaierror, TimeoutError,
                    asyncio.TimeoutError) as e2:
                # Both primary AND fallback had network failures — truly unreachable
                return ModuleResult(
                    status=ModuleStatus.FAILED,
                    metadata={"domain": domain},
                    errors=[
                        f"WHOIS lookup failed: {primary_error}",
                        f"IANA fallback also unreachable: {e2}",
                    ],
                )
            except Exception as e2:
                # IANA fallback had a parse/decode error — still PARTIAL, not FAILED
                return ModuleResult(
                    status=ModuleStatus.PARTIAL,
                    metadata={"domain": domain},
                    errors=[
                        f"WHOIS parse failed: {primary_error}",
                        f"IANA fallback parse error: {e2}",
                    ],
                )

        if not raw_whois_text:
            raw_whois_text = _extract_raw_whois_text(w)

        def parse_date(d: object) -> datetime | None:
            if isinstance(d, list):
                d = d[0]
            if isinstance(d, datetime):
                # Strip timezone so arithmetic with naive datetime.now() never raises
                return d.replace(tzinfo=None)
            if isinstance(d, str):
                # Try ISO-8601 prefix first (handles "2022-01-15T00:00:00Z" etc.)
                for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
                    try:
                        return datetime.strptime(d[:19] if "T" in d else d[:10], fmt)
                    except Exception:
                        pass
            return None

        creation_date = parse_date(w.creation_date)
        expiration_date = parse_date(w.expiration_date)
        updated_date = parse_date(w.updated_date)

        registrar = w.registrar
        registrant_name = w.name
        registrant_org = w.org
        registrant_email = w.emails
        registrant_country = w.country
        name_servers = w.name_servers
        status = w.status

        if isinstance(registrant_email, list):
            registrant_email = registrant_email[0]
        
        is_privacy_protected = False
        privacy_keywords = ["privacy", "redacted", "protected", "whoisguard"]
        check_fields = [
            str(registrant_name).lower(), str(registrant_org).lower(), 
            str(registrant_email).lower(), str(registrar).lower()
        ]
        
        for field in check_fields:
            if any(kw in field for kw in privacy_keywords):
                is_privacy_protected = True
                break

        domain_age_days = None
        if creation_date:
            domain_age_days = (datetime.now() - creation_date).days

        is_expired = False
        if expiration_date:
            is_expired = expiration_date < datetime.now()

        metadata_raw = {
            "registrant_name": registrant_name,
            "registrant_org": registrant_org,
            "registrant_email": registrant_email,
            "registrant_country": registrant_country,
            "registrar": registrar,
            "creation_date": creation_date.isoformat() if creation_date else None,
            "expiration_date": expiration_date.isoformat() if expiration_date else None,
            "updated_date": updated_date.isoformat() if updated_date else None,
            "name_servers": name_servers,
            "status": status,
        }

        metadata_clean = {k: v for k, v in metadata_raw.items() if v is not None}
        confidence = "medium" if is_privacy_protected else "high"

        finding = {
            "platform": "whois",
            "metadata": metadata_clean,
            "confidence": confidence
        }

        phone_findings = await self._phone_findings(domain, registrar, raw_whois_text)

        module_metadata = {
            "domain": domain,
            "is_privacy_protected": is_privacy_protected,
            "registrar": registrar,
            "domain_age_days": domain_age_days,
            "is_expired": is_expired
        }
        module_metadata = {k: v for k, v in module_metadata.items() if v is not None}

        return ModuleResult(
            status=ModuleStatus.PARTIAL if is_partial else ModuleStatus.SUCCESS,
            metadata=module_metadata,
            findings=[finding, *phone_findings]
        )

    async def _phone_findings(
        self,
        domain: str,
        registrar: str | None,
        raw_whois_text: str,
    ) -> list[dict[str, Any]]:
        phones: dict[str, dict[str, Any]] = {}

        for raw_phone in _extract_whois_phones(raw_whois_text):
            normalized = normalize_phone(raw_phone)
            if normalized:
                phones[normalized] = {
                    "phone": normalized,
                    "source": "whois",
                    "registrar": registrar,
                    "domain": domain,
                }

        rdap_data = await _fetch_rdap(domain)
        if rdap_data:
            for raw_phone in _extract_rdap_phones(rdap_data):
                normalized = normalize_phone(raw_phone)
                if normalized:
                    phones[normalized] = {
                        "phone": normalized,
                        "source": "rdap",
                        "registrar": registrar or _rdap_registrar(rdap_data),
                        "domain": domain,
                    }

        return [
            {
                "platform": "whois_phone",
                "signal_type": "phone_number",
                "confidence": "medium",
                "metadata": {k: v for k, v in metadata.items() if v},
            }
            for metadata in phones.values()
        ]


def _extract_raw_whois_text(whois_result: Any) -> str:
    candidates: list[str] = []
    for attr in ("text", "raw", "raw_text"):
        value = getattr(whois_result, attr, None)
        if isinstance(value, str) and value.strip():
            candidates.append(value)
    try:
        text = str(whois_result)
    except Exception:
        text = ""
    if text:
        candidates.append(text)
    return "\n".join(candidates)


def _extract_whois_phones(raw_text: str) -> list[str]:
    return [match.group(1).strip() for match in _WHOIS_PHONE_RE.finditer(raw_text or "")]


async def _fetch_rdap(domain: str) -> dict[str, Any] | None:
    try:
        async with build_client(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(f"https://rdap.org/domain/{domain}")
        if resp.status_code != 200:
            return None
        data = resp.json()
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _extract_rdap_phones(value: Any) -> list[str]:
    phones: list[str] = []
    if isinstance(value, dict):
        if value.get("type") == "tel" and isinstance(value.get("value"), str):
            phones.append(value["value"].strip())
        for nested in value.values():
            phones.extend(_extract_rdap_phones(nested))
    elif isinstance(value, list):
        if (
            len(value) >= 4
            and value[0] == "tel"
            and isinstance(value[3], str)
        ):
            phones.append(value[3].strip())
        for nested in value:
            phones.extend(_extract_rdap_phones(nested))
    return phones


def _rdap_registrar(data: dict[str, Any]) -> str | None:
    entities = data.get("entities")
    if not isinstance(entities, list):
        return None
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles")
        if isinstance(roles, list) and "registrar" not in roles:
            continue
        name = entity.get("handle")
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list):
            for item in _extract_vcard_values(vcard, "fn"):
                return item
        return str(name) if name else None
    return None


def _extract_vcard_values(value: Any, prop_name: str) -> list[str]:
    found: list[str] = []
    if isinstance(value, list):
        if len(value) >= 4 and value[0] == prop_name and isinstance(value[3], str):
            found.append(value[3])
        for nested in value:
            found.extend(_extract_vcard_values(nested, prop_name))
    return found
