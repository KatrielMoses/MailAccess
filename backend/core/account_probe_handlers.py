"""Native handlers for sites that can't be expressed declaratively.

Each handler has the signature ``async def h(client, defn, email, timeout) -> record``
and returns a probe record (see :mod:`backend.core.account_probe`). Handlers
are defensive: they never raise, degrading to an inconclusive/rate-limited record on
any deviation so one flaky site never breaks the batch. They are dispatched from the
site definition's ``handler`` field via the :data:`HANDLERS` registry.

They implement bespoke multi-request techniques — control-email disambiguation,
Microsoft's autodiscover oracle, and the recovery-hint relays — as original
MailAccess logic against publicly-observable endpoint behavior.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any

import httpx

from .account_probe import (
    _empty_record,
    _mask_email,
    _probe_declarative,
    apply_extract_fields,
)
from .phone_extractor import mask_phone

_LOG = logging.getLogger(__name__)


def _control_email(email: str) -> str:
    domain = email.split("@", 1)[1] if "@" in email else "example.com"
    return f"ma{secrets.token_hex(6)}@{domain}"


async def control_email(
    client: httpx.AsyncClient, defn: dict[str, Any], email: str, timeout: float
) -> dict[str, Any]:
    """Probe the real email and a random control at the same domain.

    Defeats allow-all / deny-all endpoints: the account exists only when the
    real address reads as *taken* while a random control at the same domain
    reads as *available*. If both read taken, the domain answers uniformly
    (catch-all) and the result is not-exists.
    """
    real = await _probe_declarative(client, defn, email, timeout)
    if real.get("rateLimit"):
        return real
    if real.get("exists") is not True:
        return real  # not taken (or inconclusive) — nothing to disambiguate
    control = await _probe_declarative(client, defn, _control_email(email), timeout)
    record = _empty_record(defn)
    if control.get("rateLimit") or control.get("exists") is None:
        record["exists"] = None
        return record
    # real taken AND control available -> genuine account; else catch-all.
    record["exists"] = control.get("exists") is False
    return record


async def office365(
    client: httpx.AsyncClient, defn: dict[str, Any], email: str, timeout: float
) -> dict[str, Any]:
    """Microsoft autodiscover existence oracle with a control probe.

    A random control at the same domain must return non-200 (unknown) while the
    real address returns 200 (known). If the control also returns 200 the tenant
    accepts anything (catch-all) → rate-limited/inconclusive.
    """
    base = "https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/"
    suffix = "?Protocol=Autodiscoverv1"
    headers = {"User-Agent": "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0)"}

    async def _status(addr: str) -> int | None:
        try:
            resp = await client.get(
                f"{base}{addr}{suffix}", headers=headers, timeout=timeout,
                follow_redirects=False,
            )
            return resp.status_code
        except (httpx.TimeoutException, httpx.RequestError):
            return None

    control_status = await _status(_control_email(email))
    if control_status is None:
        return _empty_record(defn, rate_limited=True)
    if control_status == 200:
        # Tenant answers 200 for anything — can't distinguish.
        return _empty_record(defn, rate_limited=True)
    real_status = await _status(email)
    if real_status is None:
        return _empty_record(defn, rate_limited=True)
    record = _empty_record(defn)
    record["exists"] = real_status == 200
    return record


async def adobe_recovery(
    client: httpx.AsyncClient, defn: dict[str, Any], email: str, timeout: float
) -> dict[str, Any]:
    """Adobe IMS existence + masked recovery (secondary email / security phone).

    Step 1 POSTs the authentication state; an ``errorCode`` means no account.
    On existence, the encrypted auth-state header is relayed to the challenges
    endpoint, which may expose a masked ``secondaryEmail`` / ``securityPhoneNumber``.
    """
    client_id = str(defn.get("ims_client_id") or "adobedotcom2")
    headers = {"X-IMS-CLIENTID": client_id, "Content-Type": "application/json",
               "Origin": "https://auth.services.adobe.com"}
    try:
        step1 = await client.post(
            "https://auth.services.adobe.com/signin/v1/authenticationstate",
            json={"username": email, "accountType": "individual"},
            headers=headers, timeout=timeout,
        )
    except (httpx.TimeoutException, httpx.RequestError):
        return _empty_record(defn, rate_limited=True)

    try:
        body = step1.json()
    except Exception:
        body = {}
    if isinstance(body, dict) and body.get("errorCode"):
        return _empty_record(defn, exists=False)

    record = _empty_record(defn, exists=True)
    auth_state = step1.headers.get("X-IMS-Authentication-State-Encrypted")
    if not auth_state:
        return record
    try:
        step2 = await client.get(
            "https://auth.services.adobe.com/signin/v2/challenges",
            params={"purpose": "passwordRecovery"},
            headers={**headers, "X-IMS-Authentication-State-Encrypted": auth_state},
            timeout=timeout,
        )
    except (httpx.TimeoutException, httpx.RequestError):
        return record
    try:
        challenges = step2.json()
    except Exception:
        challenges = {}
    if isinstance(challenges, dict):
        sec_email = challenges.get("secondaryEmail")
        sec_phone = challenges.get("securityPhoneNumber")
        if isinstance(sec_email, str) and sec_email:
            record["emailrecovery"] = _mask_email(sec_email)
        if isinstance(sec_phone, str) and sec_phone:
            record["phoneNumber"] = mask_phone(sec_phone)
    return record


async def odnoklassniki_recovery(
    client: httpx.AsyncClient, defn: dict[str, Any], email: str, timeout: float
) -> dict[str, Any]:
    """OK.ru password-recovery identity leak (masked email/phone + name).

    Reimplemented with ``extract_fields`` regex over the recovery page rather
    than a DOM-class scrape, so it degrades gracefully as markup drifts.
    """
    headers = {"User-Agent": "Mozilla/5.0", "Referer": "https://ok.ru/"}
    try:
        resp = await client.get(
            "https://ok.ru/dk",
            params={"cmd": "AnonymRecoveryEnterLogin", "st.cmd": "anonymRecoveryEnterLogin",
                    "st.email": email},
            headers=headers, timeout=timeout, follow_redirects=True,
        )
    except (httpx.TimeoutException, httpx.RequestError):
        return _empty_record(defn, rate_limited=True)

    text = resp.text
    lowered = text.lower()
    # Recovery-offer container implies the account exists.
    if "offer_contact_rest" not in lowered and "registrationcontainer" not in lowered:
        if "home_rest" in lowered:
            return _empty_record(defn, exists=False)
        return _empty_record(defn)
    record = _empty_record(defn, exists=True)
    extracted = apply_extract_fields(defn, resp, text)
    record["emailrecovery"] = extracted["emailrecovery"]
    record["phoneNumber"] = extracted["phoneNumber"]
    record["others"] = extracted["others"]
    return record


async def okcupid(
    client: httpx.AsyncClient, defn: dict[str, Any], email: str, timeout: float
) -> dict[str, Any]:
    """OkCupid existence via an anonymous GraphQL token + control disambiguation.

    Step 1 mints an anonymous auth token; step 2 asks ``isEmailValid`` for the
    target. The signal is *inverted* — a valid (registerable) address means the
    account does NOT exist. An invalid address is ambiguous (taken, or the whole
    domain is refused), so a random control at the same domain is probed: if the
    control is also invalid the domain is refused (not-exists); otherwise the
    target address is taken.
    """
    base = "https://e2p-okapi.api.okcupid.com/graphql/"
    device_id = secrets.token_hex(11)
    headers = {
        "User-Agent": "Android 115.1.0",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "x-okcupid-device-id": f"Android; Pixel 6; 13; {device_id};",
        "x-okcupid-platform": "Android",
        "x-okcupid-version": "115.1.0",
        "x-okcupid-locale": "en-US",
    }
    try:
        token_resp = await client.post(
            f"{base}AnonAuthToken",
            json={
                "operationName": "AnonAuthToken",
                "variables": {"input": {"deviceId": device_id, "siteCode": 36}},
                "query": (
                    "mutation AnonAuthToken($input: AuthAnonymousInput!) "
                    "{ authAnonymous(input: $input) { token } }"
                ),
            },
            headers={**headers, "x-apollo-operation": "AnonAuthToken"},
            timeout=timeout,
        )
    except (httpx.TimeoutException, httpx.RequestError):
        return _empty_record(defn, rate_limited=True)
    if token_resp.status_code != 200:
        return _empty_record(defn, rate_limited=True)
    try:
        token = (
            (token_resp.json() or {}).get("data", {}).get("authAnonymous", {}).get("token")
        )
    except Exception:
        token = None
    if not token:
        return _empty_record(defn, rate_limited=True)

    validate_headers = {**headers, "x-apollo-operation": "ValidateEmail", "authorization": token}

    async def _is_valid(addr: str) -> bool | None:
        try:
            resp = await client.post(
                f"{base}ValidateEmail",
                json={
                    "operationName": "ValidateEmail",
                    "variables": {"email": addr},
                    "query": (
                        "query ValidateEmail($email: String!) "
                        "{ auth { isEmailValid(email: $email) } }"
                    ),
                },
                headers=validate_headers,
                timeout=timeout,
            )
        except (httpx.TimeoutException, httpx.RequestError):
            return None
        if resp.status_code != 200:
            return None
        try:
            value = (resp.json() or {}).get("data", {}).get("auth", {}).get("isEmailValid")
        except Exception:
            return None
        return value if isinstance(value, bool) else None

    valid = await _is_valid(email)
    if valid is None:
        return _empty_record(defn, rate_limited=True)
    if valid:
        # registerable -> not currently taken
        return _empty_record(defn, exists=False)
    # invalid -> taken OR domain refused; disambiguate with a control address
    domain = email.split("@", 1)[1] if "@" in email else "example.com"
    control_valid = await _is_valid(f"{secrets.token_hex(16)}@{domain}")
    if control_valid is None:
        return _empty_record(defn)
    # control invalid too -> domain-wide refusal (not a real account)
    return _empty_record(defn, exists=control_valid)


HANDLERS: dict[str, Any] = {
    "control_email": control_email,
    "office365": office365,
    "adobe_recovery": adobe_recovery,
    "odnoklassniki_recovery": odnoklassniki_recovery,
    "okcupid": okcupid,
}
