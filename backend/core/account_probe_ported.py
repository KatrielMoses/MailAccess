"""Expanded email-existence site checks.

Each entry describes, for one third-party service, the single HTTP request that
distinguishes "this email has an account" from "it does not", plus the response
markers that decide it. The checks are expressed as declarative *specs* run by
:func:`run_spec`; a handful of services that need a token pre-fetch or a second
request get a dedicated handler below.

These are independent reimplementations of publicly-observable
account-existence behaviour (endpoint, request shape, and the response signal
each service returns) — the same functional facts the rest of the site catalogue
captures. Merged into the catalogue by ``mailaccess_sites_loader`` and into the
probe registry by ``account_probe_handlers``.

Verdict mapping (honest, unlike a plain exists/rate-limit split):
* ``exists``       -> account confirmed for this email
* ``absent``       -> confirmed no account
* ``rate_limited`` -> the service actively throttled/blocked us (HTTP 429/403…)
* ``inconclusive`` -> got a response but no decisive signal (exists=None)
Transport failures (DNS/connect/timeout/TLS) are reported as ``transport_error``.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from .account_probe import _empty_record

_LOG = logging.getLogger(__name__)

_SPEC_HANDLER = "ported_spec"


def _sub(value: Any, email: str) -> Any:
    """Recursively substitute ``{email}`` in strings within a spec fragment."""
    if isinstance(value, str):
        return value.replace("{email}", email)
    if isinstance(value, dict):
        return {k: _sub(v, email) for k, v in value.items()}
    if isinstance(value, list):
        return [_sub(v, email) for v in value]
    return value


def _json_at(payload: Any, path: list[str]) -> Any:
    cur = payload
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return _MISSING
        cur = cur[key]
    return cur


_MISSING = object()


def _condition_met(cond: dict[str, Any], response: httpx.Response, text: str,
                   json_body: Any) -> bool:
    if "status" in cond and response.status_code != int(cond["status"]):
        return False
    if "status_in" in cond and response.status_code not in cond["status_in"]:
        return False
    if "text_contains" in cond and str(cond["text_contains"]) not in text:
        return False
    if "text_equals" in cond and text.strip() != str(cond["text_equals"]):
        return False
    if "not_text_contains" in cond and str(cond["not_text_contains"]) in text:
        return False
    if "header_contains" in cond:
        spec = cond["header_contains"]
        hv = response.headers.get(str(spec.get("name") or ""), "")
        if str(spec.get("sub")) not in str(hv):
            return False
    if "json_eq" in cond:
        spec = cond["json_eq"]
        if _json_at(json_body, list(spec.get("path") or [])) != spec.get("value"):
            return False
    if "json_all" in cond:
        for spec in cond["json_all"]:
            if _json_at(json_body, list(spec.get("path") or [])) != spec.get("value"):
                return False
    if "json_key" in cond:
        if _json_at(json_body, list(cond["json_key"])) is _MISSING:
            return False
    if "json_contains" in cond:
        spec = cond["json_contains"]
        val = _json_at(json_body, list(spec.get("path") or []))
        if not isinstance(val, str) or str(spec.get("sub")) not in val:
            return False
    return True


def _extract(text: str, rule: dict[str, Any]) -> str | None:
    """Pull a token out of a prefetch response (split-before/after or regex)."""
    import re as _re

    if "regex" in rule:
        m = _re.search(str(rule["regex"]), text)
        return m.group(1) if m else None
    after = rule.get("after")
    before = rule.get("before")
    body = text
    if after is not None:
        if str(after) not in body:
            return None
        body = body.split(str(after), 1)[1]
    if before is not None:
        if str(before) not in body:
            return None
        body = body.split(str(before), 1)[0]
    return body


async def run_spec(
    client: httpx.AsyncClient, defn: dict[str, Any], email: str, timeout: float
) -> dict[str, Any]:
    """Execute a declarative email-existence spec attached to ``defn['spec']``."""
    spec = defn.get("spec") or {}

    # Optional prefetch: fetch a page first and extract CSRF/token values that the
    # main request needs (the client's cookie jar carries any Set-Cookie forward).
    extracted: dict[str, str] = {}
    pf = spec.get("prefetch")
    if pf:
        try:
            pf_resp = await client.request(
                str(pf.get("method") or "GET").upper(),
                _sub(str(pf.get("url") or ""), email),
                headers=_sub(pf.get("headers") or {}, email) or None,
                timeout=timeout, follow_redirects=True,
            )
        except (httpx.TimeoutException, httpx.RequestError):
            return _empty_record(defn, transport_error=True)
        except Exception:  # noqa: BLE001
            return _empty_record(defn, transport_error=True)
        for var, rule in (pf.get("extract") or {}).items():
            if "cookie" in rule:
                token = pf_resp.cookies.get(str(rule["cookie"]))
            else:
                token = _extract(pf_resp.text or "", rule)
            if not token:
                # Required token missing -> we can't complete the check.
                return _empty_record(defn, exists=None)
            extracted[var] = token

    def _fill(value: Any) -> Any:
        value = _sub(value, email)
        if extracted and isinstance(value, str):
            for var, tok in extracted.items():
                value = value.replace("{" + var + "}", tok)
        if isinstance(value, dict):
            return {k: _fill(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_fill(v) for v in value]
        return value

    method = str(spec.get("method") or "GET").upper()
    url = _fill(str(spec.get("url") or ""))
    if not url:
        return _empty_record(defn)
    headers = _fill(spec.get("headers") or {})
    params = _fill(spec.get("params"))
    follow = bool(spec.get("follow_redirects", False))

    kwargs: dict[str, Any] = {"headers": headers or None, "timeout": timeout,
                              "follow_redirects": follow}
    if params:
        kwargs["params"] = params
    if "json" in spec:
        kwargs["json"] = _fill(spec["json"])
    elif "form" in spec:
        kwargs["data"] = _fill(spec["form"])
    elif "raw" in spec:
        kwargs["content"] = _fill(spec["raw"])

    try:
        response = await client.request(method, url, **kwargs)
    except (httpx.TimeoutException, httpx.RequestError):
        return _empty_record(defn, transport_error=True)
    except Exception:  # noqa: BLE001 - isolate a misbehaving endpoint
        return _empty_record(defn, transport_error=True)

    text = response.text or ""
    try:
        json_body = response.json()
    except Exception:  # noqa: BLE001 - not all responses are JSON
        json_body = None

    for rule in spec.get("rules") or []:
        conds = rule.get("when") or {}
        if _condition_met(conds, response, text, json_body):
            verdict = rule.get("verdict")
            if verdict == "exists":
                return _empty_record(defn, exists=True)
            if verdict == "absent":
                return _empty_record(defn, exists=False)
            if verdict == "rate_limited":
                return _empty_record(defn, rate_limited=True)
            return _empty_record(defn, exists=None)

    default = str(spec.get("default") or "inconclusive")
    if default == "rate_limited":
        return _empty_record(defn, rate_limited=True)
    if default == "absent":
        return _empty_record(defn, exists=False)
    return _empty_record(defn, exists=None)


# Common browser UA so specs don't each repeat it.
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


def _site(site_id: str, domain: str, category: str, flow: str, spec: dict[str, Any],
          *, high_value: bool = False) -> dict[str, Any]:
    return {
        "id": site_id,
        "name": site_id,
        "domain": domain,
        "category": category,
        "check_type": "email-existence",
        "flow": flow,
        "handler": _SPEC_HANDLER,
        "high_value": high_value,
        "spec": spec,
    }


# ---------------------------------------------------------------------------
# Site catalogue (declarative). Grows by category.
# ---------------------------------------------------------------------------
_SITES: list[dict[str, Any]] = [
    _site("hubspot", "hubspot.com", "crm", "login", {
        "method": "POST",
        "url": "https://api.hubspot.com/login-api/v1/login",
        "headers": {"User-Agent": _UA, "content-type": "application/json",
                    "origin": "https://app.hubspot.com",
                    "referer": "https://app.hubspot.com/"},
        "raw": '{"email":"{email}","password":"","rememberLogin":false}',
        "rules": [
            {"when": {"status": 400, "json_eq": {"path": ["status"],
                                                 "value": "INVALID_PASSWORD"}},
             "verdict": "exists"},
            {"when": {"status": 400, "json_eq": {"path": ["status"],
                                                 "value": "INVALID_USER"}},
             "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("nimble", "nimble.com", "crm", "register", {
        "method": "GET",
        "url": "https://www.nimble.com/lib/register.php?email={email}",
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Referer": "https://www.nimble.com/"},
        "rules": [
            {"when": {"text_contains": "This email is already registered."},
             "verdict": "exists"},
            {"when": {"text_equals": "true"}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("pipedrive", "pipedrive.com", "crm", "register", {
        "method": "POST",
        "url": "https://app.pipedrive.com/signup-service/start",
        "headers": {"User-Agent": _UA, "accept": "application/json",
                    "content-type": "application/json",
                    "origin": "https://www.pipedrive.com",
                    "referer": "https://www.pipedrive.com/"},
        "raw": ('{"email":"{email}","language":"fr","country_code":"fr",'
                '"selectedTier":null,"packages":[]}'),
        "rules": [
            {"when": {"status": 200, "json_contains": {
                "path": ["errors", "user_email"], "sub": "Email is not available"}},
             "verdict": "exists"},
            {"when": {"status": 200, "json_eq": {
                "path": ["data", "redirectUrl"],
                "value": "https://app.pipedrive.com/signup-service"}},
             "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("nocrm", "nocrm.io", "crm", "register", {
        "method": "GET",
        "url": "https://register.nocrm.io/register/check_trial_duplicate?email={email}",
        "headers": {"User-Agent": _UA, "x-requested-with": "XMLHttpRequest"},
        "rules": [
            {"when": {"text_contains": '{"account":1,"url":"'}, "verdict": "exists"},
            {"when": {"text_equals": '{"account":0}'}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("freelancer", "freelancer.com", "jobs", "register", {
        "method": "POST",
        "url": ("https://www.freelancer.com/api/users/0.1/users/check"
                "?compact=true&new_errors=true"),
        "headers": {"User-Agent": _UA, "Accept": "application/json, text/plain, */*",
                    "Content-Type": "application/json",
                    "Origin": "https://www.freelancer.com"},
        "raw": '{"user":{"email":"{email}"}}',
        "rules": [
            {"when": {"status": 409, "text_contains": "EMAIL_ALREADY_IN_USE"},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("nutshell", "nutshell.com", "crm", "login", {
        "method": "POST",
        "url": "https://app.nutshell.com/auth",
        "headers": {"User-Agent": _UA,
                    "content-type": "application/x-www-form-urlencoded",
                    "origin": "https://app.nutshell.com",
                    "referer": "https://app.nutshell.com/auth"},
        "form": {"via": "database", "timezone_offset": "1", "remember_me": "true",
                 "username": "{email}", "invalidToken": "false", "password": "a"},
        "rules": [
            {"when": {"text_contains": "Sorry, your password is incorrect"},
             "verdict": "exists"},
            {"when": {"text_contains":
                      "find a Nutshell account for that email address."},
             "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("insightly", "insightly.com", "crm", "register", {
        "method": "POST",
        "url": "https://accounts.insightly.com/signup/isemailvalid",
        "headers": {"User-Agent": _UA, "x-requested-with": "XMLHttpRequest",
                    "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "origin": "https://accounts.insightly.com",
                    "referer": "https://accounts.insightly.com/?plan=trial"},
        "form": {"emailaddress": "{email}"},
        "rules": [
            {"when": {"text_contains": "An account exists for this address."},
             "verdict": "exists"},
            {"when": {"text_equals": "true"}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("axonaut", "axonaut.com", "crm", "register", {
        "method": "GET",
        "url": "https://axonaut.com/onboarding/?email={email}",
        "follow_redirects": False,
        "headers": {"User-Agent": _UA, "referer": "https://axonaut.com/en"},
        "rules": [
            {"when": {"status": 302, "header_contains":
                      {"name": "Location", "sub": "/login?email"}},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("teamleader", "teamleader.eu", "crm", "register", {
        "method": "POST",
        "url": "https://focus.teamleader.eu/app/emails/availability",
        "headers": {"User-Agent": _UA, "content-type": "application/json",
                    "origin": "https://signup.focus.teamleader.fr",
                    "referer": "https://signup.focus.teamleader.fr/"},
        "raw": '{"email":"{email}"}',
        "rules": [
            {"when": {"text_equals": '{"available":false}'}, "verdict": "exists"},
            {"when": {"text_equals": '{"available":true}'}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("zoho", "zoho.com", "crm", "login", {
        "prefetch": {"method": "GET", "url": "https://accounts.zoho.com/register",
                     "headers": {"User-Agent": _UA},
                     "extract": {"csrf": {"cookie": "iamcsr"}}},
        "method": "POST",
        "url": "https://accounts.zoho.com/signin/v2/lookup/{email}",
        "headers": {"User-Agent": _UA, "Accept": "*/*",
                    "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                    "Origin": "https://accounts.zoho.com",
                    "X-ZCSRF-TOKEN": "iamcsrcoo={csrf}"},
        "form": {"mode": "primary", "servicename": "ZohoCRM",
                 "serviceurl": "https://crm.zoho.com/crm/ShowHomePage.do",
                 "service_language": "fr"},
        "rules": [
            {"when": {"status": 200, "json_all": [
                {"path": ["message"], "value": "User exists"},
                {"path": ["status_code"], "value": 201}]}, "verdict": "exists"},
            {"when": {"status": 200, "json_eq": {"path": ["status_code"],
                                                 "value": 400}}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("atlassian", "atlassian.com", "cms", "login", {
        "prefetch": {"method": "GET", "url": "https://id.atlassian.com/login",
                     "headers": {"User-Agent": _UA},
                     "extract": {"csrf": {"after": "{&quot;csrfToken&quot;:&quot;",
                                          "before": "&quot"}}},
        "method": "POST",
        "url": "https://id.atlassian.com/rest/check-username",
        "headers": {"User-Agent": _UA,
                    "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                    "Origin": "https://id.atlassian.com",
                    "Referer": "https://id.atlassian.com/"},
        "form": {"csrfToken": "{csrf}", "username": "{email}"},
        "rules": [
            {"when": {"json_eq": {"path": ["action"], "value": "signup"}},
             "verdict": "absent"},
            {"when": {"json_key": ["action"]}, "verdict": "exists"},
        ],
        "default": "inconclusive",
    }, high_value=True),

    _site("voxmedia", "voxmedia.com", "cms", "register", {
        "method": "POST",
        "url": "https://auth.voxmedia.com/chorus_auth/email_valid.json",
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": "https://auth.voxmedia.com",
                    "Referer": "https://auth.voxmedia.com/login"},
        "form": {"email": "{email}"},
        "rules": [
            {"when": {"json_eq": {"path": ["available"], "value": True}},
             "verdict": "absent"},
            {"when": {"json_eq": {"path": ["message"],
                                  "value": "You cannot use this email address."}},
             "verdict": "absent"},
            {"when": {"status": 200}, "verdict": "exists"},
        ],
        "default": "rate_limited",
    }),

    _site("wordpress", "wordpress.com", "cms", "login", {
        "method": "GET",
        "url": "https://public-api.wordpress.com/rest/v1.1/users/{email}/auth-options",
        "params": {"http_envelope": "1", "locale": "fr"},
        "headers": {"User-Agent": _UA},
        "rules": [
            {"when": {"json_eq": {"path": ["body", "email_verified"], "value": True}},
             "verdict": "exists"},
            {"when": {"json_eq": {"path": ["body", "email_verified"], "value": False}},
             "verdict": "absent"},
            {"when": {"text_contains": "unknown_user"}, "verdict": "absent"},
            {"when": {"text_contains": "email_login_not_allowed"}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("aboutme", "about.me", "company", "register", {
        "prefetch": {"method": "GET", "url": "https://about.me/",
                     "headers": {"User-Agent": _UA},
                     "extract": {"auth": {"after": ',"AUTH_TOKEN":"', "before": '"'}}},
        "method": "POST",
        "url": "https://about.me/n/signup",
        "headers": {"User-Agent": _UA, "X-Auth-Token": "{auth}",
                    "Content-Type": "application/json",
                    "X-Requested-With": "XMLHttpRequest", "Origin": "https://about.me"},
        "raw": ('{"user_name":"","first_name":"","last_name":"","allowed_features":[],'
                '"counters":{"id":"counters"},"settings":{"id":"settings"},'
                '"email_address":"{email}","honeypot":"",'
                '"signup":{"id":"signup","step":"email","method":"email"}}'),
        "rules": [
            {"when": {"status": 409}, "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("buymeacoffee", "buymeacoffee.com", "crowdfunding", "register", {
        "prefetch": {"method": "GET", "url": "https://www.buymeacoffee.com/",
                     "headers": {"User-Agent": _UA},
                     "extract": {"csrf": {
                         "regex": r'bmc_csrf_token["\'][^>]*?value=["\']([^"\']+)'}}},
        "method": "POST",
        "url": "https://www.buymeacoffee.com/auth/validate_email_and_password",
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": "https://www.buymeacoffee.com",
                    "Cookie": "bmccsrftoken={csrf}"},
        "form": {"email": "{email}", "password": "Xq9pLz2rWk7mVn4t",
                 "bmc_csrf_token": "{csrf}"},
        "rules": [
            {"when": {"status": 200, "json_eq": {"path": ["status"],
                                                 "value": "SUCCESS"}},
             "verdict": "absent"},
            {"when": {"status": 200, "json_eq": {"path": ["status"], "value": "FAIL"},
                      "text_contains": "email"}, "verdict": "exists"},
        ],
        "default": "rate_limited",
    }),

    _site("archive", "archive.org", "software", "register", {
        "method": "POST",
        "url": "https://archive.org/account/signup",
        "headers": {"User-Agent": _UA,
                    "Content-Type": ("multipart/form-data; "
                                     "boundary=---------------------------"),
                    "Origin": "https://archive.org",
                    "Referer": "https://archive.org/account/signup"},
        "raw": ('-----------------------------\r\nContent-Disposition: form-data; '
                'name="input_name"\r\n\r\nusername\r\n----------------------------'
                '-\r\nContent-Disposition: form-data; name="input_value"\r\n\r\n'
                '{email}\r\n-----------------------------\r\nContent-Disposition: '
                'form-data; name="input_validator"\r\n\r\ntrue\r\n---------------'
                '--------------\r\nContent-Disposition: form-data; name='
                '"submit_by_js"\r\n\r\ntrue\r\n-------------------------------\r\n'),
        "rules": [
            {"when": {"text_contains": "is already taken."}, "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("docker", "docker.com", "software", "register", {
        "method": "POST",
        "url": "https://hub.docker.com/v2/users/signup/",
        "headers": {"User-Agent": _UA, "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Referer": "https://hub.docker.com/signup",
                    "Origin": "https://hub.docker.com"},
        "raw": ('{"email":"{email}","password":"","recaptcha_response":"",'
                '"redirect_value":"","subscribe":true,"username":""}'),
        "rules": [
            {"when": {"text_contains": "This email is already in use."},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("firefox", "firefox.com", "software", "login", {
        "method": "POST",
        "url": "https://api.accounts.firefox.com/v1/account/status",
        "headers": {"User-Agent": _UA},
        "form": {"email": "{email}"},
        "rules": [
            {"when": {"json_eq": {"path": ["exists"], "value": True}},
             "verdict": "exists"},
            {"when": {"json_eq": {"path": ["exists"], "value": False}},
             "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("issuu", "issuu.com", "software", "register", {
        "method": "GET",
        "url": "https://issuu.com/call/signup/check-email/{email}",
        "headers": {"User-Agent": _UA, "Content-Type": "application/json"},
        "rules": [
            {"when": {"json_eq": {"path": ["status"], "value": "unavailable"}},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("lastpass", "lastpass.com", "software", "register", {
        "method": "GET",
        "url": "https://lastpass.com/create_account.php",
        "params": {"check": "avail", "skipcontent": "1", "mistype": "1",
                   "username": "{email}"},
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Referer": "https://lastpass.com/"},
        "rules": [
            {"when": {"text_equals": "no"}, "verdict": "exists"},
            {"when": {"text_equals": "ok"}, "verdict": "absent"},
            {"when": {"text_equals": "emailinvalid"}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("mail_ru", "mail.ru", "mails", "password-recovery", {
        "method": "POST",
        "url": "https://account.mail.ru/api/v1/user/password/restore",
        "headers": {"User-Agent": _UA, "x-requested-with": "XMLHttpRequest",
                    "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "origin": "https://account.mail.ru",
                    "referer": "https://account.mail.ru/recovery"},
        "form": {"email": "{email}", "htmlencoded": "false"},
        "rules": [
            {"when": {"status": 200, "json_eq": {"path": ["status"], "value": 200}},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("protonmail", "protonmail.com", "mails", "pgp-index", {
        "method": "GET",
        "url": "https://api.protonmail.ch/pks/lookup?op=index&search={email}",
        "headers": {"User-Agent": _UA},
        "rules": [
            {"when": {"text_contains": "info:1:1"}, "verdict": "exists"},
            {"when": {"text_contains": "info:1:0"}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("discord", "discord.com", "social_media", "register", {
        "method": "POST",
        "url": "https://discord.com/api/v9/auth/register",
        "headers": {"User-Agent": _UA, "Content-Type": "application/json",
                    "Origin": "https://discord.com"},
        "raw": ('{"fingerprint":"","email":"{email}","username":"probe_user_x",'
                '"password":"Xq9pLz2rWk7mVn4t","invite":null,"consent":true,'
                '"date_of_birth":"1990-01-01","gift_code_sku_id":null,'
                '"captcha_key":null}'),
        "rules": [
            {"when": {"text_contains": "EMAIL_ALREADY_REGISTERED"}, "verdict": "exists"},
            {"when": {"text_contains": "captcha-required"}, "verdict": "rate_limited"},
            {"when": {"status": 201}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("facebook", "facebook.com", "social_media", "register", {
        "prefetch": {"method": "GET",
                     "url": "https://www.facebook.com/accounts/emailsignup/",
                     "headers": {"User-Agent": _UA},
                     "extract": {"csrf": {
                         "regex": r'csrf_token"\s*:\s*"([^"]+)"'}}},
        "method": "POST",
        "url": ("https://www.facebook.com/api/v1/web/accounts/"
                "web_create_ajax/attempt/"),
        "headers": {"User-Agent": _UA, "x-csrftoken": "{csrf}",
                    "Origin": "https://www.facebook.com"},
        "form": {"email": "{email}", "first_name": "", "opt_into_one_tap": "false"},
        "rules": [
            {"when": {"text_contains": "email_is_taken"}, "verdict": "exists"},
            {"when": {"text_contains": "email_sharing_limit"}, "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("instagram", "instagram.com", "social_media", "register", {
        "prefetch": {"method": "GET",
                     "url": "https://www.instagram.com/accounts/emailsignup/",
                     "headers": {"User-Agent": _UA},
                     "extract": {"csrf": {
                         "regex": r'csrf_token\\?"\s*:\s*\\?"([^"\\]+)'}}},
        "method": "POST",
        "url": ("https://www.instagram.com/api/v1/web/accounts/"
                "web_create_ajax/attempt/"),
        "headers": {"User-Agent": _UA, "x-csrftoken": "{csrf}",
                    "Origin": "https://www.instagram.com"},
        "form": {"email": "{email}", "first_name": "", "opt_into_one_tap": "false"},
        "rules": [
            {"when": {"text_contains": "email_is_taken"}, "verdict": "exists"},
            {"when": {"text_contains": "email_sharing_limit"}, "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("imgur", "imgur.com", "social_media", "register", {
        "method": "POST",
        "url": "https://imgur.com/signin/ajax_email_available",
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": "https://imgur.com"},
        "form": {"email": "{email}"},
        "rules": [
            {"when": {"json_eq": {"path": ["data", "available"], "value": True}},
             "verdict": "absent"},
            {"when": {"text_contains": "Invalid email domain"}, "verdict": "absent"},
            {"when": {"status": 200}, "verdict": "exists"},
        ],
        "default": "rate_limited",
    }),

    _site("myspace", "myspace.com", "social_media", "register", {
        "prefetch": {"method": "GET", "url": "https://myspace.com/signup/email",
                     "headers": {"User-Agent": _UA},
                     "extract": {"hash": {
                         "after": '<input name="csrf" type="hidden" value="',
                         "before": '"'}}},
        "method": "POST",
        "url": "https://myspace.com/ajax/account/validateemail",
        "headers": {"User-Agent": _UA, "Hash": "{hash}",
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"},
        "form": {"email": "{email}"},
        "rules": [
            {"when": {"text_contains":
                      "This email address was already used to create an account."},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("crevado", "crevado.com", "social_media", "register", {
        "prefetch": {"method": "GET", "url": "https://crevado.com",
                     "headers": {"User-Agent": _UA},
                     "extract": {"csrf": {
                         "after": '<meta name="csrf-token" content="',
                         "before": '"'}}},
        "method": "POST",
        "url": "https://crevado.com/",
        "headers": {"User-Agent": _UA,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://crevado.com"},
        "form": {"utf8": "✓", "authenticity_token": "{csrf}", "plan": "basic",
                 "account[full_name]": "", "account[email]": "{email}",
                 "account[password]": "", "account[domain]": "",
                 "account[terms_accepted]": "1"},
        "rules": [
            {"when": {"text_contains": "has already been taken"}, "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("patreon", "patreon.com", "social_media", "register", {
        "method": "POST",
        "url": "https://www.patreon.com/api/email/available",
        "params": {"json-api-version": "1.0", "include": "[]"},
        "headers": {"User-Agent": _UA, "Content-Type": "application/vnd.api+json",
                    "Origin": "https://www.patreon.com"},
        "raw": '{"data":{"attributes":{"email":"{email}"},"relationships":{}}}',
        "rules": [
            {"when": {"json_eq": {"path": ["data", "is_available"], "value": True}},
             "verdict": "absent"},
            {"when": {"status": 200}, "verdict": "exists"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("fanpop", "fanpop.com", "social_media", "register", {
        "method": "POST",
        "url": "https://www.fanpop.com/login/superlogin",
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": "https://www.fanpop.com",
                    "Referer": "https://www.fanpop.com/register"},
        "form": {"type": "register", "user[name]": "", "user[password]": "",
                 "user[email]": "{email}", "agreement": "",
                 "PersistentCookie": "PersistentCookie",
                 "redirect_url": "https://www.fanpop.com/",
                 "submissiontype": "register"},
        "rules": [
            {"when": {"text_contains": "already registered"}, "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("parler", "parler.com", "social_media", "login", {
        "method": "POST",
        "url": "https://api.parler.com/v2/login/new",
        "headers": {"User-Agent": _UA, "content-type": "application/json",
                    "origin": "https://parler.com", "referer": "https://parler.com/"},
        "raw": ('{"identifier":"{email}","password":"invalidpasswordfortest",'
                '"deviceId":"probe0device0id00"}'),
        "rules": [
            {"when": {"text_contains": "password"}, "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("plurk", "plurk.com", "social_media", "register", {
        "method": "POST",
        "url": "https://www.plurk.com/Users/isEmailFound",
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": "https://www.plurk.com"},
        "form": {"email": "{email}"},
        "rules": [
            {"when": {"text_equals": "True"}, "verdict": "exists"},
            {"when": {"text_equals": "False"}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("pinterest", "pinterest.com", "social_media", "register", {
        "method": "GET",
        "url": "https://www.pinterest.com/_ngjs/resource/EmailExistsResource/get/",
        "params": {"source_url": "/",
                   "data": '{"options": {"email": "{email}"}, "context": {}}'},
        "headers": {"User-Agent": _UA},
        "rules": [
            {"when": {"text_contains": "source_field"}, "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("taringa", "taringa.net", "social_media", "register", {
        "method": "POST",
        "url": "https://www.taringa.net/api/auth/availability/email",
        "headers": {"User-Agent": _UA, "Content-Type": "application/json; charset=utf-8",
                    "Origin": "https://www.taringa.net"},
        "raw": '{"email":"{email}"}',
        "rules": [
            {"when": {"status": 200, "text_equals": '{"available":false}'},
             "verdict": "exists"},
            {"when": {"status": 200, "text_equals": '{"available":true}'},
             "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("tellonym", "tellonym.me", "social_media", "register", {
        "method": "GET",
        "url": "https://api.tellonym.me/accounts/check",
        "params": {"email": "{email}", "errorMessage": "", "limit": "25"},
        "headers": {"User-Agent": _UA, "Accept": "application/json",
                    "tellonym-client": "web:0.51.1", "Origin": "https://tellonym.me",
                    "Referer": "https://tellonym.me/register/email"},
        "rules": [
            {"when": {"text_contains": "EMAIL_ALREADY_IN_USE"}, "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("twitter", "twitter.com", "social_media", "register", {
        "method": "GET",
        "url": "https://api.twitter.com/i/users/email_available.json",
        "params": {"email": "{email}"},
        "headers": {"User-Agent": _UA},
        "rules": [
            {"when": {"json_eq": {"path": ["taken"], "value": True}}, "verdict": "exists"},
            {"when": {"json_eq": {"path": ["taken"], "value": False}}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("vsco", "vsco.co", "social_media", "register", {
        "method": "GET",
        "url": "https://api.vsco.co/2.0/users/email?email={email}",
        "headers": {"User-Agent": _UA,
                    "Authorization": "Bearer 7356455548d0a1d886db010883388d08be84d0c9"},
        "rules": [
            {"when": {"json_eq": {"path": ["email_status"], "value": "has_account"}},
             "verdict": "exists"},
            {"when": {"json_eq": {"path": ["email_status"], "value": "no_account"}},
             "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),
]


_SITES.extend([
    _site("pornhub", "pornhub.com", "porn", "register", {
        "prefetch": {"method": "GET", "url": "https://www.pornhub.com/signup",
                     "headers": {"User-Agent": _UA},
                     "extract": {"token": {
                         "regex": r'name="token"[^>]*?value="([^"]+)"'}}},
        "method": "POST", "url": "https://www.pornhub.com/user/create_account_check",
        "params": {"token": "{token}"},
        "headers": {"User-Agent": _UA},
        "form": {"check_what": "email", "email": "{email}"},
        "rules": [
            {"when": {"json_eq": {"path": ["error_message"],
                                  "value": "Email has been taken."}},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("redtube", "redtube.com", "porn", "register", {
        "prefetch": {"method": "GET", "url": "https://redtube.com/register",
                     "headers": {"User-Agent": _UA},
                     "extract": {"token": {
                         "regex": r'id="token"[^>]*?value="([^"]+)"'}}},
        "method": "POST", "url": "https://www.redtube.com/user/create_account_check",
        "params": {"token": "{token}"},
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Origin": "https://redtube.com"},
        "form": {"token": "{token}", "redirect": "", "check_what": "email",
                 "email": "{email}"},
        "rules": [
            {"when": {"text_contains": "Email has been taken."}, "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("xnxx", "xnxx.com", "porn", "register", {
        "prefetch": {"method": "GET", "url": "https://www.xnxx.com",
                     "headers": {"User-Agent": _UA}, "extract": {}},
        "method": "GET", "url": "https://www.xnxx.com/account/checkemail?email={email}",
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Referer": "https://www.xnxx.com/"},
        "rules": [
            {"when": {"text_contains": "exclu de notre site"}, "verdict": "exists"},
            {"when": {"json_eq": {"path": ["code"], "value": 0}}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("xvideos", "xvideos.com", "porn", "register", {
        "method": "GET", "url": "https://www.xvideos.com/account/checkemail",
        "params": {"email": "{email}"},
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Referer": "https://www.xvideos.com/"},
        "rules": [
            {"when": {"text_contains":
                      "already in use or its owner has excluded it"},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("blablacar", "blablacar.com", "transport", "register", {
        "prefetch": {"method": "GET", "url": "https://www.blablacar.fr/register",
                     "headers": {"User-Agent": _UA},
                     "extract": {"tok": {"after": '"appToken":"', "before": '"'}}},
        "method": "GET",
        "url": "https://edge.blablacar.fr/auth/validation/email/{email}",
        "headers": {"User-Agent": _UA, "Accept": "application/json",
                    "Authorization": "Bearer {tok}", "x-locale": "fr_FR",
                    "Origin": "https://www.blablacar.fr"},
        "rules": [
            {"when": {"json_key": ["url"]}, "verdict": "exists"},
            {"when": {"json_key": ["exists"]}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("nike", "nike.com", "shopping", "register", {
        "method": "POST", "url": "https://unite.nike.com/account/email/v1",
        "params": {"appVersion": "831", "experienceVersion": "831",
                   "uxid": "com.nike.commerce.nikedotcom.web", "locale": "fr_FR",
                   "backendEnvironment": "identity", "mobile": "false",
                   "native": "false", "visit": "1"},
        "headers": {"User-Agent": _UA, "Content-Type": "text/plain;charset=UTF-8",
                    "Origin": "https://www.nike.com", "Referer": "https://www.nike.com/"},
        "raw": '{"emailAddress":"{email}"}',
        "rules": [
            {"when": {"status": 409}, "verdict": "exists"},
            {"when": {"status": 204}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("teamtreehouse", "teamtreehouse.com", "programing", "register", {
        "prefetch": {"method": "GET",
                     "url": "https://teamtreehouse.com/subscribe/new?trial=yes",
                     "headers": {"User-Agent": _UA},
                     "extract": {"csrf": {
                         "after": '<meta name="csrf-token" content="', "before": '"'}}},
        "method": "POST", "url": "https://teamtreehouse.com/account/email_address",
        "headers": {"User-Agent": _UA, "X-CSRF-Token": "{csrf}",
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": "https://teamtreehouse.com"},
        "form": {"email": "{email}"},
        "rules": [
            {"when": {"text_contains": "that email address is taken."},
             "verdict": "exists"},
            {"when": {"text_equals": '{"success":true}'}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("strava", "strava.com", "sport", "register", {
        "prefetch": {"method": "GET",
                     "url": ("https://www.strava.com/register/free?cta=sign-up"
                             "&element=button&source=website_show"),
                     "headers": {"User-Agent": _UA},
                     "extract": {"csrf": {
                         "after": '<meta name="csrf-token" content="', "before": '"'}}},
        "method": "GET", "url": "https://www.strava.com/athletes/email_unique",
        "params": {"email": "{email}"},
        "headers": {"User-Agent": _UA, "X-CSRF-Token": "{csrf}",
                    "X-Requested-With": "XMLHttpRequest"},
        "rules": [
            {"when": {"text_equals": "false"}, "verdict": "exists"},
            {"when": {"text_equals": "true"}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("diigo", "diigo.com", "learning", "register", {
        "method": "GET", "url": "https://www.diigo.com/user_mana2/check_email",
        "params": {"email": "{email}"},
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Referer": "https://www.diigo.com/sign-up?plan=free"},
        "rules": [
            {"when": {"status": 200, "text_equals": "0"}, "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("duolingo", "duolingo.com", "learning", "register", {
        "method": "GET", "url": "https://www.duolingo.com/2017-06-30/users?email={email}",
        "headers": {"User-Agent": _UA},
        "rules": [
            {"when": {"status": 200, "not_text_contains": '"users": []',
                      "text_contains": '"users"'}, "verdict": "exists"},
            {"when": {"status": 200, "text_contains": '"users": []'},
             "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("coroflot", "coroflot.com", "jobs", "register", {
        "method": "POST", "url": "https://www.coroflot.com/home/signup_email_check",
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://www.coroflot.com",
                    "Referer": "https://www.coroflot.com/signup"},
        "form": {"email": "{email}"},
        "rules": [
            {"when": {"json_eq": {"path": ["data"], "value": -2}}, "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("seoclerks", "seoclerks.com", "jobs", "register", {
        "prefetch": {"method": "GET", "url": "https://www.seoclerks.com",
                     "headers": {"User-Agent": _UA},
                     "extract": {"token": {"after": 'token" value="', "before": '"'},
                                 "cr": {"after": '__cr" value="', "before": '"'}}},
        "method": "POST", "url": "https://www.seoclerks.com/signup/check",
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": "https://www.seoclerks.com"},
        "form": {"token": "{token}", "__cr": "{cr}", "fsub": "1", "droplet": "",
                 "user_username": "probeuserx", "user_email": "{email}",
                 "user_password": "Xq9pLz2rWk7mVn4t",
                 "confirm_password": "Xq9pLz2rWk7mVn4t"},
        "rules": [
            {"when": {"text_contains":
                      "The email address you entered is already taken."},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("anydo", "any.do", "productivity", "register", {
        "method": "POST", "url": "https://sm-prod2.any.do/check_email",
        "headers": {"User-Agent": _UA, "Content-Type": "application/json; charset=UTF-8",
                    "X-Platform": "3", "Origin": "https://desktop.any.do",
                    "Referer": "https://desktop.any.do/"},
        "raw": '{"email":"{email}"}',
        "rules": [
            {"when": {"status": 200, "json_eq": {"path": ["user_exists"],
                                                 "value": True}}, "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("evernote", "evernote.com", "productivity", "login", {
        "prefetch": {"method": "GET", "url": "https://www.evernote.com/Login.action",
                     "headers": {"User-Agent": _UA},
                     "extract": {
                         "hpts": {"after": 'getElementById("hpts").value = "',
                                  "before": '"'},
                         "hptsh": {"after": 'getElementById("hptsh").value = "',
                                   "before": '"'},
                         "sp": {"after": '<input type="hidden" name="_sourcePage"'
                                ' value="', "before": '"'},
                         "fp": {"after": '<input type="hidden" name="__fp" value="',
                                "before": '"'}}},
        "method": "POST", "url": "https://www.evernote.com/Login.action",
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": "https://www.evernote.com",
                    "Referer": "https://www.evernote.com/Login.action"},
        "form": {"username": "{email}", "evaluateUsername": "", "hpts": "{hpts}",
                 "hptsh": "{hptsh}", "analyticsLoginOrigin": "login_action",
                 "clipperFlow": "false", "showSwitchService": "true",
                 "usernameImmutable": "false", "_sourcePage": "{sp}", "__fp": "{fp}"},
        "rules": [
            {"when": {"text_contains": "usePasswordAuth"}, "verdict": "exists"},
            {"when": {"text_contains": "displayMessage"}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("caringbridge", "caringbridge.org", "medical", "login", {
        "method": "POST", "url": "https://www.caringbridge.org/signin",
        "headers": {"User-Agent": _UA,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://www.caringbridge.org",
                    "Referer": "https://www.caringbridge.org/signin"},
        "form": {"csrf": "", "email": "{email}", "password_placeholder": "",
                 "submit-btn": "Continue"},
        "rules": [
            {"when": {"text_contains": "Welcome Back,"}, "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("sevencups", "7cups.com", "medical", "register", {
        "method": "POST", "url": "https://www.7cups.com/listener/CreateAccount.php",
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Origin": "https://www.7cups.com",
                    "Referer": "https://www.7cups.com/listener/CreateAccount.php",
                    "Content-Type": ("multipart/form-data; "
                                     "boundary=---------------------------")},
        "raw": ('-----------------------------\r\nContent-Disposition: form-data; '
                'name="email"\r\n\r\n{email}\r\n-----------------------------\r\n'
                'Content-Disposition: form-data; name="passwd"\r\n\r\n\r\n----------'
                '-------------------\r\nContent-Disposition: form-data; name='
                '"dobMonth"\r\n\r\n12\r\n-----------------------------\r\nContent-'
                'Disposition: form-data; name="dobDay"\r\n\r\n11\r\n---------------'
                '--------------\r\nContent-Disposition: form-data; name="dobYear"'
                '\r\n\r\n2000\r\n-----------------------------\r\nContent-Disposition'
                ': form-data; name="data-request-datatype"\r\n\r\njson\r\n---------'
                '--------------------\r\n'),
        "rules": [
            {"when": {"status": 200, "text_contains":
                      "Account already exists with this email address"},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("vrbo", "vrbo.com", "real_estate", "login", {
        "method": "POST", "url": "https://www.vrbo.com/auth/aam/v3/status",
        "headers": {"User-Agent": _UA, "Content-Type": "application/json",
                    "x-homeaway-site": "vrbo", "Origin": "https://www.vrbo.com"},
        "raw": '{"emailAddress":"{email}"}',
        "rules": [
            {"when": {"text_contains": "LOGIN_UMS"}, "verdict": "exists"},
            {"when": {"text_contains": "SIGNUP"}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("venmo", "venmo.com", "payment", "register", {
        "prefetch": {"method": "GET", "url": "https://venmo.com/signup/email",
                     "headers": {"User-Agent": _UA},
                     "extract": {"vid": {"cookie": "v_id"}}},
        "method": "POST", "url": "https://venmo.com/api/v5/users",
        "headers": {"User-Agent": _UA, "Content-Type": "application/json",
                    "device-id": "{vid}", "Origin": "https://venmo.com",
                    "Referer": "https://venmo.com/"},
        "raw": ('{"last_name":"e","first_name":"z","email":"{email}","password":"",'
                '"phone":"1","client_id":10}'),
        "rules": [
            {"when": {"text_contains":
                      "That email is already registered in our system."},
             "verdict": "exists"},
            {"when": {"not_text_contains": "Not acceptable", "status": 200},
             "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("rocketreach", "rocketreach.co", "osint", "register", {
        "prefetch": {"method": "GET", "url": "https://rocketreach.co/signup",
                     "headers": {"User-Agent": _UA},
                     "extract": {"csrf": {
                         "regex": r'name="csrfmiddlewaretoken" value="([^"]+)"'}}},
        "method": "GET",
        "url": "https://rocketreach.co/v1/validateEmail?email_address={email}",
        "headers": {"User-Agent": _UA, "x-csrftoken": "{csrf}",
                    "Referer": "https://rocketreach.co/signup"},
        "rules": [
            {"when": {"json_eq": {"path": ["found"], "value": True}},
             "verdict": "exists"},
            {"when": {"json_eq": {"path": ["found"], "value": False}},
             "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("spotify", "spotify.com", "music", "register", {
        "method": "GET",
        "url": "https://spclient.wg.spotify.com/signup/public/v1/account",
        "params": {"validate": "1", "email": "{email}"},
        "headers": {"User-Agent": _UA, "Accept": "application/json, text/plain, */*"},
        "rules": [
            {"when": {"json_eq": {"path": ["status"], "value": 20}}, "verdict": "exists"},
            {"when": {"json_eq": {"path": ["status"], "value": 1}}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("blip", "blip.fm", "music", "register", {
        "method": "POST",
        "url": "https://blip.fm/signup/save",
        "headers": {"User-Agent": _UA, "Origin": "https://blip.fm",
                    "Referer": "https://blip.fm/"},
        "form": {"referringUrl": "", "genpass": "1", "signup[urlName]": "test",
                 "signup[emailAddress]": "{email}", "g-recaptcha-response": "",
                 "tos": "0"},
        "rules": [
            {"when": {"text_contains": "That email address is already in use."},
             "verdict": "exists"},
            {"when": {"text_contains": 'spinner.gif" alt="loading..."'},
             "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("lastfm", "last.fm", "music", "register", {
        "prefetch": {"method": "GET", "url": "https://www.last.fm/join",
                     "headers": {"User-Agent": _UA},
                     "extract": {"csrf": {"cookie": "csrftoken"}}},
        "method": "POST",
        "url": "https://www.last.fm/join/partial/validate",
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Referer": "https://www.last.fm/join",
                    "Cookie": "csrftoken={csrf}"},
        "form": {"csrfmiddlewaretoken": "{csrf}", "userName": "", "email": "{email}"},
        "rules": [
            {"when": {"text_contains":
                      "that email address is already registered to another account."},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("smule", "smule.com", "music", "register", {
        "prefetch": {"method": "GET", "url": "https://www.smule.com/user/check_email",
                     "headers": {"User-Agent": _UA},
                     "extract": {"csrf": {
                         "regex": r'content="([^"]+)"\s+name="csrf-token"'}}},
        "method": "POST",
        "url": "https://www.smule.com/user/check_email",
        "headers": {"User-Agent": _UA, "X-CSRF-Token": "{csrf}",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://www.smule.com"},
        "form": {"email": "{email}"},
        "rules": [
            {"when": {"json_eq": {"path": ["email"], "value": "True"}},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("tunefind", "tunefind.com", "music", "register", {
        "method": "POST",
        "url": "https://www.tunefind.com/user/join",
        "headers": {"User-Agent": _UA, "x-tf-react": "true",
                    "Origin": "https://www.tunefind.com",
                    "Referer": "https://www.tunefind.com/",
                    "Content-Type": ("multipart/form-data; "
                                     "boundary=---------------------------")},
        "raw": ('-----------------------------\r\nContent-Disposition: form-data; '
                'name="username"\r\n\r\n\r\n-----------------------------\r\n'
                'Content-Disposition: form-data; name="email"\r\n\r\n{email}\r\n'
                '-----------------------------\r\nContent-Disposition: form-data; '
                'name="password"\r\n\r\n\r\n-------------------------------\r\n'),
        "rules": [
            {"when": {"text_contains":
                      "Someone is already registered with that email address"},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("ello", "ello.co", "medias", "register", {
        "method": "POST",
        "url": "https://ello.co/api/v2/availability",
        "headers": {"User-Agent": _UA, "Accept": "application/json",
                    "Content-Type": "application/json", "Origin": "https://ello.co"},
        "raw": '{"email":"{email}"}',
        "rules": [
            {"when": {"json_eq": {"path": ["availability", "email"], "value": True}},
             "verdict": "absent"},
            {"when": {"json_eq": {"path": ["availability", "email"], "value": False}},
             "verdict": "exists"},
        ],
        "default": "rate_limited",
    }),

    _site("flickr", "flickr.com", "medias", "login", {
        "method": "GET",
        "url": "https://identity-api.flickr.com/migration?email={email}",
        "headers": {"User-Agent": _UA, "Origin": "https://identity.flickr.com",
                    "Referer": "https://identity.flickr.com/login"},
        "rules": [
            {"when": {"json_eq": {"path": ["state_code"], "value": "5"}},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("komoot", "komoot.com", "medias", "login", {
        "method": "POST",
        "url": "https://account.komoot.com/v1/signin",
        "headers": {"User-Agent": _UA, "Content-Type": "application/json",
                    "Origin": "https://account.komoot.com",
                    "Referer": "https://account.komoot.com/signin"},
        "raw": '{"email":"{email}"}',
        "rules": [
            {"when": {"json_contains": {"path": ["type"], "sub": "login"}},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("rambler", "rambler.ru", "medias", "login", {
        "method": "POST",
        "url": "https://id.rambler.ru/jsonrpc",
        "headers": {"User-Agent": _UA, "Content-Type": "application/json",
                    "Origin": "https://id.rambler.ru",
                    "Referer": "https://id.rambler.ru/champ/registration"},
        "raw": ('{"method":"Rambler::Id::get_email_account_info","params":'
                '[{"email":"{email}"}],"rpc":"2.0"}'),
        "rules": [
            {"when": {"json_eq": {"path": ["result", "exists"], "value": 0}},
             "verdict": "absent"},
            {"when": {"json_key": ["result"]}, "verdict": "exists"},
        ],
        "default": "rate_limited",
    }),

    _site("eventbrite", "eventbrite.com", "products", "login", {
        "prefetch": {"method": "GET",
                     "url": "https://www.eventbrite.com/signin/?referrer=%2F",
                     "headers": {"User-Agent": _UA},
                     "extract": {"csrf": {"cookie": "csrftoken"}}},
        "method": "POST",
        "url": "https://www.eventbrite.com/api/v3/users/lookup/",
        "headers": {"User-Agent": _UA, "X-CSRFToken": "{csrf}",
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/json",
                    "Origin": "https://www.eventbrite.com",
                    "Cookie": "csrftoken={csrf}"},
        "raw": '{"email":"{email}"}',
        "rules": [
            {"when": {"status": 200, "json_eq": {"path": ["exists"], "value": True}},
             "verdict": "exists"},
            {"when": {"status": 200, "json_eq": {"path": ["exists"], "value": False}},
             "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("sporcle", "sporcle.com", "sport", "register", {
        "method": "POST",
        "url": "https://www.sporcle.com/auth/ajax/verify.php",
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": "https://www.sporcle.com"},
        "form": {"email": "{email}", "password1": "", "password2": "", "handle": "",
                 "humancheck": "", "reg_path": "main_header_join", "ref_page": "",
                 "querystring": ""},
        "rules": [
            {"when": {"text_contains": "account already exists with this email"},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("armurerieauxerre", "armurerie-auxerre.com", "shopping", "register", {
        "method": "POST",
        "url": "https://www.armurerie-auxerre.com/customer/Email/email/",
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": "https://www.armurerie-auxerre.com"},
        "form": {"mail": "{email}"},
        "rules": [
            {"when": {"text_equals": "exist"}, "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("deliveroo", "deliveroo.com", "shopping", "register", {
        "method": "POST",
        "url": "https://consumer-ow-api.deliveroo.com/orderapp/v1/check-email",
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "X-Roo-Client": "orderweb-client", "X-Roo-Country": "fr",
                    "Content-Type": "application/json;charset=UTF-8",
                    "Origin": "https://deliveroo.com"},
        "json": {"email_address": "{email}"},
        "rules": [
            {"when": {"status": 200, "json_eq": {"path": ["registered"],
                                                 "value": True}}, "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("dominosfr", "dominos.fr", "shopping", "register", {
        "prefetch": {"method": "GET",
                     "url": "https://commande.dominos.fr/eStore/fr/Signup",
                     "headers": {"User-Agent": _UA}, "extract": {}},
        "method": "GET",
        "url": "https://commande.dominos.fr/eStore/fr/Signup/IsEmailAvailable",
        "params": {"email": "{email}"},
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest"},
        "rules": [
            {"when": {"status": 200, "text_equals": "false"}, "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("ebay", "ebay.com", "shopping", "login", {
        "prefetch": {"method": "GET", "url": "https://www.ebay.com/signin/",
                     "headers": {"User-Agent": _UA},
                     "extract": {"srt": {"after": '"csrfAjaxToken":"',
                                         "before": '"'}}},
        "method": "POST",
        "url": "https://signin.ebay.com/signin/srv/identifer",
        "headers": {"User-Agent": _UA, "Origin": "https://www.ebay.com"},
        "form": {"identifier": "{email}", "srt": "{srt}"},
        "rules": [
            {"when": {"json_key": ["err"]}, "verdict": "absent"},
            {"when": {"status": 200}, "verdict": "exists"},
        ],
        "default": "rate_limited",
    }),

    _site("envato", "envato.com", "shopping", "register", {
        "method": "POST",
        "url": "https://account.envato.com/api/validate_email",
        "headers": {"User-Agent": _UA, "Accept": "application/json",
                    "Content-type": "application/x-www-form-urlencoded"},
        "form": {"email": "{email}"},
        "rules": [
            {"when": {"text_contains": "Email is already in use"}, "verdict": "exists"},
            {"when": {"text_contains": "Page designed by Kotulsky"}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),

    _site("garmin", "garmin.com", "shopping", "register", {
        "prefetch": {"method": "GET", "url": "https://sso.garmin.com/sso/createNewAccount",
                     "headers": {"User-Agent": _UA},
                     "extract": {"token": {"after": '"token": "', "before": '"'}}},
        "method": "POST",
        "url": "https://sso.garmin.com/sso/validateNewAccount",
        "headers": {"User-Agent": _UA, "Origin": "https://sso.garmin.com",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"},
        "form": {"email": "{email}", "token": "{token}"},
        "rules": [
            {"when": {"text_equals": "false"}, "verdict": "exists"},
            {"when": {"text_equals": "true"}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("naturabuy", "naturabuy.fr", "shopping", "register", {
        "method": "POST",
        "url": "https://www.naturabuy.fr/includes/ajax/register.php",
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": ("multipart/form-data; "
                                     "boundary=---------------------------"),
                    "Origin": "https://www.naturabuy.fr"},
        "raw": ('-----------------------------\r\nContent-Disposition: form-data; '
                'name="jsref"\r\n\r\nemail\r\n-----------------------------\r\n'
                'Content-Disposition: form-data; name="jsvalue"\r\n\r\n{email}\r\n'
                '-----------------------------\r\nContent-Disposition: form-data; '
                'name="registerMode"\r\n\r\nfull\r\n----------------------------'
                '---\r\n'),
        "rules": [
            {"when": {"json_eq": {"path": ["free"], "value": False}},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("codecademy", "codecademy.com", "programing", "register", {
        "prefetch": {"method": "GET",
                     "url": "https://www.codecademy.com/register?redirect=%2F",
                     "headers": {"User-Agent": _UA},
                     "extract": {"csrf": {
                         "after": '<meta name="csrf-token" content="', "before": '"'}}},
        "method": "POST",
        "url": "https://www.codecademy.com/register/validate",
        "headers": {"User-Agent": _UA, "X-CSRF-Token": "{csrf}",
                    "Content-Type": "application/json",
                    "Origin": "https://www.codecademy.com"},
        "raw": '{"user":{"email":"{email}"}}',
        "rules": [
            {"when": {"text_contains": "is already taken"}, "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("codepen", "codepen.io", "programing", "register", {
        "prefetch": {"method": "GET",
                     "url": "https://codepen.io/accounts/signup/user/free",
                     "headers": {"User-Agent": _UA},
                     "extract": {"csrf": {
                         "after": '<meta name="csrf-token" content="', "before": '"'}}},
        "method": "POST",
        "url": "https://codepen.io/accounts/duplicate_check",
        "headers": {"User-Agent": _UA, "X-CSRF-Token": "{csrf}",
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": "https://codepen.io"},
        "form": {"attribute": "email", "value": "{email}", "context": "user"},
        "rules": [
            {"when": {"text_contains": "That Email is already taken."},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("devrant", "devrant.com", "programing", "register", {
        "method": "POST",
        "url": "https://devrant.com/api/users",
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": "https://devrant.com",
                    "Referer": "https://devrant.com/feed/top/month?login=1"},
        "form": {"app": "3", "type": "1", "email": "{email}", "username": "",
                 "password": "", "guid": "", "plat": "3", "sid": "", "seid": ""},
        "rules": [
            {"when": {"json_eq": {"path": ["error"],
                                  "value": ("The email specified is already "
                                            "registered to an account.")}},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    }),

    _site("replit", "replit.com", "programing", "register", {
        "method": "POST",
        "url": "https://replit.com/data/user/exists",
        "headers": {"User-Agent": _UA, "content-type": "application/json",
                    "x-requested-with": "XMLHttpRequest",
                    "Origin": "https://replit.com"},
        "raw": '{"email":"{email}"}',
        "rules": [
            {"when": {"json_eq": {"path": ["exists"], "value": True}},
             "verdict": "exists"},
            {"when": {"json_eq": {"path": ["exists"], "value": False}},
             "verdict": "absent"},
        ],
        "default": "rate_limited",
    }, high_value=True),
])


# ---------------------------------------------------------------------------
# MyBB forums — one shared flow: GET /member.php to read the ``my_post_key``
# CSRF value, then POST /xmlhttp.php?action=email_availability. The forum replies
# "…already in use by another member." when the email has an account.
# ---------------------------------------------------------------------------
_MYBB_FORUMS: list[tuple[str, str]] = [
    ("babeshows", "www.babeshows.co.uk"),
    ("badeggsonline", "www.badeggsonline.com"),
    ("biosmods", "www.bios-mods.com"),
    ("biotechnologyforums", "www.biotechnologyforums.com"),
    ("blackworldforum", "www.blackworldforum.com"),
    ("blitzortung", "forum.blitzortung.org"),
    ("bluegrassrivals", "www.bluegrassrivals.com"),
    ("cambridgemt", "discussion.cambridge-mt.com"),
    ("chinaphonearena", "www.chinaphonearena.com"),
    ("clashfarmer", "www.clashfarmer.com"),
    ("codeigniter", "forum.codeigniter.com"),
    ("cpaelites", "www.cpaelites.com"),
    ("cpahero", "www.cpahero.com"),
    ("cracked_to", "cracked.to"),
    ("demonforums", "demonforums.net"),
    ("freiberg", "drachenhort.user.stunet.tu-freiberg.de"),
    ("koditv", "forum.kodi.tv"),
    ("mybb", "community.mybb.com"),
    ("nattyornot", "nattyornotforum.nattyornot.com"),
    ("ndemiccreations", "forum.ndemiccreations.com"),
    ("nextpvr", "forums.nextpvr.com"),
    ("onlinesequencer", "onlinesequencer.net"),
    ("thecardboard", "thecardboard.org"),
    ("therianguide", "forums.therian-guide.com"),
    ("thevapingforum", "www.thevapingforum.com"),
]


def _mybb_site(site_id: str, host: str) -> dict[str, Any]:
    base = f"https://{host}"
    return _site(site_id, host, "forum", "register", {
        "prefetch": {"method": "GET", "url": f"{base}/member.php",
                     "headers": {"User-Agent": _UA},
                     "extract": {"key": {"after": 'var my_post_key = "',
                                         "before": '"'}}},
        "method": "POST",
        "url": f"{base}/xmlhttp.php",
        "params": {"action": "email_availability"},
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": base, "Referer": f"{base}/member.php"},
        "form": {"email": "{email}", "my_post_key": "{key}"},
        "rules": [
            {"when": {"text_contains": "Your request was blocked"},
             "verdict": "rate_limited"},
            {"when": {"text_contains":
                      "email address that is already in use by another member."},
             "verdict": "exists"},
            {"when": {"status": 200}, "verdict": "absent"},
        ],
        "default": "rate_limited",
    })


_SITES.extend(_mybb_site(i, d) for i, d in _MYBB_FORUMS)


# ---------------------------------------------------------------------------
# XenForo forums — LOGIN-ERROR differential (non-intrusive; no email sent, just
# a login attempt with a junk password). XenForo distinguishes a missing account
# ("The requested user '…' could not be found.") from a real one ("The password
# you entered is incorrect."). GET /login/ for the _xfToken, then POST
# /login/login. One template covers every XenForo instance; add hosts below
# (fingerprint the rest of the 355 with the platform sniffer to extend).
# ---------------------------------------------------------------------------
# 131 XenForo instances fingerprinted from the owner's 346-site research
# ("combined login form" set). One template enumerates all of them via login-error.
_XENFORO_FORUMS: list[str] = (
    "4gameforum.com 650f.bike 8wayrun.com animebase.me antique-bottles.net "
    "antiscam.space bayoushooter.com blast.hk board.mddc.dev bookandreader.com "
    "caves.ru chiase.org discussfastpitch.com dragonbyte-tech.com "
    "dronepilots.community dumpz.ws erogen.club f1-forum.fi fanficslandia.com "
    "fanforum.uscho.com ffhl.kld.im finforum.net firesofheaven.org foforum.fr "
    "forobeta.com foropl.com foropuros.com fortreeforums.xyz forum-mechanika.pl "
    "forum.alidropship.com forum.amperka.ru forum.bestflowers.ru forum.beyond3d.com "
    "forum.console-tribe.com forum.coralvuehydros.com forum.crocieristi.it "
    "forum.elektrolab.eu forum.evendim.ru forum.facmedicine.com forum.freeso.org "
    "forum.igrarena.ru forum.iinkor.com forum.lottoced.com forum.lvivport.com "
    "forum.macplanete.com forum.maidenfans.com forum.mcmodding.ru forum.mmajunkie.com "
    "forum.mohaddis.com forum.motorguia.net forum.motorka.org forum.neformat.com.ua "
    "forum.questionablequesting.com forum.rudtp.ru forum.team-mediaportal.com "
    "forum.vuurwerkcrew.nl forum.wordreference.com forum.xanasoft.com forum.xlegio.ru "
    "forumprawne.org forumroman.com forums.animeuknews.net forums.arcade-museum.com "
    "forums.canadiancontent.net forums.immigration.com forums.majorgeeks.com "
    "forums.njpinebarrens.com forums.sonicretro.org forums.talkseafishing.co.uk "
    "forums.techarp.com forums.vintagefashionguild.org forums.vitalfootball.co.uk "
    "forums.wolflair.com forumyuristov.ru gamesfrm.com gaminglatest.com "
    "gulfcoastgunforum.com icq.icqchat.co ilvesfoorumi.com immobilio.it indiedev.gg "
    "kellofoorumi.fi khatmenbuwat.org klocksnack.se kontrolkalemi.com mac-help.com "
    "macosx.com mb.srb2.org mmo-dev.info newdayrp.com newf319.com niflheim.top "
    "not606.com nucastle.co.uk nullcave.club nygunforum.com office-forums.com "
    "otland.net ourdjtalk.com outgress.com oyunlabi.com palungjit.org parkrocker.net "
    "phorum.armavir.ru physicsforums.com piratebuhta.club pixelexit.com "
    "predpriemach.com reincarnationforum.com rmmedia.ru rollitup.org rusfishing.ru "
    "sadece1.com salsaforums.com sexforum.ws skyblock.net speedsolving.com tech247.fi "
    "texasguntalk.com tgforum.ru thebuddyforum.com viethoagame.com volkswagen.lviv.ua "
    "vozer.net w7forums.com wasm.in weblogistics.vn windows10forums.com "
    "worldofplayers.ru xen-concept.com xentr.net"
).split()


def _xenforo_site(host: str) -> dict[str, Any]:
    base = f"https://{host}"
    site_id = "xf_" + host.replace(".", "_").replace("-", "_")
    entry = _site(site_id, host, "forum", "login", {
        "prefetch": {"method": "GET", "url": f"{base}/login/",
                     "headers": {"User-Agent": _UA},
                     # Grab the _xfToken hidden input, or the <html data-csrf>
                     # fallback (XenForo 2.x).
                     "extract": {"tok": {
                         "regex": r'(?:name="_xfToken"\s+value|data-csrf)='
                                  r'"([^"]+)"'}}},
        "method": "POST",
        "url": f"{base}/login/login",
        "headers": {"User-Agent": _UA, "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": base, "Referer": f"{base}/login/"},
        "form": {"login": "{email}", "password": "Wr0ngPass!x9q2z",
                 "_xfToken": "{tok}", "_xfResponseType": "json"},
        "rules": [
            {"when": {"text_contains": "could not be found"}, "verdict": "absent"},
            {"when": {"text_contains": "password you entered is incorrect"},
             "verdict": "exists"},
            {"when": {"text_contains": "Incorrect password"}, "verdict": "exists"},
        ],
        "default": "inconclusive",
    })
    # Display name = the forum host (XenForo instances share one template).
    entry["name"] = host
    return entry


_SITES.extend(_xenforo_site(h) for h in _XENFORO_FORUMS)


# ---------------------------------------------------------------------------
# Forgot-password ORACLE checks (INTRUSIVE — for a REGISTERED address the probe
# emails the subject a real password-reset). Marked ``intrusive=True`` so
# account_discovery only runs them when ``settings.enable_forgot_password_probes``
# is set. These must expose a NEGATIVE ("no account found") marker: a non-existent
# email hits that branch and sends nothing, and the marker can never falsely
# confirm. Positive "we sent you a reset" oracles are BANNED here — that wording
# renders unconditionally (anti-enumeration) and yields false positives.
# ---------------------------------------------------------------------------
def _fp_site(site_id: str, domain: str, spec: dict[str, Any]) -> dict[str, Any]:
    entry = _site(site_id, domain, "forgot-password", "password-recovery", spec,
                  high_value=True)
    entry["intrusive"] = True
    return entry


# NOTE: pluralsight and skillshare forgot-password oracles were REMOVED. Both
# render an unconditional "we sent you a reset" confirmation page for ANY email
# (anti-enumeration), so their positive marker fired for non-existent accounts
# too — a false-positive generator, and no reset email is actually sent for a
# missing account. A "we sent"-style positive marker is not a reliable existence
# signal; only add forgot-password oracles that expose a *negative* ("no account
# found") marker instead.


# ---------------------------------------------------------------------------
# Non-intrusive login-flow / signup-validation oracles (NO email is ever sent).
# Verified 2026-09-30 with a random non-existent address.
# ---------------------------------------------------------------------------
_SITES.extend([
    # Steam account-recovery search: a lookup (not a reset), so nothing is emailed.
    # Needs the ``sessionid`` cookie handed out by the help site echoed back as a
    # form field. Not-found leaks the absent branch; an empty ``errorMsg`` means
    # the search matched an account.
    _site("steam", "steampowered.com", "gaming", "account-recovery", {
        "prefetch": {"method": "GET",
                     "url": "https://help.steampowered.com/en/",
                     "headers": {"User-Agent": _UA},
                     "extract": {"sid": {"cookie": "sessionid"}}},
        "method": "POST",
        "url": "https://help.steampowered.com/en/wizard/AjaxLoginInfoSearch",
        "headers": {"User-Agent": _UA,
                    "X-Requested-With": "XMLHttpRequest",
                    "Origin": "https://help.steampowered.com",
                    "Referer": "https://help.steampowered.com/en/wizard/HelpWithLogin"},
        "form": {"text": "{email}", "sessionid": "{sid}"},
        "rules": [
            {"when": {"text_contains": "unable to find an account"},
             "verdict": "absent"},
            {"when": {"json_eq": {"path": ["errorMsg"], "value": ""}},
             "verdict": "exists"},
        ],
        "default": "inconclusive",
    }, high_value=True),

    # edX (open-edX) registration-validation API — a public availability check, no
    # email sent. ``validation_decisions.email`` is empty when the address is free
    # and carries an "already associated…" message when it is taken.
    _site("edx", "edx.org", "education", "signup-validation", {
        "method": "POST",
        "url": "https://courses.edx.org/api/user/v1/validation/registration",
        "headers": {"User-Agent": _UA,
                    "Origin": "https://courses.edx.org",
                    "Referer": "https://courses.edx.org/register"},
        "form": {"email": "{email}"},
        "rules": [
            {"when": {"json_eq": {"path": ["validation_decisions", "email"],
                                  "value": ""}},
             "verdict": "absent"},
            {"when": {"json_contains": {"path": ["validation_decisions", "email"],
                                        "sub": "associated"}},
             "verdict": "exists"},
        ],
        "default": "inconclusive",
    }, high_value=True),
])


# ---------------------------------------------------------------------------
# Intrusive forgot-password oracle with a reliable NEGATIVE marker (gated).
# ---------------------------------------------------------------------------
_SITES.extend([
    # Kompas (KG Media, Indonesia) — Laravel reset form. Prefetch the CSRF
    # ``_token`` (the XSRF cookie is carried forward automatically). A non-existent
    # address returns "…tidak ditemukan" (no email sent); anything else means the
    # account exists and a reset was dispatched, hence intrusive/gated.
    _fp_site("kompas", "kompas.com", {
        "prefetch": {"method": "GET",
                     "url": "https://account.kompas.com/forgot-password",
                     "headers": {"User-Agent": _UA},
                     "extract": {"tok": {
                         "regex": r'name="_token"[^>]*value="([^"]+)"'}}},
        "method": "POST",
        "url": "https://account.kompas.com/forgot-password",
        "headers": {"User-Agent": _UA,
                    "Origin": "https://account.kompas.com",
                    "Referer": "https://account.kompas.com/forgot-password"},
        "form": {"email": "{email}", "_token": "{tok}"},
        # Laravel post-redirect-get: the flash message only shows after the 302.
        "follow_redirects": True,
        "rules": [
            {"when": {"text_contains": "tidak ditemukan"}, "verdict": "absent"},
        ],
        "default": "exists",
    }),
])


# Dedicated handlers for multi-step / token-prefetch services go here later.
_EXTRA_HANDLERS: dict[str, Any] = {}


def ported_handlers() -> dict[str, Any]:
    """Handler-name -> callable, for merging into the probe HANDLERS registry."""
    return {_SPEC_HANDLER: run_spec, **_EXTRA_HANDLERS}


def ported_sites() -> dict[str, dict[str, Any]]:
    """Site-id -> site definition, for merging into the site catalogue."""
    return {s["id"]: s for s in _SITES}
