"""Headless-browser email-existence oracles (Playwright).

Some platforms only leak account existence through a JS-driven flow that raw
HTTP can't reproduce:

* **email-first login** — you submit the email; a password field appears (the
  account exists) or the page routes to signup (it doesn't). Detection uses a
  *pre/post* password-visibility check so a combined login form (password always
  present) can't be mistaken for a positive. **No email is sent** — safe to run
  by default.
* **forgot-password oracle** — you submit the email to a reset form; an
  unconditional "we sent you a reset" confirms existence. This **emails the
  subject**, so these oracles are flagged ``intrusive`` and only run when the
  caller opts in.

The runner is generic (one flow implementation, data-driven per site) — the same
approach used to gather the oracle list. Playwright is an OPTIONAL dependency
(``pip install mailaccess[browser] && playwright install chromium``); it is
imported lazily so this module loads fine without it.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

_LOG = logging.getLogger(__name__)


@dataclass
class BrowserOracle:
    id: str
    domain: str
    url: str
    flow: str  # "email_first" | "forgot_password"
    exists_markers: tuple[str, ...] = ()
    not_exists_markers: tuple[str, ...] = ()
    intrusive: bool = False  # True => submitting emails the subject


# Signup/registration routing seen when an email-first flow rejects an unknown
# address (=> NOT_EXISTS). Kept generic; per-site markers refine it.
_SIGNUP_MARKERS = (
    "create a new account", "create an account", "sign up for", "let's get you set up",
    "first time here", "want to try another", "we'll create an account",
)


# ---------------------------------------------------------------------------
# Oracle catalogue (from verified research; URLs + response markers). Add more
# here as they're confirmed — data only, no code changes needed.
# ---------------------------------------------------------------------------
ORACLES: list[BrowserOracle] = [
    # --- email-first login (NON-intrusive: no email sent) ---
    BrowserOracle("paypal", "paypal.com", "https://www.paypal.com/signin", "email_first"),
    BrowserOracle("docusign", "docusign.com", "https://account.docusign.com/", "email_first"),
    BrowserOracle("gemini", "gemini.com", "https://exchange.gemini.com/signin", "email_first",
                  exists_markers=("welcome",)),
    BrowserOracle("box", "box.com", "https://account.box.com/login", "email_first",
                  exists_markers=("not you?",)),
    BrowserOracle("docker", "docker.com", "https://login.docker.com/u/login/identifier", "email_first"),
    BrowserOracle("surveymonkey", "surveymonkey.com", "https://www.surveymonkey.com/user/sign-in/", "email_first"),
    BrowserOracle("twitter", "twitter.com", "https://x.com/i/flow/login", "email_first",
                  exists_markers=("where should we send",)),
    BrowserOracle("asana", "asana.com", "https://app.asana.com/-/login", "email_first"),
    BrowserOracle("dropbox", "dropbox.com", "https://www.dropbox.com/login", "email_first",
                  not_exists_markers=("first name", "last name")),
    BrowserOracle("komoot", "komoot.com", "https://www.komoot.com/login", "email_first",
                  not_exists_markers=("first time here",)),
    BrowserOracle("vivino", "vivino.com", "https://www.vivino.com/users/sign_in", "email_first",
                  not_exists_markers=("create a profile",)),
    BrowserOracle("calendly", "calendly.com", "https://calendly.com/login", "email_first",
                  not_exists_markers=("an account doesn't exist",)),
    BrowserOracle("coursera", "coursera.org", "https://www.coursera.org/login", "email_first"),
    BrowserOracle("mubi", "mubi.com", "https://mubi.com/login", "email_first",
                  not_exists_markers=("no mubi account associated",)),
    BrowserOracle("newegg", "newegg.com", "https://secure.newegg.com/login", "email_first",
                  not_exists_markers=("didn't find any matches",)),
    BrowserOracle("pcloud", "pcloud.com", "https://www.pcloud.com/", "email_first",
                  not_exists_markers=("sign up",)),
    BrowserOracle("subscribestar", "subscribestar.adult", "https://subscribestar.adult/login", "email_first",
                  exists_markers=("back to previous step",)),
    BrowserOracle("nextdoor", "nextdoor.com", "https://nextdoor.com/login/", "email_first"),

    # --- forgot-password oracle (INTRUSIVE: emails the subject) ---
    # Only NEGATIVE-marker oracles below: each exposes a specific "no account for
    # this email" message, so a hit is a reliable NOT_EXISTS and it can never
    # falsely confirm. Positive "we sent you a reset" oracles (pluralsight,
    # skillshare, flipboard, hackingwithswift) were REMOVED — those pages render
    # unconditionally, so they reported EXISTS for everyone (false positives) and
    # sent no email for a missing account.
    BrowserOracle("typeform", "typeform.com", "https://admin.typeform.com/forgot-password",
                  "forgot_password", not_exists_markers=("isn't linked to any typeform account",),
                  intrusive=True),
    BrowserOracle("grammarly", "grammarly.com", "https://account.grammarly.com/reset_password",
                  "forgot_password", not_exists_markers=("couldn't find an account for",),
                  intrusive=True),
    BrowserOracle("basecamp", "basecamp.com", "https://launchpad.37signals.com/password/new",
                  "forgot_password", not_exists_markers=("couldn't find that one",),
                  intrusive=True),
    BrowserOracle("gitee", "gitee.com", "https://gitee.com/password/new",
                  "forgot_password", not_exists_markers=("no gitee account related to this email",),
                  intrusive=True),
    BrowserOracle("knowyourmeme", "knowyourmeme.com", "https://knowyourmeme.com/forgot",
                  "forgot_password", not_exists_markers=("could not find that email address",),
                  intrusive=True),
    BrowserOracle("renderosity", "renderosity.com", "https://www.renderosity.com/users/forgot-password",
                  "forgot_password", not_exists_markers=("can't find a user with that e-mail",),
                  intrusive=True),
    BrowserOracle("mapmytracks", "mapmytracks.com", "https://www.mapmytracks.com/auth/forgot",
                  "forgot_password", not_exists_markers=("was not found in the database",),
                  intrusive=True),
]


def xenforo_browser_oracles() -> list[BrowserOracle]:
    """XenForo login-error oracles for the browser tier — catches the instances
    that Cloudflare blocks over httpx. Non-intrusive (login with a junk password;
    no email sent). Hosts come from the shared XenForo list."""
    try:
        from .account_probe_ported import _XENFORO_FORUMS
    except Exception:  # noqa: BLE001
        return []
    return [
        BrowserOracle(
            id="xf_" + h.replace(".", "_").replace("-", "_"),
            domain=h, url=f"https://{h}/login/", flow="login_error",
            exists_markers=("password you entered is incorrect", "incorrect password"),
            not_exists_markers=("could not be found",),
            intrusive=False,
        )
        for h in _XENFORO_FORUMS
    ]


_EMAIL_SEL = ("input[type='email']", "input[name*='email' i]", "input[id*='email' i]",
              "input[name*='login' i]", "input[type='text']")
_SUBMIT_SEL = ("button[type='submit']", "input[type='submit']",
               "button:has-text('Next')", "button:has-text('Continue')",
               "button:has-text('Log in')", "button:has-text('Sign in')",
               "button:has-text('Reset')", "button:has-text('Send')")


async def _first_visible(page: Any, selectors: tuple[str, ...]) -> Any | None:
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            if await loc.is_visible(timeout=800):
                return loc
        except Exception:
            continue
    return None


async def _password_visible(page: Any) -> bool:
    try:
        return await page.locator("input[type='password']").first.is_visible(timeout=500)
    except Exception:
        return False


async def run_oracle(page: Any, oracle: BrowserOracle, email: str,
                     timeout_ms: int = 15000) -> str:
    """Run one oracle. Returns exists | not_exists | inconclusive | error."""
    try:
        await page.goto(oracle.url, wait_until="domcontentloaded", timeout=timeout_ms)
    except Exception:
        return "error"

    email_box = await _first_visible(page, _EMAIL_SEL)
    if email_box is None:
        return "inconclusive"

    pre_pw = await _password_visible(page)  # combined-form guard
    try:
        await email_box.fill(email, timeout=3000)
        # login-error flow (combined forms, e.g. XenForo): also submit a junk
        # password so the server returns "user not found" vs "incorrect password".
        if oracle.flow == "login_error":
            pw_box = await _first_visible(page, ("input[type='password']",))
            if pw_box is not None:
                await pw_box.fill("Wr0ngPass!x9q2z", timeout=2000)
        submit = await _first_visible(page, _SUBMIT_SEL)
        if submit is not None:
            await submit.click(timeout=3000)
        else:
            await email_box.press("Enter")
    except Exception:
        return "error"

    try:
        await page.wait_for_load_state("networkidle", timeout=6000)
    except Exception:
        pass
    try:
        text = (await page.content()).lower()
    except Exception:
        return "error"

    for m in oracle.exists_markers:
        if m.lower() in text:
            return "exists"
    for m in oracle.not_exists_markers:
        if m.lower() in text:
            return "not_exists"

    if oracle.flow == "email_first":
        if any(s in text for s in _SIGNUP_MARKERS):
            return "not_exists"
        post_pw = await _password_visible(page)
        if post_pw and not pre_pw:
            return "exists"  # password step appeared only after the email matched
    return "inconclusive"


async def probe_all(email: str, oracles: list[BrowserOracle], *,
                    concurrency: int = 4, headless: bool = True,
                    per_oracle_timeout_ms: int = 15000) -> dict[str, str]:
    """Run the given oracles in a headless browser. Returns {domain: verdict}.

    Best-effort: if Playwright (or its browser) isn't installed, raises
    ``RuntimeError`` so the caller can SKIP gracefully.
    """
    try:
        from playwright.async_api import async_playwright  # lazy: optional dep
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            "Playwright not installed — run `pip install mailaccess[browser] "
            "&& playwright install chromium`"
        ) from exc

    # Wrap with playwright-stealth so every page evades common bot fingerprinting
    # (navigator.webdriver, headless UA/plugins, etc.). Falls back to plain
    # Playwright if the stealth package isn't present.
    try:
        from playwright_stealth import Stealth
        pw_ctx = Stealth().use_async(async_playwright())
    except Exception:  # noqa: BLE001
        pw_ctx = async_playwright()

    results: dict[str, str] = {}
    sem = asyncio.Semaphore(concurrency)
    async with pw_ctx as pw:
        try:
            browser = await pw.chromium.launch(headless=headless)
        except Exception as exc:  # noqa: BLE001 - browser binary missing
            raise RuntimeError(f"Chromium launch failed ({exc}) — "
                               "run `playwright install chromium`") from exc

        async def _one(oracle: BrowserOracle) -> None:
            async with sem:
                context = await browser.new_context()
                page = await context.new_page()
                try:
                    results[oracle.domain] = await run_oracle(
                        page, oracle, email, per_oracle_timeout_ms)
                except Exception as exc:  # noqa: BLE001
                    _LOG.debug("browser oracle %s failed: %s", oracle.id, exc)
                    results[oracle.domain] = "error"
                finally:
                    await context.close()

        await asyncio.gather(*(_one(o) for o in oracles), return_exceptions=True)
        await browser.close()
    return results
