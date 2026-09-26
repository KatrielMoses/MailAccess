"""Labeled fixtures for JEV per-task validation (eval.harness.jev_validation).

Each Case is (payload, label, extract, heuristic):
  - extract(verdict.output) -> the comparable value the task decides,
  - label            -> the correct value,
  - heuristic()      -> the baseline (today's fallback) answer, or None when the
                        current tool makes no such call (baseline scores 0 there).

Small, clear-cut cases — enough to separate a real win from a tie. Not exhaustive.
"""

from __future__ import annotations

from typing import Any

from backend.core.jev.tasks.demo import fallback_is_personal_name


def _demo() -> list:
    from eval.harness.jev_validation import Case
    cases = [
        ("Ada Lovelace", True), ("Grace Hopper", True), ("Priya Raman", True),
        ("acme-support", False), ("Our Leadership Team", False), ("noreply", False),
    ]
    return [
        Case({"text": t}, lbl, lambda o: o.is_personal_name,
             (lambda t=t: fallback_is_personal_name(t)))
        for t, lbl in cases
    ]


def _profile(platform: str, **kw: Any) -> dict[str, Any]:
    return {"platform": platform, **kw}


def _same_person() -> list:
    from eval.harness.jev_validation import Case
    # heuristic today over-merges an ambiguous pair → baseline answer "yes".
    hb = lambda: "yes"  # noqa: E731
    cases = [
        # Same rare handle + same name → yes.
        ({"a": _profile("github", username="zephqx", display_name="Zephyrine Quill"),
          "b": _profile("gitlab", username="zephqx", display_name="Zephyrine Quill"),
          "avatar_match": False, "heuristic_signals": ["shared_username"]}, "yes"),
        # Same username, conflicting names → different people (not a merge).
        ({"a": _profile("github", username="nightowl", display_name="Priya Raman"),
          "b": _profile("gitlab", username="nightowl", display_name="Tom Becker"),
          "avatar_match": False, "heuristic_signals": ["shared_username"]}, "no"),
        # Shared common first name only → not the same person.
        ({"a": _profile("reddit", display_name="John Smith", bio="Gamer in Ohio"),
          "b": _profile("mastodon", display_name="John Smith", bio="Chef in Paris"),
          "avatar_match": False, "heuristic_signals": ["shared_display_name"]}, "no"),
    ]
    return [Case(p, lbl, lambda o: o.same_person, hb) for p, lbl in cases]


def _name_reconcile() -> list:
    from eval.harness.jev_validation import Case
    payload = {
        "email_localpart": "rsmith",
        "candidates": [
            {"name": "Bob Smith", "sources": ["github_profile"], "weight": 0.6},
            {"name": "Robert Smith", "sources": ["gravatar"], "weight": 0.5},
            {"name": "Deploy Pipeline", "sources": ["hackernews"], "weight": 0.35},
        ],
    }
    # Correct: drop the junk (index 2). Baseline today drops nothing.
    return [Case(payload, [2], lambda o: sorted(o.drop), (lambda: []))]


def _bio_extract() -> list:
    from eval.harness.jev_validation import Case
    cases = [
        ({"bio": "Staff engineer at Northwind Labs, based in Leeds."}, "person"),
        ({"bio": "Official account of Northwind Labs — enterprise security software."},
         "organization"),
    ]
    return [Case(p, lbl, lambda o: o.entity_type, None) for p, lbl in cases]


def _reply_classify() -> list:
    from eval.harness.jev_validation import Case
    hb = lambda: "unknown"  # noqa: E731  (the fast matcher missed these → inconclusive)
    cases = [
        ({"protocol": "smtp_rcpt", "code": 550, "text": "5.1.1 recipient rejected: no mailbox"},
         "no_such_user"),
        ({"protocol": "smtp_rcpt", "code": 250, "text": "2.1.5 recipient ok"}, "exists"),
        ({"protocol": "smtp_rcpt", "code": 451, "text": "greylisted, try again later"},
         "temporary"),
        ({"protocol": "imap_login", "code": None, "text": "NO [AUTHENTICATIONFAILED] bad password"},
         "exists"),
    ]
    return [Case(p, lbl, lambda o: o.verdict, hb) for p, lbl in cases]


def _catchall_judge() -> list:
    from eval.harness.jev_validation import Case
    hb = lambda: "unclear"  # noqa: E731
    cases = [
        ({"domain": "x.com", "control_probe": {"code": 250, "text": "2.1.5 ok, accepted"}},
         "yes"),
        ({"domain": "x.com", "control_probe": {"code": 550, "text": "no such user"}}, "no"),
    ]
    return [Case(p, lbl, lambda o: o.catch_all, hb) for p, lbl in cases]


def _m365() -> list:
    from eval.harness.jev_validation import Case
    hb = lambda: "unknown"  # noqa: E731
    cases = [
        ({"signals": {"if_exists_result": 0, "throttle_status": 0}}, "exists"),
        ({"signals": {"if_exists_result": 1, "throttle_status": 0}}, "not_exists"),
        ({"signals": {"throttle_status": 2}}, "unknown"),
    ]
    return [Case(p, lbl, lambda o: o.mailbox, hb) for p, lbl in cases]


def _person_filter() -> list:
    from backend.core.name_classifier import classify_name
    from eval.harness.jev_validation import Case

    def hb(cand: str):
        return "yes" if classify_name(cand).is_person else "no"

    cases = [
        ({"candidate": "Our Leadership Team", "context": "nav header", "source": "company_page"},
         "no"),
        ({"candidate": "Dana Whitfield", "context": "VP Sales", "source": "linkedin_search"},
         "yes"),
        ({"candidate": "Read More", "context": "footer link", "source": "company_page"}, "no"),
    ]
    return [Case(p, lbl, lambda o: o.is_person_name, (lambda c=p["candidate"]: hb(c)))
            for p, lbl in cases]


def _title_normalize() -> list:
    from backend.core.seniority_classifier import classify_title
    from eval.harness.jev_validation import Case

    def hb(title: str):
        return classify_title(title).band

    cases = [
        ({"title": "VP of Engineering"}, "vp"),
        ({"title": "Directeur Général"}, "c-level"),          # French CEO — heuristic misses
        ({"title": "Software Engineer II"}, "ic"),
    ]
    return [Case(p, lbl, lambda o: o.seniority_bucket, (lambda t=p["title"]: hb(t)))
            for p, lbl in cases]


def _person_dedupe() -> list:
    from eval.harness.jev_validation import Case
    hb = lambda: "no"  # noqa: E731  (today keeps near-duplicates separate)
    cases = [
        ({"a": {"name": "John Smith"}, "b": {"name": "Jon Smith"}}, "yes"),
        ({"a": {"name": "Jane Doe"}, "b": {"name": "John Roe"}}, "no"),
    ]
    return [Case(p, lbl, lambda o: o.same_person, hb) for p, lbl in cases]


def _company_resolve() -> list:
    from eval.harness.jev_validation import Case
    payload = {"query": "Acme", "candidates": [
        {"name": "Acme Scam LLC", "domain": "acme-scam.example", "employees": 5},
        {"name": "Acme Corporation", "domain": "acme.example", "employees": 900},
    ]}
    return [Case(payload, 1, lambda o: o.chosen_index, None)]


def _platform_select() -> list:
    from eval.harness.jev_validation import Case
    payload = {"name": "Li Wei", "email_localpart": "liwei", "wave_cap": 2, "candidates": [
        {"id": "github", "category": "dev", "rank": 1},
        {"id": "weibo", "category": "social", "region": "cn", "rank": 2},
        {"id": "vk", "category": "social", "region": "ru", "rank": 3},
    ]}
    # A CN subject → weibo should be among the selected. Loose label: weibo selected.
    return [Case(payload, True, lambda o: "weibo" in o.ordered_platform_ids, None)]


def _role_system() -> list:
    from eval.harness.jev_validation import Case
    hb = lambda: "person"  # noqa: E731  (non-obvious → today treats as a person)
    cases = [
        ({"localpart": "orders-team", "domain": "acme.com"}, "role_or_shared"),
        ({"localpart": "j.whitfield", "domain": "acme.com"}, "person"),
        ({"localpart": "cs-emea", "domain": "acme.com", "seen_role": "shared inbox"},
         "role_or_shared"),
    ]
    return [Case(p, lbl, lambda o: o.kind, hb) for p, lbl in cases]


def _common_name() -> list:
    from eval.harness.jev_validation import Case
    hb = lambda: "unclear"  # noqa: E731
    cases = [
        ({"name": "James Smith", "subject_email": "jsmith@acme.com",
          "evidence": ["github_profile", "gravatar", "linkedin_snippet"]}, "is_subject"),
        ({"name": "James Smith", "subject_email": "jsmith@acme.com",
          "evidence": ["reddit"]}, "coincidental"),
    ]
    return [Case(p, lbl, lambda o: o.relation, hb) for p, lbl in cases]


def _breach_canon() -> list:
    from eval.harness.jev_validation import Case
    hb = lambda: "no"  # noqa: E731
    cases = [
        ({"name_a": "LinkedIn Scrape 2021", "name_b": "linkedin_2021"}, "yes"),
        ({"name_a": "Adobe 2013", "name_b": "Dropbox 2012"}, "no"),
    ]
    return [Case(p, lbl, lambda o: o.same_breach, hb) for p, lbl in cases]


# Generative tasks: unsupported on Ollaya (no decomposer); measured on jev only.
def _query_generate() -> list:
    from eval.harness.jev_validation import Case
    payload = {"engine": "ddg", "max_queries": 3, "domain": "acme.com"}
    return [Case(payload, True, lambda o: len(o.queries) > 0, None)]


def _brief_wording() -> list:
    from eval.harness.jev_validation import Case
    payload = {"risk_level": "HIGH", "subject_email": "a@acme.com",
               "next_action": "Reset the acme.com password.",
               "findings": [{"severity": "high", "text": "Adobe 2013 breach exposure."}]}
    return [Case(payload, 1, lambda o: len(o.finding_lines), None)]


def _finding_correlation() -> list:
    from eval.harness.jev_validation import Case
    payload = {"subject_email": "a@acme.com",
               "findings": [{"id": "f0", "type": "hibp", "summary": "Adobe 2013 breach"}],
               "max_leads": 3}
    return [Case(payload, True, lambda o: len(o.leads) >= 0, None)]


FIXTURES: dict[str, list] = {
    "demo.plausible_personal_name": _demo(),
    "identity.same_person": _same_person(),
    "identity.name_reconcile": _name_reconcile(),
    "identity.bio_extract": _bio_extract(),
    "verify.reply_classify": _reply_classify(),
    "verify.catchall_judge": _catchall_judge(),
    "verify.m365_signal_read": _m365(),
    "roster.person_filter": _person_filter(),
    "roster.title_normalize": _title_normalize(),
    "roster.person_dedupe": _person_dedupe(),
    "roster.company_resolve": _company_resolve(),
    "reach.platform_select": _platform_select(),
    "reach.query_generate": _query_generate(),
    "signal.role_system_classify": _role_system(),
    "signal.common_name_context": _common_name(),
    "signal.breach_canonicalize": _breach_canon(),
    "narrative.brief_wording": _brief_wording(),
    "narrative.finding_correlation": _finding_correlation(),
}
