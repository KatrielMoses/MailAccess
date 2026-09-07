"""Generate empty truth-label stubs (gitignored) for each target to be filled in.

Reads eval/targets.yaml and writes eval/truth/<id>.<kind>.yaml for any target
that doesn't yet have a truth file. Existing files are never overwritten.
"""
from __future__ import annotations

from eval.harness.manifest import REPO_ROOT
from eval.harness.run_baseline import load_targets

TRUTH_DIR = REPO_ROOT / "eval" / "truth"


def _email_stub(tid: str, email: str) -> str:
    return f"""target_id: {tid}
email: {email}
kind: email

identity:
  real_name: unknown
  name_confidence: unknown
  verification: ""
  freshness: ""

accounts: []      # add discovered profiles here, each with verdict + evidence

breaches: []      # add breach/exposure claims here, each with verdict + evidence

notes: ""
"""


def _domain_stub(tid: str, domain: str) -> str:
    return f"""target_id: {tid}
domain: {domain}
kind: domain

email_pattern: unknown

catch_all: unknown
catch_all_verification: ""

known_contacts: []       # hand-verified known-good contacts; per-contact fields:
                         # name, title, email, title_source, verification,
                         # currently_deliverable, seniority, deliverability_outcome
                         # (see eval/truth/_schema/domain.example.yaml)

false_positive_emails: []

notes: ""
"""


def main() -> int:
    TRUTH_DIR.mkdir(parents=True, exist_ok=True)
    ts = load_targets()
    created = 0
    for t in ts.emails:
        p = TRUTH_DIR / f"{t.id}.email.yaml"
        if not p.exists():
            p.write_text(_email_stub(t.id, t.value), encoding="utf-8")
            created += 1
            print(f"created {p.relative_to(REPO_ROOT)}")
    for t in ts.domains:
        p = TRUTH_DIR / f"{t.id}.domain.yaml"
        if not p.exists():
            p.write_text(_domain_stub(t.id, t.value), encoding="utf-8")
            created += 1
            print(f"created {p.relative_to(REPO_ROOT)}")
    print(f"\n{created} stub(s) created. Fill them in per eval/truth/README.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
