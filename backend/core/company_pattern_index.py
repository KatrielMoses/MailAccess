"""0.16.0 Phase 2 — company email-pattern applier (offline Layer A).

Given a person's ``full_name`` and their employer ``domain``, return **one**
graded, *unverified* email address derived from the corpus-learned pattern for
that domain — or ``None`` when we can't (domain not indexed, name unparseable).
This is the productionised form of the validated reference
(``data/email_pattern_index_reference.py``), which captured 96.9% of the
achievable ceiling on 5,000 real verified pairs.

Contract (the #1 rule). :func:`_index_norm` is **byte-identical** to
``data/pattern_pipeline.sql``'s ``norm()`` — the macro that built the index —
so lookups on the applier side land on the same normalized tokens the generator
used. We deliberately do **not** reuse
:func:`email_pattern_generator._name_parts`: that path romanises via
``unidecode`` (a different contract) and would silently drift the applier off
the index for non-Latin names. The round-trip gate (:func:`roundtrip_gate`) is
the arbiter that keeps the two in step.

Honesty discipline (0.15.0 lineage). Every result is ``verification =
"unverified"`` — a *likely* candidate, never confirmed. Phase 6 (an M365 oracle
or a catch-all/dedup upgrade) may later promote it; Phase 2 only emits correct,
provenance-tagged metadata so nothing downstream can mistake a guess for a
confirmed address. The confidence flows through the ONE canonical scorer
(:mod:`email_confidence`) and is capped below the CONFIRMED band — an unverified
inference can never, on its own, present as CONFIRMED.
"""

from __future__ import annotations

import gzip
import json
import logging
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from .email_confidence import (
    ConfidenceLabel,
    compute_confidence_breakdown,
)

logger = logging.getLogger(__name__)

#: Canonical source-type key for a company-pattern-index candidate. Registered
#: in :data:`email_confidence.SOURCE_WEIGHTS` / ``SOURCE_CLASS`` so the signal
#: lives in the one canonical scorer rather than a parallel confidence system.
SOURCE_TYPE = "company_pattern_index"

#: Schema tag asserted on load — a mismatch is a packaging bug, not a soft miss.
SCHEMA = "company-patterns/1"

#: Version of the SHARED normalization + tokenization + role-classification
#: contract (Brief C #6). Bumped together whenever :func:`_index_norm`,
#: :func:`_first_last`, :func:`_templates`, or :func:`_role_of` change. The build
#: generator uses the SAME implementations (exposed as DuckDB UDFs via
#: :func:`register_normalization_udfs`), so applier and generator cannot drift; the
#: version is recorded in the confidence basis so a stored candidate names the exact
#: transform that produced it.
NORMALIZATION_VERSION = "norm/1"

#: The confidence-basis string stamped onto every candidate's provenance so the
#: numerator/denominator semantics and the normalization version travel with it.
CONFIDENCE_BASIS = f"support_n/considered_n; {NORMALIZATION_VERSION}"

#: Valid pattern-template ids and mail-provider tags — used by record validation.
_VALID_PATTERN_IDS = frozenset(f"P{i:02d}" for i in range(1, 16))
_VALID_MX = frozenset({"m365", "google", "other"})
#: Confidence must equal support_n/considered_n within this tolerance (the index
#: rounds to 4 dp; real records deviate ≤5e-5). A larger gap is a malformed record.
_CONFIDENCE_RATIO_TOL = 0.0000500001

_INDEX_PATH = Path(__file__).resolve().parents[2] / "data" / "company_patterns.json.gz"


class MalformedPatternRecord(ValueError):
    """A selected domain/role record fails integrity validation (Brief C R8).

    Raised from :meth:`CompanyPatternIndex.apply` so the governed generator counts
    it as an ``apply_error`` (an accounted ERROR that never sprays) — a malformed
    indexed record must not silently regain high confidence or trigger ungoverned
    spraying, and it is distinct from a legitimate abstention (``apply`` -> ``None``
    for an unplaceable name).
    """


# --------------------------------------------------------------------------- #
# Normalization — byte-identical to pattern_pipeline.sql norm().
# --------------------------------------------------------------------------- #
# strip_accents handles combining diacritics (José -> jose); the explicit folds
# cover the common non-combining letters unidecode/DuckDB would otherwise map
# (ø ł ß æ œ đ ð). MUST stay in lockstep with the SQL macro — see roundtrip_gate.
_EXPLICIT_FOLDS = {
    "ø": "o",
    "ł": "l",
    "ß": "ss",
    "æ": "ae",
    "œ": "oe",
    "đ": "d",
    "ð": "d",
}


def _index_norm(s: str | None) -> str:
    """lower -> explicit folds -> NFKD drop combining marks (Mn) -> keep [a-z0-9]."""
    if not s:
        return ""
    s = s.lower()
    for a, b in _EXPLICIT_FOLDS.items():
        s = s.replace(a, b)
    s = "".join(
        c for c in unicodedata.normalize("NFKD", s) if unicodedata.category(c) != "Mn"
    )
    return re.sub(r"[^a-z0-9]", "", s)


def _first_last(full_name: str | None) -> tuple[str, str] | None:
    """Split a display name into normalized ``(first, last)`` for index lookup.

    Whitespace-tokenize (matching the SQL's ``str_split_regex(_, '\\s+')``),
    normalize the first and last tokens, and require both to survive. Returns
    ``None`` when the name is empty or normalizes away to nothing (e.g. a purely
    non-Latin name that the index generator also could not have kept).
    """
    toks = [t for t in re.split(r"\s+", (full_name or "").strip()) if t]
    if not toks:
        return None
    first, last = _index_norm(toks[0]), _index_norm(toks[-1])
    if not first or not last:
        return None
    return first, last


def _templates(first: str, last: str) -> dict[str, str]:
    """The P01–P15 localpart templates, identical to pattern_pipeline.sql."""
    fi, li = first[:1], last[:1]
    return {
        "P01": first,
        "P02": last,
        "P03": first + last,
        "P04": first + "." + last,
        "P05": fi + last,
        "P06": fi + "." + last,
        "P07": first + li,
        "P08": first + "." + li,
        "P09": first + "_" + last,
        "P10": first + "-" + last,
        "P11": last + first,
        "P12": last + "." + first,
        "P13": last + fi,
        "P14": last + "." + fi,
        "P15": fi + li,
    }


# Coarse role class from a title (fallback to seniority) — byte-identical to
# pattern_pipeline.sql role_of(). Drives per-domain role overrides (e.g. an org
# whose ICs use {first}.{last} but whose executives use {f}.{last}).
_ROLE_RULES: tuple[tuple[str, str], ...] = (
    (
        "engineering",
        r"engineer|developer|software|devops|sre|architect|programmer|data scien|"
        r"machine learning|backend|frontend|full stack",
    ),
    (
        "sales",
        r"sales|account exec|business develop|account manager|revenue|\bsdr\b|\bbdr\b",
    ),
    (
        "marketing",
        r"market|brand|growth|\bseo\b|content|demand gen|communicat|social media",
    ),
    (
        "product",
        r"product manager|product owner|product lead|head of product|chief product",
    ),
    (
        "finance",
        r"financ|accountant|controller|treasur|\bcfo\b|bookkeep|audit|payroll",
    ),
    (
        "hr",
        r"human resource|recruit|talent|people ops|\bhr\b|people & culture",
    ),
    (
        "support",
        r"support|customer success|customer care|help desk|service desk|technical support",
    ),
    (
        "executive",
        r"\bceo\b|\bcto\b|\bcoo\b|\bcfo\b|\bcmo\b|\bciso\b|chief|founder|president|"
        r"owner|partner|managing director|\bvp\b|vice president|head of|director",
    ),
)


def _role_of(title: str | None, seniority: str | None) -> str:
    t = (title or "").lower()
    if t:
        for role, pat in _ROLE_RULES:
            if re.search(pat, t):
                return role
    s = (seniority or "").lower()
    if s and re.search(r"c_suite|owner|partner|founder|vp|director", s):
        return "executive"
    return "other"


def _wilson_lb(p: float, n: int, z: float = 1.96) -> float:
    """Support-aware lower bound: thin support pulls the point estimate down.

    A 3-support/0.5 domain scores well below a 580-support/0.9 one even when the
    raw ``confidence`` looks similar — so ``applied_confidence`` is honest about
    how much evidence backs the pattern.
    """
    if n <= 0:
        return 0.0
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * ((p * (1 - p) + z * z / (4 * n)) / n) ** 0.5
    return max(0.0, (centre - margin) / denom)


@dataclass
class PatternEmail:
    """One graded, unverified email derived from the company-pattern index."""

    email: str
    pattern_id: str  # P01..P15
    support_n: int  # verified samples backing the chosen pattern
    confidence: float  # raw domain/role confidence (dominant-follow rate)
    applied_confidence: float  # support-aware Wilson lower bound of ``confidence``
    mx: str  # m365 | google | other — drives the Phase-6 oracle (only m365)
    role_used: str | None  # role name if a role override applied, else None
    provenance: str
    verification: str = "unverified"  # NEVER confirmed/verified in Phase 2
    # Root C — the TRUE denominator behind ``confidence``: all qualifying personal
    # mailboxes the generator considered for this domain (matched + unmatched +
    # ambiguous), not just the pattern-matched rows. Present only once the index is
    # regenerated with ``support_considered_n`` (see docs/company-pattern-index-refresh);
    # ``None`` on a legacy index. When present it is Wilson's ``n`` so a domain where
    # 10/100 mailboxes follow the dominant pattern is not sold as confidence 1.0.
    considered_n: int | None = None
    confidence_basis: str = CONFIDENCE_BASIS


def _content_digest(raw: dict) -> str:
    """A short, stable content fingerprint of the whole loaded artifact (Brief C R6).

    Canonical (sorted-key, compact) JSON of the entire decompressed index — every
    domain record, every role override, every ``mx`` tag, and ``_meta`` — hashed
    with SHA-256. Stable across re-compression (it hashes content, not gzip bytes)
    yet changes on ANY record or MX change, so the cache identity tracks exactly
    what generation and verification depend on.
    """
    import hashlib

    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _is_pos_int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v > 0


def _is_nonneg_int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _is_finite_number(v: object) -> bool:
    import math

    return (
        isinstance(v, int | float)
        and not isinstance(v, bool)
        and math.isfinite(float(v))
    )


def _validated_record_fields(
    rec: object, *, domain: str, role_used: str | None, require_denominator: bool = False
) -> tuple[str, float, int, int | None, bool]:
    """Validate a SELECTED domain/role record and return its calculation inputs.

    Returns ``(pattern, confidence, support_n, considered_n_or_None, legacy)`` where
    a non-``None`` ``considered_n`` is the record's OWN validated denominator and
    ``legacy`` marks a record with no denominator (Wilson falls back to the
    record's own ``support_n``). Raises :class:`MalformedPatternRecord` for any hard
    integrity failure (Brief C item 2): a bad template id, non-finite/out-of-range
    confidence, a non-integral/negative support, a non-positive denominator, a
    support greater than the denominator, or a confidence inconsistent with
    ``support_n/considered_n`` beyond :data:`_CONFIDENCE_RATIO_TOL`.

    The label ``role_used`` is only used to make the telemetry/exception message name
    which record failed (the domain record vs. a role override).
    """
    where = f"{domain}[{role_used}]" if role_used else domain
    if not isinstance(rec, dict):
        raise MalformedPatternRecord(f"{where}: record is not an object")

    pat = rec.get("pattern")
    if pat not in _VALID_PATTERN_IDS:
        raise MalformedPatternRecord(f"{where}: invalid pattern id {pat!r}")

    conf = rec.get("confidence")
    if not _is_finite_number(conf) or not (0.0 <= float(conf) <= 1.0):
        raise MalformedPatternRecord(f"{where}: invalid confidence {conf!r}")

    support = rec.get("support_n")
    if not _is_pos_int(support):
        raise MalformedPatternRecord(f"{where}: invalid support_n {support!r}")
    if require_denominator and (support < 2 or float(conf) < (0.6 if role_used else 0.5)):
        raise MalformedPatternRecord(f"{where}: record is below the emission threshold")

    considered = rec.get("considered_n")
    if considered is None:
        if require_denominator:
            raise MalformedPatternRecord(f"{where}: current artifact lacks considered_n")
        # Legacy schema (no denominator). NEVER borrow another record's denominator —
        # fall back to this record's own support as Wilson's n.
        return pat, float(conf), int(support), None, True

    if not _is_pos_int(considered):
        raise MalformedPatternRecord(f"{where}: invalid considered_n {considered!r}")
    if int(support) > int(considered):
        raise MalformedPatternRecord(
            f"{where}: support_n {support} exceeds considered_n {considered}"
        )
    ratio = int(support) / int(considered)
    if abs(float(conf) - ratio) > _CONFIDENCE_RATIO_TOL:
        raise MalformedPatternRecord(
            f"{where}: confidence {conf} inconsistent with support/considered ratio "
            f"{ratio:.6f} (tol {_CONFIDENCE_RATIO_TOL})"
        )
    return pat, float(conf), int(support), int(considered), False


# --------------------------------------------------------------------------- #
# Lazy, fail-soft, module-level singleton.
# --------------------------------------------------------------------------- #
class CompanyPatternIndex:
    """In-memory view of ``data/company_patterns.json.gz`` (schema
    ``company-patterns/1``).

    The dict is ~377K domains / ~100 MB resident, so it is loaded on first use
    (see :func:`get_index`) rather than at import — this matters for the spawned
    investigate backend, which must not pay the cost unless the feature is used.
    """

    def __init__(self, path: str | Path = _INDEX_PATH):
        self.path = Path(path)
        self.meta: dict = {}
        self._idx: dict[str, dict] = {}
        self.available = False
        try:
            with gzip.open(self.path, "rt", encoding="utf-8") as fh:
                raw = json.load(fh)
        except FileNotFoundError:
            # Fail soft: the feature simply no-ops if the index is not shipped.
            logger.warning(
                "company_pattern_index: index file not found at %s; applier disabled",
                self.path,
            )
            return
        except (OSError, ValueError):
            logger.exception(
                "company_pattern_index: failed to read %s; applier disabled", self.path
            )
            return
        self.meta = raw.get("_meta", {})
        # A schema mismatch is a packaging/build error we WANT to surface loudly,
        # unlike a missing file (a legitimate not-shipped state).
        assert self.meta.get("schema") == SCHEMA, (
            f"company_pattern_index: schema mismatch "
            f"(got {self.meta.get('schema')!r}, want {SCHEMA!r})"
        )
        self._idx = {k: v for k, v in raw.items() if k != "_meta"}
        # Root/Brief C R6 — the cache identity is a CONTENT digest of the exact
        # loaded artifact (every domain/role record AND the MX tags AND the meta),
        # not a hash of a few hand-picked ``_meta`` fields. So any generation- or
        # verification-affecting change — a pattern edit, a support/considered edit,
        # or an MX-only change — changes the identity and invalidates caches, while
        # two artifacts that share ``generated_at``/``domains_emitted`` but differ in
        # records get DIFFERENT identities. Computed once here and bound to this
        # loaded instance (the singleton is load-once / restart-only), so the
        # advertised identity always matches the records in use.
        self.content_digest = _content_digest(raw)
        self.available = True

    def is_indexed(self, domain: str) -> bool:
        """Whether ``domain`` has a record in the index (membership, pre-apply).

        Root E — the round-trip gate counts *membership* (in-index domains) as the
        abstention denominator: a name that abstains on an indexed domain must be
        counted, not silently dropped, so a mostly-abstaining sample can never
        certify as full capture.
        """
        dom = (domain or "").strip().lower().removeprefix("www.")
        return dom in self._idx

    def apply(
        self,
        full_name: str,
        domain: str,
        title: str | None = None,
        seniority: str | None = None,
    ) -> PatternEmail | None:
        """Return ONE unverified :class:`PatternEmail` for ``(full_name, domain)``.

        Returns ``None`` — and the caller falls back to live inference — when:
        the domain is not indexed; the name is unparseable / normalizes to empty
        (e.g. a non-Latin name the index generator also dropped); or the name is
        a single token whose one part cannot satisfy the domain's pattern (a
        pattern that needs a distinct first *and* last).
        """
        dom = (domain or "").strip().lower().removeprefix("www.")
        rec = self._idx.get(dom)
        if rec is None:
            return None
        fl = _first_last(full_name)
        if not fl:
            return None
        first, last = fl
        # Root E — preserve the token count so a true single-token mononym
        # ("Cher") is distinguished from two DISTINCT tokens that merely normalize
        # equal ("Li Li" -> first==last=="li"). The former can only satisfy the
        # single-part patterns; the latter is a real two-name person for whom a
        # distinct-name pattern (li.li@) is correct.
        is_mononym = len([t for t in re.split(r"\s+", (full_name or "").strip()) if t]) < 2

        # Brief C R8 — select the domain record or a role override, then VALIDATE
        # the SELECTED record on its OWN numerator/denominator. A role override that
        # lacks its own ``considered_n`` NEVER borrows the domain's denominator (that
        # let a 3-support override score off a 1,000,000-sample domain); it falls
        # back to the role's OWN support as Wilson's n, tagged legacy. A genuinely
        # malformed selected record (bad template, support>considered, confidence
        # inconsistent with the ratio, nonfinite values) raises
        # :class:`MalformedPatternRecord` → the governed caller accounts it as an
        # ``apply_error`` and never sprays; it can't silently regain high confidence.
        role = _role_of(title, seniority)
        overrides = rec.get("role_overrides") or {}
        if role in overrides:
            selected, role_used = overrides[role], role
        else:
            selected, role_used = rec, None

        pat, conf, support, considered, legacy_denominator = _validated_record_fields(
            selected, domain=dom, role_used=role_used,
            require_denominator="considered_n" in str(
                getattr(self, "meta", {}).get("confidence_basis", "")
            ) or bool(getattr(self, "meta", {}).get("normalization_version")),
        )
        # ``mx`` lives on the DOMAIN record (it drives the Phase-6 oracle); validate
        # it there regardless of which record supplied the pattern.
        mx = rec.get("mx", "other")
        if mx not in _VALID_MX:
            raise MalformedPatternRecord(f"{dom}: invalid mx {mx!r}")

        # A true single-token mononym ("Cher") yields first == last from ONE token.
        # Only the single-part patterns P01 ({first}) and P02 ({last}) are
        # meaningful then; every distinct-name pattern would emit a doubled
        # localpart (e.g. "cher.cher") that is almost certainly wrong, so we return
        # None and let the caller fall back to live inference. Two DISTINCT tokens
        # that normalize equal ("Li Li") are NOT a mononym — li.li@ is correct — so
        # they are allowed through.
        if is_mononym and first == last and pat not in ("P01", "P02"):
            return None
        localpart = _templates(first, last).get(pat)
        if not localpart:
            return None

        # Wilson's n is the selected record's OWN considered denominator when valid,
        # else the selected record's OWN support (legacy fallback) — never another
        # record's denominator. So a thin-dominant / mixed-pattern record is pulled
        # down instead of scoring like a unanimous one.
        wilson_n = considered if considered is not None else support
        applied = round(_wilson_lb(conf, wilson_n), 4)
        basis = CONFIDENCE_BASIS + (
            "; legacy-denominator=support_n" if legacy_denominator else ""
        )
        basis += "; artifact-normalization=" + str(
            getattr(self, "meta", {}).get("normalization_version", "unversioned SQL")
        )
        denom_str = str(considered) if considered is not None else f"{support}(legacy)"
        return PatternEmail(
            email=f"{localpart}@{dom}",
            pattern_id=pat,
            support_n=support,
            confidence=conf,
            applied_confidence=applied,
            considered_n=considered,
            confidence_basis=basis,
            mx=mx,
            role_used=role_used,
            provenance=(
                f"company email pattern ({pat}, {support}/{denom_str} samples, "
                f"conf {conf}; {basis})"
            ),
        )


_SINGLETON: CompanyPatternIndex | None = None


def get_index() -> CompanyPatternIndex:
    """Return the lazily-constructed, cached module-level index singleton."""
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = CompanyPatternIndex()
    return _SINGLETON


def index_version() -> str | None:
    """The loaded index's CONTENT identity (Root D / Brief C R6 — cache signature).

    Returns the :attr:`CompanyPatternIndex.content_digest` of the exact loaded
    artifact — a SHA-256 over every domain/role record, every ``mx`` tag and the
    meta — so a rebuilt/refreshed index (or an MX-only re-tag, or any pattern /
    support / considered edit) changes the fingerprint and a harvest cached against
    the old index is invalidated, while a bare ``generated_at`` bump is no longer
    the only thing that moves it. ``None`` when the index is not available. Uses the
    cached singleton — free when the harvest already loaded it; callers gate on the
    feature flag so a flag-off run never pays to load the index just for this.
    """
    idx = get_index()
    if not idx.available:
        return None
    return idx.content_digest


def apply(
    full_name: str,
    domain: str,
    title: str | None = None,
    seniority: str | None = None,
) -> PatternEmail | None:
    """Primary one-email entry point (Phase 4 wires this into harvest/pivot/leads).

    A thin pass-through to the cached singleton's :meth:`CompanyPatternIndex.apply`.
    Pure and idempotent for a given ``(full_name, domain, title, seniority)``.
    """
    return get_index().apply(full_name, domain, title, seniority)


def confidence_label(pe: PatternEmail) -> ConfidenceLabel:
    """Grade a :class:`PatternEmail` through the ONE canonical scorer.

    Feeds ``applied_confidence`` as the per-candidate source-confidence for the
    :data:`SOURCE_TYPE` source (no parallel scorer), then enforces the honesty
    cap: an unverified inference is downgraded out of the CONFIRMED band to
    LIKELY, so a pattern guess — however well-supported — never presents as a
    confirmed address (0.15.0 ``is_confirmed_account_hit`` discipline).
    """
    # Root B — the honesty cap now lives in the ONE canonical scorer
    # (``cap_unverified_inference``), so an unverified inference is downgraded out
    # of the CONFIRMED band to LIKELY the same way here, in aggregation, in export
    # and in ``read_leads``. This adapter no longer owns a private cap.
    return compute_confidence_breakdown(
        [SOURCE_TYPE],
        source_confidence={SOURCE_TYPE: pe.applied_confidence},
        cap_unverified_inference=True,
    )


# --------------------------------------------------------------------------- #
# Brief C #6 — the ONE shared transform, exposed for the build generator.
#
# The applier normalization/tokenization/role rules ARE the canonical, versioned
# transform (:data:`NORMALIZATION_VERSION`). The production index generator builds
# by registering these exact callables as DuckDB UDFs via
# :func:`register_normalization_udfs`, so the SQL build and the Python applier can
# never drift — they run the same code. The executable differential
# (``tests/test_pattern_normalization_differential.py``) drives these UDFs through
# real SQL and compares to the applier; ``strip_accents`` (NFD accent strip) is NOT
# used — :func:`_index_norm` applies the specified NFKD compatibility decomposition
# (so ``ﬃ``->``ffi``, fullwidth ``Ａ１``->``a1``, NBSP folds), then drops combining
# marks.
# --------------------------------------------------------------------------- #


def index_norm(s: str | None) -> str:
    """Public alias of the versioned normalization transform (Brief C #6)."""
    return _index_norm(s)


def first_last(full_name: str | None) -> tuple[str, str] | None:
    """Public alias of the versioned name tokenizer (Brief C #6)."""
    return _first_last(full_name)


def role_of(title: str | None, seniority: str | None = None) -> str:
    """Public alias of the versioned role classifier (Brief C #6)."""
    return _role_of(title, seniority)


def localpart_for(pattern_id: str, first: str, last: str) -> str | None:
    """The localpart the versioned templates produce for ``pattern_id`` (Brief C #6)."""
    return _templates(first, last).get(pattern_id)


def _udf_norm(s: str | None) -> str:
    return _index_norm(s)


def _udf_name_first(name: str | None) -> str:
    fl = _first_last(name)
    return fl[0] if fl else ""


def _udf_name_last(name: str | None) -> str:
    fl = _first_last(name)
    return fl[1] if fl else ""


def _udf_role_of(title: str | None, seniority: str | None) -> str:
    return _role_of(title, seniority)


def _udf_name_is_mononym(name: str | None) -> bool:
    return len((name or "").split()) < 2


def _udf_index_domain(domain: str | None) -> str:
    return (domain or "").strip().lower().removeprefix("www.")


def _udf_localpart(pattern_id: str | None, first: str | None, last: str | None) -> str:
    return localpart_for(pattern_id or "", first or "", last or "") or ""


def register_normalization_udfs(con: object) -> str:
    """Register the shared transform as DuckDB UDFs on ``con`` (Brief C #6).

    The production generator (``pattern_pipeline.sql``, in the maintainer's private
    build folder — see ``docs/company-pattern-index-refresh.md``) MUST create its
    normalization AND tokenization via THIS function so the build and the applier
    share ONE implementation and cannot drift. It registers:

    * ``norm(text) -> text`` — :func:`_index_norm` (NFKD compatibility decomposition
      + drop combining marks + keep ``[a-z0-9]``);
    * ``name_first(text) / name_last(text) -> text`` — the normalized first/last
      tokens from :func:`_first_last` (empty string = abstain). Tokenization is a
      UDF, not an in-SQL ``\\s+`` split, because SQL regex whitespace and Python's
      ``re`` disagree on characters like NBSP — the build must tokenize with the
      applier's exact logic;
    * ``role_of(title, seniority) -> text`` — :func:`_role_of`;
    * ``localpart(pattern_id, first, last) -> text`` — :func:`localpart_for`.

    All are registered with ``null_handling='special'`` so a NULL argument reaches
    the Python callable (which handles ``None``) instead of DuckDB short-circuiting
    to NULL — otherwise ``role_of(title, NULL seniority)`` would silently return NULL
    and every null-seniority corpus row would misclassify at build time.

    The UDFs wrap module-level, type-annotated callables so DuckDB can infer the
    signatures. Returns :data:`NORMALIZATION_VERSION` so the build stamps the exact
    transform version into ``_meta``. Requires the optional ``duckdb`` build
    dependency; importing it is the caller's responsibility (this only registers).
    """
    kw = {"null_handling": "special"}
    con.create_function("norm", _udf_norm, **kw)  # type: ignore[attr-defined]
    con.create_function("name_first", _udf_name_first, **kw)  # type: ignore[attr-defined]
    con.create_function("name_last", _udf_name_last, **kw)  # type: ignore[attr-defined]
    con.create_function("role_of", _udf_role_of, **kw)  # type: ignore[attr-defined]
    con.create_function("name_is_mononym", _udf_name_is_mononym, **kw)  # type: ignore[attr-defined]
    con.create_function("index_domain", _udf_index_domain, **kw)  # type: ignore[attr-defined]
    con.create_function("localpart", _udf_localpart, **kw)  # type: ignore[attr-defined]
    return NORMALIZATION_VERSION


# --------------------------------------------------------------------------- #
# Maintainer regression gate — the symmetry enforcer.
# --------------------------------------------------------------------------- #
def roundtrip_gate(
    sample_csv: str | Path,
    index_path: str | Path = _INDEX_PATH,
    min_capture: float = 0.95,
    max_abstention: float = 0.5,
) -> dict[str, float]:
    """Apply the index to a labelled sample and assert applier↔generator symmetry.

    Runs against a labelled PII validation sample (``validation_sample.csv``,
    which lives in the maintainer's private ``email-pattern-index/`` folder,
    outside the repo — treat like the corpus, never commit). ``sample_csv`` is a
    required argument with no repo-path default, so the caller points it at their
    private copy.

    Root E — abstention is certified, not hidden. The denominator is
    *membership*: every row whose DOMAIN is in the index. An in-index domain whose
    name the applier abstains on (``apply`` -> ``None``) counts as an abstention in
    that denominator, so a sample where 99/100 abstain can no longer report
    ``capture 1.0`` off the single row that applied. ``capture`` = apply-match /
    avg-confidence-ceiling over the APPLIED rows (the symmetry signal); a separate
    ``abstention_rate`` = abstained / membership is asserted below ``max_abstention``.
    A capture below ``min_capture`` means the applier's ``norm`` / tokenize /
    templates / ``role_of`` drifted from the generator — the drift this gate exists
    to catch.

    Returns the metrics dict; raises ``AssertionError`` on a symmetry regression or
    an abstention blow-out. Run it as a maintainer check (needs the private
    sample)::

        python -m backend.core.company_pattern_index /path/to/validation_sample.csv
    """
    import csv

    idx = CompanyPatternIndex(index_path)
    assert idx.available, f"index not loadable at {index_path}"
    with open(sample_csv, encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    membership = 0  # rows whose domain is indexed — abstentions belong HERE
    applied = 0
    match = 0
    conf_sum = 0.0
    for r in rows:
        if not idx.is_indexed(r["domain"]):
            continue  # domain not indexed at all — out of scope for symmetry
        membership += 1
        res = idx.apply(r["full_name"], r["domain"], r.get("title"), r.get("seniority"))
        if res is None:
            continue  # in-index domain, but the applier abstained on this name
        applied += 1
        conf_sum += res.confidence
        actual_lp = r["email"].split("@", 1)[0].strip().lower().split("+", 1)[0]
        if res.email.split("@", 1)[0] == actual_lp:
            match += 1

    abstained = membership - applied
    ceiling = conf_sum / applied if applied else 0.0
    acc = match / applied if applied else 0.0
    capture = acc / ceiling if ceiling else 0.0
    abstention_rate = abstained / membership if membership else 0.0
    metrics = {
        "membership": membership,
        "applied": applied,
        "abstained": abstained,
        "abstention_rate": round(abstention_rate, 4),
        "apply_match": round(acc, 4),
        "ceiling": round(ceiling, 4),
        "capture": round(capture, 4),
    }
    assert capture >= min_capture, (
        f"SYMMETRY REGRESSION — applier diverged from the index generator: "
        f"capture {capture:.1%} < {min_capture:.0%} ({metrics})"
    )
    assert abstention_rate <= max_abstention, (
        f"ABSTENTION BLOW-OUT — {abstention_rate:.1%} of in-index rows abstained "
        f"(> {max_abstention:.0%}); capture cannot be certified on the thin applied "
        f"remainder ({metrics})"
    )
    return metrics


if __name__ == "__main__":  # pragma: no cover - maintainer entry point
    import sys

    if len(sys.argv) > 1:
        m = roundtrip_gate(sys.argv[1])
        print(
            f"membership: {m['membership']} | applied {m['applied']} | "
            f"abstained {m['abstained']} ({m['abstention_rate']*100:.1f}%) | "
            f"apply-match {m['apply_match']*100:.1f}% "
            f"| ceiling(avg conf) {m['ceiling']*100:.1f}% "
            f"| capture {m['capture']*100:.1f}% of achievable"
        )
        print("GATE PASS")
    else:
        print("usage: python -m backend.core.company_pattern_index <validation_sample.csv>")
