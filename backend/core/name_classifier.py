"""Optional ML-backed person-name classification."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from backend.core.name_quality import is_plausible_person_name, name_suspicion_penalty


@dataclass(frozen=True)
class NameClassificationResult:
    is_person: bool
    confidence: float
    source: str
    reason: str


_NLP: Any | None = None
_NLP_LOAD_FAILED = False


def _load_nlp() -> Any | None:
    global _NLP, _NLP_LOAD_FAILED
    if _NLP is not None:
        return _NLP
    if _NLP_LOAD_FAILED:
        return None
    try:
        import spacy

        _NLP = spacy.load(
            "en_core_web_md",
            disable=["tagger", "parser", "attribute_ruler", "lemmatizer"],
        )
        return _NLP
    except (ImportError, OSError):
        _NLP_LOAD_FAILED = True
        return None


def _get_nlp() -> Any | None:
    """Return the model only when ML was explicitly enabled."""
    from backend.config import settings

    if str(getattr(settings, "ml_name_classifier", "off") or "off").lower() != "on":
        return None
    return _load_nlp()


def is_ml_available() -> bool:
    """Return True when spaCy and en_core_web_md are both loadable."""
    try:
        import spacy

        if not spacy.util.is_package("en_core_web_md"):
            return False
        return _load_nlp() is not None
    except ImportError:
        return False


def _heuristic_prefilter(text: str) -> tuple[NameClassificationResult | None, float]:
    if not is_plausible_person_name(text):
        return (
            NameClassificationResult(
                is_person=False,
                confidence=0.0,
                source="heuristic",
                reason="failed is_plausible_person_name",
            ),
            0.0,
        )
    penalty = name_suspicion_penalty(text)
    if penalty == 0.0:
        return (
            NameClassificationResult(
                is_person=False,
                confidence=0.0,
                source="heuristic",
                reason="suspicion_penalty=0.0",
            ),
            penalty,
        )
    return None, penalty


def _has_person_entity(doc: Any) -> bool:
    return any(getattr(ent, "label_", None) == "PERSON" for ent in getattr(doc, "ents", ()))


def classify_name(text: str) -> NameClassificationResult:
    """Classify text as a person name using heuristic prefilter + optional NER."""
    prefilter_result, penalty = _heuristic_prefilter(text)
    if prefilter_result is not None:
        return prefilter_result

    nlp = _get_nlp()
    if nlp is None:
        return NameClassificationResult(
            is_person=True,
            confidence=round(0.6 * penalty, 3),
            source="heuristic",
            reason="ml_unavailable",
        )

    doc = nlp(text)
    if not _has_person_entity(doc):
        return NameClassificationResult(
            is_person=False,
            confidence=0.15,
            source="hybrid",
            reason="ner_veto",
        )

    return NameClassificationResult(
        is_person=True,
        confidence=round(min(0.95, 0.85 * penalty), 3),
        source="hybrid",
        reason="heuristic+ner_agree",
    )


async def classify_names_batch(names: list[str]) -> list[NameClassificationResult]:
    """Batch classify names, sending only heuristic-passing candidates to NER."""
    heuristic_results: dict[str, NameClassificationResult] = {}
    ner_candidates: list[tuple[str, float]] = []

    for name in names:
        prefilter_result, penalty = _heuristic_prefilter(name)
        if prefilter_result is not None:
            heuristic_results[name] = prefilter_result
        else:
            ner_candidates.append((name, penalty))

    nlp = _get_nlp()
    if nlp is None or not ner_candidates:
        for name, penalty in ner_candidates:
            heuristic_results[name] = NameClassificationResult(
                True,
                round(0.6 * penalty, 3),
                "heuristic",
                "ml_unavailable",
            )
        return [heuristic_results[name] for name in names]

    def _run_batch(items: list[tuple[str, float]]) -> dict[str, NameClassificationResult]:
        results: dict[str, NameClassificationResult] = {}
        texts = [name for name, _ in items]
        for doc, (name, penalty) in zip(nlp.pipe(texts, batch_size=32), items, strict=True):
            if _has_person_entity(doc):
                results[name] = NameClassificationResult(
                    True,
                    round(min(0.95, 0.85 * penalty), 3),
                    "hybrid",
                    "heuristic+ner_agree",
                )
            else:
                results[name] = NameClassificationResult(False, 0.15, "hybrid", "ner_veto")
        return results

    heuristic_results.update(await asyncio.to_thread(_run_batch, ner_candidates))
    return [heuristic_results[name] for name in names]
