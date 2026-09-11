"""Release gate for a rebuilt pattern artifact; prints aggregate diagnostics only."""
from __future__ import annotations

import argparse

from backend.core.company_pattern_index import (
    NORMALIZATION_VERSION,
    CompanyPatternIndex,
    _validated_record_fields,
)


def validate_artifact(path: str) -> dict:
    index = CompanyPatternIndex(path)
    if not index.available:
        raise ValueError("artifact is unavailable")
    if index.meta.get("normalization_version") != NORMALIZATION_VERSION:
        raise ValueError(
            "artifact was not built with the current normalization; "
            "regenerate counts before stamping a version"
        )
    roles = 0
    for domain, record in index._idx.items():
        _validated_record_fields(record, domain=domain, role_used=None, require_denominator=True)
        if record.get("mx") not in {"m365", "google", "other"}:
            raise ValueError("artifact has missing or invalid MX classifications")
        for role, override in (record.get("role_overrides") or {}).items():
            _validated_record_fields(
                override, domain=domain, role_used=role, require_denominator=True
            )
            roles += 1
    if not index._idx:
        raise ValueError("artifact contains no domains")
    return {"domains": len(index._idx), "roles": roles, "digest": index.content_digest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", nargs="?", default="data/company_patterns.json.gz")
    args = parser.parse_args()
    try:
        print(validate_artifact(args.artifact))
    except (ValueError, AssertionError) as exc:
        parser.exit(1, f"Pattern artifact gate failed: {exc}\n")


if __name__ == "__main__":
    main()
