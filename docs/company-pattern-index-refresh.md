# Refreshing the company pattern index

The runtime ships `data/company_patterns.json.gz`. Build from a checkout on the
processing host with read access to the corpus. Export aggregate counts only;
the corpus and validation sample remain private.

## Current release gate

The September 11 artifact has true-denominator counts but was built by the old
SQL normalization macros. It has no `normalization_version`. It must be rebuilt
with the pipeline below before the normalization finding can close. Do not add a
version tag to an old artifact: the underlying counts must be regenerated.

## Build

Install the optional build dependency (`pip install -e ".[build]"`). Run:

```bash
python -m scripts.build_pattern_aggregates --corpus /root/corpus.duckdb --out /root/out --temp /root/ddtmp
python -m scripts.assemble_pattern_index --indir /root/out --out /root/out/company_patterns.json.gz --qa /root/out/qa_report.md --corpus-snapshot "<snapshot>"
```

`scripts/company_pattern_pipeline.sql` is the actual pipeline under test. The
runner registers the applier's versioned normalization, Unicode tokenization,
role classification and domain normalization as DuckDB UDFs before executing SQL.
Do not run an old SQL file that replaces these UDFs with local macros. Duplicate
mailbox rows select a consistent complete row deterministically. Mononyms cannot
contribute support to templates that require two name tokens.

The runner writes `build_identity.json`; the assembler requires it and stamps
`normalization_version=norm/1`. Confidence is dominant support divided by every
qualifying considered mailbox, including unmatched and ambiguous mailboxes.
Every domain and role record carries its own `considered_n`. The assembler emits
only JSON and fails explicitly above its configured size limit; the runtime does
not accept JSONL.

Run the existing maintainer MX enrichment over the rebuilt domain set. Preserve
the new metadata, including `normalization_version`, and verify all surviving
records have an `m365`, `google` or `other` tag. Copy the enriched artifact to
`data/company_patterns.json.gz` only after validation.

## Validation

```bash
python -m pytest tests/test_pattern_normalization_differential.py tests/test_pattern_remediation_boundaries.py tests/test_company_pattern_index.py tests/test_pattern_oracle_verify.py
python -m backend.core.company_pattern_index /private/path/validation_sample.csv
```

The differential executes the actual SQL stages on synthetic Unicode inputs and
the actual assembler on a 10/100 domain; that domain must be omitted. The private
round-trip gate must meet capture and abstention thresholds. Scan all emitted
domain and role records for positive denominators, support bounds, confidence
ratios within four-decimal rounding tolerance, valid templates and MX values.

The cache identity hashes the complete loaded artifact, including MX and role
records. Loading is restart-only: restart the process after replacing the file.
The old singleton and its digest stay paired until restart. A metadata date bump
alone is not the cache-identity test; changing record content or only MX must
invalidate cached results even when metadata is identical.

After building a wheel, verify the installed artifact from outside the checkout.
Keep private corpus rows, credentials and validation samples out of distributions.
