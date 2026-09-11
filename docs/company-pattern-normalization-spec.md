# Company-pattern normalization spec (`norm/1`)

The company email-pattern index is built by the private generator SQL
(`pattern_pipeline.sql`, in the maintainer's `email-pattern-index/` folder) and
applied at runtime by
[`backend/core/company_pattern_index.py`](../backend/core/company_pattern_index.py).
The generator and the applier **must normalize names identically** — if they
drift, the applier looks up tokens the generator never wrote and capture
collapses.

**Single implementation, not two (Brief C #6).** The versioned transform
(`NORMALIZATION_VERSION = "norm/1"`) is implemented ONCE in the applier
(`_index_norm`, `_first_last`, `_role_of`, `_templates`). The generator does **not**
re-implement it in SQL: it registers the exact same Python callables as DuckDB UDFs
via `company_pattern_index.register_normalization_udfs(con)` and calls
`norm(...)`, `name_first(...)`, `name_last(...)`, `role_of(...)`, `localpart(...)`
in the pipeline. So the two sides cannot drift — they run the same code. The
executable differential
[`tests/test_pattern_normalization_differential.py`](../tests/test_pattern_normalization_differential.py)
drives those UDFs through real SQL (needs the `[build]` extra: `pip install -e .[build]`)
and compares normalized tokens, acceptance/abstention, role, and localpart to the
applier — the real SQL↔Python check, not a constant table. Bump
`NORMALIZATION_VERSION` whenever any of the four rules change, then rebuild.

> Tokenization is a UDF (`name_first`/`name_last`), **not** an in-SQL `\s+` split:
> DuckDB's SQL-regex whitespace and Python's `re` disagree on characters such as
> NBSP, so an in-SQL split silently diverged from the applier. `role_of` etc. are
> registered with `null_handling='special'` so a NULL seniority reaches the Python
> classifier instead of DuckDB short-circuiting the whole call to NULL.

## The canonical transform (`norm`)

Applied to each whitespace token of a display name, in this exact order:

1. `lower()` — Unicode-aware lowercasing (fullwidth `Ａ` → `ａ`, `İ`→`i̇`).
2. Explicit folds for the common **non-combining** letters that NFKD does not
   decompose: `ø→o`, `ł→l`, `ß→ss`, `æ→ae`, `œ→oe`, `đ→d`, `ð→d`.
3. `NFKD` compatibility decomposition, then **drop combining marks** (category
   `Mn`). This both strips diacritics (`é`→`e`) and folds compatibility forms
   (ligature `ﬃ`→`ffi`, fullwidth `ＡＢＣ`→`abc`, circled `①`→`1`, superscripts,
   etc.).
4. Keep only `[a-z0-9]`; drop everything else (apostrophes, hyphens, spaces,
   NBSP residue, punctuation).

## Tokenization

Split the display name on Unicode whitespace `\s+` (this includes NBSP
` `), keep the first and last surviving tokens as `first` / `last`. A token
that normalizes to empty (e.g. a purely non-Latin token) drops the whole name
(the generator could not have kept it either → the applier abstains). Two
distinct tokens that normalize equal (`Li Li` → `li`/`li`) are **not** a mononym
and are allowed; only a single-token name (`Cher`) is a mononym and is restricted
to the single-part patterns.

## Frozen reference table (the differential gate)

Both implementations must produce exactly these outputs. The Python side is
asserted in `test_normalization_differential_python_matches_reference`; the SQL
side is exercised by `tests/test_pattern_normalization_differential.py`, which
executes `scripts/company_pattern_pipeline.sql` through the actual build runner.

| input          | norm      | note                                   |
|----------------|-----------|----------------------------------------|
| `José`         | `jose`    | combining diacritic dropped            |
| `Müller`       | `muller`  | leading/trailing space trimmed         |
| `straße`       | `strasse` | explicit fold `ß→ss`                    |
| `Łukasz`       | `lukasz`  | explicit fold `ł→l`                     |
| `Øystein`      | `oystein` | explicit fold `ø→o`                     |
| `æon`          | `aeon`    | explicit fold `æ→ae`                    |
| `naïve`        | `naive`   | combining diaeresis dropped            |
| `ﬃ`            | `ffi`     | NFKD ligature decomposition            |
| `ＡＢＣ`         | `abc`     | NFKD fullwidth fold                     |
| `３Ｄ`           | `3d`      | NFKD fullwidth digit + letter           |
| `①`            | `1`       | NFKD circled-number fold                |
| `O’Brien`      | `obrien`  | curly apostrophe stripped              |
| `Ｏ’Ｎｅｉｌｌ`   | `oneill`  | fullwidth + apostrophe                  |

`Jane Smith` (NBSP separator) tokenizes to `("jane", "smith")` — NBSP is
whitespace for the split and is stripped from the norm either way.
