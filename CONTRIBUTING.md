# Contributing

## Adding a Module

Each OSINT module is a single `.py` file in `backend/modules/`. The auto-discovery registry (`backend/modules/__init__.py`) scans the package at import time — no manual wiring needed.

### The five things every module must implement

```python
from backend.modules.base import BaseModule, ModuleResult, ModuleStatus

class MyModule(BaseModule):
    name = "my_module"         # 1. unique slug — used in API responses and DB records
    description = "One line."  # 2. human-readable purpose (shown in GET /api/modules/)
    requires_key = True        # 3. True if the module should skip when its API key is absent

    async def run(self, email: str) -> ModuleResult:  # 4. async, takes the email string
        ...
        return ModuleResult(   # 5. always return ModuleResult — never raise
            status=ModuleStatus.SUCCESS,   # SUCCESS | PARTIAL | FAILED | SKIPPED
            findings=[                     # list of dicts — flexible schema per module
                {
                    "platform": "my_service",
                    "url": "https://...",
                    "metadata": {...},
                    "confidence": "high",  # high | medium | low
                }
            ],
            metadata={},   # module-level supplementary info (counts, API version, etc.)
            errors=[],     # human-readable error strings
        )
```

### Key constraints

- **Never raise from `run()`.** Catch all exceptions and return `ModuleResult(status=ModuleStatus.FAILED, errors=[str(e)])`.
- **Check for missing keys early.** If `requires_key = True`, check `settings.your_api_key` at the top of `run()` and return `ModuleStatus.SKIPPED` if absent.
- **Use `build_client()`** from `backend.core.http_client` for all outbound HTTP — it respects proxy settings and the rate limiter.
- The engine enforces `MODULE_TIMEOUT_SECONDS` (default 30 s) per module via `asyncio.wait_for`. Plan accordingly.
- Do not call blocking libraries directly on the event loop — wrap them with `asyncio.to_thread()`.

### File placement

Drop the file at `backend/modules/my_module.py`. The next server start auto-registers it. Module `name` values must be unique across the package.

---

## Adding an Exporter

Exporters live in `backend/exporters/`. Each inherits `BaseExporter`:

```python
from backend.exporters.base import BaseExporter

class MyExporter(BaseExporter):
    format_name = "myformat"              # matched against ?format= query param
    content_type = "application/x-mine"  # MIME type returned in the HTTP response

    def export(self, investigation_id: str, data: dict) -> bytes:
        ...
        return result_bytes
```

After writing the class, register it in `backend/exporters/__init__.py` — add it to the import list and to the `EXPORTERS` dict.

The `data` argument is the enriched report dict produced by `enrich_report()` in `backend/core/service.py`. It contains: `id`, `email`, `status`, `exposure_score`, `risk_level`, `summary`, `findings`, `module_runs`, `findings_by_module`, `metadata_table`.

PDF exports use an async `generate()` method instead of `export()`; see `PdfExporter` for the pattern.

---

## Code Style

- Python 3.11+, `from __future__ import annotations` at the top of every file
- Type annotations on all function signatures
- `async`/`await` throughout — no blocking I/O on the event loop
- No comments that describe *what* the code does — only comments explaining *why* when the reason is non-obvious
- Line length: 100 characters
- Formatter: `ruff format` (black-compatible)

---

## PR Checklist

- [ ] Module or exporter follows the contracts above
- [ ] `requires_key = True` modules return `SKIPPED` (not `FAILED`) when the key is absent
- [ ] No blocking I/O executed directly on the asyncio event loop
- [ ] No hardcoded credentials, tokens, or identifying user-agent strings
- [ ] Existing tests pass (`pytest`)
- [ ] Tests are bundled in the same PR, not submitted separately
- [ ] If the result shape changes, `docs/modules.md` and `docs/architecture.md` are updated in the same PR
- [ ] Reasoning modules are wired into `backend/core/engine.py`, `backend/core/phases.py`, or the equivalent post-primary pipeline
- [ ] No new third-party dependencies are added; use the standard library and existing project dependencies
- [ ] PR description explains what data source is queried, what the findings look like, and why they are useful for OSINT

---

## Adding a New Platform

OSINT social / communication probes are defined as YAML files — no Python changes required.

1. Create `backend/platforms/{platform_name}.yaml` (copy from `backend/platforms/TEMPLATE.yaml`).
2. Follow the schema in `backend/platforms/schema.py` (`PlatformCheck` fields).
3. Set `category` to `social` or `communication` (the `social` module loads both).
4. Test locally:

   ```bash
   mailaccess investigate test@example.com --modules social
   ```

5. Open a PR with the YAML only. Invalid files are logged and skipped at runtime; they do not crash the server.

Use `|` in `success_string` or `failure_string` for multiple alternative substrings (OR). Use `{email}`, `{username}`, or `{md5}` in URLs and bodies.

---

## Adding a Reasoning Module

Reasoning modules run after primary collectors and do not fetch external data. They
consume the existing `dict[str, ModuleResult]`, then emit synthesized clusters,
scores, normalized findings, or other enriched output. See
`backend/core/identity_graph.py`, `backend/core/name_consensus.py`,
`backend/core/breach_normalizer.py`, and `backend/core/credential_risk.py`.

Keep the contract narrow: accept the results dictionary, return an enriched copy or
modify and return the same dictionary, and preserve each collector's provenance.
Wire the component into `backend/core/engine.py`, `backend/core/phases.py`, or the
equivalent post-primary pipeline; core reasoning files are not discovered through
`backend/modules/__init__.py`.

---

## Testing Guidelines

- `pytest` is the project test runner. `asyncio_mode = "auto"` in `pyproject.toml`
  makes async test functions auto-detect.
- Mock HTTP with `unittest.mock.patch` on `httpx.Client.get`, or use
  `monkeypatch.setattr` on the module-level import. Do not add `respx` or
  `httpx_mock`.
- For settings-dependent tests, use
  `monkeypatch.setattr(settings, "field_name", value)`; pytest restores the value
  during teardown.
- Isolate files with `tmp_path`. Cache tests should pass a path such as
  `cache_path=tmp_path / "x.json"` instead of mutating global cache files.
- Build result fixtures with
  `ModuleResult(status=ModuleStatus.SUCCESS, findings=[...])`; see
  `tests/test_platform_dedup.py`.
- Use `caplog` for log assertions; see `tests/test_breach_normalizer.py`.
- Follow the async orchestration patterns in `tests/test_phase_runner.py`.

---

## Releasing a new version

1. Bump version in `pyproject.toml` — the CLI reads this dynamically, no other files need updating.
2. `python -m build`
3. `twine upload dist/mailaccess-{version}*`
