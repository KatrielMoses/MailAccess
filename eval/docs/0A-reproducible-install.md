# 0A — Environment Reproducibility & Clean-Install Gate

**Goal:** a fresh machine can install the locked project and run the full test +
baseline harness deterministically, and a CI clean-room gate protects every
future PR.

## Mechanism chosen: `uv` + `uv.lock`

We use [`uv`](https://docs.astral.sh/uv/) as the install/lock mechanism.

**Why `uv` over the alternatives named in the brief:**

| Option | Verdict |
|---|---|
| **`uv`** ✅ | Single universal lockfile (`uv.lock`) resolving the *entire* dependency graph incl. all extras; pins the Python version via `.python-version`; `uv sync --frozen` gives a deterministic, fail-closed install; fast; first-class GitHub Action (`astral-sh/setup-uv`). Directly satisfies both 0A requirements (lock + Python pin) with one tool. |
| `pip-tools` | Produces `requirements.txt` locks but does **not** pin the interpreter, and multi-extra locking (`ml`/`pdf`/`ghunt`/`dev`) needs several compiled files stitched together. More moving parts for the same result. |
| `hatch` | Already our build backend, but its environment/locking story is weaker than uv's and would duplicate what uv does better. We keep `hatchling` as the **build backend** (unchanged) and use uv only for install/lock — they compose cleanly. |

The build backend stays `hatchling` (see `pyproject.toml`); uv reads the same
PEP 621 metadata, so nothing about the package build changes.

### The root-cause fix (`pydantic_settings` "missing despite declared")

The Doc-1 audit found the suite wouldn't start because `pydantic_settings` was
absent even though it's declared in `pyproject.toml`. That is the classic
symptom of an install that **didn't resolve declared dependencies** (e.g. an
editable/wheel install done without its deps, or a partially-populated venv).
`uv sync --frozen` resolves the *locked* graph into a fresh venv every time, so
this class of "declared-but-not-installed" drift cannot recur. `pydantic-settings`
is a normal locked dependency in `uv.lock`.

## Python version

Pinned to **3.10** via `.python-version` (repo targets `>=3.10`). `uv python
install` in CI fetches exactly this interpreter. Baseline captured on CPython
3.10.6, Windows.

## Optional-extras matrix

| Extra | Contents | Needed for baselining? |
|---|---|---|
| *(core)* | fastapi, sqlalchemy, pydantic(+settings), httpx, dnspython, typer, holehe, user-scanner, rapidfuzz, … | **Yes** — the tool itself. |
| `dev` | pytest, pytest-asyncio, ruff, mypy | **Yes** — the test + lint gate. |
| `ml` | spaCy (name classifier) | **No.** Only used by `--enable-ml` / `--verify` name classification. Keyless baseline runs without it; tests that import spaCy skip. |
| `pdf` | weasyprint | **No.** Only for `--output report.pdf`. |
| `ghunt` | ghunt | **No.** Opt-in, key/creds-gated module (off by default). |

**Baseline env = core + `dev`.** Install with `uv sync --extra dev`.
`ml`/`pdf`/`ghunt` are locked (so they're reproducible if needed later) but not
installed for the primary baseline.

Known latent packaging nit (documented, **not changed** to keep v0.14.4 frozen):
`pyproject.toml` declares `typer[all]`, but modern typer folded the `all` extra
into the base package, so uv emits a harmless "no extra named all" warning.
Resolution still succeeds. Fix belongs in a later phase, not the baseline.

## Clean-room CI gate

`.github/workflows/ci.yml` runs on `pull_request` and pushes to `main`, matrixed
over **windows-latest** (reference OS) and **ubuntu-latest**:

1. `actions/checkout`
2. `astral-sh/setup-uv` (cached on `uv.lock`)
3. `uv python install` + `uv sync --extra dev --frozen` → fresh locked venv
4. `uv run python -m eval.harness.manifest` → prints the reproducibility manifest
5. `uv run python -m eval.harness.gate check` → **ruff + pytest baseline-diff gate**

The gate fails the PR only on **new** failures vs the committed baseline (below),
so pre-existing noise never blocks a PR but a genuine regression does.

## Known-failure baseline & catalogue

The suite has thousands of tests with a **stable set of pre-existing failures**,
and ruff reports hundreds of pre-existing findings. These are captured as
committed baselines and classified so future PRs can tell a new regression from
old noise:

* `eval/baseline/known-test-failures.txt` — one failing pytest nodeid per line.
* `eval/baseline/known-ruff.txt` — one `<relpath>\t<code>` per line (line-number
  independent, so ordinary edits don't churn it).
* `eval/docs/failure-catalogue.md` — every failing test classified as
  **env-only** / **pre-existing-known** / **real**.

### Hermetic + terminating test runs

The suite has live-network tests and **no per-test timeout**, so a plain
`pytest` run *hangs indefinitely* on the first unreachable host. Two pieces of
harness tooling make the run deterministic and terminating:

* `-p eval.harness.no_network` — a plugin that blocks non-local sockets/DNS, so
  live tests **fail fast** (`BlockedNetworkError` / `gaierror`) instead of
  hanging. This is also what a CI clean-room (no third-party reachability) sees.
* `--timeout=60 --timeout-method=thread` (`pytest-timeout`) — a backstop for any
  residual non-socket hang.

The committed baseline and the CI gate use these **exact** flags, so the gate
compares like-for-like. Failures that only appear because network is blocked are
classified **env-only** in the catalogue.

Regenerate the baselines with:

```bash
uv run python -m eval.harness.gate snapshot
```

### Baseline is environment-specific (important caveat)

The failing SET depends on OS, installed extras, network reachability, and which
API keys are present. The committed baseline is captured in the **keyless
clean-room** config (no keys, `dev` extra, Windows reference). If you regenerate
in a different environment, expect the set to shift; the gate's "N previously
failing now pass — consider refreshing the baseline" hint flags this. For the
cross-machine gate, run `gate snapshot` once inside CI and commit that baseline.

## Done-when

- [x] Locked, reproducible install (`uv.lock`, Python pinned).
- [x] Optional-extras matrix documented; baseline needs core + `dev` only.
- [x] Clean-room CI job (fresh venv → locked install → ruff + pytest → publish).
- [x] Pre-existing failures catalogued & classified (see `failure-catalogue.md`).
