"""Migration 0016, retention, and harvest --events-jsonl."""

from __future__ import annotations

import json
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from backend.db.database import _alembic_config


@pytest.fixture
def workdir():
    path = Path(tempfile.mkdtemp(prefix="mailaccess-ev-"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _op(rev: str, direction: str):
    def _fn(sync_conn) -> None:
        from alembic import command

        getattr(command, direction)(_alembic_config(sync_conn), rev)

    return _fn


async def _alembic(engine, rev: str, direction: str) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(_op(rev, direction))


async def _tables(engine) -> set[str]:
    async with engine.connect() as conn:
        return await conn.run_sync(lambda c: set(sa.inspect(c).get_table_names()))


async def _version(engine) -> str:
    async with engine.connect() as conn:
        return (await conn.execute(text("select version_num from alembic_version"))).scalar_one()


async def test_migration_0016_upgrades_downgrades_and_reupgrades_on_a_0_18_7_database(
    workdir: Path,
) -> None:
    """0.18.7's head is 0014. Build that database, put a run in it, then go to 0016,
    back, and forward again: existing data survives every step."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{(workdir / 'v0187.db').as_posix()}")
    try:
        await _alembic(engine, "0014", "upgrade")
        assert await _version(engine) == "0014"
        assert "run_events" not in await _tables(engine)
        async with engine.begin() as conn:
            await conn.execute(text(
                "insert into investigations (id, email, status, created_at, mode) "
                "values ('keep-me', 'a@b.com', 'COMPLETE', '2026-10-01 00:00:00', 'security-investigation')"
            ))

        await _alembic(engine, "0016", "upgrade")
        assert await _version(engine) == "0016"
        async with engine.connect() as conn:
            cols = await conn.run_sync(
                lambda c: {x["name"] for x in sa.inspect(c).get_columns("run_events")}
            )
            indexes = await conn.run_sync(
                lambda c: {i["name"]: i["column_names"] for i in sa.inspect(c).get_indexes("run_events")}
            )
        assert cols == {"id", "investigation_id", "seq", "ts", "type", "payload"}
        assert indexes["ix_run_events_investigation_seq"] == ["investigation_id", "seq"]
        async with engine.begin() as conn:
            await conn.execute(text(
                "insert into run_events (investigation_id, seq, ts, type, payload) "
                "values ('keep-me', 1, '2026-10-01T00:00:00.000Z', 'run_started', '{}')"
            ))
            with pytest.raises(sa.exc.IntegrityError):  # (run, seq) is unique
                await conn.execute(text(
                    "insert into run_events (investigation_id, seq, ts, type, payload) "
                    "values ('keep-me', 1, 'x', 'run_started', '{}')"
                ))

        await _alembic(engine, "0015", "downgrade")
        assert await _version(engine) == "0015"
        assert "run_events" not in await _tables(engine)

        await _alembic(engine, "0016", "upgrade")
        assert await _version(engine) == "0016"
        assert "run_events" in await _tables(engine)
        async with engine.connect() as conn:
            kept = (await conn.execute(text("select email from investigations where id='keep-me'"))).scalar_one()
        assert kept == "a@b.com"
    finally:
        await engine.dispose()


async def test_retention_deletes_events_only_for_runs_past_report_retention(isolated_db) -> None:
    from backend.core.retention import purge_run_events
    from backend.db import database as _database
    from backend.db.models import Investigation, RunEvent

    now = datetime.now(timezone.utc)
    async with _database.AsyncSessionLocal() as db:
        old = Investigation(email="old@x.com", created_at=now - timedelta(days=400))
        new = Investigation(email="new@x.com", created_at=now - timedelta(days=2))
        db.add_all([old, new])
        await db.flush()
        for inv in (old, new):
            db.add(RunEvent(investigation_id=inv.id, seq=1, ts="t", type="run_started", payload={}))
        await db.commit()
        old_id, new_id = old.id, new.id

    async with _database.AsyncSessionLocal() as db:
        async with db.begin():
            assert await purge_run_events(db, now, dry_run=True) >= 1  # counts only
    async with _database.AsyncSessionLocal() as db:
        async with db.begin():
            assert await purge_run_events(db, now) >= 1
    async with _database.AsyncSessionLocal() as db:
        left = {r for (r,) in (await db.execute(sa.select(RunEvent.investigation_id))).all()}
    assert old_id not in left and new_id in left


# ------------------------------------------------------------------- --events-jsonl
def test_events_jsonl_lines_are_valid_json_and_flushed_per_line(workdir: Path) -> None:
    from backend.core.harvest_events import HarvestEvents

    path = workdir / "out" / "events.jsonl"
    events = HarvestEvents(path, "example.com", ["commoncrawl_email", "security_txt"], "security-investigation")

    # flushed per line: readable by another reader before the run ends
    first = [json.loads(line) for line in path.read_text().splitlines()]
    assert [e["type"] for e in first] == ["run_started", "phase_start"]

    events.progress("commoncrawl_email", "Starting module...")
    events.signal(SimpleNamespace(kind="email", source="commoncrawl_email", value="a@example.com", metadata={}))
    events.complete("commoncrawl_email", "success")
    events.progress("security_txt", "Starting module...")
    events.complete("security_txt", "skipped", ["no file"])
    # The final export keeps this one email: only the result becomes a finding.
    events.finalize({"emails": [{"email": "a@example.com", "found_by_modules": ["commoncrawl_email"],
                                 "confidence_label": "HIGH"}]})

    lines = path.read_text().splitlines()
    parsed = [json.loads(line) for line in lines]  # every line is valid JSON
    assert [e["seq"] for e in parsed] == list(range(1, len(parsed) + 1))
    types = [e["type"] for e in parsed]
    assert types[0] == "run_started" and types[-1] == "run_done"
    assert types.count("module_start") == types.count("module_done") == 2
    assert {"finding", "phase_end"} <= set(types)
    started = parsed[0]
    assert "payload" not in started  # fields sit at the top level, plus seq, ts and type
    assert started["unavailable"] == []
    assert [m["module"] for m in started["planned_modules"]] == ["commoncrawl_email", "security_txt"]
    assert started["total_sources"] == 2
    finding = next(e for e in parsed if e["type"] == "finding")
    assert finding["value"] == "a@example.com" and finding["trace"]["reason"]
    assert finding["kind"] == "email" and finding["label"] is None and "url" in finding
    assert "_" not in finding["trace"]["reason"]
    start = next(e for e in parsed if e["type"] == "module_start")
    assert start["technique"] and start["technique_id"]
    done_events = [e for e in parsed if e["type"] == "module_done"]
    assert {e["status"] for e in done_events} == {"success", "skipped"}
    assert next(e for e in done_events if e["status"] == "skipped")["skipped_reason"] == "disabled"
    done = parsed[-1]
    assert done["sources_checked"] == 1 and done["total_sources"] == 2 and done["findings"] == 1
    assert (done["candidates"], done["emails"], done["names"], done["subdomains"]) == (1, 1, 0, 0)
    candidate = next(e for e in parsed if e["type"] == "candidate")
    assert candidate == {k: candidate[k] for k in ("seq", "ts", "type", "module", "kind", "count")}
    assert "a@example.com" not in json.dumps(candidate)
    for e in parsed:
        if e["type"] == "module_progress":
            assert e["checked"] <= e["total"]


def test_harvest_progress_uses_the_real_module_list_not_a_hardcoded_one() -> None:
    from backend.core.harvest_runner import planned_harvest_modules

    base = planned_harvest_modules()
    assert len(base) > 11 and len(base) == len(set(base))
    assert {"security_txt", "wayback_domain_harvest", "hackertarget_hosts"} <= set(base)
    assert "security_txt" not in planned_harvest_modules({"security_txt"})
    keyed = planned_harvest_modules(netlas=True, whoisfreaks=True, hunter=True)
    assert set(keyed) - set(base) == {
        "netlas_responses", "netlas_cert", "netlas_whois_emails", "whoisfreaks_history", "hunter",
    }


def test_harvest_command_exposes_events_jsonl() -> None:
    from typer.testing import CliRunner

    import cli.main as main

    result = CliRunner().invoke(main.app, ["harvest-emails", "--help"])
    assert result.exit_code == 0
    assert "--events-jsonl" in result.output


def test_jsonl_never_lets_a_payload_type_clash_with_the_event_type(workdir: Path) -> None:
    from backend.core.harvest_events import HarvestEvents

    events = HarvestEvents(workdir / "e.jsonl", "example.com", [])
    events.emitter.emit("edge_added", {"source": {}, "target": {}, "type": "derived_username",
                                       "reason": "x", "finding_id": None})
    events.finish()
    edge = next(json.loads(l) for l in (workdir / "e.jsonl").read_text().splitlines()
                if '"edge_added"' in l)
    assert edge["type"] == "edge_added" and edge["edge_type"] == "derived_username"
