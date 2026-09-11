"""The actual production SQL must consume the shared transforms, not shadow them."""
import gzip
import json
import subprocess
import sys

import pytest

from backend.core.company_pattern_index import _first_last, _index_norm, _role_of
from scripts.build_pattern_aggregates import run_pipeline


def test_actual_pipeline_normalization_and_denominator(tmp_path):
    duckdb = pytest.importorskip("duckdb")
    con = duckdb.connect()
    con.execute("ATTACH ':memory:' AS c")
    con.execute(
        "CREATE TABLE c.contacts(domain VARCHAR,email VARCHAR,full_name VARCHAR,"
        "title VARCHAR,seniority VARCHAR,is_verified BOOLEAN)"
    )
    names = [
        "ﬃ Smith",
        "ＡＢＣ Smith",
        "① Smith",
        "Jane\u00a0Smith",
        "\tJane Smith\n",
        "Jane\u0085Smith",
        "Mary-Jane O’Brien",
        "李 雷",
        "Иван Иванов",
        "Li Li",
        "",
        None,
    ]
    rows = [
        (f"case{i}.example", f"person{i}@case{i}.example", name, "营销HR", None, True)
        for i, name in enumerate(names)
    ]
    rows += [
        (
            "mixed.example",
            (f"jane{i}.smith{i}" if i < 10 else f"employee{i}") + "@mixed.example",
            f"Jane{i} Smith{i}",
            None,
            None,
            True,
        )
        for i in range(100)
    ]
    con.executemany("INSERT INTO c.contacts VALUES (?,?,?,?,?,?)", rows)
    assert run_pipeline(con, tmp_path) == "norm/1"
    for i, name in enumerate(names):
        assert con.execute("SELECT norm(?)", [name]).fetchone()[0] == _index_norm(name)
        actual = con.execute(
            "SELECT first,last FROM f_named WHERE dom=?", [f"case{i}.example"]
        ).fetchone()
        assert actual == _first_last(name)
    for title in ["营销HR", "éCTOé", "CTO", "VP Sales", None]:
        assert con.execute("SELECT role_of(?,NULL)", [title]).fetchone()[0] == _role_of(title, None)
    assert con.execute("SELECT count(*) FROM dedup WHERE dom='mixed.example'").fetchone()[0] == 100
    assert (
        con.execute("SELECT count(*) FROM resolved WHERE dom='mixed.example'").fetchone()[0] == 10
    )
    assert (tmp_path / "considered_dom.csv").exists()
    con.close()
    from scripts import assemble_pattern_index

    artifact = tmp_path / "assembled.gz"
    subprocess.run([
        sys.executable, assemble_pattern_index.__file__, "--indir", str(tmp_path),
        "--out", str(artifact), "--qa", str(tmp_path / "qa.md"),
    ], check=True, capture_output=True)
    with gzip.open(artifact, "rt") as f:
        index = json.load(f)
    assert "mixed.example" not in index  # 10/100 must not ship as high confidence.
    assert index["_meta"]["normalization_version"] == "norm/1"
