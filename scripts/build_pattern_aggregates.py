"""Run the versioned pattern pipeline; export aggregate counts only.

Usage: python -m scripts.build_pattern_aggregates --corpus /root/corpus.duckdb
       --out /root/out --temp /root/ddtmp
Requires the optional DuckDB build dependency. The corpus is attached read-only.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from backend.core.company_pattern_index import register_normalization_udfs

PIPELINE = Path(__file__).with_name("company_pattern_pipeline.sql")


def prepare_connection(con):
    """Register exactly the functions used by the production SQL stages."""
    return register_normalization_udfs(con)


def run_pipeline(con, out: Path) -> str:
    version = prepare_connection(con)
    out.mkdir(parents=True, exist_ok=True)
    sql = PIPELINE.read_text(encoding="utf-8")
    sql = sql.replace("/root/out/", out.resolve().as_posix().replace("'", "''") + "/")
    con.execute(sql)
    (out / "build_identity.json").write_text(
        json.dumps({"normalization_version": version}), encoding="utf-8"
    )
    return version


def main():
    import duckdb

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--temp", type=Path, required=True)
    args = parser.parse_args()
    if not args.corpus.is_file():
        parser.error("corpus must be an existing DuckDB file")
    args.temp.mkdir(parents=True, exist_ok=True)
    with duckdb.connect() as con:
        con.execute("SET memory_limit='12GB'")
        con.execute("SET threads=8")
        con.execute("SET temp_directory=?", [str(args.temp.resolve())])
        path = args.corpus.resolve().as_posix().replace("'", "''")
        con.execute(f"ATTACH '{path}' AS c (READ_ONLY)")
        run_pipeline(con, args.out)


if __name__ == "__main__":
    main()
