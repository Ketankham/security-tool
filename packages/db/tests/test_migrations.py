"""The migration chain against a scratch database: upgrade to head, step the
newest revision down and up again, and check that the models and the
migrations agree (``alembic check``). Uses its own throwaway database, so it
never touches the one the other tests use. Skipped when Postgres is not
reachable or the role may not create a database."""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

psycopg = pytest.importorskip("psycopg")

ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"
SYNC_URL = os.environ.get(
    "DATABASE_URL_SYNC", "postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinel"
)
HEAD = "a7c9e5f1d3b6"
PREVIOUS = "f6b8d4e0c2a5"


def _dsn(database: str) -> str:
    base = SYNC_URL.replace("postgresql+psycopg://", "postgresql://")
    return base.rsplit("/", 1)[0] + "/" + database


@pytest.fixture
def scratch_db():
    name = f"sentinel_migtest_{uuid.uuid4().hex[:8]}"
    try:
        with psycopg.connect(_dsn("postgres"), autocommit=True) as admin:
            admin.execute(f'create database "{name}"')
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"cannot create a scratch database: {exc}")
    try:
        yield name
    finally:
        with psycopg.connect(_dsn("postgres"), autocommit=True) as admin:
            admin.execute(f'drop database if exists "{name}" with (force)')


def alembic(database: str, *args: str) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "DATABASE_URL_SYNC": SYNC_URL.rsplit("/", 1)[0] + "/" + database,
    }
    return subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ALEMBIC_INI), *args],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def _columns(database: str, table: str) -> dict[str, tuple[str, str, str | None]]:
    with psycopg.connect(_dsn(database)) as conn:
        rows = conn.execute(
            "select column_name, data_type, is_nullable, column_default from "
            "information_schema.columns where table_name = %s",
            (table,),
        ).fetchall()
    return {r[0]: (r[1], r[2], r[3]) for r in rows}


def _revision(database: str) -> str | None:
    with psycopg.connect(_dsn(database)) as conn:
        row = conn.execute("select version_num from alembic_version").fetchone()
    return row[0] if row else None


def test_the_chain_has_one_head_and_it_is_this_revision():
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ALEMBIC_INI), "heads"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
        env={**os.environ, "DATABASE_URL_SYNC": SYNC_URL},
    )
    assert result.returncode == 0, result.stderr
    heads = [line.split()[0] for line in result.stdout.splitlines() if "(head)" in line]
    assert heads == [HEAD]


def test_upgrade_downgrade_upgrade_and_check_are_clean(scratch_db):
    up = alembic(scratch_db, "upgrade", "head")
    assert up.returncode == 0, up.stderr
    assert _revision(scratch_db) == HEAD

    ports = _columns(scratch_db, "port_services")
    assert {
        "id", "created_at", "updated_at", "scan_id", "tool_run_id", "ip", "hosts", "port",
        "protocol", "state", "service", "product", "version", "extra_info", "confidence",
        "scripts", "cdn", "found_by",
    } == set(ports)  # fmt: skip
    assert ports["hosts"][0] == "jsonb" and ports["scripts"][0] == "jsonb"
    assert ports["scan_id"][1] == "NO" and ports["tool_run_id"][1] == "YES"
    assert ports["service"][1] == "YES" and ports["confidence"][1] == "NO"
    tool_runs = _columns(scratch_db, "tool_runs")
    assert tool_runs["extra_output"][1] == "NO" and "''" in (tool_runs["extra_output"][2] or "")
    assert tool_runs["extra_output_label"][1] == "YES"

    down = alembic(scratch_db, "downgrade", "-1")
    assert down.returncode == 0, down.stderr
    assert _revision(scratch_db) == PREVIOUS
    assert _columns(scratch_db, "port_services") == {}
    assert "extra_output" not in _columns(scratch_db, "tool_runs")
    assert "extra_output_label" not in _columns(scratch_db, "tool_runs")

    again = alembic(scratch_db, "upgrade", "head")
    assert again.returncode == 0, again.stderr
    assert _revision(scratch_db) == HEAD

    check = alembic(scratch_db, "check")
    assert check.returncode == 0, check.stdout + check.stderr
    assert "No new upgrade operations detected" in check.stdout + check.stderr


def test_existing_tool_runs_get_an_empty_extra_output_when_the_column_is_added(scratch_db):
    assert alembic(scratch_db, "upgrade", PREVIOUS).returncode == 0
    with psycopg.connect(_dsn(scratch_db), autocommit=True) as conn:
        org = conn.execute(
            "insert into organizations (id, name, slug, wrapped_data_key, plan, created_at, "
            "updated_at) values (gen_random_uuid(), 'o', 'o', 'k', 'free_scan', now(), now()) "
            "returning id"
        ).fetchone()
        target = conn.execute(
            "insert into targets (id, organization_id, root_domain, display_name, "
            "authorization_accepted, is_production, ownership_verified, created_at, updated_at) "
            "values (gen_random_uuid(), %s, 'a.test', 'a', false, true, false, now(), now()) "
            "returning id",
            (org[0],),
        ).fetchone()
        scan = conn.execute(
            "insert into scans (id, target_id, state, triggered_by, is_degraded, "
            "degraded_reasons, llm_token_budget, llm_tokens_used, created_at, updated_at) "
            "values (gen_random_uuid(), %s, 'QUEUED', 'manual', false, '[]'::jsonb, 0, 0, now(), "
            "now()) returning id",
            (target[0],),
        ).fetchone()
        conn.execute(
            "insert into tool_runs (id, scan_id, seq, phase, tool, status, command, timed_out, "
            "results_count, stdout, stderr, stdout_truncated, stderr_truncated, created_at, "
            "updated_at) values (gen_random_uuid(), %s, 1, 'recon', 'httpx', 'ok', '', false, 0, "
            "'', '', false, false, now(), now())",
            (scan[0],),
        )
    assert alembic(scratch_db, "upgrade", "head").returncode == 0
    with psycopg.connect(_dsn(scratch_db)) as conn:
        row = conn.execute("select extra_output, extra_output_label from tool_runs").fetchone()
    assert row == ("", None)
