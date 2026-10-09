# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Throwaway-database machinery for the migration-chain tests.

Each test here needs a database that ``alembic upgrade head`` built from empty, which
is not what the rest of the suite runs against. So each one gets its own scratch
database on the same PostgreSQL server the suite is already pointed at, and drops it
again afterwards. Nothing touches the suite's own database.

The "upgraded appliance" database is NOT built by running the chain from 001. It is
restored from :data:`BASELINE_SCHEMA_PATH`, a checked-in schema-only dump. See the
comment on :data:`BASELINE_REVISION` for why that distinction is the whole point.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import URL, make_url

BACKEND_ROOT = Path(__file__).resolve().parents[2]

# Private/public suites and pytest workers may share one PostgreSQL server. Never
# let one process recreate or drop another process's migration fixture database.
_SCRATCH_RUN_ID = uuid4().hex[:12]


def _scratch_name(name: str) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9_]*", name):
        raise ValueError("scratch database names must be lowercase SQL identifiers")
    digest = hashlib.sha256(name.encode()).hexdigest()[:8]
    return f"{name[:40]}_{digest}_{_SCRATCH_RUN_ID}"


# The revision the frozen baseline dump is stamped at: the last one that predates the
# four un-migrated model commits of 2026-06-21/22.
#
# The baseline used to be built by running `alembic upgrade 007` here, and that made the
# whole fixture circular. 001_initial carries no DDL -- it calls
# ``Base.metadata.create_all()`` against the LIVE ORM models -- so replaying 001..007
# produces TODAY'S schema, not a 2026-06 one. LEGACY_SCHEMA_SQL then rewound exactly
# four known June defects and nothing else, which means any model change made after this
# file was written was already present in the "pre-fix" database before the fixture
# upgraded it. The comparison against the models then passed by construction while a
# real upgraded appliance, which only ever runs migrations, would never receive that
# change. The detector could not see the class of bug it was written for.
#
# So the baseline is now an immutable artifact: a schema-only dump captured once and
# checked in. Nothing regenerates it at test time. A model change with no migration is
# absent from it, ``alembic upgrade head`` does not add it, and the drift shows up.
BASELINE_REVISION = "007_widen_pending_status"

#: The frozen schema itself. Its own header documents the capture recipe.
BASELINE_SCHEMA_PATH = Path(__file__).with_name("baseline_007_schema.sql")

#: sha256 of BASELINE_SCHEMA_PATH with CRLF normalised to LF.
#:
#: This is a ratchet, not a checksum for corruption. The one way to silently undo the
#: fix above is to regenerate the dump from current models the next time this test
#: fails -- which restores the circularity in a single command and looks like routine
#: maintenance in the diff. Pinning the hash means regenerating is a deliberate,
#: reviewable two-file change, and the .sql header states the only condition under
#: which it is legitimate (a release boundary, with every model change already
#: migrated).
BASELINE_SCHEMA_SHA256 = "d34e400ca5acce752465886dbf5e764f3480eb8ec7efb208d4f271c0bf72a93e"

# Rewind the frozen baseline to the shape those five commits left behind on a database
# that was NOT rebuilt from the models. Verified against the maintainer's live dev
# database (stamped 007): every index definition and every pg_constraint row below
# matches it exactly, so this is a reproduction of a real appliance, not a guess.
#
#   is_active          -- a5dd43f3 changed String(10) -> Boolean, no migration
#   the five indexes   -- 1e0abdb0 made them partial + dropped unique=True, no migration
#   the XOR constraint -- 67353ef0 added it, no migration
#   the review UNIQUE  -- 934099b6 added it, no migration
#
# Now exhaustive for the 2026-06-21/22 drift. The review UNIQUE was the one left out
# when 008-010 landed, because repairing it means deciding what to do with duplicate
# reviews; 011 makes that decision (add where there are none, refuse to delete anyone's
# review where there are) so the rewind belongs here too. Confirmed absent on the live
# dev database: core.plugin_reviews carries only pk_plugin_reviews and the two
# non-unique column indexes.
LEGACY_SCHEMA_SQL = """
ALTER TABLE events.event_subscriptions
    ALTER COLUMN is_active TYPE character varying(10)
    USING (CASE WHEN is_active THEN 'true' ELSE 'false' END);

DROP INDEX core.ix_users_email;
DROP INDEX core.ix_users_username;
DROP INDEX core.ix_organizations_slug;
DROP INDEX core.ix_sites_slug;
DROP INDEX agents.ix_remote_agents_agent_key;
CREATE UNIQUE INDEX ix_users_email ON core.users (email);
CREATE UNIQUE INDEX ix_users_username ON core.users (username);
CREATE UNIQUE INDEX ix_organizations_slug ON core.organizations (slug);
CREATE UNIQUE INDEX ix_sites_slug ON core.sites (organization_id, slug);
CREATE UNIQUE INDEX ix_remote_agents_agent_key ON agents.remote_agents (agent_key);
ALTER TABLE core.users ADD CONSTRAINT uq_users_email UNIQUE (email);
ALTER TABLE core.organizations ADD CONSTRAINT uq_organizations_slug UNIQUE (slug);
ALTER TABLE agents.remote_agents ADD CONSTRAINT uq_remote_agents_agent_key UNIQUE (agent_key);

ALTER TABLE devices.poe_schedules
    DROP CONSTRAINT ck_poe_schedules_ck_poe_schedule_xor_target;

ALTER TABLE core.plugin_reviews
    DROP CONSTRAINT uq_plugin_review_user_plugin;
"""


def configured_url() -> URL:
    """The async URL the suite is pointed at, as a SQLAlchemy URL."""
    raw = os.environ.get("DATABASE_URL")
    if not raw:
        from app.core.config import settings

        raw = str(settings.DATABASE_URL)
    return make_url(raw)


def _sync(url: URL) -> URL:
    return url.set(drivername="postgresql+psycopg")


@pytest.fixture(scope="session")
def maintenance_engine() -> Iterator[sa.Engine]:
    """Engine on the ``postgres`` maintenance database, in AUTOCOMMIT.

    CREATE/DROP DATABASE cannot run inside a transaction block.
    """
    engine = sa.create_engine(
        _sync(configured_url()).set(database="postgres"),
        isolation_level="AUTOCOMMIT",
        poolclass=sa.pool.NullPool,
        # Without this, a host that silently drops the SYN (no listener behind a
        # firewall, a stopped container) leaves the whole suite hanging on connect
        # instead of reaching the skip below.
        connect_args={"connect_timeout": 10},
    )
    try:
        with engine.connect() as conn:
            conn.execute(sa.text("SELECT 1"))
    except sa.exc.OperationalError as exc:  # pragma: no cover - environment-dependent
        engine.dispose()
        pytest.skip(
            "migration-chain tests need a reachable PostgreSQL server "
            f"(DATABASE_URL={configured_url().render_as_string(hide_password=True)}): {exc}"
        )
    yield engine
    engine.dispose()


def make_scratch_database(engine: sa.Engine, name: str) -> URL:
    """Recreate this process's database for logical ``name`` and return its URL."""
    name = _scratch_name(name)
    with engine.connect() as conn:
        conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
    return configured_url().set(database=name)


def drop_scratch_database(engine: sa.Engine, name: str) -> None:
    name = _scratch_name(name)
    with engine.connect() as conn:
        conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))


def run_alembic(
    url: URL, *args: str, expect_success: bool = True
) -> subprocess.CompletedProcess[str]:
    """Run the real Alembic CLI against ``url``, the way an operator upgrade does.

    A subprocess rather than ``alembic.command``: ``env.py`` calls ``asyncio.run()``,
    which cannot run inside the event loop pytest-asyncio has open.
    """
    env = dict(os.environ)
    # Pytest may encode a binary parameter's full value in this diagnostic label.
    # Keep the parent test identity intact; a migration child is not a pytest case
    # and must not inherit an environment entry beyond the OS exec limit.
    env.pop("PYTEST_CURRENT_TEST", None)
    env["DATABASE_URL"] = url.render_as_string(hide_password=False)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(BACKEND_ROOT), *([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])]
    )
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "alembic", *args],
        cwd=BACKEND_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if expect_success and result.returncode != 0:
        raise AssertionError(
            f"alembic {' '.join(args)} failed ({result.returncode})\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )
    return result


def scratch_engine(url: URL) -> sa.Engine:
    return sa.create_engine(_sync(url), poolclass=sa.pool.NullPool)


def baseline_schema_sql() -> str:
    """The frozen dump, after asserting it is the one this module was written against."""
    text = BASELINE_SCHEMA_PATH.read_text(encoding="utf-8")
    digest = hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()
    if digest != BASELINE_SCHEMA_SHA256:
        raise AssertionError(
            f"{BASELINE_SCHEMA_PATH.name} has changed (sha256 {digest}, expected "
            f"{BASELINE_SCHEMA_SHA256}).\n"
            "This file is the frozen 'what an already-deployed appliance has on disk' "
            "schema. Regenerating it from current models is how the missing-migration "
            "gate silently stops working -- see the header of the .sql file. If the "
            "refresh really is intended (a release boundary, every model change already "
            "carried by a migration on the chain), update BASELINE_SCHEMA_SHA256 in the "
            "same commit."
        )
    return text


def _load_baseline_schema(url: URL) -> None:
    """Restore the frozen dump into an empty scratch database."""
    sql = baseline_schema_sql()
    engine = scratch_engine(url)
    raw = engine.raw_connection()
    try:
        cursor = raw.cursor()
        # The raw DBAPI cursor with NO parameters, deliberately: psycopg only treats
        # '%' as a placeholder introducer once parameters are bound, and one column
        # COMMENT in the dump carries a SQL LIKE pattern ('EAP%'). Passing the dump
        # through SQLAlchemy's exec_driver_sql (which binds an empty parameter set)
        # fails on that line. No parameters also means the simple query protocol, so
        # the whole multi-statement dump goes in one round trip.
        cursor.execute(sql)
        cursor.execute(
            f"INSERT INTO public.alembic_version (version_num) VALUES ('{BASELINE_REVISION}')"
        )
        raw.commit()
    finally:
        raw.close()
        engine.dispose()


def build_pre_fix_database(engine: sa.Engine, name: str) -> URL:
    """Create a scratch database in the shape an appliance upgraded before the fixes has.

    Restores the frozen :data:`BASELINE_SCHEMA_PATH` dump, stamps ``alembic_version`` at
    :data:`BASELINE_REVISION`, and rewinds the four un-migrated June 2026 model commits,
    so the database genuinely predates 008-011 -- the exact state the reporter measured
    on the live dev database.

    It deliberately does NOT run the chain to get here. ``001_initial`` builds its schema
    from the live models, so replaying it would seed this database with every later
    model change and the drift test would have nothing left to find.
    """
    url = make_scratch_database(engine, name)
    _load_baseline_schema(url)
    scratch = scratch_engine(url)
    try:
        with scratch.begin() as conn:
            conn.execute(sa.text(LEGACY_SCHEMA_SQL))
    finally:
        scratch.dispose()
    return url
