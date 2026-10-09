# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Smart migration script for fresh vs existing databases.

``001_initial`` is a consolidated baseline that builds the whole schema with
``Base.metadata.create_all()`` off the live ORM models. It is NOT the only
revision any more -- alembic/versions/ has carried incremental migrations on top
of it since 002, and every schema change needs one.

Strategy:
  - Fresh DB  → create_all() + alembic stamp head   (full schema, zero migrations)
  - Existing  → keep the current known head or upgrade a known older revision
  - Ambiguous → refuse missing, multiple or unrecognized revision metadata

Know what the fresh path costs: it takes its schema straight from the models and
stamps, so running this script proves NOTHING about the migration chain. CI
bootstrapped its test schema with it too, which is how four schema-changing
commits (1e0abdb0, a5dd43f3, 934099b6, 67353ef0) merged green having shipped no
migration at all -- only an UPGRADED appliance, the one path nothing ran, ended
up with a schema the code did not expect. The chain is now executed for real by
tests/db/, which .github/workflows/ci.yml runs as its own must-not-skip step.
That step is the gate; this script is not a substitute for it.

This script is fully synchronous to avoid ``asyncio.run()`` conflicts when
invoked from shell entrypoints that may already have an event loop.
"""

import os
import re
import sys
import traceback

# Ensure /app is on Python path (matches alembic behavior)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alembic.config import Config
from sqlalchemy import create_engine, text

from alembic import command
from scripts.migration_lock import migration_lock


def _get_sync_url() -> str:
    """Convert the async DATABASE_URL to a synchronous psycopg3 URL."""
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        # Fallback: try importing settings (may fail if deps missing)
        from app.core.config import settings

        url = str(settings.DATABASE_URL)
    # asyncpg → psycopg (sync driver, psycopg3)
    url = re.sub(r"postgresql\+asyncpg://", "postgresql+psycopg://", url)
    return url


def _is_fresh_db(engine) -> bool:
    """Bootstrap only an unversioned database without user relations.

    Missing migration metadata does not establish an empty database. In
    particular, create_all does not add missing columns to restored tables;
    stamping such a database to head would silently skip required upgrades.
    The caller holds the startup migration lock throughout this check and DDL.
    """
    with engine.connect() as conn:
        has_revision_table = conn.scalar(
            text(
                "SELECT EXISTS ("
                "  SELECT 1 FROM information_schema.tables "
                "  WHERE table_name = 'alembic_version'"
                ")"
            )
        )
        if has_revision_table:
            return False
        has_user_relations = conn.scalar(
            text(
                "SELECT EXISTS ("
                "  SELECT 1 FROM pg_catalog.pg_class AS relation "
                "  JOIN pg_catalog.pg_namespace AS namespace "
                "    ON namespace.oid = relation.relnamespace "
                "  WHERE relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') "
                "    AND namespace.nspname <> 'information_schema' "
                "    AND left(namespace.nspname, 3) <> 'pg_' "
                "    AND NOT EXISTS ("
                "      SELECT 1 FROM pg_catalog.pg_depend AS dependency "
                "      WHERE dependency.classid = 'pg_catalog.pg_class'::regclass "
                "        AND dependency.objid = relation.oid "
                "        AND dependency.objsubid = 0 "
                "        AND dependency.refclassid = 'pg_catalog.pg_extension'::regclass "
                "        AND dependency.deptype = 'e'"
                "    )"
                ")"
            )
        )
        if has_user_relations:
            raise RuntimeError(
                "Refusing to initialize a non-empty database without migration metadata. "
                "Preserve the database and restore its verified migration history; "
                "do not stamp it to head or delete existing objects to bypass this guard."
            )
        return True


def _create_all(connection) -> None:
    """Create any missing schemas + tables from the live ORM models.

    Idempotent: create_all only CREATES missing tables — it never alters an
    existing table (so it won't add a missing COLUMN to a table that already
    exists) and never touches data. Use only after the empty-database guard;
    it is not a replacement for incremental upgrades of existing schemas.
    """
    # Import every model module so all tables register on Base.metadata.
    # We only need the import side-effect (registration); order is irrelevant.
    # NOTE: this list MUST cover every module that owns tables — a module whose
    # models aren't imported here silently gets no tables on a fresh DB.
    import app.models  # noqa: F401  core + cross-cutting (incl. fabric.connections)
    import app.modules.access_control.models  # noqa: F401
    import app.modules.ai.models  # noqa: F401
    import app.modules.backup.models  # noqa: F401
    import app.modules.cameras.models  # noqa: F401
    import app.modules.collector.models  # noqa: F401
    import app.modules.firewall.models  # noqa: F401
    import app.modules.gateway.models  # noqa: F401
    import app.modules.hypervisor.models  # noqa: F401
    import app.modules.network.models  # noqa: F401
    import app.modules.voip.models  # noqa: F401
    from app.db.base import Base

    # Derive the schema set straight from the registered metadata rather than a
    # hand-maintained list. The old static list silently missed `fabric` (added
    # after it was written), so `create_all` tried to build `fabric.connections`
    # in a schema that was never created and every fresh-DB install crashed.
    # Deriving from metadata means a new module that declares a new schema is
    # picked up automatically — this class of drift can't recur.
    schemas = sorted({t.schema for t in Base.metadata.tables.values() if t.schema})

    for schema in schemas:
        connection.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema}"))
    Base.metadata.create_all(bind=connection)
    print(f"Schema build: created any missing tables across {len(schemas)} schemas")


def _create_all_and_stamp(engine) -> None:
    """Create all tables from models and stamp alembic to head (fresh DB)."""
    # Schema creation and its revision must commit together. If startup dies
    # before stamping, a committed schema without history correctly fails the
    # nonempty-database guard and cannot be retried as a fresh installation.
    # Existing revision upgrades keep their separate migration/autocommit path.
    with engine.begin() as connection:
        _create_all(connection)
        alembic_cfg = Config("alembic.ini")
        alembic_cfg.attributes["connection"] = connection
        command.stamp(alembic_cfg, "head")
    print("Fresh DB: created all tables and stamped to head")


def _get_current_revision(engine) -> str:
    """Require one nonempty revision; do not guess after partial restores."""
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT version_num FROM alembic_version LIMIT 2")).all()
    if (
        len(rows) != 1
        or not isinstance(rows[0][0], str)
        or not rows[0][0]
        or rows[0][0] != rows[0][0].strip()
    ):
        raise RuntimeError(
            "Refusing database migration with missing or ambiguous revision metadata. "
            "Preserve the database and restore its verified migration history; "
            "do not select a revision or stamp to head by guesswork."
        )
    return rows[0][0]


def _upgrade_head() -> None:
    """Run standard alembic upgrade head."""
    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")
    print("Existing DB: alembic upgrade head completed")


def _stamp_head() -> None:
    """Stamp alembic to head without running migrations."""
    alembic_cfg = Config("alembic.ini")
    command.stamp(alembic_cfg, "head")


def main() -> None:
    sync_url = _get_sync_url()
    engine = create_engine(sync_url)
    try:
        with migration_lock(engine):
            fresh = _is_fresh_db(engine)
            if fresh:
                print("Detected fresh database — using create_all + stamp approach")
                _create_all_and_stamp(engine)
            else:
                # Existing DB — check if revision needs transition to consolidated
                from alembic.script import ScriptDirectory

                alembic_cfg = Config("alembic.ini")
                script = ScriptDirectory.from_config(alembic_cfg)
                head_rev = script.get_current_head()
                current_rev = _get_current_revision(engine)

                if current_rev == head_rev:
                    print(f"Schema already at head ({head_rev}) — nothing to do")
                elif current_rev not in {r.revision for r in script.walk_revisions()}:
                    # An unknown value may be a future, divergent or incomplete
                    # schema. Re-stamping it to 001 and replaying migrations can
                    # modify user data before discovering incompatibility.
                    raise RuntimeError(
                        "Refusing database migration from an unrecognized revision. "
                        "Use its matching release or a separately reviewed legacy migration; "
                        "preserve the existing schema and revision metadata."
                    )
                else:
                    print("Detected existing database — running alembic upgrade head")
                    _upgrade_head()
    finally:
        engine.dispose()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        traceback.print_exc(file=sys.stderr)
        print(f"Migration failed: {e}", file=sys.stderr)
        sys.exit(1)
