# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Smart migration script for fresh vs existing databases.

All migrations have been consolidated into a single ``001_initial``
revision.  ``Base.metadata.create_all()`` creates every table from the
current ORM models, so a fresh install never needs incremental migrations.

Strategy:
  - Fresh DB  → create_all() + alembic stamp head   (full schema, zero migrations)
  - Existing  → stamp head if schema already current (handles old revision IDs)
              → alembic upgrade head otherwise        (future incremental migrations)

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
    """Return True if the database has no alembic_version table."""
    with engine.connect() as conn:
        result = conn.execute(
            text(
                "SELECT EXISTS ("
                "  SELECT 1 FROM information_schema.tables "
                "  WHERE table_name = 'alembic_version'"
                ")"
            )
        )
        return not result.scalar()


def _create_all(engine) -> None:
    """Create any missing schemas + tables from the live ORM models.

    Idempotent: create_all only CREATES missing tables — it never alters an
    existing table (so it won't add a missing COLUMN to a table that already
    exists) and never touches data. Used both for a fresh DB and to backfill
    whole tables an old pre-consolidation DB predates, before running the
    column-adding migrations.
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

    with engine.begin() as conn:
        for schema in schemas:
            conn.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema}"))
        Base.metadata.create_all(bind=conn)
    print(f"Schema build: created any missing tables across {len(schemas)} schemas")


def _create_all_and_stamp(engine) -> None:
    """Create all tables from models and stamp alembic to head (fresh DB)."""
    _create_all(engine)
    alembic_cfg = Config("alembic.ini")
    command.stamp(alembic_cfg, "head")
    print("Fresh DB: created all tables and stamped to head")


def _get_current_revision(engine) -> str | None:
    """Return the current alembic revision, or None if not stamped."""
    with engine.connect() as conn:
        result = conn.execute(text("SELECT version_num FROM alembic_version LIMIT 1"))
        row = result.fetchone()
        return row[0] if row else None


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
            elif current_rev and current_rev not in {r.revision for r in script.walk_revisions()}:
                # Old revision from pre-consolidation era — directly update
                # the alembic_version table.  We cannot use command.stamp()
                # because Alembic tries to resolve the *current* DB revision
                # against the script directory and the old files are gone.
                # Re-stamp to the consolidated BASELINE (001_initial), not head:
                # the pre-consolidation DB has all the pre-squash tables but NOT
                # any column added by post-baseline migrations (002/003 ...), so we
                # must still RUN those after re-stamping. Stamp to 001_initial, then
                # `alembic upgrade head` applies 002/003 (their ADD COLUMN IF NOT
                # EXISTS is a safe no-op for anything already present). Stamping
                # straight to head here would SKIP 002/003 and leave the new
                # columns missing → ORM 500s on VPN connections.
                baseline = "001_initial"
                print(f"Detected pre-consolidation revision ({current_rev}) — backfilling tables, re-stamping to {baseline}, then upgrading")
                # First backfill any whole tables this old DB predates (e.g. a DB
                # stamped before vpn.vpn_connections existed) — create_all only adds
                # MISSING tables. THEN stamp to baseline and run 002/003, which ALTER
                # existing tables to add new columns (ADD COLUMN IF NOT EXISTS, so a
                # no-op for anything create_all just built).
                _create_all(engine)
                with engine.begin() as conn:
                    conn.execute(text("DELETE FROM alembic_version"))
                    conn.execute(
                        text("INSERT INTO alembic_version (version_num) VALUES (:rev)"),
                        {"rev": baseline},
                    )
                _upgrade_head()
                print("Existing DB: backfilled tables, re-stamped to baseline, upgraded to head")
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
