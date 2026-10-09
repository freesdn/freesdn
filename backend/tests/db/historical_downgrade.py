"""Keep historical downgrade coverage separate from irreversible audit history."""

import sqlalchemy as sa
from alembic.config import Config
from alembic.script import ScriptDirectory

from tests.db.conftest import BACKEND_ROOT, run_alembic

# This is an explicit historical contract, not the application's current head.
# Revisions 029/030 deliberately prevent destructive audit-history downgrades.
HISTORICAL_HEAD = "028_remote_write_history"


def _snapshot(engine):
    """Read all owned fixture tables and their column/constraint/index catalogues."""
    with engine.connect().execution_options(isolation_level="REPEATABLE READ") as connection:
        tables = connection.execute(sa.text(
            "SELECT schemaname, tablename FROM pg_tables "
            "WHERE schemaname NOT IN ('pg_catalog','information_schema') "
            "ORDER BY schemaname, tablename"
        )).all()
        data = {}
        for schema, name in tables:
            table = sa.table(name, schema=schema)
            # SQLAlchemy quotes database identifiers; no interpolated row SQL.
            statement = sa.select(sa.cast(sa.func.to_jsonb(table.table_valued()), sa.Text))
            data[f"{schema}.{name}"] = sorted(connection.scalars(statement))
        columns = connection.execute(sa.text(
            "SELECT table_schema, table_name, column_name, ordinal_position, "
            "data_type, udt_schema, udt_name, is_nullable, column_default "
            "FROM information_schema.columns "
            "WHERE table_schema NOT IN ('pg_catalog','information_schema') "
            "ORDER BY table_schema, table_name, ordinal_position"
        )).all()
        constraints = connection.execute(sa.text(
            "SELECT n.nspname,c.relname,k.conname,k.contype,k.convalidated, "
            "pg_get_constraintdef(k.oid) FROM pg_constraint k "
            "JOIN pg_class c ON c.oid=k.conrelid "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname NOT IN ('pg_catalog','information_schema') "
            "ORDER BY n.nspname,c.relname,k.conname"
        )).all()
        indexes = connection.execute(sa.text(
            "SELECT schemaname,tablename,indexname,indexdef FROM pg_indexes "
            "WHERE schemaname NOT IN ('pg_catalog','information_schema') "
            "ORDER BY schemaname,tablename,indexname"
        )).all()
    return data, columns, constraints, indexes


def require_current_audit_protection(url, engine, target, record_property):
    """After legacy assertions, qualify the real CLI head upgrade/refusal too."""
    run_alembic(url, "upgrade", HISTORICAL_HEAD)
    historical = _snapshot(engine)[0]
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    head = ScriptDirectory.from_config(config).get_current_head()
    assert head == "030_audit_retention_state"
    run_alembic(url, "upgrade", "head")
    before = _snapshot(engine)
    for name, rows in historical.items():
        if name != "public.alembic_version":
            assert before[0][name] == rows, name
    assert set(before[0]) - set(historical) == {"audit.audit_chain_state"}
    with engine.connect() as connection:
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == head
    refused = run_alembic(url, "downgrade", target, expect_success=False)
    assert refused.returncode != 0
    assert "Refusing downgrade that discards audit retention state and owner snapshots" in refused.stderr
    assert _snapshot(engine) == before
    record_property("historical_downgrade_revision", HISTORICAL_HEAD)
    record_property("separate_current_audit_head", head)
    record_property("head_upgrade_preserved_all_historical_table_rows", True)
    record_property("head_downgrade_refused_and_all_rows_schema_preserved", True)
    record_property("head_snapshot_table_count", len(before[0]))
