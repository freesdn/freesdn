# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""``alembic upgrade head`` must land on the schema the ORM models declare.

Four schema-changing commits (1e0abdb0, a5dd43f3, 934099b6, 67353ef0, all 2026-06-21/22)
shipped zero migrations. Nothing caught it: a fresh install builds its schema with
``Base.metadata.create_all()`` so it silently got the new shape, CI builds its test
schema the same way (``scripts/migrate.py``), and ``alembic revision --autogenerate``
could not run at all because ``env.py`` pinned ``target_metadata=None``. Only an
UPGRADED appliance -- which runs the migrations and nothing else -- ended up with a
different schema than the code expects, and nothing in the repo ran the migrations.

Read :func:`test_upgraded_database_matches_the_model_metadata` as the gate. The
fresh-install variant below is deliberately weaker and says so.

The gate is only as good as the database it starts from. It starts from the frozen dump
in ``baseline_007_schema.sql``, never from a replay of ``001_initial`` -- 001 builds its
schema out of the live models, so replaying it would hand the "old appliance" every
model change made since, and the gate would confirm nothing.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
import sqlalchemy as sa
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy.engine import URL

from tests.db.conftest import (
    build_pre_fix_database,
    drop_scratch_database,
    make_scratch_database,
    run_alembic,
    scratch_engine,
)

_FRESH_DB = "freesdn_migchain_fresh"
_UPGRADED_DB = "freesdn_migchain_upgraded"
_PROBE_DB = "freesdn_migchain_probe"

# Objects the migration chain creates ON PURPOSE that no ORM model declares, plus one
# comparator artifact. Asserted as an EQUALITY, so anything new fails the test.
#
#   remove_index ix_devices_is_active / ix_devices_device_type /
#                ix_device_ports_is_enabled / ix_device_clients_is_online
#       001_initial.PERF_INDEXES, raw CREATE INDEX. These are REDUNDANT, not missing:
#       every one of the four columns is already indexed by the model (`index=True` on
#       Device.is_active / DevicePort.is_enabled / DeviceClient.is_online, and an
#       explicit Index("ix_devices_type") for device_type), so create_all builds an
#       equivalent index under its convention name and 001 builds a second one beside
#       it. An upgraded appliance therefore carries four duplicate indexes; a fresh one
#       does not. Verified 2026-08-29 by building both databases on Linux and diffing
#       pg_index by (table, columns) rather than by NAME -- by name these look like a
#       gap, by columns they are a duplicate. Left in place: dropping an index on a
#       live appliance is a migration with real cost and no correctness benefit.
#   remove_index ix_fabric_conn_org / ix_fabric_run_conn
#       Same shape. 005_fabric_connections creates both with raw CREATE INDEX while
#       Connection.organization_id and ConnectionRun.connection_id already carry
#       `index=True`, so these too are duplicates of a model-built index.
#
# NOT exempt, and deliberately so: the two COMPOSITE indexes 005 creates
# (ix_fabric_conn_org_enabled, ix_fabric_run_org_time) were the only entries in this
# list that named an index a fresh install genuinely did not have in any form. They are
# now declared in app/models/fabric.py __table_args__ under the same names, so both
# bring-up paths build them and neither belongs here. That divergence is what the same
# 2026-08-29 diff turned up: 645 indexes each side, previously differing by exactly
# those two rows.
#   add_constraint ...device_configs(device_id) / auto_backup_policies(organization_id)
#       Comparator artifact, NOT drift: both models declare `unique=True` on the column
#       AND a named UniqueConstraint on the same column, so the metadata carries two
#       objects where PostgreSQL has one. The one PostgreSQL holds is the explicitly
#       named uq_device_configs_device / uq_auto_backup_policies_org; what is reported
#       here is the convention-named twin the bare `unique=True` produced.
#       test_phantom_unique_constraints_are_physically_present proves the real one
#       exists, so this exemption cannot hide a genuinely missing constraint.
EXPECTED_DIFFS = frozenset(
    {
        "remove_index:devices.devices.ix_devices_is_active",
        "remove_index:devices.devices.ix_devices_device_type",
        "remove_index:devices.device_ports.ix_device_ports_is_enabled",
        "remove_index:devices.device_clients.ix_device_clients_is_online",
        "remove_index:fabric.connections.ix_fabric_conn_org",
        "remove_index:fabric.connection_runs.ix_fabric_run_conn",
        "add_constraint:unique:devices.device_configs(device_id)[uq_device_configs_device_id]",
        "add_constraint:unique:enterprise.auto_backup_policies(organization_id)"
        "[uq_auto_backup_policies_organization_id]",
    }
)

# The two double-declared unique constraints above, and the name PostgreSQL holds them
# under.
PHANTOM_CONSTRAINTS = (
    ("devices", "device_configs", "uq_device_configs_device", "device_id"),
    ("enterprise", "auto_backup_policies", "uq_auto_backup_policies_org", "organization_id"),
)


def _model_metadata() -> sa.MetaData:
    """Import every model module, mirroring ``scripts/migrate.py``'s canonical list."""
    import app.models  # noqa: F401
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

    return Base.metadata


def _describe(diff: Any) -> str:
    """Collapse one autogenerate diff to a stable, readable key."""
    kind = diff[0]
    if kind in {"add_index", "remove_index"}:
        index = diff[1]
        return f"{kind}:{index.table.schema}.{index.table.name}.{index.name}"
    if kind in {"add_constraint", "remove_constraint"}:
        constraint = diff[1]
        table = constraint.table
        cols = ",".join(c.name for c in constraint.columns)
        family = type(constraint).__name__.replace("Constraint", "").lower()
        # A CheckConstraint has no columns, so without the name its key would be an
        # unactionable "devices.poe_schedules()". Anonymous constraints keep name=None
        # and are identified by their column list alone.
        named = f"[{constraint.name}]" if isinstance(constraint.name, str) else ""
        return f"{kind}:{family}:{table.schema}.{table.name}({cols}){named}"
    if kind in {"add_table", "remove_table"}:
        table = diff[1]
        return f"{kind}:{table.schema}.{table.name}"
    if kind in {"add_column", "remove_column"}:
        return f"{kind}:{diff[1]}.{diff[2]}.{diff[3].name}"
    if kind.startswith("modify_"):
        return f"{kind}:{diff[1]}.{diff[2]}.{diff[3]}"
    return f"{kind}:{diff[1:]}"


def _drift(url: URL) -> set[str]:
    metadata = _model_metadata()
    engine = scratch_engine(url)
    try:
        with engine.connect() as conn:
            context = MigrationContext.configure(
                conn,
                opts={"compare_type": True, "include_schemas": True},
            )
            raw = compare_metadata(context, metadata)
    finally:
        engine.dispose()

    flat: list[Any] = []
    for diff in raw:
        # A multi-part change (modify_type + modify_nullable on one column) arrives as
        # a nested list.
        flat.extend(diff) if isinstance(diff, list) else flat.append(diff)
    return {_describe(d) for d in flat}


def _assert_matches_models(url: URL, what: str) -> None:
    actual = _drift(url)
    unexpected = actual - EXPECTED_DIFFS
    disappeared = EXPECTED_DIFFS - actual
    assert not unexpected, (
        f"{what} does not agree with the ORM models. A model changed without a "
        "migration -- add one under alembic/versions/, because an upgraded appliance "
        f"will NOT get the change otherwise: {sorted(unexpected)}"
    )
    assert not disappeared, (
        "An expected DB-only object is gone, so the exemption list in EXPECTED_DIFFS is "
        f"now wrong and would hide real drift: {sorted(disappeared)}"
    )


@pytest.fixture(scope="module")
def fresh_url(maintenance_engine: sa.Engine) -> Iterator[URL]:
    url = make_scratch_database(maintenance_engine, _FRESH_DB)
    try:
        run_alembic(url, "upgrade", "head")
        yield url
    finally:
        drop_scratch_database(maintenance_engine, _FRESH_DB)


@pytest.fixture(scope="module")
def upgraded_url(maintenance_engine: sa.Engine) -> Iterator[URL]:
    url = build_pre_fix_database(maintenance_engine, _UPGRADED_DB)
    try:
        run_alembic(url, "upgrade", "head")
        yield url
    finally:
        drop_scratch_database(maintenance_engine, _UPGRADED_DB)


def test_upgraded_database_matches_the_model_metadata(upgraded_url: URL) -> None:
    """THE gate: a pre-2026-06-22 schema, upgraded to head, must match the models.

    This is the case that was broken and that nothing tested. It fails if 008, 009 or
    010 is removed, reordered off the chain, or made inert (an early ``return``, a guard
    that always short-circuits), because the pre-fix schema this fixture builds is
    genuinely the old shape -- see ``LEGACY_SCHEMA_SQL``, which is verified against the
    live dev database rather than invented.

    It also fails for a model change made TODAY that ships no migration, which is the
    general case it exists for and which it could not see while the fixture replayed
    ``001_initial`` to build its baseline. Verified by adding a nullable column to
    ``voip.ring_groups`` with no migration: this test passed before the baseline was
    frozen and fails after, naming ``add_column:voip.ring_groups.<column>``.
    """
    _assert_matches_models(upgraded_url, "A pre-fix database upgraded to head")


@pytest.fixture
def probe_url(maintenance_engine: sa.Engine) -> Iterator[URL]:
    """An upgraded database the test below is allowed to damage, then throws away."""
    url = build_pre_fix_database(maintenance_engine, _PROBE_DB)
    try:
        run_alembic(url, "upgrade", "head")
        yield url
    finally:
        drop_scratch_database(maintenance_engine, _PROBE_DB)


def _a_plain_nullable_column() -> tuple[str, str, str]:
    """(schema, table, column) for a model column nothing else in the schema depends on.

    Chosen from the live metadata rather than hard-coded, so this does not rot the day
    somebody renames whichever column was named here.
    """
    for table in sorted(_model_metadata().tables.values(), key=lambda t: (t.schema or "", t.name)):
        indexed = {c.name for index in table.indexes for c in index.columns}
        constrained = {c.name for con in table.constraints for c in con.columns}
        for column in table.columns:
            if (
                column.nullable
                and not column.primary_key
                and not column.unique
                and not column.foreign_keys
                and column.name not in indexed
                and column.name not in constrained
            ):
                return table.schema or "public", table.name, column.name
    raise AssertionError("no unencumbered nullable column found in the model metadata")


def test_a_model_column_the_chain_never_creates_is_reported(probe_url: URL) -> None:
    """The gate must name a column the models declare and the upgrade path never adds.

    That is the general shape of the bug -- somebody edits a model and ships no
    migration -- and until the baseline was frozen the fixture could not produce it,
    because ``001_initial`` seeded the "old" database from the current models. Dropping
    a column from the upgraded database reproduces the same end state without needing a
    model edit, and asserts the failure is actionable rather than just non-empty.

    Mutations this catches: adding ``add_column`` to EXPECTED_DIFFS or otherwise
    exempting column drift; ``_describe``/``_drift`` dropping column diffs on the floor;
    ``_assert_matches_models`` computing ``unexpected`` but not asserting on it.
    """
    schema, table, column = _a_plain_nullable_column()
    engine = scratch_engine(probe_url)
    try:
        with engine.begin() as conn:
            conn.execute(sa.text(f'ALTER TABLE "{schema}"."{table}" DROP COLUMN "{column}"'))
    finally:
        engine.dispose()

    with pytest.raises(AssertionError) as exc:
        _assert_matches_models(probe_url, "A pre-fix database upgraded to head")

    assert f"add_column:{schema}.{table}.{column}" in str(exc.value)
    assert "add one under alembic/versions/" in str(exc.value)


def test_the_frozen_baseline_is_pinned(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regenerating the baseline dump must not be something that just happens.

    The fix for this detector was to stop rebuilding the "old appliance" database from
    the live models. The one-command way to undo that is to re-run pg_dump the next time
    the gate fails, which reads as maintenance in a diff. The pinned hash turns it into a
    deliberate edit of two files.

    Mutation this catches: deleting the hash comparison from ``baseline_schema_sql`` (or
    reducing it to a warning) -- the file could then be silently refreshed from current
    models and every test above would pass while gating nothing.
    """
    from tests.db import conftest as db_conftest

    assert db_conftest.baseline_schema_sql().lstrip().startswith("--")

    monkeypatch.setattr(db_conftest, "BASELINE_SCHEMA_SHA256", "0" * 64)
    with pytest.raises(AssertionError) as exc:
        db_conftest.baseline_schema_sql()
    assert "frozen" in str(exc.value)
    assert "BASELINE_SCHEMA_SHA256" in str(exc.value)


def test_fresh_database_matches_the_model_metadata(fresh_url: URL) -> None:
    """Weaker companion: ``upgrade head`` on an EMPTY database.

    Do not mistake this for a missing-migration gate. ``001_initial`` builds the schema
    with ``Base.metadata.create_all()`` off the live models, so on an empty database the
    chain agrees with the models by construction no matter what a later model commit
    does. What it does pin is the raw-SQL DDL in 001 and 005 (the exempted indexes) and
    that the chain runs to completion at all.
    """
    _assert_matches_models(fresh_url, "A fresh database built by the chain")


def test_alembic_autogenerate_is_wired_up(fresh_url: URL) -> None:
    """``env.py`` must hand its MetaData to the migration context.

    It used to pass ``target_metadata=None``, which makes Alembic refuse every
    autogenerate-based command -- so ``alembic revision --autogenerate`` and ``alembic
    check`` both died before doing any work, and the four un-migrated model commits had
    nothing that could report them.

    ``alembic check`` legitimately exits non-zero here (the EXPECTED_DIFFS above are
    real diffs), so what is asserted is that it got far enough to compare at all.
    """
    result = run_alembic(fresh_url, "check", expect_success=False)
    output = result.stdout + result.stderr
    assert "does not provide a MetaData object" not in output, (
        "alembic/env.py is not passing target_metadata to context.configure(), so "
        "autogenerate and `alembic check` cannot run:\n" + output
    )


def _declared_partial_indexes() -> list[tuple[str, str, str, bool, str]]:
    """(schema, table, index, unique, predicate) for every model index with a WHERE."""
    declared = []
    for table in _model_metadata().tables.values():
        for index in table.indexes:
            where = index.dialect_options.get("postgresql", {}).get("where")
            if where is None:
                continue
            declared.append(
                (table.schema or "public", table.name, index.name or "", index.unique, str(where))
            )
    return sorted(declared)


def _normalize(sql: str) -> str:
    return " ".join(sql.lower().replace("(", " ").replace(")", " ").split())


@pytest.mark.parametrize("which", ["upgraded", "fresh"])
def test_partial_indexes_really_are_partial(which: str, upgraded_url: URL, fresh_url: URL) -> None:
    """Every model index that declares ``postgresql_where`` must be partial in the DB.

    ``compare_metadata`` does not compare index predicates at all, so the test above
    passes on a database where ``ix_users_email`` is a FULL unique index -- which is
    precisely the bug 009 fixes and precisely what an appliance upgraded before
    2026-06-22 has. Without this assertion, 009 could be made inert and the drift test
    would only notice the leftover UNIQUE constraints, not the missing predicate.
    """
    url = upgraded_url if which == "upgraded" else fresh_url
    engine = scratch_engine(url)
    try:
        with engine.connect() as conn:
            for schema, table, name, unique, predicate in _declared_partial_indexes():
                row = conn.execute(
                    sa.text(
                        """
                        SELECT i.indisunique,
                               pg_get_expr(i.indpred, i.indrelid) AS predicate
                        FROM pg_index i
                        JOIN pg_class ic ON ic.oid = i.indexrelid
                        JOIN pg_namespace n ON n.oid = ic.relnamespace
                        WHERE n.nspname = :schema AND ic.relname = :name
                        """
                    ),
                    {"schema": schema, "name": name},
                ).fetchone()
                assert row is not None, f"{schema}.{table}: index {name} does not exist"
                assert row.indisunique == unique, (
                    f"{schema}.{name}: unique={row.indisunique}, model says unique={unique}"
                )
                assert row.predicate is not None, (
                    f"{schema}.{name} is a FULL index but the model declares "
                    f"postgresql_where={predicate!r}. On this database the identifier "
                    "stays taken after a soft delete and cannot be reused."
                )
                if "deleted_at is null" in _normalize(predicate):
                    assert "deleted_at is null" in _normalize(row.predicate), (
                        f"{schema}.{name} is partial on {row.predicate!r}, which does "
                        f"not include the soft-delete term the model declares: {predicate!r}"
                    )
    finally:
        engine.dispose()


def test_phantom_unique_constraints_are_physically_present(fresh_url: URL) -> None:
    """Prove the two exempted ``add_constraint`` diffs really are comparator artifacts.

    Without this, EXPECTED_DIFFS would be a licence to ignore a genuinely missing unique
    constraint on either table.
    """
    engine = scratch_engine(fresh_url)
    try:
        with engine.connect() as conn:
            for schema, table, name, column in PHANTOM_CONSTRAINTS:
                definition = conn.execute(
                    sa.text(
                        """
                        SELECT pg_get_constraintdef(con.oid)
                        FROM pg_constraint con
                        JOIN pg_class c ON c.oid = con.conrelid
                        JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = :schema
                          AND c.relname = :table
                          AND con.conname = :name
                          AND con.contype = 'u'
                        """
                    ),
                    {"schema": schema, "table": table, "name": name},
                ).scalar()
                assert definition is not None, (
                    f"{schema}.{table} has no unique constraint {name}; the "
                    "add_constraint exemption in EXPECTED_DIFFS is hiding real drift"
                )
                assert column in definition
    finally:
        engine.dispose()
