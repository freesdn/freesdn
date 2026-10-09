"""Real upgrades preserve ciphertext; unsafe/concurrent downgrades cannot cut it."""

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
import sqlalchemy as sa
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.orm import Session

from app.core.crypto import decrypt_credential, encrypt_credential
from app.models.core import Credential, Organization
from tests.db.conftest import (
    BACKEND_ROOT,
    build_pre_fix_database,
    drop_scratch_database,
    run_alembic,
    scratch_engine,
)
from tests.db.historical_downgrade import HISTORICAL_HEAD, require_current_audit_protection

OLD = "020_inapp_event_outbox"


def shape(engine):
    with engine.connect() as connection:
        return tuple(
            connection.execute(
                sa.text(
                    "SELECT data_type, character_maximum_length, is_nullable "
                    "FROM information_schema.columns WHERE table_schema='core' "
                    "AND table_name='credentials' AND column_name='snmp_community'"
                )
            ).one()
        )


def snapshot(engine):
    with engine.connect() as connection:
        return (
            connection.execute(sa.text("SELECT to_jsonb(c) FROM core.credentials c ORDER BY id"))
            .scalars()
            .all()
        )


def schema_identity(engine):
    with engine.connect() as connection:
        revision = connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
        indexes = connection.execute(sa.text(
            "SELECT tablename, indexname, indexdef FROM pg_indexes "
            "WHERE schemaname='core' AND tablename IN ('users','credentials') "
            "ORDER BY tablename, indexname",
        )).all()
    return revision, [tuple(row) for row in indexes]


def require_historical_head(revision):
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    assert revision == ScriptDirectory.from_config(config).get_revision(HISTORICAL_HEAD).revision


def seed(engine):
    encrypted = encrypt_credential("x" * 127)
    with Session(engine) as db:
        orgs = [Organization(name="Owned SNMP migration", slug=f"owned-snmp-{i}") for i in range(2)]
        db.add_all(orgs)
        db.flush()
        records = []
        for i, value in enumerate([None, "", encrypted, "legacy-plaintext", "é" * 255]):
            row = Credential(
                organization_id=orgs[i % 2].id,
                name=f"Preserve {i}",
                credential_type="snmp_community",
                snmp_community=value,
                encrypted_password=encrypt_credential("owned-other-secret"),
                options={"must": "survive"},
                is_active=i != 3,
                deleted_at=datetime.now(UTC) if i == 4 else None,
            )
            records.append(row)
        db.add_all(records)
        db.flush()
        identity = records[2].id
        db.commit()
    return identity, encrypted


@pytest.fixture
def legacy_snmp(maintenance_engine):
    name = "freesdn_snmp_migration"
    url = build_pre_fix_database(maintenance_engine, name)
    engine = scratch_engine(url)
    try:
        run_alembic(url, "upgrade", OLD)
        assert shape(engine) == ("character varying", 255, "YES")
        identity, encrypted = seed(engine)
        yield engine, url, identity, encrypted
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, name)


def test_upgrade_and_safe_downgrade_preserve_every_credential_column(legacy_snmp, record_property):
    engine, url, identity, encrypted = legacy_snmp
    before = snapshot(engine)
    run_alembic(url, "upgrade", HISTORICAL_HEAD)
    assert shape(engine) == ("text", None, "YES")
    assert snapshot(engine) == before
    run_alembic(url, "upgrade", HISTORICAL_HEAD)
    assert snapshot(engine) == before
    run_alembic(url, "downgrade", OLD)
    assert shape(engine) == ("character varying", 255, "YES")
    assert snapshot(engine) == before
    run_alembic(url, "upgrade", HISTORICAL_HEAD)
    assert shape(engine) == ("text", None, "YES")
    assert snapshot(engine) == before
    with Session(engine) as db:
        assert db.get(Credential, identity).snmp_community == encrypted
        assert decrypt_credential(encrypted) == "x" * 127
    require_current_audit_protection(url, engine, OLD, record_property)


@pytest.mark.parametrize("kind", ["live", "inactive", "deleted", "legacy-unicode"])
def test_unsafe_downgrade_preserves_bytes_and_revision(legacy_snmp, kind, request, record_property):
    engine, url, identity, _ = legacy_snmp
    run_alembic(url, "upgrade", HISTORICAL_HEAD)
    schema_before = schema_identity(engine)
    require_historical_head(schema_before[0])
    with Session(engine) as db:
        row = db.get(Credential, identity)
        row.snmp_community = (
            "é" * 256 if kind == "legacy-unicode" else encrypt_credential("🔑" * 512)
        )
        row.is_active = kind != "inactive"
        row.deleted_at = datetime.now(UTC) if kind == "deleted" else None
        db.commit()
    before = snapshot(engine)
    refusal = run_alembic(url, "downgrade", OLD, expect_success=False)
    assert refusal.returncode != 0 and "SNMP credential downgrade refused" in refusal.stderr
    assert shape(engine) == ("text", None, "YES")
    assert snapshot(engine) == before
    schema_after = schema_identity(engine)
    request.node.user_properties.extend([
        ("schema_revision_before_refused_downgrade", schema_before[0]),
        ("schema_revision_after_refused_downgrade", schema_after[0]),
        ("credential_and_user_indexes_preserved", schema_after[1] == schema_before[1]),
    ])
    with engine.connect() as connection:
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == schema_before[0]
    assert schema_after == schema_before
    require_current_audit_protection(url, engine, OLD, record_property)


def test_downgrade_waits_for_writer_then_checks_committed_value(legacy_snmp, request, record_property):
    engine, url, identity, _ = legacy_snmp
    run_alembic(url, "upgrade", HISTORICAL_HEAD)
    schema_before = schema_identity(engine)
    require_historical_head(schema_before[0])
    value = encrypt_credential("x" * 512)
    with ThreadPoolExecutor(max_workers=1) as pool:
        with engine.begin() as writer:
            writer.execute(
                sa.text("UPDATE core.credentials SET snmp_community=:v WHERE id=:id"),
                {"v": value, "id": identity},
            )
            future = pool.submit(run_alembic, url, "downgrade", OLD, expect_success=False)
            deadline = time.monotonic() + 15
            waiting = False
            while time.monotonic() < deadline:
                with engine.connect() as observer:
                    waiting = observer.scalar(
                        sa.text(
                            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE "
                            "datname=current_database() AND wait_event_type='Lock' "
                            "AND query LIKE 'LOCK TABLE core.credentials%')"
                        )
                    )
                if waiting or future.done():
                    break
                time.sleep(0.05)
            assert waiting and not future.done(), "Downgrade did not lock before inspecting values"
        refusal = future.result(timeout=30)
    assert refusal.returncode != 0 and "SNMP credential downgrade refused" in refusal.stderr
    assert shape(engine) == ("text", None, "YES")
    schema_after = schema_identity(engine)
    request.node.user_properties.extend([
        ("schema_revision_before_refused_downgrade", schema_before[0]),
        ("schema_revision_after_refused_downgrade", schema_after[0]),
        ("credential_and_user_indexes_preserved", schema_after[1] == schema_before[1]),
    ])
    with Session(engine) as db:
        assert db.get(Credential, identity).snmp_community == value
        assert decrypt_credential(value) == "x" * 512
        assert db.scalar(sa.text("SELECT version_num FROM alembic_version")) == schema_before[0]
    assert schema_after == schema_before
    require_current_audit_protection(url, engine, OLD, record_property)
