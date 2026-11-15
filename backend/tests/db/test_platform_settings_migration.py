# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Migration 033 copies the read-only switch from Valkey into Postgres.

Runs the real Alembic CLI against a scratch database upgraded from the frozen
baseline, with the switch set in the suite's Valkey the way a pre-26.12 install
stored it, and checks the upgrade keeps the operator's choice.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
import sqlalchemy as sa
from alembic.config import Config
from alembic.script import ScriptDirectory

from tests.db.conftest import (
    BACKEND_ROOT,
    build_pre_fix_database,
    drop_scratch_database,
    run_alembic,
    scratch_engine,
)

REVISION = "033_platform_settings"
LEGACY_KEY = "freesdn:config:adapter_read_only"


def _previous_revision() -> str:
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    down = ScriptDirectory.from_config(config).get_revision(REVISION).down_revision
    assert isinstance(down, str)
    return down


@pytest.fixture
def valkey() -> Iterator[object]:
    from app.core.redis_client import get_sync_redis

    client = get_sync_redis(decode_responses=True, socket_timeout=2, socket_connect_timeout=2)
    try:
        saved = client.get(LEGACY_KEY)
    except Exception as exc:  # pragma: no cover - environment-dependent
        pytest.skip(f"no Valkey reachable: {exc}")
    yield client
    if saved is None:
        client.delete(LEGACY_KEY)
    else:
        client.set(LEGACY_KEY, saved)


@pytest.fixture
def at_previous(maintenance_engine):
    name = "freesdn_platform_settings_033"
    url = build_pre_fix_database(maintenance_engine, name)
    engine = scratch_engine(url)
    try:
        run_alembic(url, "upgrade", _previous_revision())
        yield engine, url
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, name)


def _row(engine: sa.Engine) -> tuple[object, int] | None:
    with engine.connect() as conn:
        row = conn.execute(
            sa.text(
                "SELECT value, version FROM core.platform_settings WHERE key = 'adapter_read_only'"
            )
        ).first()
    return None if row is None else (row[0], row[1])


@pytest.mark.parametrize(("legacy", "expected"), [("true", True), ("false", False)])
def test_upgrade_copies_the_saved_switch(at_previous, valkey, legacy, expected) -> None:
    engine, url = at_previous
    valkey.set(LEGACY_KEY, legacy)  # type: ignore[attr-defined]

    run_alembic(url, "upgrade", REVISION)

    assert _row(engine) == ({"read_only": expected}, 1)


def test_upgrade_without_a_saved_switch_adds_no_row(at_previous, valkey) -> None:
    engine, url = at_previous
    valkey.delete(LEGACY_KEY)  # type: ignore[attr-defined]

    run_alembic(url, "upgrade", REVISION)

    assert _row(engine) is None


def test_upgrade_with_valkey_unreadable_saves_read_only(at_previous, monkeypatch) -> None:
    """The operator's choice is unknown, so the conservative value is stored.

    Leaving the row out made the saved switch depend on the Valkey key alone:
    lose it after the upgrade and the shipped read-write default came back.
    """
    engine, url = at_previous
    # A closed port: the migration's own client cannot read the switch.
    monkeypatch.delenv("REDIS_SENTINELS", raising=False)
    monkeypatch.setenv("REDIS_HOST", "127.0.0.1")
    monkeypatch.setenv("REDIS_PORT", "1")
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")

    result = run_alembic(url, "upgrade", REVISION)

    assert _row(engine) == ({"read_only": True}, 1)
    assert "read-only is saved" in result.stdout + result.stderr


@pytest.mark.parametrize("legacy", ["false", None])
def test_downgrade_drops_the_table(at_previous, valkey, legacy) -> None:
    """Saved read-write, or nothing saved: nothing a downgrade could lose."""
    engine, url = at_previous
    if legacy is None:
        valkey.delete(LEGACY_KEY)  # type: ignore[attr-defined]
    else:
        valkey.set(LEGACY_KEY, legacy)  # type: ignore[attr-defined]
    run_alembic(url, "upgrade", REVISION)
    run_alembic(url, "downgrade", _previous_revision())
    with engine.connect() as conn:
        assert conn.scalar(sa.text("SELECT to_regclass('core.platform_settings')")) is None


def test_downgrade_carries_a_saved_read_only_into_valkey(at_previous, valkey) -> None:
    """The older release reads Valkey ahead of its environment default.

    The operator saved read-only after the upgrade, while Valkey still holds a
    stale "false". Dropping the table (the old downgrade) left that "false" for
    the older release, which then wrote to devices whatever ADAPTER_READ_ONLY
    said. The downgrade now writes "true" there first.
    """
    engine, url = at_previous
    valkey.set(LEGACY_KEY, "false")  # type: ignore[attr-defined]
    run_alembic(url, "upgrade", REVISION)
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "UPDATE core.platform_settings SET value = '{\"read_only\": true}' "
                "WHERE key = 'adapter_read_only'"
            )
        )
    run_alembic(url, "downgrade", _previous_revision())
    assert valkey.get(LEGACY_KEY) == "true"  # type: ignore[attr-defined]
    with engine.connect() as conn:
        assert conn.scalar(sa.text("SELECT to_regclass('core.platform_settings')")) is None


def test_downgrade_refuses_when_valkey_cannot_take_the_read_only(
    at_previous, valkey, monkeypatch
) -> None:
    engine, url = at_previous
    valkey.set(LEGACY_KEY, "true")  # type: ignore[attr-defined]
    run_alembic(url, "upgrade", REVISION)
    monkeypatch.delenv("REDIS_SENTINELS", raising=False)
    monkeypatch.setenv("REDIS_HOST", "127.0.0.1")
    monkeypatch.setenv("REDIS_PORT", "1")
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
    refused = run_alembic(url, "downgrade", _previous_revision(), expect_success=False)
    assert refused.returncode != 0
    assert "downgrade refused: read-only mode is saved" in refused.stdout + refused.stderr
    assert _row(engine) == ({"read_only": True}, 1)
