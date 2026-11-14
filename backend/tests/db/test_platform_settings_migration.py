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


def test_downgrade_drops_the_table(at_previous, valkey) -> None:
    engine, url = at_previous
    valkey.set(LEGACY_KEY, "true")  # type: ignore[attr-defined]
    run_alembic(url, "upgrade", REVISION)
    run_alembic(url, "downgrade", _previous_revision())
    with engine.connect() as conn:
        assert conn.scalar(sa.text("SELECT to_regclass('core.platform_settings')")) is None
