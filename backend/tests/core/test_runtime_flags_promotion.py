# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A read-only switch that only Valkey holds is written to Postgres once.

Runs against the suite's real Postgres and Valkey. Before 26.12 the Settings
switch lived only in a Valkey key; when migration 033 could not read it, the
value stayed there, so a later flush or lost volume turned an operator's
read-only back into the read-write environment default.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any

import pytest
import sqlalchemy as sa

import app.core.runtime_flags as rf

_KEYS = (rf._REDIS_KEY, rf._REDIS_VERSION_KEY)


def _sql(statement: str) -> Any:
    async def run() -> Any:
        async with rf._get_db_engine().begin() as conn:
            result = await conn.execute(sa.text(statement))
            return result.first() if result.returns_rows else None

    return asyncio.run(run())


def _row() -> tuple[Any, int] | None:
    row = _sql("SELECT value, version FROM core.platform_settings WHERE key = 'adapter_read_only'")
    return None if row is None else (row[0], row[1])


@pytest.fixture
def real_stores(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    from app.core.redis_client import get_sync_redis

    valkey = get_sync_redis(decode_responses=True, socket_timeout=2, socket_connect_timeout=2)
    try:
        saved = valkey.mget(list(_KEYS))
    except Exception as exc:  # pragma: no cover - environment-dependent
        pytest.skip(f"no Valkey reachable: {exc}")
    for name in ("_client", "_db_engine", "_db_state", "_db_read_at"):
        monkeypatch.setattr(rf, name, None)
    monkeypatch.setattr(rf, "_cache", (None, 0.0))
    monkeypatch.setattr(rf, "_cache_primed", False)
    monkeypatch.setattr(rf, "_refresh_in_flight", False)
    monkeypatch.setattr(rf, "_CACHE_TTL_S", 0.0)
    monkeypatch.setattr(rf, "_DB_TTL_S", 0.0)
    monkeypatch.setattr(rf, "_env_default", lambda: False)  # the shipped read-write compose
    _sql("DELETE FROM core.platform_settings WHERE key = 'adapter_read_only'")
    valkey.delete(*_KEYS)
    try:
        yield valkey
    finally:
        _sql("DELETE FROM core.platform_settings WHERE key = 'adapter_read_only'")
        valkey.delete(*_KEYS)
        for key, value in zip(_KEYS, saved, strict=True):
            if value is not None:
                valkey.set(key, value)
        rf._cache = (None, 0.0)
        rf._cache_primed = False
        rf._client = None
        rf._db_engine = None
        rf._db_state = None
        rf._db_read_at = None


def test_a_legacy_valkey_value_is_promoted_and_survives_a_flush(real_stores) -> None:
    valkey = real_stores
    valkey.set(rf._REDIS_KEY, "true")  # saved by 26.11, no version key

    assert rf.is_adapter_read_only() is True
    assert _row() == ({"read_only": True}, 1)
    assert valkey.mget(list(_KEYS)) == ["true", "1"]

    valkey.delete(*_KEYS)  # FLUSHALL, a lost volume

    assert rf.is_adapter_read_only() is True
    assert _row() == ({"read_only": True}, 1)


def test_an_existing_row_is_never_overwritten_by_the_cache(real_stores) -> None:
    valkey = real_stores
    _sql(
        "INSERT INTO core.platform_settings (key, value, version) "
        "VALUES ('adapter_read_only', '{\"read_only\": true}', 4)"
    )
    valkey.set(rf._REDIS_KEY, "false")

    assert rf.is_adapter_read_only() is True
    assert _row() == ({"read_only": True}, 4)


def test_neither_store_holds_a_value_keeps_read_write_and_adds_no_row(real_stores) -> None:
    assert rf.is_adapter_read_only() is False
    assert _row() is None
