# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
GET/PUT /system/settings/adapter-read-only report both sources of the
write-safety mode, and the Settings switch cannot turn off a read-only mode the
server environment enforces.

The endpoint used to answer only ``{"read_only": ...}``, so the page could not
say WHY writes were refused, and the PUT wrote a Valkey key that overrode the
environment in both directions: the UI could switch off ADAPTER_READ_ONLY=true.
"""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from fastapi import HTTPException

import app.core.redis_client as redis_client
import app.core.runtime_flags as rf
from app.api.v1.endpoints import system


class _Valkey:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    def mget(self, keys: list[str]) -> list[str | None]:
        return [self.data.get(k) for k in keys]

    def eval(self, _script: str, _n: int, value_key: str, version_key: str, v: str, ver: str):
        if int(ver) > int(self.data.get(version_key, "-1")):
            self.data[value_key], self.data[version_key] = v, ver
            return 1
        return 0


@pytest.fixture
def flags(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
    valkey = _Valkey()
    env = {"read_only": False}
    monkeypatch.setattr(redis_client, "get_sync_redis", lambda **_: valkey)
    monkeypatch.setattr(rf, "_client", None)
    monkeypatch.setattr(rf, "_cache", (None, 0.0))
    monkeypatch.setattr(rf, "_cache_primed", False)
    monkeypatch.setattr(rf, "_db_state", None)
    monkeypatch.setattr(rf, "_db_read_at", None)
    # The request runs in the test's uncommitted transaction, which the gate's
    # own connection cannot see; the endpoint itself reads the row.
    monkeypatch.setattr(rf, "_read_db", lambda: rf._NO_ROW)
    # These tests' Postgres is a stand-in, so a cached value is never copied
    # into the real database behind it.
    monkeypatch.setattr(rf, "_promote_cached", lambda _cached: rf._NO_ROW)
    monkeypatch.setattr(rf, "_env_default", lambda: env["read_only"])
    yield {"valkey": valkey, "env": env}
    rf._cache = (None, 0.0)
    rf._cache_primed = False
    rf._client = None
    rf._db_state = None
    rf._db_read_at = None


def _super_admin() -> Any:
    return SimpleNamespace(id=uuid4(), is_superuser=True, _scoped=False)


async def test_get_reports_both_sources(flags, db_session) -> None:
    flags["env"]["read_only"] = True
    state = await system.get_adapter_read_only_state(_user=None, session=db_session)
    assert state.read_only is True
    assert state.env_read_only is True
    assert state.setting_read_only is False
    assert state.enforced_by == "environment"
    assert state.can_disable is False


async def test_put_cannot_turn_off_an_environment_read_only(flags, db_session) -> None:
    from app.models.platform_settings import ADAPTER_READ_ONLY_KEY, PlatformSetting

    flags["env"]["read_only"] = True
    with pytest.raises(HTTPException) as refused:
        await system.set_adapter_read_only_state(
            system.AdapterReadOnlyUpdate(read_only=False),
            current_user=_super_admin(),
            session=db_session,
        )
    assert refused.value.status_code == 409
    assert "ADAPTER_READ_ONLY=true" in str(refused.value.detail)
    assert "environment" in str(refused.value.detail)
    assert await db_session.get(PlatformSetting, ADAPTER_READ_ONLY_KEY) is None
    assert flags["valkey"].data == {}


async def test_put_on_while_the_environment_enforces_it_is_saved(flags, db_session) -> None:
    flags["env"]["read_only"] = True
    state = await system.set_adapter_read_only_state(
        system.AdapterReadOnlyUpdate(read_only=True),
        current_user=_super_admin(),
        session=db_session,
    )
    assert state.read_only is True
    assert state.setting_read_only is True
    assert state.enforced_by == "environment_and_setting"


async def test_put_saves_the_switch_and_reports_it(flags, db_session) -> None:
    from sqlalchemy import select

    from app.models.platform_settings import ADAPTER_READ_ONLY_KEY, PlatformSetting
    from app.models.security_audit import AuditLogRecord

    admin = _super_admin()
    state = await system.set_adapter_read_only_state(
        system.AdapterReadOnlyUpdate(read_only=True), current_user=admin, session=db_session
    )
    assert state.read_only is True
    assert state.setting_read_only is True
    assert state.enforced_by == "setting"
    assert state.can_disable is True
    assert state.propagated is True
    row = await db_session.get(PlatformSetting, ADAPTER_READ_ONLY_KEY)
    assert row is not None and row.value == {"read_only": True}
    assert row.updated_by == admin.id
    assert state.setting_updated_at is not None
    audit = (
        (
            await db_session.execute(
                select(AuditLogRecord).where(AuditLogRecord.action == "settings.adapter_read_only")
            )
        )
        .scalars()
        .all()
    )
    assert any(a.new_state and a.new_state.get("setting_read_only") is True for a in audit)

    state = await system.set_adapter_read_only_state(
        system.AdapterReadOnlyUpdate(read_only=False), current_user=admin, session=db_session
    )
    assert state.read_only is False
    assert state.enforced_by == "none"


async def test_put_needs_an_unscoped_super_admin(flags, db_session) -> None:
    with pytest.raises(HTTPException) as refused:
        await system.set_adapter_read_only_state(
            system.AdapterReadOnlyUpdate(read_only=False),
            current_user=SimpleNamespace(id=uuid4(), is_superuser=True, _scoped=True),
            session=db_session,
        )
    assert refused.value.status_code == 403
