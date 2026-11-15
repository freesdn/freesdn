# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The Settings read-only switch is stored in Postgres, cached in Valkey, and can
never loosen what the environment enforces.

Before 26.12 the switch lived only in a Valkey key, and a missing key meant
"use ADAPTER_READ_ONLY from the environment". The shipped compose file sets
that to read-WRITE, so a Valkey flush or a lost volume silently turned an
operator's "read-only" back into "write to every device". And the key, when
present, overrode the environment in both directions, so the UI could switch
off a read-only mode the deployment had set on purpose.

Now: effective = environment OR stored switch; Postgres is the record; a
process that can read neither store refuses writes.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from uuid import uuid4

import pytest

import app.core.redis_client as redis_client
import app.core.runtime_flags as rf

_VALUE = rf._REDIS_KEY
_VERSION = rf._REDIS_VERSION_KEY


class _Valkey:
    """A Valkey stand-in that runs the same compare-and-set the Lua script does."""

    def __init__(self) -> None:
        self.data: dict[str, str] = {}
        self.down = False

    def mget(self, keys: list[str]) -> list[str | None]:
        if self.down:
            raise ConnectionError("valkey unreachable")
        return [self.data.get(k) for k in keys]

    def eval(self, script: str, numkeys: int, *args: Any) -> int:
        if self.down:
            raise ConnectionError("valkey unreachable")
        assert script == rf._CAS_SCRIPT and numkeys == 2
        value_key, version_key, value, version = args
        cur = int(self.data.get(version_key, "-1"))
        new = int(version)
        if new > cur or (value_key not in self.data and new >= cur):
            self.data[value_key] = value
            self.data[version_key] = version
            return 1
        return 0


class _Postgres:
    def __init__(self) -> None:
        self.row: tuple[bool, int] | None = None
        self.down = False
        self.reads = 0

    def __call__(self) -> rf.StoredSwitch | rf._NoRow:
        self.reads += 1
        if self.down:
            raise rf._Unreadable("postgres unreachable")
        if self.row is None:
            return rf._NO_ROW
        return rf.StoredSwitch(self.row[0], self.row[1], "database")

    def promote(self, cached: rf.StoredSwitch) -> rf.StoredSwitch | rf._NoRow:
        """INSERT ... ON CONFLICT DO NOTHING, then read back, as the real one does."""
        if self.row is None:
            self.row = (cached.read_only, max(cached.version, 1))
        return self()


@pytest.fixture
def stores(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[_Valkey, _Postgres]]:
    valkey = _Valkey()
    postgres = _Postgres()
    monkeypatch.setattr(redis_client, "get_sync_redis", lambda **_: valkey)
    monkeypatch.setattr(rf, "_client", None)
    monkeypatch.setattr(rf, "_cache", (None, 0.0))
    monkeypatch.setattr(rf, "_cache_primed", False)
    monkeypatch.setattr(rf, "_refresh_in_flight", False)
    monkeypatch.setattr(rf, "_db_state", None)
    monkeypatch.setattr(rf, "_db_read_at", None)
    monkeypatch.setattr(rf, "_read_db", postgres)
    monkeypatch.setattr(rf, "_promote_cached", postgres.promote)
    # Every call re-reads; Postgres is consulted on every refresh.
    monkeypatch.setattr(rf, "_CACHE_TTL_S", 0.0)
    monkeypatch.setattr(rf, "_DB_TTL_S", 0.0)
    env = {"read_only": False}
    monkeypatch.setattr(rf, "_env_default", lambda: env["read_only"])
    valkey.env = env  # type: ignore[attr-defined]
    yield valkey, postgres
    rf._cache = (None, 0.0)
    rf._cache_primed = False
    rf._client = None
    rf._db_state = None
    rf._db_read_at = None


def _env(valkey: _Valkey, read_only: bool) -> None:
    valkey.env["read_only"] = read_only  # type: ignore[attr-defined]


# ── The bug: losing the cache turned read-only off ───────────────────────────


def test_a_flushed_valkey_keeps_the_saved_read_only_switch(stores) -> None:
    valkey, postgres = stores
    postgres.row = (True, 3)
    valkey.data = {_VALUE: "true", _VERSION: "3"}
    assert rf.is_adapter_read_only() is True

    valkey.data.clear()  # FLUSHALL, a lost volume, a restarted cache

    assert rf.is_adapter_read_only() is True
    # ...and the cache is refilled from the record.
    assert valkey.data == {_VALUE: "true", _VERSION: "3"}


def test_a_worker_started_during_a_valkey_outage_reads_postgres(stores) -> None:
    valkey, postgres = stores
    valkey.down = True
    postgres.row = (True, 1)
    assert rf.is_adapter_read_only() is True
    postgres.row = (False, 2)
    assert rf.is_adapter_read_only() is False


def test_nothing_readable_refuses_writes(stores) -> None:
    valkey, postgres = stores
    valkey.down = True
    postgres.down = True
    assert rf.is_adapter_read_only() is True


def test_a_postgres_blip_keeps_the_cached_switch(stores) -> None:
    valkey, postgres = stores
    postgres.row = (True, 4)
    valkey.data = {_VALUE: "true", _VERSION: "4"}
    assert rf.is_adapter_read_only() is True
    postgres.down = True
    assert rf.is_adapter_read_only() is True


def test_both_stores_down_keeps_the_last_value_read(stores) -> None:
    valkey, postgres = stores
    postgres.row = (True, 2)
    assert rf.is_adapter_read_only() is True
    valkey.down = True
    postgres.down = True
    assert rf.is_adapter_read_only() is True


def test_a_missing_cache_key_with_postgres_down_refuses_writes(stores) -> None:
    """No cached value and no answer from the record is not "never set"."""
    _valkey, postgres = stores
    postgres.down = True
    assert rf.is_adapter_read_only() is True


# ── The record wins over a stale cache, a newer cache wins over an old read ──


def test_a_cache_that_missed_a_write_is_corrected_from_postgres(stores) -> None:
    """A PUT made while Valkey was down: the row is newer than the cache."""
    valkey, postgres = stores
    valkey.data = {_VALUE: "false", _VERSION: "5"}
    postgres.row = (True, 6)
    assert rf.is_adapter_read_only() is True
    assert valkey.data == {_VALUE: "true", _VERSION: "6"}


def test_a_newer_cached_value_beats_an_older_postgres_read(stores) -> None:
    valkey, postgres = stores
    postgres.row = (True, 6)
    assert rf.is_adapter_read_only() is True
    # Another process saved v7 and published it; this process's Postgres read
    # is still v6 (stale) and must not win, nor overwrite the cache.
    postgres.down = True
    valkey.data = {_VALUE: "false", _VERSION: "7"}
    assert rf.is_adapter_read_only() is False
    assert valkey.data == {_VALUE: "false", _VERSION: "7"}


def test_a_value_saved_before_the_upgrade_is_moved_into_postgres(stores) -> None:
    """The legacy key, with no row behind it (the upgrade could not copy it).

    It used to be honoured only while Valkey kept it: a later flush turned the
    saved read-only back into the read-write environment default.
    """
    valkey, postgres = stores
    valkey.data = {_VALUE: "true"}
    assert rf.is_adapter_read_only() is True
    assert postgres.row == (True, 1)
    assert rf._cache[0] == rf.StoredSwitch(True, 1, "database")
    assert valkey.data == {_VALUE: "true", _VERSION: "1"}

    valkey.data.clear()

    assert rf.is_adapter_read_only() is True
    assert postgres.row == (True, 1)


def test_never_saved_anywhere_is_read_write_on_a_read_write_environment(stores) -> None:
    assert rf.is_adapter_read_only() is False


# ── The environment always wins in the restrictive direction ─────────────────


@pytest.mark.parametrize(
    ("env", "switch", "expected"),
    [(False, False, False), (False, True, True), (True, False, True), (True, True, True)],
)
def test_effective_is_the_more_restrictive_source(stores, env, switch, expected) -> None:
    valkey, postgres = stores
    _env(valkey, env)
    postgres.row = (switch, 1)
    assert rf.is_adapter_read_only() is expected


def test_a_cached_read_write_value_cannot_override_an_env_read_only(stores) -> None:
    """The old resolution let the Valkey key win over the environment."""
    valkey, _postgres = stores
    _env(valkey, True)
    valkey.data = {_VALUE: "false"}
    assert rf.is_adapter_read_only() is True


# ── Saving ───────────────────────────────────────────────────────────────────


async def test_saving_off_while_the_environment_enforces_read_only_is_refused(stores) -> None:
    valkey, _postgres = stores
    _env(valkey, True)

    class _NoDb:
        async def execute(self, *_a: Any, **_k: Any) -> Any:
            raise AssertionError("nothing may be written")

    with pytest.raises(rf.EnvironmentEnforcesReadOnly):
        await rf.store_adapter_read_only(_NoDb(), False)  # type: ignore[arg-type]


async def test_saving_writes_the_row_then_the_cache(stores, db_session) -> None:
    from app.models.platform_settings import ADAPTER_READ_ONLY_KEY, PlatformSetting

    valkey, _postgres = stores
    actor = uuid4()
    first = await rf.store_adapter_read_only(db_session, True, actor_id=actor)
    second = await rf.store_adapter_read_only(db_session, False, actor_id=actor)

    row = await db_session.get(PlatformSetting, ADAPTER_READ_ONLY_KEY)
    await db_session.refresh(row)
    assert row.value == {"read_only": False}
    assert row.updated_by == actor
    assert first.status.setting_version + 1 == second.status.setting_version == row.version
    assert valkey.data == {_VALUE: "false", _VERSION: str(row.version)}
    assert second.propagated is True
    assert second.status.read_only is False
    assert second.status.enforced_by == "none"


async def test_saving_while_valkey_is_down_is_durable_and_says_so(stores, db_session) -> None:
    valkey, _postgres = stores
    valkey.down = True
    result = await rf.store_adapter_read_only(db_session, True)
    assert result.propagated is False
    assert result.status.read_only is True
    assert result.status.enforced_by == "setting"


# ── Status report ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("env", "row", "postgres_down", "enforced_by"),
    [
        (True, (True, 1), False, "environment_and_setting"),
        (True, (False, 1), False, "environment"),
        (False, (True, 1), False, "setting"),
        (False, (False, 1), False, "none"),
        (False, None, True, "unverified"),
    ],
)
async def test_status_names_the_source_in_force(stores, env, row, postgres_down, enforced_by):
    valkey, postgres = stores
    _env(valkey, env)
    postgres.row = row
    postgres.down = postgres_down
    status = await rf.read_only_status()
    assert status.enforced_by == enforced_by
    assert status.env_read_only is env
    assert status.read_only is (enforced_by != "none")


# ── The compare-and-set itself, on the real Valkey ───────────────────────────


def test_the_cas_script_never_replaces_a_newer_version() -> None:
    """Runs the Lua script against the suite's Valkey, on throwaway keys."""
    from app.core.redis_client import get_sync_redis

    client = get_sync_redis(decode_responses=True, socket_timeout=2, socket_connect_timeout=2)
    try:
        client.ping()
    except Exception as exc:  # pragma: no cover - environment-dependent
        pytest.skip(f"no Valkey reachable: {exc}")
    value_key = f"test:ro:{uuid4().hex}"
    version_key = f"{value_key}:version"

    def cas(value: str, version: int) -> int:
        return int(client.eval(rf._CAS_SCRIPT, 2, value_key, version_key, value, str(version)))

    try:
        client.set(value_key, "true")  # a pre-26.12 value, no version
        assert cas("false", 1) == 1
        assert cas("true", 3) == 1
        assert cas("false", 2) == 0  # older: refused
        assert cas("false", 3) == 0  # same version: refused
        assert client.mget([value_key, version_key]) == ["true", "3"]
        client.delete(value_key)  # value lost, version kept
        assert cas("true", 3) == 1
        assert client.get(value_key) == "true"
    finally:
        client.delete(value_key, version_key)
