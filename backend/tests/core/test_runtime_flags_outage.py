# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A Valkey outage must not turn read-only mode off.

The live read-only switch is a Valkey key; the deploy-time env default backs
it. A failed read used to be reported as "no override set", so the gate fell
back to the env default. The shipped compose defaults to read-WRITE, so an
operator who had put the install in read-only mode from Settings got device
writes back for as long as Valkey could not be read, and a worker that started
during an outage never consulted the override at all, though the module says
the first read must not be answered with a guess.

A failed read now keeps the value last read successfully, and refuses writes
before the first successful read. A key that is genuinely absent still means
"use the env default".

Since the switch moved into Postgres (26.12), Valkey is only its cache and a
process can also learn the switch from Postgres. These tests are about Valkey,
so Postgres is held unreadable here unless a test says otherwise: "a worker
that can read nothing" still has to refuse writes. The Postgres side is covered
by test_runtime_flags_durable.py.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

import app.core.redis_client as redis_client
import app.core.runtime_flags as rf


class _Valkey:
    def __init__(self, value: str | None) -> None:
        self.value = value
        self.down = False

    def get(self, key: str) -> str | None:
        if self.down:
            raise ConnectionError("valkey unreachable")
        return self.value

    def mget(self, keys: list[str]) -> list[str | None]:
        # The value key carries the switch; no version key (a pre-26.12 value).
        return [self.get(keys[0]), None]

    def eval(self, *_args: object) -> int:
        if self.down:
            raise ConnectionError("valkey unreachable")
        return 0


class _NoRowYet:
    """Postgres stand-in: unreadable, or answering "never saved"."""

    def __init__(self) -> None:
        self.down = True

    def __call__(self) -> object:
        if self.down:
            raise rf._Unreadable("postgres unreachable")
        return rf._NO_ROW


@pytest.fixture
def valkey(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Valkey]:
    fake = _Valkey(value=None)
    monkeypatch.setattr(redis_client, "get_sync_redis", lambda **_: fake)
    monkeypatch.setattr(rf, "_client", None)
    monkeypatch.setattr(rf, "_cache", (None, 0.0))
    monkeypatch.setattr(rf, "_cache_primed", False)
    monkeypatch.setattr(rf, "_refresh_in_flight", False)
    monkeypatch.setattr(rf, "_db_state", None)
    monkeypatch.setattr(rf, "_db_read_at", None)
    db = _NoRowYet()
    monkeypatch.setattr(rf, "_read_db", db)
    # These tests' Postgres is a stand-in, so a cached value is never copied
    # into the real database behind it.
    monkeypatch.setattr(rf, "_promote_cached", lambda _cached: rf._NO_ROW)
    # Every call re-reads (sync caller, so inline), and the deploy default is
    # read-WRITE, as in the shipped compose.
    monkeypatch.setattr(rf, "_CACHE_TTL_S", 0.0)
    monkeypatch.setattr(rf, "_env_default", lambda: False)
    fake.db = db  # type: ignore[attr-defined]
    yield fake
    rf._cache = (None, 0.0)
    rf._cache_primed = False
    rf._client = None
    rf._db_state = None
    rf._db_read_at = None


def test_a_worker_started_during_an_outage_refuses_writes(valkey: _Valkey) -> None:
    valkey.down = True
    assert rf.is_adapter_read_only() is True


def test_an_outage_keeps_the_operators_read_only_choice(valkey: _Valkey) -> None:
    valkey.value = "true"
    assert rf.is_adapter_read_only() is True
    valkey.down = True
    assert rf.is_adapter_read_only() is True
    assert rf.is_adapter_read_only() is True


def test_an_outage_keeps_an_explicit_read_write_choice(valkey: _Valkey) -> None:
    # Postgres must have answered once before a cached "false" grants writes
    # (see test_runtime_flags_promotion.py for the cold-worker cases).
    valkey.db.down = False  # type: ignore[attr-defined]
    valkey.value = "false"
    assert rf.is_adapter_read_only() is False
    valkey.down = True
    assert rf.is_adapter_read_only() is False


def test_an_absent_key_still_means_the_env_default(valkey: _Valkey) -> None:
    # "Absent" is now a statement by both stores: no cached value, and Postgres
    # says the switch was never saved. A missing cache key alone, with Postgres
    # unreadable, is not known to be "unset" and refuses writes (see
    # test_runtime_flags_durable.py).
    valkey.db.down = False  # type: ignore[attr-defined]
    assert rf.is_adapter_read_only() is False
    valkey.down = True
    assert rf.is_adapter_read_only() is False


def test_recovery_after_an_outage_reads_the_real_value(valkey: _Valkey) -> None:
    valkey.down = True
    assert rf.is_adapter_read_only() is True
    valkey.down = False
    valkey.value = "false"
    # Valkey alone is back: a cached "false" grants nothing until Postgres answers.
    assert rf.is_adapter_read_only() is True
    valkey.db.down = False  # type: ignore[attr-defined]
    assert rf.is_adapter_read_only() is False


def test_a_cached_read_write_value_with_postgres_unreadable_refuses_writes(
    valkey: _Valkey,
) -> None:
    """A first read whose Postgres check fails cannot trust a cached "false"."""
    valkey.value = "false"
    assert rf.is_adapter_read_only() is True
    valkey.db.down = False  # type: ignore[attr-defined]
    assert rf.is_adapter_read_only() is False
