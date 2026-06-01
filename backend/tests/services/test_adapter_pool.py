# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the shared adapter pool (PERF-CRIT-1+2+6).

The pool reuses a single connected adapter per ``(controller_id, vendor)``
tuple across requests so the controller dashboard with 9-13 tabs polling
doesn't reauthenticate 50+ times a minute.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from app.adapters.pool import AdapterConnectionPool


class _FakeAdapter:
    """Minimal stand-in for a real adapter. Tracks connect()/disconnect()
    calls so tests can assert reuse / eviction."""

    def __init__(self, host: str, username: str, password: str, **kwargs: Any) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.kwargs = kwargs
        self._connected = False
        self.connect_calls = 0
        self.disconnect_calls = 0
        self.is_acquired = False

    async def connect(self, **kwargs: Any) -> None:
        self.connect_calls += 1
        self._connected = True

    async def disconnect(self) -> None:
        self.disconnect_calls += 1
        self._connected = False


def _patch_registry(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Replace the registry's create_adapter with a factory that emits
    :class:`_FakeAdapter` so we can assert on connect counts without
    touching real network code."""
    counters: dict[str, Any] = {"created": []}

    def _create(
        adapter_id: str,
        host: str,
        username: str,
        password: str,
        **kwargs: Any,
    ) -> _FakeAdapter:
        a = _FakeAdapter(host, username, password, **kwargs)
        counters["created"].append((adapter_id, a))
        return a

    monkeypatch.setattr(
        "app.adapters.pool.adapter_registry.create_adapter", _create
    )
    return counters


# ─── PERF-CRIT-1: pool returns the same adapter for the same controller ─


@pytest.mark.asyncio
async def test_adapter_pool_returns_same_instance_for_same_controller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    counters = _patch_registry(monkeypatch)
    pool = AdapterConnectionPool()

    first = await pool.get_or_create_shared(
        adapter_id="mikrotik",
        controller_id="ctrl-a",
        host="10.0.0.1",
        username="admin",
        password="x",
    )
    second = await pool.get_or_create_shared(
        adapter_id="mikrotik",
        controller_id="ctrl-a",
        host="10.0.0.1",
        username="admin",
        password="x",
    )

    assert first is second, "pool must reuse the same adapter for the same key"
    assert len(counters["created"]) == 1, "only one connect should happen"
    assert first.connect_calls == 1


@pytest.mark.asyncio
async def test_adapter_pool_distinct_controllers_get_distinct_adapters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_registry(monkeypatch)
    pool = AdapterConnectionPool()

    a = await pool.get_or_create_shared(
        "mikrotik", "ctrl-a", "10.0.0.1", "u", "p"
    )
    b = await pool.get_or_create_shared(
        "mikrotik", "ctrl-b", "10.0.0.2", "u", "p"
    )
    assert a is not b


# ─── Concurrent requests share at most a small number of adapters ─────


@pytest.mark.asyncio
async def test_adapter_pool_concurrent_requests_share_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """100 concurrent get-or-create calls for the same controller
    should result in ≤2 underlying httpx clients (the pool serialises
    via its asyncio.Lock so realistically all 100 share one client)."""
    counters = _patch_registry(monkeypatch)
    pool = AdapterConnectionPool()

    async def grab() -> _FakeAdapter:
        return await pool.get_or_create_shared(
            adapter_id="mikrotik",
            controller_id="ctrl-shared",
            host="10.0.0.1",
            username="u",
            password="p",
        )

    results = await asyncio.gather(*[grab() for _ in range(100)])
    distinct = {id(r) for r in results}
    assert len(distinct) == 1, (
        f"100 concurrent grabs should share one adapter, got {len(distinct)}"
    )
    assert len(counters["created"]) <= 2, (
        f"≤2 underlying clients expected; got {len(counters['created'])}"
    )


# ─── Credential / controller eviction ────────────────────────────────


@pytest.mark.asyncio
async def test_adapter_pool_evicts_on_credential_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """invalidate_controller marks every pooled connection unhealthy
    so the next request gets a fresh adapter (after cleanup)."""
    counters = _patch_registry(monkeypatch)
    pool = AdapterConnectionPool(
        max_idle_time_seconds=0,
        max_connection_age_seconds=0,
        cleanup_interval_seconds=60,
    )

    first = await pool.get_or_create_shared(
        "mikrotik", "ctrl-a", "10.0.0.1", "u", "p"
    )
    # Simulate credential rotation: invalidate, then force a cleanup
    # so the marked-unhealthy connection is reaped.
    pool.invalidate_controller("ctrl-a")
    await pool._cleanup_connections()

    second = await pool.get_or_create_shared(
        "mikrotik", "ctrl-a", "10.0.0.1", "u", "p2"
    )
    assert first is not second, "post-eviction, a fresh adapter must be issued"
    assert len(counters["created"]) == 2


@pytest.mark.asyncio
async def test_adapter_pool_closes_clients_on_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_registry(monkeypatch)
    pool = AdapterConnectionPool()

    a = await pool.get_or_create_shared(
        "mikrotik", "ctrl-a", "10.0.0.1", "u", "p"
    )
    b = await pool.get_or_create_shared(
        "mikrotik", "ctrl-b", "10.0.0.2", "u", "p"
    )
    await pool.stop()

    # Each pooled adapter received exactly one disconnect call.
    assert a.disconnect_calls == 1
    assert b.disconnect_calls == 1


# ─── Pool start/stop is idempotent + safe ────────────────────────────


@pytest.mark.asyncio
async def test_adapter_pool_stop_is_safe_when_never_started() -> None:
    pool = AdapterConnectionPool()
    # No connections, no background task — stop() should still complete.
    await pool.stop()
