# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Per-controller solo lock on device discovery.

A slow controller sync + repeated "Sync Now" clicks (or manual-vs-scheduled
overlap) ran two discoveries for the SAME controller concurrently; the dedup's
``with_for_update(skip_locked=True)`` then made the second run miss the first's
in-flight rows and INSERT duplicate devices. The lock makes discovery one-at-a-
time per controller — an overlapping call returns early without touching the DB.
"""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

import app.tasks.discovery as d


@pytest.mark.asyncio
async def test_overlapping_discovery_is_skipped(monkeypatch) -> None:
    monkeypatch.setattr("app.core.celery_app.acquire_solo_lock", lambda *_a, **_k: False)
    released: list = []
    monkeypatch.setattr("app.core.celery_app.release_solo_lock", lambda key: released.append(key))
    impl = AsyncMock(return_value={"ok": True})
    monkeypatch.setattr(d, "_discover_devices_for_controller_impl", impl)

    res = await d._discover_devices_for_controller("cid-1")

    assert res["skipped"] is True and res["reason"] == "already_running"
    impl.assert_not_awaited()  # the impl (which touches the DB) never ran
    assert released == []  # never acquired → never released


@pytest.mark.asyncio
async def test_discovery_runs_and_releases_lock(monkeypatch) -> None:
    monkeypatch.setattr("app.core.celery_app.acquire_solo_lock", lambda *_a, **_k: True)
    released: list = []
    monkeypatch.setattr("app.core.celery_app.release_solo_lock", lambda key: released.append(key))
    impl = AsyncMock(return_value={"ok": True, "synced": 10})
    monkeypatch.setattr(d, "_discover_devices_for_controller_impl", impl)

    res = await d._discover_devices_for_controller("cid-1")

    assert res == {"ok": True, "synced": 10}
    impl.assert_awaited_once_with("cid-1")
    assert released == ["discover_devices:cid-1"]  # lock released after run


@pytest.mark.asyncio
async def test_lock_released_even_if_impl_raises(monkeypatch) -> None:
    monkeypatch.setattr("app.core.celery_app.acquire_solo_lock", lambda *_a, **_k: True)
    released: list = []
    monkeypatch.setattr("app.core.celery_app.release_solo_lock", lambda key: released.append(key))

    async def _boom(_cid):
        raise RuntimeError("adapter down")

    monkeypatch.setattr(d, "_discover_devices_for_controller_impl", _boom)

    with pytest.raises(RuntimeError):
        await d._discover_devices_for_controller("cid-1")
    assert released == ["discover_devices:cid-1"]  # finally released the lock
