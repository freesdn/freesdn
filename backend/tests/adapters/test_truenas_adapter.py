# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Facade tests for ``TrueNASAdapter``.

The adapter wraps :class:`TrueNASClient` with the
:class:`~app.adapters.base.BaseAdapter` contract. We exercise the
required overrides (connect / disconnect / test_connection /
discover_devices / get_device_status / get_device_info) and the
TrueNAS-specific normalized read API (get_pools / get_datasets /
get_snapshots / get_disks) against a mocked client.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from app.adapters.base import AdapterResult
from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
)
from app.adapters.truenas.adapter import TrueNASAdapter


def _adapter(api: Any = None) -> TrueNASAdapter:
    a = TrueNASAdapter(
        host="truenas.lab", username="root", password="",
        api_key="abc", verify_ssl=False,
    )
    if api is not None:
        a._api = api
    return a


class TestManifest:
    def test_id_and_caps(self) -> None:
        m = TrueNASAdapter.manifest
        assert m.id == "truenas"
        assert m.vendor == "iXsystems"
        assert m.supports_direct is True
        assert m.supports_controller is False
        assert "storage" in m.device_types
        assert "api_key" in m.auth_methods


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_connect_marks_connected(self) -> None:
        api = AsyncMock()
        a = _adapter(api)
        ok = await a.connect()
        assert ok is True
        assert a.is_connected is True
        api.connect.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_disconnect_clears_state(self) -> None:
        api = AsyncMock()
        a = _adapter(api)
        await a.connect()
        await a.disconnect()
        assert a.is_connected is False
        api.disconnect.assert_awaited_once()


class TestTestConnection:
    @pytest.mark.asyncio
    async def test_returns_ok_with_version_and_hostname(self) -> None:
        api = AsyncMock()
        api.get_system_info.return_value = {
            "version": "TrueNAS-SCALE-24.04.0",
            "hostname": "nas01",
        }
        a = _adapter(api)
        r: AdapterResult = await a.test_connection()
        assert r.success is True
        assert r.data["version"] == "TrueNAS-SCALE-24.04.0"
        assert r.data["hostname"] == "nas01"
        # connect + get_system_info + disconnect — clean lifecycle.
        api.connect.assert_awaited_once()
        api.disconnect.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_auth_error_classified(self) -> None:
        api = AsyncMock()
        api.connect.side_effect = AdapterAuthenticationError("nope")
        a = _adapter(api)
        r = await a.test_connection()
        assert r.success is False
        assert r.error_code == "AUTH"

    @pytest.mark.asyncio
    async def test_connection_error_classified(self) -> None:
        api = AsyncMock()
        api.connect.side_effect = AdapterConnectionError("offline")
        a = _adapter(api)
        r = await a.test_connection()
        assert r.success is False
        assert r.error_code == "UNREACHABLE"


class TestDiscoverDevices:
    @pytest.mark.asyncio
    async def test_emits_single_device_with_serial(self) -> None:
        api = AsyncMock()
        api.get_system_info.return_value = {
            "hostname": "nas01",
            "system_product": "TrueNAS-M40",
            "system_serial": "SN1234",
            "version": "SCALE-24.04",
        }
        a = _adapter(api)
        devs = await a.discover_devices()
        assert len(devs) == 1
        assert devs[0].name == "nas01"
        assert devs[0].model == "TrueNAS-M40"
        assert devs[0].serial_number == "SN1234"
        assert devs[0].device_type == "storage"
        assert devs[0].vendor == "iXsystems"

    @pytest.mark.asyncio
    async def test_swallows_exception_returns_empty(self) -> None:
        """A discovery failure must not poison the caller — return []."""
        api = AsyncMock()
        api.get_system_info.side_effect = RuntimeError("boom")
        a = _adapter(api)
        assert await a.discover_devices() == []


class TestStatusRollup:
    @pytest.mark.asyncio
    async def test_all_online_pools_yields_ok(self) -> None:
        api = AsyncMock()
        api.get_system_info.return_value = {"hostname": "h", "version": "v"}
        api.list_pools.return_value = [
            {"name": "tank", "status": "ONLINE"},
            {"name": "backup", "status": "ONLINE"},
        ]
        a = _adapter(api)
        st = await a.get_device_status("ignored")
        assert st["status"] == "ok"
        assert st["pool_count"] == 2

    @pytest.mark.asyncio
    async def test_degraded_pool_yields_warning(self) -> None:
        api = AsyncMock()
        api.get_system_info.return_value = {"hostname": "h", "version": "v"}
        api.list_pools.return_value = [
            {"name": "tank", "status": "ONLINE"},
            {"name": "backup", "status": "DEGRADED"},
        ]
        a = _adapter(api)
        st = await a.get_device_status("ignored")
        assert st["status"] == "warning"

    @pytest.mark.asyncio
    async def test_faulted_pool_yields_error_and_short_circuits(self) -> None:
        """FAULTED is worse than DEGRADED — and we stop scanning once
        we've established the appliance is in error."""
        api = AsyncMock()
        api.get_system_info.return_value = {"hostname": "h", "version": "v"}
        api.list_pools.return_value = [
            {"name": "tank", "status": "FAULTED"},
            {"name": "backup", "status": "DEGRADED"},  # never reached
        ]
        a = _adapter(api)
        st = await a.get_device_status("ignored")
        assert st["status"] == "error"

    @pytest.mark.asyncio
    async def test_exception_returns_error_status(self) -> None:
        api = AsyncMock()
        api.get_system_info.side_effect = RuntimeError("dead")
        a = _adapter(api)
        st = await a.get_device_status("ignored")
        assert st["status"] == "error"
        assert "dead" in st["error"]


class TestNormalizedReads:
    @pytest.mark.asyncio
    async def test_get_pools_normalizes(self) -> None:
        api = AsyncMock()
        api.list_pools.return_value = [
            {"id": 1, "name": "tank", "status": "ONLINE", "healthy": True,
             "size": 100, "allocated": 40, "free": 60},
        ]
        a = _adapter(api)
        pools = await a.get_pools()
        assert pools[0].name == "tank"
        assert pools[0].healthy is True
        assert pools[0].usage.allocated == 40

    @pytest.mark.asyncio
    async def test_get_datasets_normalizes(self) -> None:
        api = AsyncMock()
        api.list_datasets.return_value = [
            {"id": "tank/share", "pool": "tank", "type": "FILESYSTEM",
             "used": {"parsed": 4096}, "available": {"parsed": 8192}},
        ]
        a = _adapter(api)
        ds = await a.get_datasets()
        assert ds[0].id == "tank/share"
        assert ds[0].usage.used_bytes == 4096
        assert ds[0].usage.available_bytes == 8192

    @pytest.mark.asyncio
    async def test_get_snapshots_normalizes(self) -> None:
        api = AsyncMock()
        api.list_snapshots.return_value = [
            {"id": "tank@hourly-1"},
        ]
        a = _adapter(api)
        snaps = await a.get_snapshots()
        assert snaps[0].dataset == "tank"
        assert snaps[0].snapshot_name == "hourly-1"

    @pytest.mark.asyncio
    async def test_get_disks_normalizes(self) -> None:
        api = AsyncMock()
        api.list_disks.return_value = [
            {"name": "sda", "serial": "X", "size": 1000, "type": "HDD"},
        ]
        a = _adapter(api)
        disks = await a.get_disks()
        assert disks[0].name == "sda"
        assert disks[0].size == 1000
