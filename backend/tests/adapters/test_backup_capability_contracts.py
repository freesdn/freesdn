"""Unsupported operations do not invent writes or empty inventory; exports remain distinct."""

from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio

from app.adapters.exceptions import CapabilityNotSupportedError
from app.adapters.openwrt.adapter import OpenWRTAdapter
from app.adapters.opnsense.adapter import OPNsenseAdapter
from app.core.config import settings

CREATE_UNAVAILABLE = "OPNsense backup creation is not supported by this API; no backup was created"


@pytest_asyncio.fixture
async def wire():
    adapter = OPNsenseAdapter(
        host="192.0.2.55", username="owned", password="owned", verify_ssl=True
    )
    requests = []

    async def response(request):
        requests.append((request.method, request.url.path))
        if request.url.path.endswith("/download/this"):
            return httpx.Response(
                200, content=b"<opnsense><description>Owned</description></opnsense>"
            )
        if request.url.path.endswith("/backups/this"):
            return httpx.Response(200, json={"items": []})
        return httpx.Response(200, json={"status": "ok"})

    adapter._api._client = httpx.AsyncClient(
        base_url=adapter._api.base_url, transport=httpx.MockTransport(response)
    )
    try:
        yield adapter, requests
    finally:
        await adapter.disconnect()


@pytest.mark.parametrize("read_only", [False, True])
@pytest.mark.parametrize("force", [False, True])
async def test_direct_client_creation_is_unsupported_even_with_force(
    wire, monkeypatch, read_only, force
):
    adapter, requests = wire
    monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", read_only)
    with pytest.raises(CapabilityNotSupportedError, match=CREATE_UNAVAILABLE) as error:
        await adapter._api.create_backup(force=force)
    assert error.value.capability == "create_backup" and not requests


@pytest.mark.parametrize("read_only", [False, True])
@pytest.mark.parametrize("force", [False, True])
async def test_adapter_creation_is_unsupported_without_network_io(
    wire, monkeypatch, read_only, force
):
    adapter, requests = wire
    monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", read_only)
    adapter._direct_write_force = force
    result = await adapter.create_backup()
    assert result.success is False and result.error_code == "NOT_SUPPORTED"
    assert result.error == CREATE_UNAVAILABLE and result.data is None and not requests


async def test_openwrt_history_is_unsupported_without_claiming_empty_inventory():
    adapter = OpenWRTAdapter(host="192.0.2.55", username="owned", password="owned")
    try:
        result = await adapter.get_backup_list()
        assert result.success is False and result.error_code == "NOT_SUPPORTED"
        assert result.data is None and result.error == "OpenWRT backup inventory is not supported"
        assert adapter._api._client is None
    finally:
        await adapter.disconnect()


async def test_opnsense_confirmed_empty_history_is_still_a_success(wire):
    adapter, requests = wire
    result = await adapter.get_backup_list()
    assert result.success is True and result.data == {"backups": []}
    assert requests == [("GET", "/api/core/backup/backups/this")]


async def test_opnsense_configuration_export_stays_separate(wire):
    adapter, requests = wire
    result = await adapter.download_config()
    assert result.success is True
    assert result.data == {"config_xml": "<opnsense><description>Owned</description></opnsense>"}
    assert requests == [("GET", "/api/core/backup/download/this")]


async def test_openwrt_configuration_export_stays_separate(monkeypatch):
    adapter = OpenWRTAdapter(host="192.0.2.55", username="owned", password="owned")
    export = AsyncMock(return_value="owned-archive-bytes")
    monkeypatch.setattr(adapter._api, "create_backup", export)
    try:
        result = await adapter.download_config()
        assert result.success is True
        assert result.data == {
            "backup_data": "owned-archive-bytes",
            "format": "tar.gz",
            "scope": "sysupgrade",
        }
        export.assert_awaited_once_with()
    finally:
        await adapter.disconnect()
