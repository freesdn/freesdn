"""The backup-write permission must not become a full-configuration export permission."""

import asyncio
import base64
import gzip
from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import pytest_asyncio

from app.adapters.openwrt.adapter import OpenWRTAdapter
from app.adapters.openwrt.client import OpenWRTClient
from app.core.config import settings
from tests.modules import test_gateway_backup_capabilities as helpers

trigger = helpers.trigger
capability = helpers.capability
snapshot = helpers.snapshot
UNSUPPORTED = (
    "OpenWRT backup creation is not supported; use configuration download to export an archive"
)
SECRET = "owned-openwrt-config-export-secret"
ARCHIVE = gzip.compress(SECRET.encode(), mtime=0)


@pytest.mark.parametrize("read_only", [False, True])
@pytest.mark.parametrize("force", [False, True])
async def test_adapter_create_does_not_export_or_claim_a_saved_backup(
    monkeypatch, read_only, force
):
    adapter = OpenWRTAdapter(host="192.0.2.55", username="owned", password="owned")
    export = AsyncMock(return_value=ARCHIVE)
    monkeypatch.setattr(adapter._api, "create_backup", export)
    monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", read_only)
    adapter._direct_write_force = force
    try:
        result = await adapter.create_backup()
        assert result.success is False and result.error_code == "NOT_SUPPORTED"
        assert result.error == UNSUPPORTED and result.data is None
        export.assert_not_awaited()
    finally:
        await adapter.disconnect()


@pytest.mark.parametrize("read_only", [False, True])
@pytest.mark.parametrize("content", [ARCHIVE, b"", b"owned-ascii"])
async def test_adapter_download_keeps_the_existing_export_contract(monkeypatch, read_only, content):
    adapter = OpenWRTAdapter(host="192.0.2.55", username="owned", password="owned")
    export = AsyncMock(return_value=content)
    monkeypatch.setattr(adapter._api, "create_backup", export)
    monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", read_only)
    try:
        result = await adapter.download_config()
        assert result.success is True
        assert result.data == {"backup_data": content, "format": "tar.gz", "scope": "sysupgrade"}
        export.assert_awaited_once_with()
    finally:
        await adapter.disconnect()


async def test_adapter_download_cancellation_is_not_a_failure_result(monkeypatch):
    adapter = OpenWRTAdapter(host="192.0.2.55", username="owned", password="owned")
    export = AsyncMock(side_effect=asyncio.CancelledError())
    monkeypatch.setattr(adapter._api, "create_backup", export)
    try:
        with pytest.raises(asyncio.CancelledError):
            await adapter.download_config()
        export.assert_awaited_once_with()
    finally:
        await adapter.disconnect()


async def test_adapter_download_failure_is_not_a_saved_backup(monkeypatch):
    adapter = OpenWRTAdapter(host="192.0.2.55", username="owned", password="owned")
    export = AsyncMock(side_effect=RuntimeError("owned-export-failure"))
    monkeypatch.setattr(adapter._api, "create_backup", export)
    try:
        result = await adapter.download_config()
        assert result.success is False and result.data is None
        export.assert_awaited_once_with()
    finally:
        await adapter.disconnect()


@pytest_asyncio.fixture
async def separation(capability, monkeypatch):
    f = capability
    f.gateway.vendor = "openwrt"
    f.export_calls = []
    f.export_result = ARCHIVE

    async def export(client):
        f.export_calls.append("archive-export")
        if isinstance(f.export_result, BaseException):
            raise f.export_result
        return f.export_result

    monkeypatch.setattr(OpenWRTClient, "create_backup", export)
    yield f


@pytest.mark.parametrize("read_only", [False, True])
@pytest.mark.parametrize("role", ["super_admin", "viewer"])
@pytest.mark.parametrize("outcome", ["ascii", "gzip", "vendor-error"])
async def test_create_endpoint_never_returns_configuration_under_backup_permission(
    separation, monkeypatch, read_only, role, outcome, caplog
):
    f = separation
    f.user.role = role
    f.permissions = ["firewall.manage_rules"]
    f.site_ids = {f.gateway.site_id}
    f.export_result = {
        "ascii": SECRET.encode(),
        "gzip": ARCHIVE,
        "vendor-error": RuntimeError(SECRET),
    }[outcome]
    monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", read_only)
    before = await snapshot(f)
    response = await f.client.post(f"/firewall/gateways/{f.gateway.id}/backups")
    assert response.status_code == 501
    assert response.json() == {"error": {"code": 501, "message": UNSUPPORTED, "request_id": None}}
    assert not f.export_calls and not f.requests and f.calls == ["construct", "connect"]
    assert SECRET not in response.text and SECRET not in caplog.text
    assert await snapshot(f) == before


@pytest.mark.parametrize(
    "denial",
    [
        "missing",
        "organization",
        "deleted",
        "site",
        "null-site",
        "permission",
        "scoped",
        "anonymous",
    ],
)
async def test_create_retains_access_checks_before_adapter_construction(separation, denial):
    f = separation
    gateway_id = f.gateway.id
    expected = 404
    if denial == "missing":
        gateway_id = uuid4()
    elif denial == "organization":
        f.user.organization_id = uuid4()
    elif denial == "deleted":
        f.gateway.deleted_at = datetime.now(UTC)
    elif denial in ["site", "null-site"]:
        f.user.role = "viewer"
        f.site_ids = {f.sites[1].id}
        if denial == "null-site":
            f.gateway.site_id = None
    elif denial in ["permission", "scoped"]:
        f.permissions = []
        f.scoped = denial == "scoped"
        if denial == "permission":
            f.user.role = "viewer"
        expected = 403
    else:
        f.anonymous = True
        expected = 401
    before = await snapshot(f)
    response = await f.client.post(f"/firewall/gateways/{gateway_id}/backups")
    assert response.status_code == expected
    assert not f.calls and not f.export_calls and not f.requests
    assert "not supported" not in response.text
    assert await snapshot(f) == before


@pytest.mark.parametrize("read_only", [False, True])
async def test_full_export_remains_on_the_privileged_download_endpoint(
    separation, monkeypatch, read_only
):
    f = separation
    monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", read_only)
    before = await snapshot(f)
    response = await f.client.get(f"/firewall/gateways/{f.gateway.id}/config/download")
    assert response.status_code == 200
    assert response.json() == {
        "gateway_id": str(f.gateway.id),
        "vendor": "openwrt",
        "config": {
            "backup_data": base64.b64encode(ARCHIVE).decode("ascii"),
            "encoding": "base64",
            "format": "tar.gz",
            "scope": "sysupgrade",
        },
    }
    assert f.export_calls == ["archive-export"] and not f.requests
    assert await snapshot(f) == before


@pytest.mark.parametrize("denial", ["role", "permission"])
async def test_backup_permission_does_not_authorize_config_download(separation, denial):
    f = separation
    if denial == "role":
        f.user.role = "viewer"
        f.site_ids = {f.gateway.site_id}
    else:
        f.permissions = ["firewall.manage_rules"]
        f.scoped = True
    before = await snapshot(f)
    response = await f.client.get(f"/firewall/gateways/{f.gateway.id}/config/download")
    assert response.status_code == 403 and not f.calls and not f.export_calls
    assert await snapshot(f) == before
