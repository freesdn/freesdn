# SPDX-License-Identifier: AGPL-3.0-only
"""First imports must create an org-visible record, not fail after provider reads."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_credential, is_encrypted
from app.models.core import Controller, Site
from app.models.vpn import VPNSource, VPNStatus, VPNType
from app.services.brain_vpn import BrainVPNService

CONFIG = "client\ndev tun\nproto udp\nremote 198.51.100.10 1194\n"


def result(row):
    value = MagicMock()
    value.scalar_one_or_none.return_value = row
    value.scalars.return_value.all.return_value = [] if row is None else [row]
    return value


@pytest.mark.parametrize("origin", ["manual", "brain"])
async def test_first_import_creates_owned_configuration(origin, monkeypatch):
    org_id, site_id, controller_id = uuid4(), uuid4(), uuid4()
    site = Site(id=site_id, organization_id=org_id, name="Import fixture", slug="import")
    controller = Controller(
        id=controller_id, site_id=site_id, name="Owned provider", controller_type="opnsense",
        host="198.51.100.10",
    )
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock(side_effect=[
        *([result(controller)] if origin == "brain" else []), result(site), result(None),
    ])
    session.flush = AsyncMock()
    session.refresh = AsyncMock()
    adapter = SimpleNamespace(
        get_openvpn_instance=AsyncMock(return_value=SimpleNamespace(
            success=True, data={"proto": "udp", "port": 1194, "local_network": "192.0.2.0/24"},
        )), close=AsyncMock(),
    )
    connect = AsyncMock(return_value=adapter)
    monkeypatch.setattr("app.services.brain_vpn._get_adapter_for_controller", connect)
    service = BrainVPNService(session)
    if origin == "manual":
        config = await service.import_openvpn_config(site_id, org_id, CONFIG)
        connect.assert_not_awaited()
        assert is_encrypted(config.openvpn_config_content)
        assert decrypt_credential(config.openvpn_config_content) == CONFIG
        assert config.vpn_source == VPNSource.MANUAL
    else:
        config = await service.import_from_brain(
            controller_id, org_id, VPNType.OPENVPN, "fixture-server"
        )
        adapter.get_openvpn_instance.assert_awaited_once_with("fixture-server")
        adapter.close.assert_awaited_once()
        assert config.vpn_source == VPNSource.BRAIN_IMPORT
        assert config.controller_id == controller_id
        assert config.remote_subnets == ["192.0.2.0/24"]
    assert config.organization_id == org_id
    assert config.site_id == site_id
    assert config.vpn_type == VPNType.OPENVPN
    assert config.vpn_endpoint == "198.51.100.10"
    assert config.vpn_port == 1194
    assert config.status == VPNStatus.DISCONNECTED
    session.add.assert_called_once_with(config)
    session.flush.assert_awaited_once()
    session.refresh.assert_awaited_once_with(config)


@pytest.mark.parametrize("origin", ["manual", "brain"])
async def test_missing_or_foreign_site_never_fetches_config_or_creates_row(origin, monkeypatch):
    org_id, site_id, controller_id = uuid4(), uuid4(), uuid4()
    controller = Controller(
        id=controller_id, site_id=site_id, name="Owned provider", controller_type="opnsense",
        host="198.51.100.10",
    )
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock(side_effect=[
        *([result(controller)] if origin == "brain" else []), result(None),
    ])
    connect = AsyncMock()
    monkeypatch.setattr("app.services.brain_vpn._get_adapter_for_controller", connect)
    service = BrainVPNService(session)
    with pytest.raises(ValueError, match="Site not found"):
        if origin == "manual":
            await service.import_openvpn_config(site_id, org_id, CONFIG)
        else:
            await service.import_from_brain(controller_id, org_id, VPNType.OPENVPN, "fixture-server")
    connect.assert_not_awaited()
    session.add.assert_not_called()
