# SPDX-License-Identifier: AGPL-3.0-only
"""Real-database ownership, encryption and reimport checks; no VPN daemon/device."""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.crypto import decrypt_credential, is_encrypted
from app.models.core import Controller, Organization, Site
from app.models.vpn import SiteVPNConfiguration, VPNSource, VPNType
from app.services.brain_vpn import BrainVPNService

CONFIG = "client\ndev tun\nproto udp\nremote 198.51.100.10 1194\n"


@pytest.fixture
async def import_fixture(db_session, monkeypatch):
    org = Organization(name="VPN import fixture", slug="vpn-import-" + uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(organization_id=org.id, name="Owned site", slug="owned")
    db_session.add(site)
    await db_session.flush()
    controller = Controller(site_id=site.id, name="Owned brain", controller_type="opnsense",
                            host="198.51.100.10", port=443)
    db_session.add(controller)
    await db_session.flush()
    adapter = SimpleNamespace(get_wireguard_server=AsyncMock(return_value=SimpleNamespace(
        success=True, data={"name": "wg0", "port": 51820, "pubkey": "synthetic-public-key"},
    )), close=AsyncMock())
    connect = AsyncMock(return_value=adapter)
    monkeypatch.setattr("app.services.brain_vpn._get_adapter_for_controller", connect)
    return BrainVPNService(db_session), org, site, controller, connect


@pytest.mark.parametrize("origin", ["manual", "brain"])
async def test_new_import_is_queryable_by_organization_and_reimport_keeps_identity(
    db_session, import_fixture, origin,
):
    service, org, site, controller, connect = import_fixture

    async def create():
        if origin == "manual":
            return await service.import_openvpn_config(site.id, org.id, CONFIG)
        return await service.import_from_brain(controller.id, org.id, VPNType.WIREGUARD, "fixture-wg")

    first = await create()
    rows = (await db_session.execute(select(SiteVPNConfiguration).where(
        SiteVPNConfiguration.organization_id == org.id,
    ))).scalars().all()
    assert len(rows) == 1 and rows[0].id == first.id
    assert first.site_id == site.id
    if origin == "manual":
        assert first.vpn_source == VPNSource.MANUAL
        assert is_encrypted(first.openvpn_config_content)
        assert decrypt_credential(first.openvpn_config_content) == CONFIG
        connect.assert_not_awaited()
    else:
        assert first.vpn_source == VPNSource.BRAIN_IMPORT
        assert first.controller_id == controller.id
        assert first.wireguard_endpoint == "198.51.100.10:51820"
    second = await create()
    assert second.id == first.id
    assert second.organization_id == org.id
    assert len((await db_session.execute(select(SiteVPNConfiguration).where(
        SiteVPNConfiguration.organization_id == org.id,
    ))).scalars().all()) == 1


@pytest.mark.parametrize("site_state", ["foreign", "deleted"])
async def test_manual_import_refuses_unowned_or_deleted_site(db_session, import_fixture, site_state):
    service, org, site, _, connect = import_fixture
    owner = org.id
    if site_state == "foreign":
        owner = uuid4()
    else:
        site.deleted_at = datetime.now(UTC)
        await db_session.flush()
    with pytest.raises(ValueError, match="Site not found"):
        await service.import_openvpn_config(site.id, owner, CONFIG)
    connect.assert_not_awaited()
    assert (await db_session.execute(select(SiteVPNConfiguration).where(
        SiteVPNConfiguration.site_id == site.id,
    ))).scalars().all() == []
