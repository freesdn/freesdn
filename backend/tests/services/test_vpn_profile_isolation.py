# SPDX-License-Identifier: AGPL-3.0-only
"""Imports must preserve unrelated site profiles and encrypt each credential write."""

from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.crypto import decrypt_credential, encrypt_credential, is_encrypted
from app.models.core import Controller, Organization, Site
from app.models.vpn import SiteVPNConfiguration, VPNSource, VPNType
from app.services.brain_vpn import BrainVPNService
from app.services.vpn_integration import PersistentVPNService

CONFIG = "client\ndev tun\nproto udp\nremote 198.51.100.10 1194\n"


@pytest.fixture
async def profiles(db_session, monkeypatch):
    org = Organization(name="Profile isolation", slug="profiles-" + uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(organization_id=org.id, name="Owned profiles", slug="profiles")
    db_session.add(site)
    await db_session.flush()
    controller = Controller(site_id=site.id, name="Owned brain", controller_type="opnsense",
                            host="198.51.100.10", port=443)
    db_session.add(controller)
    await db_session.flush()
    adapter = SimpleNamespace(get_wireguard_server=AsyncMock(return_value=SimpleNamespace(
        success=True, data={"name": "wg0", "port": 51820, "pubkey": "synthetic-public-key"},
    )), close=AsyncMock())
    monkeypatch.setattr("app.services.brain_vpn._get_adapter_for_controller", AsyncMock(return_value=adapter))
    return BrainVPNService(db_session), org, site, controller


async def add_profile(session, org, site, **values):
    row = SiteVPNConfiguration(site_id=site.id, organization_id=org.id, **values)
    session.add(row)
    await session.flush()
    return row


@pytest.mark.parametrize("origin", ["brain", "manual"])
async def test_import_never_converts_an_unrelated_profile(db_session, profiles, origin):
    service, org, site, controller = profiles
    old = await add_profile(db_session, org, site, vpn_type=VPNType.TAILSCALE,
                            vpn_source=VPNSource.MANUAL, is_primary=True, tailscale_node="keep-node")
    if origin == "brain":
        imported = await service.import_from_brain(controller.id, org.id, VPNType.WIREGUARD, "server-a")
    else:
        imported = await service.import_openvpn_config(site.id, org.id, CONFIG)
    assert imported.id != old.id
    await db_session.refresh(old)
    assert old.vpn_type == VPNType.TAILSCALE and old.tailscale_node == "keep-node"
    assert old.is_primary and old.vpn_source == VPNSource.MANUAL


async def test_brain_server_identity_selects_only_its_own_profile(db_session, profiles):
    service, org, site, controller = profiles
    first = await service.import_from_brain(controller.id, org.id, VPNType.WIREGUARD, "server-a")
    second = await service.import_from_brain(controller.id, org.id, VPNType.WIREGUARD, "server-b")
    assert first.id != second.id
    again = await service.import_from_brain(controller.id, org.id, VPNType.WIREGUARD, "server-a")
    assert again.id == first.id
    await db_session.refresh(second)
    assert second.brain_vpn_server_id == "server-b"


async def test_duplicate_brain_identity_is_an_explicit_conflict(db_session, profiles):
    service, org, site, controller = profiles
    for _ in range(2):
        await add_profile(db_session, org, site, vpn_type=VPNType.WIREGUARD,
                          vpn_source=VPNSource.BRAIN_IMPORT, controller_id=controller.id,
                          brain_vpn_server_id="server-a")
    with pytest.raises(ValueError, match="Multiple.*profiles"):
        await service.import_from_brain(controller.id, org.id, VPNType.WIREGUARD, "server-a")


async def test_manual_import_requires_a_target_when_several_profiles_match(db_session, profiles):
    service, org, site, _ = profiles
    rows = [await add_profile(db_session, org, site, vpn_type=VPNType.OPENVPN,
                             vpn_source=VPNSource.MANUAL, vpn_endpoint=endpoint)
            for endpoint in ["198.51.100.20", "198.51.100.21"]]
    with pytest.raises(ValueError, match="Multiple.*profiles"):
        await service.import_openvpn_config(site.id, org.id, CONFIG)
    imported = await service.import_openvpn_config(site.id, org.id, CONFIG, config_id=rows[1].id)
    assert imported.id == rows[1].id and is_encrypted(imported.openvpn_config_content)
    await db_session.refresh(rows[0])
    assert rows[0].vpn_endpoint == "198.51.100.20" and rows[0].openvpn_config_content is None


@pytest.mark.parametrize("kind", ["other-site", "other-org", "other-type", "brain-managed"])
async def test_explicit_manual_target_cannot_cross_ownership_or_profile_kind(db_session, profiles, kind):
    service, org, site, controller = profiles
    values = {"vpn_type": VPNType.OPENVPN, "vpn_source": VPNSource.MANUAL}
    row = await add_profile(db_session, org, site, **values)
    if kind == "other-site":
        other = Site(organization_id=org.id, name="Other", slug="other")
        db_session.add(other)
        await db_session.flush()
        row.site_id = other.id
    elif kind == "other-org":
        other_org = Organization(name="Foreign profile owner", slug="foreign-" + uuid4().hex)
        db_session.add(other_org)
        await db_session.flush()
        row.organization_id = other_org.id
    elif kind == "other-type":
        row.vpn_type = VPNType.TAILSCALE
    else:
        row.vpn_source = VPNSource.BRAIN_IMPORT
        row.controller_id = controller.id
    await db_session.flush()
    with pytest.raises(ValueError, match="VPN profile not found"):
        await service.import_openvpn_config(site.id, org.id, CONFIG, config_id=row.id)
    await db_session.refresh(row)
    assert row.openvpn_config_content is None


@pytest.mark.parametrize("mode", ["create", "update"])
async def test_legacy_site_upsert_encrypts_config_without_modifying_input(db_session, profiles, mode):
    _, org, site, _ = profiles
    if mode == "update":
        await add_profile(db_session, org, site, vpn_type=VPNType.OPENVPN)
    data = {"vpn_type": VPNType.OPENVPN, "openvpn_config_content": CONFIG}
    row = await PersistentVPNService.upsert_site_config(db_session, site.id, data)
    await db_session.refresh(row)
    assert is_encrypted(row.openvpn_config_content)
    assert decrypt_credential(row.openvpn_config_content) == CONFIG
    assert data["openvpn_config_content"] == CONFIG


async def test_multi_profile_create_encrypts_storage_and_omits_secret_response(db_session, profiles, monkeypatch):
    from app.api.v1.endpoints import vpn
    from app.schemas.vpn import SiteVPNConfigCreate

    _, org, site, _ = profiles
    monkeypatch.setattr(vpn, "_verify_site_org", AsyncMock(return_value=site))
    response = await vpn.create_site_vpn_config(
        site.id, SiteVPNConfigCreate(vpn_type=VPNType.OPENVPN, openvpn_config_content=CONFIG),
        db_session, SimpleNamespace(id=uuid4()),
    )
    row = (await db_session.execute(select(SiteVPNConfiguration).where(
        SiteVPNConfiguration.id == response.id,
    ))).scalar_one()
    assert is_encrypted(row.openvpn_config_content)
    assert decrypt_credential(row.openvpn_config_content) == CONFIG
    assert "openvpn_config_content" not in response.model_dump()


async def test_site_profile_response_serializes_database_identifiers_and_sync_time(profiles):
    from app.schemas.vpn import SiteVPNConfigResponse

    service, org, site, controller = profiles
    row = await service.import_from_brain(controller.id, org.id, VPNType.WIREGUARD, "server-a")
    response = SiteVPNConfigResponse.model_validate(row).model_dump(mode="json")
    assert response["site_id"] == str(site.id)
    assert response["organization_id"] == str(org.id)
    assert response["controller_id"] == str(controller.id)
    assert response["last_config_sync"] is not None


@pytest.mark.parametrize("apply", [False, True])
async def test_legacy_batch_audits_or_encrypts_without_rewriting_ciphertext(db_session, profiles, apply):
    from app.services.vpn_profile_storage import encrypt_legacy_profile_batch

    _, org, site, _ = profiles
    old_cipher = encrypt_credential(CONFIG)
    plain = await add_profile(db_session, org, site, openvpn_config_content=CONFIG)
    encrypted = await add_profile(db_session, org, site, openvpn_config_content=old_cipher)
    await add_profile(db_session, org, site, openvpn_config_content=None)
    result = await encrypt_legacy_profile_batch(db_session, apply=apply)
    assert result["examined"] == 2 and result["plaintext"] == 1
    assert result["already_encrypted"] == 1 and result["updated"] == int(apply)
    await db_session.refresh(plain)
    await db_session.refresh(encrypted)
    assert encrypted.openvpn_config_content == old_cipher
    if apply:
        assert is_encrypted(plain.openvpn_config_content)
        assert decrypt_credential(plain.openvpn_config_content) == CONFIG
        again = await encrypt_legacy_profile_batch(db_session, apply=True)
        assert again["plaintext"] == again["updated"] == 0
    else:
        assert plain.openvpn_config_content == CONFIG


@pytest.mark.parametrize("bad_cipher", ["gAAAA-invalid-token", "foreign-key"])
async def test_legacy_batch_refuses_unreadable_cipher_before_any_write(db_session, profiles, bad_cipher):
    from cryptography.fernet import Fernet

    from app.services.vpn_profile_storage import encrypt_legacy_profile_batch

    _, org, site, _ = profiles
    if bad_cipher == "foreign-key":
        bad_cipher = Fernet(Fernet.generate_key()).encrypt(CONFIG.encode()).decode()
    plain = await add_profile(db_session, org, site, openvpn_config_content=CONFIG)
    await add_profile(db_session, org, site, openvpn_config_content=bad_cipher)
    with pytest.raises(ValueError, match="Cannot decrypt credential"):
        await encrypt_legacy_profile_batch(db_session, apply=True)
    await db_session.refresh(plain)
    assert plain.openvpn_config_content == CONFIG


async def test_legacy_batch_cursor_visits_every_profile_once(db_session, profiles):
    from uuid import UUID

    from app.services.vpn_profile_storage import encrypt_legacy_profile_batch

    _, org, site, _ = profiles
    values = [CONFIG + "# München\n", CONFIG + "# 東京\n", CONFIG]
    rows = [await add_profile(db_session, org, site, openvpn_config_content=value) for value in values]
    cursor, seen = None, []
    for _ in range(4):
        result = await encrypt_legacy_profile_batch(db_session, apply=True, after_id=cursor, limit=1)
        if result["examined"] == 0:
            break
        assert result["updated"] == 1
        cursor = UUID(result["last_id"])
        seen.append(cursor)
    assert len(seen) == 3 and set(seen) == {row.id for row in rows}
    for row, value in zip(rows, values, strict=True):
        await db_session.refresh(row)
        assert decrypt_credential(row.openvpn_config_content) == value
