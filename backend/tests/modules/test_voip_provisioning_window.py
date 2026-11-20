# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 FreeSDN
"""An unsigned fetch from the site subnet gets a phone's config only in a window.

Found in review of 26.11.2: a factory phone cannot prove who it is, so the
unsigned ``cfg<MAC>.xml`` fetch was served to ANY device on the site subnet
that knew the MAC, SIP password included. The Provision actions now open a
short window for that fetch; outside it only a signed URL works. Real
PostgreSQL; the request is a stand-in carrying the resolved client address.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_credential
from app.core.dependencies import CurrentUser
from app.models.core import Organization, Site, User
from app.modules.voip import api as voip_api
from app.modules.voip.models import PBX, ConfigTemplate, Extension, Phone
from app.modules.voip.provisioning import ProvisioningService
from app.modules.voip.provisioning_auth import (
    PROVISIONING_WINDOW,
    generate_provisioning_signature,
    resolve_provisioning_request,
)
from app.modules.voip.schemas import ConfigTemplateResponse
from app.modules.voip.service import VoIPService

MAC = "00:0b:82:aa:bb:cc"


def _request(host: str, sig: str | None = None) -> SimpleNamespace:
    params = {"sig": sig} if sig else {}
    return SimpleNamespace(
        client=SimpleNamespace(host=host),
        query_params=params,
        headers={},
    )


async def _phone(db: AsyncSession) -> Phone:
    org = Organization(name="Window", slug=f"window-{uuid4().hex[:8]}")
    db.add(org)
    await db.flush()
    site = Site(
        organization_id=org.id,
        name="Main",
        slug=f"main-{uuid4().hex[:6]}",
        subnets=[{"cidr": "192.168.50.0/24", "name": "phones"}],
        voip_zero_touch_provisioning=True,
    )
    db.add(site)
    await db.flush()
    phone = Phone(
        site_id=site.id,
        name="desk",
        mac_address=MAC,
        ip_address="192.168.50.77",  # 26.11.3: zero-touch needs a recorded address
        vendor="grandstream",
        status="offline",
        lifecycle_state="managed",
        sip_registered=False,
        settings={},
        tags=[],
    )
    db.add(phone)
    await db.flush()
    return phone


async def test_a_subnet_fetch_without_a_window_is_refused(db_session):
    """Fails on 26.11.2: any host on the subnet got the config."""
    await _phone(db_session)
    ctx = await resolve_provisioning_request(_request("192.168.50.77"), db_session, MAC)
    assert ctx is None


async def test_provision_opens_the_window_for_a_subnet_fetch(db_session, tmp_path):
    phone = await _phone(db_session)
    prov = ProvisioningService(db_session, provision_dir=str(tmp_path))
    before = datetime.now(UTC)
    result = await prov.generate_phone_config(phone.id, write_file=True, open_window=True)
    await db_session.refresh(phone)
    assert phone.provisioning_open_until is not None
    assert phone.provisioning_open_until <= before + PROVISIONING_WINDOW + timedelta(seconds=5)
    assert result["provisioning_open_until"] == phone.provisioning_open_until.isoformat()

    ctx = await resolve_provisioning_request(_request("192.168.50.77"), db_session, MAC)
    assert ctx is not None and ctx.auth_method == "subnet"
    # Still refused from outside the subnet, window or not.
    assert await resolve_provisioning_request(_request("10.9.9.9"), db_session, MAC) is None


async def test_the_window_closes(db_session):
    phone = await _phone(db_session)
    phone.provisioning_open_until = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.flush()
    assert await resolve_provisioning_request(_request("192.168.50.77"), db_session, MAC) is None


async def test_the_phones_own_fetch_does_not_reopen_the_window(db_session, tmp_path):
    """The config pull regenerates a missing file; that must not extend trust."""
    phone = await _phone(db_session)
    prov = ProvisioningService(db_session, provision_dir=str(tmp_path))
    await prov.generate_phone_config(phone.id, write_file=True)
    await db_session.refresh(phone)
    assert phone.provisioning_open_until is None


async def test_a_signed_url_works_at_any_time(db_session):
    await _phone(db_session)
    sig = generate_provisioning_signature(MAC)
    for host in ("192.168.50.77", "203.0.113.5"):
        ctx = await resolve_provisioning_request(_request(host, sig), db_session, MAC)
        assert ctx is not None and ctx.auth_method == "hmac"


async def _linked_phone(db: AsyncSession) -> tuple[Phone, ConfigTemplate]:
    """A phone on an extension with a SIP password and a template admin password."""
    phone = await _phone(db)
    pbx = PBX(site_id=phone.site_id, name="pbx", ip_address="192.168.50.2")
    db.add(pbx)
    await db.flush()
    ext = Extension(pbx_id=pbx.id, extension_number="101", display_name="Desk")
    db.add(ext)
    await db.flush()
    template = ConfigTemplate(
        site_id=phone.site_id,
        name="desk",
        vendor="grandstream",
        feature_settings={"admin_password": "template-admin-secret", "timezone": "UTC"},
        raw_overrides={"P34": "override-sip-secret", "P271": "1"},
    )
    db.add(template)
    await db.flush()
    phone.extension_id = ext.id
    phone.config_template_id = template.id
    phone.sip_password_enc = encrypt_credential("phone-sip-secret")
    await db.flush()
    db.expunge_all()  # the provision path must load what it needs itself
    return phone, template


async def test_a_phone_on_an_extension_can_be_provisioned(db_session, tmp_path):
    """Fails on 26.11.2 and the first 26.11.3 candidate: the renderer read the
    lazy extension relationship in an async session, so Provision raised for
    every phone linked to an extension and could never open its window."""
    phone, _ = await _linked_phone(db_session)
    prov = ProvisioningService(db_session, provision_dir=str(tmp_path))
    result = await prov.generate_phone_config(phone.id, write_file=True, open_window=True)
    assert "<P35>101</P35>" in result["xml"]
    assert result["provisioning_open_until"]


async def test_the_config_preview_never_shows_a_password(db_session):
    """Fails on 26.11.2: any Viewer (voip.view) read the SIP and admin passwords."""
    phone, _ = await _linked_phone(db_session)
    xml = await ProvisioningService(db_session).generate_config_preview(phone.id)
    for secret in ("phone-sip-secret", "template-admin-secret", "override-sip-secret"):
        assert secret not in xml
    assert "<P2>********</P2>" in xml and "<P34>********</P34>" in xml
    assert "<P35>101</P35>" in xml and "<P271>1</P271>" in xml


async def test_a_template_read_hides_credentials_and_an_update_keeps_them(db_session):
    _, template = await _linked_phone(db_session)
    shown = ConfigTemplateResponse.model_validate(
        await ProvisioningService(db_session).get_template(template.id)
    ).model_dump(mode="json")
    assert shown["feature_settings"] == {"admin_password": "********", "timezone": "UTC"}
    assert shown["raw_overrides"] == {"P34": "********", "P271": "1"}

    # The editor sends the shown values back with one real change.
    prov = ProvisioningService(db_session)
    await prov.update_template(
        template.id,
        {
            "feature_settings": {**shown["feature_settings"], "timezone": "CET"},
            "raw_overrides": shown["raw_overrides"],
        },
    )
    stored = await prov.get_template(template.id)
    assert stored.feature_settings == {"admin_password": "template-admin-secret", "timezone": "CET"}
    assert stored.raw_overrides == {"P34": "override-sip-secret", "P271": "1"}


def _caller(*permissions: str, organization_id: object = None) -> CurrentUser:
    user = User(
        id=uuid4(),
        email=f"{uuid4().hex[:8]}@example.com",
        username=uuid4().hex[:8],
        organization_id=organization_id or uuid4(),
        role="viewer",
        hashed_password="x",
        is_active=True,
    )
    return CurrentUser(user=user, permissions=list(permissions))


async def test_a_viewer_gets_no_p_value_from_a_template(db_session):
    """Fails on the second 26.11.3 candidate: a numeric P2 and P-values its
    list did not name (P1361, the config-server password) reached a Viewer."""
    _, template = await _linked_phone(db_session)
    stored = await db_session.get(ConfigTemplate, template.id)  # the fixture detached it
    stored.raw_overrides = {"P2": 123456, "P1361": "cfg-server-secret", "P271": "1"}
    stored.sip_settings = {"accounts": [{"password": "nested-secret", "port": 5060}]}
    await db_session.flush()
    await db_session.refresh(stored)  # as update_template does before returning

    viewer = voip_api._template_out(stored, _caller("voip.view"))
    assert viewer["raw_overrides"] == {"P2": "********", "P1361": "********", "P271": "********"}
    assert viewer["sip_settings"] == {"accounts": [{"password": "********", "port": 5060}]}

    manager = voip_api._template_out(stored, _caller("voip.view", "voip.manage_phones"))
    assert manager["raw_overrides"] == {"P2": "********", "P1361": "********", "P271": "1"}


async def test_a_template_duplicated_from_a_read_stores_no_placeholder(db_session):
    _, template = await _linked_phone(db_session)
    prov = ProvisioningService(db_session)
    shown = voip_api._template_out(
        await prov.get_template(template.id), _caller("voip.view", "voip.manage_phones")
    )
    copy = await prov.create_template(
        {
            "site_id": template.site_id,
            "name": "copy",
            "vendor": "grandstream",
            "feature_settings": shown["feature_settings"],
            "raw_overrides": shown["raw_overrides"],
        }
    )
    assert copy.feature_settings == {"timezone": "UTC"}
    assert copy.raw_overrides == {"P271": "1"}


async def test_a_phones_own_p_values_are_hidden_and_kept(db_session):
    phone, _ = await _linked_phone(db_session)
    stored = await db_session.get(Phone, phone.id)
    stored.settings = {"p_values": {"P2": "phone-admin-secret", "P64": "UTC"}}
    await db_session.flush()

    viewer = voip_api._sanitize_phone_response(stored, _caller("voip.view"))
    assert viewer["settings"]["p_values"] == {"P2": "********", "P64": "********"}
    manager = voip_api._sanitize_phone_response(stored, _caller("voip.view", "voip.manage_phones"))
    assert manager["settings"]["p_values"] == {"P2": "********", "P64": "UTC"}


async def test_the_window_serves_one_fetch(db_session, tmp_path):
    """Fails on the third 26.11.3 candidate: every fetch in the 15 minutes was
    served, so any device on the subnet could take a copy alongside the phone."""
    phone = await _phone(db_session)
    prov = ProvisioningService(db_session, provision_dir=str(tmp_path))
    await prov.generate_phone_config(phone.id, write_file=True, open_window=True)
    first = await resolve_provisioning_request(_request("192.168.50.77"), db_session, MAC)
    assert first is not None and first.auth_method == "subnet"
    await db_session.flush()
    assert await resolve_provisioning_request(_request("192.168.50.78"), db_session, MAC) is None


async def test_a_known_phone_is_served_only_at_its_address(db_session, tmp_path):
    phone = await _phone(db_session)
    phone.ip_address = "192.168.50.20"
    await db_session.flush()
    prov = ProvisioningService(db_session, provision_dir=str(tmp_path))
    await prov.generate_phone_config(phone.id, write_file=True, open_window=True)
    assert await resolve_provisioning_request(_request("192.168.50.77"), db_session, MAC) is None
    ctx = await resolve_provisioning_request(_request("192.168.50.20"), db_session, MAC)
    assert ctx is not None and ctx.auth_method == "subnet"


async def test_a_phone_created_from_a_read_stores_no_placeholder(db_session):
    phone = await _phone(db_session)
    service = VoIPService(db=db_session)
    created = await service.create_phone(
        {
            "site_id": phone.site_id,
            "name": "copy",
            "mac_address": "00:0b:82:aa:bb:dd",
            "settings": {"p_values": {"P2": "********", "P64": "UTC"}},
        }
    )
    assert created.settings == {"p_values": {"P64": "UTC"}}


def test_freepbx_password_aliases_are_redacted_everywhere():
    """Fails on the third 26.11.3 candidate: extension details and staged
    extension changes showed these to a Viewer."""
    from app.core.redaction import redact_secrets

    shown = redact_secrets(
        {"extPassword": "a", "vmPassword": "b", "sippasswd": "c", "has_password": True}
    )
    assert shown == {
        "extPassword": "***",
        "vmPassword": "***",
        "sippasswd": "***",
        "has_password": True,
    }


def test_a_config_backup_leaves_out_password_p_values():
    from app.modules.voip.backup import _redact

    assert _redact({"P2": "admin", "P34": "sip", "P271": "1"}, pvalues=True) == {"P271": "1"}


def test_a_vault_backup_keeps_password_p_values():
    """A vault (include_secrets) restore must not lose them."""
    from app.modules.voip.backup import _redact

    assert _redact({"P2": "admin", "P271": "1"}, pvalues=False) == {"P2": "admin", "P271": "1"}


def test_the_config_xml_hides_a_server_login():
    from app.modules.voip.setting_secrets import redact_config_xml

    xml = redact_config_xml(
        '<?xml version="1.0"?><gs_provision><config>'
        "<P237>https://prov:hunter2@cfg.example.com/p</P237><P30>pool.ntp.org</P30>"
        "</config></gs_provision>"
    )
    assert "hunter2" not in xml and "<P30>pool.ntp.org</P30>" in xml


def test_a_shared_redactor_placeholder_is_dropped_on_create():
    from app.modules.voip.setting_secrets import restore_redacted

    assert restore_redacted({"web_password": "***", "P64": "UTC"}, None) == {"P64": "UTC"}


async def test_a_site_without_zero_touch_serves_no_unsigned_fetch(db_session, tmp_path):
    """New sites start with zero-touch off: even in a window, the subnet gets nothing."""
    phone = await _phone(db_session)
    site = await db_session.get(Site, phone.site_id)
    site.voip_zero_touch_provisioning = False
    await db_session.flush()
    prov = ProvisioningService(db_session, provision_dir=str(tmp_path))
    await prov.generate_phone_config(phone.id, write_file=True, open_window=True)
    assert await resolve_provisioning_request(_request("192.168.50.77"), db_session, MAC) is None
    sig = generate_provisioning_signature(MAC)
    assert await resolve_provisioning_request(_request("192.168.50.77", sig), db_session, MAC)


class _ReadOnlyGrant:
    def site_level_allows(self, _action: str, _site_id: object) -> bool:
        return False


async def test_a_read_only_site_grant_cannot_open_the_window(db_session, tmp_path):
    """Fails on the fifth 26.11.3 candidate: a read-only grant could Provision."""
    from fastapi import HTTPException

    from app.core.site_access import current_user_var

    phone = await _phone(db_session)
    prov = ProvisioningService(db_session, provision_dir=str(tmp_path))
    token = current_user_var.set(_ReadOnlyGrant())
    try:
        with pytest.raises(HTTPException) as refused:
            await prov.generate_phone_config(phone.id, write_file=True, open_window=True)
    finally:
        current_user_var.reset(token)
    assert refused.value.status_code == 403
    await db_session.rollback()


async def test_the_zero_touch_switch_is_set_per_site(db_session, monkeypatch):
    """The change and its audit record go in one transaction (strict audit)."""
    from unittest.mock import AsyncMock

    from app.services import audit as audit_module

    logged = AsyncMock()
    monkeypatch.setattr(audit_module.AuditService, "log", logged)
    phone = await _phone(db_session)
    site = await db_session.get(Site, phone.site_id)
    manager = _caller("voip.view", "voip.manage_phones", organization_id=site.organization_id)
    service = VoIPService(db=db_session)
    off = await voip_api.set_zero_touch(
        site.id, voip_api.ZeroTouchSetting(enabled=False), manager, service
    )
    assert off.enabled is False
    await db_session.refresh(site)
    assert site.voip_zero_touch_provisioning is False
    kwargs = logged.await_args.kwargs
    assert kwargs["strict"] is True and kwargs["actor_id"] == manager.id
    assert kwargs["new_state"] == {"voip_zero_touch_provisioning": False}


def test_a_config_backup_leaves_out_server_logins_and_sippasswd():
    from app.modules.voip.backup import _redact

    kept = _redact(
        {"server_url": "http://prov:hunter2@cfg.example.com/", "sippasswd": "x", "tz": "UTC"},
        pvalues=True,
    )
    assert kept == {"tz": "UTC"}


def test_a_server_login_in_a_settings_list_is_hidden():
    from app.modules.voip.setting_secrets import redact_settings

    shown = redact_settings(
        {"servers": ["http://prov:hunter2@cfg.example.com/", "ntp.example.com"]}
    )
    assert shown == {"servers": ["********", "ntp.example.com"]}


async def test_a_read_only_site_grant_cannot_change_phones_or_templates(db_session):
    """Fails on the sixth 26.11.3 candidate: reboot, factory reset, SIP push,
    decommission, maintenance, delete and template edits loaded the phone or
    template through the read path and never asked for write access."""
    from fastapi import HTTPException

    from app.core.site_access import current_user_var

    phone, template = await _linked_phone(db_session)
    service = VoIPService(db=db_session)
    prov = ProvisioningService(db_session)
    token = current_user_var.set(_ReadOnlyGrant())
    try:
        for call in (
            lambda: service.delete_phone(phone.id),
            lambda: service.reboot_phone(phone.id),
            lambda: service.set_maintenance_mode(phone.id, True),
            lambda: service.update_phone(phone.id, {"name": "x"}),
            lambda: prov.update_template(template.id, {"name": "x"}),
            lambda: prov.delete_template(template.id),
        ):
            with pytest.raises(HTTPException) as refused:
                await call()
            assert refused.value.status_code == 403
    finally:
        current_user_var.reset(token)


async def test_discovery_does_not_move_a_managed_phone(db_session):
    """Fails on the sixth 26.11.3 candidate: any device answering a scan with a
    managed phone's MAC became that phone's address, where FreeSDN then sends
    SIP passwords and reboots."""
    phone = await _phone(db_session)
    phone.ip_address = "192.168.50.20"
    await db_session.flush()
    service = VoIPService(db=db_session)
    seen, created = await service.upsert_discovered_phone(
        site_id=phone.site_id, ip_address="192.168.50.99", mac_address=MAC, vendor="grandstream"
    )
    assert not created and seen.id == phone.id
    assert seen.ip_address == "192.168.50.20"
    assert seen.settings["discovered_address"]["ip"] == "192.168.50.99"


async def test_an_authenticated_connection_test_confirms_a_new_address(db_session):
    phone = await _phone(db_session)
    phone.ip_address = "192.168.50.20"
    phone.settings = {"discovered_address": {"ip": "192.168.50.99"}}
    await db_session.flush()
    await voip_api._persist_connection_result(
        phone, {"authenticated": False}, "192.168.50.99", db_session
    )
    assert phone.ip_address == "192.168.50.20"
    # Logged in, but the stored password is still the one for the old address.
    await voip_api._persist_connection_result(
        phone, {"authenticated": True}, "192.168.50.99", db_session
    )
    assert phone.ip_address == "192.168.50.20"
    # No MAC reported: nothing proves this is the same phone.
    await voip_api._persist_connection_result(
        phone, {"authenticated": True}, "192.168.50.99", db_session, credentials_saved=True
    )
    assert phone.ip_address == "192.168.50.20"
    await voip_api._persist_connection_result(
        phone,
        {"authenticated": True, "mac_address": MAC},
        "192.168.50.99",
        db_session,
        credentials_saved=True,
    )
    assert phone.ip_address == "192.168.50.99"
    assert "discovered_address" not in (phone.settings or {})


class _WritableExcept:
    def __init__(self, read_only_site):
        self.read_only_site = read_only_site

    def site_level_allows(self, _action: str, site_id: object) -> bool:
        return site_id != self.read_only_site


async def test_provision_checks_the_template_site_before_writing(db_session, tmp_path):
    """Fails on the sixth 26.11.3 candidate: the config file was written before
    the site-write refusal, and the template's site was never checked."""
    from fastapi import HTTPException

    from app.core.site_access import current_user_var

    phone, template = await _linked_phone(db_session)
    other = Site(
        organization_id=(await db_session.get(Site, phone.site_id)).organization_id,
        name="Other",
        slug=f"other-{uuid4().hex[:6]}",
    )
    db_session.add(other)
    await db_session.flush()
    stored = await db_session.get(ConfigTemplate, template.id)
    stored.site_id = other.id
    await db_session.flush()
    prov = ProvisioningService(db_session, provision_dir=str(tmp_path))
    token = current_user_var.set(_WritableExcept(other.id))
    try:
        with pytest.raises(HTTPException):
            await prov.generate_phone_config(phone.id, write_file=True, open_window=True)
    finally:
        current_user_var.reset(token)
    assert list(tmp_path.iterdir()) == []


async def test_a_phone_without_a_recorded_address_is_not_served_unsigned(db_session, tmp_path):
    """Fails on the seventh 26.11.3 candidate: any device on the subnet that knew
    the MAC took the fetch for a phone FreeSDN had no address for."""
    phone = await _phone(db_session)
    phone.ip_address = None
    await db_session.flush()
    prov = ProvisioningService(db_session, provision_dir=str(tmp_path))
    await prov.generate_phone_config(phone.id, write_file=True, open_window=True)
    assert await resolve_provisioning_request(_request("192.168.50.77"), db_session, MAC) is None


def test_a_manager_with_a_read_only_grant_gets_viewer_masking():
    site = uuid4()

    class _Manager:
        def has_permission(self, permission):
            return permission == "voip.manage_phones"

        def site_level_allows(self, _action, site_id):
            return site_id != site

    assert voip_api._may_see_site_credentials(_Manager(), uuid4()) is True
    assert voip_api._may_see_site_credentials(_Manager(), site) is False


async def test_a_read_only_grant_cannot_preview_a_config(db_session):
    from fastapi import HTTPException

    from app.core.site_access import current_user_var

    phone, _ = await _linked_phone(db_session)
    token = current_user_var.set(_ReadOnlyGrant())
    try:
        with pytest.raises(HTTPException):
            await ProvisioningService(db_session).generate_config_preview(phone.id)
    finally:
        current_user_var.reset(token)


async def test_discovery_on_one_site_leaves_another_sites_phone_alone(db_session):
    phone = await _phone(db_session)
    other = Site(
        organization_id=(await db_session.get(Site, phone.site_id)).organization_id,
        name="Other",
        slug=f"other-{uuid4().hex[:6]}",
    )
    db_session.add(other)
    await db_session.flush()
    seen, created = await VoIPService(db=db_session).upsert_discovered_phone(
        site_id=other.id, ip_address="10.1.1.5", mac_address=MAC, vendor="grandstream"
    )
    # No phone comes back, so the worker cannot onboard it either.
    assert seen is None and not created
    await db_session.refresh(phone)
    assert phone.ip_address == "192.168.50.77"


async def test_a_failed_login_records_nothing_the_device_claims(db_session):
    phone = await _phone(db_session)
    await voip_api._persist_connection_result(
        phone,
        {"authenticated": False, "mac_address": "00:0b:82:99:99:99", "model": "FAKE"},
        "192.168.50.77",
        db_session,
    )
    assert phone.mac_address == MAC and phone.model != "FAKE"
    await voip_api._persist_connection_result(
        phone,
        {"authenticated": True, "mac_address": "00:0b:82:99:99:99"},
        "192.168.50.77",
        db_session,
    )
    assert phone.mac_address == MAC  # a different MAC is noted, not applied
    assert phone.settings["reported_mac"] == "00:0b:82:99:99:99"


async def test_a_connection_test_needs_an_ip_address():
    from app.modules.voip.discovery import test_phone_connection

    result = await test_phone_connection(ip="metadata.google.internal", username="a", password="b")
    assert result["status"] == "blocked"


def test_a_signed_url_expires():
    from app.modules.voip.provisioning_auth import (
        generate_provisioning_signature,
        verify_hmac,
    )

    then = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
    sig = generate_provisioning_signature(MAC, now=then)
    assert verify_hmac(MAC, sig, now=then + timedelta(hours=23)) is True
    assert verify_hmac(MAC, sig, now=then + timedelta(hours=25)) is False
    assert verify_hmac(MAC, sig.split(".", 1)[1], now=then) is False  # old format


async def test_a_pbx_keeps_its_credentials_only_at_its_address(db_session):
    from app.modules.voip.service import VoIPError

    phone, _ = await _linked_phone(db_session)
    pbx = PBX(
        site_id=phone.site_id,
        name="pbx2",
        ip_address="192.168.50.3",
        settings={"api_password": encrypt_credential("pbx-secret")},
    )
    db_session.add(pbx)
    await db_session.flush()
    service = VoIPService(db=db_session)
    with pytest.raises(VoIPError):
        await service.update_pbx(pbx.id, {"ip_address": "203.0.113.9"})
    await service.update_pbx(pbx.id, {"ip_address": "192.168.50.4", "api_password": "new"})


def test_a_vault_backup_keeps_template_fields_and_a_snapshot_drops_raw_p_values():
    from app.modules.voip.backup import _template_field

    fields = {"admin_password": "x", "timezone": "UTC"}
    assert _template_field(fields, True) == fields
    assert _template_field(fields, False) == {"timezone": "UTC"}


async def test_a_stale_config_file_is_not_served(db_session, tmp_path):
    """A file left by a deleted phone with the same MAC holds its SIP password."""
    await _phone(db_session)
    prov = ProvisioningService(db_session, provision_dir=str(tmp_path))
    path = prov._config_file_path(MAC, "grandstream")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("<gs_provision>old phone's secret</gs_provision>", encoding="utf-8")
    content, _ = await prov.get_config_for_mac(MAC)
    assert "old phone's secret" not in content


async def test_a_redirect_to_another_host_is_refused():
    from types import SimpleNamespace as NS

    import aiohttp
    from yarl import URL

    from app.core.http_client import _same_host_redirects_only

    trace = _same_host_redirects_only()
    hook = trace.on_request_redirect[0]
    same = NS(url=URL("http://192.168.1.5/"), response=NS(headers={"Location": "/login"}))
    await hook(None, None, same)
    other = NS(
        url=URL("http://192.168.1.5/"),
        response=NS(headers={"Location": "http://169.254.169.254/latest"}),
    )
    with pytest.raises(aiohttp.ClientError):
        await hook(None, None, other)


async def test_discovery_holds_the_address_of_any_recorded_phone(db_session):
    """Fails on the eighth 26.11.3 candidate: only managed phones were held, but
    a discovered or maintenance phone can hold credentials and a window."""
    phone = await _phone(db_session)
    phone.lifecycle_state = "discovered"
    await db_session.flush()
    seen, _ = await VoIPService(db=db_session).upsert_discovered_phone(
        site_id=phone.site_id, ip_address="192.168.50.99", mac_address=MAC, vendor="grandstream"
    )
    assert seen.ip_address == "192.168.50.77"


async def test_a_pbx_retarget_forgets_every_saved_credential(db_session):
    """Fails on the eighth 26.11.3 candidate: one new secret kept all the others."""
    phone, _ = await _linked_phone(db_session)
    pbx = PBX(
        site_id=phone.site_id,
        name="pbx3",
        ip_address="192.168.50.5",
        settings={"api_password": encrypt_credential("old-api"), "ami_secret": "old-ami"},
        web_password_enc=encrypt_credential("old-web"),
    )
    db_session.add(pbx)
    await db_session.flush()
    updated = await VoIPService(db=db_session).update_pbx(
        pbx.id, {"ip_address": "192.168.50.6", "api_password": "new-api"}
    )
    assert updated.web_password_enc is None
    assert "ami_secret" not in (updated.settings or {})


async def test_a_read_only_grant_cannot_add_a_pbx_or_edit_voicemail(db_session):
    from fastapi import HTTPException

    from app.core.site_access import current_user_var

    phone = await _phone(db_session)
    service = VoIPService(db=db_session)
    token = current_user_var.set(_ReadOnlyGrant())
    try:
        with pytest.raises(HTTPException):
            await service.create_pbx(
                {"site_id": phone.site_id, "name": "x", "ip_address": "192.168.50.9"}
            )
    finally:
        current_user_var.reset(token)


def test_a_host_name_for_loopback_is_refused():
    from app.adapters.base import validate_host

    with pytest.raises(ValueError):
        validate_host("localhost")


def test_more_secret_names_are_hidden():
    from app.core.redaction import redact_secrets
    from app.modules.voip.setting_secrets import is_secret_setting

    for name in ("api_key", "passphrase", "voicemail_pin", "auth_token", "wifi_psk"):
        assert is_secret_setting(name), name
    assert not is_secret_setting("key")  # a line key's index
    assert redact_secrets({"voicemail_pin": "1234", "pin": "9"}) == {
        "voicemail_pin": "***",
        "pin": "***",
    }


class _FakeResponse:
    def __init__(self, status, headers=None, body=""):
        self.status = status
        self.headers = headers or {}
        self._body = body

    async def text(self):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    def __init__(self, first):
        self.first = first
        self.auth_sent = []

    def get(self, _url, params=None, auth=None):
        self.auth_sent.append(auth)
        return self.first if auth is None else _FakeResponse(200, body="Yealink")


async def test_the_yealink_probe_sends_credentials_only_to_a_yealink():
    """Fails on the eighth 26.11.3 candidate: the scan login went to every host."""
    from app.modules.voip.discovery import _probe_yealink

    creds = {"username": "admin", "password": "scan-secret"}
    other = _FakeSession(_FakeResponse(401, {"WWW-Authenticate": 'Basic realm="router"'}))
    await _probe_yealink(other, "192.168.50.30", creds)
    assert other.auth_sent == [None]
    yealink = _FakeSession(_FakeResponse(401, {"WWW-Authenticate": 'Basic realm="Yealink"'}))
    await _probe_yealink(yealink, "192.168.50.31", creds)
    assert len(yealink.auth_sent) == 2 and yealink.auth_sent[1] is not None


async def test_an_rtsp_url_never_carries_the_recorders_login(db_session):
    from app.modules.cameras.models import NVR, Camera
    from app.modules.cameras.service import StreamService

    phone = await _phone(db_session)
    site = await db_session.get(Site, phone.site_id)
    nvr = NVR(
        organization_id=site.organization_id,
        site_id=site.id,
        name="nvr",
        ip_address="192.168.50.40",
        username="admin",
        password_encrypted=encrypt_credential("nvr-secret"),
    )
    db_session.add(nvr)
    await db_session.flush()
    cam = Camera(
        organization_id=site.organization_id,
        site_id=site.id,
        nvr_id=nvr.id,
        name="lobby",
        ip_address="192.168.50.40",
        channel_id=1,
        username="admin",
        password_encrypted=encrypt_credential("nvr-secret"),
        rtsp_main_stream="rtsp://192.168.50.40:554/Streaming/Channels/101",
    )
    db_session.add(cam)
    await db_session.flush()
    url = await StreamService(db_session).get_stream_url(
        cam.id, "main", "rtsp", organization_id=site.organization_id
    )
    assert "nvr-secret" not in url and "@" not in url


@pytest.mark.parametrize(
    "host",
    ["[::ffff:127.0.0.1]", "[::1]:443", "::1", "169.254.169.254:80", "localhost"],
)
def test_the_host_check_reads_every_address_form(host):
    """Fails on the ninth 26.11.3 candidate for the bracketed forms."""
    from app.adapters.base import validate_host

    with pytest.raises(ValueError):
        validate_host(host)


def test_the_host_check_keeps_private_addresses():
    from app.adapters.base import validate_host

    for host in ("192.168.1.5", "192.168.1.5:8443", "[fd00::5]", "fd00::5"):
        assert validate_host(host) == host


async def test_an_http_client_checks_the_address_it_connects_to():
    """A name checked at setup could resolve elsewhere when used (DNS rebinding)."""
    import httpx

    from app.core.http_client import build_async_client

    async with build_async_client(timeout=2.0) as client:
        with pytest.raises(httpx.ConnectError, match="does not connect to"):
            await client.get("http://localhost:9/")


async def test_an_aiohttp_device_client_checks_the_address_it_connects_to():
    import aiohttp

    from app.core.http_client import build_aiohttp_session, checked_connector

    async with build_aiohttp_session(connector=checked_connector()) as session:
        with pytest.raises((aiohttp.ClientError, OSError)):
            async with session.get("http://localhost:9/"):
                pass


class _PlainWebSession:
    """A web server that answers 200 to anything and records what it was sent."""

    def __init__(self):
        self.requests = []

    def _record(self, method, url, kwargs):
        self.requests.append((method, url, kwargs.get("auth"), kwargs.get("data")))
        return _FakeResponse(200, body="<html>welcome</html>")

    def get(self, url, **kwargs):
        return self._record("GET", url, kwargs)

    def post(self, url, **kwargs):
        return self._record("POST", url, kwargs)


async def test_the_grandstream_probe_sends_nothing_to_a_plain_web_server():
    """Fails on the ninth 26.11.3 candidate: any 200 led to the challenge login
    (a hash of the password) and then Basic auth with the password."""
    from app.modules.voip.discovery import _probe_grandstream

    session = _PlainWebSession()
    result = await _probe_grandstream(
        session, "192.168.50.60", {"username": "admin", "password": "scan-secret"}, False
    )
    assert result is None
    assert all(auth is None and data is None for _m, _u, auth, data in session.requests)
    assert len(session.requests) == 1


async def test_a_stored_ciphertext_is_not_accepted_as_a_credential(db_session):
    from app.core.crypto import encrypt_credential as enc
    from app.modules.voip.service import VoIPError

    phone, _ = await _linked_phone(db_session)
    pbx = PBX(site_id=phone.site_id, name="pbx4", ip_address="192.168.50.7")
    db_session.add(pbx)
    await db_session.flush()
    with pytest.raises(VoIPError):
        await VoIPService(db=db_session).update_pbx(
            pbx.id, {"ip_address": "192.168.50.8", "api_password": enc("x")}
        )


def _ps_pack(seconds: float) -> bytes:
    """An MPEG-2 program stream pack header whose clock reads ``seconds``."""
    base = int(seconds * 90000)
    header = bytes(
        (
            0x40 | ((base >> 30) & 0x07) << 3 | 0x04 | ((base >> 28) & 0x03),
            (base >> 20) & 0xFF,
            ((base >> 15) & 0x1F) << 3 | 0x04 | ((base >> 13) & 0x03),
            (base >> 5) & 0xFF,
            (base & 0x1F) << 3 | 0x04,
            0x01,
            0x01,
            0x89,
            0xC3,
            0xF8,
        )
    )
    return bytes((0x00, 0x00, 0x01, 0xBA)) + header


# A video PES packet: MPEG-2 header ('10' marker), PTS flag, 5-byte PTS with
# its marker bits, then a few payload bytes.
_PS_VIDEO_PES = bytes(
    (0x00, 0x00, 0x01, 0xE0, 0x00, 0x10, 0x80, 0x80, 0x05, 0x21, 0x00, 0x01, 0x00, 0x01)
) + bytes((0x00, 0x00, 0x00, 0x01, 0x65, 0x88))
# An audio PES packet (stream C0).
_PS_AUDIO_PES = bytes((0x00, 0x00, 0x01, 0xC0, 0x00, 0x08, 0x80, 0x00, 0x00)) + bytes(5)


def test_an_interleaved_or_damaged_program_stream_is_measured_by_its_video(tmp_path):
    """Fails on candidate 11: audio-only packs reset the count (a whole hold
    measured half), and a video start code with a zero-filled payload counted
    as video (a damaged export passed)."""
    from app.tasks import cameras as cam_tasks

    interleaved = tmp_path / "interleaved.ps"
    parts = []
    for t in range(31):  # video every second, audio half a second later
        parts.append(_ps_pack(t) + _PS_VIDEO_PES)
        parts.append(_ps_pack(t + 0.5) + _PS_AUDIO_PES)
    interleaved.write_bytes(b"".join(parts))
    assert cam_tasks._mpeg_ps_covered_seconds(str(interleaved)) == pytest.approx(30.0, abs=0.01)

    # Larger than the 1 MiB read size, so packs straddle read boundaries.
    large = tmp_path / "large.ps"
    filler = bytes([0xFF]) * 40_009
    large.write_bytes(b"".join(_ps_pack(t * 0.5) + _PS_VIDEO_PES + filler for t in range(61)))
    assert large.stat().st_size > 2 * (1 << 20)
    assert cam_tasks._mpeg_ps_covered_seconds(str(large)) == pytest.approx(30.0, abs=0.01)

    damaged = tmp_path / "damaged.ps"
    zero_payload = bytes((0x00, 0x00, 0x01, 0xE0, 0x00, 0x08)) + bytes(8)
    damaged.write_bytes(b"".join(_ps_pack(t * 0.5) + zero_payload for t in range(61)))
    assert cam_tasks._mpeg_ps_covered_seconds(str(damaged)) is None


def test_an_mpeg_program_stream_hold_is_measured(tmp_path):
    """Fails on candidate 10: an MPEG-PS export was sealed unchecked on its
    first four bytes, so a truncated one counted as complete."""
    from app.tasks import cameras as cam_tasks

    steady = tmp_path / "steady.ps"
    steady.write_bytes(b"".join(_ps_pack(t * 0.5) + _PS_VIDEO_PES for t in range(61)))
    assert cam_tasks._mpeg_ps_covered_seconds(str(steady)) == pytest.approx(30.0, abs=0.01)

    gapped = tmp_path / "gapped.ps"
    early = [_ps_pack(t * 0.5) + _PS_VIDEO_PES for t in range(21)]  # 0..10 s
    late = [_ps_pack(40 + t * 0.5) + _PS_VIDEO_PES for t in range(21)]  # 40..50 s
    gapped.write_bytes(b"".join(early + late))
    assert cam_tasks._mpeg_ps_covered_seconds(str(gapped)) == pytest.approx(20.0, abs=0.01)

    truncated = tmp_path / "truncated.ps"
    truncated.write_bytes(bytes((0x00, 0x00, 0x01, 0xBA)) + bytes(2048))
    assert cam_tasks._mpeg_ps_covered_seconds(str(truncated)) is None

    no_video = tmp_path / "audio.ps"
    no_video.write_bytes(b"".join(_ps_pack(t * 0.5) for t in range(61)))
    assert cam_tasks._mpeg_ps_covered_seconds(str(no_video)) is None


def test_a_short_mpeg_program_stream_hold_fails(tmp_path):
    import asyncio
    from datetime import UTC, datetime, timedelta

    from app.tasks import cameras as cam_tasks

    clip = tmp_path / "short.ps"
    clip.write_bytes(b"".join(_ps_pack(t * 0.5) + _PS_VIDEO_PES for t in range(21)))  # 10 s
    start = datetime(2026, 11, 20, tzinfo=UTC)
    with pytest.raises(RuntimeError, match="nothing was sealed"):
        asyncio.run(
            cam_tasks._require_window_coverage(
                str(clip), start, start + timedelta(seconds=60), readable_required=False
            )
        )
    assert asyncio.run(
        cam_tasks._require_window_coverage(
            str(clip), start, start + timedelta(seconds=11), readable_required=False
        )
    )
