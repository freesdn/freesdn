"""Legacy device builder shares controller authentication and fails safely.

Real PostgreSQL Controller/Device rows; Proxmox client requests use MockTransport.
TLS socket acceptance is recorded separately. No appliance action is performed.
"""

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException

from app.adapters.exceptions import AdapterConfirmationRequiredError, AdapterReadOnlyError
from app.api.v1.endpoints import devices
from app.core.crypto import encrypt_credential
from app.models.core import Controller, Organization, Site
from app.models.devices import Device
from app.services import adapter_factory
from tests.tasks.test_proxmox_controller_auth import SECRET, TOKEN
from tests.tasks.test_proxmox_controller_auth import peer as peer


async def stored_device(db, kind, config, *, verify_ssl=True):
    org = Organization(name="Owned device builder", slug=uuid4().hex)
    db.add(org)
    await db.flush()
    site = Site(organization_id=org.id, name="Owned device builder", slug=uuid4().hex)
    db.add(site)
    await db.flush()
    ctrl = Controller(
        site_id=site.id,
        name="Owned controller",
        controller_type=kind,
        host="192.168.254.254",
        port=8006 if kind == "proxmox" else 443,
        use_ssl=True,
        verify_ssl=verify_ssl,
        config=config,
    )
    db.add(ctrl)
    await db.flush()
    device = Device(site_id=site.id, controller=ctrl, name="Owned device", device_type="hypervisor")
    db.add(device)
    await db.flush()
    return device


def capture_builder(monkeypatch, failure=None):
    calls = []

    def factory(**kwargs):
        calls.append(kwargs)
        if failure:
            raise failure
        return SimpleNamespace()

    monkeypatch.setattr(devices, "get_adapter", factory, raising=False)
    monkeypatch.setattr(adapter_factory, "get_adapter", factory)
    return calls


@pytest.mark.parametrize("encrypted", [False, True])
@pytest.mark.parametrize("mode", ["token", "password", "token-and-password"])
async def test_device_builder_authenticates_with_stored_proxmox_settings(
    db_session, peer, mode, encrypted
):
    secret = encrypt_credential(SECRET) if encrypted else SECRET
    config = {"realm": "pve"}
    if mode != "password":
        config.update(token_id=TOKEN, token_secret=secret)
    if mode != "token":
        config.update(username="owned", password=secret)
    peer.token_mode = mode != "password"
    device = await stored_device(db_session, "proxmox", config)
    adapter = await devices._get_adapter_for_device(device)
    try:
        result = await adapter.test_connection()
        assert result.success
    finally:
        await adapter.disconnect()
    assert peer.clients and all(client.is_closed for client in peer.clients)
    assert any(method == "POST" for method, _ in peer.requests) is (mode == "password")


@pytest.mark.parametrize("encrypted", [False, True])
async def test_device_builder_default_pam_control(db_session, peer, encrypted):
    peer.token_mode = False
    peer.realm = "pam"
    device = await stored_device(
        db_session,
        "proxmox",
        {"username": "owned", "password": encrypt_credential(SECRET) if encrypted else SECRET},
    )
    adapter = await devices._get_adapter_for_device(device)
    try:
        assert (await adapter.test_connection()).success
    finally:
        await adapter.disconnect()
    assert peer.clients and all(client.is_closed for client in peer.clients)


@pytest.mark.parametrize("encrypted", [False, True])
async def test_wrong_proxmox_token_still_denied(db_session, peer, encrypted):
    value = encrypt_credential("owned-wrong-token") if encrypted else "owned-wrong-token"
    device = await stored_device(
        db_session, "proxmox", {"token_id": TOKEN, "token_secret": value, "realm": "pve"}
    )
    adapter = await devices._get_adapter_for_device(device)
    try:
        assert not (await adapter.test_connection()).success
    finally:
        await adapter.disconnect()
    assert all(client.is_closed for client in peer.clients)


@pytest.mark.parametrize("cloud", [False, True])
@pytest.mark.parametrize("encrypted", [False, True])
@pytest.mark.parametrize("verify_ssl", [False, True])
async def test_other_controller_settings_preserved(
    db_session, monkeypatch, cloud, encrypted, verify_ssl
):
    secret = encrypt_credential(SECRET) if encrypted else SECRET
    config = {"username": "owned", "password": secret}
    if cloud:
        config.update(
            connection_mode="cloud",
            client_id="owned-client",
            client_secret=secret,
            omada_id="owned-controller",
            cloud_region="eu",
        )
    device = await stored_device(
        db_session, "omada" if cloud else "unifi", config, verify_ssl=verify_ssl
    )
    calls = capture_builder(monkeypatch)
    await devices._get_adapter_for_device(device)
    assert len(calls) == 1
    sent = calls[0]
    assert sent["username"] == "owned" and sent["password"] == SECRET
    assert sent["port"] == 443 and sent["use_ssl"] is True and sent["verify_ssl"] is verify_ssl
    assert sent["mode"] == ("cloud" if cloud else "local")
    if cloud:
        assert (
            sent["client_id"],
            sent["client_secret"],
            sent["omada_id"],
            sent["cloud_region"],
        ) == ("owned-client", SECRET, "owned-controller", "eu")


@pytest.mark.parametrize("field", ["password", "client_secret", "token_secret"])
@pytest.mark.parametrize("broken", ["wrong-key", "malformed"])
async def test_invalid_stored_secrets_return_safe_error_before_constructor(
    db_session, monkeypatch, caplog, field, broken
):
    value = (
        Fernet(Fernet.generate_key()).encrypt(b"owned-private-synthetic-diagnostic").decode()
        if broken == "wrong-key"
        else "gAAAAA" + "x" * 120
    )
    config = {field: value}
    if field == "client_secret":
        config.update(connection_mode="cloud", client_id="owned")
    if field == "token_secret":
        config["token_id"] = TOKEN
    device = await stored_device(
        db_session, "proxmox" if field == "token_secret" else "omada", config
    )
    calls = capture_builder(monkeypatch)
    # Exclude fixture INSERT SQL echo; inspect only the builder invocation.
    caplog.clear()
    with pytest.raises(HTTPException) as caught:
        await devices._get_adapter_for_device(device)
    assert (
        caught.value.status_code == 502 and caught.value.detail == "Controller adapter unavailable"
    )
    assert not calls
    assert value not in caplog.text and "owned-private-synthetic-diagnostic" not in caplog.text


@pytest.mark.parametrize("failure", [ValueError, RuntimeError])
async def test_constructor_error_has_safe_response_and_log(
    db_session, monkeypatch, caplog, failure
):
    device = await stored_device(db_session, "unifi", {"username": "owned", "password": "owned"})
    calls = capture_builder(monkeypatch, failure("owned-private-constructor-diagnostic"))
    with pytest.raises(HTTPException) as caught:
        await devices._get_adapter_for_device(device)
    assert (
        caught.value.status_code == 502 and caught.value.detail == "Controller adapter unavailable"
    )
    assert len(calls) == 1 and "owned-private-constructor-diagnostic" not in caplog.text


@pytest.mark.parametrize(
    "failure", [asyncio.CancelledError, AdapterReadOnlyError, AdapterConfirmationRequiredError]
)
async def test_cancellation_and_adapter_policy_errors_propagate(db_session, monkeypatch, failure):
    device = await stored_device(db_session, "unifi", {})
    capture_builder(monkeypatch, failure("owned-policy-control"))
    with pytest.raises(failure):
        await devices._get_adapter_for_device(device)


async def test_missing_controller_retains_400(monkeypatch):
    calls = capture_builder(monkeypatch)
    with pytest.raises(HTTPException) as caught:
        await devices._get_adapter_for_device(SimpleNamespace(controller=None))
    assert caught.value.status_code == 400 and not calls
