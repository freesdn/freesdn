# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Exercise real adapter authentication serialization against a synthetic peer."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.adapters.registry import adapter_registry
from app.adapters.truenas import ws_client
from app.adapters.truenas.adapter import TrueNASAdapter
from app.api.v1.endpoints import controllers
from app.core.crypto import encrypt_credential
from app.core.dependencies import CurrentUser
from app.models.core import Controller, Site, User
from app.schemas.core import ControllerProbe

KEY = "owned-synthetic-api-key"


@pytest.fixture
def owned():
    org, site_id = uuid4(), uuid4()
    site = Site(id=site_id, organization_id=org, name="Owned", slug=site_id.hex)
    row = Controller(
        id=uuid4(),
        site=site,
        site_id=site_id,
        controller_type="truenas",
        name="Owned NAS",
        host="192.168.254.254",
        port=443,
        use_ssl=True,
        verify_ssl=True,
        status="unknown",
        config={"username": "owned", "password": KEY},
    )
    user = CurrentUser(
        user=User(id=uuid4(), organization_id=org, role="org_admin", is_active=True),
        permissions=["controller:read", "controller:update", "controller:create"],
        accessible_site_ids=set(),
    )
    session = MagicMock()
    session.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: row))
    session.commit = AsyncMock()
    return SimpleNamespace(row=row, user=user, session=session)


@pytest.fixture
def peer(monkeypatch):
    state = SimpleNamespace(requests=[], sockets=[], password_mode=False)

    class Socket:
        closed = False

        async def send(self, payload):
            self.request = json.loads(payload)
            state.requests.append(self.request)

        async def recv(self):
            request = self.request
            if request["method"] == "auth.login_ex":
                login = request["params"][0]
                expected = (
                    {"mechanism": "PASSWORD_PLAIN", "username": "owned", "password": KEY}
                    if state.password_mode
                    else {"mechanism": "API_KEY_PLAIN", "username": "owned", "api_key": KEY}
                )
                result = {"response_type": "SUCCESS" if login == expected else "AUTH_ERR"}
            else:
                assert request["method"] == "system.info"
                result = {"version": "owned-version", "hostname": "owned-nas"}
            return json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result})

        async def close(self):
            self.closed = True

    async def connect(uri, **kwargs):
        assert uri == "wss://192.168.254.254:443/api/current"
        assert kwargs["ssl"].check_hostname
        socket = Socket()
        state.sockets.append(socket)
        return socket

    monkeypatch.setattr(ws_client, "_NoRedirectConnect", connect)
    # Actual registry, adapter, WS client, authentication and JSON-RPC code run.
    assert adapter_registry.get("truenas") is TrueNASAdapter
    return state


@pytest.mark.asyncio
@pytest.mark.parametrize("encrypted", [False, True])
@pytest.mark.parametrize("kind", ["truenas", "TrueNAS"])
async def test_saved_controller_accepts_the_same_api_key_as_onboarding(
    owned, peer, encrypted, kind
):
    row = owned.row
    row.controller_type = kind
    row.config = {"username": "owned", "password": encrypt_credential(KEY) if encrypted else KEY}
    result = await controllers.test_controller_connection(row.id, owned.user, owned.session)
    assert result["success"] is True
    assert result["details"]["controller_version"] == "owned-version"
    assert row.status == "connected" and row.last_error is None
    assert peer.sockets and all(socket.closed for socket in peer.sockets)
    assert KEY not in json.dumps(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("encrypted", [False, True])
async def test_existing_storage_adapter_path_keeps_api_key_auth(owned, peer, encrypted):
    row = owned.row
    row.config = {"username": "owned", "password": encrypt_credential(KEY) if encrypted else KEY}
    _, adapter = await controllers._get_controller_and_adapter(row.id, owned.session, owned.user)
    async with adapter:
        result = await adapter.test_connection()
    assert result.success and all(socket.closed for socket in peer.sockets)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["truenas", "TrueNAS"])
async def test_onboarding_api_key_auth_remains_successful(owned, peer, kind):
    result = await controllers.test_connection_precreation(
        ControllerProbe(
            controller_type=kind,
            host=owned.row.host,
            port=443,
            username="owned",
            password=KEY,
            use_ssl=True,
            verify_ssl=True,
        ),
        owned.user,
    )
    assert result["success"] is True and all(socket.closed for socket in peer.sockets)


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["saved", "precreation"])
async def test_wrong_key_remains_rejected_without_credential_echo(owned, peer, path):
    wrong = "owned-wrong-secret"
    if path == "saved":
        owned.row.config = {"username": "owned", "password": encrypt_credential(wrong)}
        result = await controllers.test_controller_connection(
            owned.row.id, owned.user, owned.session
        )
        assert owned.row.status == "disconnected" and wrong not in owned.row.last_error
    else:
        result = await controllers.test_connection_precreation(
            ControllerProbe(
                controller_type="truenas",
                host=owned.row.host,
                port=443,
                username="owned",
                password=wrong,
            ),
            owned.user,
        )
    assert result["success"] is False and wrong not in json.dumps(result)
    assert peer.sockets and all(socket.closed for socket in peer.sockets)


@pytest.mark.asyncio
async def test_direct_adapter_password_auth_is_still_supported(peer):
    peer.password_mode = True
    async with TrueNASAdapter(host="192.168.254.254", username="owned", password=KEY) as adapter:
        result = await adapter.test_connection()
    assert result.success and all(socket.closed for socket in peer.sockets)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["omada", "cloud", "proxmox"])
async def test_other_controller_authentication_is_unchanged(owned, monkeypatch, kind):
    row = owned.row
    row.controller_type = "omada" if kind == "cloud" else kind
    row.config = {"username": "owned", "password": encrypt_credential(KEY)}
    if kind == "proxmox":
        row.config.update(
            token_id="owned@pve!test", token_secret=encrypt_credential(KEY), realm="pve"
        )
    if kind == "cloud":
        row.config.update(
            connection_mode="cloud",
            client_id="owned-client",
            client_secret=encrypt_credential(KEY),
            omada_id="owned-controller",
            cloud_region="use1",
        )
    adapter = MagicMock()
    adapter.__aenter__ = AsyncMock(return_value=adapter)
    adapter.__aexit__ = AsyncMock(return_value=False)
    adapter.test_connection = AsyncMock(return_value=SimpleNamespace(success=True, data={}))
    factory = MagicMock(return_value=adapter)
    monkeypatch.setattr(adapter_registry, "create_adapter", factory)
    result = await controllers.test_controller_connection(row.id, owned.user, owned.session)
    assert result["success"]
    sent = factory.call_args.kwargs
    assert "api_key" not in sent and sent["password"] == KEY
    if kind == "proxmox":
        assert sent["token_secret"] == KEY and sent["realm"] == "pve"
    if kind == "cloud":
        assert sent["client_secret"] == KEY and sent["mode"] == "cloud"


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["saved", "operations"])
async def test_foreign_tenant_denied_before_authentication(owned, peer, path):
    owned.user.user.organization_id = uuid4()
    with pytest.raises(HTTPException) as exc:
        if path == "saved":
            await controllers.test_controller_connection(owned.row.id, owned.user, owned.session)
        else:
            await controllers._get_controller_and_adapter(owned.row.id, owned.session, owned.user)
    assert exc.value.status_code == 403 and not peer.requests
    owned.session.commit.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["authentication", "connection", "unexpected"])
async def test_standalone_connection_test_closes_transport_after_read_failure(failure):
    from app.adapters.exceptions import AdapterAuthenticationError, AdapterConnectionError

    errors = {
        "authentication": AdapterAuthenticationError("owned failure"),
        "connection": AdapterConnectionError("owned failure"),
        "unexpected": RuntimeError("owned failure"),
    }
    api = AsyncMock()
    api.get_system_info.side_effect = errors[failure]
    adapter = TrueNASAdapter(host="192.168.254.254", api_key=KEY)
    adapter._api = api
    result = await adapter.test_connection()
    assert result.success is False
    api.disconnect.assert_awaited_once()
    assert adapter.is_connected is False


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["ws", "rest"])
async def test_sequential_connect_reuses_live_transport_and_reconnects_after_close(transport):
    api = AsyncMock()
    adapter = TrueNASAdapter(host="192.168.254.254", api_key=KEY)
    adapter._api = api
    adapter._transport = transport
    await adapter.connect()
    await adapter.connect()
    assert api.connect.await_count == 1
    await adapter.disconnect()
    await adapter.connect()
    assert api.connect.await_count == 2 and adapter.is_connected
    await adapter.disconnect()
    assert api.disconnect.await_count == 2 and not adapter.is_connected
