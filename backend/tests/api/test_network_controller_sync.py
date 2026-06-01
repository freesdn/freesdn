# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Regression: direct controller writes must report failure honestly.

Several network routes write to the live controller OUTSIDE the staged-apply
pipeline (interactive management). That direct path is by design, but two of them
used to SWALLOW a controller-write exception and still report success / commit
optimistic local state:

* ``block_client`` / ``unblock_client`` logged the error and returned
  ``{"success": True}`` with ``blocked`` flipped — a security-relevant FALSE
  POSITIVE for an enforcement action (the client stayed reachable while the UI
  said "blocked"). Now they raise 502 and do not commit the false state.
* ``_push_wifi_to_controller`` only logged on failure and returned nothing, so
  create/update/delete WiFi routes reported an unqualified success. Now it
  returns a ``{controller_synced, controller_warning}`` envelope (mirroring the
  VLAN helper) that the routes surface.

These are unit-level: no DB / no live controller — the session and adapter are
mocked, and the module-level ``_get_adapter_for_controller`` is monkeypatched.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints import network as net


def _unrestricted_user(org_id):
    """A user with no site limit ⇒ _verify_site_grant is a no-op."""
    from app.core.dependencies import CurrentUser
    from app.models.core import User

    user = User(
        id=uuid4(),
        email=f"{uuid4().hex[:8]}@example.com",
        organization_id=org_id,
        role="org_admin",
        hashed_password="x",
        is_active=True,
    )
    return CurrentUser(user=user, permissions=["device:update"], accessible_site_ids=set())


# ── block / unblock: must raise 502 on controller failure, not false-succeed ──


@pytest.mark.asyncio
async def test_block_client_raises_502_and_does_not_commit_on_controller_failure(monkeypatch):
    org = uuid4()
    device = SimpleNamespace(site_id=uuid4(), controller_id=uuid4())
    client = SimpleNamespace(
        id="c1", device=device, mac_address="aa:bb:cc:dd:ee:ff", client_metadata={}
    )
    ctrl = SimpleNamespace(id=device.controller_id)
    res_client = MagicMock(scalar_one_or_none=MagicMock(return_value=client))
    res_ctrl = MagicMock(scalar_one_or_none=MagicMock(return_value=ctrl))
    session = MagicMock()
    session.execute = AsyncMock(side_effect=[res_client, res_ctrl])
    session.commit = AsyncMock()
    monkeypatch.setattr(
        net, "_get_adapter_for_controller", AsyncMock(side_effect=RuntimeError("controller down"))
    )

    with pytest.raises(HTTPException) as exc:
        await net.block_client("c1", session=session, _user=_unrestricted_user(org))

    assert exc.value.status_code == 502
    session.commit.assert_not_awaited()  # no false "blocked" state recorded
    assert client.client_metadata.get("blocked") is not True


@pytest.mark.asyncio
async def test_unblock_client_raises_502_and_does_not_commit_on_controller_failure(monkeypatch):
    org = uuid4()
    device = SimpleNamespace(site_id=uuid4(), controller_id=uuid4())
    client = SimpleNamespace(
        id="c1", device=device, mac_address="aa:bb:cc:dd:ee:ff", client_metadata={"blocked": True}
    )
    ctrl = SimpleNamespace(id=device.controller_id)
    session = MagicMock()
    session.execute = AsyncMock(
        side_effect=[
            MagicMock(scalar_one_or_none=MagicMock(return_value=client)),
            MagicMock(scalar_one_or_none=MagicMock(return_value=ctrl)),
        ]
    )
    session.commit = AsyncMock()
    monkeypatch.setattr(
        net, "_get_adapter_for_controller", AsyncMock(side_effect=RuntimeError("controller down"))
    )

    with pytest.raises(HTTPException) as exc:
        await net.unblock_client("c1", session=session, _user=_unrestricted_user(org))

    assert exc.value.status_code == 502
    session.commit.assert_not_awaited()  # still blocked locally — no false unblock


# ── wifi push helper: honest controller_synced envelope ──────────────────────


class _FakeAdapter:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def delete_ssid(self, *a, **k):
        return None


def _wifi():
    return SimpleNamespace(
        controller_id=uuid4(),
        site_id=uuid4(),
        wifi_metadata={},
        external_id="ssid-1",
        ssid="net",
        security="wpa2_personal",
        band="both",
        hidden=False,
        vlan_id=None,
    )


@pytest.mark.asyncio
async def test_push_wifi_reports_unsynced_on_controller_failure(monkeypatch):
    wifi = _wifi()
    ctrl = SimpleNamespace(id=wifi.controller_id)
    session = MagicMock()
    session.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=ctrl))
    )
    session.flush = AsyncMock()
    monkeypatch.setattr(
        net, "_get_adapter_for_controller", AsyncMock(side_effect=RuntimeError("controller down"))
    )

    out = await net._push_wifi_to_controller(session, wifi, action="delete")
    assert out["controller_synced"] is False
    assert "controller write failed" in out["controller_warning"]


@pytest.mark.asyncio
async def test_push_wifi_reports_synced_on_success(monkeypatch):
    wifi = _wifi()
    ctrl = SimpleNamespace(id=wifi.controller_id)
    session = MagicMock()
    session.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=ctrl))
    )
    session.flush = AsyncMock()
    monkeypatch.setattr(net, "_get_adapter_for_controller", AsyncMock(return_value=_FakeAdapter()))

    out = await net._push_wifi_to_controller(session, wifi, action="delete")
    assert out == {"controller_synced": True, "controller_warning": None}


@pytest.mark.asyncio
async def test_push_wifi_noop_when_no_controller():
    wifi = SimpleNamespace(controller_id=None, site_id=None, wifi_metadata={})
    session = MagicMock()
    out = await net._push_wifi_to_controller(session, wifi, action="delete")
    assert out == {"controller_synced": True, "controller_warning": None}
