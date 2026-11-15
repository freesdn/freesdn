# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The RADIUS service builds its adapter with the controller's SSL setting.

``RadiusProfileService`` passed the controller's ``use_ssl`` to the adapter as
``ssl=``. No adapter reads ``ssl``: every constructor reads ``use_ssl`` (Omada,
UniFi, pfSense and OPNsense default it to True, MikroTik auto-detects from the
port). The key was dropped silently, so an Omada controller set to plain HTTP
was spoken to over HTTPS by the 802.1X push and the auth-event sync, and they
failed against a controller every other page reached fine.

Only the adapter's connection and the vendor call are replaced; the real
service, the real factory and the real Omada adapter and client config run
against controller rows in PostgreSQL.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import AdapterResult
from app.adapters.omada.adapter import OmadaAdapter
from app.core.crypto import encrypt_credential
from app.models.core import Controller, Organization, Site
from app.models.radius import Dot1xPortConfig, RadiusServerProfile
from app.services.radius import RadiusProfileService


async def _controller(db: AsyncSession, *, use_ssl: bool) -> Controller:
    org = Organization(id=uuid4(), name="RADIUS ssl probe", slug="radius-ssl-" + uuid4().hex[:10])
    db.add(org)
    await db.flush()
    site = Site(id=uuid4(), organization_id=org.id, name="Office", slug="o-" + uuid4().hex[:8])
    db.add(site)
    await db.flush()
    controller = Controller(
        id=uuid4(),
        site_id=site.id,
        name="Omada over plain HTTP" if not use_ssl else "Omada over HTTPS",
        controller_type="omada",
        host="192.0.2.10",
        port=8088 if not use_ssl else 8043,
        use_ssl=use_ssl,
        verify_ssl=False,
        config={"username": "radius-probe", "password": encrypt_credential("not-a-secret")},
    )
    db.add(controller)
    await db.flush()
    return controller


@pytest.fixture
def seen(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Record the transport the real Omada adapter was configured with."""
    calls: list[dict[str, Any]] = []

    def _record(adapter: OmadaAdapter, op: str) -> None:
        cfg = adapter._client.config
        calls.append({"op": op, "use_ssl": cfg.use_ssl, "port": cfg.port})

    async def _connect(self: OmadaAdapter) -> bool:
        return True

    async def _disconnect(self: OmadaAdapter) -> None:
        return None

    async def _events(self: OmadaAdapter, limit: int = 100) -> list[dict[str, Any]]:
        _record(self, "sync")
        return []

    async def _push(self: OmadaAdapter, config: dict[str, Any]) -> AdapterResult:
        _record(self, "push")
        return AdapterResult.ok({}, message="recorded")

    monkeypatch.setattr(OmadaAdapter, "connect", _connect)
    monkeypatch.setattr(OmadaAdapter, "disconnect", _disconnect)
    monkeypatch.setattr(OmadaAdapter, "get_dot1x_auth_events", _events)
    monkeypatch.setattr(OmadaAdapter, "update_dot1x_config", _push)
    return calls


@pytest.mark.parametrize("use_ssl", [False, True])
async def test_auth_event_sync_uses_the_controllers_ssl_setting(
    db_session: AsyncSession, seen: list[dict[str, Any]], use_ssl: bool
) -> None:
    controller = await _controller(db_session, use_ssl=use_ssl)

    result = await RadiusProfileService(db_session).sync_auth_events(controller.id)

    assert result.get("success") is True, result
    assert seen == [{"op": "sync", "use_ssl": use_ssl, "port": controller.port}]


@pytest.mark.parametrize("use_ssl", [False, True])
async def test_dot1x_push_uses_the_controllers_ssl_setting(
    db_session: AsyncSession,
    seen: list[dict[str, Any]],
    use_ssl: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The push is a staged write (08b00c18); model a read-write install so the
    # chokepoint's fail-safe read-only default does not refuse it.
    import app.core.runtime_flags as rf

    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: False)
    controller = await _controller(db_session, use_ssl=use_ssl)
    org_id = (await db_session.get(Site, controller.site_id)).organization_id  # type: ignore[union-attr]
    profile = RadiusServerProfile(
        id=uuid4(),
        organization_id=org_id,
        name="probe",
        host="192.0.2.20",
        port=1812,
        shared_secret_encrypted=encrypt_credential("probe-shared-secret"),
    )
    db_session.add(profile)
    await db_session.flush()
    config = Dot1xPortConfig(id=uuid4(), controller_id=controller.id, radius_profile_id=profile.id)
    db_session.add(config)
    await db_session.flush()

    await RadiusProfileService(db_session).push_dot1x_config(config.id)

    assert seen == [{"op": "push", "use_ssl": use_ssl, "port": controller.port}]
