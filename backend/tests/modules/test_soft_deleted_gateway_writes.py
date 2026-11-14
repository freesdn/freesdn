# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A soft-deleted gateway is never written to.

Deleting a gateway sets ``deleted_at`` on its ``GatewayConnection``. Three
paths still reached the device afterwards:

* ``ReconciliationService._get_gateway_adapter`` (Distribute to limbs) loaded
  the row with ``db.get``, which ignores ``deleted_at``;
* the distribution engine's gateway cache (``_preload_gateways``) selected
  plan devices with no ``deleted_at`` filter;
* a gateway staged through the vendor services (OPNsense, pfSense, MikroTik)
  is paired with a Controller row of the same id, which the delete leaves
  live, so a change staged before the delete could still be applied.

The adapter builders (``adapter_helpers.build_adapter``,
``GatewayService._build_adapter``) and the staged appliers' client builder
(``GatewayServiceBase._get_client``) now refuse a soft-deleted gateway, so no
caller that forgets the filter reaches the device. Nothing is contacted.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import HTTPException

from app.core.crypto import encrypt_dict
from app.db.models import Controller
from app.models.core import Organization, Site
from app.modules.firewall.models import GatewayConnection


@pytest_asyncio.fixture
async def removed(db_session, monkeypatch: pytest.MonkeyPatch):
    from app.modules.firewall import gateway_service

    org = Organization(name="soft-deleted gateways", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(name="s", slug=uuid4().hex, organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    gw = GatewayConnection(
        org_id=org.id,
        site_id=site.id,
        name="edge",
        vendor="opnsense",
        host="192.0.2.120",
        port=443,
        verify_ssl=True,
        credentials=encrypt_dict({"api_key": "k", "api_secret": "s"}),
        settings={},
        sync_enabled=False,
    )
    db_session.add(gw)
    await db_session.flush()
    # The Controller row the vendor services pair with the gateway (same id).
    paired = Controller(
        id=gw.id,
        name="edge",
        site_id=site.id,
        controller_type="opnsense",
        host="192.0.2.120",
        port=443,
    )
    db_session.add(paired)
    gw.deleted_at = datetime.now(UTC)
    await db_session.commit()
    built: list[Any] = []
    monkeypatch.setattr(
        gateway_service.adapter_registry, "create_adapter", lambda **kw: built.append(kw)
    )
    return gw, paired, built


async def test_distribute_to_limbs_does_not_load_a_soft_deleted_gateway(
    db_session, removed
) -> None:
    from app.modules.gateway.services.reconciliation_service import (
        ReconciliationError,
        ReconciliationService,
    )

    gw, _paired, built = removed
    with pytest.raises(ReconciliationError):
        await ReconciliationService(db_session)._get_gateway_adapter(gw.id)
    assert built == []


async def test_the_adapter_builders_refuse_a_soft_deleted_gateway(db_session, removed) -> None:
    from app.modules.firewall.gateway_service import GatewayNotFoundError, GatewayService
    from app.modules.gateway.adapter_helpers import build_adapter

    gw, _paired, built = removed
    with pytest.raises(GatewayNotFoundError):
        GatewayService(db_session)._build_adapter(gw)
    with pytest.raises(HTTPException) as refused:
        build_adapter(gw)
    assert refused.value.status_code == 404
    assert built == []


async def test_the_engine_leaves_a_soft_deleted_gateway_out_of_its_plan(
    db_session, removed
) -> None:
    from app.modules.gateway.services.distribution_service import DistributionService

    gw, _paired, _built = removed
    cache = await DistributionService(db_session)._preload_gateways(
        [{"tier": 1, "device_id": str(gw.id), "action": "create_vlan", "params": {}}],
        org_id=gw.org_id,
    )
    assert cache == {}


async def test_a_staged_vendor_write_through_the_paired_controller_is_refused(
    db_session, removed
) -> None:
    from app.services.adapter_base import GatewayServiceBase

    _gw, paired, _built = removed
    svc = GatewayServiceBase.__new__(GatewayServiceBase)
    svc.db = db_session
    with pytest.raises(HTTPException) as refused:
        await svc._get_client(paired)
    assert refused.value.status_code == 404
    assert refused.value.detail == "gateway not found"
