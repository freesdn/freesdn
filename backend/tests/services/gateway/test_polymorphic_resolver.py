# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Gateway/Controller UUID polymorphism tests.
=====================================================

Covers :class:`GatewayServiceBase._resolve_controller_or_gateway`,
which lets the per-vendor service layer accept EITHER a
``core.controllers`` row id OR a ``firewall.gateway_connections`` row
id transparently. The historical setup created two parallel tables for
what is functionally the same vendor connection, breaking every
MikroTik tab on the GatewayDetailPage (which passes the gateway id).

These tests stub the SQLAlchemy session at the ``execute`` boundary so
they run pure-Python without Postgres. The fields covered:

1. controller-id path still works (backward compat).
2. gateway-id path now resolves to a Controller-shaped facade.
3. Cross-org access is denied on BOTH paths.
4. 404 raised cleanly when neither table has the id.
5. Vendor-credential mapping: mikrotik = username/password,
   opnsense/pfsense = api_key/api_secret → username/password slot.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.core.crypto import encrypt_dict
from app.models.core import Controller
from app.modules.firewall.models import GatewayConnection
from app.services.adapter_base import GatewayServiceBase

# ─── helpers ─────────────────────────────────────────────────────────


def _make_service() -> GatewayServiceBase:
    """Build a base service against a MagicMock session.

    Each test then sets ``svc.db.execute`` to return scalar-shaped
    results matching whichever lookup path it wants to exercise.
    """
    svc = GatewayServiceBase.__new__(GatewayServiceBase)
    svc.db = MagicMock()
    svc.staging = MagicMock()
    return svc


def _scalar_result(value: Any) -> MagicMock:
    """Return a Result-shaped mock whose ``scalar_one_or_none`` returns
    ``value``. Mirrors what ``self.db.execute(stmt)`` produces in real
    code."""
    r = MagicMock()
    r.scalar_one_or_none = MagicMock(return_value=value)
    return r


# ─── 1. Controller-id path keeps working (backward compat) ───────────


@pytest.mark.asyncio
async def test_controller_id_resolves_via_core_controllers() -> None:
    """A real Controller row in core.controllers is returned as-is —
    the polymorphic helper must not break the fast path."""
    svc = _make_service()
    ctrl = Controller(
        id=uuid4(),
        site_id=uuid4(),
        name="ctrl-1",
        controller_type="mikrotik",
        host="10.0.0.1",
        port=443,
        use_ssl=True,
        verify_ssl=False,
        status="connected",
        config={},
    )
    org_id = uuid4()

    # First execute() call hits core.controllers and finds the row.
    svc.db.execute = AsyncMock(return_value=_scalar_result(ctrl))

    got = await svc._resolve_controller_or_gateway(ctrl.id, org_id)
    assert got is ctrl
    # Only one DB hit on the fast path — no fallback needed.
    assert svc.db.execute.await_count == 1


# ─── 2. Gateway-id path returns a Controller facade ─────────────────


@pytest.mark.asyncio
async def test_gateway_id_resolves_to_controller_facade() -> None:
    """The bug: a GatewayConnection.id used to return 404. After the
    fix it returns a Controller facade hydrated from the gateway."""
    svc = _make_service()
    org_id = uuid4()
    gw_id = uuid4()
    site_id = uuid4()

    gw = GatewayConnection(
        id=gw_id,
        org_id=org_id,
        site_id=site_id,
        name="edge-mt-01",
        vendor="mikrotik",
        host="192.168.1.133",
        port=443,
        verify_ssl=False,
        credentials=encrypt_dict({"username": "admin", "password": "s3cret"}),
        sync_enabled=True,
        sync_interval_seconds=300,
        settings={},
    )

    # First execute() returns no Controller; second returns the gateway.
    svc.db.execute = AsyncMock(
        side_effect=[
            _scalar_result(None),  # core.controllers miss
            _scalar_result(gw),    # firewall.gateway_connections hit
        ]
    )

    got = await svc._resolve_controller_or_gateway(gw_id, org_id)
    # Facade carries the gateway's id + host + port verbatim.
    assert got.id == gw_id
    assert got.host == "192.168.1.133"
    assert got.port == 443
    assert got.controller_type == "mikrotik"
    assert got.site_id == site_id
    # Credentials roundtrip through the facade's config dict.
    assert got.config["username"] == "admin"
    assert got.config["password"] == "s3cret"
    assert got.config["connection_mode"] == "local"
    # Flag the test bench can use to distinguish a facade.
    assert getattr(got, "_is_gateway_facade", False) is True


# ─── 3. Tenant isolation on both paths ───────────────────────────────


@pytest.mark.asyncio
async def test_controller_lookup_is_tenant_scoped() -> None:
    """A controller belonging to another org must return 404 — the
    fast-path query already filters by Site.organization_id and the
    behaviour must survive the rename."""
    svc = _make_service()
    other_org = uuid4()

    # No Controller, no GatewayConnection — both lookups miss.
    svc.db.execute = AsyncMock(
        side_effect=[
            _scalar_result(None),
            _scalar_result(None),
        ]
    )

    with pytest.raises(HTTPException) as exc:
        await svc._resolve_controller_or_gateway(uuid4(), other_org)
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_gateway_lookup_is_tenant_scoped() -> None:
    """A gateway belonging to another org must return 404. The query
    filters ``GatewayConnection.org_id == organization_id`` — if a
    cross-org access slipped through we'd hand back the gateway."""
    svc = _make_service()

    # Both queries return None (the gateway's org_id != the request
    # org_id so it never matches).
    svc.db.execute = AsyncMock(
        side_effect=[
            _scalar_result(None),
            _scalar_result(None),
        ]
    )

    with pytest.raises(HTTPException) as exc:
        await svc._resolve_controller_or_gateway(uuid4(), uuid4())
    assert exc.value.status_code == 404


# ─── 4. Missing-from-both raises a clean 404 ─────────────────────────


@pytest.mark.asyncio
async def test_404_when_neither_table_has_the_id() -> None:
    svc = _make_service()
    svc.db.execute = AsyncMock(
        side_effect=[
            _scalar_result(None),
            _scalar_result(None),
        ]
    )
    with pytest.raises(HTTPException) as exc:
        await svc._resolve_controller_or_gateway(uuid4(), uuid4())
    assert exc.value.status_code == 404
    assert "controller not found" in exc.value.detail.lower()


# ─── 5. Vendor-credential mapping (opnsense / pfsense) ──────────────


@pytest.mark.asyncio
async def test_opnsense_credentials_map_to_username_password_slots() -> None:
    """The OPNsense adapter's __init__ accepts username/password, then
    forwards them as ``api_key=username``, ``api_secret=password``. The
    facade must therefore put the gateway's ``api_key`` in
    ``config["username"]`` and ``api_secret`` in ``config["password"]``
    — otherwise authentication breaks silently."""
    svc = _make_service()
    org_id = uuid4()
    gw_id = uuid4()

    gw = GatewayConnection(
        id=gw_id,
        org_id=org_id,
        site_id=None,
        name="opnsense-edge",
        vendor="opnsense",
        host="10.20.30.40",
        port=443,
        verify_ssl=True,
        credentials=encrypt_dict(
            {"api_key": "AAA-key", "api_secret": "BBB-secret"}
        ),
        sync_enabled=True,
        sync_interval_seconds=300,
        settings={},
    )
    svc.db.execute = AsyncMock(
        side_effect=[
            _scalar_result(None),
            _scalar_result(gw),
        ]
    )

    got = await svc._resolve_controller_or_gateway(gw_id, org_id)
    assert got.controller_type == "opnsense"
    assert got.config["username"] == "AAA-key"
    assert got.config["password"] == "BBB-secret"
    assert got.verify_ssl is True


@pytest.mark.asyncio
async def test_pfsense_credentials_map_to_username_password_slots() -> None:
    svc = _make_service()
    org_id = uuid4()
    gw_id = uuid4()
    gw = GatewayConnection(
        id=gw_id,
        org_id=org_id,
        site_id=None,
        name="pfsense-edge",
        vendor="pfsense",
        host="10.20.30.50",
        port=443,
        verify_ssl=False,
        credentials=encrypt_dict({"api_key": "K", "api_secret": "S"}),
        sync_enabled=True,
        sync_interval_seconds=300,
        settings={},
    )
    svc.db.execute = AsyncMock(
        side_effect=[
            _scalar_result(None),
            _scalar_result(gw),
        ]
    )
    got = await svc._resolve_controller_or_gateway(gw_id, org_id)
    assert got.controller_type == "pfsense"
    assert got.config["username"] == "K"
    assert got.config["password"] == "S"


# ─── 6. Empty / plaintext credentials still work ─────────────────────


@pytest.mark.asyncio
async def test_facade_tolerates_unencrypted_credentials() -> None:
    """Legacy rows may carry plaintext credentials (decrypt_dict is a
    no-op on dicts without ``_encrypted``). The facade must accept
    those without falling over."""
    svc = _make_service()
    org_id = uuid4()
    gw = GatewayConnection(
        id=uuid4(),
        org_id=org_id,
        site_id=None,
        name="legacy",
        vendor="mikrotik",
        host="10.0.0.5",
        port=443,
        verify_ssl=False,
        credentials={"username": "u", "password": "p"},  # plaintext
        sync_enabled=True,
        sync_interval_seconds=300,
        settings={},
    )
    svc.db.execute = AsyncMock(
        side_effect=[
            _scalar_result(None),
            _scalar_result(gw),
        ]
    )
    got = await svc._resolve_controller_or_gateway(gw.id, org_id)
    assert got.config["username"] == "u"
    assert got.config["password"] == "p"


# ─── 7. Legacy _get_controller still queries only core.controllers ──


@pytest.mark.asyncio
async def test_get_controller_does_not_fall_back_to_gateway() -> None:
    """``_get_controller`` is the controllers-page surface; it must
    NOT silently match a gateway id to keep tests + telemetry that
    explicitly target Omada-style controllers honest."""
    svc = _make_service()
    # First (and only) execute — Controller miss. Should NOT issue a
    # second query against gateway_connections.
    svc.db.execute = AsyncMock(return_value=_scalar_result(None))

    with pytest.raises(HTTPException) as exc:
        await svc._get_controller(uuid4(), uuid4())
    assert exc.value.status_code == 404
    assert svc.db.execute.await_count == 1


# ─── 8. Facade is not added to the session ──────────────────────────


@pytest.mark.asyncio
async def test_facade_is_transient_not_added_to_session() -> None:
    """The facade is built via the ORM constructor purely for the
    field-by-field shape — it must NEVER end up in the unit-of-work
    or it would conflict with the real core.controllers PK constraint
    on flush."""
    svc = _make_service()
    org_id = uuid4()
    gw_id = uuid4()
    gw = GatewayConnection(
        id=gw_id,
        org_id=org_id,
        site_id=None,
        name="x",
        vendor="mikrotik",
        host="10.0.0.6",
        port=443,
        verify_ssl=False,
        credentials=encrypt_dict({"username": "u", "password": "p"}),
        sync_enabled=True,
        sync_interval_seconds=300,
        settings={},
    )
    svc.db.execute = AsyncMock(
        side_effect=[_scalar_result(None), _scalar_result(gw)]
    )
    # ``add`` should NEVER be invoked on the session for the facade.
    svc.db.add = MagicMock()
    await svc._resolve_controller_or_gateway(gw_id, org_id)
    svc.db.add.assert_not_called()


# ─── 8.5. use_ssl heuristic for MikroTik on port 80 ────────────────


@pytest.mark.asyncio
async def test_mikrotik_port_80_disables_use_ssl_by_default() -> None:
    """MikroTik CHR commonly ships with the REST API on HTTP port 80
    (``www-ssl`` disabled). The facade has no GatewayConnection
    ``use_ssl`` column to read, so it defaults based on port: port 80
    → HTTP, otherwise → HTTPS. Without this heuristic the adapter
    would try ``https://chr:80`` and TLS-handshake against a plain
    HTTP socket."""
    svc = _make_service()
    org_id = uuid4()
    gw = GatewayConnection(
        id=uuid4(),
        org_id=org_id,
        site_id=None,
        name="chr",
        vendor="mikrotik",
        host="192.168.1.133",
        port=80,
        verify_ssl=False,
        credentials=encrypt_dict({"username": "u", "password": "p"}),
        sync_enabled=True,
        sync_interval_seconds=300,
        settings={},
    )
    svc.db.execute = AsyncMock(
        side_effect=[_scalar_result(None), _scalar_result(gw)]
    )
    got = await svc._resolve_controller_or_gateway(gw.id, org_id)
    assert got.use_ssl is False


@pytest.mark.asyncio
async def test_explicit_use_ssl_setting_wins_over_heuristic() -> None:
    """Operators can override the port-80 heuristic by passing
    ``settings.use_ssl`` on POST /firewall/gateways — useful for
    gateways behind a TLS-terminating reverse proxy."""
    svc = _make_service()
    org_id = uuid4()
    gw = GatewayConnection(
        id=uuid4(),
        org_id=org_id,
        site_id=None,
        name="chr-tls-proxy",
        vendor="mikrotik",
        host="192.168.1.133",
        port=80,  # would normally trigger HTTP heuristic
        verify_ssl=False,
        credentials=encrypt_dict({"username": "u", "password": "p"}),
        sync_enabled=True,
        sync_interval_seconds=300,
        settings={"use_ssl": True},  # explicit override
    )
    svc.db.execute = AsyncMock(
        side_effect=[_scalar_result(None), _scalar_result(gw)]
    )
    got = await svc._resolve_controller_or_gateway(gw.id, org_id)
    assert got.use_ssl is True


@pytest.mark.asyncio
async def test_opnsense_defaults_to_use_ssl_true() -> None:
    """OPNsense / pfSense ship HTTPS-only by default; the port-80
    heuristic must not apply to them — even if some unusual lab
    setup wired the gateway on port 80."""
    svc = _make_service()
    org_id = uuid4()
    gw = GatewayConnection(
        id=uuid4(),
        org_id=org_id,
        site_id=None,
        name="opnsense",
        vendor="opnsense",
        host="10.0.0.1",
        port=80,
        verify_ssl=False,
        credentials=encrypt_dict({"api_key": "K", "api_secret": "S"}),
        sync_enabled=True,
        sync_interval_seconds=300,
        settings={},
    )
    svc.db.execute = AsyncMock(
        side_effect=[_scalar_result(None), _scalar_result(gw)]
    )
    got = await svc._resolve_controller_or_gateway(gw.id, org_id)
    assert got.use_ssl is True


# ─── 9. Vendor-to-controller_type mapping covers every supported vendor


def test_vendor_to_controller_type_mapping_is_complete() -> None:
    """The four GatewayVendor values are mikrotik, opnsense, pfsense,
    openwrt — every one must resolve to a vendor-adapter id the
    registry knows about."""
    from app.services.adapter_base import _GATEWAY_VENDOR_TO_CONTROLLER_TYPE
    for vendor in ("mikrotik", "opnsense", "pfsense", "openwrt"):
        assert vendor in _GATEWAY_VENDOR_TO_CONTROLLER_TYPE, (
            f"vendor {vendor!r} missing from polymorphic-resolver mapping"
        )
        assert _GATEWAY_VENDOR_TO_CONTROLLER_TYPE[vendor] == vendor


# ─── 10. stage_change rejects gateway-only ids cleanly ──────────────


@pytest.mark.asyncio
async def test_stage_change_auto_pairs_controller_for_gateway_id() -> None:
    """the ``omada_pending_changes`` table has a
    FK on ``core.controllers.id``, but the UI passes the
    gateway id to the stage endpoint. The original fix returned
    501 here, which broke the entire stage→apply UX for newly-created
    gateways. The follow-up lazy-pair logic creates a paired Controller
    row with the same UUID on first stage attempt so the FK is
    satisfied AND the operator never has to know about the two-table
    architecture. Verified end-to-end against real
    RouterOS CHR 7.21.3.

    The auto-pair path:
    1. _resolve_controller_or_gateway returns a gateway facade
    2. stage_change detects ``_is_gateway_facade=True``
    3. _auto_pair_controller_for_gateway promotes the facade to a
       real Controller row (same UUID as the gateway)
    4. staging.stage_change inserts the omada_pending_changes row,
       FK constraint satisfied

    This test exercises only the contract — that auto-pair fires AND
    staging completes without 501. The actual SQL session interactions
    are mocked.
    """
    svc = _make_service()
    org_id = uuid4()
    gw_id = uuid4()
    gw = GatewayConnection(
        id=gw_id,
        org_id=org_id,
        site_id=None,
        name="x",
        vendor="mikrotik",
        host="10.0.0.7",
        port=443,
        verify_ssl=False,
        credentials=encrypt_dict({"username": "u", "password": "p"}),
        sync_enabled=True,
        sync_interval_seconds=300,
        settings={},
    )
    # _resolve sees: controller miss, gateway hit
    svc.db.execute = AsyncMock(
        side_effect=[_scalar_result(None), _scalar_result(gw)]
    )
    # _auto_pair sees: controller miss (db.get None), gateway hit
    # (db.get returns gw)
    svc.db.get = AsyncMock(side_effect=[None, gw])
    svc.db.add = MagicMock()
    svc.db.flush = AsyncMock()
    # The staging service should be called with the gateway's UUID
    # as controller_id (because we paired them 1:1).
    svc.staging.stage_change = AsyncMock(return_value={"id": "stub"})

    result = await svc.stage_change(
        feature="mikrotik.system.identity",
        operation="update",
        payload={"name": "x"},
        controller_id=gw_id,
        organization_id=org_id,
        site_id=None,
    )

    assert result == {"id": "stub"}, "staging should land without 501"
    # Controller was added to the session
    assert svc.db.add.called, "auto-pair must persist a Controller row"
    added = svc.db.add.call_args[0][0]
    assert added.id == gw_id, "paired Controller must share the gateway's UUID"
    assert not hasattr(added, "_is_gateway_facade"), (
        "the facade marker must be stripped before persist"
    )


# ─── 11. stage_change still works for a real controller id ──────────


@pytest.mark.asyncio
async def test_stage_change_still_works_for_real_controller_id() -> None:
    svc = _make_service()
    ctrl = Controller(
        id=uuid4(),
        site_id=uuid4(),
        name="real-ctrl",
        controller_type="mikrotik",
        host="10.0.0.8",
        port=443,
        use_ssl=True,
        verify_ssl=False,
        status="unknown",
        config={},
    )
    svc.db.execute = AsyncMock(return_value=_scalar_result(ctrl))
    svc.staging = SimpleNamespace(
        stage_change=AsyncMock(return_value="staged-row")
    )

    out = await svc.stage_change(
        feature="mikrotik.system.identity",
        operation="update",
        payload={"name": "edge-99"},
        controller_id=ctrl.id,
        organization_id=uuid4(),
        site_id=None,
    )
    assert out == "staged-row"
    svc.staging.stage_change.assert_awaited_once()
