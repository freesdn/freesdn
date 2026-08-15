# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Overlay (daemon) VPN writes as Fabric ops — the safety contract (Build B).

VPN connect/disconnect are exposed as Fabric write operations under the new
``overlay.*`` feature namespace. They are appliance-local daemon actions (no vendor
controller), so they stage with ``controller_id=None`` — but they MUST still ride
the staging chokepoint: stage → operator sign-off → dual-gated apply, never an
auto-apply. These tests lock that contract without a DB (mocks only).
"""

from __future__ import annotations

import types
import uuid
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.adapter_omada_vpn import (
    _required_apply_permission,
    _service_for_feature,
)
from app.services.adapter_overlay_vpn import OverlayVPNApplierService

# Connection-bound ops resolve a stored VPN connection record (connection_id
# required); singleton ops act on the one node-local daemon (no connection_id).
_CONN_FEATURES = (
    "overlay.wireguard.connect",
    "overlay.wireguard.disconnect",
    "overlay.openvpn.connect",
    "overlay.openvpn.disconnect",
    "overlay.netbird.connect",
)
_SINGLETON_FEATURES = (
    "overlay.netbird.disconnect",
    "overlay.tailscale.disconnect",
    "overlay.tailscale.reconnect",
)
_OVERLAY_FEATURES = _CONN_FEATURES + _SINGLETON_FEATURES


# ── Catalog: the ops are declared as staged writes ────────────────────────────


def test_overlay_ops_declared_as_staged_writes() -> None:
    from app.modules.network.module import NetworkModule

    ops = {o.id: o for o in NetworkModule().get_operations()}
    for oid in _OVERLAY_FEATURES:
        assert oid in ops, f"{oid} not declared"
        op = ops[oid]
        assert op.write is True  # a device write — MUST stage
        assert op.feature == oid  # binds to the staging feature
        assert op.permission == "vpn:write"  # the daemon-VPN grant
        assert op.handler is None  # staged writes have no direct handler
        # connection-bound ops require a connection_id; singletons take none
        expected_required = ["connection_id"] if oid in _CONN_FEATURES else []
        assert op.input_schema["required"] == expected_required


# ── Apply-path routing + permission tier ──────────────────────────────────────


@pytest.mark.parametrize("feature", _OVERLAY_FEATURES)
def test_overlay_feature_routes_to_overlay_applier(feature: str) -> None:
    assert isinstance(_service_for_feature(feature, MagicMock()), OverlayVPNApplierService)


def test_vpn_features_still_route_to_omada_gateway() -> None:
    # no regression: the Omada vpn.* family is unaffected by the new overlay. branch
    assert (
        type(_service_for_feature("vpn.ipsec.policy", MagicMock())).__name__ == "GatewayVPNService"
    )


@pytest.mark.parametrize("feature", _OVERLAY_FEATURES)
def test_overlay_apply_permission_is_vpn_write(feature: str) -> None:
    # WITHOUT the overlay branch this would fall through to network:write — a
    # privilege under-gate. Lock it to the vpn:write tier.
    assert _required_apply_permission(feature) == "vpn:write"


# ── Containment guard: only overlay.* may be controllerless ───────────────────


@pytest.mark.asyncio
async def test_containment_guard_blocks_controllerless_non_overlay() -> None:
    from app.services.adapter_staging import AdapterStagingService

    svc = AdapterStagingService(db=MagicMock())
    with pytest.raises(HTTPException) as ei:
        await svc.stage_change(
            organization_id=uuid.uuid4(),
            controller_id=None,
            feature="bulk.client.block",  # a controller-bound feature
            operation="create",
            payload={},
        )
    assert ei.value.status_code == 400  # refused before any DB touch


# ── The safety property: a write STAGES, never applies ────────────────────────


@pytest.mark.asyncio
async def test_overlay_write_stages_never_applies(monkeypatch: pytest.MonkeyPatch) -> None:
    """The executor's overlay branch records a pending change and does NOT touch
    the VPN daemon — so even an auto-firing Connection can only stage."""
    import app.services.adapter_staging as st
    from app.core.fabric import executor as ex
    from app.core.fabric.execution import OperationContext
    from app.core.fabric.operations import Operation, OperationTier

    staged: dict = {}

    async def _fake_stage(self, **kw):  # noqa: ANN001
        staged.update(kw)
        return types.SimpleNamespace(id=uuid.uuid4())

    monkeypatch.setattr(st.AdapterStagingService, "stage_change", _fake_stage)

    op = Operation(
        id="overlay.wireguard.connect",
        title="x",
        write=True,
        feature="overlay.wireguard.connect",
        permission="vpn:write",
        tier=OperationTier.NATIVE,
        provider_id="network",
    )
    ctx = OperationContext(
        organization_id=uuid.uuid4(),
        params={"connection_id": str(uuid.uuid4())},
        db=MagicMock(),
    )
    res = await ex.operation_executor.execute(op, ctx)

    assert res.success and res.output.get("staged") is True
    assert res.staged_change_id  # the operator-applies handle
    assert staged["controller_id"] is None  # daemon write — no controller
    assert staged["feature"] == "overlay.wireguard.connect"
    assert staged["operation"] == "create"
    # the connection_id is a routing key (→ target_id), never carried in payload;
    # no decrypted config / secret material lands in the staged row
    assert "connection_id" not in staged["payload"]
    assert "wireguard_config_content" not in staged["payload"]


@pytest.mark.asyncio
async def test_overlay_write_drops_extra_params_from_staged_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The overlay applier re-reads everything it needs from the VPN
    connection record (via target_id) and NEVER reads change.payload, so the executor
    must not copy caller params into the staged row. An operator passing a
    secret-bearing extra (authorization_header / x_api_key) must NOT have it persisted
    to the pending-change JSON in plaintext."""
    import app.services.adapter_staging as st
    from app.core.fabric import executor as ex
    from app.core.fabric.execution import OperationContext
    from app.core.fabric.operations import Operation, OperationTier

    staged: dict = {}

    async def _fake_stage(self, **kw):  # noqa: ANN001
        staged.update(kw)
        return types.SimpleNamespace(id=uuid.uuid4())

    monkeypatch.setattr(st.AdapterStagingService, "stage_change", _fake_stage)

    op = Operation(
        id="overlay.netbird.connect",
        title="x",
        write=True,
        feature="overlay.netbird.connect",
        permission="vpn:write",
        tier=OperationTier.NATIVE,
        provider_id="network",
    )
    cid = str(uuid.uuid4())
    ctx = OperationContext(
        organization_id=uuid.uuid4(),
        params={
            "connection_id": cid,
            "authorization_header": "Bearer SECRET",
            "x_api_key": "sk-live-leak",
            "anything_else": {"nested": "value"},
        },
        db=MagicMock(),
    )
    res = await ex.operation_executor.execute(op, ctx)

    assert res.success and res.output.get("staged") is True
    # connection_id is captured as the routing key (target_id), not retained in payload
    assert staged["target_id"]  # routing preserved
    # the staged payload is EMPTY — no caller param survives, secret or otherwise
    assert staged["payload"] == {}


# ── The applier never records a false 'applied' ───────────────────────────────


@pytest.mark.asyncio
async def test_applier_surfaces_daemon_failure_as_502(monkeypatch: pytest.MonkeyPatch) -> None:
    """A daemon that reports success=False must surface as 502 (→ recorded
    ``failed``), never a silent ``applied`` against a tunnel that never came up."""
    svc = OverlayVPNApplierService(db=MagicMock())

    async def _get_rec(target_id, organization_id):  # noqa: ANN001
        return types.SimpleNamespace(id="r", wireguard_config_content=None)

    monkeypatch.setattr(svc, "_get_record", _get_rec)

    class _WG:
        async def disconnect(self, iface):  # noqa: ANN001
            return {"success": False, "message": "daemon down"}

    monkeypatch.setattr(
        "app.services.vpn_integration.get_vpn_manager",
        lambda: types.SimpleNamespace(wireguard=_WG()),
    )
    monkeypatch.setattr("app.api.v1.endpoints.vpn._wireguard_iface_name", lambda _rec: "wg-x")

    change = types.SimpleNamespace(
        feature="overlay.wireguard.disconnect", target_id="r", organization_id="o"
    )
    applier = svc.build_applier(change)
    with pytest.raises(HTTPException) as ei:
        await applier(change)
    assert ei.value.status_code == 502


@pytest.mark.asyncio
async def test_applier_rejects_unsupported_overlay_feature(monkeypatch: pytest.MonkeyPatch) -> None:
    # a not-yet-implemented overlay op (e.g. tailscale) is refused, not mis-applied
    svc = OverlayVPNApplierService(db=MagicMock())
    change = types.SimpleNamespace(
        feature="overlay.tailscale.logout", target_id="r", organization_id="o"
    )
    applier = svc.build_applier(change)
    with pytest.raises(HTTPException) as ei:
        await applier(change)
    assert ei.value.status_code == 400


@pytest.mark.asyncio
async def test_singleton_op_applies_without_a_record(monkeypatch: pytest.MonkeyPatch) -> None:
    """A singleton daemon op (tailscale.disconnect) acts on the node-local daemon
    with NO connection record — it must not require/fetch one."""
    svc = OverlayVPNApplierService(db=MagicMock())

    class _TS:
        async def disconnect(self):
            return {"success": True, "message": "down"}

    monkeypatch.setattr("app.services.vpn_integration.TailscaleSetupService", _TS)
    # if it tried to fetch a record this would blow up (db is a MagicMock)
    change = types.SimpleNamespace(
        feature="overlay.tailscale.disconnect", target_id=None, organization_id="o"
    )
    result = await svc.build_applier(change)(change)
    assert result["success"] is True


# ── Audit Finding 1: site-grant on controllerless overlay apply/discard ───────


@pytest.mark.asyncio
async def test_site_limited_blocked_on_controllerless_overlay_apply_and_discard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A controllerless overlay.* change has BOTH site_id and controller_id NULL, so
    the site-grant assert (no-op when site_id is None) AND the controller-grant
    fallback (skipped when controller_id is None) both miss it. A SITE-LIMITED
    operator must be 404'd by the explicit guard on apply AND discard; an org-admin
    (not site-limited) passes the guard (proving it doesn't over-block)."""
    import uuid

    from app.api.v1.endpoints import adapter_omada_vpn as ep

    org = uuid.uuid4()
    change = types.SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=org,
        site_id=None,
        controller_id=None,
        feature="overlay.wireguard.connect",
    )

    class _Staging:
        def __init__(self, _session):
            pass

        async def get(self, _cid):
            return change

    monkeypatch.setattr(ep, "AdapterStagingService", _Staging)

    def _user(*, site_limited: bool):
        return types.SimpleNamespace(
            organization_id=org,
            is_site_limited=site_limited,
            has_permission=lambda _p: False,  # only reached PAST the guard
        )

    body = types.SimpleNamespace(force=True)

    # site-limited operator -> 404 at the guard, on BOTH apply and discard
    with pytest.raises(HTTPException) as ei_apply:
        await ep.apply_change(
            change_id=change.id, body=body, user=_user(site_limited=True), session=object()
        )
    assert ei_apply.value.status_code == 404
    with pytest.raises(HTTPException) as ei_discard:
        await ep.discard_change(
            change_id=change.id, user=_user(site_limited=True), session=object(), force=True
        )
    assert ei_discard.value.status_code == 404

    # org-admin (not site-limited) passes the guard, reaching the permission check
    # (403 here only because the stub lacks the permission) — proves no over-block.
    with pytest.raises(HTTPException) as ei_admin:
        await ep.apply_change(
            change_id=change.id, body=body, user=_user(site_limited=False), session=object()
        )
    assert ei_admin.value.status_code == 403


@pytest.mark.asyncio
async def test_every_controllerless_family_blocks_site_limited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Structural invariant: EVERY feature family allowed to stage controllerless
    (``controller_id`` NULL — see CONTROLLERLESS_FEATURE_PREFIXES) must be caught by
    the site-limited guard on apply AND discard. Adding a prefix to that constant
    auto-extends this test; if the guard is ever narrowed to a specific prefix, this
    fails for the next family before it can silently re-introduce audit Finding 1.
    The guard fires before the permission/service lookup, so a synthetic feature in
    each family is sufficient to exercise it."""
    import uuid

    from app.api.v1.endpoints import adapter_omada_vpn as ep
    from app.services.adapter_staging import CONTROLLERLESS_FEATURE_PREFIXES

    assert CONTROLLERLESS_FEATURE_PREFIXES, "expected at least one controllerless family"

    org = uuid.uuid4()
    site_limited = types.SimpleNamespace(
        organization_id=org, is_site_limited=True, has_permission=lambda _p: False
    )
    body = types.SimpleNamespace(force=True)

    def _staging_returning(change):  # bind `change` as a param (avoids loop-var closure)
        class _Staging:
            def __init__(self, _session):
                pass

            async def get(self, _cid):
                return change

        return _Staging

    for prefix in CONTROLLERLESS_FEATURE_PREFIXES:
        change = types.SimpleNamespace(
            id=uuid.uuid4(),
            organization_id=org,
            site_id=None,
            controller_id=None,
            feature=f"{prefix}probe",
        )
        monkeypatch.setattr(ep, "AdapterStagingService", _staging_returning(change))

        with pytest.raises(HTTPException) as ei_apply:
            await ep.apply_change(
                change_id=change.id, body=body, user=site_limited, session=object()
            )
        assert ei_apply.value.status_code == 404, f"apply not guarded for {prefix!r}"
        with pytest.raises(HTTPException) as ei_discard:
            await ep.discard_change(
                change_id=change.id, user=site_limited, session=object(), force=True
            )
        assert ei_discard.value.status_code == 404, f"discard not guarded for {prefix!r}"
