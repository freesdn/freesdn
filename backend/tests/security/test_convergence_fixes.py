# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Regression tests for controller-push, tenancy, and destructive-op guards.

- VLAN/WiFi controller-push helpers must report controller_synced=False when the
  adapter returns AdapterResult(success=False) WITHOUT raising (not only on
  exceptions).
- update_organization must reject a scoped API key owned by an org_admin (a raw
  role comparison is scope-blind).
- _validate_archive must reject embedded path traversal in a Proxmox archive ref.
- Destructive direct gateway ops (system reboot/halt, bulk rule delete) require
  an explicit confirm.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException


def _user(role="org_admin", *, scoped=False, org_id=None):
    from app.core.dependencies import CurrentUser
    from app.models.core import User

    user = User(
        id=uuid4(),
        email=f"{uuid4().hex[:8]}@example.com",
        organization_id=org_id or uuid4(),
        role=role,
        hashed_password="x",
        is_active=True,
    )
    return CurrentUser(user=user, permissions=["*"], accessible_site_ids=set(), scoped=scoped)


class _FakeAdapter:
    """Async-context-manager adapter whose mutating methods return a failed
    AdapterResult WITHOUT raising (the Omada/base non-throwing failure shape)."""

    def __init__(self, ok: bool):
        self._r = SimpleNamespace(success=ok, error="controller rejected", message=None, data=None)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def create_vlan(self, *a, **k):
        return self._r

    async def update_vlan(self, *a, **k):
        return self._r

    async def delete_vlan(self, *a, **k):
        return self._r


# ── non-throwing AdapterResult.fail ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_push_vlan_reports_unsynced_on_nonthrowing_fail(monkeypatch):
    from app.api.v1.endpoints import network as net

    netobj = SimpleNamespace(
        vlan_id=10, name="v10", description="", external_id="e", controller_id=uuid4(), site_id=uuid4()
    )
    ctrl = SimpleNamespace(id=netobj.controller_id)
    session = MagicMock()
    session.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=ctrl))
    )
    monkeypatch.setattr(net, "_get_adapter_for_controller", AsyncMock(return_value=_FakeAdapter(ok=False)))

    out = await net._push_vlan_to_controller(session, netobj, "create")
    assert out["controller_synced"] is False
    assert out["controller_warning"]


@pytest.mark.asyncio
async def test_push_vlan_synced_on_nonthrowing_success(monkeypatch):
    from app.api.v1.endpoints import network as net

    netobj = SimpleNamespace(
        vlan_id=10, name="v10", description="", external_id="e", controller_id=uuid4(), site_id=uuid4()
    )
    ctrl = SimpleNamespace(id=netobj.controller_id)
    session = MagicMock()
    session.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=ctrl))
    )
    monkeypatch.setattr(net, "_get_adapter_for_controller", AsyncMock(return_value=_FakeAdapter(ok=True)))

    out = await net._push_vlan_to_controller(session, netobj, "update")
    assert out["controller_synced"] is True


# ── scoped key cannot update org settings ───────────────────────────────────


@pytest.mark.asyncio
async def test_update_organization_refuses_scoped_org_admin_key():
    from app.api.v1.endpoints.organizations import update_organization
    from app.schemas import OrganizationUpdate

    org_id = uuid4()
    scoped = _user(role="org_admin", scoped=True, org_id=org_id)  # narrowed key, own org
    with pytest.raises(HTTPException) as exc:
        await update_organization(org_id, OrganizationUpdate(name="x"), MagicMock(), scoped)
    assert exc.value.status_code == 403


# ── Proxmox archive traversal ───────────────────────────────────────────────


def test_validate_archive_rejects_traversal():
    from app.services.adapter_proxmox_backup import _validate_archive

    assert _validate_archive("local:backup/vzdump-qemu-100.vma.zst")  # valid
    for bad in (
        "local:backup/../../etc/shadow",
        "local:../escape",
        "local:a//b",
        "local:backup/./x",
        "local:backup\\x",
    ):
        with pytest.raises(HTTPException):
            _validate_archive(bad)


# ── Destructive direct ops require confirmation ─────────────────────────────


@pytest.mark.asyncio
async def test_gateway_reboot_halt_require_confirm():
    from app.modules.firewall.gateway_api import halt_gateway, reboot_gateway

    for fn in (reboot_gateway, halt_gateway):
        with pytest.raises(HTTPException) as exc:
            await fn(uuid4(), _user(), MagicMock(), confirm=False)
        assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_bulk_rule_delete_requires_confirm():
    from app.modules.firewall.gateway_api import BulkRuleAction, bulk_rule_operations

    body = BulkRuleAction(action="delete", rule_uuids=[str(uuid4())], confirm=False)
    with pytest.raises(HTTPException) as exc:
        await bulk_rule_operations(uuid4(), body, _user(), MagicMock())
    assert exc.value.status_code == 400


# ── non-throwing block/redaction/agent-download guards ──────────────────────


class _BlockAdapter:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def block_client(self, mac):
        return SimpleNamespace(success=False, error_code=None, error="controller rejected", message=None)


@pytest.mark.asyncio
async def test_block_client_raises_on_nonthrowing_adapter_fail(monkeypatch):
    """block_client must surface a non-throwing AdapterResult(success=False) (not
    only exceptions) and NOT commit the blocked state."""
    from app.api.v1.endpoints import network as net

    device = SimpleNamespace(site_id=uuid4(), controller_id=uuid4())
    client = SimpleNamespace(
        id="c1", device=device, mac_address="aa:bb:cc:dd:ee:ff", client_metadata={}
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
    monkeypatch.setattr(net, "_get_adapter_for_controller", AsyncMock(return_value=_BlockAdapter()))

    from app.adapters.exceptions import AdapterError

    with pytest.raises(AdapterError):  # raise_for_adapter_result → AdapterError → 502
        await net.block_client("c1", session=session, _user=_user(role="org_admin"))
    session.commit.assert_not_awaited()  # no false "blocked" state


def test_fabric_run_dict_redacts_for_non_author():
    """Non-author/admin viewers get a redacted run (no raw payload)."""
    from app.api.v1.endpoints.fabric import _run_dict

    r = SimpleNamespace(
        id=uuid4(), connection_id=uuid4(), source_event_type="x",
        trigger_payload={"secret": "v"}, success=True, steps=[{"a": 1}], error="boom",
        duration_ms=5, created_at=None,
    )
    full = _run_dict(r, full=True)
    assert full["trigger_payload"] == {"secret": "v"} and full["steps"] == [{"a": 1}]
    redacted = _run_dict(r, full=False)
    assert redacted["trigger_payload"] == "[redacted]"
    assert redacted["steps"] == [] and redacted["error"] is None
    assert redacted["success"] is True  # non-sensitive fields preserved


@pytest.mark.asyncio
async def test_disabled_agent_release_download_rejected(monkeypatch):
    """A disabled (is_enabled=False) approved agent cannot download releases."""
    from app.api.v1.endpoints.agent_release_upload import _authenticate_release_download

    disabled = SimpleNamespace(id=uuid4(), is_approved=True, is_enabled=False)
    session = MagicMock()
    session.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=disabled))
    )
    with pytest.raises(HTTPException) as exc:
        await _authenticate_release_download(session, str(disabled.id), "k")
    assert exc.value.status_code == 401

    enabled = SimpleNamespace(id=uuid4(), is_approved=True, is_enabled=True)
    session2 = MagicMock()
    session2.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=enabled))
    )
    assert await _authenticate_release_download(session2, str(enabled.id), "k") is enabled


# ── site-subnet CIDR safety + fabric site-grant plumbing ────────────────────


def test_site_subnet_rejects_dangerous_cidrs():
    """Site.subnets gates unauthenticated VoIP provisioning, so the schema must
    reject default-route / special-use / overbroad-public CIDRs."""
    import ipaddress

    from pydantic import ValidationError

    from app.schemas.core import SiteSubnet, is_safe_site_cidr

    assert SiteSubnet(cidr="192.168.1.0/24").cidr == "192.168.1.0/24"
    assert SiteSubnet(cidr="10.0.0.0/8").cidr == "10.0.0.0/8"  # large PRIVATE ok
    for bad in ("0.0.0.0/0", "::/0", "169.254.0.0/16", "127.0.0.0/8", "224.0.0.0/4", "8.0.0.0/8"):
        with pytest.raises(ValidationError):
            SiteSubnet(cidr=bad)
    assert is_safe_site_cidr(ipaddress.ip_network("192.168.1.0/24")) is True
    assert is_safe_site_cidr(ipaddress.ip_network("0.0.0.0/0")) is False


def test_provisioning_subnet_match_fails_closed_on_unsafe_row():
    """A stored unsafe CIDR (e.g. 0.0.0.0/0 from a pre-validation row) must NOT
    grant a provisioning match."""
    from app.modules.voip.provisioning_auth import _ip_in_subnets

    assert _ip_in_subnets("8.8.8.8", [{"cidr": "0.0.0.0/0"}]) is False  # fail-closed
    assert _ip_in_subnets("192.168.1.50", [{"cidr": "192.168.1.0/24"}]) is True
    assert _ip_in_subnets("10.1.2.3", [{"cidr": "192.168.1.0/24"}]) is False


def test_operation_context_carries_site_grant():
    """Fabric OperationContext must carry the caller's site grant so site-scoped
    handlers can confine to granted sites."""
    from app.core.fabric.execution import OperationContext

    sid = uuid4()
    ctx = OperationContext(organization_id=uuid4(), params={}, accessible_site_ids={sid})
    assert ctx.accessible_site_ids == {sid}
    assert OperationContext(organization_id=uuid4(), params={}).accessible_site_ids is None


@pytest.mark.asyncio
async def test_collector_reload_restricted_to_super_admin(monkeypatch):
    """A tenant admin's collector config update must NOT trigger the process-wide
    receiver reload (cross-tenant DoS); only a platform super_admin may."""
    from app.modules.collector import api as capi
    from app.modules.collector.services import manager as cmgr

    reload_mock = AsyncMock()
    monkeypatch.setattr(cmgr, "get_collector_manager", lambda: SimpleNamespace(reload_config=reload_mock))

    def _session():
        cfg = SimpleNamespace(organization_id=uuid4())
        s = MagicMock()
        s.execute = AsyncMock(
            return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=cfg))
        )
        s.commit = AsyncMock()
        s.refresh = AsyncMock()
        return s

    body = capi.CollectorConfigUpdate()

    await capi.update_config(body, _user(role="org_admin"), _session())
    reload_mock.assert_not_awaited()  # tenant admin cannot reload the shared listeners

    await capi.update_config(body, _user(role="super_admin"), _session())
    reload_mock.assert_awaited_once()  # platform super_admin can


# ── site-grant enforcement + session-revocation hardening ───────────────────


def _site_user(role="operator", *, granted=None, org_id=None):
    """A site-LIMITED CurrentUser: non-admin role + at least one explicit grant."""
    from app.core.dependencies import CurrentUser
    from app.models.core import User

    user = User(
        id=uuid4(),
        email=f"{uuid4().hex[:8]}@example.com",
        organization_id=org_id or uuid4(),
        role=role,
        hashed_password="x",
        is_active=True,
    )
    return CurrentUser(user=user, permissions=["*"], accessible_site_ids=set(granted or set()))


@pytest.mark.asyncio
async def test_get_controller_enforces_site_grant():
    """GatewayServiceBase._get_controller must deny a site-limited caller holding a
    SIBLING-site controller UUID (org filter alone is not enough), while staying a
    no-op for granted / admin / background callers."""
    from app.core import site_access
    from app.services.adapter_base import GatewayServiceBase

    org = uuid4()
    sibling_site = uuid4()
    ctrl = SimpleNamespace(id=uuid4(), site_id=sibling_site)

    svc = GatewayServiceBase.__new__(GatewayServiceBase)  # skip __init__ (no real db)
    svc.db = MagicMock()
    svc.db.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=ctrl))
    )

    # (a) site-limited caller granted only a DIFFERENT site → 404
    limited = _site_user(granted={uuid4()}, org_id=org)
    tok = site_access.current_user_var.set(limited)
    try:
        with pytest.raises(HTTPException) as exc:
            await svc._get_controller(ctrl.id, org)
        assert exc.value.status_code == 404
    finally:
        site_access.current_user_var.reset(tok)

    # (b) caller granted the controller's own site → returns it
    ok = _site_user(granted={sibling_site}, org_id=org)
    tok = site_access.current_user_var.set(ok)
    try:
        assert await svc._get_controller(ctrl.id, org) is ctrl
    finally:
        site_access.current_user_var.reset(tok)

    # (c) background / system context (no request user) → no-op
    assert await svc._get_controller(ctrl.id, org) is ctrl


@pytest.mark.asyncio
async def test_gateway_create_rejects_null_site_for_site_limited(monkeypatch):
    """A site-limited caller may not create an org-global (null-site) gateway (it
    would be parented under an arbitrary fallback site); an org admin
    (accessible_site_ids None) still may."""
    from app.modules.firewall.gateway_service import GatewayService
    from app.modules.firewall.models import GatewayVendor

    svc = GatewayService.__new__(GatewayService)
    svc.db = MagicMock()
    svc.accessible_site_ids = {uuid4()}  # site-limited

    # Patch the SSRF host check (static method) so we reach the site logic.
    # Use monkeypatch so it is AUTO-RESTORED — a bare class reassignment would
    # leak the no-op into sibling SSRF tests (test_pentest_preprod_round).
    from app.services.adapter_base import GatewayServiceBase

    monkeypatch.setattr(
        GatewayServiceBase, "_validate_controller_host", staticmethod(lambda *_a, **_k: None)
    )

    with pytest.raises(HTTPException) as exc:
        await svc.create_gateway(
            org_id=uuid4(), name="g", description=None, vendor=GatewayVendor.OPNSENSE,
            host="10.0.0.1", port=443, verify_ssl=False, site_id=None,
            api_key="k", api_secret="s", username=None, password=None,
        )
    assert exc.value.status_code == 422


def test_gateway_connection_tenant_column_is_org_id():
    """GatewayConnection names its tenant column ``org_id`` (NOT
    ``organization_id``); device_sync reads both. If this is ever renamed, the
    device_sync fallback derivation must be revisited."""
    from app.modules.firewall.models import GatewayConnection

    assert hasattr(GatewayConnection, "org_id")
    assert not hasattr(GatewayConnection, "organization_id")


@pytest.mark.asyncio
async def test_discovery_scan_rejects_ungranted_supplied_site():
    """A site-limited caller supplying a sibling site_id to the VoIP discovery scan
    must get 404 (otherwise it would run a live scan + writes on an ungranted
    site). An org admin supplying any in-org site is unaffected."""
    from app.modules.voip.api import trigger_discovery_scan
    from app.modules.voip.schemas import DiscoveryScanRequest

    org = uuid4()
    granted = uuid4()
    sibling = uuid4()
    limited = _site_user(role="site_admin", granted={granted}, org_id=org)

    body = DiscoveryScanRequest(site_id=sibling, scan_type="full", subnet="10.9.9.0/24")
    with pytest.raises(HTTPException) as exc:
        await trigger_discovery_scan(body, limited, MagicMock(), MagicMock())
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_session_revocation_helper_blocks_revoked_jti():
    """The shared helper reports a revoked session, and treats a missing (legacy)
    row as not-revoked — this is what makes the shared REST dependency honor a
    targeted single-device revocation."""
    from app.core.session_revocation import is_session_revoked_for_access_jti

    revoked_session = MagicMock()
    revoked_session.execute = AsyncMock(
        return_value=MagicMock(first=MagicMock(return_value=(object(), True)))
    )
    assert await is_session_revoked_for_access_jti(revoked_session, "jti-1") is True

    legacy_session = MagicMock()
    legacy_session.execute = AsyncMock(
        return_value=MagicMock(first=MagicMock(return_value=None))
    )
    assert await is_session_revoked_for_access_jti(legacy_session, "jti-2") is False


def test_voip_phone_endpoints_bind_site_grant():
    """The phone test-connection / save-credentials / bulk-connect endpoints
    construct the VoIP service via _set_org, which MUST bind the
    per-user site grant (get_phone skips its grant filter when accessible_site_ids
    is None, so an org-only service would let a site-limited caller probe/write a
    sibling-site phone)."""
    from app.modules.voip.api import _set_org
    from app.modules.voip.service import VoIPService

    granted = uuid4()
    limited = _site_user(role="site_admin", granted={granted})
    svc = _set_org(VoIPService(db=MagicMock()), limited)
    assert svc.accessible_site_ids == {granted}  # grant bound → get_phone filters

    # org admin is never site-limited → grant is None (full org access)
    svc2 = _set_org(VoIPService(db=MagicMock()), _user(role="org_admin"))
    assert svc2.accessible_site_ids is None


@pytest.mark.asyncio
async def test_create_firmware_track_asserts_site_grant(monkeypatch):
    """create_firmware_track must validate a caller-supplied site_id against the
    org + per-user grant, rather than inserting blindly."""
    from app.modules.voip.service import CrossTenantError, VoIPService

    svc = VoIPService(db=MagicMock(), organization_id=uuid4(), accessible_site_ids={uuid4()})
    svc.db.add = MagicMock()
    svc.db.commit = AsyncMock()
    svc.db.refresh = AsyncMock()

    asserter = AsyncMock(side_effect=CrossTenantError("site not in grant"))
    monkeypatch.setattr(svc, "_assert_site_in_org", asserter)

    sibling = uuid4()
    with pytest.raises(CrossTenantError):
        await svc.create_firmware_track({"site_id": sibling, "vendor": "x", "version": "1.0"})
    asserter.assert_awaited_once_with(sibling)
    svc.db.add.assert_not_called()  # guard fired before the insert


def test_validate_target_host_blocks_metadata_and_linklocal():
    """validate_target_host must block ALL cloud-metadata IPs (incl. Alibaba
    100.100.100.200 + Oracle 192.0.0.192, which are NOT link-local) and IPv6
    link-local, while still allowing on-prem RFC1918 and public hosts. Backs the
    setup-wizard SSRF guard + scan blocklist."""
    from app.core.security_utils import validate_target_host

    # allowed: on-prem private + public
    assert validate_target_host("192.168.1.10", allow_private=True) == "192.168.1.10"
    assert validate_target_host("10.20.30.40", allow_private=True) == "10.20.30.40"
    assert validate_target_host("8.8.8.8", allow_private=True) == "8.8.8.8"

    # blocked: metadata (incl. non-link-local Alibaba/Oracle/AWS-IPv6), loopback, link-local
    for bad in (
        "169.254.169.254", "100.100.100.200", "192.0.0.192", "fd00:ec2::254",
        "127.0.0.1", "fe80::1", "::1",
    ):
        with pytest.raises(ValueError):
            validate_target_host(bad, allow_private=True)


@pytest.mark.asyncio
async def test_ws_revalidation_enforces_jti_revocation(monkeypatch):
    """WebSocket revalidation must reject a connection whose per-device session was
    revoked (UserSession.revoked_at via access_jti), even when token_version still
    matches — mirroring the REST chokepoint."""
    from app.api.v1.endpoints import websocket as ws

    info = ws.ConnectionInfo(
        websocket=MagicMock(), user_id=str(uuid4()), token_version=0, access_jti="jti-x"
    )

    class _FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def execute(self, *a, **k):
            # active user, token_version=0 (matches), not deleted → reaches jti check
            return MagicMock(one_or_none=MagicMock(return_value=(True, 0, None)))

    monkeypatch.setattr("app.db.async_session_factory", lambda: _FakeSession())

    import app.core.session_revocation as sr

    monkeypatch.setattr(sr, "is_session_revoked_for_access_jti", AsyncMock(return_value=True))
    assert await ws._revalidate_ws_session(info) is False  # revoked device → reject

    monkeypatch.setattr(sr, "is_session_revoked_for_access_jti", AsyncMock(return_value=False))
    assert await ws._revalidate_ws_session(info) is True  # not revoked → allowed

    # token_version mismatch is rejected regardless of jti
    info.token_version = 5
    assert await ws._revalidate_ws_session(info) is False


def test_voip_live_writes_blocked_honors_runtime_flag(monkeypatch):
    """The VoIP phone-write gate must honor the LIVE Settings-UI/Redis read-only
    override (is_adapter_read_only), not just the import-time env."""
    import app.adapters.apply_context as ac
    import app.core.runtime_flags as rf
    from app.modules.voip import service as vs

    monkeypatch.setattr(ac, "in_apply_window", lambda: False)
    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: True)
    assert vs._voip_live_writes_blocked() is True  # live flag ON → blocked
    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: False)
    assert vs._voip_live_writes_blocked() is False  # live flag OFF → allowed
    # an approved staged-apply window short-circuits to allowed regardless
    monkeypatch.setattr(ac, "in_apply_window", lambda: True)
    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: True)
    assert vs._voip_live_writes_blocked() is False


@pytest.mark.parametrize(
    "modpath,cls,err",
    [
        ("app.adapters.freepbx.adapter", "FreePBXAdapter", "FreePBXReadOnlyError"),
        ("app.adapters.grandstream.adapter", "GrandstreamAdapter", "GrandstreamReadOnlyError"),
    ],
)
def test_pbx_adapter_read_only_gate_resolves_live_flag(monkeypatch, modpath, cls, err):
    """FreePBX/Grandstream write gates must resolve the LIVE runtime read-only flag
    when unpinned (self._read_only is None), instead of an import-time env snapshot,
    so an operator's live freeze toggle is honored."""
    import importlib

    mod = importlib.import_module(modpath)
    adapter = getattr(mod, cls).__new__(getattr(mod, cls))
    exc = getattr(mod, err)
    adapter._read_only = None  # unpinned → resolve live

    import app.core.runtime_flags as rf

    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: True)
    with pytest.raises(exc):
        adapter._check_write_allowed(force=False, op="write")
    adapter._check_write_allowed(force=True, op="write")  # force overrides

    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: False)
    adapter._check_write_allowed(force=False, op="write")  # live OFF → allowed

    adapter._read_only = True  # explicit pin still blocks regardless of live flag
    with pytest.raises(exc):
        adapter._check_write_allowed(force=False, op="write")


def test_gateway_test_override_has_no_host_port():
    """The saved-gateway test override must NOT accept host/port (replaying the
    stored decrypted credentials to a caller-chosen host would let a low-priv
    viewer exfiltrate the firewall's admin secrets). Only verify_ssl is
    overridable; host/port always come from the stored row."""
    from app.modules.firewall.schemas import GatewayTestOverride

    assert set(GatewayTestOverride.model_fields) == {"verify_ssl"}


@pytest.mark.asyncio
async def test_mikrotik_backup_download_enforces_extension_whitelist():
    """The RouterOS download path must enforce the backup-extension whitelist so a
    name-validated GET cannot read arbitrary file contents."""
    from app.adapters.mikrotik.client import MikroTikClient

    c = MikroTikClient.__new__(MikroTikClient)
    hits = {"get": 0}

    async def _get(path):
        hits["get"] += 1
        return [{"name": "x", "contents": "SECRET"}]

    c.get = _get
    # non-backup extension → rejected BEFORE any GET
    assert await c.download_backup_content("config.txt") == ""
    assert hits["get"] == 0
    # whitelisted backup extension → proceeds
    assert await c.download_backup_content("daily.backup") == "SECRET"
    assert hits["get"] == 1


@pytest.mark.asyncio
async def test_voip_factory_reset_requires_confirm():
    """The destructive single-phone factory reset must require an explicit confirm
    (matches the bulk-reboot / NVR / hypervisor destructive gate)."""
    from app.modules.voip.api import factory_reset_phone_endpoint

    with pytest.raises(HTTPException) as exc:
        await factory_reset_phone_endpoint(
            uuid4(), _user(role="site_admin"), MagicMock(), confirm=False
        )
    assert exc.value.status_code == 409


def test_mikrotik_tool_fetch_blocks_metadata_allows_rfc1918():
    """tool_fetch must reject cloud-metadata + loopback (via the central
    blocklist), while still allowing RFC1918 (LAN artifact fetch)."""
    from app.services.adapter_mikrotik_system import _validate_tool_fetch_payload

    for bad in ("http://100.100.100.200/latest/meta-data/", "http://169.254.169.254/", "http://127.0.0.1/x"):
        with pytest.raises(HTTPException):
            _validate_tool_fetch_payload({"url": bad, "mode": "http"})
    # RFC1918 LAN target is allowed (no raise)
    _validate_tool_fetch_payload({"url": "http://192.168.1.10/firmware.npk", "mode": "http"})
    # an unresolvable hostname fails CLOSED (RouterOS does the final fetch; we
    # can't verify it isn't an internal/metadata target).
    with pytest.raises(HTTPException):
        _validate_tool_fetch_payload({"url": "http://nonexistent.invalid./x", "mode": "http"})


@pytest.mark.asyncio
async def test_device_reboot_requires_confirm():
    """Single-device reboot must require confirm=true (matches batch)."""
    from app.api.v1.endpoints.devices import reboot_device

    with pytest.raises(HTTPException) as exc:
        await reboot_device(uuid4(), _user(role="operator"), MagicMock(), confirm=False)
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_notifications_list_providers_requires_admin():
    """The notification-provider list must be admin-gated like every sibling
    provider op (a viewer/operator should not enumerate org notification
    infrastructure)."""
    from app.api.v1.endpoints.notifications import list_providers

    with pytest.raises(HTTPException) as exc:
        await list_providers(MagicMock(), _user(role="operator"))
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_reboot_ap_requires_confirm():
    """AP reboot must require confirm=true (matches device reboot / forget)."""
    from app.api.v1.endpoints.access_points import reboot_ap

    with pytest.raises(HTTPException) as exc:
        await reboot_ap("ap1", MagicMock(), _user(role="site_admin"), confirm=False)
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_forget_device_requires_confirm():
    """Forget/unadopt (irreversible) must require confirm=true."""
    from app.api.v1.endpoints.devices import forget_device

    with pytest.raises(HTTPException) as exc:
        await forget_device(uuid4(), _user(role="admin"), MagicMock(), confirm=False)
    assert exc.value.status_code == 400


def test_base_adapter_validate_host_blocks_metadata():
    """BaseAdapter.validate_host uses the central blocklist (blocks
    Alibaba/Oracle/IPv6 metadata + loopback), still allows RFC1918."""
    from app.adapters.base import validate_host

    assert validate_host("192.168.1.10") == "192.168.1.10"  # on-prem allowed
    for bad in ("127.0.0.1", "169.254.169.254", "100.100.100.200", "192.0.0.192"):
        with pytest.raises(ValueError):
            validate_host(bad)


def test_no_curl_pipe_to_interpreter_in_dockerfiles():
    """No release Dockerfile may pipe a remote download straight into an
    interpreter (curl ... | python/sh/bash) — build-time RCE risk."""
    import re
    from pathlib import Path

    backend = Path(__file__).resolve().parents[2]  # tests/security → backend
    repo = backend.parent  # freesdn/
    pat = re.compile(r"curl[^|]*\|\s*(python3?|sh|bash)\b")
    checked = 0
    for df in list(repo.rglob("Dockerfile*")):
        if "node_modules" in df.parts:
            continue  # vendored third-party, not part of our release build
        checked += 1
        for line in df.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.lstrip().startswith("#"):
                continue  # comments/docs may mention the pattern
            assert not pat.search(line), f"{df}: curl-pipe-to-interpreter: {line!r}"
    assert checked >= 1  # sanity: we actually scanned the Dockerfiles


# ── setup-probe DNS-rebind + secret-redaction hardening ─────────────────────


class _FakeSetupAdapter:
    """Async-context adapter whose test_connection fails WITHOUT raising, so the
    setup probe short-circuits before discover_devices."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def test_connection(self):
        return SimpleNamespace(success=False, error="nope", message=None, data=None)

    async def discover_devices(self):
        return []


@pytest.mark.asyncio
async def test_setup_controller_test_pins_ip_even_with_verify_ssl(monkeypatch):
    """The unauthenticated first-boot controller test must connect to the PINNED IP
    even when verify_ssl=true. Multi-subchannel adapters (FreePBX
    AMI:5038 / ARI:8088) open NON-TLS subchannels that re-resolve the hostname, so
    the cert-validation defense cannot stop a DNS-rebind there — the only complete
    fix is to hand every subchannel the validated IP literal."""
    import app.core.security_utils as su
    from app.adapters.registry import adapter_registry
    from app.setup.schemas import ControllerAddRequest
    from app.setup.service import SetupService

    monkeypatch.setattr(su, "resolve_and_pin_host", MagicMock(return_value="203.0.113.9"))
    captured: dict = {}

    def _fake_create(**kwargs):
        captured.update(kwargs)
        return _FakeSetupAdapter()

    monkeypatch.setattr(adapter_registry, "create_adapter", _fake_create)

    req = ControllerAddRequest(
        adapter_id="freepbx",
        name="pbx",
        host="rebind.evil.example",
        username="u",
        password="p",
        verify_ssl=True,
    )
    await SetupService(MagicMock()).test_controller_connection(req)
    assert captured["host"] == "203.0.113.9"  # pinned IP, NOT the rebindable hostname


def test_template_redactor_masks_camelcase_secrets():
    """The config-template redactor must mask camelCase vendor keys
    (preSharedKey/securityKey/bindPassword/wpaPsk), not only underscored forms —
    a config:read viewer must never read a cleartext PSK / bind-password. The
    edit-and-save round-trip must still restore the real stored secret."""
    from app.api.v1.endpoints.enterprise import _redact_template_config, _unredact_config

    cfg = {
        "ssid": "corp",
        "preSharedKey": "psk-secret",
        "securityKey": "sec-secret",
        "wpaPsk": "wpa-secret",
        "ldap": {"bindPassword": "ldap-secret"},
    }
    red = _redact_template_config(cfg)
    assert red["preSharedKey"] == "***REDACTED***"
    assert red["securityKey"] == "***REDACTED***"
    assert red["wpaPsk"] == "***REDACTED***"
    assert red["ldap"]["bindPassword"] == "***REDACTED***"
    assert red["ssid"] == "corp"  # non-secret survives
    # round-trip: an edit-and-save restores the real stored secret from the sentinel
    restored = _unredact_config(red, cfg)
    assert restored["preSharedKey"] == "psk-secret"
    assert restored["ldap"]["bindPassword"] == "ldap-secret"


def test_drift_details_redaction_masks_secret_values():
    """drift_details embeds the raw desired/running VALUES under the
    secret-named key; the device-config read-path and persist-path redact it via
    redact_secrets so a config:read viewer can't read a secret through the diff."""
    from app.core.redaction import redact_secrets

    drift = {
        "changed": {"radius_secret": {"desired": "old-sec", "running": "new-sec"}},
        "added": {"wpa_psk": "psk123", "preSharedKey": "camel-psk"},
        "removed": {"snmp_community": "public-ro"},
    }
    red = redact_secrets(drift)
    assert red["changed"]["radius_secret"] == "***"  # whole sub-dict masked by key
    assert red["added"]["wpa_psk"] == "***"
    assert red["added"]["preSharedKey"] == "***"  # camelCase too
    assert red["removed"]["snmp_community"] == "***"


def test_mikrotik_tool_fetch_pins_hostname_to_ip(monkeypatch):
    """A hostname tool_fetch URL must be rewritten to the validated IP literal so
    RouterOS cannot re-resolve (DNS-rebind) it at fetch time. An IP literal is
    returned unchanged; scheme/port/path/query are preserved."""
    import socket

    from app.services.adapter_mikrotik_system import _validate_tool_fetch_payload

    def _fake_getaddrinfo(host, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.50.5", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)

    out = _validate_tool_fetch_payload(
        {"url": "http://artifacts.lan.example:8080/fw.npk?x=1", "mode": "http"}
    )
    assert out["url"] == "http://192.168.50.5:8080/fw.npk?x=1"  # host pinned to IP
    # an IP-literal url is returned unchanged (RouterOS performs no DNS lookup)
    out2 = _validate_tool_fetch_payload({"url": "http://192.168.1.10/fw.npk", "mode": "http"})
    assert out2["url"] == "http://192.168.1.10/fw.npk"


def test_remote_migrate_request_defaults_no_delete_source():
    """A source-destroying remote migration must never be the silent default —
    delete_source defaults False and confirmed defaults False."""
    from app.modules.hypervisor.schemas import RemoteMigrateRequest

    req = RemoteMigrateRequest(target_host="8.8.8.8", target_token="t", target_storage="local-lvm")
    assert req.delete_source is False
    assert req.confirmed is False


@pytest.mark.asyncio
async def test_remote_migrate_vm_requires_confirm_when_deleting_source(monkeypatch):
    """Deleting the source on a remote migration requires confirmed=true."""
    from app.modules.hypervisor import api as hv
    from app.modules.hypervisor.schemas import RemoteMigrateRequest

    monkeypatch.setattr(hv, "_get_controller", AsyncMock(return_value=SimpleNamespace(id=uuid4())))
    body = RemoteMigrateRequest(
        target_host="8.8.8.8",
        target_token="tok",
        target_storage="local-lvm",
        delete_source=True,
        confirmed=False,
    )
    with pytest.raises(HTTPException) as exc:
        await hv.remote_migrate_vm(
            uuid4(), body, node="pve1", vmid=100, session=MagicMock(), current_user=_user(role="site_admin")
        )
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_cert_upload_requires_confirm(monkeypatch):
    """Uploading a node TLS cert can lock pveproxy out → require confirmed=true on
    the direct route (parity with the destructive confirm class and the
    staged-apply catastrophic gate)."""
    from app.modules.hypervisor import api as hv
    from app.modules.hypervisor.schemas import UploadCertificateRequest

    monkeypatch.setattr(hv, "_get_controller", AsyncMock(return_value=SimpleNamespace(id=uuid4())))
    body = UploadCertificateRequest(
        certificates="-----BEGIN CERTIFICATE-----",
        key="-----BEGIN PRIVATE KEY-----",
        confirmed=False,
    )
    with pytest.raises(HTTPException) as exc:
        await hv.upload_custom_certificate(
            uuid4(), body, node="pve1", session=MagicMock(), current_user=_user(role="site_admin")
        )
    assert exc.value.status_code == 409


# ── parser / raw-path secret + resource guards ──────────────────────────────


def test_snmp_trap_does_not_leak_community():
    """The SNMP trap community (a device credential) must never be persisted in the
    readable log message that /collector/logs + /logs/{id}
    return to any collector.logs.read holder (operator/site_admin). The message
    is free text, so the key-based redact_secrets cannot mask it — redact at source."""
    from app.modules.collector.services.snmp_trap import _parse_snmp_trap

    def _ber(tag: int, payload: bytes) -> bytes:
        return bytes([tag, len(payload)]) + payload  # short-form length (<128)

    version = _ber(0x02, b"\x01")  # INTEGER version = 1 (v2c)
    community = _ber(0x04, b"secret123")  # OCTET STRING community
    int0 = _ber(0x02, b"\x00")
    vbl = _ber(0x30, b"")  # empty VarBindList
    pdu = _ber(0xA7, int0 + int0 + int0 + vbl)  # v2c trap PDU
    packet = _ber(0x30, version + community + pdu)

    parsed = _parse_snmp_trap(packet, "203.0.113.7")
    assert parsed is not None
    assert "secret123" not in parsed["message"]
    assert "<redacted>" in parsed["message"]
    assert "secret123" not in str(parsed)  # not leaked anywhere in the persisted row


@pytest.mark.asyncio
async def test_opnsense_get_raw_enforces_response_size_guard():
    """get_raw (the raw config.xml fallback path) must enforce the shared
    response-size guard — parity with the JSON _request path — so an oversized
    device body is rejected before being materialized."""
    from app.adapters._response_limits import ResponseTooLargeError
    from app.adapters.opnsense.client import OPNsenseClient

    client = OPNsenseClient(host="192.0.2.1", api_key="k", api_secret="s", port=443, verify_ssl=False)
    huge = MagicMock(status_code=200)
    huge.headers = {"Content-Length": str(65 * 1024 * 1024)}  # > 64 MB cap
    client._client = AsyncMock()
    client._client.is_closed = False
    client._client.get = AsyncMock(return_value=huge)
    with pytest.raises(ResponseTooLargeError):
        await client.get_raw("/api/core/backup/download/this")


def test_cli_profile_bounds_and_dedupes_port_indices():
    """apply_cli_profile fans out one live controller PATCH per port_index — bound
    the batch (max 500, matching the device_ids/port_ids sibling caps), reject
    negatives, and de-dup so duplicates don't multiply writes."""
    from pydantic import ValidationError

    from app.api.v1.endpoints.switches import CLIProfileIn

    # over the cap → rejected
    with pytest.raises(ValidationError):
        CLIProfileIn(name="p", port_indices=list(range(501)), config={"x": 1})
    # negative index → rejected
    with pytest.raises(ValidationError):
        CLIProfileIn(name="p", port_indices=[0, -1], config={"x": 1})
    # duplicates de-duped preserving order (no multiplied PATCH calls)
    m = CLIProfileIn(name="p", port_indices=[3, 1, 3, 2, 1], config={"x": 1})
    assert m.port_indices == [3, 1, 2]


# ── credential-egress / secret-read guards ──────────────────────────────────


@pytest.mark.asyncio
async def test_omada_routing_redacts_bgp_vrrp_secrets(monkeypatch):
    """get_routing_data must redact device-native routing secrets (BGP neighbor MD5
    `password`, VRRP `authKey`) before returning to a network:read (viewer) caller
    — parity with the omada VPN read sibling."""
    from app.services.adapter_omada_routing import GatewayRoutingService

    svc = GatewayRoutingService.__new__(GatewayRoutingService)
    fake_client = MagicMock()
    fake_client.get_bgp_config = AsyncMock(
        return_value={"neighbors": [{"ip": "10.0.0.1", "password": "bgpmd5secret"}]}
    )

    async def _resolve(*a, **k):
        return (None, fake_client, "site1")

    monkeypatch.setattr(svc, "_resolve_site_context", _resolve)
    out = await svc.get_routing_data(uuid4(), uuid4(), uuid4(), "bgp")
    assert out["data"]["neighbors"][0]["password"] == "***"
    assert "bgpmd5secret" not in str(out)


@pytest.mark.asyncio
async def test_hypervisor_sdn_controllers_redacted(monkeypatch):
    """GET sdn/controllers must redact the Proxmox bgp/evpn controller `password`
    for a hypervisor:read (viewer) caller."""
    from app.modules.hypervisor import api as hv

    monkeypatch.setattr(hv, "_get_controller", AsyncMock(return_value=SimpleNamespace(id=uuid4())))
    fake_svc = MagicMock()
    fake_svc.get_sdn_controllers = AsyncMock(
        return_value=SimpleNamespace(
            success=True,
            data=[{"controller": "bgp1", "type": "bgp", "password": "topsecret"}],
            error=None,
        )
    )
    monkeypatch.setattr(hv, "HypervisorService", MagicMock(return_value=fake_svc))
    out = await hv.get_sdn_controllers(
        uuid4(), session=MagicMock(), current_user=_user(role="viewer")
    )
    assert out[0]["password"] == "***"
    assert "topsecret" not in str(out)


def test_redacted_dc_masks_all_config_blobs():
    """_redacted_dc detaches + redacts every secret-bearing config blob so the read
    AND the two write-response handlers share one redaction."""
    from app.api.v1.endpoints.enterprise import _redacted_dc

    dc = SimpleNamespace(
        desired_config={"radius_secret": "s1"},
        pushed_config={"preSharedKey": "s2"},
        running_config={"snmp_community": "s3"},
        device_overrides={"password": "s4"},
        drift_details={"changed": {"wpa_psk": {"desired": "a", "running": "b"}}},
    )
    db = MagicMock()
    out = _redacted_dc(db, dc)
    db.expunge.assert_called_once_with(dc)
    assert out.desired_config["radius_secret"] == "***"
    assert out.pushed_config["preSharedKey"] == "***"
    assert out.running_config["snmp_community"] == "***"
    assert out.device_overrides["password"] == "***"
    assert out.drift_details["changed"]["wpa_psk"] == "***"


@pytest.mark.asyncio
async def test_access_events_masks_card_number(monkeypatch):
    """GET /access/events masks the full card_number to last-4 for a viewer —
    parity with the AccessCredential read path."""
    from app.modules.access_control import api as ac

    ev = SimpleNamespace(card_number="1234567890")
    fake_svc = MagicMock()
    fake_svc.search_events = AsyncMock(return_value=([ev], 1))
    monkeypatch.setattr(ac, "_get_service", MagicMock(return_value=fake_svc))
    out = await ac.search_events(
        current_user=_user(role="viewer"),
        session=MagicMock(),
        door_id=None,
        cardholder_id=None,
        event_type=None,
        start_time=None,
        end_time=None,
        limit=100,
    )
    assert out["items"][0].card_number == "****7890"


def test_local_controller_public_host_detection(monkeypatch):
    """The write-path helper flags a LOCAL-mode controller whose host resolves to a
    PUBLIC address (so create/update can gate it behind confirm_public_host).
    Cloud-mode and private/on-prem hosts return None (no gate, no friction)."""
    import app.core.security_utils as su
    from app.api.v1.endpoints.controllers import _local_controller_public_host

    # cloud mode is exempt (vendor cloud endpoint, gated separately by region/omada_id)
    assert _local_controller_public_host("controller.example.com", "cloud") is None

    # local + private/on-prem host → None (allowed, no confirm needed)
    monkeypatch.setattr(su, "resolve_and_pin_host", MagicMock(return_value="192.168.1.5"))
    monkeypatch.setattr(su, "is_private_ip", MagicMock(return_value=True))
    assert _local_controller_public_host("nas.local", "local") is None

    # local + public host → returns the resolved public IP (write path requires confirm)
    monkeypatch.setattr(su, "resolve_and_pin_host", MagicMock(return_value="203.0.113.9"))
    monkeypatch.setattr(su, "is_private_ip", MagicMock(return_value=False))
    assert _local_controller_public_host("remote.example.com", "local") == "203.0.113.9"


@pytest.mark.asyncio
async def test_create_controller_public_host_requires_confirm(monkeypatch):
    """Creating a LOCAL-mode controller with a genuinely PUBLIC host requires
    confirm_public_host=true (409 otherwise). 8.8.8.8 passes the SSRF block-list and
    is is_private_ip==False (documentation ranges like 203.0.113.x are treated as
    non-public, so they don't trip the gate — only a real global host does)."""
    from app.api.v1.endpoints import controllers as ctl
    from app.schemas import ControllerCreate

    site = SimpleNamespace(id=uuid4(), organization_id=uuid4())
    session = MagicMock()
    session.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=site))
    )
    monkeypatch.setattr(ctl, "is_unscoped_superuser", MagicMock(return_value=True))
    monkeypatch.setattr(ctl, "_assert_mapping_targets_accessible", AsyncMock())

    body = ControllerCreate(
        name="remote",
        controller_type="omada",
        host="8.8.8.8",
        port=443,
        username="u",
        password="p",
        site_id=site.id,
        connection_mode="local",
    )
    with pytest.raises(HTTPException) as exc:
        await ctl.create_controller(
            body, _user(role="admin"), session, None, confirm_public_host=False
        )
    assert exc.value.status_code == 409


def test_camera_adapter_refuses_public_host():
    """The credentialed camera adapter path refuses a PUBLIC host so the stored
    camera secret can't egress to an attacker-settable address (cameras are
    private). A public IP passes the SSRF block-list but is not private."""
    from app.modules.cameras.service import CameraError, StreamService

    with pytest.raises(CameraError):
        StreamService._create_camera_adapter(
            host="8.8.8.8", port=80, username="u", password="p", vendor="onvif"
        )


# ── destructive-without-confirm consistency ─────────────────────────────────


@pytest.mark.asyncio
async def test_device_firmware_upgrade_requires_confirm():
    """Single-device firmware upgrade must require confirm=true (parity with the
    AP-upgrade + batch-reboot sibling gates — flashing is irreversible)."""
    from app.api.v1.endpoints.devices import upgrade_device_firmware

    with pytest.raises(HTTPException) as exc:
        await upgrade_device_firmware(
            uuid4(), _user(role="super_admin"), MagicMock(), confirm=False
        )
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_batch_firmware_upgrade_requires_confirm():
    """Batch device firmware upgrade must require confirm=true."""
    from app.api.v1.endpoints.devices import BatchActionIn, batch_upgrade_firmware

    with pytest.raises(HTTPException) as exc:
        await batch_upgrade_firmware(
            BatchActionIn(device_ids=[uuid4()]),
            _user(role="super_admin"),
            MagicMock(),
            confirm=False,
        )
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_controller_batch_firmware_upgrade_requires_confirm():
    """Controller batch firmware-upgrade must require confirm=true."""
    from app.api.v1.endpoints.controllers import BatchDevicesIn, batch_firmware_upgrade

    with pytest.raises(HTTPException) as exc:
        await batch_firmware_upgrade(
            uuid4(),
            BatchDevicesIn(device_macs=["AA:BB:CC:DD:EE:FF"]),
            MagicMock(),
            _user(role="super_admin"),
            confirm=False,
        )
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_actions_reboot_requires_confirm():
    """The actions-module reboot must require confirm=true (parity with the
    canonical POST /devices/{id}/reboot)."""
    from app.api.v1.endpoints.actions import DeviceRebootRequest, reboot_device

    with pytest.raises(HTTPException) as exc:
        await reboot_device(
            DeviceRebootRequest(device_id=uuid4()),
            _user(role="org_admin"),
            MagicMock(),
            confirm=False,
        )
    assert exc.value.status_code == 400
