# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Regression tests for the pre-release confirmed security blockers.

- a SCOPED API key must not mint an empty-scope (inherit-full-role) child
  key — that would self-escalate the deliberately-narrowed credential.
- the DIRECT Proxmox backup restore/prune service path must refuse
  (steer to the staged path that runs the catastrophic pre-flight + confirmed=true
  + archive-volid validation) instead of writing live with none of those guards.

(firmware:upgrade gating and alert.resolve org-scope are covered by
the route-level real-PG suite + the existing bulk-op-authz / alert-API tests.)
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException


def _scoped_user(permissions: list[str]):
    """A SCOPED principal (e.g. a narrowed API key) owned by a super_admin."""
    from app.core.dependencies import CurrentUser
    from app.models.core import User

    user = User(
        id=uuid4(),
        email=f"{uuid4().hex[:8]}@example.com",
        organization_id=uuid4(),
        role="super_admin",
        hashed_password="x",
        is_active=True,
    )
    return CurrentUser(
        user=user, permissions=permissions, accessible_site_ids=set(), scoped=True
    )


def _unscoped_user(role: str = "super_admin"):
    """A normal (unscoped) principal — a JWT user or an unscoped/empty-scope key."""
    from app.core.dependencies import CurrentUser
    from app.models.core import User

    user = User(
        id=uuid4(),
        email=f"{uuid4().hex[:8]}@example.com",
        organization_id=uuid4(),
        role=role,
        hashed_password="x",
        is_active=True,
    )
    return CurrentUser(user=user, permissions=["*"], accessible_site_ids=set(), scoped=False)


class TestR2022EmptyScopeChildKey:
    @pytest.mark.asyncio
    async def test_scoped_key_cannot_mint_empty_scope_child(self):
        from app.api.v1.endpoints.api_keys import APIKeyCreate, create_api_key

        user = _scoped_user(["network:read"])  # deliberately narrowed
        count_res = MagicMock()
        count_res.scalar_one.return_value = 0  # under the per-user key ceiling
        session = MagicMock()
        session.execute = AsyncMock(side_effect=[MagicMock(), count_res])

        with pytest.raises(HTTPException) as exc:
            await create_api_key(APIKeyCreate(name="child", scopes=[]), user, session)
        assert exc.value.status_code == 403
        assert "empty-scope" in exc.value.detail or "unscoped" in exc.value.detail
        # The key was never persisted.
        session.add.assert_not_called()


class TestR3038DirectProxmoxRestorePruneRefused:
    @pytest.mark.asyncio
    async def test_direct_restore_backup_refused(self):
        from app.modules.hypervisor.service import HypervisorService

        svc = HypervisorService(MagicMock())
        with pytest.raises(ValueError) as exc:
            await svc.restore_backup(
                MagicMock(), "node1", "qemu", "local:backup/vzdump-qemu-100.vma.zst", 100
            )
        # Steers the operator to the staged path; no live adapter call happened.
        assert "stage" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_direct_prune_backups_refused(self):
        from app.modules.hypervisor.service import HypervisorService

        svc = HypervisorService(MagicMock())
        with pytest.raises(ValueError) as exc:
            await svc.prune_backups(MagicMock(), "node1", "local", keep_last=1)
        assert "stage" in str(exc.value).lower()


class TestScopedKeyRoleGateChokepoint:
    """(owner-approved chokepoint)role-based gates must
    REFUSE a scoped API key (it can't satisfy a role gate via its owner's raw
    role) while leaving normal users / unscoped keys unaffected."""

    @pytest.mark.asyncio
    async def test_require_min_role_refuses_scoped_key(self):
        from fastapi import HTTPException as _HTTPExc

        from app.core.dependencies import require_min_role

        dep = require_min_role("site_admin")
        with pytest.raises(_HTTPExc) as exc:
            await dep(current_user=_scoped_user(["network:read"]))  # owner super_admin
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_require_min_role_allows_unscoped_owner(self):
        from app.core.dependencies import require_min_role

        dep = require_min_role("site_admin")
        unscoped = _unscoped_user(role="super_admin")
        assert await dep(current_user=unscoped) is unscoped

    @pytest.mark.asyncio
    async def test_require_roles_refuses_scoped_key(self):
        from app.api.v1.deps import require_roles
        from app.models import UserRole

        dep = require_roles([UserRole.SUPER_ADMIN, UserRole.ORG_ADMIN])
        with pytest.raises(HTTPException) as exc:
            await dep(user=_scoped_user(["network:read"]))
        assert exc.value.status_code == 403

    def test_local_require_admin_helpers_refuse_scoped_key(self):
        from app.api.v1.endpoints.firmware import require_admin as fw_admin
        from app.api.v1.endpoints.radius import _require_admin as radius_admin
        from app.api.v1.endpoints.ztp import _require_admin as ztp_admin

        scoped = _scoped_user(["network:read"])
        for fn in (fw_admin, ztp_admin, radius_admin):
            with pytest.raises(HTTPException) as exc:
                fn(scoped)
            assert exc.value.status_code == 403
        # An unscoped org_admin still passes all three.
        for fn in (fw_admin, ztp_admin, radius_admin):
            fn(_unscoped_user(role="org_admin"))  # no raise


def _camera_user(role: str, permissions: list[str]):
    from app.core.dependencies import CurrentUser
    from app.models.core import User

    user = User(
        id=uuid4(),
        email=f"{uuid4().hex[:8]}@example.com",
        organization_id=uuid4(),
        role=role,
        hashed_password="x",
        is_active=True,
    )
    return CurrentUser(user=user, permissions=permissions, accessible_site_ids=set(), scoped=False)


class TestScopeAwareRoleHelpersSource:
    """Grand-finale: source-level completion of the role-gate chokepoint.
    has_min_role/has_role return False for scoped keys, so the ~17 INLINE
    has_min_role(...) gates (firewall config download, camera export/evidence,
    mikrotik/omada catastrophic-feature, staging guards) enforce the scope ceiling
    too. Plus the remaining module-local _require_admin helpers (dpi/integrations/
    poe) refuse scoped keys."""

    def test_has_min_role_and_has_role_false_for_scoped_key(self):
        scoped = _scoped_user(["network:read"])  # owner is super_admin
        assert scoped.has_min_role("site_admin") is False
        assert scoped.has_min_role("viewer") is False
        assert scoped.has_role("super_admin") is False
        # Unscoped owner unaffected.
        unscoped = _unscoped_user(role="super_admin")
        assert unscoped.has_min_role("site_admin") is True
        assert unscoped.has_role("super_admin") is True

    def test_remaining_require_admin_helpers_refuse_scoped_key(self):
        from app.api.v1.endpoints.dpi import _require_admin as dpi_admin
        from app.api.v1.endpoints.integrations import _require_admin as integ_admin
        from app.api.v1.endpoints.poe import _require_admin as poe_admin

        scoped = _scoped_user(["network:read"])
        for fn in (dpi_admin, integ_admin, poe_admin):
            with pytest.raises(HTTPException) as exc:
                fn(scoped)
            assert exc.value.status_code == 403
        for fn in (dpi_admin, integ_admin, poe_admin):
            fn(_unscoped_user(role="org_admin"))  # no raise


class TestActionsSuccessOnFailure:
    """Grand-finale: SSID toggle (and PoE cycle / reboot siblings) must report
    success=False when the controller REFUSES the write (AdapterResult.success
    is False) rather than returning {success:true}."""

    @pytest.mark.asyncio
    async def test_toggle_ssid_reports_failure_when_controller_refuses(self, monkeypatch):
        from types import SimpleNamespace

        from app.api.v1.endpoints import actions as actions_mod

        controller = SimpleNamespace(id=uuid4(), name="ctrl-1")
        monkeypatch.setattr(
            actions_mod, "get_controller_with_access", AsyncMock(return_value=controller)
        )

        class _FakeAdapter:
            async def connect(self):
                return None

            async def disconnect(self):
                return None

            async def toggle_ssid(self, *a, **k):
                return SimpleNamespace(success=False, error="controller is read-only", message=None)

        monkeypatch.setattr(actions_mod, "create_adapter", lambda _c: _FakeAdapter())

        req = actions_mod.SSIDToggleRequest(
            controller_id=controller.id, ssid_name="net", enabled=False
        )
        resp = await actions_mod.toggle_ssid(req, _unscoped_user(role="org_admin"), MagicMock())
        assert resp.success is False
        assert "read-only" in (resp.message or "")


class TestR5054RtspCredentialGate:
    """the credential-bearing rtsp stream URL must require cameras.access,
    not plain cameras.view — a viewer must not be able to extract the camera's
    decrypted device credentials (it still gets the proxied HLS/WebRTC stream)."""

    @pytest.mark.asyncio
    async def test_view_only_viewer_denied_rtsp(self):
        from app.modules.cameras.api import get_stream_url

        viewer = _camera_user("viewer", ["cameras.view", "cameras.playback"])
        with pytest.raises(HTTPException) as exc:
            await get_stream_url(
                uuid4(), viewer, MagicMock(), stream_type="main", protocol="rtsp"
            )
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_view_only_viewer_still_gets_proxied_hls(self):
        from app.modules.cameras.api import get_stream_url

        viewer = _camera_user("viewer", ["cameras.view", "cameras.playback"])
        service = MagicMock()
        service.get_stream_url = AsyncMock(return_value="/api/v1/cameras/x/stream/hls")
        result = await get_stream_url(
            uuid4(), viewer, service, stream_type="main", protocol="hls"
        )
        assert result["protocol"] == "hls"  # no 403 — proxied path stays open to viewers

    @pytest.mark.asyncio
    async def test_camera_access_holder_allowed_rtsp(self):
        from app.modules.cameras.api import get_stream_url

        operator = _camera_user("operator", ["cameras.view", "cameras.access"])
        service = MagicMock()
        service.get_stream_url = AsyncMock(return_value="rtsp://u:p@10.0.0.5:554/stream")
        result = await get_stream_url(
            uuid4(), operator, service, stream_type="main", protocol="rtsp"
        )
        assert result["protocol"] == "rtsp"
